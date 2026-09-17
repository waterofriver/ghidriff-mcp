"""Async job management for long-running ghidriff analyses.

A real binary diff spends minutes inside Ghidra, which is far longer than an
agent wants to block a tool call for. Every diff therefore runs as a background
job with an id, a log file and a persisted ``job.json`` so results survive a
server restart.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .config import Settings
from .reports import ReportError, latest_artifacts, load_pdiff, summarize_pdiff
from .runner import DiffRequest, GhidriffRunner

STATUS_QUEUED = "queued"
STATUS_RUNNING = "running"
STATUS_SUCCEEDED = "succeeded"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
STATUS_TIMEOUT = "timeout"
TERMINAL_STATUSES = frozenset({STATUS_SUCCEEDED, STATUS_FAILED, STATUS_CANCELLED, STATUS_TIMEOUT})

JOB_FILE = "job.json"


class JobError(LookupError):
    """Raised for unknown or unusable job ids."""


@dataclass
class Job:
    id: str
    request: DiffRequest
    run_dir: Path
    log_path: Path
    status: str = STATUS_QUEUED
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    returncode: int | None = None
    error: str | None = None
    command: list[str] = field(default_factory=list)
    tail: list[str] = field(default_factory=list)
    summary: dict[str, Any] | None = None

    _task: asyncio.Task[None] | None = field(default=None, repr=False, compare=False)

    @property
    def output_dir(self) -> Path:
        return self.request.output_dir

    @property
    def terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    def duration_s(self) -> float | None:
        if self.started_at is None:
            return None
        end = self.finished_at if self.finished_at is not None else time.time()
        return round(end - self.started_at, 3)

    def as_dict(self, *, include_request: bool = True, tail: int = 0) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "job_id": self.id,
            "status": self.status,
            "created_at": _iso(self.created_at),
            "started_at": _iso(self.started_at),
            "finished_at": _iso(self.finished_at),
            "duration_s": self.duration_s(),
            "returncode": self.returncode,
            "error": self.error,
            "log_path": str(self.log_path),
            "run_dir": str(self.run_dir),
            "output_dir": str(self.output_dir),
            "command": self.command,
            "notices": list(self.request.notices),
        }
        if include_request:
            payload["request"] = self.request.as_dict()
        if tail:
            payload["log_tail"] = self.tail[-tail:]
        if self.summary is not None:
            payload["summary"] = self.summary
        return payload

    def save(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        path = self.run_dir / JOB_FILE
        payload = self.as_dict(include_request=True)
        payload["_schema"] = 1
        # Persisting is best effort: a job must never fail because its own
        # bookkeeping could not be written.
        with contextlib.suppress(OSError):
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _iso(stamp: float | None) -> str | None:
    if stamp is None:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(stamp))


def _new_job_id() -> str:
    return f"{time.strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"


class JobManager:
    """Owns every diff run in this server process."""

    def __init__(
        self,
        settings: Settings,
        runner: GhidriffRunner | None = None,
        *,
        max_parallel: int | None = None,
    ) -> None:
        self.settings = settings
        self.runner = runner or GhidriffRunner(settings)
        self.max_parallel = max_parallel or settings.max_concurrent_jobs
        self._jobs: dict[str, Job] = {}
        self._semaphore = asyncio.Semaphore(self.max_parallel)
        self._load_existing()

    # ------------------------------------------------------------------ lookup

    def get(self, job_id: str) -> Job:
        job = self._jobs.get(job_id)
        if job is None:
            known = ", ".join(sorted(self._jobs)[-5:]) or "none"
            raise JobError(f"Unknown job_id {job_id!r}. Recent jobs: {known}")
        return job

    def list(self, *, limit: int = 20, status: str | None = None) -> list[Job]:
        jobs = sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)
        if status:
            jobs = [job for job in jobs if job.status == status]
        return jobs[:limit]

    def _load_existing(self) -> None:
        runs_dir = self.settings.runs_dir
        if not runs_dir.is_dir():
            return
        for job_file in sorted(runs_dir.glob(f"*/{JOB_FILE}")):
            try:
                payload = json.loads(job_file.read_text(encoding="utf-8"))
                request = DiffRequest.from_dict(payload["request"])
            except (OSError, ValueError, KeyError):
                continue
            status = payload.get("status", STATUS_FAILED)
            if status not in TERMINAL_STATUSES:
                # The process that owned this job is gone.
                status = STATUS_FAILED
            job = Job(
                id=payload.get("job_id", job_file.parent.name),
                request=request,
                run_dir=job_file.parent,
                log_path=Path(payload.get("log_path", job_file.parent / "ghidriff.log")),
                status=status,
                created_at=_parse_iso(payload.get("created_at")) or job_file.stat().st_mtime,
                started_at=_parse_iso(payload.get("started_at")),
                finished_at=_parse_iso(payload.get("finished_at")),
                returncode=payload.get("returncode"),
                error=payload.get("error")
                or (
                    "Interrupted: the MCP server restarted while this job was running."
                    if payload.get("status") not in TERMINAL_STATUSES
                    else None
                ),
                command=payload.get("command", []),
                summary=payload.get("summary"),
            )
            self._jobs[job.id] = job

    # ------------------------------------------------------------------ control

    def reserve(self) -> tuple[str, Path]:
        """Allocate a job id and its run directory before the request is built.

        The run directory is where ghidriff's default output and Ghidra project
        paths are placed, so it has to exist before the request is resolved.
        """
        job_id = _new_job_id()
        run_dir = self.settings.runs_dir / job_id
        run_dir.mkdir(parents=True, exist_ok=True)
        return job_id, run_dir

    async def start(
        self,
        request: DiffRequest,
        *,
        job_id: str | None = None,
        run_dir: Path | None = None,
    ) -> Job:
        if job_id is None or run_dir is None:
            job_id, run_dir = self.reserve()
        job = Job(
            id=job_id,
            request=request,
            run_dir=run_dir,
            log_path=run_dir / "ghidriff.log",
        )
        self._jobs[job_id] = job
        job.save()
        job._task = asyncio.create_task(self._run(job))
        return job

    async def _run(self, job: Job) -> None:
        async with self._semaphore:
            if job.status == STATUS_CANCELLED:
                return
            job.status = STATUS_RUNNING
            job.started_at = time.time()
            job.save()

            try:
                self.runner.prepare_dirs(job.request)
            except OSError as exc:
                self._finish(job, STATUS_FAILED, error=f"Could not create output dirs: {exc}")
                return

            try:
                outcome = await self.runner.run(
                    job.request,
                    log_path=job.log_path,
                    on_process=lambda process: None,
                )
            except asyncio.CancelledError:
                self._finish(job, STATUS_CANCELLED, error="Cancelled by request.")
                raise
            except FileNotFoundError as exc:
                self._finish(
                    job,
                    STATUS_FAILED,
                    error=f"Could not launch ghidriff: {exc}",
                )
                return
            except Exception as exc:
                self._finish(job, STATUS_FAILED, error=f"{type(exc).__name__}: {exc}")
                return

            job.command = outcome.command
            job.tail = outcome.tail
            job.returncode = outcome.returncode

            if outcome.cancelled:
                self._finish(job, STATUS_CANCELLED, error="Cancelled by request.")
                return
            if outcome.timed_out:
                self._finish(
                    job,
                    STATUS_TIMEOUT,
                    error=(
                        f"ghidriff did not finish within {job.request.timeout_s}s and was killed. "
                        "Increase timeout_s or narrow the diff."
                    ),
                )
                return
            if outcome.returncode != 0:
                self._finish(
                    job,
                    STATUS_FAILED,
                    error=_explain_failure(outcome.tail, outcome.returncode),
                )
                return

            summary, warning = await asyncio.to_thread(_summarize_output, job.output_dir)
            if summary is None:
                self._finish(
                    job,
                    STATUS_FAILED,
                    error=(
                        f"ghidriff exited 0 but no diff artefacts were found in {job.output_dir}. "
                        f"{warning or ''}".strip()
                    ),
                )
                return
            job.summary = summary
            self._finish(job, STATUS_SUCCEEDED, error=warning)

    def _finish(self, job: Job, status: str, *, error: str | None = None) -> None:
        job.status = status
        job.finished_at = time.time()
        if error:
            job.error = error
        job.save()

    async def wait(self, job_id: str, *, timeout_s: float | None = None) -> Job:
        job = self.get(job_id)
        if job.terminal or job._task is None:
            return job
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(asyncio.shield(job._task), timeout=timeout_s)
        return job

    async def cancel(self, job_id: str) -> Job:
        job = self.get(job_id)
        if job.terminal:
            return job
        job.status = STATUS_CANCELLED
        if job._task is not None:
            job._task.cancel()
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await job._task
        self._finish(job, STATUS_CANCELLED, error="Cancelled by request.")
        return job

    async def shutdown(self) -> None:
        for job in list(self._jobs.values()):
            if not job.terminal and job._task is not None:
                job._task.cancel()
        tasks = [job._task for job in self._jobs.values() if job._task is not None]
        for task in tasks:
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await task


def _summarize_output(output_dir: Path) -> tuple[dict[str, Any] | None, str | None]:
    artifacts = latest_artifacts(output_dir)
    if artifacts is None or artifacts.json_path is None:
        return None, None
    try:
        pdiff = load_pdiff(artifacts.json_path)
    except ReportError as exc:
        return None, f"pdiff could not be parsed: {exc}"
    return summarize_pdiff(pdiff, max_names=25, artifacts=artifacts), None


def _explain_failure(tail: list[str], returncode: int) -> str:
    joined = "\n".join(tail)
    hints = [
        (
            "Path element starting with '.' is not permitted",
            "Ghidra rejected the project path because a path element starts with '.'. "
            "Point GHIDRIFF_MCP_HOME at a dot-free directory.",
        ),
        (
            "GHIDRA_INSTALL_DIR",
            "Ghidra could not be located. Set GHIDRA_INSTALL_DIR to the extracted Ghidra folder.",
        ),
        (
            "No module named ghidriff",
            "The interpreter this server launches does not have ghidriff installed. "
            "Set GHIDRIFF_MCP_PYTHON or GHIDRIFF_MCP_COMMAND.",
        ),
        (
            "ModuleNotFoundError: No module named 'pyghidra'",
            "pyghidra is missing; install ghidriff with its dependencies.",
        ),
        (
            "OutOfMemoryError",
            "The JVM ran out of memory. Lower max_ram_percent or diff smaller binaries.",
        ),
    ]
    for marker, message in hints:
        if marker in joined:
            return f"ghidriff failed (exit {returncode}): {message}"
    last = tail[-1].strip() if tail else "no output captured"
    return f"ghidriff failed with exit code {returncode}. Last output: {last}"


def _parse_iso(value: str | None) -> float | None:
    if not value:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"):
        try:
            return time.mktime(time.strptime(value, fmt))
        except ValueError:
            continue
    return None
