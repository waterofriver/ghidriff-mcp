"""FastMCP tool surface for the ghidriff binary-diffing engine.

Tool naming convention: everything is prefixed with ``ghidriff_`` so an agent
can tell these apart from other Ghidra-related servers (for example a GUI
bridge). Long analyses are exposed as jobs: ``ghidriff_start_diff`` returns
immediately and the agent polls ``ghidriff_job_status`` / ``ghidriff_job_result``.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any

from mcp.server.fastmcp import FastMCP
from pydantic import Field

from .config import Settings
from .ghidra_env import diagnose
from .jobs import JobError, JobManager
from .paths import PathError
from .reports import (
    ReportError,
    discover_artifacts,
    function_detail,
    load_pdiff,
    metadata_diff,
    read_text_page,
    search_functions,
    summarize_pdiff,
)
from .runner import DiffRequest, GhidriffRunner, RunnerError, build_request

__all__ = ["ServerState", "get_state", "main", "mcp", "reset_state"]

INSTRUCTIONS = """\
This server drives ghidriff, the Ghidra-based binary diffing engine, and exposes
its results as structured data.

Typical flow:
1. Call ghidriff_environment once to confirm Ghidra, Java and ghidriff are usable.
2. Call ghidriff_start_diff with an old binary and one or more newer binaries.
   Each run writes a Markdown report plus a pdiff JSON next to it.
3. Poll ghidriff_job_status until the status is terminal, then call
   ghidriff_job_result for the stats and the lists of added/deleted/modified
   functions.
4. Drill into individual changes with ghidriff_function_detail, or read the
   rendered report with ghidriff_read_report.

A single diff of a mid-sized binary typically takes one to several minutes
because Ghidra imports and analyses every input. Pass several newer binaries to
get the chained diffs old->v2->v3, and set summary=true to also diff old->newest.
"""

#: Parsed pdiffs above this size are not kept in memory (they are re-read on demand).
CACHE_MAX_BYTES = 64 * 1024 * 1024
CACHE_MAX_ENTRIES = 3


@dataclass
class ServerState:
    settings: Settings
    runner: GhidriffRunner
    jobs: JobManager
    _cache: dict[str, tuple[float, dict[str, Any]]] = field(default_factory=dict)

    def cached_pdiff(self, path: Path) -> dict[str, Any]:
        """Load a pdiff, caching the small ones.

        Real pdiffs are large and there is no reason to hold several of them in
        memory, so only diffs below ``CACHE_MAX_BYTES`` are kept.
        """
        key = str(path)
        try:
            stat = path.stat()
        except OSError as exc:
            raise ReportError(f"pdiff not found: {path}") from exc
        mtime = stat.st_mtime
        hit = self._cache.get(key)
        if hit is not None and hit[0] == mtime:
            return hit[1]
        pdiff = load_pdiff(path)
        if stat.st_size > CACHE_MAX_BYTES:
            self._cache.pop(key, None)
            return pdiff
        while len(self._cache) >= CACHE_MAX_ENTRIES:
            self._cache.pop(next(iter(self._cache)))
        self._cache[key] = (mtime, pdiff)
        return pdiff


_state: ServerState | None = None


def get_state() -> ServerState:
    global _state
    if _state is None:
        settings = Settings.from_env()
        _state = ServerState(
            settings=settings,
            runner=GhidriffRunner(settings),
            jobs=JobManager(settings),
        )
    return _state


def reset_state(settings: Settings | None = None) -> ServerState:
    """Rebuild global state (used by tests and by ``--workspace`` overrides)."""
    global _state
    settings = settings or Settings.from_env()
    _state = ServerState(
        settings=settings,
        runner=GhidriffRunner(settings),
        jobs=JobManager(settings),
    )
    return _state


mcp = FastMCP("ghidriff", instructions=INSTRUCTIONS)


# --------------------------------------------------------------------- helpers


def _job_payload(job_id: str, *, tail: int = 0, include_request: bool = True) -> dict[str, Any]:
    state = get_state()
    try:
        job = state.jobs.get(job_id)
    except JobError as exc:
        raise ValueError(str(exc)) from exc
    return job.as_dict(include_request=include_request, tail=tail)


def _resolve_pdiff(job_id: str | None, json_path: str | None) -> tuple[dict[str, Any], Path]:
    state = get_state()
    if json_path:
        path = Path(json_path).expanduser()
        if not path.is_absolute():
            path = (state.settings.workspace / path).resolve()
        return state.cached_pdiff(path), path
    if not job_id:
        raise ValueError("Provide either job_id or json_path.")
    try:
        job = state.jobs.get(job_id)
    except JobError as exc:
        raise ValueError(str(exc)) from exc
    artifacts = discover_artifacts(job.output_dir)
    pdiff_path = next((item.json_path for item in artifacts if item.json_path), None)
    if pdiff_path is None:
        raise ValueError(
            f"Job {job_id} has no pdiff json yet (status={job.status}). "
            "Wait for the job to finish or read ghidriff_job_log."
        )
    return state.cached_pdiff(pdiff_path), pdiff_path


def _start_request(settings: Settings, run_dir: Path, kwargs: dict[str, Any]) -> DiffRequest:
    try:
        return build_request(settings, run_dir=run_dir, **kwargs)
    except (RunnerError, PathError) as exc:
        raise ValueError(str(exc)) from exc


def _ensure_workspace(workspace: Path) -> str | None:
    """Create the workspace, returning a warning instead of raising on failure.

    A read-only or missing workspace must not stop the server from starting: an
    agent can still run discovery tools and read the error from the job log.
    """
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return f"Workspace {workspace} is not usable: {exc}"
    return None


# ----------------------------------------------------------------------- tools


@mcp.tool()
async def ghidriff_environment(probe: bool = True) -> dict[str, Any]:
    """Check that Ghidra, Java and ghidriff are installed and reachable.

    Args:
        probe: also launch the ghidriff interpreter to confirm it can import
            ghidriff (adds up to a minute on a cold start).
    """
    state = get_state()
    _ensure_workspace(state.settings.workspace)
    return await asyncio.to_thread(diagnose, state.settings, probe=probe)


@mcp.tool()
async def ghidriff_start_diff(
    old_binary: Annotated[
        str,
        Field(
            description="Path to the older binary (relative paths resolve against the workspace)."
        ),
    ],
    new_binaries: Annotated[
        list[str],
        Field(
            description="One or more newer binaries, oldest first. Several entries produce chained diffs."
        ),
    ],
    engine: Annotated[
        str,
        Field(
            description="Diff engine: VersionTrackingDiff (default), SimpleDiff or StructualGraphDiff."
        ),
    ] = "VersionTrackingDiff",
    output_dir: Annotated[
        str | None,
        Field(
            description="Where to write the report and pdiff JSON. Defaults to <run_dir>/ghidriff."
        ),
    ] = None,
    project_dir: Annotated[
        str | None,
        Field(
            description="Ghidra project location. Must not contain a path element starting with '.'."
        ),
    ] = None,
    summary: Annotated[
        bool,
        Field(
            description="Also diff the oldest against the newest binary (only useful with 3+ binaries)."
        ),
    ] = False,
    side_by_side: Annotated[
        bool, Field(description="Also emit side-by-side HTML code diffs (more disk, slower).")
    ] = False,
    force_analysis: Annotated[
        bool,
        Field(
            description="Re-analyse every binary instead of reusing the Ghidra project (very slow)."
        ),
    ] = False,
    force_diff: Annotated[
        bool, Field(description="Diff even when architecture or symbols do not match.")
    ] = False,
    bsim: Annotated[
        bool | None,
        Field(
            description="Enable Ghidra BSIM function correlation (default: upstream default, on)."
        ),
    ] = None,
    bsim_full: Annotated[
        bool, Field(description="Slower but higher-quality BSIM matching.")
    ] = False,
    min_func_len: Annotated[
        int | None, Field(description="Minimum function length considered for diffing.")
    ] = None,
    max_section_funcs: Annotated[
        int | None, Field(description="Cap on functions rendered per report section.")
    ] = None,
    base_address: Annotated[
        str | None, Field(description="Base address for both programs, e.g. '0x2000'.")
    ] = None,
    no_symbols: Annotated[
        bool,
        Field(
            description=(
                "Turn symbols off for analysis. Use it for offline/air-gapped work: "
                "ghidriff otherwise queries PDB symbol servers such as Microsoft's."
            )
        ),
    ] = False,
    timeout_s: Annotated[
        float | None,
        Field(description="Kill the run after this many seconds (default: server setting, 3600)."),
    ] = None,
) -> dict[str, Any]:
    """Start a binary diff in the background and return a job id immediately.

    Raw engine pass-through arguments are deliberately not accepted here: the
    agent decides *what* to diff, the operator decides *how* the engine runs,
    through GHIDRIFF_MCP_EXTRA_ARGS.
    """
    state = get_state()
    job_id, run_dir = state.jobs.reserve()
    request = _start_request(
        state.settings,
        run_dir,
        {
            "old_binary": old_binary,
            "new_binaries": list(new_binaries),
            "engine": engine,
            "output_dir": output_dir,
            "project_dir": project_dir,
            "summary": summary,
            "side_by_side": side_by_side,
            "force_analysis": force_analysis,
            "force_diff": force_diff,
            "bsim": bsim,
            "bsim_full": bsim_full,
            "min_func_len": min_func_len,
            "max_section_funcs": max_section_funcs,
            "base_address": base_address,
            "no_symbols": no_symbols,
            "timeout_s": timeout_s,
        },
    )
    # The job id creates the run directory, so the request is resolved first and
    # the job then reuses the very same directory.
    job = await state.jobs.start(request, job_id=job_id, run_dir=run_dir)
    return {
        "job_id": job.id,
        "status": job.status,
        "output_dir": str(job.request.output_dir),
        "log_path": str(job.log_path),
        "notices": list(job.request.notices),
        "next": f"Poll ghidriff_job_status with job_id={job.id!r} until status is terminal.",
    }


@mcp.tool()
async def ghidriff_run_diff(
    old_binary: Annotated[str, Field(description="Path to the older binary.")],
    new_binaries: Annotated[
        list[str], Field(description="One or more newer binaries, oldest first.")
    ],
    engine: Annotated[
        str,
        Field(
            description="Diff engine: VersionTrackingDiff (default), SimpleDiff or StructualGraphDiff."
        ),
    ] = "VersionTrackingDiff",
    output_dir: Annotated[
        str | None, Field(description="Where to write diffs. Defaults to the job run directory.")
    ] = None,
    summary: Annotated[
        bool, Field(description="Also diff the oldest against the newest binary.")
    ] = False,
    force_analysis: Annotated[
        bool, Field(description="Re-analyse every binary instead of reusing cached analysis.")
    ] = False,
    force_diff: Annotated[
        bool, Field(description="Diff even when architecture or symbols do not match.")
    ] = False,
    no_symbols: Annotated[
        bool,
        Field(
            description=(
                "Turn symbols off for analysis. Use it for offline/air-gapped work: "
                "ghidriff otherwise queries PDB symbol servers such as Microsoft's."
            )
        ),
    ] = False,
    timeout_s: Annotated[
        float | None,
        Field(description="Overall budget in seconds (default: server setting, 3600)."),
    ] = None,
) -> dict[str, Any]:
    """Run a diff and wait for it to finish (blocking convenience wrapper).

    Prefer ghidriff_start_diff for large binaries: this call occupies the tool
    call for the whole analysis.
    """
    state = get_state()
    started = await ghidriff_start_diff(
        old_binary=old_binary,
        new_binaries=new_binaries,
        engine=engine,
        output_dir=output_dir,
        summary=summary,
        force_analysis=force_analysis,
        force_diff=force_diff,
        no_symbols=no_symbols,
        timeout_s=timeout_s,
    )
    job_id = started["job_id"]
    budget = (timeout_s if timeout_s is not None else state.settings.default_timeout_s) + 120
    await state.jobs.wait(job_id, timeout_s=budget)
    payload = _job_payload(job_id, tail=15)
    payload["tip"] = (
        "Use ghidriff_job_result for the full stats and function lists, "
        "ghidriff_job_log for the raw log."
    )
    return payload


@mcp.tool()
async def ghidriff_job_status(
    job_id: Annotated[str, Field(description="Job id returned by ghidriff_start_diff.")],
    log_tail: Annotated[int, Field(description="How many trailing log lines to include.")] = 15,
) -> dict[str, Any]:
    """Report the state of one diff job, including a short log tail."""
    return _job_payload(job_id, tail=max(0, min(log_tail, 200)), include_request=False)


@mcp.tool()
async def ghidriff_job_result(
    job_id: Annotated[str, Field(description="Job id returned by ghidriff_start_diff.")],
    max_functions: Annotated[
        int, Field(description="Cap on function names listed per category.")
    ] = 50,
    include_metadata_diff: Annotated[
        bool, Field(description="Include old/new program metadata differences.")
    ] = False,
) -> dict[str, Any]:
    """Return the structured result of a finished (or running) diff job."""
    state = get_state()
    try:
        job = state.jobs.get(job_id)
    except JobError as exc:
        raise ValueError(str(exc)) from exc

    payload = job.as_dict(include_request=False, tail=10)
    artifacts = discover_artifacts(job.output_dir)
    payload["artifacts"] = [artifact.as_dict() for artifact in artifacts]

    pdiff_path = next((item.json_path for item in artifacts if item.json_path), None)
    if pdiff_path is None:
        payload["summary"] = None
        payload["hint"] = (
            "No pdiff JSON yet. Check ghidriff_job_log; if the job failed, the log "
            "tail above usually names the cause."
        )
        return payload

    try:
        pdiff = await asyncio.to_thread(state.cached_pdiff, pdiff_path)
    except ReportError as exc:
        payload["summary"] = None
        payload["hint"] = f"pdiff JSON could not be read: {exc}"
        return payload

    summary = summarize_pdiff(pdiff, max_names=max(1, min(max_functions, 500)))
    if include_metadata_diff:
        summary["metadata_diff"] = metadata_diff(pdiff)
    payload["summary"] = summary
    return payload


@mcp.tool()
async def ghidriff_job_log(
    job_id: Annotated[str, Field(description="Job id returned by ghidriff_start_diff.")],
    tail_lines: Annotated[
        int, Field(description="Return only the last N lines (0 disables the tail).")
    ] = 100,
    start_line: Annotated[
        int | None, Field(description="Read from this 1-based line instead of the tail.")
    ] = None,
    max_lines: Annotated[
        int, Field(description="Maximum lines returned when paging with start_line.")
    ] = 200,
) -> dict[str, Any]:
    """Read the ghidriff console log of a job, tailed or paged."""
    state = get_state()
    try:
        job = state.jobs.get(job_id)
    except JobError as exc:
        raise ValueError(str(exc)) from exc

    if not job.log_path.is_file():
        return {
            "job_id": job.id,
            "status": job.status,
            "log_path": str(job.log_path),
            "content": "",
        }

    if start_line is not None:
        page = await asyncio.to_thread(
            read_text_page, job.log_path, start_line=start_line, max_lines=max_lines
        )
        page.update({"job_id": job.id, "status": job.status})
        return page

    lines = job.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = lines[-tail_lines:] if tail_lines > 0 else lines
    return {
        "job_id": job.id,
        "status": job.status,
        "log_path": str(job.log_path),
        "total_lines": len(lines),
        "returned_lines": len(tail),
        "content": "\n".join(tail),
    }


@mcp.tool()
async def ghidriff_job_cancel(
    job_id: Annotated[str, Field(description="Job id to cancel.")],
) -> dict[str, Any]:
    """Cancel a running diff job and kill its ghidriff process."""
    state = get_state()
    try:
        job = await state.jobs.cancel(job_id)
    except JobError as exc:
        raise ValueError(str(exc)) from exc
    return job.as_dict(include_request=False)


@mcp.tool()
async def ghidriff_jobs(
    limit: Annotated[int, Field(description="Maximum number of jobs returned.")] = 20,
    status: Annotated[
        str | None,
        Field(
            description="Filter by status: queued, running, succeeded, failed, cancelled, timeout."
        ),
    ] = None,
) -> dict[str, Any]:
    """List diff jobs known to this server, newest first (survives restarts)."""
    state = get_state()
    jobs = state.jobs.list(limit=max(1, min(limit, 200)), status=status)
    return {
        "workspace": str(state.settings.workspace),
        "count": len(jobs),
        "jobs": [job.as_dict(include_request=False) for job in jobs],
    }


@mcp.tool()
async def ghidriff_list_runs(
    directory: Annotated[
        str | None, Field(description="Also scan this directory for diff artefacts.")
    ] = None,
    limit: Annotated[int, Field(description="Maximum number of artefacts returned.")] = 100,
) -> dict[str, Any]:
    """List diff outputs on disk, either from the run history or a given directory."""
    state = get_state()
    result: dict[str, Any] = {"workspace": str(state.settings.workspace)}
    if directory:
        path = Path(directory).expanduser()
        if not path.is_absolute():
            path = (state.settings.workspace / path).resolve()
        result["scanned_directory"] = str(path)
        result["artifacts"] = [
            artifact.as_dict() for artifact in discover_artifacts(path)[: max(1, limit)]
        ]
    else:
        result["artifacts"] = [
            artifact.as_dict()
            for job in state.jobs.list(limit=max(1, limit))
            for artifact in discover_artifacts(job.output_dir)
        ]
    return result


@mcp.tool()
async def ghidriff_read_report(
    start_line: Annotated[int, Field(description="1-based first line to return.")] = 1,
    max_lines: Annotated[int, Field(description="Maximum number of lines to return.")] = 200,
    path: Annotated[str | None, Field(description="Explicit Markdown report path.")] = None,
    job_id: Annotated[
        str | None, Field(description="Job whose report should be read instead.")
    ] = None,
) -> dict[str, Any]:
    """Read a page of the generated Markdown diff report."""
    state = get_state()
    target: Path | None = None
    if path:
        target = Path(path).expanduser()
        if not target.is_absolute():
            target = (state.settings.workspace / target).resolve()
    elif job_id:
        try:
            job = state.jobs.get(job_id)
        except JobError as exc:
            raise ValueError(str(exc)) from exc
        artifacts = discover_artifacts(job.output_dir)
        target = next((item.md_path for item in artifacts if item.md_path), None)
        if target is None:
            raise ValueError(f"Job {job_id} has no Markdown report yet (status={job.status}).")
    else:
        raise ValueError("Provide either path or job_id.")

    page = await asyncio.to_thread(
        read_text_page, target, start_line=start_line, max_lines=max_lines
    )
    return page


@mcp.tool()
async def ghidriff_function_detail(
    name: Annotated[str, Field(description="Function name (or part of it) to inspect.")],
    job_id: Annotated[str | None, Field(description="Job to read the pdiff from.")] = None,
    json_path: Annotated[
        str | None, Field(description="Explicit pdiff JSON path (alternative to job_id).")
    ] = None,
) -> dict[str, Any]:
    """Explain one changed function: metadata, code, and the code diff if modified."""
    pdiff, source = _resolve_pdiff(job_id, json_path)
    detail = await asyncio.to_thread(function_detail, pdiff, name)
    detail["source"] = str(source)
    return detail


@mcp.tool()
async def ghidriff_search_functions(
    query: Annotated[
        str,
        Field(
            description="Substring to look for in function names (empty lists everything changed)."
        ),
    ],
    job_id: Annotated[str | None, Field(description="Job to read the pdiff from.")] = None,
    json_path: Annotated[
        str | None, Field(description="Explicit pdiff JSON path (alternative to job_id).")
    ] = None,
    kinds: Annotated[
        list[str] | None, Field(description="Restrict to added, deleted and/or modified.")
    ] = None,
    limit: Annotated[int, Field(description="Maximum number of hits.")] = 50,
) -> dict[str, Any]:
    """Search the changed functions of a diff by name."""
    pdiff, source = _resolve_pdiff(job_id, json_path)
    selected = tuple(kinds) if kinds else ("added", "deleted", "modified")
    invalid = [kind for kind in selected if kind not in ("added", "deleted", "modified")]
    if invalid:
        raise ValueError(f"Unknown kinds: {invalid}. Use added, deleted or modified.")
    hits = await asyncio.to_thread(
        search_functions, pdiff, query, kinds=selected, limit=max(1, min(limit, 500))
    )
    return {
        "query": query,
        "kinds": list(selected),
        "source": str(source),
        "count": len(hits),
        "hits": hits,
    }


@mcp.tool()
async def ghidriff_settings() -> dict[str, Any]:
    """Show the server configuration (workspace, interpreter, limits)."""
    state = get_state()
    payload = state.settings.as_dict()
    payload["workspace_warning"] = _ensure_workspace(state.settings.workspace)
    payload["environment_variables"] = {
        key: os.environ[key]
        for key in (
            "GHIDRIFF_MCP_HOME",
            "GHIDRA_INSTALL_DIR",
            "GHIDRIFF_MCP_PYTHON",
            "GHIDRIFF_MCP_COMMAND",
            "GHIDRIFF_MCP_TIMEOUT",
            "GHIDRIFF_MCP_MAX_JOBS",
            "GHIDRIFF_MCP_EXTRA_ARGS",
        )
        if key in os.environ
    }
    return payload


# ------------------------------------------------------------------ entrypoint


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ghidriff-mcp",
        description="MCP server exposing the ghidriff Ghidra binary-diffing engine.",
    )
    parser.add_argument("--workspace", help="Directory for runs, projects and diff output.")
    parser.add_argument("--ghidra-install-dir", help="Path to the extracted Ghidra folder.")
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=("stdio", "streamable-http", "sse"),
        help="MCP transport to serve (default: stdio).",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Bind address for HTTP transports.")
    parser.add_argument("--port", type=int, default=8765, help="Port for HTTP transports.")
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    parser.add_argument(
        "--check",
        action="store_true",
        help=(
            "Diagnose the Ghidra/Java/ghidriff tool chain, print the report as JSON "
            "and exit non-zero when it is not ready."
        ),
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.version:
        from . import __version__

        print(f"ghidriff-mcp {__version__}")
        return 0

    if args.workspace:
        os.environ["GHIDRIFF_MCP_HOME"] = str(Path(args.workspace).expanduser().resolve())
    if args.ghidra_install_dir:
        os.environ["GHIDRA_INSTALL_DIR"] = str(Path(args.ghidra_install_dir).expanduser().resolve())

    state = reset_state()

    if args.check:
        report = diagnose(state.settings)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        return 0 if report["ready"] else 1

    warning = _ensure_workspace(state.settings.workspace)
    if warning:
        # Never fatal: the server stays usable for discovery and diagnostics.
        print(f"ghidriff-mcp: {warning}", file=sys.stderr, flush=True)

    if args.transport != "stdio":
        mcp.settings.host = args.host
        mcp.settings.port = args.port

    mcp.run(transport=args.transport)
    return 0
