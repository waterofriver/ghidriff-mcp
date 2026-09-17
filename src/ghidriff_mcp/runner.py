"""Building and running ghidriff command lines.

The server drives the ``ghidriff`` CLI as a child process rather than importing
it, for three reasons: the JVM it starts through PyGhidra stays isolated, a
crash cannot take the MCP server down with it, and cancelling a job is just a
matter of killing one process.

Upstream quirk worth remembering: ``--summary`` is declared as a value-taking
option, so a bare ``--summary`` is an argparse error; it must be passed as
``--summary True``.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

from .config import Settings
from .paths import resolve_binary, resolve_path

#: Engines shipped by ghidriff 1.x. The misspelling of ``StructualGraphDiff``
#: is upstream's; the correctly spelled name is accepted as an alias.
ENGINES = ("VersionTrackingDiff", "SimpleDiff", "StructualGraphDiff")
ENGINE_ALIASES = {"StructuralGraphDiff": "StructualGraphDiff"}

TAIL_LINES = 40


class RunnerError(ValueError):
    """Raised when a diff request cannot be turned into a valid command."""


@dataclass(frozen=True)
class DiffRequest:
    """A validated, fully resolved diff request."""

    old: Path
    new: tuple[Path, ...]
    output_dir: Path
    project_dir: Path
    engine: str = "VersionTrackingDiff"
    project_name: str = "ghidriff"
    symbols_dir: Path | None = None
    gzfs_dir: Path | None = None
    base_address: str | None = None
    min_func_len: int | None = None
    threaded: bool = True
    force_analysis: bool = False
    force_diff: bool = False
    no_symbols: bool = False
    bsim: bool | None = None
    bsim_full: bool = False
    use_calling_counts: bool = False
    summary: bool = False
    side_by_side: bool = False
    max_section_funcs: int | None = None
    md_title: str | None = None
    max_ram_percent: float | None = None
    jvm_args: str | None = None
    log_level: str = "INFO"
    verbose_analysis: bool = False
    extra_args: tuple[str, ...] = ()
    timeout_s: float | None = None
    notices: tuple[str, ...] = ()

    def with_updates(self, **changes: Any) -> DiffRequest:
        return replace(self, **changes)

    def as_dict(self) -> dict[str, Any]:
        return {
            "old": str(self.old),
            "new": [str(path) for path in self.new],
            "output_dir": str(self.output_dir),
            "project_dir": str(self.project_dir),
            "engine": self.engine,
            "project_name": self.project_name,
            "symbols_dir": str(self.symbols_dir) if self.symbols_dir else None,
            "gzfs_dir": str(self.gzfs_dir) if self.gzfs_dir else None,
            "base_address": self.base_address,
            "min_func_len": self.min_func_len,
            "threaded": self.threaded,
            "force_analysis": self.force_analysis,
            "force_diff": self.force_diff,
            "no_symbols": self.no_symbols,
            "bsim": self.bsim,
            "bsim_full": self.bsim_full,
            "use_calling_counts": self.use_calling_counts,
            "summary": self.summary,
            "side_by_side": self.side_by_side,
            "max_section_funcs": self.max_section_funcs,
            "md_title": self.md_title,
            "max_ram_percent": self.max_ram_percent,
            "jvm_args": self.jvm_args,
            "log_level": self.log_level,
            "verbose_analysis": self.verbose_analysis,
            "extra_args": list(self.extra_args),
            "timeout_s": self.timeout_s,
            "notices": list(self.notices),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiffRequest:
        return cls(
            old=Path(data["old"]),
            new=tuple(Path(item) for item in data.get("new", ())),
            output_dir=Path(data["output_dir"]),
            project_dir=Path(data["project_dir"]),
            engine=data.get("engine", "VersionTrackingDiff"),
            project_name=data.get("project_name", "ghidriff"),
            symbols_dir=Path(data["symbols_dir"]) if data.get("symbols_dir") else None,
            gzfs_dir=Path(data["gzfs_dir"]) if data.get("gzfs_dir") else None,
            base_address=data.get("base_address"),
            min_func_len=data.get("min_func_len"),
            threaded=bool(data.get("threaded", True)),
            force_analysis=bool(data.get("force_analysis", False)),
            force_diff=bool(data.get("force_diff", False)),
            no_symbols=bool(data.get("no_symbols", False)),
            bsim=data.get("bsim"),
            bsim_full=bool(data.get("bsim_full", False)),
            use_calling_counts=bool(data.get("use_calling_counts", False)),
            summary=bool(data.get("summary", False)),
            side_by_side=bool(data.get("side_by_side", False)),
            max_section_funcs=data.get("max_section_funcs"),
            md_title=data.get("md_title"),
            max_ram_percent=data.get("max_ram_percent"),
            jvm_args=data.get("jvm_args"),
            log_level=data.get("log_level", "INFO"),
            verbose_analysis=bool(data.get("verbose_analysis", False)),
            extra_args=tuple(data.get("extra_args", ())),
            timeout_s=data.get("timeout_s"),
            notices=tuple(data.get("notices", ())),
        )


@dataclass
class ProcessOutcome:
    returncode: int
    command: list[str]
    log_path: Path
    duration_s: float
    timed_out: bool = False
    cancelled: bool = False
    tail: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and not self.cancelled

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 3),
            "timed_out": self.timed_out,
            "cancelled": self.cancelled,
            "command": self.command,
            "log_path": str(self.log_path),
        }


def normalize_engine(engine: str | None) -> str:
    name = (engine or "VersionTrackingDiff").strip()
    name = ENGINE_ALIASES.get(name, name)
    if name not in ENGINES:
        raise RunnerError(f"Unknown engine {engine!r}. Choose one of: {', '.join(ENGINES)}.")
    return name


def build_request(
    settings: Settings,
    *,
    old_binary: str,
    new_binaries: list[str] | tuple[str, ...],
    run_dir: Path,
    engine: str | None = None,
    output_dir: str | None = None,
    project_dir: str | None = None,
    project_name: str = "ghidriff",
    symbols_dir: str | None = None,
    gzfs_dir: str | None = None,
    base_address: str | None = None,
    min_func_len: int | None = None,
    threaded: bool = True,
    force_analysis: bool = False,
    force_diff: bool = False,
    no_symbols: bool = False,
    bsim: bool | None = None,
    bsim_full: bool = False,
    use_calling_counts: bool = False,
    summary: bool = False,
    side_by_side: bool = False,
    max_section_funcs: int | None = None,
    md_title: str | None = None,
    max_ram_percent: float | None = None,
    jvm_args: str | None = None,
    log_level: str = "INFO",
    verbose_analysis: bool = False,
    extra_args: list[str] | tuple[str, ...] = (),
    timeout_s: float | None = None,
) -> DiffRequest:
    """Resolve and validate a caller-supplied request against the workspace."""
    base = settings.workspace
    old_path = resolve_binary(old_binary, base=base)

    if not new_binaries:
        raise RunnerError("At least one new binary is required.")
    new_paths = tuple(resolve_binary(item, base=base) for item in new_binaries)
    if old_path in new_paths:
        raise RunnerError("The old binary must differ from the new binaries.")

    resolved_output = resolve_path(output_dir, base=base) if output_dir else run_dir / "ghidriff"
    resolved_project = (
        resolve_path(project_dir, base=base) if project_dir else run_dir / "ghidra_projects"
    )

    notices: list[str] = []
    if settings.ghidra_install_dir is None:
        notices.append(
            "GHIDRA_INSTALL_DIR is not set on this server; ghidriff will have to find "
            "Ghidra on its own. Run ghidriff_environment for a full diagnosis."
        )

    return DiffRequest(
        old=old_path,
        new=new_paths,
        output_dir=resolved_output,
        project_dir=resolved_project,
        engine=normalize_engine(engine),
        project_name=project_name or "ghidriff",
        symbols_dir=resolve_path(symbols_dir, base=run_dir) if symbols_dir else None,
        gzfs_dir=resolve_path(gzfs_dir, base=run_dir) if gzfs_dir else None,
        base_address=str(base_address) if base_address is not None else None,
        min_func_len=min_func_len,
        threaded=threaded,
        force_analysis=force_analysis,
        force_diff=force_diff,
        no_symbols=no_symbols,
        bsim=bsim,
        bsim_full=bsim_full,
        use_calling_counts=use_calling_counts,
        summary=summary,
        side_by_side=side_by_side,
        max_section_funcs=max_section_funcs,
        md_title=md_title,
        max_ram_percent=max_ram_percent,
        jvm_args=jvm_args,
        log_level=log_level.upper(),
        verbose_analysis=verbose_analysis,
        extra_args=tuple(extra_args) + settings.extra_args,
        timeout_s=timeout_s if timeout_s is not None else settings.default_timeout_s,
        notices=tuple(notices),
    )


def build_command(settings: Settings, request: DiffRequest) -> list[str]:
    """Translate a request into an argv list for ghidriff."""
    if settings.ghidriff_command:
        command = list(settings.ghidriff_command)
    else:
        command = [settings.interpreter, "-m", "ghidriff"]

    command.append(str(request.old))
    command.extend(str(path) for path in request.new)

    # Absolute paths only: Ghidra rejects project locations containing a path
    # element that starts with '.', and ghidriff resolves the project/symbols/gzfs
    # defaults relative to the output path.
    command += ["-o", str(request.output_dir)]
    command += ["-p", str(request.project_dir)]
    command += ["--project-name", request.project_name]
    command += ["--engine", request.engine]
    command += ["--log-level", request.log_level]

    command.append("--threaded" if request.threaded else "--no-threaded")
    if request.force_analysis:
        command.append("--force-analysis")
    if request.force_diff:
        command.append("--force-diff")
    if request.no_symbols:
        command.append("--no-symbols")
    if request.bsim is not None:
        command.append("--bsim" if request.bsim else "--no-bsim")
    if request.bsim_full:
        command.append("--bsim-full")
    if request.use_calling_counts:
        command.append("--use-calling-counts")
    if request.side_by_side:
        command.append("--sxs")
    if request.summary:
        # Upstream declares --summary as a value-taking option, so the bare flag
        # would fail to parse; a non-empty value is what makes it truthy.
        command += ["--summary", "True"]
    if request.verbose_analysis:
        command.append("--va")
    if request.min_func_len is not None:
        command += ["--min-func-len", str(request.min_func_len)]
    if request.max_section_funcs is not None:
        command += ["--max-section-funcs", str(request.max_section_funcs)]
    if request.md_title:
        command += ["--md-title", request.md_title]
    if request.max_ram_percent is not None:
        command += ["--max-ram-percent", str(request.max_ram_percent)]
    if request.base_address:
        command += ["--ba", request.base_address]
    if request.jvm_args:
        command += ["--jvm-args", request.jvm_args]
    if request.symbols_dir:
        command += ["-s", str(request.symbols_dir)]
    if request.gzfs_dir:
        command += ["-g", str(request.gzfs_dir)]

    command.extend(request.extra_args)
    return command


def build_env(settings: Settings, extra: dict[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ)
    if settings.ghidra_install_dir is not None:
        env["GHIDRA_INSTALL_DIR"] = str(settings.ghidra_install_dir)
    if extra:
        env.update(extra)
    return env


def read_tail(path: Path, lines: int = TAIL_LINES) -> list[str]:
    """Return the last ``lines`` lines of ``path``, ignoring read errors."""
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            content = handle.readlines()
    except OSError:
        return []
    return [line.rstrip("\n") for line in content[-lines:]]


class GhidriffRunner:
    """Thin async wrapper around the ghidriff CLI."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def prepare_dirs(self, request: DiffRequest) -> None:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        request.project_dir.mkdir(parents=True, exist_ok=True)
        for extra in (request.symbols_dir, request.gzfs_dir):
            if extra is not None:
                extra.mkdir(parents=True, exist_ok=True)

    async def run(
        self,
        request: DiffRequest,
        *,
        log_path: Path,
        on_process: Any = None,
    ) -> ProcessOutcome:
        """Run ghidriff, writing its combined output into ``log_path``.

        The child inherits a file handle for stdout/stderr rather than a pipe.
        That keeps the output streamable (the log is on disk and the status
        tools tail it) and, unlike ``stdout=PIPE``, works in restricted
        environments where asyncio's Windows transport cannot create the named
        pipes it uses for pipes.
        """
        command = build_command(self.settings, request)
        env = build_env(self.settings)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        started = time.monotonic()
        timed_out = False
        cancelled = False

        with log_path.open("w", encoding="utf-8", errors="replace") as log:
            log.write(f"$ {' '.join(command)}\n")
            log.flush()

            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=log,
                stderr=log,
                cwd=str(request.output_dir),
                env=env,
            )
            if on_process is not None:
                with contextlib.suppress(Exception):
                    on_process(process)

            try:
                if request.timeout_s:
                    await asyncio.wait_for(process.wait(), timeout=request.timeout_s)
                else:
                    await process.wait()
            except asyncio.TimeoutError:
                timed_out = True
                await self._kill(process)
            except asyncio.CancelledError:
                cancelled = True
                await self._kill(process)
                raise

        return ProcessOutcome(
            returncode=process.returncode if process.returncode is not None else -1,
            command=command,
            log_path=log_path,
            duration_s=time.monotonic() - started,
            timed_out=timed_out,
            cancelled=cancelled,
            tail=read_tail(log_path),
        )

    @staticmethod
    async def _kill(process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        with contextlib.suppress(ProcessLookupError, OSError):
            process.kill()
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(process.wait(), timeout=30)
