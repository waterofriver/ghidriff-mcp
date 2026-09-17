"""Runtime configuration for the ghidriff MCP server.

Everything is driven by environment variables so the server can be pointed at a
Ghidra installation, a Python interpreter that has ``ghidriff`` installed, and a
workspace directory without touching code.
"""

from __future__ import annotations

import os
import shlex
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path

ENV_WORKSPACE = "GHIDRIFF_MCP_HOME"
ENV_GHIDRA_INSTALL_DIR = "GHIDRA_INSTALL_DIR"
ENV_PYTHON = "GHIDRIFF_MCP_PYTHON"
ENV_COMMAND = "GHIDRIFF_MCP_COMMAND"
ENV_TIMEOUT = "GHIDRIFF_MCP_TIMEOUT"
ENV_MAX_JOBS = "GHIDRIFF_MCP_MAX_JOBS"
ENV_EXTRA_ARGS = "GHIDRIFF_MCP_EXTRA_ARGS"
ENV_LOG_LEVEL = "GHIDRIFF_MCP_LOG_LEVEL"

DEFAULT_WORKSPACE_DIRNAME = "ghidriff-mcp-work"
DEFAULT_TIMEOUT_S = 3600.0
DEFAULT_MAX_JOBS = 2
DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVELS = ("CRITICAL", "FATAL", "ERROR", "WARN", "WARNING", "INFO", "DEBUG", "NOTSET")


def _env_str(env: Mapping[str, str], name: str, default: str = "") -> str:
    value = env.get(name)
    if value is None:
        return default
    return value.strip()


def _env_float(env: Mapping[str, str], name: str, default: float) -> float:
    raw = _env_str(env, name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = _env_str(env, name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return value if value > 0 else default


def _split_args(raw: str) -> tuple[str, ...]:
    if not raw:
        return ()
    return tuple(shlex.split(raw, posix=os.name != "nt"))


@dataclass(frozen=True)
class Settings:
    """Immutable server settings resolved once at startup."""

    workspace: Path
    ghidra_install_dir: Path | None = None
    python_executable: str = ""
    ghidriff_command: tuple[str, ...] = ()
    default_timeout_s: float = DEFAULT_TIMEOUT_S
    max_concurrent_jobs: int = DEFAULT_MAX_JOBS
    extra_args: tuple[str, ...] = ()
    log_level: str = DEFAULT_LOG_LEVEL

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> Settings:
        env = os.environ if env is None else env

        workspace_raw = _env_str(env, ENV_WORKSPACE)
        workspace = (
            Path(workspace_raw).expanduser()
            if workspace_raw
            else Path.home() / DEFAULT_WORKSPACE_DIRNAME
        )

        ghidra_raw = _env_str(env, ENV_GHIDRA_INSTALL_DIR)
        ghidra = Path(ghidra_raw).expanduser() if ghidra_raw else None

        python = _env_str(env, ENV_PYTHON)
        command = _split_args(_env_str(env, ENV_COMMAND))
        if command and python:
            # An explicit command wins; drop the interpreter override so the two
            # knobs can never disagree.
            python = ""

        log_level = _env_str(env, ENV_LOG_LEVEL).upper() or DEFAULT_LOG_LEVEL
        if log_level not in LOG_LEVELS:
            log_level = DEFAULT_LOG_LEVEL

        return cls(
            workspace=workspace,
            ghidra_install_dir=ghidra,
            python_executable=python,
            ghidriff_command=command,
            default_timeout_s=_env_float(env, ENV_TIMEOUT, DEFAULT_TIMEOUT_S),
            max_concurrent_jobs=_env_int(env, ENV_MAX_JOBS, DEFAULT_MAX_JOBS),
            extra_args=_split_args(_env_str(env, ENV_EXTRA_ARGS)),
            log_level=log_level,
        )

    def with_workspace(self, workspace: Path) -> Settings:
        return replace(self, workspace=workspace)

    @property
    def runs_dir(self) -> Path:
        return self.workspace / "runs"

    @property
    def interpreter(self) -> str:
        """Interpreter used to launch ghidriff when no explicit command is set."""
        return self.python_executable or _current_python()

    def as_dict(self) -> dict[str, object]:
        return {
            "workspace": str(self.workspace),
            "runs_dir": str(self.runs_dir),
            "ghidra_install_dir": str(self.ghidra_install_dir) if self.ghidra_install_dir else None,
            "python_executable": self.python_executable or None,
            "resolved_interpreter": self.interpreter,
            "ghidriff_command": list(self.ghidriff_command) or None,
            "default_timeout_s": self.default_timeout_s,
            "max_concurrent_jobs": self.max_concurrent_jobs,
            "extra_args": list(self.extra_args),
            "log_level": self.log_level,
        }


def _current_python() -> str:
    import sys

    return sys.executable or "python"
