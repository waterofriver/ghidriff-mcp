"""Path resolution and Ghidra path-rule validation.

Two rules matter when driving ghidriff from an agent:

* Relative paths coming from a tool call are resolved against the workspace, so
  an agent never has to know the absolute layout of the machine.
* Ghidra refuses project locations containing a path element that starts with a
  dot (``java.lang.IllegalArgumentException: Path element starting with '.' is
  not permitted``). ghidriff uses this path directly, so the server validates it
  up front and falls back to a sanitised location instead of failing after a
  multi-minute import.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

_MISSING = "Path does not exist: {path}"
_NOT_A_FILE = "Path is not a regular file: {path}"


class PathError(ValueError):
    """Raised when a caller-supplied path cannot be used."""


def resolve_path(raw: str | Path, *, base: Path) -> Path:
    """Expand and resolve ``raw`` against ``base`` without requiring existence."""
    if raw is None:
        raise PathError("A path is required but none was provided.")
    text = str(raw).strip().strip('"').strip("'")
    if not text:
        raise PathError("A path is required but an empty string was provided.")
    path = Path(text).expanduser()
    if not path.is_absolute():
        path = base / path
    return Path(path).resolve()


def resolve_binary(raw: str | Path, *, base: Path) -> Path:
    """Resolve a caller-supplied binary path and require it to be a real file."""
    path = resolve_path(raw, base=base)
    if not path.exists():
        raise PathError(_MISSING.format(path=path))
    if not path.is_file():
        raise PathError(_NOT_A_FILE.format(path=path))
    return path


def has_dot_component(path: Path) -> str | None:
    """Return the first path element starting with ``.`` (Ghidra rejects it)."""
    for part in path.parts:
        if part in (path.anchor, "", "/", "\\"):
            continue
        if part.startswith(".") and part not in (".", ".."):
            return part
    return None


def is_ghidra_safe(path: Path) -> bool:
    return has_dot_component(path) is None


def ghidra_safe_project_dir(preferred: Path, *, fallback_key: str) -> tuple[Path, str | None]:
    """Return a project directory Ghidra will accept.

    ``preferred`` is used when it is safe. Otherwise a location under the system
    temp directory is returned together with a human-readable warning, because
    the Ghidra project is only an intermediate cache and can live elsewhere.
    """
    if is_ghidra_safe(preferred):
        return preferred, None
    offender = has_dot_component(preferred)
    fallback = Path(tempfile.gettempdir()) / "ghidriff-mcp" / "projects" / fallback_key
    warning = (
        f"Ghidra rejects project locations containing a path element that starts "
        f"with '.' (found {offender!r} in {preferred}). Using {fallback} for the "
        f"Ghidra project instead. Set GHIDRIFF_MCP_HOME to a dot-free directory to "
        f"keep projects next to their diff output."
    )
    return fallback, warning
