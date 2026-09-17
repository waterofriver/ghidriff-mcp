"""Tests for path resolution and Ghidra's dot-directory rule."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghidriff_mcp.paths import (
    PathError,
    ghidra_safe_project_dir,
    has_dot_component,
    is_ghidra_safe,
    resolve_binary,
    resolve_path,
)


def test_resolve_relative_against_base(tmp_path: Path) -> None:
    base = tmp_path / "ws"
    base.mkdir()
    assert resolve_path("bins/old.exe", base=base) == (base / "bins" / "old.exe").resolve()


def test_resolve_absolute_is_untouched(tmp_path: Path) -> None:
    target = (tmp_path / "somewhere" / "old.exe").resolve()
    assert resolve_path(target, base=tmp_path) == target


def test_resolve_rejects_empty(tmp_path: Path) -> None:
    with pytest.raises(PathError):
        resolve_path("   ", base=tmp_path)


def test_resolve_binary_requires_file(tmp_path: Path) -> None:
    with pytest.raises(PathError, match="does not exist"):
        resolve_binary("missing.exe", base=tmp_path)

    directory = tmp_path / "adir"
    directory.mkdir()
    with pytest.raises(PathError, match="not a regular file"):
        resolve_binary("adir", base=tmp_path)


def test_resolve_binary_strips_quotes(tmp_path: Path) -> None:
    binary = tmp_path / "a b.exe"
    binary.write_bytes(b"MZ")
    assert resolve_binary(f'"{binary}"', base=tmp_path) == binary


@pytest.mark.parametrize(
    ("path", "offender"),
    [
        ("workspace/.scratch/bins", ".scratch"),
        (".hidden", ".hidden"),
    ],
)
def test_has_dot_component_flags_hidden_dirs(path: str, offender: str) -> None:
    assert has_dot_component(Path(path)) == offender


def test_has_dot_component_ignores_relative_markers() -> None:
    assert has_dot_component(Path("workspace/work/bins")) is None
    assert is_ghidra_safe(Path("workspace/work/bins"))


def test_ghidra_safe_project_dir_keeps_safe_path(tmp_path: Path) -> None:
    preferred = tmp_path / "runs" / "1" / "ghidra_projects"
    resolved, warning = ghidra_safe_project_dir(preferred, fallback_key="run-1")
    assert resolved == preferred
    assert warning is None


def test_ghidra_safe_project_dir_falls_back_for_dot_path(tmp_path: Path) -> None:
    preferred = tmp_path / ".scratch" / "ghidra_projects"
    resolved, warning = ghidra_safe_project_dir(preferred, fallback_key="run-1")
    assert resolved != preferred
    assert ".scratch" not in str(resolved)
    assert warning is not None and "Path element" not in warning
    assert "GHIDRIFF_MCP_HOME" in warning
