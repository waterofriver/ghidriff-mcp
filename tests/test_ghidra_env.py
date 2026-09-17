"""Tests for Ghidra/Java/ghidriff discovery."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from ghidriff_mcp.config import Settings
from ghidriff_mcp.ghidra_env import (
    _next_steps,
    _probe_ghidriff,
    diagnose,
    find_ghidra_install,
    ghidra_version,
    java_executable,
    java_version,
)


def _make_ghidra(root: Path, version: str = "12.1.3") -> Path:
    (root / "Ghidra").mkdir(parents=True)
    (root / "Ghidra" / "application.properties").write_text(
        f"application.name=Ghidra\napplication.version={version}\n", encoding="utf-8"
    )
    (root / "support").mkdir()
    (root / "support" / "analyzeHeadless").write_text("#!/bin/sh\n", encoding="utf-8")
    return root


def test_ghidra_version_from_application_properties(tmp_path: Path) -> None:
    install = _make_ghidra(tmp_path / "ghidra_12.1.3_PUBLIC")
    assert ghidra_version(install) == "12.1.3"
    assert ghidra_version(tmp_path / "nowhere") is None


def test_find_ghidra_install_prefers_the_explicit_path(tmp_path: Path) -> None:
    install = _make_ghidra(tmp_path / "explicit")
    found = find_ghidra_install(install, env={}, auto_discover=False)
    assert found is not None
    assert found.path == install
    assert found.version == "12.1.3"
    assert found.source == "GHIDRA_INSTALL_DIR"


def test_find_ghidra_install_uses_the_environment(tmp_path: Path) -> None:
    install = _make_ghidra(tmp_path / "from-env")
    found = find_ghidra_install(None, env={"GHIDRA_INSTALL_DIR": str(install)}, auto_discover=False)
    assert found is not None
    assert found.path == install
    assert found.source == "environment"


def test_find_ghidra_install_returns_none_for_a_non_ghidra_dir(tmp_path: Path) -> None:
    empty = tmp_path / "not-ghidra"
    empty.mkdir()
    assert find_ghidra_install(empty, env={}, auto_discover=False) is None


def test_find_ghidra_install_ignores_missing_explicit_path(tmp_path: Path) -> None:
    assert find_ghidra_install(tmp_path / "missing", env={}, auto_discover=False) is None


def test_java_executable_prefers_java_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    java_home = tmp_path / "jdk"
    binary = java_home / "bin" / ("java.exe" if __import__("os").name == "nt" else "java")
    binary.parent.mkdir(parents=True)
    binary.write_text("", encoding="utf-8")

    found = java_executable(None, env={"JAVA_HOME": str(java_home)})
    assert found == str(binary)


def test_java_executable_falls_back_to_path(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("ghidriff_mcp.ghidra_env.shutil.which", lambda name: f"/usr/bin/{name}")
    assert java_executable(None, env={}) == "/usr/bin/java"


def test_diagnose_reports_structure(settings: Settings) -> None:
    report = diagnose(settings, env={}, probe=False)
    assert set(report) == {"ready", "settings", "checks", "problems", "next_steps"}
    assert set(report["checks"]) == {"ghidra", "java", "ghidriff"}
    assert report["checks"]["ghidriff"]["detail"] == "probe skipped"
    assert isinstance(report["ready"], bool)
    if not report["ready"]:
        assert report["problems"]


def test_diagnose_accepts_a_configured_ghidra(tmp_path: Path, settings: Settings) -> None:
    install = _make_ghidra(tmp_path / "ghidra_12.1.3_PUBLIC")
    configured = Settings(
        workspace=settings.workspace,
        ghidra_install_dir=install,
        ghidriff_command=("ghidriff",),
    )
    report = diagnose(configured, env={}, probe=False)
    assert report["checks"]["ghidra"]["ok"] is True
    assert report["checks"]["ghidra"]["version"] == "12.1.3"
    assert str(install) in report["checks"]["ghidra"]["detail"]


def test_next_steps_cover_every_missing_piece() -> None:
    checks = {
        "ghidra": {"ok": False, "detail": "missing"},
        "java": {"ok": False, "detail": "missing"},
        "ghidriff": {"ok": False, "detail": "missing"},
    }
    steps = _next_steps(checks)
    assert len(steps) == 3
    assert any("GHIDRA_INSTALL_DIR" in step for step in steps)
    assert any("JDK" in step for step in steps)
    assert any("GHIDRIFF_MCP_PYTHON" in step for step in steps)

    assert _next_steps({key: {"ok": True} for key in checks}) == []


def test_probe_ghidriff_reports_a_missing_interpreter(tmp_path: Path) -> None:
    settings = Settings(workspace=tmp_path, python_executable="definitely-not-a-real-python")
    report = _probe_ghidriff(settings)
    assert report.ok is False
    assert "interpreter not found" in report.detail


def test_probe_ghidriff_asks_the_interpreter_to_import_ghidriff(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: the ``-c`` script belongs to the interpreter, not to ghidriff."""
    seen: dict[str, list[str]] = {}

    class FakeProc:
        returncode = 0
        stdout = "1.0.0\n"
        stderr = ""

    def fake_run(command, **kwargs):
        seen["command"] = list(command)
        return FakeProc()

    monkeypatch.setattr("ghidriff_mcp.ghidra_env.subprocess.run", fake_run)
    settings = Settings(workspace=tmp_path, python_executable="python-x")

    report = _probe_ghidriff(settings)

    assert report.ok is True
    assert report.detail == "ghidriff 1.0.0 importable by python-x"
    assert report.extra["version"] == "1.0.0"
    assert seen["command"][0] == "python-x"
    assert seen["command"][1] == "-c"
    assert "importlib.metadata" in seen["command"][2]
    assert "-m" not in seen["command"]


def test_probe_ghidriff_reports_an_unimportable_package(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeProc:
        returncode = 1
        stdout = ""
        stderr = "ModuleNotFoundError: No module named 'ghidriff'"

    monkeypatch.setattr(
        "ghidriff_mcp.ghidra_env.subprocess.run", lambda *args, **kwargs: FakeProc()
    )
    settings = Settings(workspace=tmp_path, python_executable="python-x")

    report = _probe_ghidriff(settings)

    assert report.ok is False
    assert "not importable by python-x" in report.detail
    assert "ModuleNotFoundError" in report.detail


def test_probe_ghidriff_runs_a_custom_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: dict[str, list[str]] = {}

    class FakeProc:
        returncode = 0
        stdout = "ghidriff - A Command Line Ghidra Binary Diffing Engine\n"
        stderr = ""

    def fake_run(command, **kwargs):
        seen["command"] = list(command)
        return FakeProc()

    monkeypatch.setattr("ghidriff_mcp.ghidra_env.subprocess.run", fake_run)
    settings = Settings(workspace=tmp_path, ghidriff_command=("ghidriff", "--log-level", "WARN"))

    report = _probe_ghidriff(settings)

    assert report.ok is True
    assert "custom command works" in report.detail
    assert seen["command"] == ["ghidriff", "--log-level", "WARN", "--help"]


def test_probe_ghidriff_flags_a_broken_custom_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeProc:
        returncode = 2
        stdout = ""
        stderr = "usage: ghidriff ...\nboom"

    monkeypatch.setattr(
        "ghidriff_mcp.ghidra_env.subprocess.run", lambda *args, **kwargs: FakeProc()
    )
    settings = Settings(workspace=tmp_path, ghidriff_command=("ghidriff",))

    report = _probe_ghidriff(settings)

    assert report.ok is False
    assert "custom command failed (exit 2)" in report.detail
    assert "boom" in report.detail


def test_probe_ghidriff_reports_a_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_timeout(command, **kwargs):
        raise subprocess.TimeoutExpired(cmd=command, timeout=kwargs.get("timeout", 1))

    monkeypatch.setattr("ghidriff_mcp.ghidra_env.subprocess.run", raise_timeout)

    interpreter_probe = _probe_ghidriff(Settings(workspace=tmp_path, python_executable="python-x"))
    assert interpreter_probe.ok is False
    assert "did not answer within" in interpreter_probe.detail

    command_probe = _probe_ghidriff(Settings(workspace=tmp_path, ghidriff_command=("ghidriff",)))
    assert command_probe.ok is False
    assert "did not answer within" in command_probe.detail


def test_probe_ghidriff_reports_a_missing_custom_command(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def raise_missing(command, **kwargs):
        raise FileNotFoundError(command[0])

    monkeypatch.setattr("ghidriff_mcp.ghidra_env.subprocess.run", raise_missing)
    report = _probe_ghidriff(Settings(workspace=tmp_path, ghidriff_command=("ghidriff",)))
    assert report.ok is False
    assert "command not found" in report.detail


def test_probes_never_inherit_the_protocol_stream(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression: a probe inheriting stdin can deadlock an MCP stdio server."""
    seen: list[dict] = []

    class FakeProc:
        returncode = 0
        stdout = "1.0.0\n"
        stderr = ""

    def fake_run(command, **kwargs):
        seen.append(kwargs)
        return FakeProc()

    monkeypatch.setattr("ghidriff_mcp.ghidra_env.subprocess.run", fake_run)

    _probe_ghidriff(Settings(workspace=tmp_path, python_executable="python-x"))
    _probe_ghidriff(Settings(workspace=tmp_path, ghidriff_command=("ghidriff",)))
    java_version("java-x")

    assert len(seen) == 3
    for kwargs in seen:
        assert kwargs.get("stdin") is subprocess.DEVNULL
