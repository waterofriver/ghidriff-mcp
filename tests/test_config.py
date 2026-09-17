"""Tests for environment-driven settings."""

from __future__ import annotations

from pathlib import Path

from ghidriff_mcp.config import Settings


def test_defaults_without_environment() -> None:
    settings = Settings.from_env({})
    assert settings.workspace == Path.home() / "ghidriff-mcp-work"
    assert settings.ghidra_install_dir is None
    assert settings.ghidriff_command == ()
    assert settings.max_concurrent_jobs == 2
    assert settings.runs_dir == settings.workspace / "runs"
    assert settings.interpreter  # falls back to the current interpreter


def test_reads_every_supported_variable(tmp_path: Path) -> None:
    env = {
        "GHIDRIFF_MCP_HOME": str(tmp_path / "ws"),
        "GHIDRA_INSTALL_DIR": str(tmp_path / "ghidra"),
        "GHIDRIFF_MCP_PYTHON": "/usr/bin/python3.12",
        "GHIDRIFF_MCP_TIMEOUT": "120",
        "GHIDRIFF_MCP_MAX_JOBS": "4",
        "GHIDRIFF_MCP_EXTRA_ARGS": "--bsim --no-symbols",
        "GHIDRIFF_MCP_LOG_LEVEL": "debug",
    }
    settings = Settings.from_env(env)

    assert settings.workspace == tmp_path / "ws"
    assert settings.ghidra_install_dir == tmp_path / "ghidra"
    assert settings.python_executable == "/usr/bin/python3.12"
    assert settings.interpreter == "/usr/bin/python3.12"
    assert settings.default_timeout_s == 120.0
    assert settings.max_concurrent_jobs == 4
    assert settings.extra_args == ("--bsim", "--no-symbols")
    assert settings.log_level == "DEBUG"


def test_explicit_command_wins_over_interpreter(tmp_path: Path) -> None:
    settings = Settings.from_env(
        {
            "GHIDRIFF_MCP_HOME": str(tmp_path),
            "GHIDRIFF_MCP_COMMAND": "ghidriff --log-level WARN",
            "GHIDRIFF_MCP_PYTHON": "/usr/bin/python3.12",
        }
    )
    assert settings.ghidriff_command == ("ghidriff", "--log-level", "WARN")
    assert settings.python_executable == ""


def test_invalid_numbers_fall_back_to_defaults(tmp_path: Path) -> None:
    settings = Settings.from_env(
        {
            "GHIDRIFF_MCP_HOME": str(tmp_path),
            "GHIDRIFF_MCP_TIMEOUT": "not-a-number",
            "GHIDRIFF_MCP_MAX_JOBS": "-3",
            "GHIDRIFF_MCP_LOG_LEVEL": "SHOUTING",
        }
    )
    assert settings.default_timeout_s == 3600.0
    assert settings.max_concurrent_jobs == 2
    assert settings.log_level == "INFO"


def test_workspace_can_be_overridden(tmp_path: Path) -> None:
    settings = Settings.from_env({"GHIDRIFF_MCP_HOME": str(tmp_path / "a")})
    moved = settings.with_workspace(tmp_path / "b")
    assert moved.workspace == tmp_path / "b"
    assert settings.workspace == tmp_path / "a"


def test_as_dict_is_json_friendly(tmp_path: Path) -> None:
    settings = Settings.from_env({"GHIDRIFF_MCP_HOME": str(tmp_path)})
    payload = settings.as_dict()
    assert payload["workspace"] == str(tmp_path)
    assert isinstance(payload["resolved_interpreter"], str)
    assert payload["ghidriff_command"] is None
