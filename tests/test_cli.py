"""Tests for the command-line entry point."""

from __future__ import annotations

import json

import ghidriff_mcp.server as server_module
from ghidriff_mcp.config import Settings


def test_parse_args_defaults() -> None:
    args = server_module._parse_args([])
    assert args.transport == "stdio"
    assert args.host == "127.0.0.1"
    assert args.port == 8765
    assert args.check is False
    assert args.version is False


def test_parse_args_accepts_overrides() -> None:
    args = server_module._parse_args(
        [
            "--transport",
            "streamable-http",
            "--host",
            "0.0.0.0",
            "--port",
            "9001",
            "--workspace",
            "/tmp/ws",
            "--ghidra-install-dir",
            "/opt/ghidra",
        ]
    )
    assert args.transport == "streamable-http"
    assert args.host == "0.0.0.0"
    assert args.port == 9001
    assert args.workspace == "/tmp/ws"
    assert args.ghidra_install_dir == "/opt/ghidra"


def test_version_flag(capsys) -> None:
    assert server_module.main(["--version"]) == 0
    assert "ghidriff-mcp" in capsys.readouterr().out


def test_check_flag_exits_zero_when_ready(monkeypatch, capsys, settings: Settings) -> None:
    server_module.reset_state(settings)
    monkeypatch.setattr(
        server_module,
        "diagnose",
        lambda *args, **kwargs: {"ready": True, "problems": [], "checks": {}},
    )

    assert server_module.main(["--check"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ready"] is True


def test_check_flag_exits_nonzero_when_not_ready(monkeypatch, capsys, settings: Settings) -> None:
    server_module.reset_state(settings)
    monkeypatch.setattr(
        server_module,
        "diagnose",
        lambda *args, **kwargs: {"ready": False, "problems": ["ghidra missing"], "checks": {}},
    )

    assert server_module.main(["--check"]) == 1
    payload = json.loads(capsys.readouterr().out)
    assert payload["problems"] == ["ghidra missing"]


def test_workspace_flag_sets_the_environment(monkeypatch, tmp_path, settings: Settings) -> None:
    server_module.reset_state(settings)
    monkeypatch.setattr(
        server_module,
        "diagnose",
        lambda *args, **kwargs: {"ready": True, "problems": [], "checks": {}},
    )
    target = tmp_path / "chosen-workspace"

    assert server_module.main(["--check", "--workspace", str(target)]) == 0
    assert server_module.get_state().settings.workspace == target.resolve()
