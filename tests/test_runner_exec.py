"""Tests that exercise the real subprocess path in GhidriffRunner.

The fake runner used by the job tests never spawns anything, so these tests pin
down the parts that only exist for real: output redirection into the log file,
timeouts that must kill the child, and launch failures.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ghidriff_mcp.config import Settings
from ghidriff_mcp.runner import GhidriffRunner, build_request, read_tail


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    directory = tmp_path / "run"
    directory.mkdir()
    return directory


def _request(settings: Settings, run_dir: Path, fake_binaries, timeout_s: float | None = None):
    old, new = fake_binaries
    return build_request(
        settings,
        old_binary=str(old),
        new_binaries=[str(new)],
        run_dir=run_dir,
        timeout_s=timeout_s,
    )


def _settings(workspace: Path, command: tuple[str, ...]) -> Settings:
    return Settings(workspace=workspace, ghidriff_command=command, default_timeout_s=30.0)


async def test_child_output_lands_in_the_log(tmp_path: Path, fake_binaries) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    script = "import sys; print('to stdout'); print('to stderr', file=sys.stderr)"
    settings = _settings(workspace, (sys.executable, "-c", script))
    runner = GhidriffRunner(settings)
    request = _request(settings, workspace / "run", fake_binaries)
    runner.prepare_dirs(request)

    outcome = await runner.run(request, log_path=workspace / "run" / "ghidriff.log")

    assert outcome.ok is True
    assert outcome.returncode == 0
    assert not outcome.timed_out and not outcome.cancelled
    content = outcome.log_path.read_text(encoding="utf-8")
    assert "to stdout" in content
    assert "to stderr" in content
    assert content.startswith("$ ")
    assert any("to stdout" in line for line in outcome.tail)
    assert outcome.duration_s >= 0


async def test_timeout_kills_a_hanging_child(tmp_path: Path, fake_binaries) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    script = "import time; time.sleep(60)"
    settings = _settings(workspace, (sys.executable, "-c", script))
    runner = GhidriffRunner(settings)
    request = _request(settings, workspace / "run", fake_binaries, timeout_s=1.0)
    runner.prepare_dirs(request)

    outcome = await runner.run(request, log_path=workspace / "run" / "ghidriff.log")

    assert outcome.timed_out is True
    assert outcome.ok is False
    assert outcome.duration_s < 30


async def test_cancellation_kills_the_child(tmp_path: Path, fake_binaries) -> None:
    import asyncio

    workspace = tmp_path / "ws"
    workspace.mkdir()
    settings = _settings(workspace, (sys.executable, "-c", "import time; time.sleep(60)"))
    runner = GhidriffRunner(settings)
    request = _request(settings, workspace / "run", fake_binaries)
    runner.prepare_dirs(request)

    task = asyncio.create_task(runner.run(request, log_path=workspace / "run" / "ghidriff.log"))
    await asyncio.sleep(0.5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_missing_command_raises_file_not_found(tmp_path: Path, fake_binaries) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    settings = _settings(workspace, ("definitely-not-a-real-binary-xyz",))
    runner = GhidriffRunner(settings)
    request = _request(settings, workspace / "run", fake_binaries)
    runner.prepare_dirs(request)

    with pytest.raises(FileNotFoundError):
        await runner.run(request, log_path=workspace / "run" / "ghidriff.log")


def test_read_tail_handles_missing_and_short_files(tmp_path: Path) -> None:
    assert read_tail(tmp_path / "absent.log") == []

    path = tmp_path / "log.txt"
    path.write_text("\n".join(f"line {index}" for index in range(1, 11)), encoding="utf-8")
    assert read_tail(path, lines=3) == ["line 8", "line 9", "line 10"]
    assert read_tail(path, lines=50)[0] == "line 1"
