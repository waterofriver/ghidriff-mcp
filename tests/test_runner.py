"""Tests for request validation and command-line construction."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghidriff_mcp.config import Settings
from ghidriff_mcp.paths import PathError
from ghidriff_mcp.runner import (
    DiffRequest,
    RunnerError,
    build_command,
    build_env,
    build_request,
    normalize_engine,
)


@pytest.fixture
def ghidra_settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return Settings(
        workspace=workspace,
        ghidra_install_dir=tmp_path / "ghidra",
        python_executable="python-x",
        default_timeout_s=600.0,
    )


def _request(settings: Settings, old: Path, new: Path, run_dir: Path) -> DiffRequest:
    return build_request(
        settings,
        old_binary=str(old),
        new_binaries=[str(new)],
        run_dir=run_dir,
    )


def test_build_request_resolves_paths(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path], tmp_path: Path
) -> None:
    old, new = fake_binaries
    run_dir = ghidra_settings.workspace / "runs" / "job1"
    request = _request(ghidra_settings, old, new, run_dir)

    assert request.old == old.resolve()
    assert request.new == (new.resolve(),)
    assert request.output_dir == run_dir / "ghidriff"
    assert request.project_dir == run_dir / "ghidra_projects"
    assert request.timeout_s == 600.0
    assert request.notices == ()


def test_build_request_warns_without_ghidra_dir(
    settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(settings, old, new, settings.workspace / "runs" / "j")
    assert any("GHIDRA_INSTALL_DIR" in notice for notice in request.notices)


def test_build_request_rejects_missing_binary(ghidra_settings: Settings, tmp_path: Path) -> None:
    new = tmp_path / "new.exe"
    new.write_bytes(b"MZ")
    with pytest.raises(PathError):
        build_request(
            ghidra_settings,
            old_binary="nope.exe",
            new_binaries=[str(new)],
            run_dir=tmp_path,
        )


def test_build_request_requires_new_binaries(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, _new = fake_binaries
    with pytest.raises(RunnerError, match="At least one new binary"):
        build_request(
            ghidra_settings, old_binary=str(old), new_binaries=[], run_dir=ghidra_settings.workspace
        )


def test_build_request_rejects_identical_inputs(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, _new = fake_binaries
    with pytest.raises(RunnerError, match="must differ"):
        build_request(
            ghidra_settings,
            old_binary=str(old),
            new_binaries=[str(old)],
            run_dir=ghidra_settings.workspace,
        )


@pytest.mark.parametrize(
    ("given", "expected"),
    [
        (None, "VersionTrackingDiff"),
        ("SimpleDiff", "SimpleDiff"),
        ("StructualGraphDiff", "StructualGraphDiff"),
        ("StructuralGraphDiff", "StructualGraphDiff"),
        ("  VersionTrackingDiff ", "VersionTrackingDiff"),
    ],
)
def test_normalize_engine(given: str | None, expected: str) -> None:
    assert normalize_engine(given) == expected


def test_normalize_engine_rejects_unknown() -> None:
    with pytest.raises(RunnerError, match="Unknown engine"):
        normalize_engine("MagicDiff")


def test_command_puts_binaries_after_a_separator(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(ghidra_settings, old, new, ghidra_settings.workspace / "runs" / "j")
    command = build_command(ghidra_settings, request)

    assert command[:3] == ["python-x", "-m", "ghidriff"]
    separator = command.index("--")
    assert command[separator + 1 :] == [str(request.old), str(request.new[0])]
    assert command.index("-o") < separator
    assert command[command.index("-o") + 1] == str(request.output_dir)
    assert command[command.index("-p") + 1] == str(request.project_dir)
    assert "--engine" in command
    assert "--threaded" in command
    # No bare --summary: upstream declares it as a value-taking option.
    assert "--summary" not in command


def test_option_like_filenames_cannot_inject_flags(
    ghidra_settings: Settings, tmp_path: Path
) -> None:
    """A binary called ``--force-analysis`` must stay a positional argument."""
    bins = tmp_path / "bins"
    bins.mkdir()
    old = bins / "old.exe"
    old.write_bytes(b"MZ")
    new = bins / "--force-analysis"
    new.write_bytes(b"MZ")

    request = build_request(
        ghidra_settings,
        old_binary=str(old),
        new_binaries=[str(new)],
        run_dir=ghidra_settings.workspace / "runs" / "j",
    )
    command = build_command(ghidra_settings, request)

    separator = command.index("--")
    assert command[separator + 1 :] == [str(request.old), str(new.resolve())]
    assert "--force-analysis" not in command[:separator]


def test_operator_extra_args_stay_on_the_option_side(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(ghidra_settings, old, new, ghidra_settings.workspace / "runs" / "j")
    request = request.with_updates(extra_args=("--jvm-args", "-Xmx1g"))
    command = build_command(ghidra_settings, request)

    separator = command.index("--")
    assert command.index("--jvm-args") < separator
    assert command[separator + 1 :] == [str(request.old), str(request.new[0])]


def test_summary_flag_is_passed_a_value(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(ghidra_settings, old, new, ghidra_settings.workspace / "runs" / "j")
    request = request.with_updates(summary=True)
    command = build_command(ghidra_settings, request)

    index = command.index("--summary")
    assert command[index + 1] == "True"


def test_boolean_and_value_options(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(ghidra_settings, old, new, ghidra_settings.workspace / "runs" / "j")
    request = request.with_updates(
        threaded=False,
        force_diff=True,
        no_symbols=True,
        bsim=False,
        bsim_full=True,
        side_by_side=True,
        verbose_analysis=True,
        min_func_len=20,
        max_section_funcs=5,
        max_ram_percent=40.0,
        base_address="0x2000",
        md_title="my diff",
        extra_args=("--gdt", "file.gdt"),
    )
    command = build_command(ghidra_settings, request)

    assert "--no-threaded" in command
    assert "--force-diff" in command
    assert "--no-symbols" in command
    assert "--no-bsim" in command and "--bsim" not in command
    assert "--bsim-full" in command
    assert "--sxs" in command
    assert "--va" in command
    assert command[command.index("--min-func-len") + 1] == "20"
    assert command[command.index("--max-section-funcs") + 1] == "5"
    assert command[command.index("--max-ram-percent") + 1] == "40.0"
    assert command[command.index("--ba") + 1] == "0x2000"
    assert command[command.index("--md-title") + 1] == "my diff"
    separator = command.index("--")
    assert command[separator - 2 : separator] == ["--gdt", "file.gdt"]


def test_explicit_command_overrides_interpreter(
    tmp_path: Path, fake_binaries: tuple[Path, Path]
) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    settings = Settings(workspace=workspace, ghidriff_command=("/opt/ghidriff", "--quiet"))
    old, new = fake_binaries
    request = _request(settings, old, new, workspace / "runs" / "j")
    assert build_command(settings, request)[:2] == ["/opt/ghidriff", "--quiet"]


def test_build_env_injects_ghidra_dir(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("GHIDRA_INSTALL_DIR", raising=False)
    env = build_env(ghidra_settings)
    assert env["GHIDRA_INSTALL_DIR"] == str(ghidra_settings.ghidra_install_dir)

    empty = Settings(workspace=ghidra_settings.workspace)
    assert "GHIDRA_INSTALL_DIR" not in build_env(empty)


def test_request_round_trips_through_dict(
    ghidra_settings: Settings, fake_binaries: tuple[Path, Path]
) -> None:
    old, new = fake_binaries
    request = _request(ghidra_settings, old, new, ghidra_settings.workspace / "runs" / "j")
    restored = DiffRequest.from_dict(request.as_dict())
    assert restored == request
