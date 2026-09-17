"""Opt-in test that runs a real ghidriff diff through real Ghidra.

Enable it with::

    GHIDRIFF_MCP_INTEGRATION=1 \
    GHIDRA_INSTALL_DIR=/path/to/ghidra \
    GHIDRIFF_MCP_PYTHON=/path/to/python-with-ghidriff \
    pytest -m integration

It is skipped by default because it needs a Ghidra installation, a JDK and a
few minutes of CPU time.
"""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest

from ghidriff_mcp.config import Settings

pytestmark = pytest.mark.integration

REQUIRED_ENV = ("GHIDRIFF_MCP_INTEGRATION", "GHIDRA_INSTALL_DIR")


def _integration_ready() -> tuple[bool, str]:
    for name in REQUIRED_ENV:
        if not os.environ.get(name):
            return False, f"{name} is not set"
    interpreter = os.environ.get("GHIDRIFF_MCP_PYTHON")
    if interpreter:
        return True, ""
    if importlib.util.find_spec("ghidriff") is None:
        return False, "ghidriff is not importable and GHIDRIFF_MCP_PYTHON is not set"
    return True, ""


READY, REASON = _integration_ready()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not READY, reason=f"integration test disabled: {REASON}"),
]


@pytest.fixture
def integration_settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return Settings(
        workspace=workspace,
        ghidra_install_dir=Path(os.environ["GHIDRA_INSTALL_DIR"]),
        python_executable=os.environ.get("GHIDRIFF_MCP_PYTHON", ""),
        default_timeout_s=float(os.environ.get("GHIDRIFF_MCP_TIMEOUT", "1800")),
    )


async def test_real_diff_reports_a_modified_function(
    integration_settings: Settings, tmp_path: Path
) -> None:
    from ghidriff_mcp.jobs import STATUS_SUCCEEDED, JobManager
    from ghidriff_mcp.runner import GhidriffRunner, build_request
    from pe_fixtures import make_pair

    old, new = make_pair(tmp_path / "fixtures")
    manager = JobManager(integration_settings, runner=GhidriffRunner(integration_settings))

    job_id, run_dir = manager.reserve()
    request = build_request(
        integration_settings,
        old_binary=str(old),
        new_binaries=[str(new)],
        run_dir=run_dir,
        timeout_s=integration_settings.default_timeout_s,
    )
    job = await manager.start(request, job_id=job_id, run_dir=run_dir)
    await manager.wait(job.id, timeout_s=integration_settings.default_timeout_s + 60)

    if job.status != STATUS_SUCCEEDED:
        log = job.log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
        pytest.fail(f"diff failed with status {job.status}: {job.error}\n\n{log}")

    assert job.summary is not None
    counts = job.summary["function_counts"]
    assert counts["modified"] >= 1, job.summary
    assert job.summary["stats"]["total_funcs_len"] > 0
    assert job.output_dir.is_dir()

    await manager.shutdown()
