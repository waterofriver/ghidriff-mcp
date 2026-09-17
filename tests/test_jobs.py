"""Tests for the background job manager."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from fakes import FakeRunner
from ghidriff_mcp.config import Settings
from ghidriff_mcp.jobs import (
    STATUS_CANCELLED,
    STATUS_FAILED,
    STATUS_SUCCEEDED,
    STATUS_TIMEOUT,
    JobError,
    JobManager,
)
from ghidriff_mcp.runner import build_request


@pytest.fixture
def request_for(settings: Settings, fake_binaries: tuple[Path, Path]):
    old, new = fake_binaries

    def build(job_dir: Path):
        return build_request(
            settings,
            old_binary=str(old),
            new_binaries=[str(new)],
            run_dir=job_dir,
            timeout_s=5.0,
        )

    return build


async def _start(manager: JobManager, request_factory, settings: Settings):
    job_id, run_dir = manager.reserve()
    request = request_factory(run_dir)
    return await manager.start(request, job_id=job_id, run_dir=run_dir)


async def test_successful_job_records_summary(
    settings: Settings, request_for, sample_pdiff: dict
) -> None:
    manager = JobManager(settings, runner=FakeRunner("success", sample_pdiff))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)

    assert job.status == STATUS_SUCCEEDED
    assert job.returncode == 0
    assert job.error is None
    assert job.summary is not None
    assert job.summary["function_counts"] == {"added": 1, "deleted": 1, "modified": 1}
    assert job.duration_s() is not None
    assert job.log_path.is_file()

    payload = job.as_dict()
    assert payload["status"] == STATUS_SUCCEEDED
    assert payload["request"]["engine"] == "VersionTrackingDiff"

    saved = json.loads((job.run_dir / "job.json").read_text(encoding="utf-8"))
    assert saved["status"] == STATUS_SUCCEEDED
    assert saved["summary"]["function_counts"]["modified"] == 1


async def test_failed_job_explains_ghidra_path_rule(settings: Settings, request_for) -> None:
    manager = JobManager(settings, runner=FakeRunner("fail"))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)

    assert job.status == STATUS_FAILED
    assert job.returncode == 1
    assert job.error is not None
    assert "dot-free" in job.error


async def test_timeout_job(settings: Settings, request_for) -> None:
    manager = JobManager(settings, runner=FakeRunner("timeout"))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)

    assert job.status == STATUS_TIMEOUT
    assert "did not finish" in (job.error or "")


async def test_missing_artifacts_is_a_failure(settings: Settings, request_for) -> None:
    manager = JobManager(settings, runner=FakeRunner("success", pdiff=None))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)

    assert job.status == STATUS_FAILED
    assert "no diff artefacts" in (job.error or "")


async def test_launch_failure_is_reported(settings: Settings, request_for) -> None:
    manager = JobManager(settings, runner=FakeRunner("explode"))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)

    assert job.status == STATUS_FAILED
    assert "Could not launch ghidriff" in (job.error or "")


async def test_cancel_running_job(settings: Settings, request_for) -> None:
    runner = FakeRunner("hang")
    manager = JobManager(settings, runner=runner)
    job = await _start(manager, request_for, settings)

    await asyncio.sleep(0.05)
    assert job.status in {"queued", "running"}

    cancelled = await manager.cancel(job.id)
    assert cancelled.status == STATUS_CANCELLED
    assert cancelled.terminal


async def test_unknown_job_id_lists_recent_jobs(settings: Settings) -> None:
    manager = JobManager(settings, runner=FakeRunner())
    with pytest.raises(JobError, match="Unknown job_id"):
        manager.get("nope")


async def test_jobs_are_listed_newest_first(
    settings: Settings, request_for, sample_pdiff: dict
) -> None:
    manager = JobManager(settings, runner=FakeRunner("success", sample_pdiff))
    first = await _start(manager, request_for, settings)
    await manager.wait(first.id, timeout_s=5)
    await asyncio.sleep(1.01)  # job ids have one-second resolution
    second = await _start(manager, request_for, settings)
    await manager.wait(second.id, timeout_s=5)

    listed = manager.list(limit=10)
    assert [job.id for job in listed] == [second.id, first.id]
    assert manager.list(status=STATUS_SUCCEEDED) == listed
    assert manager.list(status=STATUS_FAILED) == []


async def test_jobs_survive_a_restart(settings: Settings, request_for, sample_pdiff: dict) -> None:
    manager = JobManager(settings, runner=FakeRunner("success", sample_pdiff))
    job = await _start(manager, request_for, settings)
    await manager.wait(job.id, timeout_s=5)
    await manager.shutdown()

    reloaded = JobManager(settings, runner=FakeRunner())
    recovered = reloaded.get(job.id)
    assert recovered.status == STATUS_SUCCEEDED
    assert recovered.summary is not None
    assert recovered.request.old == job.request.old


async def test_interrupted_jobs_are_marked_failed(settings: Settings, request_for) -> None:
    manager = JobManager(settings, runner=FakeRunner("success"))
    job_id, run_dir = manager.reserve()
    request = request_for(run_dir)
    payload = {
        "job_id": job_id,
        "status": "running",
        "request": request.as_dict(),
        "log_path": str(run_dir / "ghidriff.log"),
    }
    (run_dir / "job.json").write_text(json.dumps(payload), encoding="utf-8")

    reloaded = JobManager(settings, runner=FakeRunner())
    recovered = reloaded.get(job_id)
    assert recovered.status == STATUS_FAILED
    assert "restart" in (recovered.error or "")


async def test_concurrency_limit_is_respected(settings: Settings, request_for) -> None:
    settings = settings.with_workspace(settings.workspace)
    runner = FakeRunner("hang")
    manager = JobManager(settings, runner=runner, max_parallel=1)
    first = await _start(manager, request_for, settings)
    await asyncio.sleep(0.05)

    second_id, second_dir = manager.reserve()
    second = await manager.start(request_for(second_dir), job_id=second_id, run_dir=second_dir)
    await asyncio.sleep(0.05)

    assert first.status == "running"
    assert second.status == "queued"
    assert runner.run_calls == 1

    await manager.cancel(first.id)
    await manager.cancel(second.id)
