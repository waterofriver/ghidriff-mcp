"""End-to-end tests of the MCP tool surface using an in-memory client session.

These tests exercise the real MCP protocol (tool listing, argument validation,
JSON results) but swap the ghidriff process for a fake runner, so they run
anywhere without Ghidra.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

import ghidriff_mcp.server as server_module
from fakes import FakeRunner
from ghidriff_mcp.config import Settings
from ghidriff_mcp.server import mcp


@pytest.fixture
def state(settings: Settings):
    state = server_module.reset_state(settings)
    yield state
    server_module.reset_state(settings)


def decode(result: Any) -> Any:
    """Pull the JSON payload out of a CallToolResult."""
    structured = getattr(result, "structuredContent", None)
    if structured:
        if set(structured) == {"result"}:
            return structured["result"]
        return structured
    return json.loads(result.content[0].text)


async def call(name: str, arguments: dict[str, Any]) -> Any:
    async with create_connected_server_and_client_session(mcp._mcp_server) as session:
        return await session.call_tool(name, arguments)


async def test_all_tools_are_registered_with_the_ghidriff_prefix() -> None:
    async with create_connected_server_and_client_session(mcp._mcp_server) as session:
        tools = (await session.list_tools()).tools

    names = {tool.name for tool in tools}
    assert names == {
        "ghidriff_environment",
        "ghidriff_start_diff",
        "ghidriff_run_diff",
        "ghidriff_job_status",
        "ghidriff_job_result",
        "ghidriff_job_log",
        "ghidriff_job_cancel",
        "ghidriff_jobs",
        "ghidriff_list_runs",
        "ghidriff_read_report",
        "ghidriff_function_detail",
        "ghidriff_search_functions",
        "ghidriff_settings",
    }
    start = next(tool for tool in tools if tool.name == "ghidriff_start_diff")
    assert "old_binary" in start.inputSchema["properties"]
    assert start.description


async def test_settings_tool_reports_workspace(state, settings: Settings) -> None:
    result = await call("ghidriff_settings", {})
    assert result.isError is False
    payload = decode(result)
    assert payload["workspace"] == str(settings.workspace)
    assert payload["max_concurrent_jobs"] == settings.max_concurrent_jobs


async def test_environment_tool_without_probe(state) -> None:
    result = await call("ghidriff_environment", {"probe": False})
    payload = decode(result)
    assert set(payload) >= {"ready", "checks", "problems", "settings", "next_steps"}
    assert set(payload["checks"]) == {"ghidra", "java", "ghidriff"}


async def test_start_diff_rejects_a_missing_binary(state) -> None:
    result = await call(
        "ghidriff_start_diff",
        {"old_binary": "nope.exe", "new_binaries": ["also-nope.exe"]},
    )
    assert result.isError is True
    assert "does not exist" in result.content[0].text


async def test_start_diff_rejects_an_unknown_engine(state, fake_binaries) -> None:
    old, new = fake_binaries
    result = await call(
        "ghidriff_start_diff",
        {"old_binary": str(old), "new_binaries": [str(new)], "engine": "MagicDiff"},
    )
    assert result.isError is True
    assert "Unknown engine" in result.content[0].text


async def test_diff_flow_end_to_end(state, settings: Settings, fake_binaries, sample_pdiff) -> None:
    state.jobs.runner = FakeRunner("success", sample_pdiff)
    old, new = fake_binaries

    started = decode(
        await call(
            "ghidriff_start_diff",
            {"old_binary": str(old), "new_binaries": [str(new)]},
        )
    )
    job_id = started["job_id"]
    assert started["status"] in {"queued", "running"}

    await state.jobs.wait(job_id, timeout_s=10)

    status = decode(await call("ghidriff_job_status", {"job_id": job_id}))
    assert status["status"] == "succeeded"
    assert status["log_tail"]

    result = decode(await call("ghidriff_job_result", {"job_id": job_id}))
    summary = result["summary"]
    assert summary["function_counts"] == {"added": 1, "deleted": 1, "modified": 1}
    assert summary["function_names"]["modified"] == ["entry"]
    assert result["artifacts"][0]["markdown_report"].endswith(".ghidriff.md")

    with_meta = decode(
        await call("ghidriff_job_result", {"job_id": job_id, "include_metadata_diff": True})
    )
    assert any(row["field"] == "Program Name" for row in with_meta["summary"]["metadata_diff"])

    detail = decode(await call("ghidriff_function_detail", {"job_id": job_id, "name": "entry"}))
    assert detail["kind"] == "modified"
    assert "__security_init_cookie" in detail["code_diff"]

    search = decode(await call("ghidriff_search_functions", {"job_id": job_id, "query": "helper"}))
    assert search["count"] == 1
    assert search["hits"][0]["kind"] == "deleted"

    report = decode(await call("ghidriff_read_report", {"job_id": job_id, "max_lines": 5}))
    assert report["content"].startswith("# diff")
    assert report["has_more"] is True

    log = decode(await call("ghidriff_job_log", {"job_id": job_id, "tail_lines": 5}))
    assert "fake run" in log["content"]

    jobs = decode(await call("ghidriff_jobs", {}))
    assert jobs["count"] == 1
    assert jobs["jobs"][0]["job_id"] == job_id

    runs = decode(await call("ghidriff_list_runs", {}))
    assert runs["artifacts"]


async def test_run_diff_blocks_until_finished(state, fake_binaries, sample_pdiff) -> None:
    state.jobs.runner = FakeRunner("success", sample_pdiff)
    old, new = fake_binaries
    payload = decode(
        await call(
            "ghidriff_run_diff",
            {"old_binary": str(old), "new_binaries": [str(new)]},
        )
    )
    assert payload["status"] == "succeeded"
    assert payload["summary"]["function_counts"]["modified"] == 1


async def test_failed_job_result_surfaces_the_hint(state, fake_binaries) -> None:
    state.jobs.runner = FakeRunner("fail")
    old, new = fake_binaries
    started = decode(
        await call("ghidriff_start_diff", {"old_binary": str(old), "new_binaries": [str(new)]})
    )
    await state.jobs.wait(started["job_id"], timeout_s=10)

    result = decode(await call("ghidriff_job_result", {"job_id": started["job_id"]}))
    assert result["status"] == "failed"
    assert "dot-free" in result["error"]
    assert "hint" in result


async def test_cancel_tool(state, fake_binaries) -> None:
    state.jobs.runner = FakeRunner("hang")
    old, new = fake_binaries
    started = decode(
        await call("ghidriff_start_diff", {"old_binary": str(old), "new_binaries": [str(new)]})
    )
    cancelled = decode(await call("ghidriff_job_cancel", {"job_id": started["job_id"]}))
    assert cancelled["status"] == "cancelled"


async def test_unknown_job_is_a_tool_error(state) -> None:
    result = await call("ghidriff_job_status", {"job_id": "does-not-exist"})
    assert result.isError is True
    assert "Unknown job_id" in result.content[0].text


async def test_function_detail_without_target_is_a_tool_error(state) -> None:
    result = await call("ghidriff_function_detail", {"name": "entry"})
    assert result.isError is True
    assert "job_id or json_path" in result.content[0].text


async def test_search_rejects_unknown_kinds(state, fake_binaries, sample_pdiff) -> None:
    state.jobs.runner = FakeRunner("success", sample_pdiff)
    old, new = fake_binaries
    started = decode(
        await call("ghidriff_start_diff", {"old_binary": str(old), "new_binaries": [str(new)]})
    )
    await state.jobs.wait(started["job_id"], timeout_s=10)

    result = await call(
        "ghidriff_search_functions",
        {"job_id": started["job_id"], "query": "", "kinds": ["exploded"]},
    )
    assert result.isError is True
    assert "Unknown kinds" in result.content[0].text


async def test_read_report_by_path(state, fake_binaries, sample_pdiff) -> None:
    state.jobs.runner = FakeRunner("success", sample_pdiff)
    old, new = fake_binaries
    started = decode(
        await call("ghidriff_start_diff", {"old_binary": str(old), "new_binaries": [str(new)]})
    )
    await state.jobs.wait(started["job_id"], timeout_s=10)

    runs = decode(await call("ghidriff_list_runs", {}))
    report_path = runs["artifacts"][0]["markdown_report"]
    page = decode(await call("ghidriff_read_report", {"path": report_path, "max_lines": 3}))
    assert page["path"] == report_path
    assert page["end_line"] == 3
