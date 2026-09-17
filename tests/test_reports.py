"""Tests for parsing ghidriff's output artefacts."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghidriff_mcp.reports import (
    ReportError,
    discover_artifacts,
    function_detail,
    function_names,
    latest_artifacts,
    load_pdiff,
    metadata_diff,
    read_text_page,
    search_functions,
    summarize_pdiff,
)


def test_discover_artifacts_finds_every_file(sample_output_dir: Path) -> None:
    artifacts = discover_artifacts(sample_output_dir)
    assert len(artifacts) == 1
    entry = artifacts[0]
    assert entry.name == "old.exe-new.exe.ghidriff"
    assert entry.md_path is not None and entry.md_path.suffix == ".md"
    assert entry.json_path is not None and entry.json_path.name.endswith(".ghidriff.json")
    assert entry.matches_path is not None
    assert entry.log_path is not None

    payload = entry.as_dict()
    assert payload["pdiff_json"].endswith(".ghidriff.json")


def test_discover_artifacts_on_missing_dir(tmp_path: Path) -> None:
    assert discover_artifacts(tmp_path / "nope") == []
    assert latest_artifacts(tmp_path / "nope") is None


def test_latest_artifacts_picks_the_newest(tmp_path: Path, sample_pdiff: dict) -> None:
    output = tmp_path / "out"
    (output / "json").mkdir(parents=True)
    older = output / "a.exe-b.exe.ghidriff.md"
    newer = output / "b.exe-c.exe.ghidriff.md"
    older.write_text("old\n", encoding="utf-8")
    newer.write_text("new\n", encoding="utf-8")
    (output / "json" / "a.exe-b.exe.ghidriff.json").write_text(
        json.dumps(sample_pdiff), encoding="utf-8"
    )
    (output / "json" / "b.exe-c.exe.ghidriff.json").write_text(
        json.dumps(sample_pdiff), encoding="utf-8"
    )
    import os

    os.utime(older, (1000, 1000))
    os.utime(newer, (2000, 2000))
    (output / "json" / "a.exe-b.exe.ghidriff.json").touch()
    os.utime(output / "json" / "a.exe-b.exe.ghidriff.json", (1000, 1000))
    os.utime(output / "json" / "b.exe-c.exe.ghidriff.json", (2000, 2000))

    latest = latest_artifacts(output)
    assert latest is not None
    assert latest.name == "b.exe-c.exe.ghidriff"


def test_load_pdiff_rejects_wrong_files(sample_output_dir: Path, tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="not found"):
        load_pdiff(tmp_path / "missing.json")

    matches = next(sample_output_dir.glob("json/*.matches.json"))
    with pytest.raises(ReportError, match="matches file"):
        load_pdiff(matches)

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(ReportError, match="not valid JSON"):
        load_pdiff(broken)

    not_pdiff = tmp_path / "other.json"
    not_pdiff.write_text('{"hello": 1}', encoding="utf-8")
    with pytest.raises(ReportError, match="does not look like a ghidriff pdiff"):
        load_pdiff(not_pdiff)


def test_load_pdiff_refuses_oversized_files(tmp_path: Path, sample_pdiff: dict) -> None:
    """A pdiff is attacker-influenced input; parsing must be size bounded."""
    path = tmp_path / "big.ghidriff.json"
    path.write_text(json.dumps(sample_pdiff), encoding="utf-8")

    with pytest.raises(ReportError, match=r"above the .* MB parse limit"):
        load_pdiff(path, max_bytes=10)

    # The same file loads fine under a limit that fits it.
    assert load_pdiff(path, max_bytes=10 * 1024 * 1024)["functions"]


def test_summarize_pdiff(sample_pdiff: dict, sample_output_dir: Path) -> None:
    artifacts = latest_artifacts(sample_output_dir)
    summary = summarize_pdiff(sample_pdiff, max_names=10, artifacts=artifacts)

    assert summary["function_counts"] == {"added": 1, "deleted": 1, "modified": 1}
    assert summary["function_names"]["modified"] == ["entry"]
    assert summary["function_names"]["added"] == ["FUN_140001900"]
    assert summary["function_names"]["deleted"] == ["old_helper"]
    assert summary["function_names_truncated"] == {
        "added": False,
        "deleted": False,
        "modified": False,
    }
    assert summary["strings"] == {"added": 1, "deleted": 1}
    assert summary["old"]["Program Name"] == "old.exe"
    assert summary["new"]["Program Name"] == "new.exe"
    assert summary["stats"]["modified_funcs_len"] == 1
    assert summary["artifacts"]["name"] == "old.exe-new.exe.ghidriff"
    # Metadata that is not in the interesting subset is not copied over.
    assert "FSRL" not in summary["old"]


def test_summarize_pdiff_caps_names(sample_pdiff: dict) -> None:
    for index in range(30):
        sample_pdiff["functions"]["added"].append(
            {"name": f"FUN_{index}", "fullname": f"FUN_{index}"}
        )
    summary = summarize_pdiff(sample_pdiff, max_names=10)
    assert len(summary["function_names"]["added"]) == 10
    assert summary["function_names_truncated"]["added"] is True
    assert summary["function_counts"]["added"] == 31


def test_function_names_uncapped(sample_pdiff: dict) -> None:
    assert function_names(sample_pdiff, "added") == ["FUN_140001900"]
    assert function_names(sample_pdiff, "nonexistent") == []


def test_metadata_diff_lists_only_changes(sample_pdiff: dict) -> None:
    rows = metadata_diff(sample_pdiff)
    fields = {row["field"] for row in rows}
    assert "Program Name" in fields
    assert "Executable SHA256" in fields
    assert "Language ID" not in fields


def test_function_detail_for_modified(sample_pdiff: dict) -> None:
    detail = function_detail(sample_pdiff, "entry")
    assert detail["kind"] == "modified"
    assert detail["matched_by"] == "exact"
    assert detail["old_name"] == "entry"
    assert detail["new_name"] == "entry"
    assert detail["ratio"] == 0.57
    assert detail["diff_type"] == ["code", "length"]
    assert "__security_init_cookie" in detail["code_diff"]
    assert detail["code_diff_truncated"] is False
    assert detail["old"]["address"] == "0x1400013c0"
    assert detail["new"]["length"] == 32


def test_function_detail_for_added_and_deleted(sample_pdiff: dict) -> None:
    added = function_detail(sample_pdiff, "FUN_140001900")
    assert added["kind"] == "added"
    assert added["code"].startswith("undefined FUN_140001900")
    assert added["address"] == "0x140001900"

    deleted = function_detail(sample_pdiff, "old_helper")
    assert deleted["kind"] == "deleted"
    assert "old_helper" in deleted["code"]


def test_function_detail_truncates_code(sample_pdiff: dict) -> None:
    sample_pdiff["functions"]["added"][0]["code"] = "x" * 10000
    detail = function_detail(sample_pdiff, "FUN_140001900")
    assert detail["code_truncated"] is True
    assert len(detail["code"]) == 4000


def test_function_detail_substring_and_ambiguity(sample_pdiff: dict) -> None:
    detail = function_detail(sample_pdiff, "helper")
    assert detail["kind"] == "deleted"
    assert detail["matched_by"] == "substring"


def test_function_detail_reports_other_matches(sample_pdiff: dict) -> None:
    sample_pdiff["functions"]["added"].append(
        {"name": "FUN_140001901", "fullname": "FUN_140001901", "code": ""}
    )
    detail = function_detail(sample_pdiff, "FUN_14000190")
    assert "other_matches" in detail
    assert detail["other_matches"][0]["name"] == "FUN_140001901"


def test_function_detail_unknown_name(sample_pdiff: dict) -> None:
    with pytest.raises(ReportError, match="No changed function"):
        function_detail(sample_pdiff, "totally_absent")

    with pytest.raises(ReportError, match="required"):
        function_detail(sample_pdiff, "")


def test_search_functions(sample_pdiff: dict) -> None:
    everything = search_functions(sample_pdiff, "")
    assert {hit["kind"] for hit in everything} == {"added", "deleted", "modified"}

    only_modified = search_functions(sample_pdiff, "entry", kinds=("modified",))
    assert len(only_modified) == 1
    assert only_modified[0]["ratio"] == 0.57

    assert search_functions(sample_pdiff, "zzz") == []

    capped = search_functions(sample_pdiff, "", limit=2)
    assert len(capped) == 2


def test_read_text_page_pages_through_a_file(tmp_path: Path) -> None:
    path = tmp_path / "report.md"
    path.write_text("\n".join(f"line {index}" for index in range(1, 51)), encoding="utf-8")

    first = read_text_page(path, start_line=1, max_lines=10)
    assert first["content"].splitlines() == [f"line {index}" for index in range(1, 11)]
    assert first["total_lines"] == 50
    assert first["has_more"] is True
    assert first["next_start_line"] == 11

    last = read_text_page(path, start_line=45, max_lines=10)
    assert last["has_more"] is False
    assert last["end_line"] == 50


def test_read_text_page_respects_char_budget(tmp_path: Path) -> None:
    path = tmp_path / "big.txt"
    path.write_text("x" * 1000, encoding="utf-8")
    page = read_text_page(path, max_lines=5, max_chars=100)
    assert page["truncated_by_chars"] is True
    assert len(page["content"]) == 100


def test_read_text_page_missing_file(tmp_path: Path) -> None:
    with pytest.raises(ReportError, match="file not found"):
        read_text_page(tmp_path / "nope.md")
