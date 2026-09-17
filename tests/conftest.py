"""Shared pytest fixtures: a synthetic ghidriff pdiff and an isolated workspace."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghidriff_mcp.config import Settings

OLD_ESYM = {
    "name": "entry",
    "fullname": "entry",
    "address": "0x1400013c0",
    "length": 28,
    "paramcount": 0,
    "refcount": 1,
    "called": 0,
    "calling": 2,
    "sig": "void entry(void)",
    "code": "void entry(void)\n{\n  __security_init_cookie();\n  __wmainCRTStartup();\n}\n",
    "sym_type": "Function",
    "sym_source": "IMPORTED",
    "external": False,
}

NEW_ESYM = {
    **OLD_ESYM,
    "length": 32,
    "code": "void entry(void)\n{\n  code *pcVar1;\n  pcVar1 = (code *)swi(3);\n  (*pcVar1)();\n}\n",
}

ADDED_ESYM = {
    "name": "FUN_140001900",
    "fullname": "FUN_140001900",
    "address": "0x140001900",
    "length": 96,
    "paramcount": 1,
    "refcount": 0,
    "called": 0,
    "calling": 1,
    "sig": "undefined FUN_140001900(int param_1)",
    "code": "undefined FUN_140001900(int param_1)\n{\n  return param_1 + 1;\n}\n",
    "sym_type": "Function",
    "sym_source": "ANALYSIS",
    "external": False,
}

DELETED_ESYM = {
    **ADDED_ESYM,
    "name": "old_helper",
    "fullname": "old_helper",
    "address": "0x140001a00",
    "code": "void old_helper(void)\n{\n  return;\n}\n",
}

MODIFIED_ENTRY = {
    "old": OLD_ESYM,
    "new": NEW_ESYM,
    "diff": (
        "--- entry\n+++ entry\n@@ -1,9 +1,11 @@\n \n void entry(void)\n \n {\n"
        "-  __security_init_cookie();\n+  code *pcVar1;\n   return;\n }\n"
    ),
    "diff_type": ["code", "length"],
    "ratio": 0.57,
    "i_ratio": 0.0,
    "m_ratio": 0.38,
    "b_ratio": 0.0,
    "match_types": ["SymbolsHash"],
}

STATS = {
    "added_funcs_len": 1,
    "deleted_funcs_len": 1,
    "modified_funcs_len": 1,
    "added_symbols_len": 2,
    "deleted_symbols_len": 0,
    "diff_time": 11.46,
    "deleted_strings_len": 1,
    "added_strings_len": 3,
    "match_types": {"SymbolsHash": 64, "ExternalsName": 33},
    "unmatched_funcs_len": 0,
    "total_funcs_len": 130,
    "matched_funcs_len": 130,
    "matched_funcs_with_code_changes_len": 1,
    "matched_funcs_with_no_changes_len": 0,
    "match_func_similarity_percent": "97.6923%",
    "func_match_overall_percent": "100.0000%",
}

META_OLD = {
    "Program Name": "old.exe",
    "Executable SHA256": "aa" * 32,
    "Executable MD5": "bb" * 16,
    "# of Functions": 130,
    "# of Bytes": 32768,
    "Language ID": "x86:LE:64:default",
    "Compiler": "windows",
    "Date Created": "Mon Sep 01 10:00:00 2025",
}

META_NEW = {
    **META_OLD,
    "Program Name": "new.exe",
    "Executable SHA256": "cc" * 32,
    "# of Functions": 131,
}


@pytest.fixture
def sample_pdiff() -> dict:
    """A pdiff shaped exactly like ghidriff 1.0.0 writes it."""
    return {
        "old_meta": dict(META_OLD),
        "new_meta": dict(META_NEW),
        "stats": dict(STATS),
        "functions": {
            "added": [dict(ADDED_ESYM)],
            "deleted": [dict(DELETED_ESYM)],
            "modified": [json.loads(json.dumps(MODIFIED_ENTRY))],
        },
        "strings": {
            "added": {"hello": {"refs": 1}},
            "deleted": {"goodbye": {"refs": 1}},
        },
        "matches": {"SymbolsHash": {"entry": "entry"}},
    }


@pytest.fixture
def sample_output_dir(tmp_path: Path, sample_pdiff: dict) -> Path:
    """An output directory laid out the way ghidriff lays it out."""
    output = tmp_path / "ghidriff"
    (output / "json").mkdir(parents=True)
    base = "old.exe-new.exe.ghidriff"
    (output / f"{base}.md").write_text("# old.exe-new.exe Diff\n\nbody\n", encoding="utf-8")
    (output / "json" / f"{base}.json").write_text(json.dumps(sample_pdiff), encoding="utf-8")
    (output / "json" / f"{base}.matches.json").write_text("{}", encoding="utf-8")
    (output / "ghidriff.log").write_text("INFO | ghidriff | hi\n", encoding="utf-8")
    return output


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return Settings(workspace=workspace, default_timeout_s=30.0, max_concurrent_jobs=1)


@pytest.fixture
def fake_binaries(tmp_path: Path) -> tuple[Path, Path]:
    old = tmp_path / "old.exe"
    new = tmp_path / "new.exe"
    old.write_bytes(b"MZ" + b"\0" * 64)
    new.write_bytes(b"MZ" + b"\0" * 64 + b"\x90")
    return old, new
