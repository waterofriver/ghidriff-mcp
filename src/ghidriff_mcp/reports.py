"""Turning ghidriff output into compact, agent-friendly structures.

ghidriff writes three artefacts per diff:

* ``<name>.ghidriff.md`` - the human-readable report
* ``json/<name>.ghidriff.json`` - the full ``pdiff`` (stats, functions, strings)
* ``json/<name>.ghidriff.matches.json`` - the raw match table

The full pdiff of a real binary easily runs into megabytes, so every helper in
this module caps what it returns and hands out line ranges instead of whole
files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

DIFF_SUFFIX = ".ghidriff"
MAX_CODE_CHARS = 4000

#: Interesting keys copied out of the Ghidra program metadata blob.
_META_KEYS = (
    "Program Name",
    "Executable Format",
    "Executable Location",
    "Executable MD5",
    "Executable SHA256",
    "# of Bytes",
    "# of Functions",
    "# of Symbols",
    "# of Instructions",
    "Language ID",
    "Compiler",
    "Compiler ID",
    "Processor",
    "Address Size",
    "Endian",
    "Date Created",
    "Created With Ghidra Version",
    "PDB File",
    "Relocatable",
)


class ReportError(ValueError):
    """Raised when ghidriff output cannot be read."""


@dataclass
class RunArtifacts:
    output_dir: Path
    name: str
    md_path: Path | None = None
    json_path: Path | None = None
    matches_path: Path | None = None
    log_path: Path | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "output_dir": str(self.output_dir),
            "name": self.name,
            "markdown_report": str(self.md_path) if self.md_path else None,
            "pdiff_json": str(self.json_path) if self.json_path else None,
            "matches_json": str(self.matches_path) if self.matches_path else None,
            "ghidriff_log": str(self.log_path) if self.log_path else None,
        }


def _strip_suffix(filename: str, suffix: str) -> str:
    """Drop ``suffix`` from ``filename``, or return it unchanged."""
    return filename[: -len(suffix)] if filename.endswith(suffix) else filename


def discover_artifacts(output_dir: Path) -> list[RunArtifacts]:
    """Find every diff written below ``output_dir``.

    ghidriff names a diff ``<old>-<new>.ghidriff`` and then appends ``.md``,
    ``.json`` or ``.matches.json``, so the base name keeps the ``.ghidriff``
    suffix.
    """
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        return []
    found: dict[str, RunArtifacts] = {}

    for md in sorted(output_dir.glob(f"*{DIFF_SUFFIX}.md")):
        base = _strip_suffix(md.name, ".md")
        entry = found.setdefault(base, RunArtifacts(output_dir=output_dir, name=base))
        entry.md_path = md

    json_dir = output_dir / "json"
    if json_dir.is_dir():
        for js in sorted(json_dir.glob(f"*{DIFF_SUFFIX}.json")):
            base = _strip_suffix(js.name, ".json")
            entry = found.setdefault(base, RunArtifacts(output_dir=output_dir, name=base))
            entry.json_path = js
        for js in sorted(json_dir.glob(f"*{DIFF_SUFFIX}.matches.json")):
            base = _strip_suffix(js.name, ".matches.json")
            entry = found.setdefault(base, RunArtifacts(output_dir=output_dir, name=base))
            entry.matches_path = js

    log = output_dir / "ghidriff.log"
    if log.is_file():
        for entry in found.values():
            entry.log_path = log

    return [found[key] for key in sorted(found)]


def latest_artifacts(output_dir: Path) -> RunArtifacts | None:
    artifacts = discover_artifacts(output_dir)
    if not artifacts:
        return None

    def mtime(entry: RunArtifacts) -> float:
        stamps = [
            path.stat().st_mtime
            for path in (entry.json_path, entry.md_path, entry.matches_path)
            if path is not None and path.is_file()
        ]
        return max(stamps) if stamps else 0.0

    return max(artifacts, key=mtime)


def load_pdiff(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    if not path.is_file():
        raise ReportError(f"pdiff json not found: {path}")
    if path.name.endswith(".matches.json"):
        raise ReportError(
            f"{path.name} is a matches file, not a pdiff. Pass the *.ghidriff.json file."
        )
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except json.JSONDecodeError as exc:
        raise ReportError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or "functions" not in data:
        raise ReportError(f"{path} does not look like a ghidriff pdiff (missing 'functions').")
    return data


def _truncate(text: str | None, limit: int = MAX_CODE_CHARS) -> tuple[str | None, bool]:
    if text is None:
        return None, False
    if len(text) <= limit:
        return text, False
    return text[:limit], True


def _meta_summary(meta: dict[str, Any] | None) -> dict[str, Any]:
    if not isinstance(meta, dict):
        return {}
    return {key: meta.get(key) for key in _META_KEYS if meta.get(key) is not None}


def _entry_name(entry: dict[str, Any]) -> str:
    for key in ("fullname", "name"):
        value = entry.get(key)
        if isinstance(value, str) and value:
            return value
    return "<unnamed>"


def _modified_names(entry: dict[str, Any]) -> tuple[str, str]:
    old = entry.get("old") if isinstance(entry.get("old"), dict) else {}
    new = entry.get("new") if isinstance(entry.get("new"), dict) else {}
    return _entry_name(old), _entry_name(new)


def _function_name(entry: dict[str, Any], kind: str) -> str:
    if kind == "modified":
        old_name, new_name = _modified_names(entry)
        return new_name if new_name != "<unnamed>" else old_name
    return _entry_name(entry)


def function_names(pdiff: dict[str, Any], kind: str, *, limit: int | None = None) -> list[str]:
    entries = pdiff.get("functions", {}).get(kind, []) or []
    names = [_function_name(entry, kind) for entry in entries]
    return names if limit is None else names[:limit]


def summarize_pdiff(
    pdiff: dict[str, Any],
    *,
    max_names: int = 40,
    artifacts: RunArtifacts | None = None,
) -> dict[str, Any]:
    """Build the compact summary used by most tool responses."""
    functions = pdiff.get("functions", {}) or {}
    stats = pdiff.get("stats", {}) or {}
    strings = pdiff.get("strings", {}) or {}

    counts = {kind: len(functions.get(kind, []) or []) for kind in ("added", "deleted", "modified")}
    names = {
        kind: function_names(pdiff, kind, limit=max_names)
        for kind in ("added", "deleted", "modified")
    }
    truncated = {kind: counts[kind] > len(names[kind]) for kind in counts}

    summary: dict[str, Any] = {
        "old": _meta_summary(pdiff.get("old_meta")),
        "new": _meta_summary(pdiff.get("new_meta")),
        "stats": stats,
        "function_counts": counts,
        "function_names": names,
        "function_names_truncated": truncated,
        "strings": {
            "added": len(strings.get("added", {}) or {}),
            "deleted": len(strings.get("deleted", {}) or {}),
        },
    }
    if artifacts is not None:
        summary["artifacts"] = artifacts.as_dict()
        summary["artifacts"]["diff_files"] = [
            artifact.as_dict() for artifact in discover_artifacts(artifacts.output_dir)
        ]
    return summary


def metadata_diff(pdiff: dict[str, Any], *, limit: int = 40) -> list[dict[str, Any]]:
    """Field-by-field diff of the old/new program metadata."""
    old = pdiff.get("old_meta") or {}
    new = pdiff.get("new_meta") or {}
    rows: list[dict[str, Any]] = []
    for key in sorted(set(old) | set(new)):
        before = old.get(key)
        after = new.get(key)
        if before == after:
            continue
        rows.append({"field": key, "old": before, "new": after})
        if len(rows) >= limit:
            break
    return rows


def search_functions(
    pdiff: dict[str, Any],
    query: str,
    *,
    kinds: tuple[str, ...] = ("added", "deleted", "modified"),
    limit: int = 50,
) -> list[dict[str, Any]]:
    """Case-insensitive substring search across diffed function names."""
    needle = (query or "").strip().lower()
    results: list[dict[str, Any]] = []
    for kind in kinds:
        for entry in pdiff.get("functions", {}).get(kind, []) or []:
            name = _function_name(entry, kind)
            old_name, new_name = _modified_names(entry) if kind == "modified" else (name, name)
            haystack = f"{old_name}\n{new_name}".lower()
            if needle and needle not in haystack:
                continue
            results.append(
                {
                    "kind": kind,
                    "name": name,
                    "old_name": old_name,
                    "new_name": new_name,
                    "ratio": entry.get("ratio"),
                    "diff_type": entry.get("diff_type"),
                }
            )
            if len(results) >= limit:
                return results
    return results


def function_detail(pdiff: dict[str, Any], name: str) -> dict[str, Any]:
    """Return everything ghidriff knows about one changed function."""
    needle = (name or "").strip()
    if not needle:
        raise ReportError("A function name is required.")
    lowered = needle.lower()

    exact: list[tuple[str, dict[str, Any]]] = []
    partial: list[tuple[str, dict[str, Any]]] = []
    for kind in ("modified", "added", "deleted"):
        for entry in pdiff.get("functions", {}).get(kind, []) or []:
            if kind == "modified":
                old_name, new_name = _modified_names(entry)
                candidates = (old_name, new_name)
            else:
                candidates = (_entry_name(entry),)
            bucket = (
                exact if any(candidate.lower() == lowered for candidate in candidates) else partial
            )
            if any(lowered in candidate.lower() for candidate in candidates):
                bucket.append((kind, entry))

    matches = exact or partial
    if not matches:
        available = sum(
            len(pdiff.get("functions", {}).get(kind, []) or [])
            for kind in ("added", "deleted", "modified")
        )
        raise ReportError(
            f"No changed function matching {needle!r} "
            f"(searched {available} added/deleted/modified functions)."
        )

    kind, entry = matches[0]
    detail: dict[str, Any] = {"kind": kind, "matched_by": "exact" if exact else "substring"}
    if len(matches) > 1:
        detail["other_matches"] = [
            {"kind": other_kind, "name": _function_name(other, other_kind)}
            for other_kind, other in matches[1:11]
        ]

    if kind == "modified":
        old = entry.get("old") or {}
        new = entry.get("new") or {}
        code_diff, truncated = _truncate(entry.get("diff"))
        detail.update(
            {
                "old_name": _entry_name(old),
                "new_name": _entry_name(new),
                "ratio": entry.get("ratio"),
                "instruction_ratio": entry.get("i_ratio"),
                "mnemonic_ratio": entry.get("m_ratio"),
                "basic_block_ratio": entry.get("b_ratio"),
                "diff_type": entry.get("diff_type"),
                "match_types": entry.get("match_types"),
                "code_diff": code_diff,
                "code_diff_truncated": truncated,
                "old": _esym_summary(old),
                "new": _esym_summary(new),
            }
        )
    else:
        code, truncated = _truncate(entry.get("code"))
        detail.update({"name": _entry_name(entry), **_esym_summary(entry)})
        detail["code"] = code
        detail["code_truncated"] = truncated

    return detail


def _esym_summary(entry: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    return {
        key: entry.get(key)
        for key in (
            "name",
            "fullname",
            "address",
            "length",
            "paramcount",
            "refcount",
            "called",
            "calling",
            "sig",
            "sym_type",
            "sym_source",
            "external",
        )
        if entry.get(key) is not None
    }


def read_text_page(
    path: str | Path,
    *,
    start_line: int = 1,
    max_lines: int = 200,
    max_chars: int = 20000,
) -> dict[str, Any]:
    """Read a bounded window of a text artefact."""
    path = Path(path)
    if not path.is_file():
        raise ReportError(f"file not found: {path}")
    start_line = max(1, int(start_line))
    max_lines = max(1, int(max_lines))

    lines: list[str] = []
    total = 0
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for index, line in enumerate(handle, start=1):
            total = index
            if index < start_line:
                continue
            if len(lines) >= max_lines:
                continue
            lines.append(line.rstrip("\n"))

    content = "\n".join(lines)
    truncated_chars = len(content) > max_chars
    if truncated_chars:
        content = content[:max_chars]

    end_line = start_line + len(lines) - 1 if lines else start_line - 1
    return {
        "path": str(path),
        "start_line": start_line,
        "end_line": end_line,
        "total_lines": total,
        "has_more": end_line < total,
        "next_start_line": end_line + 1,
        "truncated_by_chars": truncated_chars,
        "content": content,
    }
