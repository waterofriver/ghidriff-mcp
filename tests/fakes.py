"""Test doubles shared by the job and server test modules."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from ghidriff_mcp.runner import ProcessOutcome

DIFF_BASE = "old.exe-new.exe.ghidriff"


class FakeRunner:
    """Stands in for GhidriffRunner without launching Ghidra.

    ``behavior`` selects what the run looks like from the job manager's point of
    view: ``success``, ``fail``, ``timeout``, ``hang`` (never finishes) or
    ``explode`` (raises before producing an outcome).
    """

    def __init__(self, behavior: str = "success", pdiff: dict | None = None) -> None:
        self.behavior = behavior
        self.pdiff = pdiff
        self.run_calls = 0

    def prepare_dirs(self, request) -> None:
        request.output_dir.mkdir(parents=True, exist_ok=True)
        request.project_dir.mkdir(parents=True, exist_ok=True)

    async def run(self, request, *, log_path: Path, on_process=None) -> ProcessOutcome:
        self.run_calls += 1
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text("INFO | ghidriff | fake run\n", encoding="utf-8")

        if self.behavior == "hang":
            await asyncio.sleep(3600)
        if self.behavior == "explode":
            raise FileNotFoundError("ghidriff-not-found")

        returncode = 1 if self.behavior == "fail" else 0
        outcome = ProcessOutcome(
            returncode=returncode,
            command=["ghidriff", "--fake"],
            log_path=log_path,
            duration_s=0.01,
            timed_out=self.behavior == "timeout",
            tail=tail_for(self.behavior),
        )

        if self.behavior == "success" and self.pdiff is not None:
            write_diff_artifacts(request.output_dir, self.pdiff)
        return outcome


def tail_for(behavior: str) -> list[str]:
    if behavior == "fail":
        return [
            "INFO | ghidriff | Starting Ghidra...",
            "java.lang.IllegalArgumentException: Path element starting with '.' is not permitted",
        ]
    if behavior == "timeout":
        return ["INFO | ghidriff | Analyzing..."]
    return ["INFO | ghidriff | Wrote diff.md"]


def write_diff_artifacts(
    output_dir: Path, pdiff: dict, *, base: str = DIFF_BASE, lines: int = 40
) -> None:
    """Write a Markdown report and pdiff JSON the way ghidriff would."""
    (output_dir / "json").mkdir(parents=True, exist_ok=True)
    body = "\n".join(f"line {index}" for index in range(1, lines + 1))
    (output_dir / f"{base}.md").write_text(f"# diff\n{body}\n", encoding="utf-8")
    (output_dir / "json" / f"{base}.json").write_text(json.dumps(pdiff), encoding="utf-8")
    (output_dir / "json" / f"{base}.matches.json").write_text("{}", encoding="utf-8")
