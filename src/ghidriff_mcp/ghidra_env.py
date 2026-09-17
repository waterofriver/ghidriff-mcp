"""Discovery and health-checking of the external tools ghidriff depends on.

The MCP server itself is a thin process: the heavy lifting happens in a separate
``ghidriff`` process which boots a JVM through PyGhidra. That means the server's
own interpreter and the interpreter that runs ghidriff are not necessarily the
same one, and neither of them is necessarily the one that has Ghidra configured.
This module resolves that puzzle once and reports it in plain language.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .config import Settings

_VERSION_RE = re.compile(r"^application\.version\s*=\s*(\S+)", re.MULTILINE)
_JAVA_RE = re.compile(r'version "([^"]+)"')

_COMMON_GHIDRA_GLOBS = (
    "ghidra_*",
    "ghidra",
    "tools/ghidra/ghidra_*",
    "tools/ghidra*",
    "Applications/ghidra_*",
    "opt/ghidra_*",
    "Program Files/ghidra_*",
    "Program Files (x86)/ghidra_*",
)


@dataclass
class GhidraInstall:
    path: Path
    version: str | None = None
    source: str = "unknown"

    def as_dict(self) -> dict[str, object]:
        return {"path": str(self.path), "version": self.version, "source": self.source}


@dataclass
class ToolReport:
    name: str
    ok: bool
    detail: str
    extra: dict[str, object] = field(default_factory=dict)

    def as_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {"ok": self.ok, "detail": self.detail}
        payload.update(self.extra)
        return payload


def _looks_like_ghidra_dir(path: Path) -> bool:
    return (
        (path / "Ghidra" / "application.properties").is_file()
        or (path / "support" / "analyzeHeadless").exists()
        or (path / "support" / "analyzeHeadless.bat").is_file()
    )


def ghidra_version(path: Path) -> str | None:
    props = path / "Ghidra" / "application.properties"
    try:
        text = props.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    match = _VERSION_RE.search(text)
    return match.group(1) if match else None


def _candidate_dirs(explicit: Path | None, env: dict[str, str]) -> list[tuple[Path, str]]:
    candidates: list[tuple[Path, str]] = []
    if explicit is not None:
        candidates.append((explicit, "GHIDRA_INSTALL_DIR"))
    env_dir = env.get("GHIDRA_INSTALL_DIR", "").strip()
    if env_dir:
        candidates.append((Path(env_dir).expanduser(), "environment"))

    homes = [Path.home()]
    roots: list[Path] = []
    for home in homes:
        roots.append(home)
        for glob in _COMMON_GHIDRA_GLOBS:
            roots.extend(sorted(home.glob(glob)))
    if os.name == "nt":
        for drive in ("C:/", "D:/", "E:/"):
            roots.append(Path(drive))
    else:
        roots.extend([Path("/opt"), Path("/usr/local"), Path("/usr/share")])

    for root in roots:
        try:
            if not root.is_dir():
                continue
        except OSError:
            continue
        candidates.append((root, "auto-discovery"))

    seen: set[str] = set()
    unique: list[tuple[Path, str]] = []
    for path, source in candidates:
        key = str(path)
        if key in seen:
            continue
        seen.add(key)
        unique.append((path, source))
    return unique


def find_ghidra_install(
    explicit: Path | None = None,
    *,
    env: dict[str, str] | None = None,
    auto_discover: bool = True,
) -> GhidraInstall | None:
    """Locate a Ghidra installation without importing anything from ghidriff."""
    env = dict(os.environ if env is None else env)
    candidates = _candidate_dirs(explicit, env)
    if not auto_discover:
        candidates = [item for item in candidates if item[1] != "auto-discovery"]
    for path, source in candidates:
        if _looks_like_ghidra_dir(path):
            return GhidraInstall(path=path, version=ghidra_version(path), source=source)
    return None


def java_executable(
    ghidra: GhidraInstall | None = None, *, env: dict[str, str] | None = None
) -> str | None:
    env = dict(os.environ if env is None else env)
    java_home = env.get("JAVA_HOME", "").strip()
    if java_home:
        candidate = Path(java_home) / "bin" / ("java.exe" if os.name == "nt" else "java")
        if candidate.is_file():
            return str(candidate)
    return shutil.which("java")


def java_version(java: str | None, *, timeout: float = 20.0) -> str | None:
    if not java:
        return None
    try:
        proc = subprocess.run(
            [java, "-version"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = f"{proc.stderr}\n{proc.stdout}"
    match = _JAVA_RE.search(output)
    return match.group(1) if match else None


def _last_line(text: str) -> str:
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    return lines[-1] if lines else "no output"


def _probe_ghidriff(settings: Settings, *, timeout: float = 120.0) -> ToolReport:
    """Check that ghidriff is runnable and, when possible, report its version.

    With an explicit ``GHIDRIFF_MCP_COMMAND`` the only safe check is running it
    (``--help``) and looking at what comes back. Otherwise the configured
    interpreter is asked to import ghidriff directly, which is the question that
    actually matters at diff time.

    The timeout is generous on purpose: this starts an interpreter that may be
    busy loading a large site-packages tree next to a running Ghidra JVM.

    Every probe gets ``stdin=DEVNULL``: a child of an MCP stdio server must never
    be able to read the protocol stream, and it must not hold that handle open
    either.
    """
    if settings.ghidriff_command:
        command = [*settings.ghidriff_command, "--help"]
        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                stdin=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            return ToolReport(
                "ghidriff", False, f"command not found: {command[0]}", {"command": command}
            )
        except subprocess.TimeoutExpired:
            return ToolReport(
                "ghidriff",
                False,
                f"'{' '.join(command)}' did not answer within {timeout:.0f}s; "
                "the machine may be busy, re-run the check.",
                {"command": command},
            )
        except subprocess.SubprocessError as exc:  # pragma: no cover - environment specific
            return ToolReport("ghidriff", False, f"probe failed: {exc}", {"command": command})

        output = f"{proc.stdout}\n{proc.stderr}"
        ok = proc.returncode == 0 and "ghidriff" in output.lower()
        detail = (
            f"custom command works: {' '.join(settings.ghidriff_command)}"
            if ok
            else f"custom command failed (exit {proc.returncode}): {_last_line(output)}"
        )
        return ToolReport("ghidriff", ok, detail, {"command": command})

    script = "import importlib.metadata as m; print(m.version('ghidriff'))"
    interpreter = settings.interpreter
    command = [interpreter, "-c", script]
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            stdin=subprocess.DEVNULL,
        )
    except FileNotFoundError:
        return ToolReport(
            "ghidriff", False, f"interpreter not found: {interpreter}", {"command": command}
        )
    except subprocess.TimeoutExpired:
        return ToolReport(
            "ghidriff",
            False,
            f"{interpreter} did not answer within {timeout:.0f}s; it may be busy or "
            "loading a very large environment. Re-run the check.",
            {"command": command},
        )
    except subprocess.SubprocessError as exc:  # pragma: no cover - environment specific
        return ToolReport("ghidriff", False, f"probe failed: {exc}", {"command": command})

    if proc.returncode != 0:
        tail = _last_line(proc.stderr) if proc.stderr.strip() else _last_line(proc.stdout)
        return ToolReport(
            "ghidriff",
            False,
            f"ghidriff is not importable by {interpreter}: {tail}",
            {"command": command},
        )

    version = _last_line(proc.stdout)
    return ToolReport(
        "ghidriff",
        True,
        f"ghidriff {version} importable by {interpreter}",
        {"version": version, "command": command},
    )


def diagnose(
    settings: Settings,
    *,
    env: dict[str, str] | None = None,
    probe: bool = True,
) -> dict[str, object]:
    """Return a structured health report for the ghidriff tool chain."""
    env = dict(os.environ if env is None else env)
    ghidra = find_ghidra_install(settings.ghidra_install_dir, env=env)
    java = java_executable(ghidra, env=env)
    jversion = java_version(java)

    checks: dict[str, object] = {
        "ghidra": ToolReport(
            "ghidra",
            ghidra is not None,
            (
                f"Ghidra {ghidra.version} at {ghidra.path} (found via {ghidra.source})"
                if ghidra
                else "No Ghidra installation found. Set GHIDRA_INSTALL_DIR."
            ),
            ghidra.as_dict() if ghidra else {},
        ).as_dict(),
        "java": ToolReport(
            "java",
            bool(java) and bool(jversion),
            f"Java {jversion} ({java})" if jversion else "No usable java on PATH or JAVA_HOME.",
            {"executable": java, "version": jversion},
        ).as_dict(),
        "ghidriff": (
            _probe_ghidriff(settings).as_dict()
            if probe
            else ToolReport("ghidriff", True, "probe skipped").as_dict()
        ),
    }

    ready = all(bool(check.get("ok")) for check in checks.values())
    problems = [
        f"{name}: {check.get('detail')}" for name, check in checks.items() if not check.get("ok")
    ]
    return {
        "ready": ready,
        "settings": settings.as_dict(),
        "checks": checks,
        "problems": problems,
        "next_steps": _next_steps(checks),
    }


def _next_steps(checks: dict[str, object]) -> list[str]:
    steps: list[str] = []
    if not checks["ghidra"].get("ok"):
        steps.append(
            "Download Ghidra and set GHIDRA_INSTALL_DIR to the extracted folder, "
            "e.g. GHIDRA_INSTALL_DIR=C:\\\\ghidra\\\\ghidra_12.1.3_PUBLIC"
        )
    if not checks["java"].get("ok"):
        steps.append("Install a JDK 21+ and either set JAVA_HOME or put java on PATH.")
    if not checks["ghidriff"].get("ok"):
        steps.append(
            "Install ghidriff into the interpreter this server launches "
            "(pip install ghidriff) or set GHIDRIFF_MCP_PYTHON / GHIDRIFF_MCP_COMMAND."
        )
    return steps
