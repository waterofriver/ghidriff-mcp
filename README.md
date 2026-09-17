# ghidriff-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes
[ghidriff](https://github.com/clearbluejar/ghidriff) — the Ghidra binary diffing
engine — as tools an AI agent can call.

Point it at an old and a new build of a binary and it drives Ghidra headlessly
through ghidriff, then hands back structured results: match statistics,
added/deleted/modified functions, per-function code diffs and the generated
Markdown report — as JSON, not as a screenful of console noise.

[![CI](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-server-6E56CF.svg)](https://modelcontextprotocol.io)

**English** | [简体中文](README.zh-CN.md)

---

## Contents

- [Why this exists](#why-this-exists)
- [Requirements](#requirements)
- [Install](#install)
- [Configuration](#configuration)
- [Tools](#tools)
- [Example session](#example-session)
- [How it works](#how-it-works)
- [Security and trust model](#security-and-trust-model)
- [Troubleshooting](#troubleshooting)
- [Compared with GhidraMCP](#compared-with-ghidramcp)
- [Project layout](#project-layout)
- [Development](#development)
- [License](#license)

## Why this exists

`ghidriff` is excellent but it is a **batch CLI**: you invoke it, wait while
Ghidra imports and analyses every input, and you get a Markdown report plus a
large `pdiff` JSON on disk. That shape does not fit an agent loop, where you want
to inspect a change, follow up on one function, and keep the reasoning in
context.

This server closes that gap:

* **Jobs instead of blocking calls.** Every diff runs in the background with an
  id, a log file and a persisted `job.json`, so a crash or restart does not lose
  the result.
* **Structured output.** The `pdiff` JSON ghidriff writes is the source of
  truth; the server turns it into compact summaries and per-function details
  instead of dumping megabytes into the model's context.
* **Late-bound environment.** The server does not need ghidriff or Ghidra in its
  own interpreter — it launches whichever interpreter or command you configure.
* **Honest errors.** Ghidra's failure modes are translated into actionable
  messages: missing `GHIDRA_INSTALL_DIR`, a project path Ghidra refuses, a JVM
  out of memory, a missing `pyghidra`.
* **A boundary you control.** The agent decides *what* to diff; you decide *how*
  the engine runs. See [Security and trust model](#security-and-trust-model).

## Requirements

| Component | Version | Notes |
| --- | --- | --- |
| Python | 3.10+ | for the MCP server itself |
| [ghidriff](https://github.com/clearbluejar/ghidriff) | 1.x | `pip install ghidriff` |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 11.x / 12.x | set `GHIDRA_INSTALL_DIR` |
| JDK | 21+ | Ghidra 12 requires a modern JDK |

Ghidra and ghidriff do **not** have to live in the same interpreter as this
server. If your MCP client runs the server from an isolated virtualenv, point
`GHIDRIFF_MCP_PYTHON` at the interpreter that has ghidriff installed.

Tested against ghidriff 1.0.0, Ghidra 12.1.3 and JDK 21 on Windows, and in CI on
Ubuntu, macOS and Windows with Python 3.10 and 3.13.

## Install

```bash
pip install ghidriff-mcp
```

Or from source:

```bash
git clone https://github.com/waterofriver/ghidriff-mcp
cd ghidriff-mcp
pip install -e .
```

Verify the tool chain with the built-in self check:

```bash
ghidriff-mcp --check
```

It prints a JSON diagnosis of Ghidra, Java and ghidriff, with next steps for
anything missing, and exits non-zero when the setup is not usable yet:

```jsonc
// ghidriff-mcp --check (trimmed for length)
{
  "ready": true,
  "checks": {
    "ghidra": { "ok": true, "detail": "Ghidra 12.1.3 at C:\\ghidra\\ghidra_12.1.3_PUBLIC (found via GHIDRA_INSTALL_DIR)" },
    "java": { "ok": true, "detail": "Java 21.0.12.1 (C:\\Program Files\\Microsoft\\jdk-21...\\bin\\java.exe)" },
    "ghidriff": { "ok": true, "detail": "ghidriff 1.0.0 importable by C:\\Python313\\python.exe" }
  },
  "problems": [],
  "next_steps": []
}
```

The same report is available to agents through the `ghidriff_environment` tool.

## Configuration

Everything is environment driven.

| Variable | Default | Purpose |
| --- | --- | --- |
| `GHIDRIFF_MCP_HOME` | `~/ghidriff-mcp-work` | Root for run directories, Ghidra projects and diff output. |
| `GHIDRA_INSTALL_DIR` | auto-discovery | Path to the extracted Ghidra folder. |
| `GHIDRIFF_MCP_PYTHON` | the server's own interpreter | Interpreter that has ghidriff installed. |
| `GHIDRIFF_MCP_COMMAND` | — | Explicit ghidriff command line, e.g. `ghidriff --max-ram-percent 40`. Takes precedence over `GHIDRIFF_MCP_PYTHON`. |
| `GHIDRIFF_MCP_TIMEOUT` | `3600` | Default per-run timeout in seconds. |
| `GHIDRIFF_MCP_MAX_JOBS` | `2` | Maximum concurrent diffs (each one boots a JVM). |
| `GHIDRIFF_MCP_EXTRA_ARGS` | — | Raw ghidriff arguments appended to every run. Operator-only: this is where `--no-symbols` or `--jvm-args` belong, not in tool calls. |
| `GHIDRIFF_MCP_LOG_LEVEL` | `INFO` | ghidriff log level (`DEBUG` is very verbose). |

> **Ghidra path rule.** Ghidra refuses a project location containing a path
> element that starts with `.` (`Path element starting with '.' is not
> permitted`). Keep `GHIDRIFF_MCP_HOME` dot-free; if it is not, the server
> relocates the Ghidra project to the system temp directory and reports a
> warning instead of failing after a multi-minute import.

### MCP client configuration

```json
{
  "mcpServers": {
    "ghidriff": {
      "command": "C:\\path\\to\\venv\\Scripts\\python.exe",
      "args": ["-m", "ghidriff_mcp"],
      "env": {
        "GHIDRA_INSTALL_DIR": "C:\\ghidra\\ghidra_12.1.3_PUBLIC",
        "GHIDRIFF_MCP_PYTHON": "C:\\Python313\\python.exe",
        "GHIDRIFF_MCP_HOME": "C:\\ghidriff-work"
      }
    }
  }
}
```

HTTP transports are available for clients that prefer them:

```bash
ghidriff-mcp --transport streamable-http --host 127.0.0.1 --port 8765
```

Command-line flags: `--check` (self check), `--workspace PATH` and
`--ghidra-install-dir PATH` (override the matching environment variables for this
process), `--transport`, `--host`, `--port`, `--version`.

## Tools

Thirteen tools, all prefixed `ghidriff_` so an agent can tell them apart from
other Ghidra-related servers.

| Tool | What it does |
| --- | --- |
| `ghidriff_environment` | Verifies Ghidra, Java and ghidriff, and explains how to fix anything missing. |
| `ghidriff_start_diff` | Starts a diff in the background, returns a `job_id` immediately. |
| `ghidriff_run_diff` | Blocking convenience wrapper around the above. |
| `ghidriff_job_status` | Status, timing and log tail of one job. |
| `ghidriff_job_result` | Match statistics, function counts, names, artefacts. |
| `ghidriff_job_log` | The raw ghidriff log, tailed or paged. |
| `ghidriff_job_cancel` | Kills a running diff. |
| `ghidriff_jobs` | Job history (persisted in `job.json`, survives restarts). |
| `ghidriff_list_runs` | Diff artefacts on disk, workspace-wide or in one directory. |
| `ghidriff_read_report` | Page through the generated Markdown report. |
| `ghidriff_function_detail` | One changed function: metadata, code, and the code diff. |
| `ghidriff_search_functions` | Search changed functions by name. |
| `ghidriff_settings` | Effective configuration and environment variables. |

`ghidriff_start_diff` accepts `old_binary`, one or more `new_binaries`, the
engine (`VersionTrackingDiff`, `SimpleDiff`, `StructualGraphDiff`), `output_dir`,
`project_dir`, `summary`, `side_by_side`, `force_analysis`, `force_diff`, `bsim`,
`bsim_full`, `min_func_len`, `max_section_funcs`, `base_address`, `no_symbols`
and `timeout_s`. Raw engine pass-through is deliberately *not* on this list —
that lives in `GHIDRIFF_MCP_EXTRA_ARGS`.

## Example session

An agent diffing two builds of an executable, from first call to a single
function's code change. The JSON below is real output, trimmed for length.

```
ghidriff_environment()
  → ready: true, ghidriff 1.0.0, Ghidra 12.1.3, Java 21.0.12.1

ghidriff_start_diff(
    old_binary="fixtures/old.exe",
    new_binaries=["fixtures/new.exe"],
    engine="VersionTrackingDiff")
  → job_id: "20260917-214305-24c6", status: "queued"
```

```jsonc
// ghidriff_job_result(job_id="20260917-214305-24c6")
{
  "job_id": "20260917-214305-24c6",
  "status": "succeeded",
  "returncode": 0,
  "duration_s": 11.6,
  "summary": {
    "old": {
      "Program Name": "old.exe",
      "# of Functions": "65",
      "Language ID": "x86:LE:64:default (4.8)"
    },
    "new": {
      "Program Name": "new.exe",
      "# of Functions": "65",
      "Language ID": "x86:LE:64:default (4.8)"
    },
    "stats": {
      "total_funcs_len": 130,
      "matched_funcs_len": 130,
      "modified_funcs_len": 3,
      "added_funcs_len": 0,
      "deleted_funcs_len": 0,
      "func_match_overall_percent": "100.0000%",
      "match_func_similarity_percent": "97.6923%"
    },
    "function_counts": { "added": 0, "deleted": 0, "modified": 3 },
    "function_names": {
      "added": [],
      "deleted": [],
      "modified": ["entry", "__security_init_cookie", "__wmainCRTStartup"]
    },
    "strings": { "added": 0, "deleted": 0 }
  },
  "artifacts": [{
    "output_dir": "...\\runs\\20260917-214305-24c6\\ghidriff",
    "name": "old.exe-new.exe.ghidriff",
    "markdown_report": "...\\old.exe-new.exe.ghidriff.md",
    "pdiff_json": "...\\json\\old.exe-new.exe.ghidriff.json",
    "matches_json": "...\\json\\old.exe-new.exe.ghidriff.matches.json",
    "ghidriff_log": "...\\ghidriff.log"
  }]
}
```

```jsonc
// ghidriff_function_detail(job_id="...", name="entry")
{
  "kind": "modified",
  "matched_by": "exact",
  "ratio": 0.57,
  "diff_type": ["code", "length", "called"],
  "code_diff": "--- entry\n+++ entry\n@@ -1,9 +1,11 @@\n \n void entry(void)\n \n {\n-  __security_init_cookie();\n-  __wmainCRTStartup();\n+  code *pcVar1;\n+  \n+  pcVar1 = (code *)swi(3);\n+  (*pcVar1)();\n   return;\n }\n"
}
```

Then follow up with `ghidriff_search_functions(query="crypt")` to find related
changes, or `ghidriff_read_report(start_line=1, max_lines=150)` to page through
the rendered report.

Pass several newer binaries to get chained diffs (`old → v2 → v3`), and set
`summary=true` to also diff `old → newest`. Use `side_by_side=true` if you want
the per-function HTML diffs on disk.

## How it works

```
MCP client ──stdio──▶ ghidriff-mcp ──subprocess──▶ ghidriff ──PyGhidra──▶ Ghidra (JVM)
                           │                            │
                           │                            └── writes <name>.ghidriff.md
                           │                                       json/<name>.ghidriff.json
                           └── job.json + ghidriff.log              json/<name>.ghidriff.matches.json
                               (structured summaries, paged reads)
```

* The server never imports ghidriff, so a JVM crash cannot take it down, and
  cancelling a job is a single `kill`.
* One run directory per job: `<workspace>/runs/<job_id>/` containing `job.json`,
  `ghidriff.log`, `ghidriff/` (output) and `ghidra_projects/`.
* Child output is redirected into the log file through an inherited handle
  rather than a pipe, which keeps it streamable and works in environments where
  pipes are restricted.
* `pdiff` JSON files are parsed lazily, capped in size and cached by mtime.
* Relative paths in tool calls resolve against the workspace, so an agent never
  has to know the absolute layout of the machine.

## Security and trust model

This server drives ghidriff locally with your own privileges on files you point
it at. Before wiring it to an agent, know what it does and does not constrain:

* **No shell.** Every command is an argv list built by the server and passed to
  `exec`-style process creation. Nothing is interpolated into a shell string, so
  file names and option values cannot become shell syntax.
* **The agent picks the target, you pick the engine.** Tool arguments select
  which binaries to diff, which supported engine to use, and how much output to
  render. They cannot select the executable, its JVM arguments, or arbitrary
  extra CLI switches. That matters, because `--jvm-args -javaagent:...` would
  otherwise be a code-execution primitive one model decision away.
* **Option-like file names are neutralised.** Binaries are passed after a `--`
  separator, so a file named `--force-analysis` stays a file.
* **Binaries are untrusted input.** Strings, symbol names, decompiled code and
  report text from a sample end up in the model's context. Treat all of it as
  data, never as instructions: a crafted binary can try to talk your agent into
  something. The same holds for anything else you feed the model.
* **Symbol lookups reach the network by default.** ghidriff lets Ghidra resolve
  PDBs, and for PE files with PDB metadata that can mean a query to a symbol
  server (Microsoft's among them), which leaks a little about what you are
  analysing. Pass `no_symbols=true`, or set
  `GHIDRIFF_MCP_EXTRA_ARGS=--no-symbols`, for offline work.
* **File access is not confined.** The server reads and writes wherever you
  point it, because binaries normally live outside the workspace. Use a
  dedicated workspace and do not hand an agent paths to files you would not want
  in a transcript.
* **Transports.** stdio by default. The HTTP transports bind to `127.0.0.1`
  unless you pass `--host`, and they carry no authentication — treat a
  non-loopback bind as exposing the server to that network.
* **External tooling is the real attack surface.** Ghidra parsing a hostile file
  is a much bigger risk than this wrapper. Keep ghidriff and Ghidra current, and
  run samples in a VM you can throw away.

Everything a run produces lives under `GHIDRIFF_MCP_HOME`, so that directory is
the thing to review — and delete — when you are done.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `Path element starting with '.' is not permitted` | Ghidra rejected the project path. Set `GHIDRIFF_MCP_HOME` to a directory without dot-prefixed elements. |
| `GHIDRA_INSTALL_DIR` missing / Ghidra not found | Set it to the extracted Ghidra folder (the one containing `support/`). |
| `No module named ghidriff` | The launched interpreter lacks ghidriff: set `GHIDRIFF_MCP_PYTHON` or `GHIDRIFF_MCP_COMMAND`. |
| `No module named 'pyghidra'` | Install ghidriff with its dependencies (`pip install ghidriff`), not just the CLI. |
| First diff takes minutes | Expected: Ghidra imports and analyses every binary once. Later diffs reuse the Ghidra project unless `force_analysis=true`. |
| `Symbols are disabled, but the symbol is already downloaded` | You passed `no_symbols=true` for a binary whose PDB is already in the symbol store. Delete it or drop the flag. |
| `OutOfMemoryError` | Lower `max_ram_percent`, or diff smaller binaries. |
| Job stuck in `queued` | Another job holds a slot; `GHIDRIFF_MCP_MAX_JOBS` limits concurrent JVMs. |
| `ghidriff exited 0 but no diff artefacts` | The output directory was overridden, e.g. by `GHIDRIFF_MCP_EXTRA_ARGS`; check `ghidriff_job_log`. |
| `above the 512 MB parse limit` | The pdiff is too large to parse safely. Page through the Markdown report with `ghidriff_read_report` instead. |
| `ghidriff_environment` is slow the first time | It starts the configured interpreter next to a possibly running JVM; the probe has a 120s budget and reports a timeout rather than hanging. |

## Compared with GhidraMCP

[GhidraMCP](https://github.com/LaurieWired/GhidraMCP) bridges a **running Ghidra
GUI** to an agent: interactive decompilation, renaming, commenting. This server
does the opposite job: **batch, headless diffing between two builds**, with no
GUI and no open project. They complement each other, and the `ghidriff_` prefix
means an agent can use both at once.

## Project layout

```
src/ghidriff_mcp/
  server.py      FastMCP tool surface and CLI entry point
  runner.py      ghidriff command construction and subprocess execution
  jobs.py        background job state machine, job.json persistence
  reports.py     pdiff / Markdown parsing, paging, size limits
  ghidra_env.py  Ghidra, Java and ghidriff discovery and diagnosis
  paths.py       workspace path resolution and Ghidra path rules
  config.py      environment-driven settings
tests/           unit, protocol-level and opt-in integration tests
```

## Development

```bash
pip install -e ".[dev]"
pytest                       # 110 tests, no Ghidra needed
ruff check src tests
ruff format --check src tests
```

The Ghidra-dependent test is opt-in:

```bash
GHIDRIFF_MCP_INTEGRATION=1 GHIDRA_INSTALL_DIR=/path/to/ghidra pytest -m integration
```

It generates a pair of PE files (a pristine copy of a system binary and one whose
entry point is patched) and asserts that at least one function is reported as
modified.

## License

MIT — see [LICENSE](LICENSE).

This project contains no ghidriff source code and does not link against it. It
invokes `ghidriff` (GPL-3.0) and Ghidra (Apache-2.0) as separate processes that
you install yourself; those programs keep their own licenses.
