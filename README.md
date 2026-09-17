# ghidriff-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes
[ghidriff](https://github.com/clearbluejar/ghidriff) — the Ghidra binary diffing
engine — as tools an AI agent can call.

Point it at an old and a new build of a binary and it will drive Ghidra
headlessly through ghidriff, then hand back structured results: match
statistics, added/deleted/modified functions, per-function code diffs, and the
generated Markdown report — as JSON, not as a screenful of console noise.

[![CI](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)

---

## Why this exists

`ghidriff` is excellent but it is a **batch CLI**: you invoke it, wait minutes
while Ghidra imports and analyses every input, and you get a Markdown report plus
a large `pdiff` JSON on disk. That shape does not fit an agent loop, where you
want to inspect a change, follow up on one function, and keep the reasoning in
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
  messages (missing `GHIDRA_INSTALL_DIR`, a project path Ghidra refuses, a JVM
  out of memory, a missing `pyghidra`).

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

It prints a JSON diagnosis of Ghidra, Java and ghidriff (with next steps for
anything missing) and exits non-zero when the setup is not usable yet. The same
report is available to agents through the `ghidriff_environment` tool.

On Windows, quoting the Ghidra path inside JSON config is the usual source of
pain: double the backslashes (`D:\\tools\\ghidra\\ghidra_12.1.3_PUBLIC`) or use
forward slashes.

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
| `GHIDRIFF_MCP_EXTRA_ARGS` | — | Extra raw ghidriff arguments appended to every run. |
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
        "GHIDRA_INSTALL_DIR": "D:\\tools\\ghidra\\ghidra_12.1.3_PUBLIC",
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

Useful command-line flags: `--check` (self check, see above), `--workspace PATH`
and `--ghidra-install-dir PATH` (override the matching environment variables for
this process), `--version`.

## Tools

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

### Typical agent flow

```
ghidriff_environment()
  → ready: true, ghidriff 1.0.0, Ghidra 12.1.3, Java 21

ghidriff_start_diff(
    old_binary="samples/app-1.0.exe",
    new_binaries=["samples/app-1.1.exe"],
    engine="VersionTrackingDiff")
  → job_id: "20260917-133102-a1b2"

ghidriff_job_status(job_id="20260917-133102-a1b2")     # poll until terminal
ghidriff_job_result(job_id="20260917-133102-a1b2")
  → stats: 130 matched / 3 modified / 0 added / 0 deleted

ghidriff_function_detail(job_id="20260917-133102-a1b2", name="entry")
  → the unified diff of the changed function

ghidriff_search_functions(job_id="20260917-133102-a1b2", query="crypt")
ghidriff_read_report(job_id="20260917-133102-a1b2", start_line=1, max_lines=150)
```

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

* The server never imports ghidriff, so a JVM crash cannot take it down and
  cancelling a job is a single `kill`.
* One run directory per job: `<workspace>/runs/<job_id>/` containing
  `job.json`, `ghidriff.log`, `ghidriff/` (output) and `ghidra_projects/`.
* `pdiff` JSON files are parsed lazily and cached by mtime; a diff of a large
  binary can easily be tens of megabytes.
* Relative paths in tool calls resolve against the workspace, so an agent never
  has to know the absolute layout of the machine.

## Troubleshooting

| Symptom | Cause and fix |
| --- | --- |
| `Path element starting with '.' is not permitted` | Ghidra rejected the project path. Set `GHIDRIFF_MCP_HOME` to a directory without dot-prefixed elements. |
| `GHIDRA_INSTALL_DIR` missing / Ghidra not found | Set it to the extracted Ghidra folder (the one containing `support/`). |
| `No module named ghidriff` | The launched interpreter lacks ghidriff: set `GHIDRIFF_MCP_PYTHON` or `GHIDRIFF_MCP_COMMAND`. |
| `No module named 'pyghidra'` | Install ghidriff with its dependencies (`pip install ghidriff`), not just the CLI. |
| First diff takes minutes | Expected: Ghidra imports and analyses every binary once. Later diffs reuse the Ghidra project unless `force_analysis=true`. |
| `OutOfMemoryError` | Lower `max_ram_percent`, or diff smaller binaries. |
| Job stuck in `queued` | Another job holds a slot; `GHIDRIFF_MCP_MAX_JOBS` limits concurrent JVMs. |
| `ghidriff exited 0 but no diff artefacts` | The output directory was overridden by `extra_args`; check `ghidriff_job_log`. |

### Relationship to GhidraMCP

[GhidraMCP](https://github.com/LaurieWired/GhidraMCP) bridges a **running Ghidra
GUI** to an agent: interactive decompilation, renaming, commenting. This server
does the opposite job: **batch, headless diffing between two builds**, with no
GUI and no open project. They complement each other; tool names here are
prefixed `ghidriff_` so an agent can use both at once.

## Development

```bash
pip install -e ".[dev]"
pytest                       # unit + MCP protocol tests, no Ghidra needed
ruff check src tests
```

The Ghidra-dependent test is opt-in:

```bash
GHIDRIFF_MCP_INTEGRATION=1 GHIDRA_INSTALL_DIR=/path/to/ghidra pytest -m integration
```

It diffs two generated PE files (a pristine copy of a system binary and one with
a patched entry point) and asserts that at least one function is reported as
modified.

## 中文快速开始

```bash
pip install ghidriff-mcp
```

在 MCP 客户端里配置（注意 Windows 路径里的反斜杠要写成 `\\`）：

```json
{
  "mcpServers": {
    "ghidriff": {
      "command": "python",
      "args": ["-m", "ghidriff_mcp"],
      "env": {
        "GHIDRA_INSTALL_DIR": "D:\\tools\\ghidra\\ghidra_12.1.3_PUBLIC",
        "GHIDRIFF_MCP_PYTHON": "C:\\Python313\\python.exe",
        "GHIDRIFF_MCP_HOME": "C:\\ghidriff-work"
      }
    }
  }
}
```

要点：

1. `GHIDRA_INSTALL_DIR` 指向解压后的 Ghidra 目录（含 `support/` 子目录那个）。
2. `GHIDRIFF_MCP_HOME` **不能包含以 `.` 开头的路径段**（如 `.scratch`），否则
   Ghidra 会拒绝创建工程。
3. 先调用 `ghidriff_environment` 自检，再用 `ghidriff_start_diff` 起任务，轮询
   `ghidriff_job_status`，最后用 `ghidriff_job_result` / `ghidriff_function_detail`
   读取结构化结果。
4. 每个任务独占一个目录 `<workspace>/runs/<job_id>/`，里面同时保留
   `ghidriff.log` 和 ghidriff 原始输出，排查问题很方便。

## License

MIT — see [LICENSE](LICENSE).

This project contains no ghidriff source code and does not link against it. It
invokes `ghidriff` (GPL-3.0) and Ghidra (Apache-2.0) as separate processes that
you install yourself; those programs keep their own licenses.
