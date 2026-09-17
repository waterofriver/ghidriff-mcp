# ghidriff-mcp

把 [ghidriff](https://github.com/clearbluejar/ghidriff)（基于 Ghidra 的二进制 diff 引擎）
封装成 AI agent 可直接调用的 [MCP](https://modelcontextprotocol.io) server。

给它一对新旧版本的二进制，它会通过 ghidriff 无头驱动 Ghidra 完成分析，然后把结果以**结构化 JSON**
交回来：匹配统计、新增/删除/修改的函数、单函数代码 diff、以及生成的 Markdown 报告 —— 而不是一屏控制台日志。

[![CI](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/waterofriver/ghidriff-mcp/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![MCP](https://img.shields.io/badge/MCP-server-6E56CF.svg)](https://modelcontextprotocol.io)

[English](README.md) | **简体中文**

---

## 目录

- [为什么需要它](#为什么需要它)
- [环境要求](#环境要求)
- [安装](#安装)
- [配置](#配置)
- [工具一览](#工具一览)
- [一次真实会话](#一次真实会话)
- [工作原理](#工作原理)
- [安全与信任模型](#安全与信任模型)
- [故障排查](#故障排查)
- [与 GhidraMCP 的关系](#与-ghidramcp-的关系)
- [项目结构](#项目结构)
- [开发](#开发)
- [许可证](#许可证)

## 为什么需要它

`ghidriff` 本身很好用，但它是**批处理 CLI**：调用之后要等 Ghidra 逐个导入、分析，最后在磁盘上得到一份
Markdown 报告和一份很大的 `pdiff` JSON。这个形态不适合 agent 循环 —— 在 agent 循环里你希望看完一个改动
就能追问某个函数，并把推理过程留在上下文里。

这个 server 补上的正是这段：

* **任务化而非阻塞调用。** 每次 diff 都在后台跑，有 id、有日志文件、有持久化的 `job.json`，
  进程崩溃或 server 重启都不会丢掉结果。
* **结构化输出。** 以 ghidriff 写出的 `pdiff` JSON 为准，server 把它转成紧凑摘要和单函数细节，
  而不是把几 MB 数据灌进模型上下文。
* **环境后置绑定。** server 自己的解释器里不需要装 ghidriff 或 Ghidra —— 它调用你配置的任意解释器或命令。
* **诚实的报错。** Ghidra 的各种失败模式被翻译成可执行的提示：缺少 `GHIDRA_INSTALL_DIR`、
  工程路径被 Ghidra 拒绝、JVM 内存不足、缺少 `pyghidra`。
* **边界由你掌握。** agent 决定 **diff 什么**，你决定 **引擎怎么跑**。见[安全与信任模型](#安全与信任模型)。

## 环境要求

| 组件 | 版本 | 说明 |
| --- | --- | --- |
| Python | 3.10+ | MCP server 自身 |
| [ghidriff](https://github.com/clearbluejar/ghidriff) | 1.x | `pip install ghidriff` |
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | 11.x / 12.x | 设置 `GHIDRA_INSTALL_DIR` |
| JDK | 21+ | Ghidra 12 需要较新的 JDK |

Ghidra 和 ghidriff **不必**和本 server 在同一个解释器里。如果你的 MCP 客户端从独立 venv 启动 server，
把 `GHIDRIFF_MCP_PYTHON` 指向装了 ghidriff 的那个解释器即可。

已在 Windows 上对 ghidriff 1.0.0 + Ghidra 12.1.3 + JDK 21 实测；CI 覆盖 Ubuntu / macOS / Windows
与 Python 3.10 / 3.13。

## 安装

```bash
pip install ghidriff-mcp
```

或从源码安装：

```bash
git clone https://github.com/waterofriver/ghidriff-mcp
cd ghidriff-mcp
pip install -e .
```

用内置自检确认工具链：

```bash
ghidriff-mcp --check
```

它会打印 Ghidra / Java / ghidriff 的 JSON 诊断（缺什么就给对应的修复建议），环境不可用时退出码非 0：

```jsonc
// ghidriff-mcp --check 输出（为控制篇幅做了删减）
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

同一份报告也通过 `ghidriff_environment` 工具提供给 agent。

## 配置

全部通过环境变量驱动。

| 变量 | 默认值 | 作用 |
| --- | --- | --- |
| `GHIDRIFF_MCP_HOME` | `~/ghidriff-mcp-work` | 运行目录、Ghidra 工程、diff 产物的根目录。 |
| `GHIDRA_INSTALL_DIR` | 自动探测 | 解压后的 Ghidra 目录。 |
| `GHIDRIFF_MCP_PYTHON` | server 自身解释器 | 装了 ghidriff 的解释器。 |
| `GHIDRIFF_MCP_COMMAND` | — | 显式指定 ghidriff 命令行，例如 `ghidriff --max-ram-percent 40`。优先级高于 `GHIDRIFF_MCP_PYTHON`。 |
| `GHIDRIFF_MCP_TIMEOUT` | `3600` | 单次运行的默认超时（秒）。 |
| `GHIDRIFF_MCP_MAX_JOBS` | `2` | 最大并发 diff 数（每个都会起一个 JVM）。 |
| `GHIDRIFF_MCP_EXTRA_ARGS` | — | 每次运行都追加的 ghidriff 原始参数。**仅限运维侧**：`--no-symbols`、`--jvm-args` 这类东西放这里，不要从工具调用传。 |
| `GHIDRIFF_MCP_LOG_LEVEL` | `INFO` | ghidriff 日志级别（`DEBUG` 非常啰嗦）。 |

> **Ghidra 路径规则。** Ghidra 拒绝任何包含以 `.` 开头路径段的工程路径
> （报错 `Path element starting with '.' is not permitted`）。请让 `GHIDRIFF_MCP_HOME` 不含这种路径段；
> 万一包含了，server 会把 Ghidra 工程挪到系统临时目录并给出警告，而不是等导入几分钟后才失败。

### MCP 客户端配置

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

需要 HTTP 传输的客户端：

```bash
ghidriff-mcp --transport streamable-http --host 127.0.0.1 --port 8765
```

命令行参数：`--check`（自检）、`--workspace PATH` 与 `--ghidra-install-dir PATH`
（对本次进程覆盖对应环境变量）、`--transport`、`--host`、`--port`、`--version`。

## 工具一览

共 13 个工具，统一 `ghidriff_` 前缀，便于和其他 Ghidra 相关 server 区分。

| 工具 | 作用 |
| --- | --- |
| `ghidriff_environment` | 检查 Ghidra / Java / ghidriff，并说明缺什么、怎么修。 |
| `ghidriff_start_diff` | 后台启动一次 diff，立刻返回 `job_id`。 |
| `ghidriff_run_diff` | 阻塞式便捷封装（内部就是上面这个 + 等待）。 |
| `ghidriff_job_status` | 单个任务的状态、耗时、日志尾部。 |
| `ghidriff_job_result` | 匹配统计、函数计数、函数名、产物路径。 |
| `ghidriff_job_log` | 原始 ghidriff 日志，支持 tail 与分页。 |
| `ghidriff_job_cancel` | 杀掉正在跑的 diff。 |
| `ghidriff_jobs` | 任务历史（持久化在 `job.json`，重启不丢）。 |
| `ghidriff_list_runs` | 列出磁盘上的 diff 产物，全工作区或指定目录。 |
| `ghidriff_read_report` | 分页读取生成的 Markdown 报告。 |
| `ghidriff_function_detail` | 单个改动函数：元数据、代码、代码 diff。 |
| `ghidriff_search_functions` | 按名字搜索改动过的函数。 |
| `ghidriff_settings` | 生效配置与环境变量。 |

`ghidriff_start_diff` 接受 `old_binary`、一个或多个 `new_binaries`、引擎
（`VersionTrackingDiff`、`SimpleDiff`、`StructualGraphDiff`）、`output_dir`、`project_dir`、
`summary`、`side_by_side`、`force_analysis`、`force_diff`、`bsim`、`bsim_full`、`min_func_len`、
`max_section_funcs`、`base_address`、`no_symbols`、`timeout_s`。
引擎原始透传参数**刻意不在**这个列表里 —— 它们只存在于 `GHIDRIFF_MCP_EXTRA_ARGS`。

## 一次真实会话

下面是 agent 从第一次调用到看清某个函数改动的完整流程。JSON 是**真实输出**，为控制篇幅做了删减。

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

接着可以用 `ghidriff_search_functions(query="crypt")` 找相关改动，或用
`ghidriff_read_report(start_line=1, max_lines=150)` 分页阅读渲染好的报告。

传入多个新版本二进制可以得到链式 diff（`old → v2 → v3`），再加 `summary=true` 会额外做一次
`old → 最新版` 的对比。想要逐函数 HTML diff 落盘就设 `side_by_side=true`。

## 工作原理

```
MCP 客户端 ──stdio──▶ ghidriff-mcp ──子进程──▶ ghidriff ──PyGhidra──▶ Ghidra (JVM)
                          │                         │
                          │                         └── 写出 <name>.ghidriff.md
                          │                                  json/<name>.ghidriff.json
                          └── job.json + ghidriff.log          json/<name>.ghidriff.matches.json
                              （结构化摘要、分页读取）
```

* server 从不 import ghidriff，所以 JVM 崩了也拖不倒它，取消任务就是一次 `kill`。
* 每个任务一个运行目录：`<workspace>/runs/<job_id>/`，里面有 `job.json`、`ghidriff.log`、
  `ghidriff/`（产物）和 `ghidra_projects/`。
* 子进程输出通过**继承的文件句柄**重定向进日志文件，而不是管道 —— 既保证可流式查看，
  也能在限制管道创建的环境里正常工作。
* `pdiff` JSON 惰性解析、限制体积、按 mtime 缓存。
* 工具调用里的相对路径按工作区解析，agent 不需要知道机器的绝对目录结构。

## 安全与信任模型

这个 server 以**你自己的权限**、在你指定的文件上本地驱动 ghidriff。接到 agent 之前，值得先清楚它约束了什么、
没约束什么：

* **不经过 shell。** 所有命令都是 server 拼好的 argv 数组，直接交给 exec 式进程创建。
  没有任何东西被插进 shell 字符串，因此文件名和参数值不可能变成 shell 语法。
* **agent 选目标，你选引擎。** 工具参数能决定 diff 哪些二进制、用哪个受支持的引擎、渲染多少输出；
  但**不能**决定跑哪个可执行文件、它的 JVM 参数，或任意额外 CLI 开关。这一点很关键：
  否则 `--jvm-args -javaagent:...` 就成了离一次模型决策只有一步之遥的任意代码执行。
* **形如选项的文件名被化解。** 二进制路径放在 `--` 分隔符之后，所以一个叫 `--force-analysis` 的文件仍然只是文件。
* **二进制是不可信输入。** 样本里的字符串、符号名、反编译代码、报告文本都会进入模型上下文。
  请把它们当作**数据**而非**指令**：精心构造的二进制可以试图诱导你的 agent 做事。
  你喂给模型的其它任何内容同理。
* **默认会访问网络查符号。** ghidriff 允许 Ghidra 解析 PDB，对带 PDB 元数据的 PE 文件来说，
  这可能意味着向符号服务器（包括微软的）发起查询，从而泄露一点"你正在分析什么"。
  离线场景请传 `no_symbols=true`，或设置 `GHIDRIFF_MCP_EXTRA_ARGS=--no-symbols`。
* **文件访问不做限制。** server 会读写你指定的任意位置，因为二进制通常不在工作区内。
  请使用专用的工作区，并且不要把你不希望出现在对话记录里的路径交给 agent。
* **传输方式。** 默认 stdio。HTTP 传输默认只绑 `127.0.0.1`（除非你传 `--host`），且**没有认证** ——
  绑到非回环地址等于把 server 暴露给该网络。
* **真正的攻击面是外部工具。** Ghidra 解析恶意文件的危险性远大于这层封装。保持 ghidriff 与 Ghidra 为最新版，
  并在用完即弃的虚拟机里跑样本。

一次运行产生的所有东西都在 `GHIDRIFF_MCP_HOME` 下，所以收工时该检查（并删除）的就是那个目录。

## 故障排查

| 现象 | 原因与处理 |
| --- | --- |
| `Path element starting with '.' is not permitted` | Ghidra 拒绝了工程路径。把 `GHIDRIFF_MCP_HOME` 设成不含 `.` 开头路径段的目录。 |
| 找不到 `GHIDRA_INSTALL_DIR` / Ghidra | 指向解压后的 Ghidra 目录（含 `support/` 的那个）。 |
| `No module named ghidriff` | 被调用的解释器里没装 ghidriff：设置 `GHIDRIFF_MCP_PYTHON` 或 `GHIDRIFF_MCP_COMMAND`。 |
| `No module named 'pyghidra'` | 要装带依赖的 ghidriff（`pip install ghidriff`），而不是只有 CLI。 |
| 第一次 diff 要等好几分钟 | 正常：Ghidra 需要把每个二进制导入并分析一遍。之后的 diff 会复用 Ghidra 工程，除非 `force_analysis=true`。 |
| `Symbols are disabled, but the symbol is already downloaded` | 对该二进制传了 `no_symbols=true`，但符号库里已有它的 PDB。删掉 PDB 或去掉该参数。 |
| `OutOfMemoryError` | 调低 `max_ram_percent`，或换更小的二进制。 |
| 任务一直 `queued` | 名额被别的任务占了；`GHIDRIFF_MCP_MAX_JOBS` 限制并发 JVM 数。 |
| `ghidriff exited 0 but no diff artefacts` | 输出目录被覆盖了（例如被 `GHIDRIFF_MCP_EXTRA_ARGS`）；看 `ghidriff_job_log`。 |
| `above the 512 MB parse limit` | pdiff 太大，出于安全不解析。改用 `ghidriff_read_report` 分页读 Markdown 报告。 |
| `ghidriff_environment` 第一次很慢 | 它要在可能已有 JVM 在跑的情况下启动配置的解释器；探测预算 120s，超时会明确报超时而不是一直挂着。 |

## 与 GhidraMCP 的关系

[GhidraMCP](https://github.com/LaurieWired/GhidraMCP) 把**运行中的 Ghidra GUI** 接给 agent：
交互式反编译、改名、加注释。本 server 做的是相反的事：**无 GUI、无打开工程，在两个版本之间做批量化 headless diff**。
两者互补，`ghidriff_` 前缀让 agent 可以同时使用它们而不混淆。

## 项目结构

```
src/ghidriff_mcp/
  server.py      FastMCP 工具层与 CLI 入口
  runner.py      ghidriff 命令构造与子进程执行
  jobs.py        后台任务状态机、job.json 持久化
  reports.py     pdiff / Markdown 解析、分页、体积限制
  ghidra_env.py  Ghidra / Java / ghidriff 的发现与诊断
  paths.py       工作区路径解析与 Ghidra 路径规则
  config.py      环境变量驱动的配置
tests/           单元测试、协议级测试、以及可选的集成测试
```

## 开发

```bash
pip install -e ".[dev]"
pytest                       # 110 个测试，不需要 Ghidra
ruff check src tests
ruff format --check src tests
```

依赖 Ghidra 的测试是可选的：

```bash
GHIDRIFF_MCP_INTEGRATION=1 GHIDRA_INSTALL_DIR=/path/to/ghidra pytest -m integration
```

它会生成一对 PE 文件（一份系统二进制的原始副本 + 一份入口点被改写过的副本），
并断言至少有一个函数被报告为 modified。

## 许可证

MIT，见 [LICENSE](LICENSE)。

本项目不包含 ghidriff 的源码，也不与其链接。它把 `ghidriff`（GPL-3.0）和 Ghidra（Apache-2.0）
作为**独立进程**调用，这两者由你自己安装，各自遵循自己的许可证。
