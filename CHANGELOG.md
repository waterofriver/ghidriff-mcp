# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-09-17

Initial release.

### Added

* MCP server exposing the [ghidriff](https://github.com/clearbluejar/ghidriff)
  Ghidra binary-diffing engine over stdio, streamable HTTP and SSE.
* Background job model: `ghidriff_start_diff` returns immediately, jobs carry a
  log file and a persisted `job.json`, and results survive a server restart.
* Structured access to ghidriff's `pdiff` JSON: match statistics, added/deleted/
  modified function names, per-function metadata and code diffs, old/new program
  metadata diffs.
* Paged reads of the generated Markdown report and of raw job logs, so large
  diffs never have to be dumped into an agent's context at once.
* Environment discovery and diagnosis (`ghidriff_environment`) for Ghidra, Java
  and ghidriff, including actionable next steps, plus the same report from the
  command line via `ghidriff-mcp --check`.
* Automatic translation of common ghidriff/Ghidra failures (missing
  `GHIDRA_INSTALL_DIR`, Ghidra's dot-directory project rule, JVM out-of-memory,
  missing `pyghidra`) into readable errors.
* Guard against Ghidra's `Path element starting with '.' is not permitted`
  rejection: unsafe project locations fall back to a sanitised directory and
  raise a warning instead of failing after a lengthy import.
* Unit, protocol-level and opt-in integration tests (85 tests before the
  integration suite).

[Unreleased]: https://github.com/waterofriver/ghidriff-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/waterofriver/ghidriff-mcp/releases/tag/v0.1.0
