# Changelog

All notable changes to **agent-pd** are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

_Nothing yet._

## [0.1.0] — 2026-06-08

First public release. A logging-only hook records every tool & permission event from
the main Claude Code agent **and** its subagents; the `pd` CLI replays that log through
deterministic detectors and reports rule offenses with quoted evidence. Catch-and-report
— it never blocks.

### Added
- **Logging hook** — registered on PostToolUse / PermissionDenied / SubagentStart /
  SubagentStop; appends one normalized, hash-chained line per event to a per-session
  audit log and always exits 0 (never blocks, never loses an event).
- **Six deterministic detectors** (zero token cost): `permission_bypass`, `out_of_scope`
  (project-boundary + sensitive paths), `self_permission`, `tool_not_allowed`,
  `redundant`, `off_task`.
- **`pd judge`** — opt-in, cost-capped LLM pass to confirm/drop noisy `off_task` flags,
  via the `claude` CLI (your subscription) or the Anthropic API (`pip install "agent-pd[judge]"`).
- **CLI**: `pd install-hook`, `list`, `report` (md/json, `--verbose`, `--agent`),
  `watch` (live "police scanner", `--all`, `--crimes-only`), `verify`, `compact`,
  `sink push|status`, and `pd --version`.
- **Permission-aware severity** — offenses matching your `permissions.allow` rules are
  downgraded to `info`, with faithful Claude Code matching semantics (see SYSTEM-DESIGN §9).
  Sensitive-path access and categorically-catastrophic commands are never downgraded.
- **Tamper-evident audit log** — per-session SHA-256 (or HMAC with `PD_AUDIT_KEY`) hash
  chain; `pd verify` detects edits/reordering/truncation. Optional off-host append-only
  sink (`pd sink`) closes the retroactive-deletion gap.
- **Configuration** — `pd-rules.yaml` is auto-discovered (cwd → project root → `~/.claude`;
  `--rules` overrides); configurable audit-log location via `--audit-dir` / `PD_AUDIT_DIR`
  (always resolved to an absolute path).

[Unreleased]: https://github.com/varmabudharaju/agent-pd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/varmabudharaju/agent-pd/releases/tag/v0.1.0
