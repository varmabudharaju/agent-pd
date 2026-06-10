# Test evidence — session identity & multi-agent live view

Real Terminal screenshots (via [`capture`](https://github.com/varmabudharaju/capture))
of agent-pd running against a realistic multi-session, multi-agent fleet — three
Claude Code sessions across three projects, seeded through the **real** recorder by
[`examples/demo-sessions.sh`](../examples/demo-sessions.sh) (real hash chains, real
transcripts, real subagent briefs; nothing hand-drawn). Reproduce with:

```bash
bash examples/demo-sessions.sh && capture run
```

Spec for the session-identity feature:
[2026-06-09-session-identity-design.md](superpowers/specs/2026-06-09-session-identity-design.md).

## `pd list` — every session identified

One row per session: id, project directory, last activity, and the session's first
user prompt as a title. Identity is derived at read time from the audit log +
transcript, so it works for sessions recorded before this feature existed.

<img src="screenshots/demo/01-pd-list.png" width="100%" alt="pd list: three sessions, each identified by project directory, last activity and its first user prompt"/>

## `pd watch` — the header names the attached session

`pd watch` with no arguments attaches to the most recent session; the header says
*what* that is (project + first prompt), so it's never a mystery.

<img src="screenshots/demo/02-pd-watch-header.png" width="100%" alt="pd watch header naming the watched session: its project directory and first prompt, not just the UUID"/>

## `pd watch --all` — merged multi-agent feed

Three sessions interleaved in one feed: a `§sid · project · “title”` intro line on
each session's first appearance, agent banners with their briefs, per-agent colors,
and the two genuine flags this fleet contains — a `~/.aws/credentials` read and a
user-denied `curl | sh` — named on the line. Note what is **not** flagged: all the
ordinary in-project work is a quiet ✓.

<img src="screenshots/demo/03-pd-watch-all.png" width="100%" alt="pd watch --all: merged live feed across three sessions with intro lines, agent briefs and two genuine flags"/>

## `pd report` — forensic offense report

The orders-api session after the fact: per-agent digest (main + the
general-purpose subagent) and an offense table with quoted evidence.

<img src="screenshots/demo/04-pd-report.png" width="100%" alt="pd report for the orders-api session: per-agent digest and offense table with quoted evidence"/>

## `pd verify --all` — audit-log integrity

The hash chain verifies across all three sessions.

<img src="screenshots/demo/05-pd-verify.png" width="100%" alt="pd verify --all: hash-chain integrity check across all three demo sessions"/>
