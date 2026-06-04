# Session handoff — agent-pd

**Prepared:** 2026-06-03 · **Repo:** `/Users/varma/agent-pd` (GitHub `varmabudharaju/agent-pd`, branch `master`)
**State:** `master` @ `a65ec0e` · **104 commits** · **392 tests passing** · 6 detectors · working tree clean
(only this file is untracked). **3 feature PRs merged this session** (#4, #5, #6).

This captures what we did and decided so a new session can continue without re-deriving context.
For the project's architecture/mental-model read `HANDOFF.md`; for the security posture read
`SECURITY.md`; for deferred work + heuristic limits read `KNOWN-GAPS.md`.

---

## What this session did (3 PRs, in order)

### PR #4 — `feat/audit-storage-compaction` (gzip-only) — merged
Goal: make the audit log scalable for long-term bookkeeping/autopsy.
- New `agent_pd/store.py` owns ALL on-disk-layout knowledge. New `pd compact` gzips inactive
  session logs (`<sid>.jsonl` → `<sid>.jsonl.gz`), skipping the most-recently-modified (active)
  session. `pd report`/`pd watch`/`pd list` read both formats transparently via
  `store.iter_events`. Optional `--prune-older-than DAYS` (default: keep everything).
- **The pivot (important):** we first built a content-addressed **blob store** that externalized
  bulky `tool_input` strings. A final adversarial review caught that those exact fields
  (`content`/`new_string`/Bash `command`) are **detector-read**, so externalizing them made
  `pd compact` silently DROP real critical offenses — "provably lossless" was FALSE. We pivoted to
  **gzip-only** (every field stays inline → trivially lossless; ~5–10× on JSON text). Full history
  preserved on master (the blob commits → the pivot). Rationale in the design-doc revision history.
- Real-data check: a copy of `~/.claude/pd` went 1.7 MB → 436 KB with identical report output.

### PR #5 — `fix/security-hardening` — merged
Goal: close UNDER-flagging holes (the cardinal sin for a watchdog). Found via a 4-agent parallel
adversarial audit (permissions / hook-data-integrity / detector-evasion / red-team), each finding
backed by a runnable repro; fixed one batch at a time (TDD), then an adversarial whole-branch
review, then an independent verification sweep (which itself found one more — `/etc/shadow`).
- **permissions matching** now faithful to Claude Code: shell-operator split (a `Bash(git:*)` rule
  no longer permits `git status && rm -rf ~`), `$(...)`/backtick extraction, redirect targets
  treated separately (a command rule can't authorize `> ~/.ssh/authorized_keys`), word-boundary
  (`npm install:*` ≠ `npm installmalware`), gitignore-style globs (`*` ≠ cross `/`), conservative
  bias (ambiguity → NOT permitted).
- **Sensitive paths are never downgraded** to `info` by allow-rules. System credential files
  (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`, `/etc/ssh`, `/root`, shell history) and `~/.claude`
  (incl. the pd audit dir) added to the sensitive list.
- **self_permission** reframed: flags ANY agent write to its own control files
  (`.claude/settings*.json`, `.claude/agents/*.md`, `pd-rules*.yaml`) via ANY method
  (Write/Edit/NotebookEdit, or Bash cp/mv/tee/sed/python/base64/redirect/bare-name), regardless of
  content. Closes hook-removal + opaque-write evasions.
- **scope/out_of_scope** recurses into interpreter one-liners (`bash -c`, `python3 -c`, `node -e`),
  expands single-level `$VAR`, follows symlinks (best-effort), catches bare-basename sensitive files
  inside scripts.
- **permission_bypass** is now a regex engine with TWO tiers: `never_downgrade_patterns`
  (catastrophic — `rm -rf /` incl. long-flag/quoted forms, `rm -rf ~`/`$HOME`, `--no-preserve-root`,
  fork bomb, `dd of=/dev/`, `mkfs`, `curl|sh`) stay critical even under a broad allow-rule;
  `escalation_patterns` (sudo, chmod 777/setuid, chown root, shred, cwd-wipe `rm -rf .`/`*`)
  downgradable only by a PRECISE allow-rule (a bare `Bash` is not precise enough). Routine
  `rm -rf ./build` is not flagged.
- **hook** captures `denial_reason`, `tool_result`, `permission_mode`, `transcript_path`, and an
  `_extra` passthrough for unknown fields; forces `decision=deny` on `PermissionDenied`; logs errors
  to stderr; still always exits 0. **store.iter_events** dedups across the gz/plain compaction window
  (no double-counted offenses). `agent_type` allowlist lookup is case-insensitive.

### PR #6 — `feat/audit-integrity` — merged
Goal: make audit-log tampering DETECTABLE. New `agent_pd/integrity.py` + `pd verify`.
- Each event gains `seq` (monotonic/session) + `chain = sha256(prev_chain + canonical(event))`, or
  HMAC-SHA256 when `PD_AUDIT_KEY` is set. Computed by the hook under a **per-session flock** (correct
  under parallel subagents), with a `<sid>.head.json` anchor. Hook stays crash-safe (always exit 0,
  never loses an event, head-write failure is benign).
- `pd verify [--session ID] [--all]` recomputes the chain; rc 0 intact / rc 2 tamper|truncation.
  Detects edits, reordering, mid-deletion, tail truncation, inserted unchained lines, stale-head
  re-chain, and (with HMAC) edits by anyone without the key. **Verifies across `pd compact`.**
- **Honest framing (kept everywhere):** tamper-EVIDENT, not tamper-PROOF. A same-user agent that
  knows the scheme and can read `PD_AUDIT_KEY` can re-chain the whole log and pass `pd verify`. True
  tamper-proofing needs an off-host append-only sink (see "pick up next").

---

## Key decisions & rationale (so we don't relitigate)

- **gzip-only compaction, not blob externalization** — the bulky fields are detector-read, so
  externalizing them isn't lossless for detection. "100% correct detection" is a hard requirement.
- **Under-flagging is worse than over-flagging** for a watchdog. Matching is faithful to CC with a
  conservative bias (ambiguity → not permitted = stays flagged). Sensitive paths + catastrophic
  commands are NEVER downgraded.
- **self_permission = "any write to own control files"**, not "permission-keyword present" — the old
  narrow rule was the hook-removal hole.
- **Audit integrity is tamper-evident, not tamper-proof** — stated honestly; we explicitly did NOT
  oversell it (same mistake as the original "provably lossless" claim we had to retract).
- **Catch-and-report only** — the hook never blocks; always exit 0.

## Working conventions (IMPORTANT — repeat these)

- **Commit author:** `varma <sairam.vzf33@gmail.com>`. **NO AI-attribution trailers** — the repo
  forbids `Co-Authored-By: Claude` / "Generated with"; subagents sometimes add them. Verify each
  branch before merge: `git log <base>..HEAD --format=%B | grep -i "co-authored\|generated with"`
  must be empty.
- **Landing:** branch → push → `gh pr create --body-file <file>` (inline heredocs break on
  apostrophes/backticks) → `gh pr merge <branch> --rebase --delete-branch`. **Rebase-merge, never
  squash** — the user wants each feature-wise commit preserved on `master` (contribution graph).
  Direct `git push origin master` is blocked; the PR-merge path works.
  - Local-merge gotcha: a rebase-merge rewrites SHAs, so after merge `git pull --ff-only` FAILS
    (local master diverged). Fix: `git fetch origin && git reset --hard origin/master`.
- **Dev workflow used each PR:** parallel adversarial audit / brainstorming → writing-plans (bite-
  sized TDD) → subagent-driven-development (fresh implementer per task + spec/quality review) →
  **adversarial final review (use the opus model)** → independent verification sweep → PR. The
  adversarial reviews repeatedly caught real bugs the implementers/I missed — keep doing them.
- Recorded in memory: `~/.claude/projects/-Users-varma-agent-pd/memory/agent-pd-commit-workflow.md`.

## How to test it by hand (verified recipes)

```bash
python3 -m pytest -q                                   # 392 passing
python3 -c "from agent_pd.detectors import DETECTORS; print(list(DETECTORS))"  # 6 detectors
python3 -m agent_pd.cli list                           # real recorded sessions
python3 -m agent_pd.cli report --format md | head -40
python3 -m agent_pd.cli compact --dry-run              # then drop --dry-run to gzip old sessions
python3 -m agent_pd.cli verify --all                   # hash-chain integrity (rc 2 on tamper)
```
Live tamper demo: run the hook 3× for a test session, `pd verify` → intact; edit a middle line on
disk; `pd verify` → `✗ TAMPER DETECTED — chain breaks at seq 2 (bad-link)` rc 2. (We verified this.)

## Honest current state for PUBLIC release (see SECURITY.md / KNOWN-GAPS.md)
The product is substantially more correct/reliable than at session start (155 → 392 tests; every
exploit the audits+reviews+sweep found is closed and regression-tested). NOT claimed "bug-free."
Documented residual limits:
- Static analysis can't beat obfuscation/indirection: multi-level `$VAR`, `$IFS`/word-split,
  two-step `curl -o; sh`, base64/eval-assembled commands.
- Only Write/Edit/NotebookEdit + Bash are inspected for control-file writes (MCP filesystem tools
  could bypass self_permission). Symlink resolution is best-effort. `tool_result` stored verbatim
  (gzip mitigates). off_task is heuristic (`pd judge`); `~/.config` sensitivity is broad.
- Audit integrity is tamper-EVIDENT only (same-user re-chain defeats it).
Pre-public checklist still open: **add a LICENSE file**; validate the `PermissionDenied`/`tool_result`
field names against a real Claude Code denial (event names confirmed by recorded data; enrichment
fields are doc-sourced — see the claude-code-guide notes in the conversation).

## Open items / where to pick up next
- **Off-host append-only sink** — the one thing that makes the audit log truly tamper-PROOF against a
  same-user agent (the user flagged interest; it's the biggest remaining architectural gap). Options:
  mirror events to a different mount / syslog / an HTTP endpoint. Bigger scope, external dep.
- **LICENSE** for public release (MIT/Apache-2.0) — quick but blocking for others to use it.
- Confirm real `PermissionDenied` payload fields against a live denial (set a deny rule, trigger it,
  read the recorded line — the `_extra` passthrough now captures anything we didn't map).
- Lower-priority documented residuals above (truncate `tool_result`, MCP-tool coverage, etc.).

## Pointers
- Specs: `docs/superpowers/specs/2026-06-0{1,2,3}-*.md` (the 2026-06-03 storage spec has the
  gzip-only pivot in its revision history). Plans: `docs/superpowers/plans/`.
- `SECURITY.md` — threat model + honest limitations (public-facing). `HANDOFF.md` — mental model +
  detector table. `KNOWN-GAPS.md` — shipped/residual/deferred.
- Code map: `agent_pd/` — `hook.py` (recorder + chain), `integrity.py` (hash-chain core + head/lock),
  `store.py` (gzip compaction + transparent reads), `investigator.py` (`gather`), `live.py`
  (`watch`), `detectors/` (6), `scope.py`, `permissions.py`, `agents_def.py`, `summary.py`,
  `report.py`, `render.py`, `judge.py`, `config.py`, `models.py`, `cli.py`.
