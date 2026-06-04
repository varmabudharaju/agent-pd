# Session handoff — agent-pd

**Prepared:** 2026-06-03 · **Repo:** `/Users/varma/agent-pd` (GitHub `varmabudharaju/agent-pd`, `master`)
**State:** `master` @ `815a928` · **110 commits** · **434 tests passing** · 6 detectors · tree clean.

agent-pd is a **catch-and-report watchdog** for Claude Code agent activity (main + subagents): it
records every tool call via a hook, then flags misbehavior (out-of-scope/sensitive access,
permission bypass, an agent editing its own config, disallowed-tool use, off-task work). It
DETECTS and REPORTS; it never blocks.

**Status note:** there are **no known *unfixed* bugs** — every bug found by this session's audits
and adversarial reviews was fixed with a regression test. The "Open work" below is **documented
limitations, enhancements, and one pre-public validation** — not latent defects. Items are scoped
so a fresh session can pick any one up cold.

Canonical companion docs (keep them authoritative; this file is the work-queue view):
- `HANDOFF.md` — architecture / mental model / detector table.
- `SECURITY.md` — threat model + honest limitations (public-facing).
- `KNOWN-GAPS.md` — full shipped/residual/declined ledger (more detail than this file).

---

## 60-second orientation

**Flow:** `hook.py` (runs per tool call, always exit 0) → appends a chained event to
`~/.claude/pd/audit/<sid>.jsonl` → `store.iter_events` reads it (transparently handles
`.jsonl` + gzipped `.jsonl.gz`) → `investigator.gather` builds per-agent `AgentRecord`s →
`detectors/` flag offenses → `report.py`/`render.py` (forensic `pd report`) and `live.py`
(live `pd watch`).

**Commands:** `pd report` · `pd watch` · `pd list` · `pd judge` (LLM off_task verdicts) ·
`pd compact` (gzip old sessions) · `pd verify` (hash-chain tamper check) ·
`pd sink push|status` (forward off-host) · `pd install-hook`.

**Code map (`agent_pd/`):** `hook.py` (recorder + hash-chain), `integrity.py` (chain core +
head/lock helpers), `sink.py` (off-host forwarder: file/http), `store.py` (gzip compaction +
transparent reads), `investigator.py` (`gather`), `live.py` (`watch`), `detectors/` (6:
permission_bypass, out_of_scope, redundant, off_task, self_permission, tool_scope),
`scope.py` (path extraction/classification), `permissions.py` (allow-rule matching →
`info` downgrade), `agents_def.py` (subagent tool allowlists), `config.py`, `models.py`,
`report.py`, `render.py`, `summary.py`, `judge.py`, `cli.py`, `install_hook.py`.

**Key invariants (don't regress):**
- The hook NEVER blocks and ALWAYS exits 0; it never loses an event (unchained fallback).
- Detection is faithful: **under-flagging is worse than over-flagging**; ambiguity → not
  permitted (stays flagged). Sensitive paths + catastrophic commands are NEVER downgraded.
- `pd compact` is gzip-only and **lossless for detection** (no field externalization — that was
  tried and reverted; see KNOWN-GAPS "declined").

---

## Working conventions (REPEAT THESE — they're load-bearing)

- **No AI-attribution trailers** in commits (`Co-Authored-By: Claude` / "Generated with"). Verify
  before merge: `git log <base>..HEAD --format=%B | grep -i "co-authored\|generated with"` empty.
- **Land via branch → push → `gh pr create --body-file` → `gh pr merge <b> --rebase
  --delete-branch`.** Rebase-merge, never squash (preserve per-commit history / contribution
  graph). Direct `git push origin master` is blocked.
  - **Gotcha:** rebase-merge rewrites SHAs, so after merge `git pull --ff-only` FAILS. Sync with
    `git fetch origin && git reset --hard origin/master`.
- **Dev flow that worked all session:** (parallel adversarial audit / design) → TDD batches via
  fresh subagents → **adversarial final review using the opus model** → independent verification
  sweep → PR. The adversarial reviews repeatedly caught real bugs (incl. two credential-leak-class
  issues) — KEEP doing them; don't skip the opus review or the manual sweep.
- **Test discipline:** at least one test per hook-fed path must use a **realistic** payload (the
  shape Claude Code actually sends), not a convenient fabricated one. (A prior denial bug survived
  for exactly this reason.)
- Memory: `~/.claude/projects/-Users-varma-agent-pd/memory/agent-pd-commit-workflow.md`.

## Hand-test recipes

```bash
python3 -m pytest -q                                   # 434 passing
python3 -c "from agent_pd.detectors import DETECTORS; print(list(DETECTORS))"   # 6
python3 -m agent_pd.cli report --format md | head -40
python3 -m agent_pd.cli compact --dry-run              # then drop --dry-run
python3 -m agent_pd.cli verify --all                   # rc 2 on tamper
PD_SINK_TYPE=file PD_SINK_PATH=/tmp/pd.ndjson python3 -m agent_pd.cli sink push --all
```

---

## OPEN WORK (prioritized — pick any item cold)

Legend: 🔴 do before public · 🟠 correctness/quality improvement · 🟢 enhancement/backlog ·
⚪ accepted limitation (document, likely won't "fix")

### ✅ P0 — pre-public validation (DONE 2026-06-04)
1. **`PermissionDenied` payload validated against a real recorded denial.**
   - Evidence: a genuine recorded denial (session `29f86214`, 2026-06-02 — the auto-mode classifier
     blocking a direct `git push origin master`) confirms the deny→critical path on real data:
     `decision=deny` set, `reason` captured, `tool_name`/`tool_input`/`cwd` correct, main-agent
     fields empty. Locked in as `tests/test_hook.py::test_build_event_real_recorded_denial_shape`.
   - **Finding:** the real CC reason field is **`reason`** (the only key the pre-`_extra` hook mapped,
     and it captured the reason) — **NOT** the doc-claimed `denial_reason`. Our mapping reads all
     three (`denial_reason`→`reason`→`permissionDecisionReason`) so it's correct regardless; comment
     in `hook.py` corrected to say so.
   - **Caveat (honest):** the hook normalizes, so the *complete* raw field set isn't fully
     observable, and a fresh denial couldn't be forced in autonomous mode (a no-op `git push` is
     allowed, not denied). The `_extra` passthrough now captures any unmapped field on the **next**
     live denial — so the tool can no longer silently miss a schema change. If you later get a real
     denial, run `pd report`/inspect its audit line for a populated `_extra` to confirm nothing new.
   - `LICENSE` (Apache-2.0) is DONE; copyright holder is `varma` — change to your full legal name /
     company entity in `LICENSE` if this becomes a venture (the holder is who owns it).

### 🟠 Correctness / quality improvements
2. **MCP / non-Bash file-write tools bypass `self_permission`.**
   - Where: `detectors/self_permission.py` (only inspects Write/Edit/NotebookEdit + Bash).
   - Why: a filesystem MCP tool with a different tool name could write `.claude/settings.json`
     undetected.
   - Approach: make the control-file check tool-agnostic — flag ANY tool whose input names a
     control path in a write-shaped field; or a configurable `write_tools` set. Size: M.
3. **Multi-level `$VAR` indirection not resolved** (`A=/etc/shadow; B=$A; cat $B`).
   - Where: `scope.py` (`_subst_var` / assignment tracking — currently single-level).
   - Why: a 2-hop variable hides a sensitive path from `out_of_scope`.
   - Approach: iterate variable substitution to a fixed point (cap iterations); only literal
     assignments. Size: S–M. (Note: `$IFS`/word-split, `$(...)`-built paths, base64/eval remain
     inherently out of reach — see ⚪ below.)
4. **`tool_result` stored verbatim** (can be large — full stdout / file contents).
   - Where: `hook.py` (capture), optionally `render.py`/`store.py`.
   - Why: inflates audit lines; gzip compaction mitigates on disk but raw `.jsonl` grows.
   - Approach: cap/truncate `tool_result` at capture (keep size + a head), or only at the render
     boundary. Decide whether detectors will ever READ it (currently none do). Size: S.
5. **`~/.config` is broad for `critical`** (holds innocuous app config → noisy).
   - Where: `config.py` `DEFAULT_SENSITIVE`.
   - Approach: narrow to the credential-bearing subpaths (`~/.config/gh`, `~/.config/gcloud`, …)
     instead of the whole tree, or downgrade `~/.config` to boundary. Size: S.
6. **Allow-rules read once per agent** (no mid-session reload).
   - Where: `live.py`/`models.py` (`AgentRecord.allow_rules` loaded at first event).
   - Why: if the user changes `permissions.allow` mid-session it isn't picked up. Minor.
   - Approach: re-read on change / per-event (watch perf). Size: S. (Low priority.)

### 🟢 Enhancements / backlog
7. **Sink: chunk large backlogs.** `sink.push_session` sends ALL pending events in one POST/append.
   - Where: `sink.py`. Approach: batch by max-N / max-bytes, advance state per chunk. Size: S.
8. **Sink: syslog backend** (stdlib `logging.handlers.SysLogHandler` → remote syslog = off-host).
   - Where: `sink.py` `make_sink`. Size: S.
9. **Sink: read-back reconciliation** `pd verify --against-sink` (fetch the off-host copy, diff vs
   local) — only if the sink is readable. Where: `cli.py`/`sink.py`. Size: M.
10. **Judge verdict disk cache** — skip re-judging identical (brief, search) pairs. Where:
    `judge.py`. Size: S–M.
11. **`pd summary <session>`** — per-agent digest (files touched, time span, tool histogram).
    Where: new `cli` cmd + `summary.py`. Size: S.
12. **Capture more hook events** (`PostToolUseFailure`, `PreCompact`, `SessionEnd`) to enrich the
    timeline. Where: hook is event-agnostic already; just ensure they flow through. Size: S.
    (`tool_result` outcome capture is already DONE.)

### ⚪ Accepted limitations (document, not "bugs" — see SECURITY.md)
- **Obfuscation/indirection evades static detection:** `$IFS`/word-split, two-step
  `curl -o f; sh f`, base64/eval-assembled commands, dynamically-built paths. pd raises the bar;
  it is **not a sandbox**. A determined same-privilege adversary can evade pattern matching.
- **Symlink resolution is best-effort** (symlink must exist at analysis time).
- **`off_task` is heuristic** (word-overlap); `pd judge` is the trustworthy path. Can't run on the
  main agent (no brief).
- **Audit integrity is tamper-EVIDENT, not tamper-PROOF.** Even with the off-host sink, the
  same-user agent holds the write credential → it can **forge** entries into the sink and can
  **disable the hook** (a gap, not a deletion). The sink only guarantees a genuine event already
  shipped off-host can't be retroactively deleted — AND only if the destination is genuinely
  append-only with non-deleting creds (a deployment requirement pd can't enforce). This is the
  realistic ceiling for this threat model; don't let anyone re-frame it as "tamper-proof."
- **Sessions predating the hook** (transcript-only, no `<sid>.jsonl`) don't appear in `pd report`.

---

## Session history (how we got here — 6 PRs, tests 155 → 434)
- **#4 `feat/audit-storage-compaction`** — `pd compact` gzip-only (pivoted away from a blob store
  that broke detection-losslessness; full story in the design-doc revision history).
- **#5 `fix/security-hardening`** — closed a class of under-flagging holes across permissions,
  self_permission, scope, permission_bypass, hook capture (10 fix commits).
- **#6 `feat/audit-integrity`** — hash-chain + `pd verify` (tamper-evident).
- **#7** — prior handoff. **#8** — Apache-2.0 `LICENSE` + metadata.
- **#9 `feat/audit-sink`** — off-host forwarder `pd sink push/status` (file/http).

Pointers: specs in `docs/superpowers/specs/`, plans in `docs/superpowers/plans/`.
