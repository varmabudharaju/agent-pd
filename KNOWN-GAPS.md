# Known gaps & deferred work

Captured 2026-06-02 during the "watch both main + subagents, flag snooping/bypass
consistently" redesign (Approach A). Things that are **not up to the mark** but are
deliberately out of the current change set, so we can come back to them.

Legend: 🐞 confirmed bug · ⚠️ heuristic/limitation · 📋 backlog/v2 · ✅ decided (won't do now)

---

## Being fixed in the current change set (NOT deferred — listed for context)

- **Denial capture was broken.** `hook.build_event` only set `decision` from a
  `permissionDecision`/`decision` field, but the real `PermissionDenied` payload has no
  such field (denial is implicit in the event name). So every recorded `PermissionDenied`
  landed with `decision=null` and the investigator dropped it — the permission-bypass
  *denial* path never fired with real data. → fixed in Section 3 (infer `decision="deny"`
  from the event name).
- **`pd report` couldn't see the main agent.** It built records from subagent transcripts
  + audit *denials* only; main-agent activity (`agent_id=""`) lived only as non-deny audit
  events that were thrown away. → fixed in Section 1 (audit log as single source).
- **`permission_bypass` scanned the whole `tool_input`** (incl. Bash `description`), so a
  command whose *description* mentioned `sudo` false-positived. → fixed in Section 3
  (match the `command` field only).

---

## 🐞 Confirmed issues, deferred

- **Judge API backend (`_call_model`) is unverified at runtime.** No test exercises the
  real Anthropic call (tests inject a fake `call`). The `output_config={"format":{"type":
  "json_schema",...}}` shape looks correct per docs but is unproven against a live key,
  and `pyproject` pins `anthropic>=0.40`, which likely predates structured-output support.
  *Fix later:* bump the floor pin, add one live-call smoke test (gated on a key), and wrap
  the call so a bad-param failure degrades like the no-credentials path already does.

## ⚠️ Heuristic limits / by-design

- **Bash path extraction (new scope engine) is heuristic.** It catches literal paths
  (`cat ../x`, `ls /etc`, `cd ..`, `find /`) but will miss paths built via shell variables,
  `$(...)`, or command substitution, and can occasionally over-flag. Deterministic
  file-tool checks remain exact.
- **`off_task` cannot run on the main agent.** It needs a "brief," which only subagents
  have (`meta.json`). The main interactive session has no brief, so off-task detection
  doesn't apply there. A main-agent off-task signal would need a different anchor (e.g. the
  user's last prompt) — not in scope.
- **`off_task` flag-value mis-extraction.** `_extract_search_term` returns the first
  non-dash token, so `rg -t py "foo"` extracts `py` (the value of `-t`) instead of `foo`.
  Adds noise to an already-noisy heuristic; inflates judge item count/cost.
- **`redundant` flags legitimate re-reads.** Re-reading a file after editing it counts as a
  duplicate. Severity is `low`, so tolerable, but `Read` re-reads probably shouldn't weigh
  the same as a duplicated `Grep`/`Bash`.
- **Sessions predating the hook (transcript-only) drop out of `pd report`.** With the audit
  log as the single source, a session with no `<id>.jsonl` won't appear. Acceptable — the
  hook records everything going forward.
- **Concurrent appends** to one session file could in theory interleave a >4 KB tool input
  on one line; the reader skips malformed/partial lines. Harmless, documented.

## 📋 Backlog / v2

- **Capture tool results/outcomes in the hook** (exit code, output size) → feed shows what
  each action *did*, not just what it attempted. Watch audit-log growth.
- **`out_of_scope` tool-allowlist half** — flag a subagent using a tool outside its declared
  `tools:` allowlist (needs reading `.claude/agents/<type>.md` frontmatter).
- **Verdict disk cache for the judge** — skip re-judging identical (brief, search) pairs.
- **`pd summary <session>`** — per-agent digest (files touched, time span, tool histogram).
- **Self-permissioning detection** — flag edits to `~/.claude/settings.json` that widen
  permissions (partly covered once `~/.claude` is on the sensitive list).
- **Other hook events** — `PostToolUseFailure`, `PreCompact`, etc. are not captured; could
  enrich the timeline.

## ✅ Considered, declined (for now)

- **Real-time push/desktop alerts.** Chosen delivery is `pd watch` (live scanner) +
  `pd report` (forensic). No OS-notification subsystem.
- **Blocking/intervention.** The hook stays logging-only, always exit 0. Catch-and-report,
  never arrest.

## Test-discipline note

The denial bug survived because the test fixtures *fabricated* a `permissionDecision`
field the real payload never sends, and every downstream test hand-built `decision="deny"`
objects — so nothing exercised the real `PermissionDenied` payload end-to-end. Going
forward: at least one test per hook-fed path must use a **realistic** payload (the shape
Claude Code actually sends), not a convenient one.
