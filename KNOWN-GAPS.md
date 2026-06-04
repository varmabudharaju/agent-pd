# Known gaps & deferred work

Captured 2026-06-02 during the "watch both main + subagents, flag snooping/bypass
consistently" redesign (Approach A). Things that are **not up to the mark** but are
deliberately out of the current change set, so we can come back to them.

Legend: 🐞 confirmed bug · ⚠️ heuristic/limitation · 📋 backlog/v2 · ✅ decided (won't do now)

---

## ✅ Shipped on `feat/scope-and-denial` (formerly "being fixed")

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

## ✅ Shipped on `feat/audit-storage-compaction`

- **Unbounded audit-log growth** — `pd compact` gzips inactive session logs in-place
  (`<sid>.jsonl` → `<sid>.jsonl.gz`). Compaction is gzip-only and lossless for detection:
  every field stays inline, so detection over a compacted session is identical to the raw
  session. Active sessions (most-recently-modified) are skipped so the hook can always
  append. `--prune-older-than DAYS` optionally hard-deletes compacted sessions older than N
  days (default: keep everything). Addressed by `pd compact`; the storage-scalability
  concern is now resolved.

---

## ✅ Shipped on `feat/known-gaps`

- **Judge backend error isolation.** `judge_records` now isolates per-agent backend
  failures into a new `errored` count instead of crashing the batch; the CLI reports it.
  A bad call degrades per-agent rather than taking down the whole pass.
- **`off_task` flag-value mis-extraction** — `_extract_search_term` now skips grep/find
  flag *values* (e.g. `rg -t py "foo"` extracts `foo`, not `py`).
- **`redundant` Read re-reads** — `redundant` now ignores `Read` re-reads (re-reading a
  file after editing it no longer counts as a duplicate).
- **Bash `extract_paths` env-prefix / pipe handling** — `scope.extract_paths` now skips
  env-assignment prefixes (`FOO=bar cat /x`) and handles pipe segments, so the real
  path-bearing command past a `|` is scanned.
- **NEW detectors** (now exist; see HANDOFF detector table):
  - `self_permission` (critical) — flags a `Write`/`Edit`/`Bash` that writes a permission
    key into a `.claude/settings*.json` file (an agent widening its own permissions).
  - `tool_not_allowed` (high) — flags a subagent using a tool outside its declared
    `tools:` allowlist (read from `.claude/agents/<type>.md` frontmatter, carried on
    `AgentRecord.tool_allowlist`).

## ⚠️ Heuristic limits / by-design

- **Bash path extraction (new scope engine) is heuristic.** It catches literal paths
  (`cat ../x`, `ls /etc`, `cd ..`, `find /`) but will miss paths built via shell variables,
  `$(...)`, or command substitution, and can occasionally over-flag. Deterministic
  file-tool checks remain exact. Specific edge cases surfaced during review:
  - **`$VAR`-prefixed paths aren't expanded** by `classify`/`resolve` (only `~`/`~user`
    are), so a `$VAR` that points at a sensitive path can slip past.
  - **Operator split happens on the RAW string before shlex.** `scope.extract_paths`
    splits compound commands by regex on the raw command string before tokenizing, so a
    `|`/`;`/`&` *inside a quoted argument* can mis-segment the command. Rare, and the
    mangled fragment almost always resolves inside the project so it seldom produces a
    false offense. A more robust fix would shlex-tokenize once and split on operator tokens.
  - **`~/.config` is broad for `critical`** and may be noisy (it holds lots of innocuous
    app config) — consider narrowing it in tuning.
- **Permission-aware severity (permissions.py) matches leniently.** When an allow-rule
  matches, a flagged item is downgraded to `info` (permitted → FYI, not a crime). The
  matching is deliberately lenient — it can only *under*-flag (downgrade a real crime to
  info), never falsely escalate:
  - **Bash allow-rule matching uses prefix `startswith` with no word boundary**, so
    `Bash(npm install:*)` also matches `npm installfoo` — lenient-only (over-downgrades a
    flagged item to info, never falsely escalates).
  - **File-glob matching uses `fnmatch`**, whose `*` crosses `/`, so `Read(~/.config/**)`
    matches any depth under `~/.config` (broader than Claude Code's real `*` vs `**`
    distinction) — again lenient-only.
  - **Allow-rules are read once per agent** at its first event (no mid-session reload).
- **`off_task` cannot run on the main agent.** It needs a "brief," which only subagents
  have (`meta.json`). The main interactive session has no brief, so off-task detection
  doesn't apply there. A main-agent off-task signal would need a different anchor (e.g. the
  user's last prompt) — not in scope.
- **Sessions predating the hook (transcript-only) drop out of `pd report`.** With the audit
  log as the single source, a session with no `<id>.jsonl` won't appear. Acceptable — the
  hook records everything going forward.
- **Concurrent appends** to one session file could in theory interleave a >4 KB tool input
  on one line; the reader skips malformed/partial lines. Harmless, documented.

## 📋 Backlog / v2

- **Capture tool results/outcomes in the hook** (exit code, output size) → feed shows what
  each action *did*, not just what it attempted. Watch audit-log growth.
- **Verdict disk cache for the judge** — skip re-judging identical (brief, search) pairs.
- **`pd summary <session>`** — per-agent digest (files touched, time span, tool histogram).
- **Other hook events** — `PostToolUseFailure`, `PreCompact`, etc. are not captured; could
  enrich the timeline.

## ✅ Considered, declined (for now)

- **Real-time push/desktop alerts.** Chosen delivery is `pd watch` (live scanner) +
  `pd report` (forensic). No OS-notification subsystem.
- **Blocking/intervention.** The hook stays logging-only, always exit 0. Catch-and-report,
  never arrest.
- **Bulky-field externalization (blob store).** An earlier design externalized large
  `tool_input` fields (file content, Bash commands) into a content-addressed blob store.
  It was **tried and rejected**: those fields are detector-read, so externalizing them
  broke detection-losslessness. The feature shipped as gzip-only instead — see the design
  doc's revision history. There is no blob store, no `pd show`, no blob pruning.
- **Live-tailing an already-compacted (gz-only) session.** `pd watch` tails the active
  plain `.jsonl` file — it is a live scanner, not a replay tool. For a compacted session,
  use `pd report` (which reads both `.jsonl` and `.jsonl.gz`). Retrofitting live-tail for
  `.jsonl.gz` is a non-goal.

## Test-discipline note

The denial bug survived because the test fixtures *fabricated* a `permissionDecision`
field the real payload never sends, and every downstream test hand-built `decision="deny"`
objects — so nothing exercised the real `PermissionDenied` payload end-to-end. Going
forward: at least one test per hook-fed path must use a **realistic** payload (the shape
Claude Code actually sends), not a convenient one.
