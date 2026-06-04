# Known gaps & deferred work

Captured 2026-06-02 during the "watch both main + subagents, flag snooping/bypass
consistently" redesign (Approach A). Things that are **not up to the mark** but are
deliberately out of the current change set, so we can come back to them.

Legend: 🐞 confirmed bug · ⚠️ heuristic/limitation · 📋 backlog/v2 · ✅ decided (won't do now)

---

## ✅ Shipped on `fix/security-hardening` (security audit + fixes)

A focused pass that closed a class of **under-flagging / data-integrity** holes — places
where a real crime could slip past as `info` or go uncounted. Tests 155 → 347.

- **Faithful permission matching.** Allow-rule matching now mirrors Claude Code's real
  semantics instead of a naïve `startswith`: shell-operator splitting (a `Bash(git:*)`
  rule no longer authorizes `git status && rm -rf ~`), command-substitution `$(...)` /
  backtick extraction, redirect targets treated as a separate authorization (a command
  rule can't license `> ~/.ssh/authorized_keys`), word-boundary prefix matching
  (`npm install:*` ≠ `npm installmalware`), gitignore-style globs (`*` does **not** cross
  `/`, `**` does), spec stripping, anchoring, process-wrapper stripping. Bias is
  conservative: ambiguity → **not** permitted.
- **Sensitive paths are immune to downgrade.** A sensitive-path offense is **never**
  reduced to `info` by an allow-rule, no matter what the user configured.
- **Control-file protection (`self_permission`).** Now flags **any** agent write to its
  own control files — `.claude/settings*.json`, `.claude/agents/*.md`, `pd-rules*.yaml` —
  via **any** method (`Write`/`Edit`/`NotebookEdit`, or Bash `cp`/`mv`/`tee`/`sed`/
  `python`/`base64`/redirect/bare-name), regardless of content. Closes the hook-removal
  and opaque-write evasions (no longer requires seeing a literal permission key).
- **Scope recursion.** `out_of_scope` now recurses into interpreter one-liners
  (`bash -c`, `python3 -c`, `node -e`), expands single-level `$VAR` assignments, follows
  symlinks (best-effort), and captures bare-basename sensitive files inside script bodies.
- **`permission_bypass` regex engine, two tiers.** Replaced literal substring matching
  with regex and split the dangerous set in two: **never-downgrade** patterns
  (categorically catastrophic — `rm -rf /` incl. long-flag/quoted forms, `rm -rf ~`/
  `$HOME`, `--no-preserve-root`, fork bomb, `dd of=/dev/`, `mkfs`, `curl|sh`) stay
  critical even under a broad allow-rule; **escalation** patterns (sudo, chmod 777/setuid,
  chown root, shred, cwd-wipe `rm -rf .`/`*`) are downgradable only by a precise allow-rule.
  Routine `rm -rf ./build` is not flagged.
- **Richer hook capture.** The hook now records `denial_reason`, `tool_result`,
  `permission_mode`, `transcript_path`, and an `_extra` passthrough for unknown fields; it
  forces `decision=deny` on `PermissionDenied` even if a spoofed field says otherwise; it
  logs errors to stderr — and still always exits 0.
- **Store dedup.** `store.iter_events` dedups across the gz/plain compaction window (no
  double-counted offenses) while preserving disjoint resume events.
- **Broader sensitivity + case-insensitive allowlist.** `~/.claude` (including the pd audit
  dir) and system credential files (`/etc/shadow`, `/etc/passwd`, `/etc/sudoers`,
  `/etc/ssh`, `/root`, shell history) are sensitive. `agent_type` allowlist lookup is now
  case-insensitive (no casing-evasion).

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

- **Bash path extraction is heuristic by nature.** It catches literal paths
  (`cat ../x`, `ls /etc`, `cd ..`, `find /`), now recurses into interpreter one-liners,
  expands single-level `$VAR` assignments, and resolves symlinks best-effort — but static
  analysis cannot follow every dynamically-constructed path (see Residual limitations).
  Deterministic file-tool checks remain exact.
- **`~/.config` is broad for `critical`** and may be noisy (it holds lots of innocuous
  app config) — consider narrowing it in tuning.
- **Permission-aware severity (permissions.py) matches faithfully but still under-flags
  by design.** When an allow-rule matches, a flagged item is downgraded to `info`
  (permitted → FYI, not a crime). Matching is now faithful to Claude Code semantics
  (word-boundary prefixes, gitignore globs, operator-split, redirect isolation), and
  ambiguity resolves to *not permitted* — so the old over-downgrade holes (the `npm
  install:*` ⇒ `npm installfoo` prefix over-match, the fnmatch `*`-crosses-`/` over-broad
  glob) are closed. The residual risk is the opposite-and-acceptable one: a user who
  writes a genuinely broad allow-rule legitimately downgrades matching crimes to `info`.
  Sensitive paths and categorically-catastrophic commands are immune regardless.
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

## ⚠️ Residual limitations (static-analysis inherent — document, can't fully close)

These are the honest limits of a static, pattern-based detector. pd raises the bar; it is
not a sandbox, and a determined adversary using obfuscation or indirection can evade it.

- **Obfuscation / indirection evades static detection.** Multi-level `$VAR` chains
  (`A=/etc/shadow; B=$A; cat $B` — only single-level expansion is followed), `$IFS` /
  word-split tricks, two-step download-then-exec (`curl -o f url; sh f`), base64- or
  eval-assembled commands, and dynamically-constructed paths can all slip past the
  pattern matcher.
- **Only `Write`/`Edit`/`NotebookEdit` and `Bash` are inspected for control-file writes.**
  A filesystem MCP tool with a different tool name/shape could write `.claude/settings.json`
  without tripping `self_permission`. The detector covers the tools an agent actually has by
  default; a custom MCP write tool is a blind spot.
- **Symlink resolution is best-effort.** The symlink must exist on disk at analysis time
  for the target to be resolved; a symlink created and traversed within the same untracked
  step may not resolve.
- **`tool_result` is captured verbatim** and can be large; gzip compaction mitigates the
  on-disk cost, but per-field truncation is a possible follow-up.
- **`off_task` remains heuristic** (word-overlap) — use `pd judge` for trustworthy verdicts.
  `~/.config` sensitivity is broad and can be noisy.

## 📨 Deferred (architectural)

- **No cryptographic integrity on the audit log.** An agent with `Bash` can still delete or
  forge `~/.claude/pd/audit/*.jsonl`. Accessing the audit directory is now flagged
  sensitive-critical (we *detect* the attempt), but pd does **not prevent** tampering and
  has no tamper-evident log (HMAC, hash-chain, append-only WORM, or off-host shipping).
  This is the most significant remaining architectural gap for a security product, and is
  documented here as future work — not something the hardening pass closed.

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
