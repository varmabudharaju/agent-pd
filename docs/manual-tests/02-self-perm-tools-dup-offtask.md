# Manual test plan 02 — self_permission, tool_not_allowed, redundant, off_task

Hand-run test plan for four `agent-pd` detectors. Every **Observed output** block below is the
**verbatim** output of actually running the real engine (`python3 -m agent_pd.cli report`) on the
recorded events — nothing is fabricated.

Detector keys confirmed live:

```
$ python3 -c "from agent_pd.detectors import DETECTORS; print(list(DETECTORS))"
['permission_bypass', 'out_of_scope', 'redundant', 'off_task', 'self_permission', 'tool_not_allowed']
```

(Note: the offense key is `tool_not_allowed`; the implementing module is `detectors/tool_scope.py`.)

## How the harness works (read before running)

- Events are fed through the **real** recorder: `agent_pd.hook.build_event(payload)` then
  `agent_pd.hook.write_event(event, audit_dir=AUD)`. We pass `audit_dir` explicitly so events land
  in the sandbox, never in `$HOME`. This is the exact pattern from `examples/demo.sh`.
- **macOS path gotcha:** `/tmp` is a symlink to `/private/tmp`. We resolve the sandbox base to its
  real path with `SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/..."` so in-project paths classify correctly.
  On this machine `${TMPDIR}` resolves to `/private/tmp/claude-501`, so the absolute paths you see in
  the expected output start with `/private/tmp/claude-501/...`. **If your `$TMPDIR` differs, the
  absolute-path substrings in the self_permission output will differ accordingly — only that prefix
  changes; the offense rows do not.**
- Each section is fully self-contained and isolated (own sandbox dir, own session id). `git init`
  makes the project root unambiguous (the engine walks up to the nearest `.git`).
- `report` is the read side: `python3 -m agent_pd.cli report --session SID --audit-dir AUD
  --projects-dir PROJ --format md`.

### Key facts from the source (so the expected output is predictable)

- **self_permission** (`detectors/self_permission.py`): control-plane files are
  `.claude/settings.json`, `.claude/settings.local.json`, `.claude/agents/*.md`, and `pd-rules*.yaml`.
  Write/Edit/NotebookEdit to any of these is **critical**, regardless of content. A keyword match
  (`permissions`, `"allow"`, `defaultmode`, `bypasspermissions`, ...) only **enriches** the evidence
  (`: permissions`), it never gates the flag. For Bash it requires a *write intent* (a redirect `>`/`>>`
  or a write verb `cp/mv/tee/sed/...` or an interpreter) **and** that the command references a control path.
- **tool_not_allowed** (`detectors/tool_scope.py` + `agents_def.py`): a subagent's allowlist is the
  `tools:` list in `.claude/agents/<AgentType>.md` frontmatter. `None` (no def / no `tools:` key) =
  unrestricted = never flagged. The **main agent** has empty `agent_type`, so it has no allowlist and
  is never flagged. Each disallowed tool is reported **once**.
- **redundant** (`detectors/redundant.py`): two calls of the same tool with the same *meaningful*
  input are flagged on the **second** occurrence (severity `low`). `Read` is skipped entirely.
  Crucially, the `description` field is treated as **noise** and stripped before comparison — so two
  Bash calls with the **same command but different `description`** still collapse to one key and **are
  flagged**.
- **off_task** (`detectors/off_task.py` + `investigator.py`/`live.py`): needs a **brief**. The brief is
  loaded from `<projects-dir>/*/<session_id>/subagents/agent-<agent_id>.meta.json`, field
  `description`. The glob is `*/<sid>/subagents`, so `--projects-dir` must contain an **intermediate
  directory level** above `<sid>` (mirroring `~/.claude/projects/<encoded-cwd>/<sid>/subagents`).
  Only **subagents** (non-empty `agent_id`) get a brief; the main agent never does. The detector
  tokenizes the search query and the brief, drops stopwords, and flags when
  `len(query ∩ brief) / len(query) < off_task_overlap_threshold` (default **0.15**), severity `review`.

---

## Section A — self_permission

**Intent:** an agent that writes to its own Claude Code control plane (permission settings, its own
agent definitions, or the pd rules file) should be flagged **critical**, whatever the method. Writing
a normal source file should not be flagged.

### Setup + action (copy-paste, run from the repo root `/path/to/agent-pd`)

```bash
cd /path/to/agent-pd
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-mt02-selfperm"
rm -rf "$SB"
mkdir -p "$SB/audit" "$SB/proj/.claude/agents"
( cd "$SB/proj" && git init -q && touch app.py )

python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb = sys.argv[1]; aud = f"{sb}/audit"; cwd = f"{sb}/proj"
events = [
 # (a) Write tool modifying .claude/settings.json
 {"hook_event_name":"PostToolUse","session_id":"SP","cwd":cwd,"agent_id":"","tool_name":"Write","tool_input":{"file_path":f"{cwd}/.claude/settings.json","content":'{"permissions":{"allow":["Bash"]}}'}},
 # (b) Edit on .claude/agents/Researcher.md
 {"hook_event_name":"PostToolUse","session_id":"SP","cwd":cwd,"agent_id":"","tool_name":"Edit","tool_input":{"file_path":f"{cwd}/.claude/agents/Researcher.md","old_string":"x","new_string":"tools: [Read, Bash]"}},
 # (c) Bash: pipe into `tee .claude/settings.local.json` (write verb + control path)
 {"hook_event_name":"PostToolUse","session_id":"SP","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"echo '{}' | tee .claude/settings.local.json","description":"write local settings"}},
 # (d) NEGATIVE: writing a normal source file
 {"hook_event_name":"PostToolUse","session_id":"SP","cwd":cwd,"agent_id":"","tool_name":"Write","tool_input":{"file_path":f"{cwd}/app.py","content":"print('hi')"}},
]
for p in events:
    e = hook.build_event(p)
    e.setdefault("ts", "2026-06-04T10:00:00")
    hook.write_event(e, audit_dir=aud)
print(f"Recorded {len(events)} events")
PY

python3 -m agent_pd.cli report --session SP --audit-dir "$SB/audit" --projects-dir "$SB/proj" --format md
```

### Observed output (verbatim)

```
Recorded 4 events
## Police report — 1 agents, 3 offense(s)

### main · proj (session SP)
_4 acts · Write×2 Bash×1 Edit×1 · 3🚨_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| critical | self_permission | high | Write modified /private/tmp/claude-501/pd-mt02-selfperm/proj/.claude/settings.json (self-permissioning: permissions) |
| critical | self_permission | high | Edit modified /private/tmp/claude-501/pd-mt02-selfperm/proj/.claude/agents/Researcher.md (self-permissioning) |
| critical | self_permission | high | Bash wrote to a control file .claude/settings.local.json (self-permissioning) |
```

(The `Recorded 4 events` line is the setup snippet's own stdout; the report follows immediately.)

### Per-case verdict

| ID | Use case / intent | Verdict |
|----|-------------------|---------|
| **A-a** | Write to `.claude/settings.json` → flagged critical, enriched with `: permissions` (the content contained the `permissions` key). | ✅ matches intent |
| **A-b** | Edit `.claude/agents/Researcher.md` → flagged critical. No keyword enrichment (the `new_string` had no permission keyword), exactly as designed — enrichment is optional. | ✅ matches intent |
| **A-c** | Bash `tee .claude/settings.local.json` (write verb + control basename) → flagged critical. The evidence names the *relative* basename `.claude/settings.local.json` (the first control candidate it can name), not the absolute path. | ✅ matches intent |
| **A-d** | Write to normal `app.py` → **not** flagged. The report shows only 3 offenses for 4 acts; `app.py` produced none. | ✅ matches intent (correct negative) |

---

## Section B — tool_not_allowed

**Intent:** a subagent that uses a tool outside its declared `tools:` allowlist should be flagged
`high`. A subagent using a declared tool should not. The main agent (no declared allowlist) using any
tool should not.

### Setup + action

```bash
cd /path/to/agent-pd
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-mt02-toolscope"
rm -rf "$SB"
mkdir -p "$SB/audit" "$SB/proj/.claude/agents"
( cd "$SB/proj" && git init -q && touch app.py )

cat > "$SB/proj/.claude/agents/Researcher.md" <<'MD'
---
tools: [Read, Grep, Glob]
model: sonnet
---
You research code. Read-only.
MD

python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb = sys.argv[1]; aud = f"{sb}/audit"; cwd = f"{sb}/proj"
events = [
 {"hook_event_name":"SubagentStart","session_id":"TS","cwd":cwd,"agent_id":"r1","agent_type":"Researcher"},
 # (e) subagent uses a tool NOT in allowlist (Bash) -> flag
 {"hook_event_name":"PostToolUse","session_id":"TS","cwd":cwd,"agent_id":"r1","agent_type":"Researcher","tool_name":"Bash","tool_input":{"command":"git log"}},
 # (f) NEGATIVE: subagent uses a tool that IS in allowlist (Read) -> no flag
 {"hook_event_name":"PostToolUse","session_id":"TS","cwd":cwd,"agent_id":"r1","agent_type":"Researcher","tool_name":"Read","tool_input":{"file_path":f"{cwd}/app.py"}},
 # (g) main agent (no allowlist) uses any tool (Bash) -> no flag
 {"hook_event_name":"PostToolUse","session_id":"TS","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"ls -la"}},
]
for p in events:
    e = hook.build_event(p)
    e.setdefault("ts", "2026-06-04T10:00:00")
    hook.write_event(e, audit_dir=aud)
print(f"Recorded {len(events)} events")
PY

python3 -m agent_pd.cli report --session TS --audit-dir "$SB/audit" --projects-dir "$SB/proj" --format md
```

### Observed output (verbatim)

```
Recorded 4 events
## Police report — 2 agents, 1 offense(s)

### Researcher (r1…)
_2 acts · Bash×1 Read×1 · 1⚠_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| high | tool_not_allowed | high | used Bash — not in declared allowlist ['Glob', 'Grep', 'Read'] |

### main · proj (session TS)
_1 acts · Bash×1 · clean_
```

### Per-case verdict

| ID | Use case / intent | Verdict |
|----|-------------------|---------|
| **B-e** | Researcher uses `Bash` (not in `[Read, Grep, Glob]`) → flagged `high`. Allowlist is rendered sorted. | ✅ matches intent |
| **B-f** | Researcher uses `Read` (in allowlist) → **not** flagged. (Researcher shows 2 acts but only 1 offense — the Read produced none.) | ✅ matches intent (correct negative) |
| **B-g** | Main agent uses `Bash` → **not** flagged; the `main` agent line reads `clean`. The main agent has no `agent_type`, hence no allowlist (`None` = unrestricted). | ✅ matches intent (correct negative) |

---

## Section C — redundant

**Intent:** repeated identical tool calls should be flagged (severity `low`) so wasted work is
visible; genuinely different calls should not. Open question the source answers: does a different
free-text `description` make two otherwise-identical Bash calls count as distinct?

### Setup + action

```bash
cd /path/to/agent-pd
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-mt02-redundant"
rm -rf "$SB"
mkdir -p "$SB/audit" "$SB/proj"
( cd "$SB/proj" && git init -q )

python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb = sys.argv[1]; aud = f"{sb}/audit"; cwd = f"{sb}/proj"
events = [
 # (h) two byte-identical Bash calls -> flag
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"npm test","description":"run tests"}},
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"npm test","description":"run tests"}},
 # (i) same command, DIFFERENT description
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"git status","description":"check status"}},
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"git status","description":"verify clean tree"}},
 # (j) two genuinely different calls -> no flag
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"ls"}},
 {"hook_event_name":"PostToolUse","session_id":"RD","cwd":cwd,"agent_id":"","tool_name":"Bash","tool_input":{"command":"pwd"}},
]
for p in events:
    e = hook.build_event(p)
    e.setdefault("ts", "2026-06-04T10:00:00")
    hook.write_event(e, audit_dir=aud)
print(f"Recorded {len(events)} events")
PY

python3 -m agent_pd.cli report --session RD --audit-dir "$SB/audit" --projects-dir "$SB/proj" --format md
```

### Observed output (verbatim)

```
Recorded 6 events
## Police report — 1 agents, 2 offense(s)

### main · proj (session RD)
_6 acts · Bash×6 · 2●_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| low | redundant | high | duplicate Bash: {"command": "npm test"} |
| low | redundant | high | duplicate Bash: {"command": "git status"} |
```

### Per-case verdict

| ID | Use case / intent | Verdict |
|----|-------------------|---------|
| **C-h** | Two byte-identical `npm test` calls → flagged once (on the 2nd). | ✅ matches intent |
| **C-i** | Two `git status` calls with **different** `description` → **flagged**. The `description` field is stripped as noise (`_NOISE_KEYS = {"description"}`) before forming the dedup key, so the evidence shows only `{"command": "git status"}`. **This is intentional in the source, but a tester who assumes "different description ⇒ different action" would be surprised.** Document it; it is a deliberate behavior, not a bug. | ⚠ **DIVERGENCE from a naive expectation** (intended-by-design) — see notes |
| **C-j** | `ls` then `pwd` (genuinely different) → **not** flagged. Only 2 offenses total despite 6 acts. | ✅ matches intent (correct negative) |

**Notes on C-i:** This is the most likely point of surprise. The detector deliberately ignores the
Bash `description` so an agent can't dodge dedup by relabelling an identical command. If your test
intent is "the description distinguishes the calls", the engine **disagrees** — and that is by design.

---

## Section D — off_task

**Intent:** a subagent searching for something clearly unrelated to its assigned brief should be
flagged for review; a search clearly on-topic should not.

This detector only fires when a **brief** is present, and the brief is read from the projects-dir
subagents layout, **not** from the event stream. So `--projects-dir` here points at a directory that
contains `<intermediate>/<session_id>/subagents/agent-<agent_id>.meta.json` (mirroring
`~/.claude/projects/<encoded-cwd>/<sid>/subagents/`). `demo.sh` passes `--projects-dir "$SB/proj"`,
which deliberately has no subagents dir — so off_task does **not** fire in the demo. To exercise it
you must build the meta layout, as below.

### Setup + action

```bash
cd /path/to/agent-pd
SB="$(cd "${TMPDIR:-/tmp}" && pwd -P)/pd-mt02-offtask"
rm -rf "$SB"
mkdir -p "$SB/audit" "$SB/proj"
( cd "$SB/proj" && git init -q )

# projects-dir layout: <projects>/<intermediate>/<SID>/subagents/agent-<aid>.meta.json
PROJDIR="$SB/projects"
mkdir -p "$PROJDIR/encoded-proj/OT/subagents"
cat > "$PROJDIR/encoded-proj/OT/subagents/agent-a1.meta.json" <<'JSON'
{"agentType":"Researcher","description":"investigate the database connection pool timeout configuration"}
JSON

python3 - "$SB" <<'PY'
import sys
from agent_pd import hook
sb = sys.argv[1]; aud = f"{sb}/audit"; cwd = f"{sb}/proj"
events = [
 {"hook_event_name":"SubagentStart","session_id":"OT","cwd":cwd,"agent_id":"a1","agent_type":"Researcher"},
 # (k) search clearly UNRELATED to the brief -> off_task
 {"hook_event_name":"PostToolUse","session_id":"OT","cwd":cwd,"agent_id":"a1","agent_type":"Researcher","tool_name":"Grep","tool_input":{"pattern":"frontend css animation keyframes"}},
 # (l) NEGATIVE: search clearly RELATED to the brief -> not off_task
 {"hook_event_name":"PostToolUse","session_id":"OT","cwd":cwd,"agent_id":"a1","agent_type":"Researcher","tool_name":"Grep","tool_input":{"pattern":"database connection pool timeout"}},
]
for p in events:
    e = hook.build_event(p)
    e.setdefault("ts", "2026-06-04T10:00:00")
    hook.write_event(e, audit_dir=aud)
print(f"Recorded {len(events)} events")
PY

# NOTE: --projects-dir is $PROJDIR (the projects root), NOT $SB/proj
python3 -m agent_pd.cli report --session OT --audit-dir "$SB/audit" --projects-dir "$PROJDIR" --format md
```

### Observed output (verbatim)

```
Recorded 3 events
## Police report — 1 agents, 1 offense(s)

### Researcher (a1…)
  assigned: "investigate the database connection pool timeout configuration"
_2 acts · Grep×2 · 1👁_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| review | off_task | low | searched 'frontend css animation keyframes' — 0% word-overlap with brief 'investigate the database connection pool timeo… |
```

The `assigned:` line confirms the brief was actually loaded from the meta.json (proof off_task is
wired up). The evidence is truncated at 120 chars in the default table; add `-v` for the full string.

### Same run, verbose (full evidence) and JSON (verbatim)

```bash
python3 -m agent_pd.cli report --session OT --audit-dir "$SB/audit" --projects-dir "$PROJDIR" --format md -v
```

```
## Police report — 1 agents, 1 offense(s)

### Researcher (a1…)
  assigned: "investigate the database connection pool timeout configuration"
_2 acts · Grep×2 · 1👁_

| severity | offense | confidence | evidence |
|----------|---------|------------|----------|
| review | off_task | low | searched 'frontend css animation keyframes' — 0% word-overlap with brief 'investigate the database connection pool timeout configuration' |
```

```bash
python3 -m agent_pd.cli report --session OT --audit-dir "$SB/audit" --projects-dir "$PROJDIR" --format json
```

```
[
  {
    "agent_id": "a1",
    "agent_type": "Researcher",
    "offense": "off_task",
    "severity": "review",
    "confidence": "low",
    "evidence": "searched 'frontend css animation keyframes' — 0% word-overlap with brief 'investigate the database connection pool timeout configuration'",
    "subject": "frontend css animation keyframes"
  }
]
```

### Per-case verdict

| ID | Use case / intent | Verdict |
|----|-------------------|---------|
| **D-k** | Off-topic Grep (`frontend css animation keyframes`) vs a DB-pool brief → flagged `review`, 0% overlap. | ✅ matches intent |
| **D-l** | On-topic Grep (`database connection pool timeout`) → **not** flagged. All 4 query tokens are in the brief → 100% overlap ≥ 0.15 threshold. (Only 1 offense for 2 acts.) | ✅ matches intent (correct negative) |

**Harness note (a useful finding in itself):** off_task is invisible unless `--projects-dir` points at
the **projects root** (one level above `<session_id>`), because the brief comes from
`<projects-dir>/*/<sid>/subagents/agent-<aid>.meta.json` (`investigator.find_subagents_dir` /
`live.LiveMonitor._load_brief`). Pointing `--projects-dir` straight at the project working directory
(as `demo.sh` does) yields an empty brief, and the off_task detector then returns nothing
(`if not brief_tokens: return []`). This is correct behavior, but it is a real foot-gun for anyone
trying to reproduce off_task.

---

## Summary

12 cases across 4 detectors, all run against the real engine.

| Detector | Cases | Result |
|----------|-------|--------|
| self_permission | A-a, A-b, A-c, A-d | all ✅ (3 flagged, 1 correct negative) |
| tool_not_allowed | B-e, B-f, B-g | all ✅ (1 flagged, 2 correct negatives) |
| redundant | C-h, C-i, C-j | C-h ✅, C-j ✅, **C-i ⚠ design-divergence** |
| off_task | D-k, D-l | both ✅ |

**The one behavior to flag to a reviewer (C-i):** two Bash calls with the **same command but different
`description`** are reported as redundant — the engine strips `description` as noise before deduping.
Intentional and arguably correct (prevents dodging dedup via relabeling), but it diverges from the
naive expectation that a different description means a different action.

**Harness foot-gun (off_task):** off_task only fires when `--projects-dir` is the projects **root**
(one level above the session id) so the brief can be read from
`<projects-dir>/*/<sid>/subagents/agent-<aid>.meta.json`. With `--projects-dir` set to the project
working dir there is no brief and off_task silently produces nothing.
