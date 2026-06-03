# agent-pd — known-gaps hardening + two new detectors

**Date:** 2026-06-02
**Status:** Design approved (brainstorm), pre-spec-review
**Scope:** Four items from `KNOWN-GAPS.md` in one PR — judge robustness, detector
noise hardening, self-permissioning detection, and the tool-allowlist half of out_of_scope.
**Extends:** `2026-06-02-scope-and-denial-redesign-design.md`

## Problem

`KNOWN-GAPS.md` tracks deferred work. This PR closes four of those gaps:

1. **Judge API backend is unverified at runtime** and crashes hard on any backend error.
2. **Detector heuristic noise:** off_task mis-extracts grep flag values; Bash path
   extraction misses `VAR=val` prefixes and pipe segments; redundant flags benign file re-reads.
3. **No self-permissioning detection** — an agent editing its own permission config to
   widen access is a real bypass vector and is currently invisible.
4. **Tool-allowlist half of out_of_scope is unbuilt** — an agent using a tool outside its
   declared `tools:` allowlist isn't flagged.

## Goals / non-goals

**Goals:** close the four gaps with focused, well-tested units; keep detectors pure
(read pre-loaded data off the `AgentRecord`, never touch the filesystem); no new severity
tier (reuse critical/high).

**Non-goals:** capturing tool results/outcomes, verdict caching, `pd summary`, other hook
events — remain deferred in `KNOWN-GAPS.md`.

## Design

### 1. Judge backend robustness (`agent_pd/judge.py`, `pyproject.toml`)

- In `judge_records`, wrap each `call(system, user)` in try/except. On any exception the
  batch is counted as `errored` (a new int in the returned dict) and skipped — the command
  never crashes. Return shape becomes `{"confirmed": [...], "dropped": N, "errored": N, "usage": {...}}`.
- `_cmd_judge` prints `… N item(s) could not be judged (backend error)` when `errored > 0`.
- Bump the `anthropic` optional-dependency pin to a recent floor (e.g. `anthropic>=0.45`)
  with a comment that the call is also guarded; the wrap guarantees graceful degradation
  regardless of the installed version.
- **Tests:** inject a `call` that raises → `judge_records` returns `errored >= 1`, does not
  throw, and still returns confirmed/dropped for the agents that succeeded. A live smoke
  test guarded by `@pytest.mark.skipif` on missing `ANTHROPIC_API_KEY`.

### 2. Detector noise hardening (`scope.py`, `detectors/off_task.py`, `detectors/redundant.py`)

- **off_task flag values.** `_extract_search_term` for the grep family must skip the
  *value* of value-taking flags. Add `_VALUE_FLAGS = {"-t","--type","-e","--regexp","-f",
  "--file","-m","--max-count","-g","--glob"}`: when a token is one of these, skip the next
  token too; `--flag=value` forms are skipped whole. Then return the first remaining
  positional. `rg -t py "foo"` → `foo`.
- **Bash path extraction.** `scope.extract_paths`:
  - Strip leading `VAR=val` env-assignment tokens before identifying the binary
    (`FOO=bar cat /x` → binary `cat`).
  - Split the command on `|`, `&&`, `||`, `;` into segments and run the existing per-command
    extraction on each segment, unioning the results (`echo x | cat secrets` inspects
    `cat secrets`). De-dup preserved.
- **redundant re-reads.** Add `_SKIP_TOOLS = {"Read"}`; `redundant.detect` ignores actions
  whose `tool_name` is in it (re-reading a file is normal). Bash/Grep/Glob/WebFetch/etc.
  exact-duplicates still flagged.

### 3. Self-permissioning detector (new `agent_pd/detectors/self_permission.py`)

- New offense `self_permission`, severity **critical**, confidence high. **Not** subject to
  the permission-aware info-downgrade (editing one's own permission file is a bypass vector
  regardless of allow-rules) — the detector emits critical directly.
- `_PERM_KEYS = ("permissions", "allow", "defaultmode", "dangerouslyskippermissions",
  "bypasspermissions")` (matched case-insensitively).
- `_is_settings_path(path)` → true when the path contains a `.claude/` segment and the
  basename is `settings.json` or `settings.local.json`.
- Triggers:
  - `Write` → check `content`; `Edit` → check `new_string`; `NotebookEdit` → check
    `new_source`. If the target is a settings path AND the new text contains a perm key → flag.
  - `Bash` → if the command redirects (`>`/`>>`) into a settings path AND mentions a perm key → flag.
- Evidence: `Write modified <path> (self-permissioning: <key>)`.
- Config: `severity["self_permission"]="critical"`, `detectors["self_permission"]=True`.

### 4. Tool-allowlist / `tool_not_allowed` (new `agent_pd/agents_def.py` + `detectors/tool_scope.py`)

- `agents_def.load_agent_tools(agent_type, cwd, config_dir=None)`:
  - Looks for `<cwd>/.claude/agents/<agent_type>.md` then `<config_dir or ~/.claude>/agents/<agent_type>.md`.
  - Parses the YAML frontmatter (between `---` fences); reads `tools:`. Accepts a YAML list
    or a comma-separated string. Returns a `set[str]` of allowed tool names, or **`None`**
    when there's no def file or no `tools:` key (= unrestricted → no checks). Tolerant of
    missing/broken files (returns `None`).
- `AgentRecord` gains `tool_allowlist: set | None = None` (default None). Populated by
  `LiveMonitor.process` on new-agent creation: `load_agent_tools(atype, cwd)`. Detectors
  read `record.tool_allowlist` — never the filesystem (pure/testable, mirrors `allow_rules`).
- New `detectors/tool_scope.py`: offense `tool_not_allowed`, severity **high**. For each
  action, if `record.tool_allowlist is not None` and `action.tool_name` is truthy and not in
  it → flag once per (tool_name) per agent. Built-ins / no-frontmatter agents
  (`tool_allowlist is None`) are never flagged.
- Evidence: `used <Tool> — not in declared allowlist {…}`.
- Config: `severity["tool_not_allowed"]="high"`, `detectors["tool_not_allowed"]=True`.

### Cross-cutting

- `detectors/__init__.py`: register `self_permission` and `tool_scope` in `DETECTORS`.
- `config.py`: add the two severities and two detector toggles to `DEFAULTS`.
- `models.py`: add `AgentRecord.tool_allowlist`.
- `live.py`: populate `tool_allowlist` alongside `allow_rules` on new-agent creation.
- `pd-rules.yaml`: document the two new toggles/severities.
- No render/report change — both new offenses use existing severities (critical/high).
- `KNOWN-GAPS.md`: move the four items to a "✅ shipped" note.

## Components & boundaries

| Unit | Purpose | Depends on |
|---|---|---|
| `judge.judge_records` | per-batch error isolation | — |
| `scope.extract_paths` | env-prefix + pipe-segment aware path extraction | stdlib |
| `off_task._extract_search_term` | flag-value-aware search term | stdlib |
| `redundant.detect` | skip Read re-reads | config |
| `detectors/self_permission` | flag perm-key writes to settings files | models, config |
| `agents_def` | load `tools:` frontmatter → set/None | stdlib, yaml |
| `detectors/tool_scope` | flag tool ∉ declared allowlist | models, config |

## Testing strategy

TDD; tests fail before, pass after; no network. Detectors tested with `AgentRecord`s
carrying pre-set `tool_allowlist`/inputs (pure — no filesystem). `agents_def` and the judge
live smoke use tmp files / skipif.

- **judge:** injected raising `call` → `errored` counted, no crash, succeeding agents still
  processed; CLI message path.
- **off_task:** `rg -t py "foo"` → term `foo`; `grep -e bar baz` → `bar`; plain `grep foo .` → `foo`.
- **scope.extract_paths:** `FOO=bar cat /x` → `["/x"]`; `echo x | cat /secret` → `["/secret"]`;
  existing cases still pass.
- **redundant:** two identical `Read`s → no offense; two identical `Bash` → one offense.
- **self_permission:** Write to `~/.claude/settings.json` with `content` containing
  `"permissions"` → critical; Write to the same file with innocuous content → none; Write to
  a non-settings file containing `"permissions"` → none; Bash `echo … >> .claude/settings.json`
  with a perm key → critical.
- **agents_def:** def with `tools: [Read, Grep]` → `{"Read","Grep"}`; `tools: Read, Grep`
  (string) → same; no `tools:` key → `None`; missing file → `None`.
- **tool_scope:** record with `tool_allowlist={"Read"}` using `Bash` → flagged high; using
  `Read` → none; `tool_allowlist=None` → never flagged; same disallowed tool twice → one offense.
- **regression:** full suite green; `detectors/__init__` runs all six detectors.

## Out of scope / deferred

Remaining `KNOWN-GAPS.md` items (tool-result capture, verdict cache, `pd summary`, other
hook events, the lenient permission/path heuristics) stay deferred.
