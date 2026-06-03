# Known-Gaps Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close four `KNOWN-GAPS.md` items in one PR — judge backend robustness, detector noise hardening, a self-permissioning detector, and the tool-allowlist half of out_of_scope.

**Architecture:** Two small bugfix/hardening edits (judge error-isolation; off_task/scope/redundant heuristics) plus two new deterministic detectors (`self_permission`, `tool_scope`). New detectors read pre-loaded data off the `AgentRecord` (`tool_allowlist`, populated by `LiveMonitor` like `allow_rules`) so they stay pure and unit-testable. No new severity tier.

**Tech Stack:** Python 3.11 stdlib + PyYAML; pytest. No new runtime deps.

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `agent_pd/judge.py` | per-batch error isolation in `judge_records` | modify |
| `pyproject.toml` | bump `anthropic` pin | modify |
| `agent_pd/detectors/off_task.py` | flag-value-aware grep term extraction | modify |
| `agent_pd/scope.py` | env-prefix + pipe-segment aware `extract_paths` | modify |
| `agent_pd/detectors/redundant.py` | skip `Read` re-reads | modify |
| `agent_pd/detectors/self_permission.py` | flag perm-key writes to settings files | **create** |
| `agent_pd/agents_def.py` | load `tools:` frontmatter → set/None | **create** |
| `agent_pd/detectors/tool_scope.py` | flag tool ∉ declared allowlist | **create** |
| `agent_pd/models.py` | `AgentRecord.tool_allowlist` | modify |
| `agent_pd/live.py` | populate `tool_allowlist` | modify |
| `agent_pd/config.py` | new severities + detector toggles | modify |
| `agent_pd/detectors/__init__.py` | register the two new detectors | modify |
| `pd-rules.yaml`, `KNOWN-GAPS.md` | docs | modify |

---

## Task 1: Judge backend robustness

**Files:** Modify `agent_pd/judge.py`, `pyproject.toml`; Test `tests/test_judge.py`.

- [ ] **Step 1: Write the failing test** — append to `tests/test_judge.py` (read its top first to reuse existing imports/helpers; it builds `AgentRecord`s and calls `judge_records` with an injected `call`):

```python
def test_judge_isolates_backend_errors():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd import judge as judge_mod
    rules = load_rules(None)
    # two agents, each with an off-task search (brief unrelated to the query)
    recs = [
        AgentRecord(agent_id="a1", agent_type="x", brief="fix the parser", cwd="/p",
                    actions=[Action(agent_id="a1", tool_name="Grep", tool_input={"pattern": "kubernetes"})]),
        AgentRecord(agent_id="a2", agent_type="x", brief="fix the parser", cwd="/p",
                    actions=[Action(agent_id="a2", tool_name="Grep", tool_input={"pattern": "billing"})]),
    ]
    calls = {"n": 0}
    def flaky_call(system, user):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("backend boom")
        return {"verdicts": [{"index": 0, "off_task": True, "reason": "unrelated"}]}, None
    result = judge_mod.judge_records(recs, rules, call=flaky_call)
    assert result["errored"] == 1            # first agent's batch failed, isolated
    assert len(result["confirmed"]) == 1     # second agent still judged
    assert "errored" in result
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_judge.py::test_judge_isolates_backend_errors -q`
Expected: FAIL — `judge_records` raises `RuntimeError` (no error isolation) or `KeyError: 'errored'`.

- [ ] **Step 3: Implement** — in `agent_pd/judge.py`, modify `judge_records` to isolate per-batch errors. Change the `usage`/return scaffolding and wrap the `call`:

Replace the line `confirmed, dropped = [], 0` with:
```python
    confirmed, dropped, errored = [], 0, 0
```
Wrap the `data, u = call(system, user)` line and everything that consumes `data` for that agent in a try/except. Concretely, replace this block:
```python
        subjects = [o.subject or o.evidence for o in offs]
        system, user = build_prompt(rec.brief, subjects)
        data, u = call(system, user)
        if u is not None:
            usage["input_tokens"] += getattr(u, "input_tokens", 0) or 0
            usage["output_tokens"] += getattr(u, "output_tokens", 0) or 0
        verdicts = {}
        for v in data.get("verdicts", []):
            idx = v.get("index", v.get("id"))   # tolerate either key name
            if idx is not None:
                verdicts[idx] = v
        for i, o in enumerate(offs):
            v = verdicts.get(i)
            if v and v.get("off_task"):
                confirmed.append(Offense(
                    o.agent_id, o.agent_type, "off_task", o.severity, "high",
                    f"judged off-task: {v.get('reason', '').strip()}", subject=o.subject))
            else:
                dropped += 1
```
with:
```python
        subjects = [o.subject or o.evidence for o in offs]
        system, user = build_prompt(rec.brief, subjects)
        try:
            data, u = call(system, user)
        except Exception:
            errored += len(offs)        # isolate: this agent's batch failed, keep going
            continue
        if u is not None:
            usage["input_tokens"] += getattr(u, "input_tokens", 0) or 0
            usage["output_tokens"] += getattr(u, "output_tokens", 0) or 0
        verdicts = {}
        for v in data.get("verdicts", []):
            idx = v.get("index", v.get("id"))   # tolerate either key name
            if idx is not None:
                verdicts[idx] = v
        for i, o in enumerate(offs):
            v = verdicts.get(i)
            if v and v.get("off_task"):
                confirmed.append(Offense(
                    o.agent_id, o.agent_type, "off_task", o.severity, "high",
                    f"judged off-task: {v.get('reason', '').strip()}", subject=o.subject))
            else:
                dropped += 1
```
Change the final return from `return {"confirmed": confirmed, "dropped": dropped, "usage": usage}` to:
```python
    return {"confirmed": confirmed, "dropped": dropped, "errored": errored, "usage": usage}
```

- [ ] **Step 4: Surface `errored` in the CLI** — in `agent_pd/cli.py`, `_cmd_judge`, after the existing `print(f"Judged …")` summary, add:
```python
    if result.get("errored"):
        print(f"  {result['errored']} item(s) could not be judged (backend error).")
```
(Find the `result = judge_mod.judge_records(...)` call and the summary print that follows; insert the new lines right after that summary print, before the `for o in confirmed:` loop.)

- [ ] **Step 5: Bump the anthropic pin** — in `pyproject.toml`, change the judge optional-dependency line `judge = ["anthropic>=0.40"]` to:
```toml
judge = ["anthropic>=0.45"]   # structured-output `output_config`; judge_records also guards the call
```

- [ ] **Step 6: Run tests to verify pass**

Run: `python3 -m pytest tests/test_judge.py -q`
Expected: PASS. Then full suite `python3 -m pytest -q` — green.

- [ ] **Step 7: Commit**

```bash
git add agent_pd/judge.py agent_pd/cli.py pyproject.toml tests/test_judge.py
git commit -m "fix(judge): isolate per-agent backend errors (errored count) so the command never crashes"
```

---

## Task 2: Detector noise hardening (off_task + scope + redundant)

**Files:** Modify `agent_pd/detectors/off_task.py`, `agent_pd/scope.py`, `agent_pd/detectors/redundant.py`; Test `tests/test_off_task.py`, `tests/test_scope.py`, `tests/test_redundant.py`.

### 2a. off_task flag-value extraction

- [ ] **Step 1: Write the failing test** — append to `tests/test_off_task.py`:

```python
def test_extract_search_term_skips_flag_values():
    from agent_pd.detectors.off_task import _extract_search_term
    assert _extract_search_term('rg -t py "foo"') == "foo"      # -t value is not the term
    assert _extract_search_term("grep -e bar baz") == "bar"     # -e value IS the term
    assert _extract_search_term("grep foo .") == "foo"
    assert _extract_search_term("grep -rn foo /path") == "foo"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_off_task.py::test_extract_search_term_skips_flag_values -q`
Expected: FAIL — `rg -t py "foo"` currently returns `py`.

- [ ] **Step 3: Implement** — in `agent_pd/detectors/off_task.py`, add two flag sets near the other module constants (after `_NAME_FLAGS`):
```python
_PATTERN_FLAGS = {"-e", "--regexp"}                 # the flag's value IS the pattern
_SKIP_VALUE_FLAGS = {"-t", "--type", "-g", "--glob", "-m", "--max-count",
                     "-f", "--file", "--include", "--exclude",
                     "-A", "-B", "-C", "--context"}  # value is not the pattern
```
Then replace the grep-family branch in `_extract_search_term` (the block `if binary in _GREP_FAMILY:`) with:
```python
    if binary in _GREP_FAMILY:
        skip_next = False
        for idx, t in enumerate(rest):
            if skip_next:
                skip_next = False
                continue
            if t in _PATTERN_FLAGS:                 # `-e PATTERN` → PATTERN is the term
                return rest[idx + 1] if idx + 1 < len(rest) else ""
            if t in _SKIP_VALUE_FLAGS:              # `-t py` → skip the value
                skip_next = True
                continue
            if t.startswith("-"):                   # bare flag or --x=y
                continue
            return t                                # first positional = pattern
        return ""
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_off_task.py -q`
Expected: PASS (new + existing).

### 2b. scope.extract_paths: env-prefix + pipe segments

- [ ] **Step 5: Write the failing test** — append to `tests/test_scope.py`:

```python
def test_extract_paths_env_prefix_and_pipes():
    assert scope.extract_paths("FOO=bar cat /x") == ["/x"]
    assert scope.extract_paths("echo x | cat /secret") == ["/secret"]
    assert scope.extract_paths("A=1 B=2 sudo cat /root/.bashrc") == ["/root/.bashrc"]
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python3 -m pytest tests/test_scope.py::test_extract_paths_env_prefix_and_pipes -q`
Expected: FAIL — `FOO=bar` is treated as the binary; pipe segments aren't inspected.

- [ ] **Step 7: Implement** — in `agent_pd/scope.py`, add `import re` at the top (with the other imports). Add a segment-splitter constant near `_SHELL_OPS`:
```python
_SEG_RE = re.compile(r"\|\||&&|\||;")          # split compound commands into segments
_ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
```
Add a helper and rename the current single-command logic. Replace the whole `extract_paths` function with:
```python
def _strip_env(toks: list) -> list:
    i = 0
    while i < len(toks) and _ENV_RE.match(toks[i]):
        i += 1
    return toks[i:]


def _extract_one(command: str) -> list:
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    toks = _strip_env(toks)
    if not toks:
        return []
    if toks[0].rsplit("/", 1)[-1] == "sudo" and len(toks) > 1:   # drop a sudo prefix
        toks = _strip_env(toks[1:])
    if not toks:
        return []
    binary = toks[0].rsplit("/", 1)[-1]
    out, seen_positional = [], False
    for t in toks[1:]:
        if not t or t.startswith("-") or t in _SHELL_OPS:
            continue
        if t.startswith(_URL_PREFIXES):
            continue
        looks = t.startswith(("/", "~", "./", "../")) or t in ("..", ".")
        first_positional = not seen_positional
        seen_positional = True
        if looks or (binary in PATH_COMMANDS and first_positional):
            out.append(t)
    return out


def extract_paths(command: str) -> list:
    """Heuristically pull filesystem paths out of a Bash command. Handles env-var
    prefixes (`FOO=bar cat /x`), a leading sudo, and compound commands (splits on
    `| || && ;` and inspects each segment). Conservative per-segment: a token is a path
    only if it looks like one or is the first positional of a known path-command."""
    out, seen = [], set()
    for seg in _SEG_RE.split(command or ""):
        for p in _extract_one(seg):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out
```

- [ ] **Step 8: Run tests to verify pass**

Run: `python3 -m pytest tests/test_scope.py tests/test_out_of_scope.py -q`
Expected: PASS (new + all existing scope/out_of_scope tests — the existing `extract_paths` cases like `echo hi > /etc/cfg`, `sudo cat /root/.bashrc`, `git commit -m x` must still hold).

### 2c. redundant: skip Read re-reads

- [ ] **Step 9: Write the failing test** — append to `tests/test_redundant.py` (read its top for the existing `_rec`/imports; reuse them):

```python
def test_read_rereads_not_flagged():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import redundant
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=[
        Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/app.py"}),
        Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/app.py"}),
    ])
    assert redundant.detect(rec, rules) == []


def test_bash_duplicates_still_flagged():
    from agent_pd.models import Action, AgentRecord
    from agent_pd.config import load_rules
    from agent_pd.detectors import redundant
    rules = load_rules(None)
    rec = AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=[
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
    ])
    assert len(redundant.detect(rec, rules)) == 1
```

- [ ] **Step 10: Run test to verify it fails**

Run: `python3 -m pytest tests/test_redundant.py::test_read_rereads_not_flagged -q`
Expected: FAIL — duplicate Reads are currently flagged.

- [ ] **Step 11: Implement** — in `agent_pd/detectors/redundant.py`, add a constant near `_NOISE_KEYS`:
```python
_SKIP_TOOLS = {"Read"}   # re-reading a file is normal; not a redundancy worth flagging
```
In `detect`, add a skip at the top of the `for a in record.actions:` loop (before the `key = ...` line):
```python
        if a.tool_name in _SKIP_TOOLS:
            continue
```

- [ ] **Step 12: Run tests + commit**

Run: `python3 -m pytest -q`
Expected: PASS (full suite green).

```bash
git add agent_pd/detectors/off_task.py agent_pd/scope.py agent_pd/detectors/redundant.py \
        tests/test_off_task.py tests/test_scope.py tests/test_redundant.py
git commit -m "fix(detectors): off_task skips flag values; extract_paths handles env-prefix/pipes; redundant ignores Read re-reads"
```

---

## Task 3: Self-permissioning detector

**Files:** Create `agent_pd/detectors/self_permission.py`; Modify `agent_pd/config.py`, `agent_pd/detectors/__init__.py`; Test `tests/test_self_permission.py`.

- [ ] **Step 1: Write the failing test** — create `tests/test_self_permission.py`:

```python
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import self_permission


def _rec(actions):
    return AgentRecord(agent_id="a1", agent_type="x", brief="b", cwd="/p", actions=actions)


def test_write_permissions_to_settings_flagged_critical():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/Users/x/.claude/settings.json",
                                   "content": '{"permissions": {"allow": ["Bash(rm:*)"]}}'})])
    offs = self_permission.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "self_permission"
    assert offs[0].severity == "critical"
    assert "self-permissioning" in offs[0].evidence


def test_edit_settings_without_perm_key_not_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Edit",
                       tool_input={"file_path": "/Users/x/.claude/settings.json",
                                   "new_string": '{"theme": "dark"}'})])
    assert self_permission.detect(rec, rules) == []


def test_perm_key_in_non_settings_file_not_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/p/notes.md",
                                   "content": "permissions and allow lists"})])
    assert self_permission.detect(rec, rules) == []


def test_bash_redirect_into_settings_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": 'echo \'{"permissions":{}}\' >> ~/.claude/settings.local.json'})])
    offs = self_permission.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_self_permission.py -q`
Expected: FAIL — `No module named 'agent_pd.detectors.self_permission'`.

- [ ] **Step 3: Implement** — create `agent_pd/detectors/self_permission.py`:

```python
"""Flags an agent modifying its OWN Claude Code permission config — writing a permission
key into a .claude/settings*.json. A real bypass vector, so always critical (not subject
to the permission-aware info-downgrade)."""
from ..models import Offense

OFFENSE = "self_permission"
_SETTINGS_NAMES = ("settings.json", "settings.local.json")
_PERM_KEYS = ("permissions", "allow", "defaultmode",
              "dangerouslyskippermissions", "bypasspermissions")
# tool -> the field holding the new text written to the file
_NEW_TEXT = {"Write": "content", "Edit": "new_string", "NotebookEdit": "new_source"}


def _is_settings_path(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    base = p.rsplit("/", 1)[-1]
    return ".claude" in p and base in _SETTINGS_NAMES


def _perm_key_in(text: str):
    low = (text or "").lower()
    for k in _PERM_KEYS:
        if k in low:
            return k
    return None


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "critical")
    out = []
    for a in record.actions:
        ti = a.tool_input or {}
        if a.tool_name in _NEW_TEXT:
            path = ti.get("file_path") or ti.get("notebook_path") or ""
            if not _is_settings_path(path):
                continue
            key = _perm_key_in(str(ti.get(_NEW_TEXT[a.tool_name], "")))
            if key:
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                                   f"{a.tool_name} modified {path} (self-permissioning: {key})"))
        elif a.tool_name == "Bash":
            cmd = str(ti.get("command", ""))
            if ">" in cmd and ".claude" in cmd and any(n in cmd for n in _SETTINGS_NAMES):
                key = _perm_key_in(cmd)
                if key:
                    out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                                       f"Bash wrote to a settings file (self-permissioning: {key})"))
    return out
```

- [ ] **Step 4: Register + config** — in `agent_pd/detectors/__init__.py`, add `self_permission` to the imports and the `DETECTORS` dict:
```python
from . import permission_bypass, out_of_scope, redundant, off_task, self_permission

DETECTORS = {
    "permission_bypass": permission_bypass,
    "out_of_scope": out_of_scope,
    "redundant": redundant,
    "off_task": off_task,
    "self_permission": self_permission,
}
```
In `agent_pd/config.py` `DEFAULTS`: add `"self_permission": "critical",` to the `severity` dict and `"self_permission": True,` to the `detectors` dict.

- [ ] **Step 5: Run tests + commit**

Run: `python3 -m pytest -q`
Expected: PASS (full suite). Note: `out_of_scope` may ALSO flag the settings writes (path scope) — that's fine, distinct offenses.

```bash
git add agent_pd/detectors/self_permission.py agent_pd/detectors/__init__.py agent_pd/config.py tests/test_self_permission.py
git commit -m "feat(self_permission): flag perm-key writes to .claude/settings files (critical)"
```

---

## Task 4: Agent-definition loader (`agents_def.py`)

**Files:** Create `agent_pd/agents_def.py`; Test `tests/test_agents_def.py`.

- [ ] **Step 1: Write the failing test** — create `tests/test_agents_def.py`:

```python
from agent_pd import agents_def


def _write_agent(dirpath, name, frontmatter):
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / f"{name}.md").write_text(f"---\n{frontmatter}\n---\nbody\n")


def test_tools_as_list(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "tools: [Read, Grep]\nmodel: opus")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) == {"Read", "Grep"}


def test_tools_as_csv_string(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "tools: Read, Grep, Bash")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) == {"Read", "Grep", "Bash"}


def test_no_tools_key_returns_none(tmp_path):
    _write_agent(tmp_path / ".claude" / "agents", "Explore", "model: opus")
    assert agents_def.load_agent_tools("Explore", str(tmp_path)) is None


def test_missing_def_returns_none(tmp_path):
    assert agents_def.load_agent_tools("Nope", str(tmp_path), config_dir=str(tmp_path / "cfg")) is None


def test_empty_agent_type_returns_none(tmp_path):
    assert agents_def.load_agent_tools("", str(tmp_path)) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_agents_def.py -q`
Expected: FAIL — `No module named 'agent_pd.agents_def'`.

- [ ] **Step 3: Implement** — create `agent_pd/agents_def.py`:

```python
"""Loads a subagent's declared `tools:` allowlist from its agent definition file
(`.claude/agents/<type>.md` frontmatter). Returns a set of tool names, or None when there
is no definition or no `tools:` key (= unrestricted). Used by the tool_scope detector."""
import os
from pathlib import Path

import yaml


def _parse_tools(front: dict):
    tools = front.get("tools")
    if tools is None:
        return None
    if isinstance(tools, str):
        return {t.strip() for t in tools.split(",") if t.strip()}
    if isinstance(tools, list):
        return {str(t).strip() for t in tools if str(t).strip()}
    return None


def _frontmatter(text: str) -> dict:
    if not text.startswith("---"):
        return {}
    parts = text.split("---", 2)
    if len(parts) < 3:
        return {}
    try:
        data = yaml.safe_load(parts[1]) or {}
    except yaml.YAMLError:
        return {}
    return data if isinstance(data, dict) else {}


def _load_one(path: Path):
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return None
    return _parse_tools(_frontmatter(text))


def load_agent_tools(agent_type: str, cwd: str = "", config_dir: str = None):
    """Project `.claude/agents/<type>.md` takes precedence over the user config dir.
    Returns a set of allowed tool names, or None (no def / no `tools:` key)."""
    if not agent_type:
        return None
    bases = []
    if cwd:
        bases.append(Path(cwd) / ".claude" / "agents")
    cfg = config_dir or os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    bases.append(Path(cfg) / "agents")
    for base in bases:
        tools = _load_one(base / f"{agent_type}.md")
        if tools is not None:
            return tools
    return None
```

- [ ] **Step 4: Run tests to verify pass + commit**

Run: `python3 -m pytest tests/test_agents_def.py -q`
Expected: PASS. Then `python3 -m pytest -q` — green.

```bash
git add agent_pd/agents_def.py tests/test_agents_def.py
git commit -m "feat(agents_def): load tools: frontmatter allowlist from .claude/agents/<type>.md"
```

---

## Task 5: tool_scope detector + wiring

**Files:** Create `agent_pd/detectors/tool_scope.py`; Modify `agent_pd/models.py`, `agent_pd/live.py`, `agent_pd/config.py`, `agent_pd/detectors/__init__.py`; Test `tests/test_tool_scope.py`, `tests/test_models.py`.

- [ ] **Step 1: Write the failing tests** — create `tests/test_tool_scope.py`:

```python
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import tool_scope


def _rec(actions, allowlist):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/p",
                       actions=actions, tool_allowlist=allowlist)


def test_tool_outside_allowlist_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"})],
               allowlist={"Read", "Grep"})
    offs = tool_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "tool_not_allowed"
    assert offs[0].severity == "high"
    assert "Bash" in offs[0].evidence


def test_tool_inside_allowlist_clean():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Read", tool_input={"file_path": "/p/x"})],
               allowlist={"Read", "Grep"})
    assert tool_scope.detect(rec, rules) == []


def test_no_allowlist_never_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"})],
               allowlist=None)
    assert tool_scope.detect(rec, rules) == []


def test_same_disallowed_tool_flagged_once():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash", tool_input={"command": "ls"}),
                Action(agent_id="a1", tool_name="Bash", tool_input={"command": "pwd"})],
               allowlist={"Read"})
    assert len(tool_scope.detect(rec, rules)) == 1
```

Add to `tests/test_models.py`:
```python
def test_agent_record_tool_allowlist_default():
    rec = AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd="/x")
    assert rec.tool_allowlist is None
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_tool_scope.py tests/test_models.py -q`
Expected: FAIL — no `tool_scope` module; `AgentRecord` has no `tool_allowlist`.

- [ ] **Step 3: Implement the model field** — in `agent_pd/models.py`, add to `AgentRecord` after `allow_rules`:
```python
    tool_allowlist: object = None   # set[str] of declared tools, or None = unrestricted
```

- [ ] **Step 4: Implement the detector** — create `agent_pd/detectors/tool_scope.py`:

```python
"""Flags a subagent using a tool outside its declared `tools:` allowlist. The allowlist is
carried on record.tool_allowlist (loaded by LiveMonitor from the agent definition); None
means unrestricted (built-in agents, or no `tools:` key) and is never flagged."""
from ..models import Offense

OFFENSE = "tool_not_allowed"


def detect(record, rules) -> list:
    allow = getattr(record, "tool_allowlist", None)
    if allow is None:
        return []
    sev = rules.severity.get(OFFENSE, "high")
    out, seen = [], set()
    for a in record.actions:
        t = a.tool_name
        if not t or t in allow or t in seen:
            continue
        seen.add(t)
        out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                           f"used {t} — not in declared allowlist {sorted(allow)}"))
    return out
```

- [ ] **Step 5: Register + config** — in `agent_pd/detectors/__init__.py`, add `tool_scope` to the imports and `DETECTORS`:
```python
from . import (permission_bypass, out_of_scope, redundant, off_task,
               self_permission, tool_scope)

DETECTORS = {
    "permission_bypass": permission_bypass,
    "out_of_scope": out_of_scope,
    "redundant": redundant,
    "off_task": off_task,
    "self_permission": self_permission,
    "tool_not_allowed": tool_scope,
}
```
In `agent_pd/config.py` `DEFAULTS`: add `"tool_not_allowed": "high",` to `severity` and `"tool_not_allowed": True,` to `detectors`.

- [ ] **Step 6: Populate `tool_allowlist` in LiveMonitor** — in `agent_pd/live.py`, add the import near `from .permissions import load_allow_rules`:
```python
from .agents_def import load_agent_tools
```
In `LiveMonitor.process`, the new-agent `AgentRecord(...)` constructor call currently passes `allow_rules=load_allow_rules(event.get("cwd", ""))`. Add a `tool_allowlist` kwarg:
```python
            self.records[aid] = AgentRecord(agent_id=aid, agent_type=atype, brief=brief,
                                            cwd=event.get("cwd", ""), actions=[],
                                            allow_rules=load_allow_rules(event.get("cwd", "")),
                                            tool_allowlist=load_agent_tools(atype, event.get("cwd", "")))
```

- [ ] **Step 7: Run tests to verify pass + commit**

Run: `python3 -m pytest -q`
Expected: PASS (full suite). The `DETECTORS` registry now has six detectors.

```bash
git add agent_pd/detectors/tool_scope.py agent_pd/detectors/__init__.py agent_pd/models.py \
        agent_pd/live.py agent_pd/config.py tests/test_tool_scope.py tests/test_models.py
git commit -m "feat(tool_scope): flag tools outside an agent's declared allowlist (out_of_scope v2)"
```

---

## Task 6: Docs + cross-cutting verify

**Files:** Modify `pd-rules.yaml`, `KNOWN-GAPS.md`, `HANDOFF.md`.

- [ ] **Step 1: Full suite**

Run: `python3 -m pytest -q`
Expected: PASS. Record the new total.

- [ ] **Step 2: Update `pd-rules.yaml`** — under `severity:` add:
```yaml
  self_permission: critical
  tool_not_allowed: high
```
and under `detectors:` add:
```yaml
  self_permission: true
  tool_not_allowed: true
```
Verify it parses: `python3 -c "import yaml; yaml.safe_load(open('pd-rules.yaml'))"`.

- [ ] **Step 3: Update `KNOWN-GAPS.md`** — move these four items to a "✅ Shipped" note (or delete from their sections): judge backend robustness (now error-isolated), off_task flag-value extraction, redundant Read re-reads, Bash extract_paths env-prefix/pipes, plus add the two new detectors (`self_permission`, `tool_not_allowed`). Leave genuinely-still-deferred items (tool-result capture, verdict cache, `pd summary`, other hook events, `~/.config` breadth, the lenient permission/path heuristics).

- [ ] **Step 4: Update `HANDOFF.md`** — add `self_permission` (critical) and `tool_not_allowed` (high) rows to the detectors table; update the test count to the new total from Step 1.

- [ ] **Step 5: Smoke**

Run: `python3 -m agent_pd.cli report --format md 2>&1 | head -30`
Expected: runs without error; report renders.

- [ ] **Step 6: Commit**

```bash
git add pd-rules.yaml KNOWN-GAPS.md HANDOFF.md
git commit -m "docs: document self_permission + tool_not_allowed detectors and noise-hardening; mark gaps shipped"
```

---

## Self-review notes (author)

- **Spec coverage:** §1 judge robustness → Task 1; §2 noise hardening (off_task/scope/redundant) → Task 2; §3 self_permission → Task 3; §4 tool-allowlist (loader → Task 4, detector + wiring → Task 5); cross-cutting config/registry/model/live spread across Tasks 3/5; docs → Task 6. All spec sections mapped.
- **Type consistency:** `load_agent_tools(agent_type, cwd, config_dir=None)` defined in Task 4, consumed in Task 5 (`live.py`). `AgentRecord.tool_allowlist` added in Task 5 Step 3, read by `tool_scope.detect` (Task 5 Step 4) and defaulted None (Task 5 model test). `judge_records` return gains `errored` (Task 1) consumed in `_cmd_judge` (Task 1 Step 4). Detector registry key `tool_not_allowed` maps to the `tool_scope` module (Task 5) — offense string and registry key intentionally both `tool_not_allowed`; severity/detector config keys use `tool_not_allowed` consistently.
- **No placeholders:** every code step shows complete code.
```
