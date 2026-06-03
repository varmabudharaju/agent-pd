# Scope Engine + Denial Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make agent-pd consistently police both the main agent and subagents — flag out-of-project / sensitive-path / out-of-allowlist file *and* Bash access, and actually capture permission denials.

**Architecture:** The audit log becomes the single source of truth: `gather()` replays a session's audit events through the existing `LiveMonitor`, so `pd report` and `pd watch` share one engine and both see every agent (main agent = empty `agent_id`). A new pure `scope.py` module powers a rewritten `out_of_scope` detector (auto project-boundary + sensitive blocklist + optional allowlist + Bash path extraction). The hook infers `decision="deny"` from the `PermissionDenied` event name (the real payload has no decision field), reactivating the denial detector.

**Tech Stack:** Python 3.11 stdlib (`os`, `fnmatch`, `shlex`, `json`), PyYAML for config, pytest. No new dependencies.

---

## File structure

| File | Responsibility | Action |
|---|---|---|
| `agent_pd/config.py` | rules + defaults (adds `sensitive_patterns`, `project_boundary`, sensitive severity) | modify |
| `agent_pd/scope.py` | pure path logic: `project_root`, `resolve`, `classify`, `extract_paths` | **create** |
| `agent_pd/detectors/out_of_scope.py` | orchestrate scope rules over file + Bash actions, de-dup | rewrite |
| `agent_pd/hook.py` | infer denial from event name | modify |
| `agent_pd/detectors/permission_bypass.py` | match escalation on Bash `command` only | modify |
| `agent_pd/investigator.py` | `gather()` replays audit via `LiveMonitor`; drop transcript-action parsing | rewrite parts |
| `tests/test_config.py`, `tests/test_scope.py`, `tests/test_out_of_scope.py`, `tests/test_hook.py`, `tests/test_permission_bypass.py`, `tests/test_investigator.py` | tests | create/modify |

Task order respects dependencies: config → scope → out_of_scope; hook and permission_bypass are independent; gather() last (touches the shared engine).

---

## Task 1: Config — new scope keys

**Files:**
- Modify: `agent_pd/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_config.py`:

```python
def test_scope_defaults_present():
    r = load_rules(None)
    assert r.project_boundary is True
    assert "~/.ssh" in r.sensitive_patterns
    assert "*.pem" in r.sensitive_patterns
    assert r.severity["out_of_scope"] == "high"
    assert r.severity["out_of_scope_sensitive"] == "critical"

def test_scope_overrides(tmp_path):
    p = tmp_path / "pd-rules.yaml"
    p.write_text("project_boundary: false\nsensitive_patterns:\n  - secret.txt\n")
    r = load_rules(p)
    assert r.project_boundary is False
    assert r.sensitive_patterns == ["secret.txt"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_config.py -q`
Expected: FAIL (`Rules` has no attribute `project_boundary`).

- [ ] **Step 3: Implement** — replace the body of `agent_pd/config.py` with:

```python
from dataclasses import dataclass
from pathlib import Path
import copy
import yaml

DEFAULT_SENSITIVE = [
    "~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config",
    ".env", ".env.*",
    "*.pem", "*.key", "id_rsa", "id_ed25519", "*.p12",
    ".netrc", ".npmrc", ".pypirc", ".git-credentials",
    "*.keychain",
]

DEFAULTS = {
    "scope_dirs": [],
    "escalation_patterns": ["dangerouslyDisableSandbox", "sudo ", "chmod 777", "rm -rf /"],
    "sensitive_patterns": DEFAULT_SENSITIVE,
    "project_boundary": True,
    "severity": {
        "permission_bypass": "critical",
        "out_of_scope": "high",
        "out_of_scope_sensitive": "critical",
        "redundant": "low",
        "off_task": "review",
    },
    "detectors": {
        "permission_bypass": True,
        "out_of_scope": True,
        "redundant": True,
        "off_task": True,
    },
    "off_task_overlap_threshold": 0.15,
}


@dataclass
class Rules:
    scope_dirs: list
    escalation_patterns: list
    sensitive_patterns: list
    project_boundary: bool
    severity: dict
    detectors: dict
    off_task_overlap_threshold: float


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (override or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_rules(path=None) -> Rules:
    data = copy.deepcopy(DEFAULTS)
    if path is not None and Path(path).exists():
        loaded = yaml.safe_load(Path(path).read_text()) or {}
        data = _deep_merge(data, loaded)
    return Rules(
        scope_dirs=data["scope_dirs"],
        escalation_patterns=data["escalation_patterns"],
        sensitive_patterns=data["sensitive_patterns"],
        project_boundary=data["project_boundary"],
        severity=data["severity"],
        detectors=data["detectors"],
        off_task_overlap_threshold=data["off_task_overlap_threshold"],
    )
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_config.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent_pd/config.py tests/test_config.py
git commit -m "feat(config): add sensitive_patterns, project_boundary, sensitive severity"
```

---

## Task 2: `scope.py` pure path helpers

**Files:**
- Create: `agent_pd/scope.py`
- Test: `tests/test_scope.py`

- [ ] **Step 1: Write the failing test** — create `tests/test_scope.py`:

```python
import os
from agent_pd import scope


def test_project_root_finds_git(tmp_path):
    (tmp_path / "proj" / ".git").mkdir(parents=True)
    sub = tmp_path / "proj" / "src"
    sub.mkdir()
    assert scope.project_root(str(sub)) == str(tmp_path / "proj")


def test_project_root_falls_back_to_cwd(tmp_path):
    d = tmp_path / "nogit"
    d.mkdir()
    assert scope.project_root(str(d)) == str(d)


def test_resolve_relative_and_home():
    assert scope.resolve("../x", "/a/b") == "/a/x"
    assert scope.resolve("~/y", "/a/b") == os.path.join(os.path.expanduser("~"), "y")


def test_classify_inside_clean():
    assert scope.classify("/proj/src/a.py", "/proj", [], [], project_boundary=True) == (None, None)


def test_classify_outside_is_boundary():
    kind, detail = scope.classify("/etc/passwd", "/proj", [], [], project_boundary=True)
    assert kind == "boundary"


def test_classify_sensitive_even_inside():
    pats = ["~/.ssh", ".env", "*.pem"]
    assert scope.classify("/proj/.env", "/proj", [], pats, project_boundary=True)[0] == "sensitive"
    home_key = os.path.join(os.path.expanduser("~"), ".ssh", "id_rsa")
    assert scope.classify(home_key, "/proj", [], pats, project_boundary=True)[0] == "sensitive"


def test_classify_allowlist():
    kind, _ = scope.classify("/proj/tests/a.py", "/proj", ["src/"], [], project_boundary=True)
    assert kind == "allowlist"
    assert scope.classify("/proj/src/a.py", "/proj", ["src/"], [], project_boundary=True) == (None, None)


def test_classify_boundary_off():
    assert scope.classify("/etc/x", "/proj", [], [], project_boundary=False) == (None, None)
    # sensitive still fires with boundary off
    assert scope.classify("/etc/x.pem", "/proj", [], ["*.pem"], project_boundary=False)[0] == "sensitive"


def test_extract_paths():
    assert scope.extract_paths("cat ../secrets") == ["../secrets"]
    assert scope.extract_paths("ls /etc") == ["/etc"]
    assert scope.extract_paths("cd ..") == [".."]
    assert scope.extract_paths("find / -name foo") == ["/"]
    assert scope.extract_paths("git commit -m x") == []
    assert scope.extract_paths("npm test") == []
    assert scope.extract_paths("curl https://x.com/a") == []
    assert scope.extract_paths("echo hi > /etc/cfg") == ["/etc/cfg"]
    assert scope.extract_paths("sudo cat /root/.bashrc") == ["/root/.bashrc"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_scope.py -q`
Expected: FAIL (`No module named 'agent_pd.scope'`).

- [ ] **Step 3: Implement** — create `agent_pd/scope.py`:

```python
"""Pure path-scope logic shared by the out_of_scope detector. No I/O except the
git-root walk in project_root(). Fully unit-testable."""
import fnmatch
import os
import shlex

# Bash commands whose first positional argument is a path even when it doesn't
# look like one (e.g. `cat foo.txt`, `cd build`).
PATH_COMMANDS = {"cat", "ls", "cd", "cp", "mv", "less", "more", "head", "tail",
                 "stat", "find", "du", "open", "code", "cmp", "diff", "rm",
                 "touch", "nano", "vim", "vi", "source"}
_URL_PREFIXES = ("http://", "https://", "ftp://")
_SHELL_OPS = {"|", "&&", "||", ";", "&", ">", ">>", "<", "2>", "2>>"}


def project_root(cwd: str) -> str:
    """Nearest ancestor of cwd containing a .git, else the (abs) cwd itself."""
    cur = os.path.abspath(cwd or os.getcwd())
    walker = cur
    while True:
        if os.path.isdir(os.path.join(walker, ".git")):
            return walker
        parent = os.path.dirname(walker)
        if parent == walker:
            return cur
        walker = parent


def resolve(path: str, cwd: str) -> str:
    """Expand ~, join against cwd if relative, normalize to an absolute path."""
    p = os.path.expanduser(path)
    if not os.path.isabs(p):
        p = os.path.join(cwd or os.getcwd(), p)
    return os.path.normpath(p)


def _matches_sensitive(abspath: str, patterns: list):
    base = os.path.basename(abspath)
    for pat in patterns:
        expanded = os.path.normpath(os.path.expanduser(pat))
        if os.path.isabs(expanded):                 # dir/path prefix (e.g. ~/.ssh)
            if abspath == expanded or abspath.startswith(expanded + os.sep):
                return pat
        if fnmatch.fnmatch(base, pat):              # basename glob (*.pem, .env.*)
            return pat
    return None


def classify(abspath: str, root: str, scope_dirs: list, sensitive_patterns: list,
             project_boundary: bool = True):
    """Return (kind, detail). kind in {'sensitive','boundary','allowlist'} or (None, None)."""
    hit = _matches_sensitive(abspath, sensitive_patterns)
    if hit:
        return ("sensitive", hit)
    inside = abspath == root or abspath.startswith(root + os.sep)
    if not inside:
        return ("boundary", root) if project_boundary else (None, None)
    if scope_dirs:
        rel = os.path.relpath(abspath, root).replace(os.sep, "/")
        for d in scope_dirs:
            d = d.rstrip("/") + "/"
            if (rel + "/").startswith(d):
                return (None, None)
        return ("allowlist", scope_dirs)
    return (None, None)


def extract_paths(command: str) -> list:
    """Heuristically pull filesystem paths out of a Bash command. Conservative:
    a token is a path only if it looks like one (starts with / ~ ./ ..) or is the
    first positional argument of a known path-command. Flags, pipes, URLs ignored."""
    try:
        toks = shlex.split(command)
    except ValueError:
        toks = command.split()
    if not toks:
        return []
    i = 1 if toks[0].rsplit("/", 1)[-1] == "sudo" and len(toks) > 1 else 0
    binary = toks[i].rsplit("/", 1)[-1] if i < len(toks) else ""
    out, seen_positional = [], False
    for t in toks[i + 1:]:
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
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_scope.py -q`
Expected: PASS (all assertions).

- [ ] **Step 5: Commit**

```bash
git add agent_pd/scope.py tests/test_scope.py
git commit -m "feat(scope): pure project-root/sensitive/allowlist/bash-path helpers"
```

---

## Task 3: Rewrite the `out_of_scope` detector

**Files:**
- Rewrite: `agent_pd/detectors/out_of_scope.py`
- Rewrite: `tests/test_out_of_scope.py`

- [ ] **Step 1: Write the failing tests** — replace the whole of `tests/test_out_of_scope.py` with:

```python
from dataclasses import replace
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import out_of_scope


def _rec(actions, cwd="/proj"):
    return AgentRecord(agent_id="a1", agent_type="Explore", brief="b", cwd=cwd, actions=actions)


def test_flags_file_outside_project_by_default():
    rules = load_rules(None)  # scope_dirs == [], project_boundary True
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/etc/passwd"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].offense == "out_of_scope"
    assert offs[0].severity == "high"
    assert "outside project" in offs[0].evidence


def test_allows_file_inside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Edit",
                       tool_input={"file_path": "/proj/src/app.py"})])
    assert out_of_scope.detect(rec, rules) == []


def test_sensitive_flagged_even_inside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Read",
                       tool_input={"file_path": "/proj/.env"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
    assert "sensitive" in offs[0].evidence


def test_allowlist_narrows_within_project():
    rules = replace(load_rules(None), scope_dirs=["src/"])
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/proj/secrets/key.txt"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert "secrets/key.txt" in offs[0].evidence


def test_bash_navigation_outside_project():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "cat /etc/hosts"})])
    offs = out_of_scope.detect(rec, rules)
    assert len(offs) == 1
    assert "outside project" in offs[0].evidence


def test_bash_inside_project_clean():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "ls src"})])
    assert out_of_scope.detect(rec, rules) == []


def test_dedup_same_path_once():
    rules = load_rules(None)
    rec = _rec([
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "cat /etc/hosts"}),
        Action(agent_id="a1", tool_name="Bash", tool_input={"command": "cat /etc/hosts"}),
    ])
    assert len(out_of_scope.detect(rec, rules)) == 1


def test_detector_can_be_disabled_via_boundary_and_empty_allowlist():
    rules = replace(load_rules(None), project_boundary=False, scope_dirs=[], sensitive_patterns=[])
    rec = _rec([Action(agent_id="a1", tool_name="Write",
                       tool_input={"file_path": "/etc/passwd"})])
    assert out_of_scope.detect(rec, rules) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_out_of_scope.py -q`
Expected: FAIL (old detector returns `[]` when `scope_dirs` empty; new behavior not implemented).

- [ ] **Step 3: Implement** — replace the whole of `agent_pd/detectors/out_of_scope.py` with:

```python
import os

from ..models import Offense
from .. import scope as scopelib

OFFENSE = "out_of_scope"
FILE_TOOLS = {"Read", "Write", "Edit", "NotebookEdit"}


def _file_path(tool_input: dict) -> str:
    return tool_input.get("file_path") or tool_input.get("notebook_path") or ""


def detect(record, rules) -> list:
    root = scopelib.project_root(record.cwd)
    cwd = record.cwd or os.getcwd()
    high = rules.severity.get(OFFENSE, "high")
    crit = rules.severity.get("out_of_scope_sensitive", "critical")
    out, seen = [], set()
    for a in record.actions:
        raw_paths = []
        if a.tool_name in FILE_TOOLS:
            p = _file_path(a.tool_input or {})
            if p:
                raw_paths.append(p)
            tool_label = a.tool_name
        elif a.tool_name == "Bash":
            raw_paths = scopelib.extract_paths(str((a.tool_input or {}).get("command", "")))
            tool_label = "Bash"
        else:
            continue
        for raw in raw_paths:
            abspath = scopelib.resolve(raw, cwd)
            kind, detail = scopelib.classify(abspath, root, rules.scope_dirs,
                                             rules.sensitive_patterns,
                                             project_boundary=rules.project_boundary)
            if kind is None:
                continue
            key = (tool_label, abspath, kind)
            if key in seen:
                continue
            seen.add(key)
            if kind == "sensitive":
                ev = f"{tool_label} touched {raw} (sensitive: {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, crit, "high", ev))
            elif kind == "boundary":
                ev = f"{tool_label} touched {raw} (outside project {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, high, "high", ev))
            else:
                ev = f"{tool_label} touched {raw} (outside scope {detail})"
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, high, "high", ev))
    return out
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_out_of_scope.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent_pd/detectors/out_of_scope.py tests/test_out_of_scope.py
git commit -m "feat(out_of_scope): real scope engine (project boundary + sensitive + allowlist + bash)"
```

---

## Task 4: Hook — infer denial from event name

**Files:**
- Modify: `agent_pd/hook.py` (`build_event`)
- Modify: `tests/test_hook.py`

- [ ] **Step 1: Write the failing test** — in `tests/test_hook.py`, REPLACE `test_build_event_camelcase_and_denial` with a realistic-payload version (the real `PermissionDenied` payload carries NO decision field) and add a forward-compat test:

```python
def test_build_event_infers_denial_from_event_name():
    # Realistic PermissionDenied payload: NO permissionDecision/decision field.
    payload = {
        "hook_event_name": "PermissionDenied",
        "agentId": "a2", "agentType": "general-purpose",
        "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
        "sessionId": "s1",
    }
    ev = build_event(payload)
    assert ev["agent_id"] == "a2"
    assert ev["event"] == "PermissionDenied"
    assert ev["decision"] == "deny"   # inferred from the event name


def test_build_event_honors_explicit_decision():
    payload = {"hook_event_name": "PermissionDenied", "session_id": "s1",
               "permissionDecision": "deny", "reason": "blocked by rule"}
    ev = build_event(payload)
    assert ev["decision"] == "deny"
    assert ev["reason"] == "blocked by rule"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_hook.py -q`
Expected: FAIL (`test_build_event_infers_denial_from_event_name`: `decision` is `None`).

- [ ] **Step 3: Implement** — in `agent_pd/hook.py`, change `build_event` to assign to a local, infer, and return it:

```python
def build_event(payload: dict) -> dict:
    event = {
        "ts": _first(payload, "timestamp", "ts"),
        "event": _first(payload, "hook_event_name", "event", default="unknown"),
        "session_id": _first(payload, "session_id", "sessionId", default=""),
        "agent_id": _first(payload, "agent_id", "agentId", default=""),
        "agent_type": _first(payload, "agent_type", "agentType", default=""),
        "tool_name": _first(payload, "tool_name", "toolName", default=""),
        "tool_input": _first(payload, "tool_input", "toolInput", default={}),
        "decision": _first(payload, "permissionDecision", "decision",
                           "permission_decision"),
        "reason": _first(payload, "reason", "permissionDecisionReason"),
        "cwd": _first(payload, "cwd", default=""),
    }
    # The real PermissionDenied payload has no decision field — the event firing IS
    # the denial. Infer it (explicit fields above still win if ever present).
    if event["event"] == "PermissionDenied" and event["decision"] is None:
        event["decision"] = "deny"
    return event
```

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_hook.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent_pd/hook.py tests/test_hook.py
git commit -m "fix(hook): infer decision=deny from PermissionDenied event name"
```

---

## Task 5: permission_bypass — match escalation on `command` only

**Files:**
- Modify: `agent_pd/detectors/permission_bypass.py`
- Modify: `tests/test_permission_bypass.py`

- [ ] **Step 1: Write the failing test** — append to `tests/test_permission_bypass.py`:

```python
from agent_pd.models import Action, AgentRecord
from agent_pd.config import load_rules
from agent_pd.detectors import permission_bypass


def _rec(actions):
    return AgentRecord(agent_id="a1", agent_type="gp", brief="b", cwd="/proj", actions=actions)


def test_description_mentioning_sudo_is_not_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "ls -la", "description": "use sudo to inspect"})])
    assert permission_bypass.detect(rec, rules) == []


def test_real_sudo_command_is_flagged():
    rules = load_rules(None)
    rec = _rec([Action(agent_id="a1", tool_name="Bash",
                       tool_input={"command": "sudo rm -rf /tmp/x"})])
    offs = permission_bypass.detect(rec, rules)
    assert len(offs) == 1
    assert offs[0].severity == "critical"
```

(Keep the file's existing tests; if any existing test relied on a pattern appearing only in a non-`command` field, update it to put the pattern in `command`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_permission_bypass.py -q`
Expected: FAIL (`test_description_mentioning_sudo_is_not_flagged`: current code scans the whole input incl. `description`, so it flags).

- [ ] **Step 3: Implement** — in `agent_pd/detectors/permission_bypass.py`, replace the escalation-scan block in `detect` (the part after the `deny` handling) so it reads the `command` field instead of `json.dumps(tool_input)`:

```python
        if a.tool_name not in EXEC_TOOLS:
            continue
        cmd = str((a.tool_input or {}).get("command", "")).lower()
        for p in patterns:
            if p.lower() in cmd:
                out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                                   f"{a.tool_name}: matched escalation pattern "
                                   f"'{p}' in {_summ(a.tool_input)}"))
                break
```

(The `import json` and `_summ` helper stay — `_summ` is still used for the evidence string and the deny branch.)

- [ ] **Step 4: Run tests to verify pass**

Run: `python3 -m pytest tests/test_permission_bypass.py -q`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add agent_pd/detectors/permission_bypass.py tests/test_permission_bypass.py
git commit -m "fix(permission_bypass): match escalation patterns on Bash command only"
```

---

## Task 6: `gather()` — audit log as single source of truth

**Files:**
- Rewrite parts of: `agent_pd/investigator.py`
- Rewrite: `tests/test_investigator.py`

- [ ] **Step 1: Write the failing tests** — replace the whole of `tests/test_investigator.py` with:

```python
import json
from agent_pd.investigator import load_meta, gather


def _audit(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def test_load_meta(tmp_path):
    m = tmp_path / "agent-a1.meta.json"
    m.write_text(json.dumps({"agentType": "Explore", "description": "find foo"}))
    agent_type, brief = load_meta(m)
    assert agent_type == "Explore"
    assert brief == "find foo"


def test_gather_includes_main_agent(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "", "tool_name": "Read",
         "tool_input": {"file_path": "/proj/app.py"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    assert records[0].agent_id == ""
    assert records[0].agent_type == "main"
    assert records[0].actions[0].tool_name == "Read"


def test_gather_includes_subagent_with_brief(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1", "agent_type": "Explore",
         "tool_name": "Grep", "tool_input": {"pattern": "foo"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert rec.agent_type == "Explore"
    assert rec.brief == "find foo"
    assert rec.actions[0].tool_name == "Grep"


def test_gather_surfaces_denial(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    # On-disk shape after the hook ran: PermissionDenied with decision already inferred.
    _audit(audit / "s1.jsonl", [
        {"event": "PermissionDenied", "session_id": "s1", "agent_id": "a1",
         "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
         "decision": "deny", "reason": "blocked", "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert rec.actions[0].decision == "deny"


def test_gather_no_double_count(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1",
         "tool_name": "Grep", "tool_input": {"pattern": "foo"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert sum(1 for a in rec.actions if a.tool_name == "Grep") == 1


def test_gather_tolerates_malformed_and_missing(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s1.jsonl").write_text(
        "not json\n" + json.dumps(
            {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1",
             "tool_name": "Read", "tool_input": {"file_path": "/proj/x"}, "cwd": "/proj"}) + "\n")
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert any(r.agent_id == "a1" for r in records)
    # missing session file -> empty
    assert gather(session_id="nope", projects_dir=projects, audit_dir=audit) == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_investigator.py -q`
Expected: FAIL (`test_gather_includes_main_agent`: current `gather()` doesn't build a `main` record from non-deny audit events).

- [ ] **Step 3: Implement** — in `agent_pd/investigator.py`:

(a) Delete `parse_transcript` and `_load_audit_actions` (no longer used). Keep `load_meta`, `find_subagents_dir`, `_latest_session`, the `DEFAULT_*` constants, and the imports they need (`json`, `Path`). Keep `from .models import Action, AgentRecord` only if still referenced — after this change `gather` no longer constructs them directly, so the import may be removed; leave it if unsure (harmless).

(b) Replace `gather` with:

```python
def gather(session_id=None, projects_dir=DEFAULT_PROJECTS_DIR, audit_dir=DEFAULT_AUDIT_DIR):
    from .live import LiveMonitor          # lazy import avoids a circular import
    from .config import load_rules
    projects_dir, audit_dir = Path(projects_dir), Path(audit_dir)
    if session_id is None:
        session_id = _latest_session(projects_dir, audit_dir)
        if session_id is None:
            return []
    audit_file = Path(audit_dir) / f"{session_id}.jsonl"
    if not audit_file.exists():
        return []
    mon = LiveMonitor(projects_dir=projects_dir, audit_dir=audit_dir)
    rules = load_rules(None)               # detectors re-run in the CLI with real rules
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        mon.process(ev, rules)
    records = list(mon.records.values())
    for r in records:                      # label the main agent (empty agent_id)
        if not r.agent_id and not r.agent_type:
            r.agent_type = "main"
    return records
```

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS (all tests, including `test_live.py` and `test_report.py`, which exercise the same `LiveMonitor` path). If a `test_live.py`/`test_report.py` assertion breaks because main-agent records or out_of_scope offenses now appear, update that assertion to match the unified model (do NOT weaken a real check — adjust expected counts).

- [ ] **Step 5: Commit**

```bash
git add agent_pd/investigator.py tests/test_investigator.py
git commit -m "refactor(investigator): gather() replays audit via LiveMonitor (main+subagents, single source)"
```

---

## Task 7: Docs + end-to-end smoke

**Files:**
- Modify: `README.md`, `HANDOFF.md`, `pd-rules.yaml`

- [ ] **Step 1: Run the full suite once more**

Run: `python3 -m pytest -q`
Expected: PASS (all green).

- [ ] **Step 2: Real-session smoke test** (no mocks — exercises the live audit log)

Run: `pd report --format md | head -40`
Expected: a markdown report that now includes a `main` agent section and, if any out-of-project/sensitive access happened, `out_of_scope` rows. Run `pd watch --crimes-only` in another pane during a session that `cat`s a file outside the repo to confirm a live flag appears.

- [ ] **Step 3: Update `pd-rules.yaml`** — add the new keys with comments:

```yaml
project_boundary: true               # flag any file/Bash path outside the project (git root or cwd)
sensitive_patterns:                  # always flagged (critical), even inside the project
  - "~/.ssh"
  - "~/.aws"
  - "~/.gnupg"
  - "~/.kube"
  - "~/.config"
  - ".env"
  - ".env.*"
  - "*.pem"
  - "*.key"
  - "id_rsa"
  - "id_ed25519"
  - "*.p12"
  - ".netrc"
  - ".npmrc"
  - ".pypirc"
  - ".git-credentials"
  - "*.keychain"
```

Add `out_of_scope_sensitive: critical` under the existing `severity:` block.

- [ ] **Step 4: Update `README.md` and `HANDOFF.md`** — revise the offenses table so `out_of_scope` reads: "file OR Bash path outside the project (auto), sensitive paths always, or outside `scope_dirs`"; note that `pd report` now covers the main agent + subagents from the audit log; and that denied calls are now captured. Remove the stale "out_of_scope is a no-op unless scope_dirs set" claim.

- [ ] **Step 5: Commit**

```bash
git add README.md HANDOFF.md pd-rules.yaml
git commit -m "docs: document scope engine, denial capture, and main-agent coverage"
```

---

## Self-review notes (author)

- **Spec coverage:** §1 gather refactor → Task 6; §2 scope engine → Tasks 1–3; §3 denial + escalation → Tasks 4–5; §4 config keys → Task 1; testing strategy → tests in every task + realistic `PermissionDenied` fixture in Task 4. All spec sections map to a task.
- **Type consistency:** `classify(abspath, root, scope_dirs, sensitive_patterns, project_boundary=…)`, `extract_paths(command)`, `project_root(cwd)`, `resolve(path, cwd)` are used identically in `scope.py` (Task 2) and `out_of_scope.py` (Task 3). `Rules` fields added in Task 1 (`sensitive_patterns`, `project_boundary`) are consumed in Task 3. `build_event` returns the same dict shape, with `decision` now possibly `"deny"` (Task 4) consumed by `LiveMonitor`/`gather` (Task 6).
- **Known follow-ups** remain in `KNOWN-GAPS.md` (judge API backend, off_task flag extraction, redundant re-reads, etc.) — intentionally out of this plan.
```
