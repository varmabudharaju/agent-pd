"""Flags an agent modifying its OWN Claude Code control plane — its permission config
(.claude/settings*.json), its own agent definitions (.claude/agents/*.md), or the pd
rules file (pd-rules*.yaml). For a SECURITY product the invariant is: any agent that
writes to its own control-plane files is critical, regardless of method or content.
Content/keyword detection only ENRICHES the evidence; it never gates the flag."""
import re

from ..models import Offense
from .. import scope

OFFENSE = "self_permission"
_SETTINGS_NAMES = ("settings.json", "settings.local.json")
_PERM_KEYS = ("permissions", '"allow"', "defaultmode",
              "dangerouslyskippermissions", "bypasspermissions")
# tool -> the field holding the new text written to the file
_NEW_TEXT = {"Write": "content", "Edit": "new_string", "NotebookEdit": "new_source"}

# Bash write-intent: a write-capable program as the head of any segment.
_WRITE_VERBS = {"cp", "mv", "tee", "sed", "dd", "install", "rsync", "ln",
                "truncate", "chmod", "chown"}
_INTERPRETERS = {"python", "python3", "ruby", "node", "perl",
                 "bash", "sh", "zsh"}
_REDIRECTS = (">", ">>")

# Pull path-ish tokens out of an arbitrary command string: anything that looks like
# a slash-separated path, including inside quotes / redirects / interpreter args that
# scope.extract_paths is too conservative to surface.
_PATHISH_RE = re.compile(r"[~./A-Za-z0-9_\-]*/[~./A-Za-z0-9_\-/]+")


def _is_settings_path(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    parts = p.split("/")
    base = parts[-1] if parts else ""
    return ".claude" in parts and base in _SETTINGS_NAMES


def _is_agent_def_path(path: str) -> bool:
    p = (path or "").replace("\\", "/")
    parts = p.split("/")
    if len(parts) < 3 or not parts[-1].endswith(".md"):
        return False
    # file directly under a .claude/agents/ directory
    return parts[-2] == "agents" and parts[-3] == ".claude"


def _is_rules_path(path: str) -> bool:
    base = (path or "").replace("\\", "/").split("/")[-1]
    return base.startswith("pd-rules") and base.endswith((".yaml", ".yml"))


def _is_control_path(path: str) -> bool:
    return _is_settings_path(path) or _is_agent_def_path(path) or _is_rules_path(path)


def _perm_key_in(text: str):
    low = (text or "").lower()
    for k in _PERM_KEYS:
        if k in low:
            return k
    return None


def _enrich(key) -> str:
    return f": {key}" if key else ""


def _bash_write_intent(cmd: str) -> bool:
    if any(r in cmd for r in _REDIRECTS):
        return True
    for seg in re.split(r"\|\||&&|\||;", cmd):
        toks = seg.split()
        # skip env-var assignments / a leading sudo to find the program
        i = 0
        while i < len(toks) and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", toks[i]):
            i += 1
        if i < len(toks) and toks[i].rsplit("/", 1)[-1] == "sudo":
            i += 1
        if i >= len(toks):
            continue
        prog = toks[i].rsplit("/", 1)[-1]
        if prog in _WRITE_VERBS or prog in _INTERPRETERS:
            return True
    return False


def _shell_tokens(cmd: str):
    """Whitespace/shlex split of a command into bare tokens, surrounding quotes
    stripped. Used so a bare basename like `pd-rules.yaml` (no slash, which the
    path-ish extractors skip) is still tested against the control-path rules."""
    import shlex
    try:
        return shlex.split(cmd)
    except ValueError:
        return [t.strip("\"'") for t in cmd.split()]


def _control_candidates(cmd: str):
    """All path candidates the command references: path-ish slash tokens AND raw
    shell tokens (plus their basenames), so bare control-file basenames surface."""
    cands = set(scope.extract_paths(cmd))
    cands.update(_PATHISH_RE.findall(cmd))
    for tok in _shell_tokens(cmd):
        cands.add(tok)
    return cands


def _bash_touches_control(cmd: str, cwd: str):
    """Return True if any path/token the command references resolves to a control path."""
    for raw in _control_candidates(cmd):
        # check the raw shape, its basename, and the cwd-resolved absolute form
        if _is_control_path(raw):
            return True
        if _is_control_path(scope.resolve(raw, cwd)):
            return True
    return False


def detect(record, rules) -> list:
    sev = rules.severity.get(OFFENSE, "critical")
    out = []
    for a in record.actions:
        ti = a.tool_input or {}
        if a.tool_name in _NEW_TEXT:
            path = ti.get("file_path") or ti.get("notebook_path") or ""
            if not _is_control_path(path):
                continue
            key = _perm_key_in(str(ti.get(_NEW_TEXT[a.tool_name], "")))
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"{a.tool_name} modified {path} (self-permissioning{_enrich(key)})"))
        elif a.tool_name == "Bash":
            cmd = str(ti.get("command", ""))
            if not _bash_write_intent(cmd):
                continue
            if not _bash_touches_control(cmd, record.cwd):
                continue
            key = _perm_key_in(cmd)
            # report the first control path we can name for clearer evidence
            named = next((p for p in _control_candidates(cmd)
                          if _is_control_path(p)
                          or _is_control_path(scope.resolve(p, record.cwd))), "")
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "high",
                               f"Bash wrote to a control file {named} (self-permissioning{_enrich(key)})"))
    return out
