"""Reads the user's Claude Code permission allow-rules and decides whether a given action
was pre-authorized. Used to downgrade flagged-but-permitted accesses to 'info' severity.
is_permitted is pure (takes the rule list); load_allow_rules does the file I/O."""
import fnmatch
import json
import os
from pathlib import Path

_SETTINGS_FILES = ("settings.json", "settings.local.json")


def _read_allow(path) -> list:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    perms = data.get("permissions") or {}
    allow = perms.get("allow") or []
    return [r for r in allow if isinstance(r, str)]


def load_allow_rules(cwd: str = "", config_dir: str = None) -> list:
    """Merge permissions.allow from the user config dir (CLAUDE_CONFIG_DIR or ~/.claude)
    and the project's <cwd>/.claude. Best-effort; missing/broken files contribute nothing."""
    cfg = config_dir or os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    rules = []
    for f in _SETTINGS_FILES:
        rules += _read_allow(Path(cfg) / f)
    base = Path(cwd) if cwd else Path.cwd()
    for f in _SETTINGS_FILES:
        rules += _read_allow(base / ".claude" / f)
    return rules


def _parse_rule(rule: str):
    rule = rule.strip()
    if rule.endswith(")") and "(" in rule:
        tool, spec = rule[:-1].split("(", 1)
        return tool.strip(), spec
    return rule, None


def _bash_match(cmd: str, spec: str) -> bool:
    cmd = cmd.strip()
    if spec.endswith(":*"):
        return cmd.startswith(spec[:-2])
    return cmd == spec


def _path_match(abspath: str, spec: str) -> bool:
    spec = os.path.expanduser(spec)
    if spec.startswith("//"):          # Claude Code's absolute-path marker
        spec = spec[1:]
    # fnmatch's '*' already crosses '/', so a trailing '/**' behaves like '/*'.
    return (fnmatch.fnmatch(abspath, spec)
            or fnmatch.fnmatch(abspath, spec.rstrip("/") + "/*"))


def is_permitted(tool_name: str, tool_input: dict, abspath, rules: list) -> bool:
    """True if (tool_name, action) matches any allow-rule. Bash rules match the command;
    file-tool rules match the resolved path; a bare `Tool` rule allows the whole tool."""
    ti = tool_input or {}
    cmd = str(ti.get("command", ""))
    for rule in rules:
        tool, spec = _parse_rule(rule)
        if tool != tool_name:
            continue
        if spec is None:
            return True
        if tool_name == "Bash":
            if _bash_match(cmd, spec):
                return True
        elif abspath and _path_match(abspath, spec):
            return True
    return False
