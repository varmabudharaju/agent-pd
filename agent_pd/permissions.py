"""Reads the user's Claude Code permission allow-rules and decides whether a given action
was pre-authorized. Used to downgrade flagged-but-permitted accesses to 'info' severity.
is_permitted is pure (takes the rule list); load_allow_rules does the file I/O.

Matching follows Claude Code's documented semantics with a CONSERVATIVE bias: when in
doubt, do NOT treat an action as permitted (keep the offense flagged)."""
import json
import os
import re
from pathlib import Path

_SETTINGS_FILES = ("settings.json", "settings.local.json")

# Split a compound Bash command into independently-authorized sub-commands.
# Splits on || && | ; & and newlines. A Bash rule authorizes a command only if
# EVERY resulting segment matches an allow-rule.
_BASH_SPLIT_RE = re.compile(r"\|\||&&|[;|&\n]")

# Leading process wrappers Claude Code strips before matching. (token, takes_arg)
# `nice` may carry an optional `-n N`; handled specially below.
_WRAPPERS = {
    "timeout": 1,   # consumes one following arg (the duration)
    "time": 0,
    "nohup": 0,
    "stdbuf": 1,
    "xargs": 0,
}


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
        return tool.strip(), spec.strip()
    return rule, None


def _strip_wrappers(segment: str) -> str:
    """Repeatedly remove leading process wrappers (timeout/time/nice/nohup/stdbuf/xargs)
    until stable. CC strips these before matching; not stripping would only over-flag,
    but we replicate for fidelity."""
    toks = segment.split()
    changed = True
    while changed and toks:
        changed = False
        head = toks[0]
        if head == "nice":
            # nice [-n N] ...
            rest = toks[1:]
            if rest and rest[0] == "-n" and len(rest) > 1:
                rest = rest[2:]
            elif rest and rest[0].startswith("-"):
                rest = rest[1:]
            toks = rest
            changed = True
            continue
        if head in _WRAPPERS:
            toks = toks[1 + _WRAPPERS[head]:]
            changed = True
    return " ".join(toks)


def _spec_to_segment_regex(spec: str) -> "re.Pattern":
    """Translate a Bash spec into an anchored full-match regex for a single segment.

    A trailing `:*` means 'this prefix optionally followed by a space + args'.
    A literal `*` anywhere matches any chars (including spaces). Everything else is
    matched literally."""
    if spec.endswith(":*"):
        prefix = spec[:-2]
        # exact prefix, OR prefix followed by a space and anything
        return re.compile(re.escape(prefix) + r"(?: .*)?\Z", re.DOTALL)
    # escape everything, then turn the placeholder back into .*
    parts = spec.split("*")
    pattern = ".*".join(re.escape(p) for p in parts)
    return re.compile(pattern + r"\Z", re.DOTALL)


def _segment_matches(segment: str, spec: str) -> bool:
    segment = _strip_wrappers(segment.strip())
    if not segment:
        # An empty segment (e.g. trailing operator) carries no command to authorize;
        # treat as harmless so it doesn't block an otherwise-permitted command.
        return True
    return bool(_spec_to_segment_regex(spec).fullmatch(segment))


def _bash_match(cmd: str, spec: str) -> bool:
    """A Bash rule authorizes a command only if EVERY sub-command (split on shell
    operators) independently matches the spec. Conservative: any unmatched segment
    means the whole command is not permitted by this rule."""
    cmd = cmd.strip()
    segments = _BASH_SPLIT_RE.split(cmd)
    matched_any = False
    for seg in segments:
        if not seg.strip():
            continue
        matched_any = True
        if not _segment_matches(seg, spec):
            return False
    return matched_any


def _glob_to_regex(pattern: str) -> str:
    """gitignore-style glob -> regex fragment. `**` crosses /, `*` does not, `?` is one
    non-/ char. All other regex metachars are escaped."""
    out = []
    i, n = 0, len(pattern)
    while i < n:
        c = pattern[i]
        if c == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(c))
        i += 1
    return "".join(out)


def _expand_spec(spec: str, cwd: str, project_root: str):
    """Resolve a path spec's anchor into an absolute glob pattern, or return None if the
    anchoring is ambiguous (CONSERVATIVE: caller should then not match)."""
    if spec.startswith("~"):                  # home-relative: expand first (already abs)
        return os.path.expanduser(spec)
    if spec.startswith("//"):                 # filesystem absolute: strip ONE leading /
        return spec[1:]
    if spec.startswith("/"):                  # project-root relative
        if not project_root:
            return None
        return project_root.rstrip("/") + spec
    if os.path.isabs(spec):                   # already absolute
        return spec
    if "/" in spec:                           # relative-with-slash: cwd-relative
        if not cwd:
            return None
        return cwd.rstrip("/") + "/" + spec
    # bare name, no slash: matches at any depth  (==  **/name)
    return "**/" + spec


def _path_match(abspath: str, spec: str, cwd: str = None, project_root: str = None) -> bool:
    expanded = _expand_spec(spec, cwd, project_root)
    if expanded is None:
        return False
    return bool(re.fullmatch(_glob_to_regex(expanded), abspath))


def is_permitted(tool_name: str, tool_input: dict, abspath, rules: list,
                 cwd: str = None, project_root: str = None) -> bool:
    """True if (tool_name, action) matches any allow-rule. Bash rules match the command
    (operator-split, every segment must match); file-tool rules match the resolved path;
    a bare `Tool` rule allows the whole tool. cwd/project_root anchor relative path specs."""
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
        elif abspath and _path_match(abspath, spec, cwd, project_root):
            return True
    return False
