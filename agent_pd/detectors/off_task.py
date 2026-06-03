import re
import shlex

from ..models import Offense

OFFENSE = "off_task"
SEARCH_TOOLS = {"Grep", "Glob", "WebSearch", "WebFetch"}
# agents frequently search via the shell rather than the Grep tool; treat these Bash
# commands as searches too so off-topic shell searching isn't invisible.
_BASH_SEARCH = {"grep", "egrep", "fgrep", "rg", "ag", "ack", "find", "fd", "locate",
                "curl", "wget"}
_GREP_FAMILY = {"grep", "egrep", "fgrep", "rg", "ag", "ack"}
_NAME_FLAGS = {"-name", "-iname", "-path", "-ipath", "-regex", "-wholename"}
_PATTERN_FLAGS = {"-e", "--regexp"}                 # the flag's value IS the pattern
_SKIP_VALUE_FLAGS = {"-t", "--type", "-g", "--glob", "-m", "--max-count",
                     "-f", "--file", "--include", "--exclude",
                     "-A", "-B", "-C", "--context"}  # value is not the pattern
_WORD = re.compile(r"[a-z0-9]+")
_STOP = {"the", "a", "an", "and", "or", "of", "to", "in", "for", "on", "is", "this", "that"}


def _tokens(text: str) -> set:
    return {w for w in _WORD.findall((text or "").lower()) if w not in _STOP and len(w) > 1}


def _query_text(tool_input: dict) -> str:
    # Prefer the human-meaningful query/prompt over the URL: a WebFetch URL path
    # tokenizes into opaque slugs that rarely overlap the brief, so the fetch prompt
    # is what reflects intent. URL is the last-resort fallback.
    for k in ("pattern", "query", "prompt", "glob", "url"):
        if tool_input.get(k):
            return str(tool_input[k])
    return ""


def _extract_search_term(cmd: str) -> str:
    """Pull the meaningful query out of a shell search command, dropping the binary,
    flags, paths and pipe/redirect noise. `grep -rn "X" /path --include=...` -> "X"."""
    try:
        toks = shlex.split(cmd)
    except ValueError:
        toks = cmd.split()
    if not toks:
        return ""
    i = 1 if toks[0].rsplit("/", 1)[-1] == "sudo" and len(toks) > 1 else 0
    if i >= len(toks):
        return ""
    binary = toks[i].rsplit("/", 1)[-1]
    rest = toks[i + 1:]
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
    if binary in ("find", "fd"):
        for j, t in enumerate(rest):         # the term is the value after -name/-path/...
            if t in _NAME_FLAGS and j + 1 < len(rest):
                return rest[j + 1]
        return ""
    if binary in ("curl", "wget", "locate"):
        for t in rest:
            if t.startswith("http"):
                return t
        for t in rest:
            if not t.startswith("-"):
                return t
    return ""


def _bash_search_query(tool_input: dict) -> str:
    """If a Bash command is a search (grep/find/curl/...), return its extracted search
    term; otherwise empty (so non-search Bash like `git commit` is ignored)."""
    cmd = str((tool_input or {}).get("command", "")).strip()
    if not cmd:
        return ""
    parts = cmd.split()
    head = parts[0].rsplit("/", 1)[-1]
    if head == "sudo" and len(parts) > 1:        # look past a sudo prefix
        head = parts[1].rsplit("/", 1)[-1]
    return _extract_search_term(cmd) if head in _BASH_SEARCH else ""


def _search_query(tool_name: str, tool_input: dict) -> str:
    if tool_name in SEARCH_TOOLS:
        return _query_text(tool_input)
    if tool_name == "Bash":
        return _bash_search_query(tool_input)
    return ""


def detect(record, rules) -> list:
    brief_tokens = _tokens(record.brief)
    if not brief_tokens:
        return []
    sev = rules.severity.get(OFFENSE, "review")
    threshold = rules.off_task_overlap_threshold
    out = []
    for a in record.actions:
        q = _search_query(a.tool_name, a.tool_input)
        if not q:
            continue
        qt = _tokens(q)
        if not qt:
            continue
        overlap = len(qt & brief_tokens) / len(qt)
        if overlap < threshold:
            term = q if len(q) <= 50 else q[:49] + "…"
            brief = record.brief if len(record.brief) <= 50 else record.brief[:49] + "…"
            out.append(Offense(record.agent_id, record.agent_type, OFFENSE, sev, "low",
                               f"searched '{term}' — {overlap:.0%} word-overlap with "
                               f"brief '{brief}'", subject=q))
    return out
