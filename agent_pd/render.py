"""Pure formatting for the live `pd watch` feed. No I/O — every function returns
strings so it is fully unit-testable without a terminal."""
import json

# severity -> (label, emoji, ansi-color-code)
SEVERITY_STYLE = {
    "critical": ("CRITICAL", "🚨", "1;31"),
    "high": ("HIGH", "⚠", "33"),
    "low": ("LOW", "●", "35"),
    "review": ("REVIEW", "👁", "34"),
}
_SEV_ORDER = {"critical": 0, "high": 1, "low": 2, "review": 3}

# stable palette for per-agent coloring (cyan, green, yellow, magenta, blue, bright variants)
_AGENT_PALETTE = ["36", "32", "33", "35", "34", "31", "96", "92", "93", "95"]

_ABBREV = {"general-purpose": "gp"}


class Style:
    def __init__(self, color: bool = True, emoji: bool = True):
        self.color = color
        self.emoji = emoji

    def paint(self, text: str, code: str) -> str:
        if not self.color or not code:
            return text
        return f"\033[{code}m{text}\033[0m"


def action_summary(tool_name: str, tool_input: dict, limit: int = 48) -> str:
    ti = tool_input or {}
    if tool_name == "Bash":
        s = str(ti.get("command", ""))
    elif tool_name == "Grep":
        s = str(ti.get("pattern", ""))
    elif tool_name == "Glob":
        s = str(ti.get("pattern") or ti.get("glob") or "")
    elif tool_name in ("Read", "Write", "Edit", "NotebookEdit"):
        s = str(ti.get("file_path") or ti.get("notebook_path") or "")
    elif tool_name == "WebFetch":
        s = str(ti.get("url", ""))
    elif tool_name == "WebSearch":
        s = str(ti.get("query", ""))
    else:
        s = json.dumps(ti, sort_keys=True)
    s = s.replace("\n", " ").replace("\r", " ")
    return s if len(s) <= limit else s[: limit - 1] + "…"


def badge(severity: str, style: Style) -> str:
    label, emoji, color = SEVERITY_STYLE.get(severity, (severity.upper(), "●", ""))
    text = f"{emoji} {label}" if style.emoji else label
    return style.paint(text, color)


def agent_color(agent_id: str) -> str:
    if not agent_id:
        return "37"   # grey for main/unknown
    idx = sum(ord(c) for c in agent_id) % len(_AGENT_PALETTE)
    return _AGENT_PALETTE[idx]


def agent_tag(agent_type: str, agent_id: str) -> str:
    t = _ABBREV.get(agent_type, agent_type) or "main"
    short = (agent_id or "")[:4] or "----"
    return f"{t}·{short}"


def _painted_tag(agent_type: str, agent_id: str, style: Style) -> str:
    return style.paint(agent_tag(agent_type, agent_id), agent_color(agent_id))


def format_banner(agent_type: str, agent_id: str, brief: str, style: Style) -> str:
    arrow = "▸" if style.emoji else ">"
    tag = _painted_tag(agent_type, agent_id, style)
    lines = [f"┌ {arrow} {tag}  started"]
    if brief:
        lines.append(f'│   brief: "{brief}"')
    lines.append("└─")
    return "\n".join(lines)


def _fmt_ts(ts) -> str:
    if not ts:
        return "--:--:--"
    s = str(ts)
    if "T" in s:                     # ISO 8601 -> take the HH:MM:SS part
        return s.split("T", 1)[1][:8]
    return s[:8]


def _worst(offenses) -> str:
    return min((o.severity for o in offenses), key=lambda s: _SEV_ORDER.get(s, 9))


def format_feed_line(ts, agent_type, agent_id, tool_name, tool_input, offenses,
                     style: Style, crimes_only: bool = False) -> list:
    if not offenses and crimes_only:
        return []
    tag = _painted_tag(agent_type, agent_id, style)
    summary = action_summary(tool_name, tool_input)
    if offenses:
        verdict = badge(_worst(offenses), style)
    else:
        verdict = style.paint("✓" if style.emoji else "ok", "2;37")
    main = f" {_fmt_ts(ts)}  {tag}  {tool_name:<8} {summary:<48}  {verdict}"
    lines = [main]
    for o in offenses:
        reason = o.evidence if len(o.evidence) <= 90 else o.evidence[:89] + "…"
        lines.append(style.paint(f"          └ {reason}", "2;37"))
    return lines


def format_rap_sheet(entries: list, total_acts: int, style: Style) -> str:
    """entries: list of (tag_str, color_code, counts_dict[severity->n])."""
    total_crimes = sum(sum(counts.values()) for _, _, counts in entries)
    parts = []
    for tag, color, counts in entries:
        bits = []
        for sev in ("critical", "high", "low", "review"):
            n = counts.get(sev, 0)
            if not n:
                continue
            _, emoji, _ = SEVERITY_STYLE[sev]
            mark = emoji if style.emoji else sev
            bits.append(f"{n}{mark}")
        summary = " ".join(bits) if bits else "clean"
        parts.append(f"{style.paint(tag, color)}: {summary}")
    body = "   ·   ".join(parts)
    head = style.paint("RAP SHEET", "1")
    return f" {head}   {body}   ·   total {total_crimes} crimes / {total_acts} acts"
