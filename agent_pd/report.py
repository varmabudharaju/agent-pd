import json
from dataclasses import asdict

_SEV_ORDER = {"critical": 0, "high": 1, "low": 2, "review": 3, "info": 4}


def render_json(offenses: list) -> str:
    return json.dumps([asdict(o) for o in offenses], indent=2)


def render_markdown(records: list, offenses: list) -> str:
    by_agent = {}
    for o in offenses:
        by_agent.setdefault(o.agent_id, []).append(o)
    total = len(offenses)
    lines = [f"## Police report — {len(records)} agents, {total} offense(s)", ""]
    for rec in records:
        offs = sorted(by_agent.get(rec.agent_id, []),
                      key=lambda o: _SEV_ORDER.get(o.severity, 9))
        header = f"### agent: {rec.agent_type or '?'} ({rec.agent_id[:8]}…)"
        if rec.brief:
            header += f"  — assigned: \"{rec.brief}\""
        lines.append(header)
        if not offs:
            lines += ["", "_no offenses_", ""]
            continue
        lines += ["", "| severity | offense | confidence | evidence |",
                  "|----------|---------|------------|----------|"]
        for o in offs:
            ev = o.evidence.replace("|", "\\|")
            lines.append(f"| {o.severity} | {o.offense} | {o.confidence} | {ev} |")
        lines.append("")
    return "\n".join(lines)
