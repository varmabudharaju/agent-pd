import json
from pathlib import Path

from .models import Action, AgentRecord

DEFAULT_PROJECTS_DIR = Path.home() / ".claude" / "projects"
DEFAULT_AUDIT_DIR = Path.home() / ".claude" / "pd" / "audit"


def parse_transcript(path: Path) -> list:
    actions = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        content = (obj.get("message") or {}).get("content")
        if not isinstance(content, list):
            continue
        for b in content:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                actions.append(Action(
                    agent_id=obj.get("agentId", ""),
                    tool_name=b.get("name", ""),
                    tool_input=b.get("input") or {},
                    ts=obj.get("timestamp"),
                    source="transcript",
                ))
    return actions


def load_meta(meta_path: Path):
    try:
        obj = json.loads(Path(meta_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return "", ""
    return obj.get("agentType", ""), obj.get("description", "")


def find_subagents_dir(projects_dir: Path, session_id: str):
    matches = list(Path(projects_dir).glob(f"*/{session_id}/subagents"))
    return matches[0] if matches else None


def _latest_session(projects_dir: Path, audit_dir: Path):
    candidates = []
    if Path(audit_dir).exists():
        candidates += [(p.stat().st_mtime, p.stem) for p in Path(audit_dir).glob("*.jsonl")]
    for sub in Path(projects_dir).glob("*/*/subagents"):
        candidates.append((sub.stat().st_mtime, sub.parent.name))
    if not candidates:
        return None
    return max(candidates)[1]


def _load_audit_actions(audit_dir: Path, session_id: str) -> dict:
    """Return {agent_id: [Action]} for audit denial events."""
    by_agent = {}
    f = Path(audit_dir) / f"{session_id}.jsonl"
    if not f.exists():
        return by_agent
    for line in f.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("decision") != "deny":
            continue   # v1 only merges denials; allows are already in transcripts
        aid = ev.get("agent_id", "")
        by_agent.setdefault(aid, []).append(Action(
            agent_id=aid,
            tool_name=ev.get("tool_name", ""),
            tool_input=ev.get("tool_input") or {},
            ts=ev.get("ts"),
            decision="deny",
            reason=ev.get("reason"),
            source="audit",
        ))
    return by_agent


def gather(session_id=None, projects_dir=DEFAULT_PROJECTS_DIR, audit_dir=DEFAULT_AUDIT_DIR):
    projects_dir, audit_dir = Path(projects_dir), Path(audit_dir)
    if session_id is None:
        session_id = _latest_session(projects_dir, audit_dir)
        if session_id is None:
            return []
    sub = find_subagents_dir(projects_dir, session_id)
    audit_actions = _load_audit_actions(audit_dir, session_id)
    records = []
    seen = set()
    if sub is not None:
        for tpath in sorted(sub.glob("agent-*.jsonl")):
            agent_id = tpath.stem[len("agent-"):]
            seen.add(agent_id)
            agent_type, brief = load_meta(sub / f"agent-{agent_id}.meta.json")
            actions = parse_transcript(tpath)
            cwd = ""
            if actions:
                first = json.loads(tpath.read_text(encoding="utf-8").splitlines()[0])
                cwd = first.get("cwd", "")
            actions += audit_actions.get(agent_id, [])
            records.append(AgentRecord(agent_id=agent_id, agent_type=agent_type,
                                       brief=brief, cwd=cwd, actions=actions))
    for agent_id, acts in audit_actions.items():
        if agent_id in seen:
            continue
        records.append(AgentRecord(agent_id=agent_id, agent_type="",
                                   brief="", cwd="", actions=acts))
    return records
