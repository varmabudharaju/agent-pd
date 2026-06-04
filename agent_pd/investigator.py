import json
from pathlib import Path

from . import store

DEFAULT_PROJECTS_DIR = Path.home() / ".claude" / "projects"
DEFAULT_AUDIT_DIR = Path.home() / ".claude" / "pd" / "audit"


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
    # projects_dir kept for the caller's signature; audit files are the only source.
    return store.latest_session(audit_dir)


def gather(session_id=None, projects_dir=DEFAULT_PROJECTS_DIR, audit_dir=DEFAULT_AUDIT_DIR):
    from .live import LiveMonitor          # lazy import avoids a circular import
    from .config import load_rules
    projects_dir, audit_dir = Path(projects_dir), Path(audit_dir)
    if session_id is None:
        session_id = _latest_session(projects_dir, audit_dir)
        if session_id is None:
            return []
    events = list(store.iter_events(session_id, audit_dir))
    if not events:
        return []
    mon = LiveMonitor(projects_dir=projects_dir, audit_dir=audit_dir)
    rules = load_rules(None)               # detectors re-run in the CLI with real rules
    for ev in events:
        mon.process(ev, rules)
    records = list(mon.records.values())
    for r in records:                      # label the main agent (empty agent_id)
        if not r.agent_id and not r.agent_type:
            r.agent_type = "main"
    return records
