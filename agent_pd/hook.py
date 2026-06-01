# agent_pd/hook.py
# Patrol hook: logging-only. Reads one hook JSON object from stdin, appends a
# normalized event to ~/.claude/pd/audit/<session_id>.jsonl, ALWAYS exits 0.
# Transcript schema confirmed in spec. Hook payload field names are read defensively
# (camelCase + snake_case fallbacks) since they are not yet confirmed against a live run.
import json
import sys
from pathlib import Path

DEFAULT_AUDIT_DIR = Path.home() / ".claude" / "pd" / "audit"


def _first(payload, *keys, default=None):
    for k in keys:
        if k in payload and payload[k] is not None:
            return payload[k]
    return default


def build_event(payload: dict) -> dict:
    return {
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


def audit_path(session_id: str, audit_dir: Path = DEFAULT_AUDIT_DIR) -> Path:
    sid = session_id or "unknown-session"
    return Path(audit_dir) / f"{sid}.jsonl"


def write_event(event: dict, audit_dir: Path = DEFAULT_AUDIT_DIR) -> None:
    audit_dir = Path(audit_dir)
    audit_dir.mkdir(parents=True, exist_ok=True)
    path = audit_path(event.get("session_id", ""), audit_dir=audit_dir)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event) + "\n")


def main() -> int:
    # Crash-safe: any error is swallowed so the agent run is never affected.
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        write_event(build_event(payload))
    except Exception:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
