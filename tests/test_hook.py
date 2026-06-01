import json
from agent_pd.hook import build_event, write_event, audit_path

def test_build_event_normalizes_fields():
    payload = {
        "hook_event_name": "PostToolUse",
        "agent_id": "a1", "agent_type": "Explore",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "session_id": "s1", "cwd": "/x", "timestamp": "2026-06-01T00:00:00Z",
    }
    ev = build_event(payload)
    assert ev["event"] == "PostToolUse"
    assert ev["agent_id"] == "a1"
    assert ev["tool_name"] == "Bash"
    assert ev["decision"] is None

def test_build_event_camelcase_and_denial():
    payload = {
        "hook_event_name": "PermissionDenied",
        "agentId": "a2", "agentType": "general-purpose",
        "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
        "sessionId": "s1",
        "permissionDecision": "deny", "reason": "blocked by rule",
    }
    ev = build_event(payload)
    assert ev["agent_id"] == "a2"
    assert ev["decision"] == "deny"
    assert ev["reason"] == "blocked by rule"

def test_write_event_appends_to_session_file(tmp_path):
    ev = {"event": "PostToolUse", "session_id": "s9", "agent_id": "a1"}
    write_event(ev, audit_dir=tmp_path)
    out = audit_path("s9", audit_dir=tmp_path)
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["agent_id"] == "a1"
    write_event(ev, audit_dir=tmp_path)
    assert len(out.read_text().splitlines()) == 2
