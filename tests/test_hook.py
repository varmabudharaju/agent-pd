import json
import agent_pd.hook as hook
from agent_pd.hook import build_event, write_event, audit_path, main

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

def test_build_event_infers_denial_from_event_name():
    # Realistic PermissionDenied payload: NO permissionDecision/decision field.
    payload = {
        "hook_event_name": "PermissionDenied",
        "agentId": "a2", "agentType": "general-purpose",
        "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
        "sessionId": "s1",
    }
    ev = build_event(payload)
    assert ev["agent_id"] == "a2"
    assert ev["event"] == "PermissionDenied"
    assert ev["decision"] == "deny"   # inferred from the event name


def test_build_event_honors_explicit_decision():
    payload = {"hook_event_name": "PermissionDenied", "session_id": "s1",
               "permissionDecision": "deny", "reason": "blocked by rule"}
    ev = build_event(payload)
    assert ev["decision"] == "deny"
    assert ev["reason"] == "blocked by rule"

def test_build_event_reads_denial_reason_first():
    payload = {
        "hook_event_name": "PermissionDenied", "session_id": "s1",
        "denial_reason": "blocked by deny rule",
        "reason": "some other reason",
    }
    ev = build_event(payload)
    assert ev["reason"] == "blocked by deny rule"


def test_build_event_captures_tool_result():
    payload = {
        "hook_event_name": "PostToolUse", "session_id": "s1",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "tool_result": {"stdout": "a.txt\nb.txt", "exit_code": 0},
    }
    ev = build_event(payload)
    assert ev["tool_result"] == {"stdout": "a.txt\nb.txt", "exit_code": 0}


def test_build_event_tool_result_defaults_none():
    ev = build_event({"hook_event_name": "PostToolUse", "session_id": "s1"})
    assert ev["tool_result"] is None


def test_build_event_captures_permission_mode():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "permission_mode": "acceptEdits"}
    ev = build_event(payload)
    assert ev["permission_mode"] == "acceptEdits"


def test_build_event_captures_transcript_path():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "transcript_path": "/tmp/transcript.jsonl"}
    ev = build_event(payload)
    assert ev["transcript_path"] == "/tmp/transcript.jsonl"


def test_build_event_extra_passthrough():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "FUTURE_FIELD": "v"}
    ev = build_event(payload)
    assert ev["_extra"]["FUTURE_FIELD"] == "v"


def test_build_event_no_extra_for_known_fields_only():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "tool_name": "Bash", "tool_input": {"command": "ls"}}
    ev = build_event(payload)
    assert "_extra" not in ev


def test_build_event_force_deny_overrides_spoofed_allow():
    payload = {"hook_event_name": "PermissionDenied", "session_id": "s1",
               "permissionDecision": "allow"}
    ev = build_event(payload)
    assert ev["decision"] == "deny"


def test_gather_record_carries_tool_result_onto_action():
    from agent_pd.live import LiveMonitor
    from agent_pd.config import load_rules
    mon = LiveMonitor(projects_dir="/nonexistent", audit_dir="/nonexistent")
    event = build_event({
        "hook_event_name": "PostToolUse", "session_id": "s1", "agent_id": "a1",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "tool_result": {"stdout": "ok"},
    })
    mon.process(event, load_rules(None))
    action = mon.records["a1"].actions[0]
    assert action.tool_result == {"stdout": "ok"}


def test_main_writes_to_stderr_on_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(hook, "write_event", boom)
    monkeypatch.setattr(hook.sys, "stdin", __import__("io").StringIO("{}"))
    rc = main()
    assert rc == 0
    captured = capsys.readouterr()
    assert "agent-pd hook error" in captured.err


def test_write_event_appends_to_session_file(tmp_path):
    ev = {"event": "PostToolUse", "session_id": "s9", "agent_id": "a1"}
    write_event(ev, audit_dir=tmp_path)
    out = audit_path("s9", audit_dir=tmp_path)
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["agent_id"] == "a1"
    write_event(ev, audit_dir=tmp_path)
    assert len(out.read_text().splitlines()) == 2
