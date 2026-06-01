import json
from pathlib import Path
from agent_pd.investigator import parse_transcript, load_meta, gather

def _write_transcript(path, agent_id, tool_calls):
    lines = []
    for name, inp in tool_calls:
        lines.append(json.dumps({
            "agentId": agent_id, "sessionId": "s1", "cwd": "/proj",
            "timestamp": "2026-06-01T00:00:00Z", "type": "assistant",
            "message": {"role": "assistant", "content": [
                {"type": "text", "text": "thinking..."},
                {"type": "tool_use", "name": name, "input": inp},
            ]},
        }))
    path.write_text("\n".join(lines) + "\n")

def test_parse_transcript_extracts_tool_uses(tmp_path):
    t = tmp_path / "agent-a1.jsonl"
    _write_transcript(t, "a1", [("Grep", {"pattern": "foo"}), ("Bash", {"command": "ls"})])
    actions = parse_transcript(t)
    assert [a.tool_name for a in actions] == ["Grep", "Bash"]
    assert actions[0].tool_input == {"pattern": "foo"}
    assert actions[0].source == "transcript"

def test_load_meta(tmp_path):
    m = tmp_path / "agent-a1.meta.json"
    m.write_text(json.dumps({"agentType": "Explore", "description": "find foo"}))
    agent_type, brief = load_meta(m)
    assert agent_type == "Explore"
    assert brief == "find foo"

def test_gather_survives_malformed_first_line(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    # leading blank line + a valid tool_use line further down
    body = "\n" + json.dumps({
        "agentId": "a1", "cwd": "/proj", "type": "assistant",
        "message": {"role": "assistant", "content": [
            {"type": "tool_use", "name": "Grep", "input": {"pattern": "foo"}}]}}) + "\n"
    (sub / "agent-a1.jsonl").write_text(body)
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"; audit.mkdir()
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    assert records[0].cwd == "/proj"   # cwd recovered from the first PARSEABLE object line
    assert any(a.tool_name == "Grep" for a in records[0].actions)


def test_gather_includes_audit_only_agent(tmp_path):
    # an agent that appears ONLY in the audit log (denied before any transcript entry)
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s1.jsonl").write_text(json.dumps({
        "event": "PermissionDenied", "session_id": "s1", "agent_id": "ghost",
        "tool_name": "Bash", "tool_input": {"command": "sudo x"},
        "decision": "deny", "reason": "blocked"}) + "\n")
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    assert records[0].agent_id == "ghost"
    assert records[0].actions[0].decision == "deny"


def test_gather_correlates_transcript_meta_and_audit(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    _write_transcript(sub / "agent-a1.jsonl", "a1", [("Grep", {"pattern": "foo"})])
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "s1.jsonl").write_text(json.dumps({
        "event": "PermissionDenied", "session_id": "s1", "agent_id": "a1",
        "agent_type": "Explore", "tool_name": "Bash",
        "tool_input": {"command": "sudo rm -rf /"}, "decision": "deny",
        "reason": "blocked"}) + "\n")

    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    rec = records[0]
    assert rec.agent_id == "a1"
    assert rec.agent_type == "Explore"
    assert rec.brief == "find foo"
    names = [(a.tool_name, a.source, a.decision) for a in rec.actions]
    assert ("Grep", "transcript", None) in names
    assert ("Bash", "audit", "deny") in names
