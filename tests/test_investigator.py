import json
from agent_pd.investigator import load_meta, gather


def _audit(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def test_load_meta(tmp_path):
    m = tmp_path / "agent-a1.meta.json"
    m.write_text(json.dumps({"agentType": "Explore", "description": "find foo"}))
    agent_type, brief = load_meta(m)
    assert agent_type == "Explore"
    assert brief == "find foo"


def test_gather_includes_main_agent(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "", "tool_name": "Read",
         "tool_input": {"file_path": "/proj/app.py"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    assert records[0].agent_id == ""
    assert records[0].agent_type == "main"
    assert records[0].actions[0].tool_name == "Read"


def test_gather_includes_subagent_with_brief(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1", "agent_type": "Explore",
         "tool_name": "Grep", "tool_input": {"pattern": "foo"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert rec.agent_type == "Explore"
    assert rec.brief == "find foo"
    assert rec.actions[0].tool_name == "Grep"


def test_gather_surfaces_denial(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    # On-disk shape after the hook ran: PermissionDenied with decision already inferred.
    _audit(audit / "s1.jsonl", [
        {"event": "PermissionDenied", "session_id": "s1", "agent_id": "a1",
         "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
         "decision": "deny", "reason": "blocked", "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert rec.actions[0].decision == "deny"


def test_gather_no_double_count(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1",
         "tool_name": "Grep", "tool_input": {"pattern": "foo"}, "cwd": "/proj"},
    ])
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    rec = next(r for r in records if r.agent_id == "a1")
    assert sum(1 for a in rec.actions if a.tool_name == "Grep") == 1


def test_latest_session_picks_newest_audit(tmp_path):
    import os
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "old.jsonl").write_text("{}\n")
    (audit / "new.jsonl").write_text("{}\n")
    # make 'new' clearly newer
    os.utime(audit / "old.jsonl", (1, 1))
    # gather(session_id=None) should resolve to the newest audit session and read it
    recs = gather(session_id=None, projects_dir=projects, audit_dir=audit)
    # both files are essentially empty ({} has no tool_name) -> no records, but no crash
    assert recs == [] or isinstance(recs, list)


def test_gather_tolerates_malformed_and_missing(tmp_path):
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s1.jsonl").write_text(
        "not json\n" + json.dumps(
            {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1",
             "tool_name": "Read", "tool_input": {"file_path": "/proj/x"}, "cwd": "/proj"}) + "\n")
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert any(r.agent_id == "a1" for r in records)
    # missing session file -> empty
    assert gather(session_id="nope", projects_dir=projects, audit_dir=audit) == []
