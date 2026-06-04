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


def test_latest_session_picks_newest_audit_only(tmp_path):
    import os
    from agent_pd.investigator import _latest_session
    projects = tmp_path / "projects"
    # a subagents-dir session with NO audit file, made the newest mtime of all
    stale = projects / "-proj" / "ghost" / "subagents"
    stale.mkdir(parents=True)
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "old.jsonl").write_text("{}\n")
    (audit / "new.jsonl").write_text("{}\n")
    os.utime(audit / "old.jsonl", (1, 1))
    os.utime(audit / "new.jsonl", (100, 100))
    os.utime(stale, (1000, 1000))            # newest mtime overall
    # must pick the newest AUDIT file, never the subagents-only 'ghost'
    assert _latest_session(projects, audit) == "new"


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


def test_gather_reads_compacted_session(tmp_path):
    from agent_pd import store
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    big = "C" * 5000
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Write", "tool_input": {"file_path": "/proj/app.py", "content": big},
         "cwd": "/proj"},
    ])
    store.compact_session("s1", audit)
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    act = records[0].actions[0]
    assert act.tool_name == "Write"
    # gzip-only: every field kept inline — path and full content are both intact
    assert act.tool_input["file_path"] == "/proj/app.py"
    assert act.tool_input["content"] == big
