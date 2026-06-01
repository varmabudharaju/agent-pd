import json
from pathlib import Path
from agent_pd.cli import main

def _setup_session(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    line = json.dumps({"agentId": "a1", "sessionId": "s1", "cwd": "/proj",
                       "type": "assistant", "message": {"role": "assistant", "content": [
                           {"type": "tool_use", "name": "Grep", "input": {"pattern": "foo"}},
                           {"type": "tool_use", "name": "Grep", "input": {"pattern": "foo"}}]}})
    (sub / "agent-a1.jsonl").write_text(line + "\n")
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"
    audit.mkdir()
    return projects, audit

def test_report_json_lists_redundant(tmp_path, capsys):
    projects, audit = _setup_session(tmp_path)
    rc = main(["report", "--session", "s1", "--format", "json",
               "--projects-dir", str(projects), "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    data = json.loads(out)
    assert any(o["offense"] == "redundant" for o in data)

def test_list_shows_session(tmp_path, capsys):
    projects, audit = _setup_session(tmp_path)
    rc = main(["list", "--projects-dir", str(projects), "--audit-dir", str(audit)])
    assert rc == 0
    assert "s1" in capsys.readouterr().out
