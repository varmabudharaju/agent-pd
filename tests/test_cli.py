import json
from pathlib import Path
from agent_pd.cli import main, build_parser, _cmd_watch


def test_judge_dry_run_reports_estimate(tmp_path, capsys):
    projects, audit = _setup_session(tmp_path)  # one agent, two identical Grep "foo"
    rc = main(["judge", "--session", "s1",
               "--projects-dir", str(projects), "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    # brief "find foo" vs pattern "foo" overlaps -> not off_task -> nothing to judge
    assert "No off_task" in out or "dry run" in out


def test_judge_dry_run_with_offtask(tmp_path, capsys):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s2" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-z1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find the version string"}))
    audit = tmp_path / "audit"
    audit.mkdir()
    # audit log is the single source of truth: Grep "kubernetes" vs brief -> off_task
    (audit / "s2.jsonl").write_text(json.dumps(
        {"event": "PostToolUse", "session_id": "s2", "agent_id": "z1",
         "agent_type": "Explore", "tool_name": "Grep",
         "tool_input": {"pattern": "kubernetes"}, "cwd": "/proj"}) + "\n")
    rc = main(["judge", "--session", "s2", "--projects-dir", str(projects),
               "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "dry run" in out and "--run" in out


def test_judge_subcommand_parses():
    args = build_parser().parse_args(
        ["judge", "--run", "--via-claude-code", "--model", "opus", "--max", "5"])
    assert args.run is True and args.model == "opus" and args.max == 5
    assert args.via_claude_code is True


def test_watch_subcommand_parses():
    args = build_parser().parse_args(
        ["watch", "--all", "--crimes-only", "-v", "--no-color", "--no-emoji"])
    assert args.func is _cmd_watch
    assert args.crimes_only is True
    assert args.verbose is True and args.all_sessions is True
    assert args.no_color is True and args.no_emoji is True
    assert args.session is None

def _setup_session(tmp_path):
    projects = tmp_path / "projects"
    sub = projects / "-proj" / "s1" / "subagents"
    sub.mkdir(parents=True)
    (sub / "agent-a1.meta.json").write_text(json.dumps(
        {"agentType": "Explore", "description": "find foo"}))
    audit = tmp_path / "audit"
    audit.mkdir()
    # audit log is the single source of truth: two identical Grep "foo" -> redundant
    ev = {"event": "PostToolUse", "session_id": "s1", "agent_id": "a1",
          "agent_type": "Explore", "tool_name": "Grep",
          "tool_input": {"pattern": "foo"}, "cwd": "/proj"}
    (audit / "s1.jsonl").write_text(json.dumps(ev) + "\n" + json.dumps(ev) + "\n")
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
