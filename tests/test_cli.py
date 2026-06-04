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


import gzip


def test_compact_subcommand_parses():
    args = build_parser().parse_args(
        ["compact", "--session", "s1", "--prune-older-than", "30", "--dry-run"])
    assert args.session == "s1" and args.prune_older_than == 30 and args.dry_run is True


def test_compact_command_compacts_a_session(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    big = "Z" * 5000
    (audit / "s1.jsonl").write_text(json.dumps(
        {"event": "PostToolUse", "session_id": "s1", "tool_name": "Write",
         "tool_input": {"file_path": "x.py", "content": big}}) + "\n")
    rc = main(["compact", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    assert (audit / "s1.jsonl.gz").exists()
    assert not (audit / "s1.jsonl").exists()
    assert "compacted" in capsys.readouterr().out.lower()


def test_compact_dry_run_writes_nothing(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s1.jsonl").write_text(json.dumps(
        {"tool_name": "Write", "tool_input": {"content": "Z" * 5000}}) + "\n")
    rc = main(["compact", "--session", "s1", "--dry-run", "--audit-dir", str(audit)])
    assert rc == 0
    assert (audit / "s1.jsonl").exists()
    assert not (audit / "s1.jsonl.gz").exists()


def test_list_includes_compacted_sessions(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    projects = tmp_path / "projects"; projects.mkdir()
    (audit / "a.jsonl.gz").write_bytes(gzip.compress(b'{"i":1}\n'))
    rc = main(["list", "--audit-dir", str(audit), "--projects-dir", str(projects)])
    assert rc == 0
    assert "a" in capsys.readouterr().out.split()


def test_compact_with_prune_older_than(tmp_path, capsys):
    import gzip as _gz, os, time
    audit = tmp_path / "audit"; audit.mkdir()
    # an old compacted session + a fresh active plain session
    (audit / "old.jsonl.gz").write_bytes(_gz.compress(b'{"i":1}\n'))
    os.utime(audit / "old.jsonl.gz", (time.time() - 40 * 86400,) * 2)
    (audit / "active.jsonl").write_text('{"tool_name":"Read","tool_input":{}}\n')
    rc = main(["compact", "--prune-older-than", "30", "--audit-dir", str(audit)])
    assert rc == 0
    assert not (audit / "old.jsonl.gz").exists()       # pruned
    assert (audit / "active.jsonl").exists()            # active untouched
