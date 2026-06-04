import json
from pathlib import Path
from agent_pd.cli import main, build_parser, _cmd_watch, _cmd_verify
from agent_pd import integrity, store


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


# ---- pd verify ----

def _write_chained_session(audit, sid, n, key=None):
    """Write a valid chained <sid>.jsonl + matching head; return the events."""
    audit.mkdir(parents=True, exist_ok=True)
    prev_hex, prev_seq = integrity.GENESIS, 0
    events = []
    lines = []
    for i in range(1, n + 1):
        base = {"event": "PostToolUse", "session_id": sid,
                "tool_name": "Read", "tool_input": {"n": i}}
        e = integrity.next_link(prev_hex, prev_seq, base, key)
        events.append(e)
        lines.append(json.dumps(e))
        prev_hex, prev_seq = e[integrity.CHAIN_KEY], e[integrity.SEQ_KEY]
    (audit / f"{sid}.jsonl").write_text("\n".join(lines) + "\n")
    integrity.write_head(sid, audit, prev_seq, prev_hex)
    return events


def test_verify_subcommand_parses():
    args = build_parser().parse_args(["verify", "--session", "s1", "--all"])
    assert args.func is _cmd_verify
    assert args.session == "s1" and args.all_sessions is True


def test_verify_intact_session(tmp_path, capsys):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "good", 3)
    rc = main(["verify", "--session", "good", "--audit-dir", str(audit)])
    assert rc == 0
    assert "intact" in capsys.readouterr().out.lower()


def test_verify_no_sessions(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    rc = main(["verify", "--audit-dir", str(audit)])
    assert rc == 0
    assert "no sessions" in capsys.readouterr().out.lower()


def test_verify_tampered_session(tmp_path, capsys):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "bad", 4)
    # flip a middle line's content on disk (seq 2)
    path = audit / "bad.jsonl"
    lines = path.read_text().splitlines()
    ev = json.loads(lines[1])
    ev["tool_input"]["n"] = 999
    lines[1] = json.dumps(ev)
    path.write_text("\n".join(lines) + "\n")
    rc = main(["verify", "--session", "bad", "--audit-dir", str(audit)])
    assert rc == 2
    out = capsys.readouterr().out.lower()
    assert "tamper" in out and "2" in out


def test_verify_truncated_session(tmp_path, capsys):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "trunc", 3)
    # head claims seq 5 but the log only ends at seq 3
    integrity.write_head("trunc", audit, 5, "deadbeef")
    rc = main(["verify", "--session", "trunc", "--audit-dir", str(audit)])
    assert rc == 2
    out = capsys.readouterr().out.lower()
    assert "truncat" in out


def test_verify_legacy_session(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    # lines without chain, no head
    (audit / "old.jsonl").write_text(
        json.dumps({"event": "PostToolUse", "tool_name": "Read"}) + "\n")
    rc = main(["verify", "--session", "old", "--audit-dir", str(audit)])
    assert rc == 0
    assert "legacy" in capsys.readouterr().out.lower()


def test_verify_all_flags_tampered(tmp_path, capsys):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "good", 2)
    _write_chained_session(audit, "bad", 3)
    # tamper bad
    path = audit / "bad.jsonl"
    lines = path.read_text().splitlines()
    ev = json.loads(lines[1]); ev["tool_input"]["n"] = 777
    lines[1] = json.dumps(ev)
    path.write_text("\n".join(lines) + "\n")
    rc = main(["verify", "--all", "--audit-dir", str(audit)])
    assert rc == 2
    out = capsys.readouterr().out.lower()
    assert "good" in out and "bad" in out


def test_verify_survives_compaction(tmp_path, capsys):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "comp", 4)
    n = store.compact_session("comp", audit)
    assert n == 4
    assert (audit / "comp.jsonl.gz").exists()
    assert not (audit / "comp.jsonl").exists()
    rc = main(["verify", "--session", "comp", "--audit-dir", str(audit)])
    assert rc == 0
    assert "intact" in capsys.readouterr().out.lower()


def test_verify_keyed(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    monkeypatch.setenv("PD_AUDIT_KEY", "s3cr3t")
    _write_chained_session(audit, "keyed", 3, key=integrity.audit_key())
    # with key set -> intact
    rc = main(["verify", "--session", "keyed", "--audit-dir", str(audit)])
    assert rc == 0
    assert "intact" in capsys.readouterr().out.lower()
    # without key -> tamper (chain recomputes differently)
    monkeypatch.delenv("PD_AUDIT_KEY")
    rc = main(["verify", "--session", "keyed", "--audit-dir", str(audit)])
    assert rc == 2
    assert "tamper" in capsys.readouterr().out.lower()


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
