import json
from pathlib import Path
from agent_pd.cli import main, build_parser, _cmd_watch, _cmd_verify
from agent_pd import integrity, store, sink


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


def test_verify_head_mismatch_rechain(tmp_path, capsys):
    # Re-chain attack: the log tail was rewritten but the head was left with the
    # SAME seq and a STALE/WRONG chain hex. verify must catch the mismatch.
    audit = tmp_path / "audit"
    _write_chained_session(audit, "rechain", 3)
    last_seq = 3
    integrity.write_head("rechain", audit, last_seq, "deadbeefwronghex")
    rc = main(["verify", "--session", "rechain", "--audit-dir", str(audit)])
    assert rc == 2
    out = capsys.readouterr().out.lower()
    assert "head" in out and ("mismatch" in out or "rewritten" in out)


def test_verify_benign_lagging_head_not_flagged(tmp_path, capsys):
    # Crash-before-head case: head lags by one seq (head_seq < last_seq). This is
    # benign and must NOT trip the head-mismatch check; verify reports intact.
    audit = tmp_path / "audit"
    events = _write_chained_session(audit, "lag", 3)
    # rewind head to seq 2 with its correct prior chain
    prior = events[1]
    integrity.write_head("lag", audit, prior[integrity.SEQ_KEY],
                         prior[integrity.CHAIN_KEY])
    rc = main(["verify", "--session", "lag", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out.lower()
    assert "intact" in out
    assert "head" not in out  # no head-mismatch complaint


def test_verify_healthy_head_matches(tmp_path, capsys):
    # head_seq == last_seq AND head_hex == last_chain -> intact.
    audit = tmp_path / "audit"
    _write_chained_session(audit, "healthy", 4)
    rc = main(["verify", "--session", "healthy", "--audit-dir", str(audit)])
    assert rc == 0
    assert "intact" in capsys.readouterr().out.lower()


# ---- pd sink ----

def _unset_sink_env(monkeypatch):
    for k in ("PD_SINK_TYPE", "PD_SINK_URL", "PD_SINK_PATH",
              "PD_SINK_TOKEN", "PD_SINK_TIMEOUT"):
        monkeypatch.delenv(k, raising=False)


def test_sink_subcommand_parses():
    args = build_parser().parse_args(["sink", "push", "--all"])
    assert args.sink_cmd == "push" and args.all_sessions is True
    args = build_parser().parse_args(["sink", "status"])
    assert args.sink_cmd == "status"


def test_sink_push_forwards_chained(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 3)
    sinkfile = tmp_path / "sink.ndjson"
    _unset_sink_env(monkeypatch)
    monkeypatch.setenv("PD_SINK_TYPE", "file")
    monkeypatch.setenv("PD_SINK_PATH", str(sinkfile))

    rc = main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sent 3" in out
    lines = sinkfile.read_text().splitlines()
    assert len(lines) == 3
    assert [json.loads(x)[integrity.SEQ_KEY] for x in lines] == [1, 2, 3]


def test_sink_push_idempotent(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 3)
    sinkfile = tmp_path / "sink.ndjson"
    _unset_sink_env(monkeypatch)
    monkeypatch.setenv("PD_SINK_TYPE", "file")
    monkeypatch.setenv("PD_SINK_PATH", str(sinkfile))

    main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    capsys.readouterr()
    rc = main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "up to date" in out
    assert len(sinkfile.read_text().splitlines()) == 3  # unchanged


def test_sink_status_up_to_date(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 3)
    sinkfile = tmp_path / "sink.ndjson"
    _unset_sink_env(monkeypatch)
    monkeypatch.setenv("PD_SINK_TYPE", "file")
    monkeypatch.setenv("PD_SINK_PATH", str(sinkfile))
    main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    capsys.readouterr()

    rc = main(["sink", "status", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "3/3 forwarded" in out
    assert "up to date" in out


def test_sink_status_pending_then_push(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 3)
    sinkfile = tmp_path / "sink.ndjson"
    _unset_sink_env(monkeypatch)
    monkeypatch.setenv("PD_SINK_TYPE", "file")
    monkeypatch.setenv("PD_SINK_PATH", str(sinkfile))
    main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    capsys.readouterr()

    # append a 4th chained event continuing the chain
    events = list(store.iter_events("s1", audit))
    last = events[-1]
    e4 = integrity.next_link(last[integrity.CHAIN_KEY], last[integrity.SEQ_KEY],
                             {"event": "PostToolUse", "session_id": "s1",
                              "tool_name": "Read", "tool_input": {"n": 4}})
    with (audit / "s1.jsonl").open("a", encoding="utf-8") as f:
        f.write(json.dumps(e4) + "\n")

    rc = main(["sink", "status", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "3/4 forwarded" in out
    assert "1 pending" in out

    rc = main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "sent 1" in out
    assert len(sinkfile.read_text().splitlines()) == 4


def test_sink_push_no_sink_configured(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 2)
    _unset_sink_env(monkeypatch)
    rc = main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "no sink configured" in out.lower()


def test_sink_push_all_two_sessions(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 2)
    _write_chained_session(audit, "s2", 3)
    sinkfile = tmp_path / "sink.ndjson"
    _unset_sink_env(monkeypatch)
    monkeypatch.setenv("PD_SINK_TYPE", "file")
    monkeypatch.setenv("PD_SINK_PATH", str(sinkfile))
    rc = main(["sink", "push", "--all", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "s1" in out and "s2" in out
    assert len(sinkfile.read_text().splitlines()) == 5


def test_sink_push_failure_rc2_no_advance(tmp_path, capsys, monkeypatch):
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 3)
    _unset_sink_env(monkeypatch)
    # http sink pointing at a dead port
    monkeypatch.setenv("PD_SINK_TYPE", "http")
    monkeypatch.setenv("PD_SINK_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("PD_SINK_TIMEOUT", "2")

    rc = main(["sink", "push", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 2
    out = capsys.readouterr().out
    assert "FAILED" in out
    # state NOT advanced
    assert sink.read_forwarded_seq("s1", audit) == 0
    rc = main(["sink", "status", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    assert "0/3 forwarded" in capsys.readouterr().out


def test_sink_status_remote_ahead_flags_tampering(tmp_path, capsys, monkeypatch):
    # forwarded_seq (off-host) is HIGHER than the local log => local truncation
    # / tamper signal. Local log only has seq 1..2 but state says 5 forwarded.
    audit = tmp_path / "audit"
    _write_chained_session(audit, "s1", 2)
    _unset_sink_env(monkeypatch)
    sink.write_forwarded_seq("s1", audit, 5)

    rc = main(["sink", "status", "--session", "s1", "--audit-dir", str(audit)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "5/2 forwarded" in out
    assert "remote ahead" in out
    assert "missing" in out
    assert "3 local event" in out  # 5 - 2 = 3 missing


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
