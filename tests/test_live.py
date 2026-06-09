import json
from agent_pd.live import LiveMonitor, tail_events, tail_all_events, watch
from agent_pd.config import load_rules
from agent_pd.render import Style

RULES = load_rules(None)


def _ev(agent_id, tool, inp, event="PostToolUse", decision=None, reason=None,
        agent_type="gp", session="s1"):
    return {"event": event, "session_id": session, "agent_id": agent_id,
            "agent_type": agent_type, "tool_name": tool, "tool_input": inp,
            "decision": decision, "reason": reason, "ts": "12:00"}


def _mon(tmp_path):
    return LiveMonitor(projects_dir=tmp_path / "p", audit_dir=tmp_path / "a")


def test_banner_once_per_agent(tmp_path):
    mon = _mon(tmp_path)
    r1 = mon.process(_ev("a1", "Grep", {"pattern": "foo"}), RULES)
    r2 = mon.process(_ev("a1", "Grep", {"pattern": "bar"}), RULES)
    assert r1.new_agent is True
    assert r2.new_agent is False


def test_watch_rereads_allow_rules_midsession(tmp_path, monkeypatch):
    # The live monitor must re-read permission allow-rules per event, so a permission
    # granted mid-session (written to .claude/settings.local.json) is reflected live and
    # not frozen at the agent's first-seen state.
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(tmp_path / "cfg"))   # isolate user config
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    mon = _mon(tmp_path)
    ev = _ev("a1", "Read", {"file_path": str(proj / "x.py")}, agent_type="main")
    ev["cwd"] = str(proj)
    mon.process(dict(ev), RULES)
    assert mon.records["a1"].allow_rules == []          # no rules yet
    # grant a permission mid-session
    (proj / ".claude" / "settings.local.json").write_text(
        '{"permissions": {"allow": ["Read(~/secrets/*)"]}}')
    mon.process(dict(ev), RULES)
    assert "Read(~/secrets/*)" in mon.records["a1"].allow_rules


def test_denial_flagged_as_permission_bypass(tmp_path):
    mon = _mon(tmp_path)
    r = mon.process(_ev("a1", "Bash", {"command": "rm x"}, event="PermissionDenied",
                        decision="deny", reason="blocked"), RULES)
    assert any(o.offense == "permission_bypass" for o in r.new_offenses)


def test_each_offense_emitted_once(tmp_path):
    mon = _mon(tmp_path)
    a = lambda: _ev("a1", "Grep", {"pattern": "dup"})
    mon.process(a(), RULES)            # 1st: clean
    r2 = mon.process(a(), RULES)       # 2nd: redundant fires
    r3 = mon.process(a(), RULES)       # 3rd: nothing new
    assert any(o.offense == "redundant" for o in r2.new_offenses)
    assert r3.new_offenses == []


def test_tallies_and_total_acts(tmp_path):
    mon = _mon(tmp_path)
    mon.process(_ev("a1", "Bash", {"command": "sudo rm"}), RULES)   # critical
    mon.process(_ev("a1", "Grep", {"pattern": "x"}), RULES)         # clean
    assert mon.total_acts == 2
    assert mon.tallies["a1"]["critical"] == 1


def test_subagent_start_registers_without_action(tmp_path):
    mon = _mon(tmp_path)
    r = mon.process({"event": "SubagentStart", "session_id": "s1", "agent_id": "a1",
                     "agent_type": "Explore", "tool_name": "", "tool_input": {}}, RULES)
    assert r.new_agent is True
    assert r.has_action is False
    assert mon.total_acts == 0


def test_tail_events_reads_appended_lines_tolerates_junk(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "s1.jsonl").write_text(
        json.dumps({"event": "PostToolUse", "agent_id": "a1"}) + "\n"
        + "\n"                                                       # blank line tolerated
        + json.dumps({"event": "PostToolUse", "agent_id": "a2"}) + "\n"
        + '{"partial": ')                                            # partial: not yielded
    evs = list(tail_events(audit, session_id="s1", poll_interval=0, _max_polls=1))
    assert [e["agent_id"] for e in evs] == ["a1", "a2"]


def test_tail_all_events_merges_sessions(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    (audit / "s1.jsonl").write_text(
        json.dumps({"event": "PostToolUse", "session_id": "s1", "agent_id": "a1"}) + "\n")
    (audit / "s2.jsonl").write_text(
        json.dumps({"event": "PostToolUse", "session_id": "s2", "agent_id": "b2"}) + "\n")
    evs = list(tail_all_events(audit, poll_interval=0, _max_polls=1))
    sids = {e["session_id"] for e in evs}
    assert sids == {"s1", "s2"}              # both sessions merged into one stream


def test_watch_all_tags_lines_with_session(tmp_path):
    out_lines = []
    evs = [_ev("a1", "Bash", {"command": "sudo rm"}, session="abc1234def")]
    watch(all_sessions=True, style=Style(color=False, emoji=False),
          projects_dir=tmp_path / "p", audit_dir=tmp_path / "a", rules=RULES,
          out=out_lines.append, _events=iter(evs))
    blob = "\n".join(out_lines)
    assert "ALL sessions" in blob          # header
    assert "§abc1234" in blob              # session marker on banner/feed line


def test_watch_emits_banner_crime_and_rap_sheet(tmp_path):
    out_lines = []
    rc = watch(style=Style(color=False, emoji=False),
               projects_dir=tmp_path / "p", audit_dir=tmp_path / "a", rules=RULES,
               out=out_lines.append, _events=iter([_ev("a1", "Bash", {"command": "sudo rm"})]))
    assert rc == 0
    blob = "\n".join(out_lines)
    assert "a1" in blob and "CRITICAL" in blob and "RAP SHEET" in blob


def test_resolve_session_file_prefers_store_latest(tmp_path):
    import os, time, gzip
    from agent_pd.live import _resolve_session_file
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "old.jsonl").write_text('{"i":1}\n')
    (audit / "new.jsonl.gz").write_bytes(gzip.compress(b'{"i":2}\n'))
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    # most-recent resolution (no session id) should pick "new" even though it's gz
    resolved = _resolve_session_file(audit, None)
    assert resolved is not None and resolved.name.startswith("new")


def test_tail_events_reads_compacted_gz(tmp_path):
    import gzip
    from agent_pd.live import tail_events
    audit = tmp_path / "audit"; audit.mkdir()
    with gzip.open(audit / "s1.jsonl.gz", "wt", encoding="utf-8") as f:
        f.write('{"i": 1}\n{"i": 2}\n')
    # no plain .jsonl exists -> _resolve_session_file returns the .gz path;
    # tail_events must read it without crashing.
    events = list(tail_events(audit, "s1", poll_interval=0, _max_polls=1))
    assert events == [{"i": 1}, {"i": 2}]


def test_tail_from_now_skips_backlog(tmp_path):
    # Default watch behavior: from_now=True starts at the end of the log, skipping the
    # existing backlog; replay (from_now=False) yields it.
    audit = tmp_path / "a"; audit.mkdir()
    (audit / "S.jsonl").write_text(json.dumps({"event": "old"}) + "\n")
    skipped = list(tail_events(audit, "S", poll_interval=0, _max_polls=1, from_now=True))
    assert skipped == []
    replayed = list(tail_events(audit, "S", poll_interval=0, _max_polls=1, from_now=False))
    assert len(replayed) == 1 and replayed[0]["event"] == "old"


def test_watch_reports_no_sessions(tmp_path):
    # A stale PD_AUDIT_DIR (or wrong --audit-dir) must not silently show an empty feed;
    # watch should say so and name the dir it looked in.
    out_lines = []
    rc = watch(style=Style(color=False, emoji=False),
               projects_dir=tmp_path / "p", audit_dir=tmp_path / "empty",
               out=out_lines.append)
    assert rc == 0
    blob = "\n".join(out_lines)
    assert "no sessions" in blob.lower()
    assert str(tmp_path / "empty") in blob
