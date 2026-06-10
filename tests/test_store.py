# tests/test_store.py
import gzip
import json
import os
import time
from pathlib import Path

from agent_pd import store


def _write_jsonl(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def _write_jsonl_gz(path, events):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(e) for e in events) + "\n")


def _read_gz_events(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def test_iter_events_reads_plain(tmp_path):
    _write_jsonl(tmp_path / "s1.jsonl", [{"i": 1}, {"i": 2}])
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_iter_events_reads_gz(tmp_path):
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"i": 1}, {"i": 2}])
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_iter_events_merges_gz_then_plain_on_race(tmp_path):
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"i": 1}])
    _write_jsonl(tmp_path / "s1.jsonl", [{"i": 2}])
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_iter_events_dedups_compaction_window(tmp_path):
    # During compaction both files briefly hold the SAME events (tmp.replace(gz) done,
    # plain.unlink() not yet). Concatenation would yield each event twice -> double-counted.
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"i": 1}, {"i": 2}])
    _write_jsonl(tmp_path / "s1.jsonl", [{"i": 1}, {"i": 2}])
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_iter_events_keeps_disjoint_resume_events(tmp_path):
    # Resume case: session compacted (gz=old), then hook appends NEW events to a fresh plain.
    # Disjoint sets -> both must be kept.
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"i": 1}])
    _write_jsonl(tmp_path / "s1.jsonl", [{"i": 2}])
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_iter_events_partial_overlap(tmp_path):
    # plain shares one event with gz and adds one new -> drop the shared, keep the new.
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"a": 1}, {"a": 2}])
    _write_jsonl(tmp_path / "s1.jsonl", [{"a": 2}, {"a": 3}])
    assert list(store.iter_events("s1", tmp_path)) == [{"a": 1}, {"a": 2}, {"a": 3}]


def test_iter_events_intra_plain_duplicates_preserved(tmp_path):
    # Two legitimately-identical lines within plain must BOTH be yielded (no within-file dedup).
    _write_jsonl(tmp_path / "s1.jsonl", [{"x": 1}, {"x": 1}])
    assert list(store.iter_events("s1", tmp_path)) == [{"x": 1}, {"x": 1}]
    # With an UNRELATED gz present, plain's two identical lines are still both yielded.
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"y": 9}])
    assert list(store.iter_events("s1", tmp_path)) == [{"y": 9}, {"x": 1}, {"x": 1}]


def test_iter_events_tolerates_blank_and_bad_lines(tmp_path):
    (tmp_path / "s1.jsonl").write_text('{"i": 1}\n\nnot json\n{"i": 2}\n')
    assert list(store.iter_events("s1", tmp_path)) == [{"i": 1}, {"i": 2}]


def test_latest_session_considers_both_extensions(tmp_path):
    _write_jsonl(tmp_path / "old.jsonl", [{"i": 1}])
    _write_jsonl_gz(tmp_path / "new.jsonl.gz", [{"i": 2}])
    old = time.time() - 100
    os.utime(tmp_path / "old.jsonl", (old, old))
    assert store.latest_session(tmp_path) == "new"


def test_list_sessions_dedups_both_extensions(tmp_path):
    _write_jsonl(tmp_path / "a.jsonl", [{"i": 1}])
    _write_jsonl_gz(tmp_path / "b.jsonl.gz", [{"i": 2}])
    (tmp_path / "a.jsonl.gz").write_bytes(gzip.compress(b'{"i": 3}\n'))
    assert store.list_sessions(tmp_path) == ["a", "b"]


def test_iter_events_missing_session_yields_nothing(tmp_path):
    # no files for this session -> empty iterator, no exception
    assert list(store.iter_events("nope", tmp_path)) == []


def test_list_sessions_missing_dir_is_empty(tmp_path):
    missing = tmp_path / "does-not-exist"
    assert store.list_sessions(missing) == []
    assert store.latest_session(missing) is None


def test_compact_session_gzips_losslessly(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    big = "Z" * 5000
    original = {"event": "PostToolUse", "tool_name": "Write",
                "tool_input": {"file_path": "x.py", "content": big}}
    _write_jsonl(audit / "s1.jsonl", [original])
    n = store.compact_session("s1", audit)
    assert n == 1
    assert not (audit / "s1.jsonl").exists()           # original removed
    assert (audit / "s1.jsonl.gz").exists()            # gz written
    ev = _read_gz_events(audit / "s1.jsonl.gz")[0]
    assert ev == original                               # every field kept inline, byte-identical


def test_compact_session_is_idempotent(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    _write_jsonl(audit / "s1.jsonl", [
        {"tool_name": "Write", "tool_input": {"content": "W" * 5000}}])
    store.compact_session("s1", audit)
    once = _read_gz_events(audit / "s1.jsonl.gz")
    store.compact_session("s1", audit)                 # 2nd pass reads the gz (no plain)
    twice = _read_gz_events(audit / "s1.jsonl.gz")
    assert once == twice


def test_compact_session_empty_session(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s1.jsonl").write_text("")
    n = store.compact_session("s1", audit)
    assert n == 0
    assert (audit / "s1.jsonl.gz").exists()
    assert not (audit / "s1.jsonl").exists()
    assert list(store.iter_events("s1", audit)) == []


def test_compact_all_skips_most_recent(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    _write_jsonl(audit / "old.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    _write_jsonl(audit / "active.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    done = store.compact_all(audit)
    assert (audit / "old.jsonl.gz").exists()
    assert (audit / "active.jsonl").exists()           # active untouched
    assert not (audit / "active.jsonl.gz").exists()
    assert done == ["old"]


def test_compact_all_skips_already_compacted_active(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    _write_jsonl(audit / "old.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    (audit / "active.jsonl.gz").write_bytes(gzip.compress(b'{"tool_name": "Read", "tool_input": {}}\n'))
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    done = store.compact_all(audit)
    assert done == ["old"]
    assert (audit / "old.jsonl.gz").exists()


def test_compact_targets_matches_compact_all(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    _write_jsonl(audit / "old.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    _write_jsonl(audit / "mid.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    _write_jsonl(audit / "active.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    os.utime(audit / "old.jsonl", (time.time() - 200,) * 2)
    os.utime(audit / "mid.jsonl", (time.time() - 100,) * 2)
    targets = store.compact_targets(audit)
    assert targets == ["mid", "old"]
    done = store.compact_all(audit)
    assert done == targets


def test_report_identical_raw_vs_compacted(tmp_path):
    from agent_pd.investigator import gather
    from agent_pd.detectors import run_detectors
    from agent_pd.config import load_rules

    projects = tmp_path / "projects"; projects.mkdir()
    rules = load_rules(None)

    def offenses_for(audit):
        recs = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
        out = []
        for r in recs:
            for o in run_detectors(r, rules):
                out.append((o.offense, o.severity, o.evidence))
        return sorted(out)

    # Self-permissioning Write: the "permissions" key sits PAST the first 500 chars of a
    # >2KB body. The rejected blob-externalization design would have dropped this critical
    # offense (only a 500-char preview was kept). Gzip-only keeps the whole body inline.
    body = "x" * 4000 + '"permissions": {"allow": ["Bash(rm:*)"]}'
    events = [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Write",
         "tool_input": {"file_path": "/proj/.claude/settings.json", "content": body},
         "cwd": "/proj"},
        {"event": "PermissionDenied", "session_id": "s1", "agent_id": "",
         "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
         "decision": "deny", "cwd": "/proj"},
    ]

    raw = tmp_path / "raw"; raw.mkdir()
    _write_jsonl(raw / "s1.jsonl", events)
    raw_offenses = offenses_for(raw)

    comp = tmp_path / "comp"; comp.mkdir()
    _write_jsonl(comp / "s1.jsonl", events)
    store.compact_session("s1", comp)

    assert offenses_for(comp) == raw_offenses
    # keystone: the self_permission offense IS detected (would be dropped by externalization)
    assert any(o[0] == "self_permission" for o in raw_offenses)


def test_gather_no_double_count_during_compaction_window(tmp_path):
    # End-to-end guard: leave BOTH gz and plain holding the SAME events (compaction window)
    # and assert each Action appears exactly once -> offenses can't be double-counted.
    from agent_pd.investigator import gather

    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    events = [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Bash", "tool_input": {"command": "echo hi"}, "cwd": "/proj"},
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Write", "tool_input": {"file_path": "/proj/a.txt", "content": "x"},
         "cwd": "/proj"},
    ]
    _write_jsonl_gz(audit / "s1.jsonl.gz", events)
    _write_jsonl(audit / "s1.jsonl", events)   # identical -> simulate the window

    recs = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    total_actions = sum(len(r.actions) for r in recs)
    assert total_actions == len(events)        # 2, not 4


def test_prune_sessions_by_age(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "old.jsonl.gz").write_bytes(gzip.compress(b'{"i":1}\n'))
    (audit / "new.jsonl.gz").write_bytes(gzip.compress(b'{"i":2}\n'))
    os.utime(audit / "old.jsonl.gz", (time.time() - 40 * 86400,) * 2)
    removed = store.prune_sessions(audit, older_than_days=30)
    assert removed == 1
    assert not (audit / "old.jsonl.gz").exists()
    assert (audit / "new.jsonl.gz").exists()


def test_prune_sessions_never_touches_plain(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "active.jsonl").write_text('{"i":1}\n')
    os.utime(audit / "active.jsonl", (time.time() - 999 * 86400,) * 2)
    removed = store.prune_sessions(audit, older_than_days=1)
    assert removed == 0                                 # plain .jsonl is never pruned
    assert (audit / "active.jsonl").exists()


def test_prune_sessions_noop_when_none(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "s.jsonl.gz").write_bytes(gzip.compress(b'{"i":1}\n'))
    assert store.prune_sessions(audit) == 0
    assert (audit / "s.jsonl.gz").exists()


# ---- session_identity ----

def _write_transcript(path, entries):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(json.dumps(e) for e in entries) + "\n")


def _user(text, **kw):
    return {"type": "user", "message": {"role": "user", "content": text}, **kw}


def test_session_identity_project_and_title(tmp_path):
    transcript = tmp_path / "projects" / "-proj" / "s1.jsonl"
    _write_transcript(transcript, [
        _user("<local-command-stdout>Set model</local-command-stdout>"),  # harness noise
        _user("Caveat: messages below were generated while running local commands"),
        _user("ignored meta", isMeta=True),
        {"type": "assistant", "message": {"role": "assistant", "content": "hi"}},
        _user("test this whole repo and features"),                       # the real prompt
    ])
    _write_jsonl(tmp_path / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "cwd": "/proj",
         "transcript_path": str(transcript)}])
    ident = store.session_identity("s1", tmp_path)
    assert ident["project"] == "/proj"
    assert ident["title"] == "test this whole repo and features"
    assert ident["last_active"] is not None


def test_session_identity_title_from_content_blocks_truncated(tmp_path):
    long = "fix the thing " * 20
    transcript = tmp_path / "t.jsonl"
    _write_transcript(transcript, [
        _user([{"type": "tool_result", "content": "ignored"}]),           # no text -> skipped
        _user([{"type": "text", "text": long}]),
    ])
    _write_jsonl(tmp_path / "s1.jsonl", [
        {"cwd": "/proj", "transcript_path": str(transcript)}])
    title = store.session_identity("s1", tmp_path)["title"]
    assert title.endswith("…") and len(title) == 60
    assert "\n" not in title


def test_session_identity_missing_transcript(tmp_path):
    _write_jsonl(tmp_path / "s1.jsonl", [
        {"cwd": "/proj", "transcript_path": str(tmp_path / "nope.jsonl")}])
    ident = store.session_identity("s1", tmp_path)
    assert ident["project"] == "/proj"
    assert ident["title"] == ""


def test_session_identity_from_gz(tmp_path):
    _write_jsonl_gz(tmp_path / "s1.jsonl.gz", [{"cwd": "/proj"}])
    ident = store.session_identity("s1", tmp_path)
    assert ident["project"] == "/proj"
    assert ident["last_active"] is not None


def test_session_identity_missing_session_degrades(tmp_path):
    ident = store.session_identity("nope", tmp_path)
    assert ident == {"project": "", "title": "", "last_active": None}
    # None / empty session id must not raise either
    assert store.session_identity("", tmp_path)["project"] == ""


def test_session_identity_skips_events_without_cwd(tmp_path):
    _write_jsonl(tmp_path / "s1.jsonl", [
        {"event": "SubagentStop", "session_id": "s1"},      # no cwd
        {"event": "PostToolUse", "session_id": "s1", "cwd": "/proj"}])
    assert store.session_identity("s1", tmp_path)["project"] == "/proj"
