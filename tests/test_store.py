# tests/test_store.py
import gzip
import hashlib
import json
import os
import time
from pathlib import Path

from agent_pd import store


def test_shrink_value_leaves_small_strings():
    obj = {"file_path": "x.py", "content": "small"}
    new, blobs = store.shrink_value(obj, threshold=2048)
    assert new == obj
    assert blobs == []


def test_shrink_value_externalizes_big_string():
    big = "A" * 5000
    obj = {"file_path": "x.py", "content": big}
    new, blobs = store.shrink_value(obj, threshold=2048)
    sha = hashlib.sha256(big.encode("utf-8")).hexdigest()
    assert new["file_path"] == "x.py"
    assert new["content"] == {"_pd_blob": sha, "bytes": 5000, "preview": "A" * 500}
    assert blobs == [(sha, big.encode("utf-8"))]


def test_shrink_value_recurses_into_lists_and_nested_dicts():
    big = "B" * 3000
    obj = {"edits": [{"new_string": big}], "k": {"deep": big}}
    new, blobs = store.shrink_value(obj, threshold=2048)
    sha = hashlib.sha256(big.encode("utf-8")).hexdigest()
    assert new["edits"][0]["new_string"]["_pd_blob"] == sha
    assert new["k"]["deep"]["_pd_blob"] == sha
    # same content appears twice -> two (sha, bytes) entries (dedup happens at put_blob)
    assert len(blobs) == 2


def test_shrink_value_is_idempotent_on_a_blob_ref():
    ref = {"content": {"_pd_blob": "abc", "bytes": 5000, "preview": "A"}}
    new, blobs = store.shrink_value(ref, threshold=2048)
    assert new == ref
    assert blobs == []


def test_shrink_value_measures_bytes_not_chars():
    # 1000 multibyte chars = 3000 UTF-8 bytes -> over a 2048 threshold
    s = "€" * 1000
    new, blobs = store.shrink_value({"content": s}, threshold=2048)
    assert new["content"]["bytes"] == len(s.encode("utf-8"))
    assert blobs and blobs[0][1] == s.encode("utf-8")


def test_shrink_value_idempotent_even_when_preview_exceeds_threshold():
    # A blob-ref whose preview is longer than the threshold must NOT be re-externalized.
    ref = {"content": {"_pd_blob": "deadbeef", "bytes": 9999, "preview": "P" * 100}}
    new, blobs = store.shrink_value(ref, threshold=10, preview_chars=500)
    assert new == ref          # unchanged
    assert blobs == []         # nothing externalized


def test_put_blob_roundtrip(tmp_path):
    raw = b"hello world" * 100
    sha = store.put_blob(raw, tmp_path)
    assert sha == hashlib.sha256(raw).hexdigest()
    assert store.blob_path(sha, tmp_path).exists()
    assert store.get_blob(sha, tmp_path) == raw


def test_put_blob_dedups(tmp_path):
    import os
    raw = b"same content"
    sha1 = store.put_blob(raw, tmp_path)
    # backdate the blob far into the past, then re-put the SAME content
    os.utime(store.blob_path(sha1, tmp_path), (0, 0))
    sha2 = store.put_blob(raw, tmp_path)
    assert sha1 == sha2
    # still exactly one file for this content (dedup, not a second write)
    assert len(list(store.blob_path(sha1, tmp_path).parent.glob("*.gz"))) == 1
    # mtime was refreshed forward from the backdated value (proves os.utime ran)
    assert store.blob_path(sha1, tmp_path).stat().st_mtime > 0


def test_get_blob_is_gzip_on_disk(tmp_path):
    raw = b"payload"
    sha = store.put_blob(raw, tmp_path)
    with gzip.open(store.blob_path(sha, tmp_path), "rb") as f:
        assert f.read() == raw


def _write_jsonl(path, events):
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n")


def _write_jsonl_gz(path, events):
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write("\n".join(json.dumps(e) for e in events) + "\n")


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


def _read_gz_events(path):
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def test_compact_session_externalizes_and_gzips(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    big = "Z" * 5000
    _write_jsonl(audit / "s1.jsonl", [
        {"event": "PostToolUse", "tool_name": "Write",
         "tool_input": {"file_path": "x.py", "content": big}},
    ])
    store.compact_session("s1", audit, blobs, threshold=2048)
    assert not (audit / "s1.jsonl").exists()           # original removed
    assert (audit / "s1.jsonl.gz").exists()            # gz written
    ev = _read_gz_events(audit / "s1.jsonl.gz")[0]
    ref = ev["tool_input"]["content"]
    assert ref["bytes"] == 5000 and ref["preview"] == "Z" * 500
    assert store.get_blob(ref["_pd_blob"], blobs).decode() == big   # recoverable


def test_compact_session_is_lossless_when_rehydrated(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    big = "Q" * 9000
    original = {"event": "PostToolUse", "tool_name": "Write",
               "tool_input": {"file_path": "a.py", "content": big}}
    _write_jsonl(audit / "s1.jsonl", [original])
    store.compact_session("s1", audit, blobs, threshold=2048)
    ev = _read_gz_events(audit / "s1.jsonl.gz")[0]
    ev["tool_input"]["content"] = store.get_blob(
        ev["tool_input"]["content"]["_pd_blob"], blobs).decode("utf-8")
    assert ev == original


def test_compact_session_is_idempotent(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    _write_jsonl(audit / "s1.jsonl", [
        {"tool_name": "Write", "tool_input": {"content": "W" * 5000}}])
    store.compact_session("s1", audit, blobs, threshold=2048)
    once = _read_gz_events(audit / "s1.jsonl.gz")
    # second pass reads the .gz (no plain file), must reproduce the same events
    store.compact_session("s1", audit, blobs, threshold=2048)
    twice = _read_gz_events(audit / "s1.jsonl.gz")
    assert once == twice
    assert once[0]["tool_input"]["content"]["bytes"] == 5000


def test_compact_all_skips_most_recent(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    _write_jsonl(audit / "old.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    _write_jsonl(audit / "active.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    done = store.compact_all(audit, blobs, threshold=2048)
    assert (audit / "old.jsonl.gz").exists()
    assert (audit / "active.jsonl").exists()           # active untouched
    assert not (audit / "active.jsonl.gz").exists()
    assert done == ["old"]


def test_compact_session_empty_session(tmp_path):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    (audit / "s1.jsonl").write_text("")          # session file with zero events
    n = store.compact_session("s1", audit, blobs, threshold=2048)
    assert n == 0
    assert (audit / "s1.jsonl.gz").exists()       # valid (empty) gz written
    assert not (audit / "s1.jsonl").exists()       # plain removed
    assert list(store.iter_events("s1", audit)) == []   # reads back as no events


def test_compact_all_skips_already_compacted_active(tmp_path):
    import gzip as _gz
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    # an older plain session + a newer already-compacted (gz-only) session
    _write_jsonl(audit / "old.jsonl", [{"tool_name": "Read", "tool_input": {}}])
    (audit / "active.jsonl.gz").write_bytes(_gz.compress(b'{"tool_name": "Read", "tool_input": {}}\n'))
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    done = store.compact_all(audit, blobs, threshold=2048)
    # active (gz, most recent) is skipped; old plain gets compacted; gz-only never re-compacted
    assert done == ["old"]
    assert (audit / "old.jsonl.gz").exists()


def test_prune_blobs_by_age(tmp_path):
    sha_old = store.put_blob(b"old-content", tmp_path)
    sha_new = store.put_blob(b"new-content", tmp_path)
    import os, time
    old = time.time() - 40 * 86400
    os.utime(store.blob_path(sha_old, tmp_path), (old, old))
    removed = store.prune_blobs(tmp_path, older_than_days=30)
    assert removed == 1
    assert not store.blob_path(sha_old, tmp_path).exists()
    assert store.blob_path(sha_new, tmp_path).exists()


def test_prune_blobs_by_max_bytes_removes_oldest_first(tmp_path):
    sha_old = store.put_blob(b"X" * 1000, tmp_path)
    sha_new = store.put_blob(b"Y" * 1000, tmp_path)
    old = time.time() - 100
    os.utime(store.blob_path(sha_old, tmp_path), (old, old))
    # cap = room for exactly one blob -> the older one is evicted, the newest is kept,
    # and the resulting total is at or under the cap (real cap enforcement).
    one = store.blob_path(sha_new, tmp_path).stat().st_size
    removed = store.prune_blobs(tmp_path, max_bytes=one)
    assert removed == 1
    assert not store.blob_path(sha_old, tmp_path).exists()
    assert store.blob_path(sha_new, tmp_path).exists()
    remaining = sum(p.stat().st_size for p in (tmp_path).glob("*/*.gz"))
    assert remaining <= one


def test_prune_blobs_noop_when_no_limits(tmp_path):
    sha = store.put_blob(b"keep", tmp_path)
    assert store.prune_blobs(tmp_path) == 0
    assert store.blob_path(sha, tmp_path).exists()


def test_prune_blobs_max_bytes_enforces_cap_across_many(tmp_path):
    shas = []
    for i, c in enumerate([b"A", b"B", b"C"]):
        s = store.put_blob(c * 1000, tmp_path)
        os.utime(store.blob_path(s, tmp_path), (time.time() - (100 - i), ) * 2)  # A oldest, C newest
        shas.append(s)
    one = store.blob_path(shas[-1], tmp_path).stat().st_size
    # cap of ~1.5 blobs -> must evict down to <= cap (keeps only the newest 1)
    store.prune_blobs(tmp_path, max_bytes=one + one // 2)
    remaining = sorted(p.name for p in tmp_path.glob("*/*.gz"))
    total = sum(p.stat().st_size for p in tmp_path.glob("*/*.gz"))
    assert total <= one + one // 2           # cap genuinely enforced
    assert (store.blob_path(shas[-1], tmp_path)).exists()   # newest always kept


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

    big = "D" * 9000
    events = [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Write", "tool_input": {"file_path": "/etc/passwd", "content": big},
         "cwd": "/proj"},
        {"event": "PermissionDenied", "session_id": "s1", "agent_id": "",
         "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
         "decision": "deny", "cwd": "/proj"},
    ]

    raw_audit = tmp_path / "raw"; raw_audit.mkdir()
    _write_jsonl(raw_audit / "s1.jsonl", events)
    raw_offenses = offenses_for(raw_audit)

    comp_audit = tmp_path / "comp"; comp_audit.mkdir()
    _write_jsonl(comp_audit / "s1.jsonl", events)
    store.compact_session("s1", comp_audit, tmp_path / "blobs", threshold=2048)

    assert offenses_for(comp_audit) == raw_offenses
    assert raw_offenses  # sanity: there ARE offenses to compare
