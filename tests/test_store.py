# tests/test_store.py
import gzip
import hashlib
import json
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
    import os, time
    old = time.time() - 100
    os.utime(tmp_path / "old.jsonl", (old, old))
    assert store.latest_session(tmp_path) == "new"


def test_list_sessions_dedups_both_extensions(tmp_path):
    _write_jsonl(tmp_path / "a.jsonl", [{"i": 1}])
    _write_jsonl_gz(tmp_path / "b.jsonl.gz", [{"i": 2}])
    (tmp_path / "a.jsonl.gz").write_bytes(gzip.compress(b'{"i": 3}\n'))
    assert store.list_sessions(tmp_path) == ["a", "b"]
