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
    raw = b"same content"
    sha1 = store.put_blob(raw, tmp_path)
    mtime1 = store.blob_path(sha1, tmp_path).stat().st_mtime_ns
    sha2 = store.put_blob(raw, tmp_path)
    assert sha1 == sha2
    # only one file exists for this content
    assert len(list(store.blob_path(sha1, tmp_path).parent.glob("*.gz"))) == 1
    # mtime refreshed (>=) so an actively re-referenced blob survives age pruning
    assert store.blob_path(sha1, tmp_path).stat().st_mtime_ns >= mtime1


def test_get_blob_is_gzip_on_disk(tmp_path):
    raw = b"payload"
    sha = store.put_blob(raw, tmp_path)
    with gzip.open(store.blob_path(sha, tmp_path), "rb") as f:
        assert f.read() == raw
