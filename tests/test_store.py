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
