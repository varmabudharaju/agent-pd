# agent_pd/store.py
"""On-disk audit storage: the single place that knows the audit/blob layout.

Capture format (hook, UNCHANGED):  audit/<sid>.jsonl
Storage format (pd compact):       audit/<sid>.jsonl.gz
Bulk blob store:                   blobs/<ab>/<sha256>.gz   (gzip, content-addressed)
"""
import gzip
import hashlib
import json
import os
import time
from pathlib import Path

BLOB_KEY = "_pd_blob"
DEFAULT_THRESHOLD = 2048
DEFAULT_PREVIEW_CHARS = 500


def shrink_value(obj, threshold=DEFAULT_THRESHOLD, preview_chars=DEFAULT_PREVIEW_CHARS):
    """Recursively replace any string longer than `threshold` UTF-8 bytes with a blob-ref
    dict. Pure: returns (new_obj, [(sha256_hex, raw_bytes), ...]). The boundary is exclusive:
    a string of exactly `threshold` bytes stays inline. The same sha may appear more than once
    in the returned list when the same large string occurs multiple times; dedup is deferred to
    `put_blob`. Idempotent — a dict that already contains BLOB_KEY is returned unchanged
    without recursing into it, regardless of threshold/preview settings."""
    blobs = []

    def walk(v):
        if isinstance(v, str):
            raw = v.encode("utf-8")
            if len(raw) > threshold:
                sha = hashlib.sha256(raw).hexdigest()
                blobs.append((sha, raw))
                return {BLOB_KEY: sha, "bytes": len(raw), "preview": v[:preview_chars]}
            return v
        if isinstance(v, dict):
            if BLOB_KEY in v:          # already an externalized blob-ref → leave intact (idempotent)
                return v
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(obj), blobs


def blob_path(sha, blob_dir):
    """Filesystem path for a content-addressed blob (sha is a 64-char sha256 hex)."""
    return Path(blob_dir) / sha[:2] / f"{sha}.gz"


def put_blob(raw_bytes, blob_dir):
    """Write `raw_bytes` gzip'd at a content-addressed path. No-op if it already exists
    (dedup); refreshes mtime so actively-referenced blobs survive age-based pruning.
    Returns the sha256 hex."""
    sha = hashlib.sha256(raw_bytes).hexdigest()
    path = blob_path(sha, blob_dir)
    if path.exists():
        now = time.time()
        os.utime(path, (now, now))
        return sha
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".gz.tmp")
    with gzip.open(tmp, "wb") as f:
        f.write(raw_bytes)
    tmp.replace(path)
    return sha


def get_blob(sha, blob_dir):
    """Return the raw bytes stored for `sha`, decompressing on the fly.
    Raises FileNotFoundError if the sha is not in the store."""
    with gzip.open(blob_path(sha, blob_dir), "rb") as f:
        return f.read()
