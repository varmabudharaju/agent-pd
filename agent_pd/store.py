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


def _parse_lines(text):
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def iter_events(session_id, audit_dir):
    """Yield parsed events for a session, reading <sid>.jsonl.gz if present, else
    <sid>.jsonl. If BOTH exist (compaction/append race), yield gz events first then the
    plain-text lines. Blank/partial lines are skipped."""
    # Reads each file fully into memory: intended for offline report/compaction, not
    # live tailing (live.py has its own incremental tail reader).
    audit_dir = Path(audit_dir)
    gz = audit_dir / f"{session_id}.jsonl.gz"
    plain = audit_dir / f"{session_id}.jsonl"
    if gz.exists():
        with gzip.open(gz, "rt", encoding="utf-8") as f:
            yield from _parse_lines(f.read())
    if plain.exists():
        yield from _parse_lines(plain.read_text(encoding="utf-8"))


def _session_files(audit_dir):
    audit_dir = Path(audit_dir)
    if not audit_dir.exists():
        return []
    out = []
    for p in audit_dir.glob("*.jsonl"):
        out.append((p.stat().st_mtime, p.stem))
    for p in audit_dir.glob("*.jsonl.gz"):
        out.append((p.stat().st_mtime, p.name[: -len(".jsonl.gz")]))
    return out


def latest_session(audit_dir):
    files = _session_files(audit_dir)
    return max(files)[1] if files else None


def list_sessions(audit_dir):
    return sorted({sid for _, sid in _session_files(audit_dir)})


def compact_session(session_id, audit_dir, blob_dir,
                    threshold=DEFAULT_THRESHOLD, preview_chars=DEFAULT_PREVIEW_CHARS):
    """Rewrite a session into <sid>.jsonl.gz, externalizing oversized tool_input strings
    into the blob store. Idempotent and atomic. Returns the number of events rewritten."""
    audit_dir = Path(audit_dir)
    events = list(iter_events(session_id, audit_dir))
    out_lines = []
    for ev in events:
        if "tool_input" in ev:
            new_input, blobs = shrink_value(ev["tool_input"], threshold, preview_chars)
            for sha, raw in blobs:
                put_blob(raw, blob_dir)
            ev = {**ev, "tool_input": new_input}
        out_lines.append(json.dumps(ev))
    gz = audit_dir / f"{session_id}.jsonl.gz"
    tmp = audit_dir / f"{session_id}.jsonl.gz.tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        f.write("\n".join(out_lines) + ("\n" if out_lines else ""))
    tmp.replace(gz)
    plain = audit_dir / f"{session_id}.jsonl"
    if plain.exists():
        plain.unlink()
    return len(events)


def compact_all(audit_dir, blob_dir, threshold=DEFAULT_THRESHOLD,
                preview_chars=DEFAULT_PREVIEW_CHARS):
    """Compact every session EXCEPT the most-recently-modified (likely-active) one.
    Returns the list of session ids compacted, in stable order."""
    files = _session_files(audit_dir)
    if not files:
        return []
    # Heuristic: the most-recently-modified session file is the one likely still being
    # appended to (the live session), so we never compact it. For an offline single-user
    # tool this is safe; the iter_events gz+plain merge is the backstop if it ever races.
    active = max(files)[1]
    audit_dir = Path(audit_dir)
    done = []
    for sid in sorted({sid for _, sid in files}):
        if sid == active:
            continue
        if (audit_dir / f"{sid}.jsonl").exists():
            compact_session(sid, audit_dir, blob_dir, threshold, preview_chars)
            done.append(sid)
    return done
