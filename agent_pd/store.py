# agent_pd/store.py
"""On-disk audit storage: the single place that knows the audit layout.

Capture format (hook, UNCHANGED):  audit/<sid>.jsonl
Storage format (pd compact):       audit/<sid>.jsonl.gz   (gzip; every field kept inline)

Compaction is gzip-only: it never drops or rewrites any field, so detection over a compacted
session is identical to detection over the raw session. (An earlier design externalized bulky
tool_input strings into a blob store, but those fields are detector-read, so that was not
lossless for detection — see the design doc's revision history. Gzip alone is ~5-10x on JSON
text and is the scalability win we keep.)
"""
import gzip
import json
import time
from pathlib import Path


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
    plain-text lines. Blank/partial lines are skipped.

    Reads each file fully into memory: intended for offline report/compaction, not live
    tailing (live.py has its own incremental tail reader)."""
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


def compact_targets(audit_dir):
    """Session ids that `compact_all` would compact: every session that still has a plain
    <sid>.jsonl, EXCEPT the most-recently-modified (active) one. Sorted. Pure read — writes
    nothing. Shared by compact_all and the `pd compact --dry-run` preview so they never drift."""
    files = _session_files(audit_dir)
    if not files:
        return []
    # Heuristic: the most-recently-modified session file is the one likely still being
    # appended to (the live session), so we never compact it. For an offline single-user
    # tool this is safe; the iter_events gz+plain merge is the backstop if it ever races.
    active = max(files)[1]
    audit_dir = Path(audit_dir)
    return [sid for sid in sorted({sid for _, sid in files})
            if sid != active and (audit_dir / f"{sid}.jsonl").exists()]


def compact_session(session_id, audit_dir):
    """Rewrite a session from <sid>.jsonl to <sid>.jsonl.gz (gzip-only — every field kept
    inline, nothing externalized or dropped). Idempotent and atomic. Returns the event count.
    Lossless: detection over the compacted session is identical to the raw session."""
    audit_dir = Path(audit_dir)
    events = list(iter_events(session_id, audit_dir))
    gz = audit_dir / f"{session_id}.jsonl.gz"
    tmp = audit_dir / f"{session_id}.jsonl.gz.tmp"
    with gzip.open(tmp, "wt", encoding="utf-8") as f:
        f.write("".join(json.dumps(ev) + "\n" for ev in events))
    tmp.replace(gz)
    plain = audit_dir / f"{session_id}.jsonl"
    if plain.exists():
        plain.unlink()
    return len(events)


def compact_all(audit_dir):
    """Compact every session EXCEPT the most-recently-modified (likely-active) one.
    Returns the list of session ids compacted, in sorted order."""
    targets = compact_targets(audit_dir)
    for sid in targets:
        compact_session(sid, audit_dir)
    return targets


def prune_sessions(audit_dir, older_than_days=None):
    """Delete whole compacted session logs (<sid>.jsonl.gz) whose mtime is older than
    `older_than_days`. Never touches a plain .jsonl (uncompacted/active). No-op when
    older_than_days is None. Returns the count removed. Opt-in: the default keeps everything
    for autopsy bookkeeping."""
    if older_than_days is None:
        return 0
    audit_dir = Path(audit_dir)
    if not audit_dir.exists():
        return 0
    cutoff = time.time() - older_than_days * 86400
    removed = 0
    for p in audit_dir.glob("*.jsonl.gz"):
        if p.stat().st_mtime < cutoff:
            p.unlink()
            removed += 1
    return removed
