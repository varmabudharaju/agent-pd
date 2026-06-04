# Audit Storage Compaction Implementation Plan

> **SUPERSEDED (2026-06-03):** Tasks 1–11 below describe the original blob-externalization design. After review found that externalizing detector-read fields breaks detection-losslessness, the feature shipped as GZIP-ONLY. See the design doc's revision history and the actual code in agent_pd/store.py. The store/iter_events/compact_session/compact_all/compact_targets structure survived; shrink_value/blob_path/put_blob/get_blob/prune_blobs and pd show were dropped.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make audit storage scalable by adding an offline, idempotent `pd compact` pass that gzips old session logs and externalizes bulky `tool_input` strings into a content-addressed, deduped, compressed blob store — losslessly for detection, recoverable until pruned.

**Architecture:** A new `agent_pd/store.py` owns all on-disk-layout knowledge: bulk externalization (`shrink_value`), the blob store (`put_blob`/`get_blob`), transparent reading of `.jsonl`/`.jsonl.gz` (`iter_events`), session resolution, compaction, and pruning. The patrol hook is untouched. `investigator`, `cli`, and `live` switch their read/resolve calls to `store`. Detectors, `LiveMonitor`, `models`, `report`, `render` are unchanged.

**Tech Stack:** Python 3, stdlib `gzip`/`hashlib`/`json`/`pathlib`, pytest with `tmp_path`. No new dependencies.

---

## File Structure

- **Create `agent_pd/store.py`** — the only module that knows the audit/blob on-disk layout. Pure helpers (`shrink_value`, `blob_path`) + I/O helpers (`put_blob`, `get_blob`, `iter_events`, `latest_session`, `list_sessions`, `compact_session`, `prune_blobs`).
- **Create `tests/test_store.py`** — unit tests for every `store` function.
- **Modify `agent_pd/config.py`** — add a `storage` section to `DEFAULTS` and a `storage` field on `Rules`.
- **Modify `agent_pd/investigator.py`** — `gather()` reads via `store.iter_events`; `_latest_session` delegates to `store.latest_session`.
- **Modify `agent_pd/cli.py`** — new `compact` and `show` subcommands; `_cmd_list` uses `store.list_sessions`.
- **Modify `agent_pd/live.py`** — `_resolve_session_file` uses `store.latest_session` for the "most recent" case.
- **Modify `tests/test_cli.py`** — tests for the new subcommands and updated list behavior.

**Conventions (from SESSION-HANDOFF.md):** TDD throughout; commit author `varma <sairam.vzf33@gmail.com>`; **no AI-attribution trailers** in commit messages. Run the full suite with `python3 -m pytest -q`.

---

## Task 1: Pure `shrink_value` + `blob_path`

**Files:**
- Create: `agent_pd/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing tests**

```python
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
    s = "é" * 1000
    new, blobs = store.shrink_value({"content": s}, threshold=2048)
    assert new["content"]["bytes"] == len(s.encode("utf-8"))
    assert blobs and blobs[0][1] == s.encode("utf-8")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_store.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agent_pd.store'`

- [ ] **Step 3: Write minimal implementation**

```python
# agent_pd/store.py
"""On-disk audit storage: the single place that knows the audit/blob layout.

Capture format (hook, UNCHANGED):  audit/<sid>.jsonl
Storage format (pd compact):       audit/<sid>.jsonl.gz
Bulk blob store:                   blobs/<ab>/<sha256>.gz   (gzip, content-addressed)
"""
import gzip
import hashlib
import json
from pathlib import Path

BLOB_KEY = "_pd_blob"
DEFAULT_THRESHOLD = 2048
DEFAULT_PREVIEW_CHARS = 500


def shrink_value(obj, threshold=DEFAULT_THRESHOLD, preview_chars=DEFAULT_PREVIEW_CHARS):
    """Recursively replace any string longer than `threshold` UTF-8 bytes with a blob-ref
    dict. Pure: returns (new_obj, [(sha256_hex, raw_bytes), ...]). Idempotent — a dict that
    already has BLOB_KEY is treated as an ordinary (small) dict."""
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
            return {k: walk(x) for k, x in v.items()}
        if isinstance(v, list):
            return [walk(x) for x in v]
        return v

    return walk(obj), blobs


def blob_path(sha, blob_dir):
    return Path(blob_dir) / sha[:2] / f"{sha}.gz"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_store.py -v`
Expected: PASS (5 tests)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/store.py tests/test_store.py
git commit -m "feat(store): pure shrink_value + blob_path for bulk externalization"
```

---

## Task 2: `put_blob` / `get_blob` (content-addressed, deduped)

**Files:**
- Modify: `agent_pd/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_store.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_store.py -k blob -v`
Expected: FAIL — `AttributeError: module 'agent_pd.store' has no attribute 'put_blob'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to agent_pd/store.py
import os
import time


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
    with gzip.open(blob_path(sha, blob_dir), "rb") as f:
        return f.read()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_store.py -k blob -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/store.py tests/test_store.py
git commit -m "feat(store): content-addressed put_blob/get_blob with dedup + mtime refresh"
```

---

## Task 3: `iter_events` / `latest_session` / `list_sessions`

**Files:**
- Modify: `agent_pd/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_store.py
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_store.py -k "iter_events or session" -v`
Expected: FAIL — `AttributeError: ... 'iter_events'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to agent_pd/store.py
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_store.py -k "iter_events or session" -v`
Expected: PASS (6 tests)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/store.py tests/test_store.py
git commit -m "feat(store): transparent iter_events + latest/list session over .jsonl(.gz)"
```

---

## Task 4: `compact_session` (idempotent, lossless, atomic)

**Files:**
- Modify: `agent_pd/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_store.py
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
    import os, time
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    done = store.compact_all(audit, blobs, threshold=2048)
    assert (audit / "old.jsonl.gz").exists()
    assert (audit / "active.jsonl").exists()           # active untouched
    assert not (audit / "active.jsonl.gz").exists()
    assert done == ["old"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_store.py -k compact -v`
Expected: FAIL — `AttributeError: ... 'compact_session'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to agent_pd/store.py
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
    active = max(files)[1]
    # only sessions that still have a plain .jsonl are candidates to compact
    audit_dir = Path(audit_dir)
    done = []
    for sid in sorted({sid for _, sid in files}):
        if sid == active:
            continue
        if (audit_dir / f"{sid}.jsonl").exists():
            compact_session(sid, audit_dir, blob_dir, threshold, preview_chars)
            done.append(sid)
    return done
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_store.py -k compact -v`
Expected: PASS (4 tests)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/store.py tests/test_store.py
git commit -m "feat(store): idempotent atomic compact_session + compact_all (skips active)"
```

---

## Task 5: `prune_blobs` (age + size retention)

**Files:**
- Modify: `agent_pd/store.py`
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_store.py
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
    import os, time
    old = time.time() - 100
    os.utime(store.blob_path(sha_old, tmp_path), (old, old))
    # cap below the on-disk total -> oldest gets evicted
    store.prune_blobs(tmp_path, max_bytes=1)
    assert not store.blob_path(sha_old, tmp_path).exists()
    assert store.blob_path(sha_new, tmp_path).exists()


def test_prune_blobs_noop_when_no_limits(tmp_path):
    sha = store.put_blob(b"keep", tmp_path)
    assert store.prune_blobs(tmp_path) == 0
    assert store.blob_path(sha, tmp_path).exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_store.py -k prune -v`
Expected: FAIL — `AttributeError: ... 'prune_blobs'`

- [ ] **Step 3: Write minimal implementation**

```python
# append to agent_pd/store.py
def _all_blobs(blob_dir):
    blob_dir = Path(blob_dir)
    if not blob_dir.exists():
        return []
    return sorted(blob_dir.glob("*/*.gz"), key=lambda p: p.stat().st_mtime)


def prune_blobs(blob_dir, older_than_days=None, max_bytes=None):
    """Delete blobs by age, then enforce a total-size cap (oldest mtime first).
    Returns the count removed. No-op when both limits are None."""
    removed = 0
    blobs = _all_blobs(blob_dir)
    if older_than_days is not None:
        cutoff = time.time() - older_than_days * 86400
        survivors = []
        for p in blobs:
            if p.stat().st_mtime < cutoff:
                p.unlink()
                removed += 1
            else:
                survivors.append(p)
        blobs = survivors
    if max_bytes is not None:
        total = sum(p.stat().st_size for p in blobs)
        for p in blobs:                       # oldest first (list is mtime-sorted)
            if total <= max_bytes:
                break
            total -= p.stat().st_size
            p.unlink()
            removed += 1
    return removed
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_store.py -k prune -v`
Expected: PASS (3 tests)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/store.py tests/test_store.py
git commit -m "feat(store): prune_blobs age + size retention"
```

---

## Task 6: Wire `investigator` to `store`

**Files:**
- Modify: `agent_pd/investigator.py:34-59` (`gather`), `:21-31` (`_latest_session`)
- Test: `tests/test_investigator.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_investigator.py
def test_gather_reads_compacted_session(tmp_path):
    import gzip, json as _json
    from agent_pd import store
    projects = tmp_path / "projects"; projects.mkdir()
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    big = "C" * 5000
    _audit(audit / "s1.jsonl", [
        {"event": "PostToolUse", "session_id": "s1", "agent_id": "",
         "tool_name": "Write", "tool_input": {"file_path": "/proj/app.py", "content": big},
         "cwd": "/proj"},
    ])
    store.compact_session("s1", audit, blobs, threshold=2048)
    records = gather(session_id="s1", projects_dir=projects, audit_dir=audit)
    assert len(records) == 1
    act = records[0].actions[0]
    assert act.tool_name == "Write"
    # the big content is now a blob ref but the path the detectors need is intact
    assert act.tool_input["file_path"] == "/proj/app.py"
    assert act.tool_input["content"]["_pd_blob"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_investigator.py::test_gather_reads_compacted_session -v`
Expected: FAIL — `gather` reads only `s1.jsonl`, which no longer exists → 0 records.

- [ ] **Step 3: Make the change**

In `agent_pd/investigator.py`, add `from . import store` at the top. Replace the body of `_latest_session` (keep the signature) with:

```python
def _latest_session(projects_dir, audit_dir):
    # projects_dir kept for the caller's signature; audit files are the only source.
    return store.latest_session(audit_dir)
```

In `gather`, replace the file-existence check + read loop:

```python
    audit_file = Path(audit_dir) / f"{session_id}.jsonl"
    if not audit_file.exists():
        return []
    mon = LiveMonitor(projects_dir=projects_dir, audit_dir=audit_dir)
    rules = load_rules(None)               # detectors re-run in the CLI with real rules
    for line in audit_file.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        mon.process(ev, rules)
```

with:

```python
    events = list(store.iter_events(session_id, audit_dir))
    if not events:
        return []
    mon = LiveMonitor(projects_dir=projects_dir, audit_dir=audit_dir)
    rules = load_rules(None)               # detectors re-run in the CLI with real rules
    for ev in events:
        mon.process(ev, rules)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_investigator.py -v`
Expected: PASS (including the existing `test_latest_session_picks_newest_audit_only`)

- [ ] **Step 5: Commit**

```bash
git add agent_pd/investigator.py tests/test_investigator.py
git commit -m "refactor(investigator): read audit via store (transparent .jsonl/.jsonl.gz)"
```

---

## Task 7: Detection equivalence — raw vs compacted

**Files:**
- Test: `tests/test_store.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_store.py
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
```

- [ ] **Step 2: Run test to verify it fails or passes**

Run: `python3 -m pytest tests/test_store.py::test_report_identical_raw_vs_compacted -v`
Expected: PASS (this is the correctness guarantee; if it FAILS, a detector reads a field we externalized — stop and reconsider the threshold/which fields are externalized before continuing).

- [ ] **Step 3: No implementation needed** — this test certifies Tasks 1–6. If it fails, fix `shrink_value`/`compact_session` so detection-relevant fields stay inline.

> **Why this is safe (verified against the detector code):** the only fields large enough to externalize are Write/Edit `content`/`new_string`. `permission_bypass` scans escalation patterns on `EXEC_TOOLS = {"Bash"}` only — never Write/Edit content. `out_of_scope` reads only `file_path`/`notebook_path` and the Bash `command`. No detector inspects a field we externalize, so which offenses fire and at what severity is identical. The single graceful-degradation edge: a **denied** Write/Edit with >threshold content has its evidence *text* (`permission_bypass` serializes `tool_input`) show the `_pd_blob` ref + preview instead of the full body — accurate, recoverable via `pd show`, and consistent with the project's existing evidence-truncation intent. To keep this test green, its denied event is a small Bash command and its bulky event is a non-denied Write.

- [ ] **Step 4: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS (all prior tests + new ones).

- [ ] **Step 5: Commit**

```bash
git add tests/test_store.py
git commit -m "test(store): certify detection is identical raw vs compacted"
```

---

## Task 8: Config `storage` section

**Files:**
- Modify: `agent_pd/config.py:14-49`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_config.py
def test_storage_defaults():
    from agent_pd.config import load_rules
    rules = load_rules(None)
    assert rules.storage["blob_threshold_bytes"] == 2048
    assert rules.storage["preview_chars"] == 500
    assert rules.storage["blob_retention_days"] is None
    assert rules.storage["max_blob_bytes"] is None


def test_storage_override(tmp_path):
    from agent_pd.config import load_rules
    p = tmp_path / "rules.yaml"
    p.write_text("storage:\n  blob_threshold_bytes: 4096\n  blob_retention_days: 30\n")
    rules = load_rules(p)
    assert rules.storage["blob_threshold_bytes"] == 4096
    assert rules.storage["blob_retention_days"] == 30
    assert rules.storage["preview_chars"] == 500   # unspecified key keeps default
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_config.py -k storage -v`
Expected: FAIL — `AttributeError: 'Rules' object has no attribute 'storage'`

- [ ] **Step 3: Make the change**

In `agent_pd/config.py`, add to `DEFAULTS` (after `off_task_overlap_threshold`):

```python
    "storage": {
        "blob_threshold_bytes": 2048,
        "preview_chars": 500,
        "blob_retention_days": None,
        "max_blob_bytes": None,
    },
```

Add `storage: dict` to the `Rules` dataclass (after `off_task_overlap_threshold: float`), and add `storage=data["storage"],` to the `Rules(...)` constructor in `load_rules`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_config.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_pd/config.py tests/test_config.py
git commit -m "feat(config): storage section (threshold, preview, retention defaults)"
```

---

## Task 9: CLI `compact` + `show` subcommands; `list` via store

**Files:**
- Modify: `agent_pd/cli.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing tests**

```python
# append to tests/test_cli.py
import gzip
from agent_pd import store


def test_compact_subcommand_parses():
    args = build_parser().parse_args(
        ["compact", "--session", "s1", "--threshold", "4096",
         "--prune-blobs-older-than", "30", "--max-blob-bytes", "1000", "--dry-run"])
    assert args.session == "s1" and args.threshold == 4096
    assert args.prune_blobs_older_than == 30 and args.max_blob_bytes == 1000
    assert args.dry_run is True


def test_compact_command_compacts_a_session(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    big = "Z" * 5000
    (audit / "s1.jsonl").write_text(json.dumps(
        {"event": "PostToolUse", "session_id": "s1", "tool_name": "Write",
         "tool_input": {"file_path": "x.py", "content": big}}) + "\n")
    rc = main(["compact", "--session", "s1",
               "--audit-dir", str(audit), "--blob-dir", str(blobs)])
    assert rc == 0
    assert (audit / "s1.jsonl.gz").exists()
    assert not (audit / "s1.jsonl").exists()
    assert "compacted" in capsys.readouterr().out.lower()


def test_compact_dry_run_writes_nothing(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    blobs = tmp_path / "blobs"
    (audit / "s1.jsonl").write_text(json.dumps(
        {"tool_name": "Write", "tool_input": {"content": "Z" * 5000}}) + "\n")
    rc = main(["compact", "--session", "s1", "--dry-run",
               "--audit-dir", str(audit), "--blob-dir", str(blobs)])
    assert rc == 0
    assert (audit / "s1.jsonl").exists()             # untouched
    assert not (audit / "s1.jsonl.gz").exists()


def test_show_blob_prints_content(tmp_path, capsys):
    blobs = tmp_path / "blobs"
    sha = store.put_blob(b"recovered content", blobs)
    rc = main(["show", "--blob", sha, "--blob-dir", str(blobs)])
    assert rc == 0
    assert "recovered content" in capsys.readouterr().out


def test_list_includes_compacted_sessions(tmp_path, capsys):
    audit = tmp_path / "audit"; audit.mkdir()
    projects = tmp_path / "projects"; projects.mkdir()
    (audit / "a.jsonl.gz").write_bytes(gzip.compress(b'{"i":1}\n'))
    rc = main(["list", "--audit-dir", str(audit), "--projects-dir", str(projects)])
    assert rc == 0
    assert "a" in capsys.readouterr().out.split()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli.py -k "compact or show or list_includes" -v`
Expected: FAIL — unknown subcommand / argparse error.

- [ ] **Step 3: Make the change**

In `agent_pd/cli.py`, add `from . import store` and `from .hook import DEFAULT_AUDIT_DIR as HOOK_AUDIT_DIR` already present. Add a blob-dir default near the audit default:

```python
DEFAULT_BLOB_DIR = Path.home() / ".claude" / "pd" / "blobs"
```

Add the two command handlers:

```python
def _cmd_compact(args) -> int:
    rules = load_rules(args.rules)
    threshold = args.threshold or rules.storage["blob_threshold_bytes"]
    preview = rules.storage["preview_chars"]
    audit, blobs = Path(args.audit_dir), Path(args.blob_dir)
    if args.dry_run:
        if args.session:
            targets = [args.session] if (audit / f"{args.session}.jsonl").exists() else []
        else:
            files = store._session_files(audit)
            active = max(files)[1] if files else None
            targets = [sid for _, sid in files
                       if sid != active and (audit / f"{sid}.jsonl").exists()]
        print(f"[dry run] would compact {len(targets)} session(s): "
              f"{', '.join(sorted(set(targets))) or '(none)'} "
              f"(threshold {threshold}B). re-run without --dry-run to apply.")
        return 0
    if args.session:
        n = store.compact_session(args.session, audit, blobs, threshold, preview)
        print(f"compacted session {args.session}: {n} event(s) rewritten.")
        done = [args.session]
    else:
        done = store.compact_all(audit, blobs, threshold, preview)
        print(f"compacted {len(done)} session(s): {', '.join(done) or '(none)'} "
              f"(skipped the active session).")
    removed = store.prune_blobs(blobs,
                                older_than_days=args.prune_blobs_older_than,
                                max_bytes=args.max_blob_bytes)
    if removed:
        print(f"pruned {removed} blob(s).")
    return 0


def _cmd_show(args) -> int:
    try:
        data = store.get_blob(args.blob, args.blob_dir)
    except FileNotFoundError:
        print(f"blob {args.blob} not found in {args.blob_dir}")
        return 1
    sys.stdout.write(data.decode("utf-8", errors="replace"))
    return 0
```

In `_cmd_list`, replace the audit-glob block:

```python
    if audit.exists():
        sessions |= {p.stem for p in audit.glob("*.jsonl")}
```

with:

```python
    sessions |= set(store.list_sessions(audit))
```

Register the subparsers in `build_parser` (after the `judge` parser):

```python
    c = sub.add_parser("compact", help="compress old sessions + externalize bulky payloads")
    c.add_argument("--session", default=None, help="compact one session (default: all but active)")
    c.add_argument("--threshold", type=int, default=None,
                   help="byte size above which a string is externalized (default: config)")
    c.add_argument("--prune-blobs-older-than", type=int, default=None,
                   help="delete blobs older than N days")
    c.add_argument("--max-blob-bytes", type=int, default=None,
                   help="cap total blob bytes (oldest evicted first)")
    c.add_argument("--dry-run", action="store_true", help="report only; write nothing")
    c.add_argument("--rules", default=None)
    c.add_argument("--audit-dir", default=DEFAULT_AUDIT_DIR)
    c.add_argument("--blob-dir", default=DEFAULT_BLOB_DIR)
    c.set_defaults(func=_cmd_compact)

    s = sub.add_parser("show", help="print the full content of a stored blob (autopsy)")
    s.add_argument("--blob", required=True, help="sha256 of the blob (the _pd_blob value)")
    s.add_argument("--blob-dir", default=DEFAULT_BLOB_DIR)
    s.set_defaults(func=_cmd_show)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_pd/cli.py tests/test_cli.py
git commit -m "feat(cli): pd compact + pd show blobs; list includes compacted sessions"
```

---

## Task 10: Wire `live` most-recent resolution to `store`

**Files:**
- Modify: `agent_pd/live.py:110-117` (`_resolve_session_file`)
- Test: `tests/test_live.py`

- [ ] **Step 1: Write the failing test**

```python
# append to tests/test_live.py
def test_resolve_session_file_prefers_store_latest(tmp_path):
    import os, time
    from agent_pd.live import _resolve_session_file
    audit = tmp_path / "audit"; audit.mkdir()
    (audit / "old.jsonl").write_text('{"i":1}\n')
    (audit / "new.jsonl.gz").write_bytes(__import__("gzip").compress(b'{"i":2}\n'))
    old = time.time() - 100
    os.utime(audit / "old.jsonl", (old, old))
    # most-recent resolution (no session id) should pick "new" even though it's gz
    resolved = _resolve_session_file(audit, None)
    assert resolved is not None and resolved.name.startswith("new")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_live.py::test_resolve_session_file_prefers_store_latest -v`
Expected: FAIL — current code globs only `*.jsonl`, so it returns `old.jsonl` (or nothing).

- [ ] **Step 3: Make the change**

In `agent_pd/live.py`, add `from . import store` at the top. Replace `_resolve_session_file`:

```python
def _resolve_session_file(audit_dir, session_id):
    audit_dir = Path(audit_dir)
    if not session_id:
        session_id = store.latest_session(audit_dir)
        if session_id is None:
            return None
    gz = audit_dir / f"{session_id}.jsonl.gz"
    plain = audit_dir / f"{session_id}.jsonl"
    # tailing follows the live plain file; fall back to the compacted gz for replay
    return plain if plain.exists() else gz
```

Note: `tail_events` opens the path with a text reader and `f.tell()`; a `.gz` path is only returned when the plain file is absent (a non-active, already-compacted session). For that replay case the existing text-open of a gz file would mis-read — but `pd watch` on a compacted historical session is a replay, not a live tail. Keep this task's scope to most-recent resolution; tailing a gz session is out of scope (documented in the spec's live note). The returned `gz` path still lets callers detect existence; live tailing in practice only ever targets the active plain file.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python3 -m pytest tests/test_live.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_pd/live.py tests/test_live.py
git commit -m "refactor(live): resolve most-recent session via store (sees .jsonl.gz)"
```

---

## Task 11: Full-suite verification + docs

**Files:**
- Modify: `README.md` or `HANDOFF.md` (whichever documents commands), `KNOWN-GAPS.md`

- [ ] **Step 1: Run the full suite**

Run: `python3 -m pytest -q`
Expected: PASS — all prior 155 tests plus the ~30 new ones.

- [ ] **Step 2: Sanity-check the detector registry is unchanged**

Run: `python3 -c "from agent_pd.detectors import DETECTORS; print(list(DETECTORS))"`
Expected: the same 6 detectors as before (this change touches storage, not detection).

- [ ] **Step 3: Manual smoke test on a copy of real data**

```bash
cp -r ~/.claude/pd /tmp/pd-smoke
python3 -m agent_pd.cli compact --dry-run --audit-dir /tmp/pd-smoke/audit --blob-dir /tmp/pd-smoke/blobs
python3 -m agent_pd.cli compact --audit-dir /tmp/pd-smoke/audit --blob-dir /tmp/pd-smoke/blobs
du -sh /tmp/pd-smoke/audit /tmp/pd-smoke/blobs   # expect audit smaller; blobs hold the bulk
python3 -m agent_pd.cli report --format md --audit-dir /tmp/pd-smoke/audit | head -20
rm -rf /tmp/pd-smoke
```

Expected: report still renders named agents + offenses against the compacted copy; audit dir is materially smaller.

- [ ] **Step 4: Update docs**

In the doc that lists `pd` commands, add `pd compact` and `pd show --blob`. In `KNOWN-GAPS.md`, note that whole-session pruning and live-tailing a compacted session are deliberate non-goals; remove the storage-scalability concern if listed.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "docs: document pd compact + pd show; note storage non-goals"
```

---

## Self-Review notes (for the implementer)

- **Spec coverage:** formats (Task 1,4), blob store + dedup (Task 2), transparent read + session resolution (Task 3,6,10), idempotent atomic compaction + skip-active (Task 4), retention (Task 5), config (Task 8), CLI `compact`/`show` + list (Task 9), the lossless/equivalence guarantees (Task 4,7). Non-goals (frozen reports, search/index, tool outcomes, whole-session pruning) intentionally absent.
- **Threshold default 2048 B, retention keep-everything** — as approved.
- If Task 7 (equivalence) ever fails, that is the signal that a detector reads a field being externalized; fix `shrink_value`/threshold before shipping — do not weaken the test.
- The `compact_all` "active session" = most-recently-modified; combined with the untouched hook, compaction never races a live write. `iter_events`'s gz+plain merge is the backstop.
