"""Tamper-evident hash-chain core for agent-pd's audit log.

Each chained audit event carries two extra fields:
  * ``seq``   - monotonic per-session integer starting at 1.
  * ``chain`` - hex hash linking the event to the previous one:
      ``chain_n = H(prev_chain_hex + canonical(event_n))``
    where ``canonical`` excludes the ``chain`` field but includes everything
    else (including ``seq``). ``H`` is sha256 by default, or HMAC-SHA256 when a
    key is provided. The genesis prev-hash for the first chained event is ``""``.

This makes the log tamper-EVIDENT: editing a line, reordering, or deleting a
middle line breaks the chain at ``pd verify`` time. It is NOT tamper-proof
against a same-user attacker who re-chains with knowledge of the scheme + key.

This module is pure: no hook/CLI wiring lives here.
"""

import hashlib
import hmac
import json
import os
from pathlib import Path

CHAIN_KEY = "chain"
SEQ_KEY = "seq"
GENESIS = ""  # prev-hash for the first chained event


def canonical(event: dict) -> bytes:
    """Deterministic bytes for hashing: the event MINUS the 'chain' field,
    serialized with sorted keys and compact separators.

    Stable across re-serialization (hook write and pd compact both round-trip
    the same dict), so the chain still verifies after compaction.
    """
    obj = {k: v for k, v in event.items() if k != CHAIN_KEY}
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def chain_hash(prev_hex: str, event: dict, key: bytes | None = None) -> str:
    """Return hex chain hash for ``event`` given the previous event's chain hex.

    sha256 by default; HMAC-SHA256 when ``key`` is provided (keyed = tamper-evident
    even against someone who knows the algorithm, IF the key stays secret).
    """
    msg = (prev_hex or "").encode("utf-8") + canonical(event)
    if key:
        return hmac.new(key, msg, hashlib.sha256).hexdigest()
    return hashlib.sha256(msg).hexdigest()


def next_link(prev_hex: str, prev_seq: int, event: dict, key: bytes | None = None) -> dict:
    """Return a NEW event dict = event + {seq: prev_seq+1, chain: <hash over event+seq>}.

    Does not mutate the input. The chain is computed over the event WITH its new seq.
    """
    e = dict(event)
    e.pop(CHAIN_KEY, None)
    e[SEQ_KEY] = (prev_seq or 0) + 1
    e[CHAIN_KEY] = chain_hash(prev_hex, e, key)
    return e


def verify_events(events, key: bytes | None = None) -> dict:
    """Verify a sequence of event dicts (in file order).

    Leading events WITHOUT a ``chain`` field are treated as legacy/pre-chain and
    skipped (counted), not failures. Once chained events begin, every subsequent
    event must: have chain+seq, seq increment by exactly 1 (starting at 1), and
    chain == recompute(prev, event). Returns::

        {"ok": bool, "verified": int, "legacy": int,
         "broken_at": int|None, "reason": str}

    ``broken_at`` is the seq (or 1-based index if seq missing) of the first
    failure; ``reason`` is one of '', 'unchained-after-chain', 'seq-gap',
    'bad-link'. Stops at the first failure.
    """
    verified = 0
    legacy = 0
    started = False
    prev_hex = GENESIS
    expected_seq = 1

    for idx, event in enumerate(events):
        if not started:
            if CHAIN_KEY not in event:
                legacy += 1
                continue
            started = True

        if CHAIN_KEY not in event or SEQ_KEY not in event:
            return {
                "ok": False,
                "verified": verified,
                "legacy": legacy,
                "broken_at": expected_seq,
                "reason": "unchained-after-chain",
            }

        if event[SEQ_KEY] != expected_seq:
            return {
                "ok": False,
                "verified": verified,
                "legacy": legacy,
                "broken_at": event.get(SEQ_KEY) or expected_seq,
                "reason": "seq-gap",
            }

        if event[CHAIN_KEY] != chain_hash(prev_hex, event, key):
            return {
                "ok": False,
                "verified": verified,
                "legacy": legacy,
                "broken_at": event[SEQ_KEY],
                "reason": "bad-link",
            }

        verified += 1
        prev_hex = event[CHAIN_KEY]
        expected_seq += 1

    return {
        "ok": True,
        "verified": verified,
        "legacy": legacy,
        "broken_at": None,
        "reason": "",
    }


# ---- head-file + key I/O helpers (pure-ish; consumed by the hook) ----
#
# The "head" of a session is the (seq, chain) of its last appended chained event,
# cached in a small sidecar file so the hook need not re-read the whole log on every
# append. last_link_from_file is the fallback when the head is missing/deleted.
#
# These sidecars (<sid>.head.json, <sid>.lock) intentionally do NOT match the
# *.jsonl / *.jsonl.gz globs in store._session_files, so they are never mistaken
# for sessions.


def head_path(session_id, audit_dir) -> Path:
    sid = session_id or "unknown-session"
    return Path(audit_dir) / f"{sid}.head.json"


def read_head(session_id, audit_dir):
    """Return (prev_hex, prev_seq) from the head file.

    On a missing or corrupt head file, return (GENESIS, 0).
    """
    hp = head_path(session_id, audit_dir)
    try:
        data = json.loads(hp.read_text(encoding="utf-8"))
        return str(data[CHAIN_KEY]), int(data[SEQ_KEY])
    except Exception:
        return GENESIS, 0


def write_head(session_id, audit_dir, seq, chain_hex) -> None:
    """Atomically write the head file (tmp + os.replace)."""
    hp = head_path(session_id, audit_dir)
    tmp = hp.with_suffix(hp.suffix + ".tmp")
    tmp.write_text(
        json.dumps({SEQ_KEY: seq, CHAIN_KEY: chain_hex}),
        encoding="utf-8",
    )
    os.replace(tmp, hp)


def last_link_from_file(session_id, audit_dir):
    """Return (prev_hex, prev_seq) from the LAST non-blank line of <sid>.jsonl.

    Used as a fallback when the head file is missing. If the file is missing, empty,
    or its last line is legacy (no chain), return (GENESIS, 0).
    """
    from agent_pd.hook import audit_path  # local import to avoid a cycle

    path = audit_path(session_id, audit_dir=audit_dir)
    try:
        last = None
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last = line
        if last is None:
            return GENESIS, 0
        ev = json.loads(last)
        if CHAIN_KEY in ev and SEQ_KEY in ev:
            return str(ev[CHAIN_KEY]), int(ev[SEQ_KEY])
        return GENESIS, 0
    except Exception:
        return GENESIS, 0


def audit_key():
    """Return the audit HMAC key bytes from PD_AUDIT_KEY, or None if unset."""
    val = os.environ.get("PD_AUDIT_KEY")
    return val.encode("utf-8") if val else None
