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
