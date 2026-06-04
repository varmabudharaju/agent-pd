import json

import pytest

from agent_pd import integrity
from agent_pd.integrity import (
    CHAIN_KEY,
    SEQ_KEY,
    GENESIS,
    canonical,
    chain_hash,
    next_link,
    verify_events,
)


# ---- canonical ----

def test_canonical_stable_across_key_order():
    a = {"b": 2, "a": 1, "c": 3}
    b = {"c": 3, "a": 1, "b": 2}
    assert canonical(a) == canonical(b)


def test_canonical_excludes_chain_includes_seq():
    e = {"tool": "Bash", SEQ_KEY: 5, CHAIN_KEY: "deadbeef"}
    out = canonical(e)
    assert CHAIN_KEY.encode() not in out
    assert b'"seq":5' in out
    # excluding chain means same as the dict without chain
    assert canonical(e) == canonical({"tool": "Bash", SEQ_KEY: 5})


def test_canonical_roundtrip_json_stable():
    e = {"tool": "Bash", "args": {"x": 1, "y": [1, 2, 3]}, SEQ_KEY: 1}
    again = json.loads(json.dumps(e))
    assert canonical(e) == canonical(again)


# ---- chain_hash ----

def test_chain_hash_deterministic():
    e = {"tool": "Bash", SEQ_KEY: 1}
    assert chain_hash(GENESIS, e) == chain_hash(GENESIS, e)


def test_chain_hash_keyed_differs_from_plain():
    e = {"tool": "Bash", SEQ_KEY: 1}
    plain = chain_hash(GENESIS, e)
    keyed = chain_hash(GENESIS, e, key=b"secret")
    assert plain != keyed


def test_chain_hash_different_keys_differ():
    e = {"tool": "Bash", SEQ_KEY: 1}
    assert chain_hash(GENESIS, e, key=b"k1") != chain_hash(GENESIS, e, key=b"k2")


def test_chain_hash_field_change_changes_hash():
    e1 = {"tool": "Bash", SEQ_KEY: 1}
    e2 = {"tool": "Read", SEQ_KEY: 1}
    assert chain_hash(GENESIS, e1) != chain_hash(GENESIS, e2)


def test_chain_hash_prev_change_changes_hash():
    e = {"tool": "Bash", SEQ_KEY: 1}
    assert chain_hash(GENESIS, e) != chain_hash("abc123", e)


def test_chain_hash_ignores_chain_field():
    e1 = {"tool": "Bash", SEQ_KEY: 1}
    e2 = {"tool": "Bash", SEQ_KEY: 1, CHAIN_KEY: "whatever"}
    assert chain_hash(GENESIS, e1) == chain_hash(GENESIS, e2)


# ---- next_link ----

def test_next_link_sets_seq_and_chain():
    e = {"tool": "Bash"}
    linked = next_link(GENESIS, 0, e)
    assert linked[SEQ_KEY] == 1
    assert CHAIN_KEY in linked
    assert linked[CHAIN_KEY] == chain_hash(GENESIS, {"tool": "Bash", SEQ_KEY: 1})


def test_next_link_does_not_mutate_input():
    e = {"tool": "Bash"}
    next_link(GENESIS, 0, e)
    assert e == {"tool": "Bash"}
    assert SEQ_KEY not in e and CHAIN_KEY not in e


def test_next_link_increments_seq():
    linked = next_link("prevhex", 4, {"tool": "Read"})
    assert linked[SEQ_KEY] == 5


def test_next_link_drops_stale_chain():
    e = {"tool": "Bash", CHAIN_KEY: "stale"}
    linked = next_link(GENESIS, 0, e)
    expected = chain_hash(GENESIS, {"tool": "Bash", SEQ_KEY: 1})
    assert linked[CHAIN_KEY] == expected


def _build_chain(events, key=None):
    out = []
    prev_hex = GENESIS
    prev_seq = 0
    for e in events:
        linked = next_link(prev_hex, prev_seq, e, key)
        out.append(linked)
        prev_hex = linked[CHAIN_KEY]
        prev_seq = linked[SEQ_KEY]
    return out


# ---- verify_events ----

def test_verify_valid_chain_of_three():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}, {"tool": "C"}])
    res = verify_events(chain)
    assert res["ok"] is True
    assert res["verified"] == 3
    assert res["legacy"] == 0
    assert res["broken_at"] is None
    assert res["reason"] == ""
    assert [e[SEQ_KEY] for e in chain] == [1, 2, 3]


def test_verify_tamper_field_bad_link():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}, {"tool": "C"}])
    chain[1]["tool"] = "TAMPERED"  # do not recompute chain
    res = verify_events(chain)
    assert res["ok"] is False
    assert res["reason"] == "bad-link"
    assert res["broken_at"] == 2


def test_verify_reorder_fails():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}, {"tool": "C"}])
    chain[1], chain[2] = chain[2], chain[1]
    res = verify_events(chain)
    assert res["ok"] is False
    assert res["reason"] in ("bad-link", "seq-gap")


def test_verify_delete_middle_seq_gap():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}, {"tool": "C"}])
    del chain[1]  # remove seq 2
    res = verify_events(chain)
    assert res["ok"] is False
    assert res["reason"] == "seq-gap"
    assert res["broken_at"] == 3


def test_verify_legacy_preamble():
    legacy = [{"tool": "old1"}, {"tool": "old2"}]
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}, {"tool": "C"}])
    res = verify_events(legacy + chain)
    assert res["ok"] is True
    assert res["legacy"] == 2
    assert res["verified"] == 3


def test_verify_unchained_after_chain():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}])
    events = [chain[0], {"tool": "intruder"}, chain[1]]
    res = verify_events(events)
    assert res["ok"] is False
    assert res["reason"] == "unchained-after-chain"
    assert res["broken_at"] == 2


# ---- keyed ----

def test_verify_keyed_roundtrip():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}], key=b"K")
    assert verify_events(chain, key=b"K")["ok"] is True


def test_verify_keyed_wrong_key_bad_link():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}], key=b"K")
    res = verify_events(chain, key=b"K2")
    assert res["ok"] is False
    assert res["reason"] == "bad-link"


def test_verify_keyed_fails_without_key():
    chain = _build_chain([{"tool": "A"}, {"tool": "B"}], key=b"K")
    res = verify_events(chain, key=None)
    assert res["ok"] is False
    assert res["reason"] == "bad-link"


def test_verify_empty_is_ok():
    res = verify_events([])
    assert res["ok"] is True
    assert res["verified"] == 0
    assert res["legacy"] == 0
