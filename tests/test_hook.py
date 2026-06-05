import json
import os

import pytest

import agent_pd.hook as hook
import agent_pd.integrity as integrity
from agent_pd.hook import build_event, write_event, audit_path, main
from agent_pd.integrity import (
    CHAIN_KEY,
    SEQ_KEY,
    GENESIS,
    verify_events,
    head_path,
    read_head,
)

def test_build_event_normalizes_fields():
    payload = {
        "hook_event_name": "PostToolUse",
        "agent_id": "a1", "agent_type": "Explore",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "session_id": "s1", "cwd": "/x", "timestamp": "2026-06-01T00:00:00Z",
    }
    ev = build_event(payload)
    assert ev["event"] == "PostToolUse"
    assert ev["agent_id"] == "a1"
    assert ev["tool_name"] == "Bash"
    assert ev["decision"] is None

def test_build_event_infers_denial_from_event_name():
    # Realistic PermissionDenied payload: NO permissionDecision/decision field.
    payload = {
        "hook_event_name": "PermissionDenied",
        "agentId": "a2", "agentType": "general-purpose",
        "tool_name": "Bash", "tool_input": {"command": "sudo rm -rf /"},
        "sessionId": "s1",
    }
    ev = build_event(payload)
    assert ev["agent_id"] == "a2"
    assert ev["event"] == "PermissionDenied"
    assert ev["decision"] == "deny"   # inferred from the event name


def test_build_event_reads_camelcase_event_name():
    # Every other field is mapped from camelCase (sessionId/toolName/...); the event
    # name must be too. A camelCase PermissionDenied must still force decision=deny and
    # not leak `hookEventName` into _extra.
    payload = {
        "hookEventName": "PermissionDenied",
        "sessionId": "s1", "toolName": "Bash", "toolInput": {"command": "rm -rf /"},
    }
    ev = build_event(payload)
    assert ev["event"] == "PermissionDenied"
    assert ev["decision"] == "deny"
    assert "hookEventName" not in (ev.get("_extra") or {})


def test_build_event_honors_explicit_decision():
    payload = {"hook_event_name": "PermissionDenied", "session_id": "s1",
               "permissionDecision": "deny", "reason": "blocked by rule"}
    ev = build_event(payload)
    assert ev["decision"] == "deny"
    assert ev["reason"] == "blocked by rule"

def test_build_event_reads_denial_reason_first():
    payload = {
        "hook_event_name": "PermissionDenied", "session_id": "s1",
        "denial_reason": "blocked by deny rule",
        "reason": "some other reason",
    }
    ev = build_event(payload)
    assert ev["reason"] == "blocked by deny rule"


def test_build_event_captures_tool_result():
    payload = {
        "hook_event_name": "PostToolUse", "session_id": "s1",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "tool_result": {"stdout": "a.txt\nb.txt", "exit_code": 0},
    }
    ev = build_event(payload)
    assert ev["tool_result"] == {"stdout": "a.txt\nb.txt", "exit_code": 0}


def test_build_event_tool_result_defaults_none():
    ev = build_event({"hook_event_name": "PostToolUse", "session_id": "s1"})
    assert ev["tool_result"] is None


def test_build_event_captures_permission_mode():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "permission_mode": "acceptEdits"}
    ev = build_event(payload)
    assert ev["permission_mode"] == "acceptEdits"


def test_build_event_captures_transcript_path():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "transcript_path": "/tmp/transcript.jsonl"}
    ev = build_event(payload)
    assert ev["transcript_path"] == "/tmp/transcript.jsonl"


def test_build_event_extra_passthrough():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "FUTURE_FIELD": "v"}
    ev = build_event(payload)
    assert ev["_extra"]["FUTURE_FIELD"] == "v"


def test_build_event_no_extra_for_known_fields_only():
    payload = {"hook_event_name": "PostToolUse", "session_id": "s1",
               "tool_name": "Bash", "tool_input": {"command": "ls"}}
    ev = build_event(payload)
    assert "_extra" not in ev


def test_build_event_force_deny_overrides_spoofed_allow():
    payload = {"hook_event_name": "PermissionDenied", "session_id": "s1",
               "permissionDecision": "allow"}
    ev = build_event(payload)
    assert ev["decision"] == "deny"


def test_gather_record_carries_tool_result_onto_action():
    from agent_pd.live import LiveMonitor
    from agent_pd.config import load_rules
    mon = LiveMonitor(projects_dir="/nonexistent", audit_dir="/nonexistent")
    event = build_event({
        "hook_event_name": "PostToolUse", "session_id": "s1", "agent_id": "a1",
        "tool_name": "Bash", "tool_input": {"command": "ls"},
        "tool_result": {"stdout": "ok"},
    })
    mon.process(event, load_rules(None))
    action = mon.records["a1"].actions[0]
    assert action.tool_result == {"stdout": "ok"}


def test_main_writes_to_stderr_on_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise RuntimeError("disk full")
    monkeypatch.setattr(hook, "write_event", boom)
    monkeypatch.setattr(hook.sys, "stdin", __import__("io").StringIO("{}"))
    rc = main()
    assert rc == 0
    captured = capsys.readouterr()
    assert "agent-pd hook error" in captured.err


def test_write_event_appends_to_session_file(tmp_path):
    ev = {"event": "PostToolUse", "session_id": "s9", "agent_id": "a1"}
    write_event(ev, audit_dir=tmp_path)
    out = audit_path("s9", audit_dir=tmp_path)
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert json.loads(lines[0])["agent_id"] == "a1"
    write_event(ev, audit_dir=tmp_path)
    assert len(out.read_text().splitlines()) == 2


# ---- hash-chain wiring ----

def _read_events(path):
    return [json.loads(l) for l in path.read_text().splitlines() if l.strip()]


def test_write_event_chains_single(tmp_path):
    write_event({"event": "PostToolUse", "session_id": "c1"}, audit_dir=tmp_path)
    out = audit_path("c1", audit_dir=tmp_path)
    evs = _read_events(out)
    assert len(evs) == 1
    assert evs[0][SEQ_KEY] == 1
    assert evs[0].get(CHAIN_KEY)
    # head file exists and matches
    hp = head_path("c1", audit_dir=tmp_path)
    assert hp.exists()
    prev_hex, prev_seq = read_head("c1", audit_dir=tmp_path)
    assert prev_seq == 1
    assert prev_hex == evs[0][CHAIN_KEY]


def test_write_event_three_sequential_verify(tmp_path):
    for i in range(3):
        write_event({"event": "PostToolUse", "session_id": "c2", "n": i},
                    audit_dir=tmp_path)
    evs = _read_events(audit_path("c2", audit_dir=tmp_path))
    assert [e[SEQ_KEY] for e in evs] == [1, 2, 3]
    res = verify_events(evs)
    assert res["ok"] is True
    assert res["verified"] == 3


def test_write_event_tamper_detected(tmp_path):
    for i in range(3):
        write_event({"event": "PostToolUse", "session_id": "c3", "n": i},
                    audit_dir=tmp_path)
    out = audit_path("c3", audit_dir=tmp_path)
    evs = _read_events(out)
    evs[1]["n"] = 999  # tamper middle, do not recompute chain
    out.write_text("\n".join(json.dumps(e) for e in evs) + "\n")
    res = verify_events(_read_events(out))
    assert res["ok"] is False
    assert res["reason"] == "bad-link"


def test_write_event_head_fallback(tmp_path):
    for i in range(3):
        write_event({"event": "PostToolUse", "session_id": "c4", "n": i},
                    audit_dir=tmp_path)
    head_path("c4", audit_dir=tmp_path).unlink()
    write_event({"event": "PostToolUse", "session_id": "c4", "n": 3},
                audit_dir=tmp_path)
    evs = _read_events(audit_path("c4", audit_dir=tmp_path))
    assert [e[SEQ_KEY] for e in evs] == [1, 2, 3, 4]
    assert verify_events(evs)["ok"] is True


def test_write_event_keyed(tmp_path, monkeypatch):
    monkeypatch.setenv("PD_AUDIT_KEY", "secret")
    for i in range(3):
        write_event({"event": "PostToolUse", "session_id": "c5", "n": i},
                    audit_dir=tmp_path)
    evs = _read_events(audit_path("c5", audit_dir=tmp_path))
    assert verify_events(evs, key=b"secret")["ok"] is True
    assert verify_events(evs, key=None)["ok"] is False


def test_write_event_crash_safe_fallback(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("chain broke")
    monkeypatch.setattr(integrity, "next_link", boom)
    # must NOT raise
    write_event({"event": "PostToolUse", "session_id": "c6", "n": 0},
                audit_dir=tmp_path)
    evs = _read_events(audit_path("c6", audit_dir=tmp_path))
    assert len(evs) == 1
    assert evs[0]["event"] == "PostToolUse"
    assert SEQ_KEY not in evs[0]  # unchained fallback


def test_write_event_head_write_failure_no_dup(tmp_path, monkeypatch):
    # If write_head raises AFTER the chained append succeeds, the event must NOT be
    # re-appended (no duplicate, no unchained tail) and the chain must stay intact —
    # only the head lags behind, which verify treats as benign.
    def boom(*a, **k):
        raise RuntimeError("head disk full")
    monkeypatch.setattr(integrity, "write_head", boom)
    for i in range(3):
        write_event({"event": "PostToolUse", "session_id": "hd", "n": i},
                    audit_dir=tmp_path)
    evs = _read_events(audit_path("hd", audit_dir=tmp_path))
    assert len(evs) == 3                      # exactly one line per call, no dups
    assert [e[SEQ_KEY] for e in evs] == [1, 2, 3]
    assert verify_events(evs)["ok"] is True   # chain intact; only the head lags


def test_main_returns_zero_on_chain_error(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("chain broke")
    monkeypatch.setattr(integrity, "next_link", boom)
    monkeypatch.setattr(hook, "DEFAULT_AUDIT_DIR", tmp_path)
    payload = json.dumps({"hook_event_name": "PostToolUse", "session_id": "c7"})
    monkeypatch.setattr(hook.sys, "stdin", __import__("io").StringIO(payload))
    assert main() == 0
    evs = _read_events(audit_path("c7", audit_dir=tmp_path))
    assert len(evs) == 1


def test_write_event_legacy_preamble(tmp_path):
    out = audit_path("c8", audit_dir=tmp_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps({"event": "PostToolUse", "session_id": "c8", "legacy": 1}) + "\n"
        + json.dumps({"event": "PostToolUse", "session_id": "c8", "legacy": 2}) + "\n"
    )
    write_event({"event": "PostToolUse", "session_id": "c8", "n": 0},
                audit_dir=tmp_path)
    evs = _read_events(out)
    assert len(evs) == 3
    assert evs[2][SEQ_KEY] == 1  # chain starts fresh after legacy preamble
    res = verify_events(evs)
    assert res["ok"] is True
    assert res["legacy"] == 2
    assert res["verified"] == 1


def test_write_event_concurrent_no_dup_seq(tmp_path):
    import threading

    N = 10
    barrier = threading.Barrier(N)

    def worker(i):
        barrier.wait()
        write_event({"event": "PostToolUse", "session_id": "c9", "n": i},
                    audit_dir=tmp_path)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(N)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    evs = _read_events(audit_path("c9", audit_dir=tmp_path))
    seqs = sorted(e[SEQ_KEY] for e in evs)
    assert seqs == list(range(1, N + 1)), seqs  # exactly 1..N, no dups/gaps
    assert verify_events(evs)["ok"] is True


def test_build_event_real_recorded_denial_shape():
    """Validated against a REAL recorded PermissionDenied (session 29f86214, 2026-06-02):
    the live Claude Code payload had NO explicit decision field and carried the reason under
    `reason` (not the doc-claimed `denial_reason`). This locks in that build_event handles the
    real shape: deny is inferred from the event name, the reason is captured, main-agent fields
    are empty, and nothing the watchdog needs lands in _extra."""
    payload = {
        "hook_event_name": "PermissionDenied",
        "session_id": "29f86214-da2a-4715-9e46-47ab92c92bb9",
        "tool_name": "Bash",
        "tool_input": {
            "command": "git push origin master",
            "description": "FF-merge master and push to origin",
        },
        "reason": ("Direct push to the default branch (master) bypasses PR review; "
                   "the user never specifically authorized pushing directly to master."),
        "cwd": "/home/dev/agent-pd",
        # NB: no permissionDecision/decision/denial_reason key — matches the observed real event.
    }
    ev = build_event(payload)
    assert ev["event"] == "PermissionDenied"
    assert ev["decision"] == "deny"          # inferred from the event name
    assert ev["reason"].startswith("Direct push to the default branch")
    assert ev["tool_name"] == "Bash"
    assert ev["tool_input"]["command"] == "git push origin master"
    assert ev["agent_id"] == "" and ev["agent_type"] == ""   # main agent
    assert ev["cwd"] == "/home/dev/agent-pd"
    assert "_extra" not in ev                 # every field in the real shape is mapped
