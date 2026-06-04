# agent_pd/hook.py
# Patrol hook: logging-only. Reads one hook JSON object from stdin, appends a
# normalized event to ~/.claude/pd/audit/<session_id>.jsonl, ALWAYS exits 0.
# Transcript schema confirmed in spec. Hook payload field names are read defensively
# (camelCase + snake_case fallbacks) since they are not yet confirmed against a live run.
import json
import sys
from datetime import datetime
from pathlib import Path

from agent_pd import integrity
from agent_pd.integrity import CHAIN_KEY, SEQ_KEY

try:
    import fcntl  # POSIX file locking; absent on Windows.
except Exception:  # pragma: no cover - platform dependent
    fcntl = None

DEFAULT_AUDIT_DIR = Path.home() / ".claude" / "pd" / "audit"


def _first(payload, *keys, default=None):
    for k in keys:
        if k in payload and payload[k] is not None:
            return payload[k]
    return default


# Every source-payload key build_event reads (snake + camel variants). Any key NOT in
# here is preserved verbatim under event["_extra"] so the watchdog never goes blind to
# new/unknown CC fields.
_CONSUMED_KEYS = {
    "timestamp", "ts",
    "hook_event_name", "event",
    "session_id", "sessionId",
    "agent_id", "agentId",
    "agent_type", "agentType",
    "tool_name", "toolName",
    "tool_input", "toolInput",
    "permissionDecision", "decision", "permission_decision",
    "denial_reason", "reason", "permissionDecisionReason",
    "cwd",
    "tool_result", "toolResult",
    "permission_mode", "permissionMode",
    "transcript_path", "transcriptPath",
}


def build_event(payload: dict) -> dict:
    event = {
        "ts": _first(payload, "timestamp", "ts"),
        "event": _first(payload, "hook_event_name", "event", default="unknown"),
        "session_id": _first(payload, "session_id", "sessionId", default=""),
        "agent_id": _first(payload, "agent_id", "agentId", default=""),
        "agent_type": _first(payload, "agent_type", "agentType", default=""),
        "tool_name": _first(payload, "tool_name", "toolName", default=""),
        "tool_input": _first(payload, "tool_input", "toolInput", default={}),
        "decision": _first(payload, "permissionDecision", "decision",
                           "permission_decision"),
        # denial_reason is the authoritative CC field for PermissionDenied; read it first.
        "reason": _first(payload, "denial_reason", "reason", "permissionDecisionReason"),
        "cwd": _first(payload, "cwd", default=""),
        # tool_result is the OUTCOME of a PostToolUse action (stdout/error/etc).
        "tool_result": _first(payload, "tool_result", "toolResult", default=None),
        "permission_mode": _first(payload, "permission_mode", "permissionMode",
                                  default=None),
        "transcript_path": _first(payload, "transcript_path", "transcriptPath",
                                  default=""),
    }
    # The event name is authoritative: a PermissionDenied firing IS the denial, so force
    # decision=deny unconditionally — a spoofed/malformed "permissionDecision: allow"
    # must not flip it.
    if event["event"] == "PermissionDenied":
        event["decision"] = "deny"
    # Preserve any unknown fields verbatim so future CC schema changes aren't dropped.
    extra = {k: v for k, v in payload.items() if k not in _CONSUMED_KEYS}
    if extra:
        event["_extra"] = extra
    return event


def audit_path(session_id: str, audit_dir: Path = DEFAULT_AUDIT_DIR) -> Path:
    sid = session_id or "unknown-session"
    return Path(audit_dir) / f"{sid}.jsonl"


def _append_line(path: Path, obj: dict) -> None:
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(obj) + "\n")


def write_event(event: dict, audit_dir: Path = None) -> None:
    """Append a hash-chained audit event to <sid>.jsonl.

    Serialized across concurrent hook processes via an exclusive per-session flock,
    so the read-prev -> append -> update-head sequence cannot fork the chain.

    CRASH-SAFE: if anything in the chaining path fails (lock unavailable, head I/O,
    next_link, etc.) we fall back to appending the ORIGINAL, unchained event so the
    event is NEVER lost. An unchained line shows up as a verify discontinuity, which
    is the acceptable tradeoff. This function never raises.
    """
    audit_dir = Path(audit_dir if audit_dir is not None else DEFAULT_AUDIT_DIR)
    audit_dir.mkdir(parents=True, exist_ok=True)
    session_id = event.get("session_id", "")
    path = audit_path(session_id, audit_dir=audit_dir)

    sid = session_id or "unknown-session"
    lock_path = audit_dir / f"{sid}.lock"

    lock_fd = None
    # Best-effort exclusive lock. If fcntl/flock is unavailable or errors, proceed
    # WITHOUT the lock rather than dropping the event.
    try:
        if fcntl is not None:
            lock_fd = open(lock_path, "w")
            fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
    except Exception:
        lock_fd = None

    wrote = False
    try:
        prev_hex, prev_seq = integrity.read_head(session_id, audit_dir)
        # Head missing/corrupt but the log already has lines -> recover from the
        # last line so the chain continues across a deleted head file.
        if prev_seq == 0 and prev_hex == integrity.GENESIS and path.exists():
            prev_hex, prev_seq = integrity.last_link_from_file(session_id, audit_dir)

        chained = integrity.next_link(
            prev_hex, prev_seq, event, key=integrity.audit_key()
        )
        # Append exactly once. Once this line lands, the event is recorded — do NOT
        # let a later head-write failure trigger the unchained fallback (that would
        # duplicate the event AND leave a permanent unchained-after-chain tamper).
        _append_line(path, chained)
        wrote = True
        try:
            integrity.write_head(
                session_id, audit_dir, chained[SEQ_KEY], chained[CHAIN_KEY]
            )
        except Exception:
            # Benign: a lagging head is detected by verify as last_seq > head_seq
            # (the one-directional truncation check), never as a tamper.
            pass
    except Exception:
        pass
    finally:
        if lock_fd is not None:
            try:
                fcntl.flock(lock_fd.fileno(), fcntl.LOCK_UN)
            except Exception:
                pass
            try:
                lock_fd.close()
            except Exception:
                pass

    if not wrote:
        # Chaining/append failed before the line landed: never lose the event —
        # append it unchained. A discontinuity here is the acceptable tradeoff.
        try:
            _append_line(path, event)
        except Exception:
            pass


def main() -> int:
    # Crash-safe: any error is swallowed so the agent run is never affected.
    try:
        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        event = build_event(payload)
        if not event.get("ts"):   # payload timestamp is often absent; stamp arrival time
            event["ts"] = datetime.now().isoformat(timespec="seconds")
        write_event(event)
    except Exception as e:
        # stderr is not captured by CC and won't affect the run — surface for debugging.
        sys.stderr.write(f"agent-pd hook error: {e}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
