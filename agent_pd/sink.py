"""Off-host audit-log sink: ship chained audit events to an append-only
destination the agent cannot retroactively alter.

The threat this addresses: the hash-chain (integrity.py) makes the local log
tamper-EVIDENT, but a same-user agent can still re-chain the whole file and
forge a clean history. Forwarding each event off-host as it is appended means a
later local rewrite cannot reach the events already shipped — the off-host copy
is the witness.

This module is the pure core: config resolution, two backends (file / http),
per-session incremental forwarding state, and the push orchestration. CLI
wiring lives in a later task.

STDLIB ONLY (urllib for HTTP) — no new dependencies.

Only CHAINED events (those carrying integrity.SEQ_KEY) are forwarded. Legacy /
pre-chain events have no seq and are intentionally NOT forwarded: without a seq
we cannot dedup them idempotently, and they predate the integrity guarantee
this sink exists to protect.
"""

import json
import os
import socket
import urllib.error
import urllib.request
from pathlib import Path

from agent_pd.integrity import SEQ_KEY


# --------------------------------------------------------------------------
# config resolution
# --------------------------------------------------------------------------

_DEFAULT_TIMEOUT = 10.0


def resolve_sink_config(rules=None) -> dict:
    """Resolve sink config: base from ``rules.sink`` (a dict, if present), then
    environment overrides.

    Env vars: PD_SINK_TYPE ("file"|"http"), PD_SINK_URL, PD_SINK_PATH,
    PD_SINK_TOKEN, PD_SINK_TIMEOUT.

    The SECRET token comes ONLY from PD_SINK_TOKEN — a ``token`` key in a
    ``rules.sink`` dict is deliberately ignored so secrets never live in a
    checked-in / world-readable config file.

    Returns ``{"type", "url", "path", "token", "timeout"}``.
    """
    base = {}
    rules_sink = getattr(rules, "sink", None)
    if isinstance(rules_sink, dict):
        base = rules_sink

    def pick(env_key, base_key):
        val = os.environ.get(env_key)
        if val is not None and val != "":
            return val
        return base.get(base_key)

    timeout_raw = os.environ.get("PD_SINK_TIMEOUT")
    if timeout_raw:
        try:
            timeout = float(timeout_raw)
        except ValueError:
            timeout = _DEFAULT_TIMEOUT
    else:
        try:
            timeout = float(base.get("timeout", _DEFAULT_TIMEOUT))
        except (TypeError, ValueError):
            timeout = _DEFAULT_TIMEOUT

    return {
        "type": pick("PD_SINK_TYPE", "type"),
        "url": pick("PD_SINK_URL", "url"),
        "path": pick("PD_SINK_PATH", "path"),
        # token: env ONLY, never from the rules dict.
        "token": os.environ.get("PD_SINK_TOKEN") or None,
        "timeout": timeout,
    }


# --------------------------------------------------------------------------
# sink backends
# --------------------------------------------------------------------------

class SinkError(Exception):
    """Raised when a sink fails to durably accept events. The caller must NOT
    advance forwarding state on this error (so the events are retried)."""


class Sink:
    def send(self, events: list) -> int:
        """Append events to the off-host destination. Returns the count sent.
        Raises SinkError on failure."""
        raise NotImplementedError


def _ndjson(events) -> str:
    """Compact NDJSON: one compact json object per line."""
    return "".join(
        json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n"
        for e in events
    )


class FileSink(Sink):
    """Append each event as a compact JSON line to ``path`` (creating parent
    dirs).

    This sink only APPENDS; the append-only / immutability guarantee is the
    operator's responsibility — point ``path`` at a destination protected by
    ``chattr +a``, a WORM volume, or a write-once protected mount. Without that,
    a same-user agent could still rewrite this file; the off-host backend
    (HttpSink to a remote collector) gives a stronger guarantee.
    """

    def __init__(self, path):
        self.path = Path(path)

    def send(self, events: list) -> int:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(_ndjson(events))
        except OSError as e:
            raise SinkError(f"file sink write failed: {e}") from e
        return len(events)


class HttpSink(Sink):
    """POST events as NDJSON to a remote collector.

    Body = newline-joined compact JSON (NDJSON), Content-Type
    ``application/x-ndjson``, plus ``Authorization: Bearer <token>`` when a token
    is set. A 2xx response is success; any non-2xx, URLError, timeout, or socket
    error raises SinkError so the caller does NOT advance state and retries on
    the next push. Never hangs past ``timeout``.
    """

    def __init__(self, url, token=None, timeout: float = _DEFAULT_TIMEOUT):
        self.url = url
        self.token = token
        self.timeout = timeout

    def send(self, events: list) -> int:
        body = _ndjson(events).encode("utf-8")
        headers = {"Content-Type": "application/x-ndjson"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(
            self.url, data=body, headers=headers, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status = getattr(resp, "status", None) or resp.getcode()
                if not (200 <= status < 300):
                    raise SinkError(f"http sink status {status}")
        except urllib.error.HTTPError as e:
            # non-2xx that urllib raises as an error (4xx/5xx)
            raise SinkError(f"http sink status {e.code}") from e
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise SinkError(f"http sink transport error: {e}") from e
        return len(events)


def make_sink(cfg: dict):
    """Build a Sink from a resolved config dict, or None when disabled.

    "file" + a path -> FileSink; "http" + a url -> HttpSink. A None/unknown type,
    or a known type missing its required field, returns None (sink disabled).
    """
    t = (cfg or {}).get("type")
    if t == "file":
        path = cfg.get("path")
        return FileSink(path) if path else None
    if t == "http":
        url = cfg.get("url")
        if not url:
            return None
        return HttpSink(url, token=cfg.get("token"),
                        timeout=cfg.get("timeout", _DEFAULT_TIMEOUT))
    return None


# --------------------------------------------------------------------------
# per-session forwarding state
# --------------------------------------------------------------------------
#
# <audit_dir>/<sid>.sink holds {"forwarded_seq": N} — the highest seq already
# shipped off-host for that session. It does NOT match the *.jsonl / *.jsonl.gz
# globs in store._session_files, so store never mistakes it for a session.

_STATE_KEY = "forwarded_seq"


def sink_state_path(session_id, audit_dir) -> Path:
    return Path(audit_dir) / f"{session_id}.sink"


def read_forwarded_seq(session_id, audit_dir) -> int:
    """Return the highest forwarded seq for a session; 0 if the state file is
    missing or corrupt (fail-safe: re-forward rather than silently skip)."""
    p = sink_state_path(session_id, audit_dir)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return int(data[_STATE_KEY])
    except Exception:
        return 0


def write_forwarded_seq(session_id, audit_dir, seq) -> None:
    """Atomically persist the forwarded seq (tmp + os.replace)."""
    p = sink_state_path(session_id, audit_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_text(json.dumps({_STATE_KEY: int(seq)}), encoding="utf-8")
    os.replace(tmp, p)


# --------------------------------------------------------------------------
# push orchestration
# --------------------------------------------------------------------------

def push_session(session_id, audit_dir, sink: Sink) -> dict:
    """Forward not-yet-shipped chained events for a session to ``sink``.

    Incremental + idempotent: only events whose seq exceeds the stored
    forwarded_seq are sent, and the state is advanced to the max seq sent ONLY
    after the sink durably accepts them. A SinkError propagates with the state
    left untouched, so the very same events are retried on the next push.

    Legacy / pre-chain events (no integrity.SEQ_KEY) are never forwarded.

    Returns ``{"sent": int, "forwarded_seq": int, "pending": int}``.
    """
    from agent_pd import store

    events = list(store.iter_events(session_id, audit_dir))
    last = read_forwarded_seq(session_id, audit_dir)
    pending = [
        e for e in events
        if isinstance(e.get(SEQ_KEY), int) and e[SEQ_KEY] > last
    ]
    if not pending:
        return {"sent": 0, "forwarded_seq": last, "pending": 0}

    n = sink.send(pending)  # raises SinkError -> propagate, state NOT advanced
    new = max(e[SEQ_KEY] for e in pending)
    write_forwarded_seq(session_id, audit_dir, new)
    return {"sent": n, "forwarded_seq": new, "pending": len(pending)}
