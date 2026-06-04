import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from agent_pd import sink as sink_mod
from agent_pd.sink import (
    FileSink,
    HttpSink,
    Sink,
    SinkError,
    make_sink,
    push_session,
    read_forwarded_seq,
    resolve_sink_config,
    sink_state_path,
    write_forwarded_seq,
)
from agent_pd.integrity import SEQ_KEY, next_link


# --------------------------------------------------------------------------
# resolve_sink_config
# --------------------------------------------------------------------------

def test_resolve_defaults_disabled(monkeypatch):
    for k in ("PD_SINK_TYPE", "PD_SINK_URL", "PD_SINK_PATH",
              "PD_SINK_TOKEN", "PD_SINK_TIMEOUT"):
        monkeypatch.delenv(k, raising=False)
    cfg = resolve_sink_config(None)
    assert cfg["type"] is None
    assert cfg["url"] is None
    assert cfg["path"] is None
    assert cfg["token"] is None
    assert cfg["timeout"] == 10.0


def test_resolve_from_rules_sink_dict(monkeypatch):
    for k in ("PD_SINK_TYPE", "PD_SINK_URL", "PD_SINK_PATH",
              "PD_SINK_TOKEN", "PD_SINK_TIMEOUT"):
        monkeypatch.delenv(k, raising=False)

    class R:
        sink = {"type": "file", "path": "/var/log/pd.ndjson", "timeout": 3.0}

    cfg = resolve_sink_config(R())
    assert cfg["type"] == "file"
    assert cfg["path"] == "/var/log/pd.ndjson"
    assert cfg["timeout"] == 3.0


def test_resolve_env_overrides_rules(monkeypatch):
    monkeypatch.setenv("PD_SINK_TYPE", "http")
    monkeypatch.setenv("PD_SINK_URL", "https://example.test/ingest")
    monkeypatch.setenv("PD_SINK_TIMEOUT", "2.5")
    monkeypatch.delenv("PD_SINK_PATH", raising=False)
    monkeypatch.delenv("PD_SINK_TOKEN", raising=False)

    class R:
        sink = {"type": "file", "url": "http://ignored", "path": "/p", "timeout": 9}

    cfg = resolve_sink_config(R())
    assert cfg["type"] == "http"
    assert cfg["url"] == "https://example.test/ingest"
    assert cfg["timeout"] == 2.5
    # path falls through from rules since no env override
    assert cfg["path"] == "/p"


def test_resolve_token_only_from_env(monkeypatch):
    monkeypatch.delenv("PD_SINK_TYPE", raising=False)
    monkeypatch.delenv("PD_SINK_TOKEN", raising=False)

    class R:
        # a token sitting in a config dict MUST be ignored
        sink = {"type": "http", "url": "http://x", "token": "from-config-SHOULD-IGNORE"}

    cfg = resolve_sink_config(R())
    assert cfg["token"] is None

    monkeypatch.setenv("PD_SINK_TOKEN", "secret-from-env")
    cfg2 = resolve_sink_config(R())
    assert cfg2["token"] == "secret-from-env"


# --------------------------------------------------------------------------
# FileSink
# --------------------------------------------------------------------------

def test_filesink_appends_json_lines(tmp_path):
    dest = tmp_path / "nested" / "sink.ndjson"
    s = FileSink(str(dest))
    events = [{"a": 1, SEQ_KEY: 1}, {"b": "two", SEQ_KEY: 2}]
    n = s.send(events)
    assert n == 2
    assert dest.exists()  # parent dir created
    lines = dest.read_text(encoding="utf-8").splitlines()
    assert [json.loads(x) for x in lines] == events


def test_filesink_appends_not_truncates(tmp_path):
    dest = tmp_path / "sink.ndjson"
    s = FileSink(str(dest))
    s.send([{"x": 1, SEQ_KEY: 1}])
    s.send([{"x": 2, SEQ_KEY: 2}])
    lines = dest.read_text(encoding="utf-8").splitlines()
    assert [json.loads(x)["x"] for x in lines] == [1, 2]


def test_filesink_is_a_sink():
    assert issubclass(FileSink, Sink)
    assert issubclass(HttpSink, Sink)


# --------------------------------------------------------------------------
# HttpSink (real local mock server)
# --------------------------------------------------------------------------

class _Recorder:
    body = None
    headers = None
    path = None


def _make_handler(recorder, status):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a):  # silence
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            recorder.body = self.rfile.read(length)
            recorder.headers = dict(self.headers)
            recorder.path = self.path
            self.send_response(status)
            self.end_headers()
            self.wfile.write(b"ok" if 200 <= status < 300 else b"err")

    return H


def _serve(recorder, status):
    srv = HTTPServer(("127.0.0.1", 0), _make_handler(recorder, status))
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


def test_httpsink_posts_ndjson_with_auth():
    rec = _Recorder()
    srv, t = _serve(rec, 200)
    try:
        port = srv.server_address[1]
        url = f"http://127.0.0.1:{port}/ingest"
        s = HttpSink(url, token="tok123", timeout=5.0)
        events = [{"a": 1, SEQ_KEY: 1}, {"b": 2, SEQ_KEY: 2}]
        n = s.send(events)
        assert n == 2
    finally:
        srv.shutdown()
        t.join(timeout=2)

    assert rec.path == "/ingest"
    assert rec.headers["Content-Type"] == "application/x-ndjson"
    assert rec.headers["Authorization"] == "Bearer tok123"
    body_lines = rec.body.decode("utf-8").splitlines()
    assert [json.loads(x) for x in body_lines] == events


def test_httpsink_no_token_no_auth_header():
    rec = _Recorder()
    srv, t = _serve(rec, 200)
    try:
        port = srv.server_address[1]
        s = HttpSink(f"http://127.0.0.1:{port}/", timeout=5.0)
        s.send([{"a": 1, SEQ_KEY: 1}])
    finally:
        srv.shutdown()
        t.join(timeout=2)
    assert "Authorization" not in rec.headers


def test_httpsink_non_2xx_raises():
    rec = _Recorder()
    srv, t = _serve(rec, 500)
    try:
        port = srv.server_address[1]
        s = HttpSink(f"http://127.0.0.1:{port}/", timeout=5.0)
        with pytest.raises(SinkError):
            s.send([{"a": 1, SEQ_KEY: 1}])
    finally:
        srv.shutdown()
        t.join(timeout=2)


def test_httpsink_connection_refused_raises():
    # grab a port then close it so nothing is listening
    s0 = socket.socket()
    s0.bind(("127.0.0.1", 0))
    port = s0.getsockname()[1]
    s0.close()
    s = HttpSink(f"http://127.0.0.1:{port}/", timeout=2.0)
    with pytest.raises(SinkError):
        s.send([{"a": 1, SEQ_KEY: 1}])


# --------------------------------------------------------------------------
# FIX 1: never send the bearer token over cleartext http to a non-loopback
# host; never auto-follow redirects (cross-host token leak).
# --------------------------------------------------------------------------

def test_httpsink_token_over_cleartext_remote_refused(monkeypatch):
    # token + http:// + non-loopback host => refuse BEFORE any request.
    called = {"n": 0}

    def boom_urlopen(*a, **k):
        called["n"] += 1
        raise AssertionError("must not open a connection when refusing")

    monkeypatch.setattr(sink_mod.urllib.request, "urlopen", boom_urlopen)
    s = HttpSink("http://example.com/ingest", token="SECRET", timeout=5.0)
    with pytest.raises(SinkError) as ei:
        s.send([{"a": 1, SEQ_KEY: 1}])
    msg = str(ei.value).lower()
    assert "cleartext" in msg or "http" in msg
    # the secret must not have leaked into the error message
    assert "SECRET" not in str(ei.value)
    # and no request was attempted at all
    assert called["n"] == 0


def test_httpsink_token_over_cleartext_loopback_allowed():
    # http:// to loopback with a token is fine for local testing.
    rec = _Recorder()
    srv, t = _serve(rec, 200)
    try:
        port = srv.server_address[1]
        s = HttpSink(f"http://127.0.0.1:{port}/ingest", token="tok", timeout=5.0)
        n = s.send([{"a": 1, SEQ_KEY: 1}])
        assert n == 1
    finally:
        srv.shutdown()
        t.join(timeout=2)
    assert rec.headers["Authorization"] == "Bearer tok"


def test_httpsink_no_token_remote_http_allowed():
    # no token => nothing to leak => http:// remote is allowed (it just has to
    # actually connect somewhere; use a loopback server but no token).
    rec = _Recorder()
    srv, t = _serve(rec, 200)
    try:
        port = srv.server_address[1]
        s = HttpSink(f"http://127.0.0.1:{port}/", timeout=5.0)
        # no token set -> the cleartext guard must not fire
        assert s.token is None
        n = s.send([{"a": 1, SEQ_KEY: 1}])
        assert n == 1
    finally:
        srv.shutdown()
        t.join(timeout=2)


def test_httpsink_redirect_not_followed_raises():
    # a 3xx must not be auto-followed (cross-host Authorization leak); it is an
    # error. Use a 302 with a Location header to confirm we do NOT chase it.
    # The redirect Location points back at THIS same server's /ok path, which
    # returns 200. So if redirects were auto-followed the send would SUCCEED;
    # only a no-follow implementation turns the 302 into a SinkError. This makes
    # the test fail against the old (follow-redirects) code.
    class Redirector(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_POST(self):
            if self.path == "/ok":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
                return
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://127.0.0.1:{self.server.server_address[1]}/ok",
            )
            self.end_headers()

        def do_GET(self):
            # urllib turns a 302 on POST into a GET on follow.
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

    srv = HTTPServer(("127.0.0.1", 0), Redirector)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        port = srv.server_address[1]
        s = HttpSink(f"http://127.0.0.1:{port}/", timeout=5.0)
        with pytest.raises(SinkError):
            s.send([{"a": 1, SEQ_KEY: 1}])
    finally:
        srv.shutdown()
        t.join(timeout=2)


# --------------------------------------------------------------------------
# FIX 3: serialization errors -> SinkError (never escape as TypeError)
# --------------------------------------------------------------------------

def test_filesink_unserializable_event_raises_sinkerror(tmp_path):
    s = FileSink(str(tmp_path / "off.ndjson"))
    with pytest.raises(SinkError):
        s.send([{"x": object(), SEQ_KEY: 1}])


def test_httpsink_unserializable_event_raises_sinkerror():
    s = HttpSink("http://127.0.0.1:9/", timeout=2.0)
    with pytest.raises(SinkError):
        s.send([{"x": object(), SEQ_KEY: 1}])


# --------------------------------------------------------------------------
# make_sink
# --------------------------------------------------------------------------

def test_make_sink_file():
    s = make_sink({"type": "file", "path": "/tmp/x.ndjson"})
    assert isinstance(s, FileSink)


def test_make_sink_file_missing_path_none():
    assert make_sink({"type": "file", "path": None}) is None


def test_make_sink_http():
    s = make_sink({"type": "http", "url": "http://x", "token": "t", "timeout": 4.0})
    assert isinstance(s, HttpSink)


def test_make_sink_http_missing_url_none():
    assert make_sink({"type": "http", "url": None}) is None


def test_make_sink_none_or_unknown():
    assert make_sink({"type": None}) is None
    assert make_sink({"type": "unknown"}) is None
    assert make_sink({}) is None


# --------------------------------------------------------------------------
# forwarded-seq state
# --------------------------------------------------------------------------

def test_sink_state_path(tmp_path):
    p = sink_state_path("sid42", tmp_path)
    assert p == tmp_path / "sid42.sink"
    # must NOT look like a session file to store globs
    assert not str(p).endswith(".jsonl")
    assert not str(p).endswith(".jsonl.gz")


def test_read_forwarded_seq_missing_is_zero(tmp_path):
    assert read_forwarded_seq("nope", tmp_path) == 0


def test_write_then_read_roundtrips(tmp_path):
    write_forwarded_seq("sid", tmp_path, 7)
    assert read_forwarded_seq("sid", tmp_path) == 7


def test_read_forwarded_seq_corrupt_is_zero(tmp_path):
    p = sink_state_path("sid", tmp_path)
    p.write_text("not json{{{", encoding="utf-8")
    assert read_forwarded_seq("sid", tmp_path) == 0


# --------------------------------------------------------------------------
# push_session
# --------------------------------------------------------------------------

def _write_chained_session(audit_dir, session_id, events):
    """Append chained events to <sid>.jsonl using integrity.next_link."""
    path = audit_dir / f"{session_id}.jsonl"
    prev_hex = ""
    prev_seq = 0
    lines = []
    for ev in events:
        linked = next_link(prev_hex, prev_seq, ev)
        prev_hex = linked["chain"]
        prev_seq = linked[SEQ_KEY]
        lines.append(json.dumps(linked))
    with path.open("a", encoding="utf-8") as f:
        f.write("".join(line + "\n" for line in lines))
    return prev_seq


def test_push_forwards_all_chained(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    last_seq = _write_chained_session(audit, "s1", [{"e": "a"}, {"e": "b"}, {"e": "c"}])
    out = tmp_path / "off.ndjson"
    s = FileSink(str(out))

    res = push_session("s1", audit, s)
    assert res["sent"] == 3
    assert res["forwarded_seq"] == last_seq == 3
    assert res["pending"] == 3
    assert read_forwarded_seq("s1", audit) == 3

    sunk = [json.loads(x) for x in out.read_text().splitlines()]
    assert [e[SEQ_KEY] for e in sunk] == [1, 2, 3]


def test_push_idempotent_second_run(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    _write_chained_session(audit, "s1", [{"e": "a"}, {"e": "b"}])
    out = tmp_path / "off.ndjson"
    s = FileSink(str(out))
    push_session("s1", audit, s)
    res2 = push_session("s1", audit, s)
    assert res2["sent"] == 0
    assert res2["pending"] == 0
    assert res2["forwarded_seq"] == 2
    # nothing new appended
    assert len(out.read_text().splitlines()) == 2


def test_push_incremental_only_new(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    _write_chained_session(audit, "s1", [{"e": "a"}, {"e": "b"}])
    out = tmp_path / "off.ndjson"
    s = FileSink(str(out))
    push_session("s1", audit, s)
    # append two more (chain continues)
    _write_chained_session_continue(audit, "s1", [{"e": "c"}, {"e": "d"}])
    res = push_session("s1", audit, s)
    assert res["sent"] == 2
    assert res["forwarded_seq"] == 4
    sunk = [json.loads(x) for x in out.read_text().splitlines()]
    assert [e[SEQ_KEY] for e in sunk] == [1, 2, 3, 4]


def _write_chained_session_continue(audit_dir, session_id, events):
    """Continue an existing chain by reading current last link from the file."""
    path = audit_dir / f"{session_id}.jsonl"
    prev_hex = ""
    prev_seq = 0
    for line in path.read_text().splitlines():
        if line.strip():
            ev = json.loads(line)
            prev_hex = ev["chain"]
            prev_seq = ev[SEQ_KEY]
    lines = []
    for ev in events:
        linked = next_link(prev_hex, prev_seq, ev)
        prev_hex = linked["chain"]
        prev_seq = linked[SEQ_KEY]
        lines.append(json.dumps(linked))
    with path.open("a", encoding="utf-8") as f:
        f.write("".join(line + "\n" for line in lines))


def test_push_legacy_only_sends_nothing(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    # legacy events have no seq
    path = audit / "s1.jsonl"
    path.write_text(
        json.dumps({"e": "a"}) + "\n" + json.dumps({"e": "b"}) + "\n",
        encoding="utf-8",
    )
    out = tmp_path / "off.ndjson"
    s = FileSink(str(out))
    res = push_session("s1", audit, s)
    assert res["sent"] == 0
    assert res["pending"] == 0
    assert not out.exists()  # nothing written at all


def test_push_failure_does_not_advance_state(tmp_path):
    audit = tmp_path / "audit"
    audit.mkdir()
    _write_chained_session(audit, "s1", [{"e": "a"}, {"e": "b"}])

    class BoomSink(Sink):
        calls = 0

        def send(self, events):
            BoomSink.calls += 1
            raise SinkError("boom")

    boom = BoomSink()
    with pytest.raises(SinkError):
        push_session("s1", audit, boom)
    # state NOT advanced -> a retry would resend
    assert read_forwarded_seq("s1", audit) == 0

    # retry with a working sink resends everything
    out = tmp_path / "off.ndjson"
    res = push_session("s1", audit, FileSink(str(out)))
    assert res["sent"] == 2
    assert read_forwarded_seq("s1", audit) == 2
