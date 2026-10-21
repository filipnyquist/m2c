import time

from m2c.writer import Writer, spool_files


class FakeInsert:
    """Reads the spool file like chDB's file() would; fails with the scripted codes first."""

    def __init__(self, fail_codes=(), poison=None):
        self.calls = []
        self.tokens = []
        self.fail_codes = list(fail_codes)
        self.poison = poison

    def __call__(self, table, columns, path, token):
        data = path.read_bytes()
        if self.poison and self.poison in data:
            raise RuntimeError("Code: 27. DB::Exception: cannot parse")
        if self.fail_codes:
            raise RuntimeError(f"Code: {self.fail_codes.pop(0)}. DB::Exception: memory limit exceeded")
        self.calls.append((table, len(data)))
        self.tokens.append(token)


def wait(cond, timeout=5):
    deadline = time.time() + timeout
    while not cond() and time.time() < deadline:
        time.sleep(0.02)
    return cond()


def test_batches_by_rows_and_spool_is_emptied(tmp_path):
    ins = FakeInsert()
    w = Writer(ins, tmp_path, batch_rows=10, flush_interval=5)
    w.start()
    for i in range(25):
        w.put("proxy_events", {"kind": "x", "message": str(i)})
    assert w.stop(5)
    assert sum(1 for t, _ in ins.calls if t == "proxy_events") == 3
    assert w.counters.written["proxy_events"] == 25
    assert spool_files(tmp_path / "spool") == []
    assert len(set(ins.tokens)) == 3


def test_flush_interval(tmp_path):
    ins = FakeInsert()
    w = Writer(ins, tmp_path, batch_rows=1000, flush_interval=0.1)
    w.start()
    w.put("proxy_events", {"kind": "x"})
    assert wait(lambda: ins.calls), "row was not flushed by the interval"
    w.stop(5)


def test_transient_errors_spool_and_recover_without_blocking(tmp_path):
    # The memory limit refuses inserts for a while: batches pile up on disk, recording goes on, nothing is lost.
    ins = FakeInsert(fail_codes=[241] * 4)
    w = Writer(ins, tmp_path, batch_rows=5, flush_interval=0.05)
    w.start()
    for i in range(50):
        w.put("proxy_events", {"kind": "x", "message": str(i)})
    assert wait(lambda: w.counters.written["proxy_events"] == 50, 15)
    assert w.stop(5)
    assert w.counters.insert_errors == 4 and w.counters.spooled_files == 0
    assert spool_files(tmp_path / "spool") == []


def test_shutdown_during_outage_keeps_spool_and_next_start_replays(tmp_path):
    down = FakeInsert(fail_codes=[241] * 10_000)
    w = Writer(down, tmp_path, batch_rows=10, flush_interval=0.05)
    w.start()
    for i in range(30):
        w.put("http_flows", {"n": i})
    assert not w.stop(0.5)
    left = spool_files(tmp_path / "spool")
    assert sum(rows for _, _, rows in left) == 30
    up = FakeInsert()
    w2 = Writer(up, tmp_path)
    w2.start()
    assert wait(lambda: w2.counters.written["http_flows"] == 30)
    assert w2.stop(5) and spool_files(tmp_path / "spool") == []
    # the replay reuses the file ids as dedup tokens, so a crash between insert and delete is harmless
    assert sorted(up.tokens) == sorted(p.name.split(".")[1] for p, _, _ in left)


def test_bisect_to_dead_letters(tmp_path):
    ins = FakeInsert(poison=b"POISON")
    w = Writer(ins, tmp_path, batch_rows=8, flush_interval=5)
    w.start()
    for i in range(8):
        w.put("proxy_events", {"kind": "x", "message": "POISON" if i == 5 else "ok"})
    w.stop(5)
    assert w.counters.written["proxy_events"] == 7 and w.counters.dead == 1
    assert len(list((tmp_path / "dead").glob("*.rowbinary"))) == 1
    assert spool_files(tmp_path / "spool") == []


def test_backpressure_strips_then_drops(tmp_path):
    w = Writer(FakeInsert(), tmp_path, queue_max_bytes=10_000)  # not started: queue only fills
    big = b"x" * 4000
    results = [w.put("http_flows", {"_resp_raw": big}) for _ in range(10)]
    assert w.counters.bodies_stripped > 0
    assert all(results[:2])
    w.queue_max_items = 3
    assert not w.put("http_flows", {})
    assert w.counters.dropped["http_flows"] >= 1


# --------------------------------------------------------------------------- shutdown, wedging, budget (review fixes)

import threading  # noqa: E402

from m2c import rows as rows_mod  # noqa: E402
from m2c import schema  # noqa: E402
from m2c.writer import live_spool, row_offsets  # noqa: E402


class ScriptedInsert:
    """Counts attempts; `fail(data)` returns an error code to raise, or None to accept."""

    def __init__(self, fail=lambda data: None, delay=0.0):
        self.fail, self.delay = fail, delay
        self.attempts = 0
        self.rows = 0
        self.lock = threading.Lock()

    def __call__(self, table, columns, path, token):
        with self.lock:
            self.attempts += 1
        if self.delay:
            time.sleep(self.delay)
        data = path.read_bytes()
        code = self.fail(data)
        if code is not None:
            raise RuntimeError(f"Code: {code}. DB::Exception: scripted failure")
        with self.lock:
            self.rows += len(row_offsets(table, data)) - 1


def _spooled_rows(tmp_path):
    return sum(n for _, _, n in spool_files(tmp_path / "spool"))


def test_put_after_stop_is_refused_and_counted(tmp_path):
    ins = ScriptedInsert()
    w = Writer(ins, tmp_path, flush_interval=0.05)
    w.start()
    w.put("proxy_events", {"kind": "a"})
    assert w.stop(5)
    assert not w.put("proxy_events", {"kind": "late"})
    assert w.counters.dropped["proxy_events"] == 1 and ins.rows == 1


def test_stop_without_start_drains_on_the_caller(tmp_path):
    ins = ScriptedInsert()
    w = Writer(ins, tmp_path)
    for i in range(3):
        w.put("proxy_events", {"kind": str(i)})
    assert w.stop(5)
    assert ins.rows == 3 and w.counters.written["proxy_events"] == 3


def test_stop_is_bounded_and_the_rest_stays_in_the_spool(tmp_path):
    # Inserts that succeed but are slow: the deadline must stop inserting, not only failing ones.
    ins = ScriptedInsert(delay=0.2)
    w = Writer(ins, tmp_path, batch_rows=10, flush_interval=0.05)
    w.start()
    for i in range(2000):
        w.put("proxy_events", {"kind": "x", "message": str(i)})
    t0 = time.monotonic()
    ok = w.stop(0.5)
    took = time.monotonic() - t0
    assert not ok and not w.running
    assert took < 0.5 + 0.2 + 1.0, took
    assert w.counters.written["proxy_events"] + _spooled_rows(tmp_path) == 2000
    assert _spooled_rows(tmp_path) > 0 and w.counters.dead == 0


def test_put_final_inserts_after_stop(tmp_path):
    ins = ScriptedInsert()
    w = Writer(ins, tmp_path, flush_interval=0.05)
    w.start()
    w.put("proxy_events", {"kind": "a"})
    assert w.stop(5)
    assert w.put_final("proxy_events", {"kind": "stopped", "counters": w.counters.flat()})
    assert ins.rows == 2 and spool_files(tmp_path / "spool") == []
    down = ScriptedInsert(fail=lambda data: 241)
    w2 = Writer(down, tmp_path)
    assert w2.stop(1) or True
    assert not w2.put_final("proxy_events", {"kind": "stopped"})
    assert _spooled_rows(tmp_path) == 1  # kept for the next start


def _event_size(message: str) -> int:
    from m2c import rowbinary

    return len(rowbinary.encoder(schema.PROXY_EVENTS)({"kind": "x", "message": message}))


def test_batch_too_big_for_memory_is_split_not_retried_forever(tmp_path):
    # Every insert over ~8 rows fails with 241: the writer must split the batch instead of wedging behind it.
    limit = int(_event_size("m" * 100) * 8.5)
    ins = ScriptedInsert(fail=lambda data: 241 if len(data) > limit else None)
    w = Writer(ins, tmp_path, batch_rows=32, flush_interval=0.05, max_attempts=2)
    w.start()
    for i in range(32):
        w.put("proxy_events", {"kind": "x", "message": "m" * 100})
    assert wait(lambda: w.counters.written["proxy_events"] == 32, 20), w.counters.flat()
    assert w.stop(5)
    assert w.counters.dead == 0 and spool_files(tmp_path / "spool") == []


def test_one_row_that_never_fits_is_dead_lettered_while_others_get_in(tmp_path):
    ins = ScriptedInsert(fail=lambda data: 241 if b"HUGE" in data else None)
    w = Writer(ins, tmp_path, batch_rows=4, flush_interval=0.05, max_attempts=2)
    w.start()
    w.put("proxy_events", {"kind": "x", "message": "HUGE"})
    sent = 1
    deadline = time.time() + 20
    while w.counters.dead == 0 and time.time() < deadline:
        w.put("proxy_events", {"kind": "x", "message": "ok"})
        sent += 1
        time.sleep(0.05)
    assert w.counters.dead == 1
    assert w.stop(5)
    assert ins.rows == sent - 1 and spool_files(tmp_path / "spool") == []
    assert len(list((tmp_path / "dead").glob("*.rowbinary"))) == 1


def test_outage_that_refuses_everything_dead_letters_nothing(tmp_path):
    state = {"down": True}
    ins = ScriptedInsert(fail=lambda data: 241 if state["down"] else None)
    w = Writer(ins, tmp_path, batch_rows=5, flush_interval=0.05, max_attempts=2)
    w.start()
    for i in range(20):
        w.put("proxy_events", {"kind": "x", "message": str(i)})
    time.sleep(3)
    assert w.counters.dead == 0 and ins.rows == 0
    state["down"] = False
    assert wait(lambda: w.counters.written["proxy_events"] == 20, 20), w.counters.flat()
    assert w.stop(5) and w.counters.dead == 0


def test_error_that_does_not_depend_on_rows_dead_letters_the_batch_whole(tmp_path):
    ins = ScriptedInsert(fail=lambda data: 164)  # READONLY
    w = Writer(ins, tmp_path, batch_rows=1000, flush_interval=5)
    w.start()
    for i in range(1000):
        w.put("proxy_events", {"kind": "x"})
    w.stop(5)
    assert ins.attempts == 1 and w.counters.dead == 1000
    assert len(list((tmp_path / "dead").glob("*.rowbinary"))) == 1


def test_same_error_for_every_piece_stops_bisecting(tmp_path):
    # Not 1999 inserts and 1000 dead-letter files: levels of 1, 2, 4 and 8 pieces, then the 8 pieces as they are.
    ins = ScriptedInsert(fail=lambda data: 27)
    w = Writer(ins, tmp_path, batch_rows=1000, flush_interval=5)
    w.start()
    for i in range(1000):
        w.put("proxy_events", {"kind": "x"})
    w.stop(5)
    assert ins.attempts == 15 and w.counters.dead == 1000
    assert len(list((tmp_path / "dead").glob("*.rowbinary"))) == 8


def test_bad_rows_in_both_halves_do_not_take_good_rows_with_them(tmp_path):
    ins = ScriptedInsert(fail=lambda data: 27 if b"POISON" in data else None)
    w = Writer(ins, tmp_path, batch_rows=100, flush_interval=5)
    w.start()
    for i in range(100):
        w.put("proxy_events", {"kind": "x", "message": "POISON" if i in (10, 90) else "ok"})
    w.stop(5)
    assert w.counters.dead == 2 and ins.rows == 98
    assert spool_files(tmp_path / "spool") == []


def test_replay_spool_dead_letters_a_poison_batch_and_inserts_the_rest(tmp_path):
    from m2c.writer import replay_spool

    down = ScriptedInsert(fail=lambda data: 241)
    w = Writer(down, tmp_path, batch_rows=4, flush_interval=0.05)
    w.start()
    for i in range(8):
        w.put("proxy_events", {"kind": "x", "message": "POISON" if i == 1 else "ok"})
    assert not w.stop(0.3)
    assert _spooled_rows(tmp_path) == 8
    ins = ScriptedInsert(fail=lambda data: 27 if b"POISON" in data else None)
    done, left = replay_spool(ins, tmp_path, timeout=5)
    assert left == 0 and ins.rows == 7 and spool_files(tmp_path / "spool") == []
    assert len(list((tmp_path / "dead").glob("*.rowbinary"))) == 1
    assert replay_spool(ins, tmp_path) == (0, 0)
    outage = Writer(down, tmp_path, batch_rows=4, flush_interval=0.05)
    outage.put("proxy_events", {"kind": "x"})
    outage.stop(0.2)
    assert replay_spool(down, tmp_path, timeout=0.3) == (0, 1)  # an outage keeps the file for the next try


def test_spool_files_are_private(tmp_path):
    w = Writer(ScriptedInsert(fail=lambda data: 241), tmp_path, batch_rows=1, flush_interval=0.05)
    w.start()
    w.put("proxy_events", {"kind": "x", "message": "secret body"})
    assert not w.stop(0.3)
    assert [p.stat().st_mode & 0o777 for p, _, _ in spool_files(tmp_path / "spool")] == [0o600]


def test_budget_counts_rows_the_writer_has_taken(tmp_path):
    # With the insert blocked, rows already taken off the queue still hold their bodies and must count.
    gate = threading.Event()
    ins = ScriptedInsert(fail=lambda data: None if gate.wait(10) else 241)
    w = Writer(ins, tmp_path, batch_rows=1, flush_interval=0, queue_max_bytes=10 << 20, body_cap=1 << 20)
    w.start()
    body = b"b" * (1 << 20)
    for _ in range(40):
        w.put("http_flows", {"_resp_raw": body})
        time.sleep(0.01)
    kept = 40 - w.counters.bodies_stripped - w.counters.dropped["http_flows"]
    gate.set()
    w.stop(10)
    assert kept <= 11, kept


def test_row_offsets_match_the_encoder():
    from m2c import rowbinary

    samples = {
        "http_flows": {"flow_id": "6f1c2a3e-1111-2222-3333-444455556666", "n": 3, "ts_start": 1.5, "client_ip": "10.0.0.1",
                       "req_headers": [("a", "b"), ("c", "d" * 300)], "req_body": b"\x00\xff" * 200, "status": 200,
                       "resp_capture": "sse", "end_reason": "complete", "tls": True, "port": 443},
        "ws_messages": {"seq": 1, "opcode": "binary", "content": b"x" * 70000},
        "sse_events": {"event": "message", "data": "hi", "retry_ms": 5},
        "proxy_events": {"kind": "health", "severity": "warn", "counters": {"written.http_flows": 10, "dead": -1}},
    }
    for table, row in samples.items():
        enc = rowbinary.encoder(schema.TABLES[table])
        parts = [enc(row), enc({}), enc(row)]
        data = b"".join(parts)
        assert row_offsets(table, data) == [0, len(parts[0]), len(parts[0]) + len(parts[1]), len(data)]
        try:
            row_offsets(table, data[:-1])
        except ValueError:
            pass
        else:
            raise AssertionError("truncated data parsed")


def test_interrupted_split_keeps_the_parent_only(tmp_path):
    spool = tmp_path / "spool"
    spool.mkdir()
    for name in ("proxy_events.1-0.2.rowbinary", "proxy_events.1-0-0.1.rowbinary", "proxy_events.1-0-1-0.1.rowbinary",
                 "proxy_events.2-0-1.1.rowbinary"):
        (spool / name).write_bytes(b"")
    assert [p.name for p, _, _ in live_spool(spool)] == ["proxy_events.1-0.2.rowbinary", "proxy_events.2-0-1.1.rowbinary"]
    assert sorted(p.name for p in spool.iterdir()) == ["proxy_events.1-0.2.rowbinary", "proxy_events.2-0-1.1.rowbinary"]


# --------------------------------------------------------------------------- rows / recorder helpers


def test_strip_bodies_keeps_full_streamed_size_and_labels():
    row = {"_resp_raw": b"x" * 100, "resp_body_size": 5_000_000, "resp_capture": "sse", "_req_raw": b"y" * 10,
           "req_body_size": 52_428_800, "req_capture": "streamed"}
    rows_mod.strip_bodies(row)
    assert row["resp_body_size"] == 5_000_000 and row["resp_capture"] == "sse" and row["resp_body_truncated"]
    assert row["req_body_size"] == 52_428_800 and row["req_capture"] == "dropped"
    buffered = {"_resp_raw": b"z" * 7}
    rows_mod.strip_bodies(buffered)
    assert buffered["resp_body_size"] == 7 and buffered["resp_capture"] == "dropped"
    untee = {"_resp_raw": None}
    rows_mod.strip_bodies(untee)
    assert untee["resp_capture"] == "streamed"


def test_error_kind_upstream_disconnect_messages():
    from mitmproxy.connection import ConnectionState
    from mitmproxy.test import tflow

    def kind(msg, client_eof=False, server_open=True):
        f = tflow.tflow(err=True)
        f.error.msg = msg
        f.server_conn.timestamp_tcp_setup = time.time()
        f.server_conn.state = ConnectionState.OPEN if server_open else ConnectionState.CAN_WRITE
        f.client_conn.state = ConnectionState.CAN_WRITE if client_eof else ConnectionState.OPEN
        return rows_mod.error_kind(f)

    assert kind("server closed connection") == "upstream_disconnect"
    assert kind("HTTP/1 protocol error: peer closed connection without sending complete message body (received 1, expected 2)",
                server_open=False) == "upstream_disconnect"
    assert kind("peer closed connection", server_open=False) == "upstream_disconnect"
    assert kind("peer closed connection", client_eof=True) == "client_abort"
    assert kind("Client disconnected.") == "client_abort"
    # mitmproxy's HTTP/1 layer says "Client disconnected." for a server that hangs up while it waits, too
    assert kind("Client disconnected.", server_open=False) == "upstream_disconnect"
    assert kind("HTTP/2 connection closed: <ConnectionTerminated error_code:0, last_stream_id:1>", server_open=False) == "upstream_disconnect"
    assert kind("HTTP/2 connection closed: <ConnectionTerminated error_code:0, last_stream_id:1>", client_eof=True) == "client_abort"
    assert kind("Connection closed by peer.", server_open=False) == "upstream_disconnect"
    assert kind("stream reset by client (CANCEL)") == "client_abort"
    assert kind("stream reset by client (REFUSED_STREAM)") == "upstream_disconnect"
    assert kind("[Errno 104] Connection reset by peer", server_open=False) == "upstream_disconnect"
    assert kind("Connection killed: blocked") == "killed"
    f = tflow.tflow(err=True)
    f.error.msg = "[Errno 111] Connect call failed ('127.0.0.1', 1)"
    f.server_conn.timestamp_tcp_setup = None
    assert rows_mod.error_kind(f) == "upstream_connect"


def test_labels_keep_commas_and_flow_metadata_is_serializable():
    from mitmproxy.io import tnetstring

    from m2c.identity import Identity
    from m2c.recorder import _meta, _meta_ident, parse_labels

    assert parse_labels("branches=main,dev,env=ci") == {"branches": "main,dev", "env": "ci"}
    assert parse_labels('{"repo": "a,b=c"}') == {"repo": "a,b=c"}
    assert parse_labels("") == {}
    ident = Identity("s1", "curl", "c7", "s1.curl.c7", "request")
    meta = _meta(ident, 5, "t")
    assert tnetstring.loads(tnetstring.dumps(meta)) == meta
    assert _meta_ident(meta) == ident
    assert _meta_ident({"session": "bad session!"}) is None


def _bare_state(tmp_path, insert, push=""):
    """A State without chDB: only what shutdown() and push() touch."""
    from m2c.state import Config, State

    class Db:
        closed = False

        def close(self):
            self.closed = True

    st = State.__new__(State)
    st.config = Config(data=tmp_path, scan_id="s", auth="open", secrets=[], body_cap=1 << 20, ws_msg_cap=1, sse_event_cap=1,
                       sse_max_events=1, stream_threshold=1, batch_rows=10, batch_bytes=1 << 20, flush_interval=0.05,
                       queue_max_bytes=1 << 20, memory_limit=None, shutdown_timeout=0.5, ws_trim=True, push_on_exit=push)
    st.lock, st._n, st._n_reserved, st.api, st.closed, st.db = threading.Lock(), 7, 1000, None, False, Db()
    st.writer = Writer(insert, tmp_path, flush_interval=0.05)
    return st


def test_shutdown_skips_push_when_rows_are_left_in_the_spool(tmp_path):
    import json

    st = _bare_state(tmp_path, ScriptedInsert(fail=lambda data: 241), push="https://m2c@ch.example:8443/m2c")
    st.writer.start()
    st.event("x")
    st.shutdown()
    marker = json.loads((tmp_path / "push-failed.json").read_text())
    assert marker["target"] == "ch.example:8443/m2c" and marker["error"].startswith("not pushed: ")
    assert _spooled_rows(tmp_path) == 2  # the row and the 'stopped' event, for the next start or `m2c push`
    assert st.db.closed
    assert json.loads((tmp_path / "n.json").read_text()) == {"n": 7}  # exact after a clean stop: numbering continues


def test_push_with_a_bad_url_writes_the_marker(tmp_path):
    import json

    st = _bare_state(tmp_path, ScriptedInsert())
    st.push("https://m2c@ch.example:84a3/m2c")
    assert "port" in json.loads((tmp_path / "push-failed.json").read_text())["error"].lower()


def test_shutdown_leaves_the_session_open_while_the_writer_is_busy(tmp_path):
    gate = threading.Event()
    st = _bare_state(tmp_path, ScriptedInsert(fail=lambda data: None if gate.wait(10) else 241))
    st.config.shutdown_timeout = 0.1
    st.writer.start()
    st.event("x")
    time.sleep(0.3)  # the insert is now blocked
    t0 = time.monotonic()
    st.shutdown()
    assert time.monotonic() - t0 < 10
    assert not st.db.closed and st.writer.running
    gate.set()
