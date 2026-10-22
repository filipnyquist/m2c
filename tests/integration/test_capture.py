import base64
import gzip
import signal
import socket
import subprocess
import time

import pytest

import servers

pytestmark = pytest.mark.integration


def curl(proxy_url, url, *args) -> subprocess.CompletedProcess:
    return subprocess.run(["curl", "-sS", "-x", proxy_url, *args, url], capture_output=True, timeout=30)


def test_http_rows_identity_and_exact_bytes(proxy, upstream):
    tok = proxy.token("run1")
    up = f"http://127.0.0.1:{upstream}"
    assert curl(proxy.url("run1.curl", tok), up + "/hello").stdout == b"hello world\n"
    assert curl(proxy.url("run1.curl.c7", tok), up + "/bin", "-H", "x-m2c-tool: scanner", "-H", "x-m2c-tag: phase-1").stdout == servers.BINARY
    assert curl(proxy.url("run1.curl", tok), up + "/gzip", "--compressed").stdout == b"compressed " * 1000
    proxy.stop()
    rows = proxy.rows("SELECT n, session, tool, call_id, tag, identity_source, path, status, resp_body_size, resp_body_decoded, "
                      "hex(resp_body) AS body, has(arrayMap(h -> lower(h.1), req_headers), 'x-m2c-tool') AS leaked FROM m2c.http_flows ORDER BY n")
    assert [(r["session"], r["tool"], r["call_id"], r["path"], r["status"]) for r in rows] == [
        ("run1", "curl", "", "/hello", 200), ("run1", "scanner", "c7", "/bin", 200), ("run1", "curl", "", "/gzip", 200)]
    assert rows[1]["tag"] == "phase-1" and rows[1]["identity_source"] == "header"
    assert bytes.fromhex(rows[1]["body"]) == servers.BINARY
    assert bytes.fromhex(rows[2]["body"]) == b"compressed " * 1000 and rows[2]["resp_body_decoded"]
    assert rows[2]["resp_body_size"] == len(gzip.compress(b"compressed " * 1000)) or rows[2]["resp_body_size"] < 1000
    assert not any(r["leaked"] for r in rows)
    assert [r["n"] for r in rows] == [1, 2, 3]


def test_auth_failures_are_events_not_flows(proxy, upstream):
    tok = proxy.token("run1")
    up = f"http://127.0.0.1:{upstream}/hello"
    assert b"407" in curl(proxy.url("run2.curl", tok), up, "-w", "%{http_code}", "-o", "/dev/null").stdout
    assert b"407" in curl(f"http://127.0.0.1:{proxy.port}", up, "-w", "%{http_code}", "-o", "/dev/null").stdout
    assert b"407" in curl(proxy.url("run1.curl", "v1.0.forgedforgedforgedforg"), up, "-w", "%{http_code}", "-o", "/dev/null").stdout
    proxy.stop()
    assert proxy.rows("SELECT count() AS c FROM m2c.http_flows")[0]["c"] == 0
    events = proxy.rows("SELECT kind, reason, proxy_user FROM m2c.proxy_events WHERE kind LIKE 'auth%' ORDER BY ts")
    assert {(e["kind"], e["reason"]) for e in events} == {("auth_rejected", "bad_mac"), ("auth_challenge", "missing")}


def test_https_through_connect(proxy, tmp_path):
    tok = proxy.token("tls1")
    ca = str(proxy.conf / "mitmproxy-ca-cert.pem")
    srv, port = servers.start_tls(str(tmp_path))  # a local self-signed upstream: the proxy doesn't verify upstreams by default
    try:
        res = curl(proxy.url("tls1.curl", tok), f"https://localhost:{port}/hello", "--cacert", ca, "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15")
    finally:
        srv.shutdown()
    assert res.stdout == b"200"
    proxy.stop()
    row = proxy.rows("SELECT session, identity_source, tls, sni, scheme FROM m2c.http_flows")[0]
    assert row == {"session": "tls1", "identity_source": "connect", "tls": True, "sni": "localhost", "scheme": "https"}


def test_sse_streams_live_and_events_recorded(proxy, upstream):
    tok = proxy.token("llm1")
    for path in ("/sse", "/sse-gzip"):
        args = ["curl", "-sSN", "-x", proxy.url("llm1.agent", tok), f"http://127.0.0.1:{upstream}{path}"]
        if path == "/sse-gzip":
            args.insert(2, "--compressed")
        t0 = time.time()
        p = subprocess.Popen(args, stdout=subprocess.PIPE)
        first = p.stdout.readline()
        first_at = time.time() - t0
        rest = p.stdout.read()
        p.wait(10)
        assert first.startswith(b"event: start")
        assert first_at < 0.5, f"first SSE event took {first_at:.2f}s: the proxy buffered the stream"
        assert b"[DONE]" in rest
    proxy.stop()
    flows = proxy.rows("SELECT path, resp_capture, sse_event_count, resp_body_decoded FROM m2c.http_flows ORDER BY n")
    assert [(f["path"], f["resp_capture"], f["sse_event_count"]) for f in flows] == [("/sse", "sse", 21), ("/sse-gzip", "sse", 21)]
    events = proxy.rows("SELECT n, seq, event, data, ms_since_req FROM m2c.sse_events ORDER BY n, seq")
    assert len(events) == 42
    assert events[0]["event"] == "start" and events[0]["data"] == '{"n": 0}'
    assert events[20]["data"] == "[DONE]" and events[41]["data"] == "[DONE]"
    assert events[1]["ms_since_req"] >= 500


def test_sse_with_bad_encoding_keeps_the_raw_body_and_says_why(proxy, upstream):
    tok = proxy.token("bad1")
    out = curl(proxy.url("bad1.curl", tok), f"http://127.0.0.1:{upstream}/sse-badgzip")
    assert out.returncode == 0 and out.stdout.count(b"data: plain") == 10
    proxy.stop()
    (f,) = proxy.rows("SELECT resp_capture, resp_body_size, length(resp_body) AS kept, resp_body_decoded FROM m2c.http_flows")
    size = sum(len(b"data: plain %d\n\n" % i) for i in range(10))
    assert (f["resp_capture"], f["resp_body_size"], f["kept"], f["resp_body_decoded"]) == ("sse", size, size, False)
    (ev,) = proxy.rows("SELECT severity, session, host, message FROM m2c.proxy_events WHERE kind = 'sse_parse_stopped'")
    assert ev["severity"] == "warn" and ev["session"] == "bad1" and "content decoding failed" in ev["message"]
    assert proxy.data.stat().st_mode & 0o777 == 0o700  # holds every captured body


def test_big_chunked_response_and_chunked_upload(proxy, upstream, tmp_path):
    tok = proxy.token("big1")
    out = curl(proxy.url("big1.curl", tok), f"http://127.0.0.1:{upstream}/big", "-o", str(tmp_path / "big"))
    assert out.returncode == 0 and (tmp_path / "big").stat().st_size == 48 * 65536
    (tmp_path / "up").write_bytes(b"u" * 3_000_000)
    res = curl(proxy.url("big1.curl", tok), f"http://127.0.0.1:{upstream}/upload", "-H", "Transfer-Encoding: chunked",
               "--data-binary", f"@{tmp_path / 'up'}")
    assert res.stdout == b"got 3000000\n"
    proxy.stop()
    rows = proxy.rows("SELECT path, resp_capture, resp_body_size, length(resp_body) AS kept, resp_body_truncated, "
                      "req_capture, req_body_size, length(req_body) AS req_kept FROM m2c.http_flows ORDER BY n")
    big, up = rows
    assert (big["resp_capture"], big["resp_body_size"], big["kept"], big["resp_body_truncated"]) == ("streamed", 48 * 65536, 1 << 20, True)
    assert (up["req_capture"], up["req_body_size"], up["req_kept"]) == ("streamed", 3000000, 1 << 20)


def _ws_session(proxy, upstream, tok, messages):
    s = socket.create_connection(("127.0.0.1", proxy.port), 10)
    auth = base64.b64encode(f"ws1.wsclient:{tok}".encode()).decode()
    s.sendall(f"CONNECT 127.0.0.1:{upstream} HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
    assert s.recv(4096).startswith(b"HTTP/1.1 200")
    s.sendall(
        f"GET /ws HTTP/1.1\r\nHost: 127.0.0.1:{upstream}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n".encode()
    )
    head = b""
    while b"\r\n\r\n" not in head:
        head += s.recv(1)
    assert head.startswith(b"HTTP/1.1 101")
    return s


def test_websocket_messages_and_close(proxy, upstream):
    tok = proxy.token("ws1")
    s = _ws_session(proxy, upstream, tok, [])
    for i in range(5):
        s.sendall(servers.ws_frame(b"msg %d" % i, mask=True))
        assert servers.ws_read(s) == (1, b"echo:msg %d" % i)
    s.sendall(servers.ws_frame(b"\x00\xffbin", opcode=2, mask=True))
    assert servers.ws_read(s) == (2, b"echo:\x00\xffbin")
    s.sendall(servers.ws_frame(b"\x03\xe8bye", opcode=8, mask=True))
    servers.ws_read(s)
    s.close()
    time.sleep(0.5)
    proxy.stop()
    flow = proxy.rows("SELECT resp_capture, ws_message_count, ws_close_code, ws_close_reason, end_reason, session, tool FROM m2c.http_flows")[0]
    assert flow == {"resp_capture": "websocket", "ws_message_count": 12, "ws_close_code": 1000, "ws_close_reason": "bye",
                    "end_reason": "ws_closed", "session": "ws1", "tool": "wsclient"}
    msgs = proxy.rows("SELECT seq, from_client, opcode, hex(content) AS c FROM m2c.ws_messages ORDER BY seq")
    assert len(msgs) == 12
    assert msgs[0] == {"seq": 1, "from_client": True, "opcode": "text", "c": b"msg 0".hex().upper()}
    assert msgs[11]["c"] == b"echo:\x00\xffbin".hex().upper() and msgs[11]["opcode"] == "binary"


def test_shutdown_records_open_streams(proxy, upstream):
    tok = proxy.token("ws1")
    s = _ws_session(proxy, upstream, tok, [])
    s.sendall(servers.ws_frame(b"hello", mask=True))
    servers.ws_read(s)
    time.sleep(1.2)
    assert proxy.stop(signal.SIGINT) == 0
    s.close()
    flow = proxy.rows("SELECT end_reason, ws_message_count, duration_ms FROM m2c.http_flows")[0]
    assert (flow["end_reason"], flow["ws_message_count"]) == ("proxy_shutdown", 2)
    assert flow["duration_ms"] >= 1000, "an open socket lasts until the shutdown, not until its handshake"
    assert proxy.rows("SELECT count() AS c FROM m2c.proxy_events WHERE kind = 'stopped'")[0]["c"] == 1


def test_restart_continues_numbering(tmp_path, upstream):
    from conftest import Proxy

    p = Proxy(tmp_path)
    tok = p.token("r1")
    curl(p.url("r1.curl", tok), f"http://127.0.0.1:{upstream}/hello")
    p.stop()
    p = Proxy(tmp_path)
    curl(p.url("r1.curl", tok), f"http://127.0.0.1:{upstream}/hello")
    p.stop()
    rows = p.rows("SELECT n, scan_id FROM m2c.http_flows ORDER BY n")
    assert [r["n"] for r in rows] == [1, 2] and rows[0]["scan_id"] == rows[1]["scan_id"]


def test_non_ascii_password_is_refused(proxy, upstream):
    # Regression: compare_digest raised TypeError on non-ASCII, and the hook guard let the request through unrecorded.
    import base64 as b64

    for raw in ("run1.curl:v1.0.é".encode(), b"run1.curl:v1.0.\xff"):
        s = socket.create_connection(("127.0.0.1", proxy.port), 5)
        s.sendall(b"GET http://127.0.0.1:%d/hello HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic %s\r\n\r\n" % (upstream, b64.b64encode(raw)))
        assert s.recv(100).startswith(b"HTTP/1.1 407"), raw
        s.close()
        s = socket.create_connection(("127.0.0.1", proxy.port), 5)
        s.sendall(b"CONNECT 127.0.0.1:%d HTTP/1.1\r\nHost: x\r\nProxy-Authorization: Basic %s\r\n\r\n" % (upstream, b64.b64encode(raw)))
        assert s.recv(100).startswith(b"HTTP/1.1 407"), raw
        s.close()
    proxy.stop()
    assert proxy.rows("SELECT count() AS c FROM m2c.http_flows")[0]["c"] == 0
    assert proxy.rows("SELECT count() AS c FROM m2c.proxy_events WHERE kind = 'auth_rejected'")[0]["c"] == 4


def test_shutdown_records_every_flow_in_flight(proxy, upstream):
    tok = proxy.token("fl1")
    url = proxy.url("fl1.curl", tok)
    up = f"http://127.0.0.1:{upstream}"
    assert curl(url, up + "/hello").returncode == 0
    waiting = subprocess.Popen(["curl", "-sS", "-x", url, up + "/slow-headers?wait=20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stream = subprocess.Popen(["curl", "-sSN", "-x", url, up + "/slow-sse?count=100"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(1.5)
    assert proxy.stop() == 0
    waiting.kill()
    stream.kill()
    flows = proxy.rows("SELECT n, path, end_reason, status, resp_capture, sse_event_count FROM m2c.http_flows ORDER BY path")
    assert [(f["path"], f["end_reason"]) for f in flows] == [
        ("/hello", "complete"), ("/slow-headers?wait=20", "proxy_shutdown"), ("/slow-sse?count=100", "proxy_shutdown")]
    assert (flows[1]["status"], flows[1]["resp_capture"]) == (0, "none")
    assert flows[2]["resp_capture"] == "sse" and flows[2]["sse_event_count"] >= 2
    # events stop with the flow's row: none arrive later, numbered past its count
    seqs = proxy.rows(f"SELECT count() AS c, max(seq) AS m FROM m2c.sse_events WHERE n = {flows[2]['n']}")[0]
    assert seqs == {"c": flows[2]["sse_event_count"], "m": flows[2]["sse_event_count"]}
    # the stopped event is written after the final flush: its counters are the run's totals
    counters = proxy.rows("SELECT counters FROM m2c.proxy_events WHERE kind = 'stopped'")[0]["counters"]
    assert counters["written.http_flows"] == 3 and counters.get("dropped.http_flows", 0) == 0


def test_kill9_never_reuses_flow_numbers(tmp_path, upstream):
    from conftest import Proxy

    p = Proxy(tmp_path)
    tok = p.token("k1")
    up = f"http://127.0.0.1:{upstream}"
    curl(p.url("k1.curl", tok), up + "/hello")
    stream = subprocess.Popen(["curl", "-sSN", "-x", p.url("k1.curl", tok), up + "/slow-sse?count=100"], stdout=subprocess.PIPE)
    stream.stdout.readline()
    time.sleep(2)  # SSE rows are written while the stream is open; its http_flows row is not
    p.stop(signal.SIGKILL)
    stream.kill()
    p = Proxy(tmp_path)
    curl(p.url("k1.curl", tok), up + "/hello?second")
    p.stop()
    sse_n = {r["n"] for r in p.rows("SELECT DISTINCT n FROM m2c.sse_events")}
    second = p.rows("SELECT n FROM m2c.http_flows WHERE path = '/hello?second'")[0]["n"]
    assert sse_n and second > max(sse_n), (second, sse_n)


def test_client_replay_reaches_upstream_and_keeps_identity(tmp_path, upstream):
    from conftest import Proxy

    marker = tmp_path / "replayed"
    addon = tmp_path / "replayer.py"
    addon.write_text(
        "from mitmproxy import ctx, http\n"
        "class Replayer:\n"
        "    last = None\n"
        "    def response(self, flow):\n"
        "        if flow.is_replay:\n"
        f"            open({str(marker)!r}, 'w').write(str(flow.response.status_code))\n"
        "        elif flow.request.path == '/hello':\n"
        "            self.last = flow\n"
        "    def request(self, flow):\n"
        "        if flow.request.path == '/__replay':\n"
        "            ctx.master.commands.call('replay.client', [self.last])\n"
        "            flow.response = http.Response.make(200, b'queued')\n"
        "addons = [Replayer()]\n"
    )
    dump = tmp_path / "flows.mitm"
    p = Proxy(tmp_path, extra=["--", "-s", str(addon), "-w", str(dump)])
    tok = p.token("rp1")
    url = p.url("rp1.curl", tok)
    assert curl(url, f"http://127.0.0.1:{upstream}/hello").stdout == b"hello world\n"
    curl(url, f"http://127.0.0.1:{upstream}/__replay")
    deadline = time.time() + 10
    while not (marker.exists() and marker.read_text()) and time.time() < deadline:
        time.sleep(0.1)
    assert marker.read_text() == "200", "the replay got a local 407 instead of the upstream's answer"
    p.stop()
    rows = p.rows("SELECT status, is_replay, session, tool FROM m2c.http_flows WHERE path = '/hello' ORDER BY n")
    assert rows == [{"status": 200, "is_replay": False, "session": "rp1", "tool": "curl"},
                    {"status": 200, "is_replay": True, "session": "rp1", "tool": "curl"}]
    assert p.rows("SELECT count() AS c FROM m2c.proxy_events WHERE kind = 'auth_rejected'")[0]["c"] == 0
    # -w works: the flows' metadata only holds plain values
    from mitmproxy import io

    with open(dump, "rb") as f:
        saved = [fl for fl in io.FlowReader(f).stream() if fl.request.path == "/hello"]
    assert saved and saved[0].metadata["m2c"]["session"] == "rp1" and saved[0].metadata["m2c"]["n"] == 1


def test_h2_upload_without_content_length_to_http1_upstream(proxy, tmp_path):
    srv, port = servers.start_tls(str(tmp_path))
    try:
        tok = proxy.token("h2u")
        payload = tmp_path / "payload"
        payload.write_bytes(b"p" * 300_000)
        res = subprocess.run(f"cat {payload} | curl -sS -k --http2 -x {proxy.url('h2u.curl', tok)} -T - https://127.0.0.1:{port}/upload",
                             shell=True, capture_output=True, timeout=30)
        assert res.stdout == b"got 300000\n", res.stderr
    finally:
        srv.shutdown()
    proxy.stop()
    row = proxy.rows("SELECT method, status, req_body_size, error FROM m2c.http_flows")[0]
    assert row == {"method": "PUT", "status": 200, "req_body_size": 300000, "error": ""}


def test_connect_to_unreachable_upstream_fails_at_connect(proxy):
    # m2c proxy uses connection_strategy=eager: the CONNECT itself fails (lazy would answer 200 to any host).
    tok = proxy.token("cx1")
    closed = servers.free_port()
    auth = base64.b64encode(f"cx1.curl:{tok}".encode()).decode()
    s = socket.create_connection(("127.0.0.1", proxy.port), 10)
    s.sendall(f"CONNECT 127.0.0.1:{closed} HTTP/1.1\r\nHost: 127.0.0.1:{closed}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
    assert s.recv(100).startswith(b"HTTP/1.1 502")
    s.close()
    proxy.stop()
    assert proxy.rows("SELECT count() AS c FROM m2c.http_flows")[0]["c"] == 0
    ev = proxy.rows("SELECT session, tool, port FROM m2c.proxy_events WHERE kind = 'connect_error'")
    assert ev == [{"session": "cx1", "tool": "curl", "port": closed}]
