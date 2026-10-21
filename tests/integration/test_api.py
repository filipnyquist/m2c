import json
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

import servers

pytestmark = pytest.mark.integration


def api(proxy, path, token=None, data=None, host=None):
    info = json.loads((proxy.data / "api.json").read_text())
    req = urllib.request.Request(info["url"] + path, data=data, method="POST" if data is not None else "GET")
    req.add_header("Authorization", f"Bearer {token or info['token']}")
    if host:
        req.add_header("Host", host)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(req, timeout=10) as res:
            return res.status, res.headers, res.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


@pytest.fixture
def traffic(proxy, upstream):
    toks = {s: proxy.token(s) for s in ("alice", "bob")}
    up = f"http://127.0.0.1:{upstream}"
    for s in ("alice", "bob"):
        for path in ("/hello", "/bin", "/sse"):
            subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url(f"{s}.curl", toks[s]), up + path], check=True)
    time.sleep(0.6)  # one flush interval
    return toks


def test_flows_detail_body_and_scoping(proxy, traffic):
    status, _, body = api(proxy, "/v1/flows?q=session:alice&order=asc")
    flows = json.loads(body)["flows"]
    assert status == 200 and [f["path"] for f in flows] == ["/hello", "/bin", "/sse"]
    n_bin = flows[1]["n"]
    status, headers, body = api(proxy, f"/v1/flows/{n_bin}/body/resp")
    assert body == servers.BINARY and headers["Content-Type"] == "application/octet-stream"
    assert headers["X-M2C-Content-Type"] == "application/octet-stream" and "sandbox" in headers["Content-Security-Policy"]
    # bob's session token sees only bob
    scoped = f"bob:{traffic['bob']}"
    status, _, body = api(proxy, "/v1/flows", token=scoped)
    assert {f["session"] for f in json.loads(body)["flows"]} == {"bob"}
    assert api(proxy, f"/v1/flows/{n_bin}", token=scoped)[0] == 404
    assert api(proxy, "/v1/sql", token=scoped, data=b"SELECT 1")[0] == 403
    assert api(proxy, "/v1/events", token=scoped)[0] == 403
    assert api(proxy, "/v1/flows", token=f"bob:{traffic['alice']}")[0] == 401
    assert api(proxy, "/v1/flows", token="nope")[0] == 401
    assert api(proxy, "/v1/flows", host="evil.example:8124")[0] == 421


def test_sql_is_readonly(proxy, traffic):
    status, _, body = api(proxy, "/v1/sql?format=JSONEachRow", data=b"SELECT count() AS c FROM m2c.http_flows")
    assert status == 200 and json.loads(body)["c"] == 6
    for sql in (b"INSERT INTO m2c.proxy_events (kind) VALUES ('x')", b"DROP TABLE m2c.http_flows",
                b"SELECT * FROM file('/etc/passwd', 'LineAsString')", b"SET readonly = 0"):
        status, _, body = api(proxy, "/v1/sql", data=sql)
        assert status == 400 and b"readonly" in body.lower(), sql


def test_tail_streams_new_flows(proxy, traffic, upstream):
    info = json.loads((proxy.data / "api.json").read_text())
    tail = subprocess.Popen(
        ["curl", "-sN", "--noproxy", "*", "-H", f"Authorization: Bearer {info['token']}", info["url"] + "/v1/tail?q=tool:late"],
        stdout=subprocess.PIPE,
    )
    time.sleep(0.5)
    t0 = time.time()
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("alice.late", traffic["alice"]), f"http://127.0.0.1:{upstream}/hello"], check=True)
    kind = None
    while True:
        line = tail.stdout.readline()
        if line.startswith(b"event:"):
            kind = line[6:].strip()
        elif line.startswith(b"data:") and kind == b"flow":
            item = json.loads(line[5:])
            break
    elapsed = time.time() - t0
    tail.kill()
    assert item["tool"] == "late" and item["path"] == "/hello"
    assert elapsed < 0.5


def test_mcp_http_and_stdio(proxy, traffic):
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2025-06-18", "capabilities": {}}}
    status, _, body = api(proxy, "/mcp", data=json.dumps(init).encode())
    assert status == 200 and json.loads(body)["result"]["serverInfo"]["name"] == "m2c"
    assert api(proxy, "/mcp", data=json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode())[0] == 202
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "traffic_search", "arguments": {"query": "path:/sse"}}}
    result = json.loads(json.loads(api(proxy, "/mcp", data=json.dumps(call).encode())[2])["result"]["content"][0]["text"])
    assert len(result["flows"]) == 2
    n = result["flows"][0]["n"]
    # stdio shim, scoped: no SQL tool, only bob's flows
    msgs = [
        init,
        {"jsonrpc": "2.0", "id": 3, "method": "tools/list"},
        {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "traffic_get", "arguments": {"n": n, "max_bytes": 40}}},
        {"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "traffic_sse", "arguments": {"n": n, "limit": 3}}},
    ]
    out = subprocess.run(
        [str(__import__("conftest").M2C), "mcp", "--token", f"bob:{traffic['bob']}", "--api", json.loads((proxy.data / "api.json").read_text())["url"]],
        input="\n".join(json.dumps(m) for m in msgs) + "\n", capture_output=True, text=True, env=proxy.env, check=True,
        executable=None,
    ).stdout.splitlines()
    replies = {json.loads(line)["id"]: json.loads(line) for line in out}
    assert "traffic_sql" not in {t["name"] for t in replies[3]["result"]["tools"]}
    flow = json.loads(replies[4]["result"]["content"][0]["text"])
    if flow == f"no flow #{n}":
        pytest.fail("scoped MCP could not see its own flow")
    assert flow["session"] == "bob" or flow.startswith("no flow")
    body = flow["resp_body"]
    assert len(body["text"]) <= 40 and "cut" in body
    events = json.loads(replies[5]["result"]["content"][0]["text"])
    assert [e["seq"] for e in events] == [1, 2, 3]


def test_mcp_http_malformed_payloads_are_jsonrpc_errors(proxy):
    for body, code in ((b"{not json", -32700), (b"{\"a\": \"\x80\"}", -32700), (b"[]", -32600)):
        status, _, reply = api(proxy, "/mcp", data=body)
        assert status == 400 and json.loads(reply)["error"]["code"] == code, body
    batch = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, 7, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": []}]
    status, _, reply = api(proxy, "/mcp", data=json.dumps(batch).encode())
    replies = json.loads(reply)
    assert status == 200 and len(replies) == 3 and "tools" in replies[0]["result"]
    assert [r["error"]["code"] for r in replies[1:]] == [-32600, -32602]


def test_ui_served(proxy):
    info = json.loads((proxy.data / "api.json").read_text())
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(info["url"] + "/ui/", timeout=5) as res:
        page = res.read()
        assert b"m2c traffic" in page and "frame-ancestors 'none'" in res.headers["Content-Security-Policy"]


def test_live_open_flow_and_child_events(proxy, upstream):
    tok = proxy.token("live")
    info = json.loads((proxy.data / "api.json").read_text())
    auth = ["--noproxy", "*", "-H", f"Authorization: Bearer {info['token']}"]
    tail = subprocess.Popen(["curl", "-sN", *auth, info["url"] + "/v1/tail?q=session:live"], stdout=subprocess.PIPE)
    time.sleep(0.4)
    stream = subprocess.Popen(["curl", "-sN", "-o", "/dev/null", "-x", proxy.url("live.agent", tok), f"http://127.0.0.1:{upstream}/slow-sse?count=6"])

    def next_event(p):
        kind, data = None, None
        while True:
            line = p.stdout.readline().decode().rstrip("\n")
            if line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("data:"):
                data = json.loads(line[5:])
            elif not line and kind:
                return kind, data

    kind, item = next_event(tail)
    while kind == "stats":
        kind, item = next_event(tail)
    assert kind == "open" and item["open"] and item["resp_capture"] == "sse"
    n = item["n"]
    flow_live = subprocess.Popen(["curl", "-sN", *auth, info["url"] + f"/v1/flows/{n}/live"], stdout=subprocess.PIPE)
    assert next_event(flow_live)[0] == "open"
    kinds = []
    while True:
        k, data = next_event(flow_live)
        kinds.append(k)
        if k == "end":
            break
        assert data["data"].startswith("slow ")
    assert kinds.count("sse") >= 3 and data["n"] == n and data["sse_event_count"] == 6
    stream.wait(10)
    while kind != "flow":
        kind, item = next_event(tail)
    assert item["n"] == n and item["sse_event_count"] == 6
    tail.kill()
    flow_live.kill()


class Sse:
    """An SSE stream read by curl on a thread: next() gives (event, data, id)."""

    def __init__(self, proxy, path, token=None):
        import queue
        import threading

        info = json.loads((proxy.data / "api.json").read_text())
        self.proc = subprocess.Popen(
            ["curl", "-sN", "--noproxy", "*", "-H", f"Authorization: Bearer {token or info['token']}", info["url"] + path], stdout=subprocess.PIPE
        )
        self.events = queue.Queue()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        kind, data, eid = None, None, None
        for raw in self.proc.stdout:
            line = raw.decode().rstrip("\n")
            if line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("data:"):
                data = json.loads(line[5:])
            elif line.startswith("id:"):
                eid = line[3:].strip()
            elif not line and kind:
                self.events.put((kind, data, eid))
                kind, data, eid = None, None, None
        self.events.put(None)

    def next(self, kinds=("flow",), timeout=10):
        deadline = time.time() + timeout
        while True:
            ev = self.events.get(timeout=max(0.01, deadline - time.time()))
            if ev is None or ev[0] in kinds:
                return ev

    def close(self):
        self.proc.kill()


def curl_via(proxy, user, tok, url):
    return subprocess.Popen(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url(user, tok), url])


def test_db_filtered_tail_delivers_flows_in_finish_order(proxy, upstream):
    # body: needs the database. The slow SSE flow starts first (smaller n) and finishes after /hello.
    tok = proxy.token("ooo")
    tail = Sse(proxy, "/v1/tail?q=" + urllib.parse.quote("session:ooo body:o"))
    assert tail.next(("stats",))[0] == "stats"
    slow = curl_via(proxy, "ooo.a", tok, f"http://127.0.0.1:{upstream}/slow-sse?count=6")
    time.sleep(0.5)
    curl_via(proxy, "ooo.b", tok, f"http://127.0.0.1:{upstream}/hello").wait(10)
    slow.wait(10)
    got = [tail.next(timeout=8)[1] for _ in range(2)]
    tail.close()
    assert [f["path"] for f in got] == ["/hello", "/slow-sse?count=6"] and got[0]["n"] > got[1]["n"]


def test_tail_resumes_from_its_last_event_id(proxy, upstream):
    tok = proxy.token("res")
    tail = Sse(proxy, "/v1/tail?q=session:res")
    _, _, cursor = tail.next(("stats",))
    tail.close()
    for path in ("/hello", "/bin"):
        curl_via(proxy, "res.x", tok, f"http://127.0.0.1:{upstream}{path}").wait(10)
    again = Sse(proxy, "/v1/tail?q=session:res&since=" + cursor)
    assert [again.next()[1]["path"] for _ in range(2)] == ["/hello", "/bin"]
    again.close()
    stale = Sse(proxy, "/v1/tail?since=0123abcd.5")  # another process's cursor
    assert stale.next(("resync", "flow"))[0] == "resync"
    stale.close()


def test_db_filtered_tails_are_limited_per_token(proxy):
    tok = proxy.token("lim")
    tails = [Sse(proxy, "/v1/tail?q=body:x", token=f"lim:{tok}") for _ in range(2)]
    for t in tails:
        assert t.next(("stats",))[0] == "stats"
    assert api(proxy, "/v1/tail?q=body:x", token=f"lim:{tok}")[0] == 429
    for t in tails:
        t.close()


def test_slow_sql_does_not_block_listing(proxy, traffic):
    import threading

    done = []
    slow = [threading.Thread(target=lambda: done.append(api(proxy, "/v1/sql", data=b"SELECT sleep(2)")[0])) for _ in range(3)]
    for t in slow:
        t.start()
    time.sleep(0.3)
    t0 = time.time()
    status, _, _ = api(proxy, "/v1/flows?limit=1")
    assert status == 200 and time.time() - t0 < 1.5
    for t in slow:
        t.join()
    assert done == [200, 200, 200]


def test_bad_tokens_and_filters_are_4xx_and_scoped_stats_stay_scoped(proxy, traffic):
    assert api(proxy, "/v1/scan", token="run1:v1.0.\xe9")[0] == 401
    assert api(proxy, "/v1/scan", token="\xe9" * 32)[0] == 401
    for q in ("n:abc", "n:5-", "n:1|x"):
        assert api(proxy, "/v1/tail?q=" + urllib.parse.quote(q))[0] == 400, q
    scoped = json.loads(api(proxy, "/v1/scan", token=f"bob:{traffic['bob']}")[2])
    assert scoped["flows"] == 3 and "live_ring" not in scoped
    bob_max = max(f["n"] for f in json.loads(api(proxy, "/v1/flows?q=session:bob")[2])["flows"])
    assert scoped["last_n"] == bob_max
    tail = Sse(proxy, "/v1/tail", token=f"bob:{traffic['bob']}")
    _, stats, _ = tail.next(("stats",))
    tail.close()
    assert "last_n" not in stats and "queued" not in stats


def test_api_hosts_keeps_loopback_and_healthz(tmp_path):
    from conftest import Proxy

    p = Proxy(tmp_path, env={"M2C_API_HOSTS": "m2c.internal"})
    try:
        info = json.loads((p.data / "api.json").read_text())
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        assert opener.open(info["url"] + "/healthz", timeout=5).status == 200
        assert api(p, "/v1/scan", host="m2c.internal:8124")[0] == 200
        assert api(p, "/v1/scan", host="evil.example:8124")[0] == 421
        assert "scan_id" in p.m2c("stats")
    finally:
        p.stop()


def test_out_of_range_numbers_are_4xx_not_wrapped(proxy, traffic):
    # chDB wraps an out-of-range UInt64 parameter (n = 2^64 + 5 would read flow 5): never pass one through
    n = json.loads(api(proxy, "/v1/flows?limit=1")[2])["flows"][0]["n"]
    assert api(proxy, f"/v1/flows/{(1 << 64) + n}")[0] == 404
    assert api(proxy, f"/v1/flows/{(1 << 64) + n}/curl")[0] == 404
    assert api(proxy, f"/v1/flows?q=n:{(1 << 64) + n}")[0] == 400
    for path in ("/v1/flows?cursor=-1", f"/v1/flows?cursor={1 << 64}", f"/v1/flows/{n}/sse?after={1 << 32}", f"/v1/flows/{n}/body/resp?max=-5"):
        assert api(proxy, path)[0] == 400, path
    for q in ("n:\u00b2", "after:" + "9" * 400 + "d"):
        assert api(proxy, "/v1/tail?q=" + urllib.parse.quote(q))[0] == 400, q
        assert api(proxy, "/v1/flows?q=" + urllib.parse.quote(q))[0] == 400, q
