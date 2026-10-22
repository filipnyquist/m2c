import json
import os
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

import pytest

import servers

pytestmark = pytest.mark.integration


def api(proxy, path, token=None, data=None, host=None, headers=None):
    info = json.loads((proxy.data / "api.json").read_text())
    req = urllib.request.Request(info["url"] + path, data=data, method="POST" if data is not None else "GET")
    req.add_header("Authorization", f"Bearer {token or info['token']}")
    if host:
        req.add_header("Host", host)
    for k, v in (headers or {}).items():
        req.add_header(k, v)
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
    assert api(proxy, "/v1/sql", data=b"SELECT 1")[0] == 404  # there is no raw SQL
    assert api(proxy, "/v1/events", token=scoped)[0] == 200  # its own events only (test_mcp_live_tools)
    assert api(proxy, "/v1/flows", token=f"bob:{traffic['alice']}")[0] == 401
    assert api(proxy, "/v1/flows", token="nope")[0] == 401
    assert api(proxy, "/v1/flows", host="evil.example:8124")[0] == 421


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
    call = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "traffic_search", "arguments": {"query": "path:/sse", "format": "json"}}}
    result = json.loads(json.loads(api(proxy, "/mcp", data=json.dumps(call).encode())[2])["result"]["content"][0]["text"])
    assert len(result["flows"]) == 2
    n = result["flows"][0]["n"]
    # stdio shim, scoped: only bob's flows
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
    assert not replies[4]["result"]["isError"], "scoped MCP could not see its own flow"
    flow = json.loads(replies[4]["result"]["content"][0]["text"])
    assert flow["session"] == "bob" and replies[4]["result"]["structuredContent"]["n"] == n
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
        csp = res.headers["Content-Security-Policy"]
        assert b"m2c traffic" in page and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp and "script-src 'self'" in csp
        assert res.headers["Cache-Control"] == "no-cache" and res.headers["ETag"]
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(info["url"] + "/ui/app.js", timeout=5) as res:
        assert res.headers["Content-Type"].startswith("text/javascript") and b"import" in res.read()


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


def test_filter_help_stats_vocabulary_and_mcp_session_flag(proxy, traffic, upstream):
    scoped = f"bob:{traffic['bob']}"
    status, _, body = api(proxy, "/v1/filter-help", token=scoped)
    help_ = json.loads(body)
    assert status == 200 and {"has", "grpc", "gstatus", "source"} <= {k["key"] for k in help_["keys"]} and "has:" in help_["text"]
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("bob.curl", traffic["bob"]), f"http://127.0.0.1:{upstream}/status/404"])
    time.sleep(0.6)
    stats = json.loads(api(proxy, "/v1/scan", token=scoped)[2])
    assert (stats["errors"], stats["failures"], stats["transport_errors"]) == (0, 1, 0)
    assert len(json.loads(api(proxy, "/v1/flows?q=has:fail", token=scoped)[2])["flows"]) == 1
    # `m2c mcp --session bob` mints bob's token from the secret: scoped
    msgs = [{"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "traffic_search", "arguments": {"limit": 50, "format": "json"}}}]
    run = subprocess.run([str(__import__("conftest").M2C), "mcp", "--session", "bob"], input="\n".join(json.dumps(m) for m in msgs) + "\n",
                         capture_output=True, text=True, env=proxy.env, check=True)
    replies = {json.loads(line)["id"]: json.loads(line) for line in run.stdout.splitlines()}
    assert {f["session"] for f in json.loads(replies[2]["result"]["content"][0]["text"])["flows"]} == {"bob"}
    assert "admin" not in run.stderr
    admin = subprocess.run([str(__import__("conftest").M2C), "mcp"], input="", capture_output=True, text=True, env=proxy.env, check=True)
    assert "serving as admin" in admin.stderr


def mcp_call(proxy, name, args, token=None, headers=None):
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
    status, _, body = api(proxy, "/mcp", token=token, data=json.dumps(msg).encode(), headers=headers)
    return status, json.loads(body)


def test_mcp_live_tools(proxy, traffic, upstream):
    scoped = f"bob:{traffic['bob']}"
    up = f"http://127.0.0.1:{upstream}"

    def later(delay, *curl):
        time.sleep(delay)
        subprocess.run(["curl", "-sS", "-o", "/dev/null", *curl], check=False)

    # traffic_wait returns a request made while it waits (it waits on the event loop: the proxy keeps working)
    threading.Thread(target=later, args=(0.3, "-x", proxy.url("bob.waiter", traffic["bob"]), up + "/hello")).start()
    t0 = time.time()
    _, reply = mcp_call(proxy, "traffic_wait", {"query": "tool:waiter", "timeout": 8, "lookback": 0}, token=scoped)
    got = reply["result"]["structuredContent"]
    assert [f["tool"] for f in got["flows"]] == ["waiter"] and not got["timed_out"] and time.time() - t0 < 3

    # a stream still running: traffic_get says pending, and traffic_wait 'n:N' returns when it ends
    stream = threading.Thread(target=later, args=(0, "-x", proxy.url("bob.streamer", traffic["bob"]), up + "/slow-sse?count=4"))
    stream.start()
    time.sleep(0.8)
    n = json.loads(api(proxy, "/v1/scan")[2])["last_n"]
    _, reply = mcp_call(proxy, "traffic_get", {"n": n}, token=scoped)
    pending = reply["result"]["structuredContent"]
    assert pending["pending"] is True and pending["tool"] == "streamer" and "traffic_wait" in pending["note"]
    assert mcp_call(proxy, "traffic_get", {"n": n}, token=f"alice:{traffic['alice']}")[1]["result"]["isError"]
    _, reply = mcp_call(proxy, "traffic_wait", {"query": f"n:{n}", "timeout": 8}, token=scoped)
    assert [f["n"] for f in reply["result"]["structuredContent"]["flows"]] == [n]
    stream.join()

    # traffic_events: bob sees a rejected attempt that named bob, never alice's
    for user in ("bob.curl:wrong", "alice.curl:wrong"):
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", f"http://{user}@127.0.0.1:{proxy.port}", up + "/hello"], check=False)
    time.sleep(0.6)
    _, reply = mcp_call(proxy, "traffic_events", {"kind": "auth_rejected"}, token=scoped)
    events = json.loads(reply["result"]["content"][0]["text"])
    assert events and all(e["proxy_user"].startswith("bob.") and e["claimed"] for e in events)

    # Streamable HTTP rules: Origin, MCP-Protocol-Version, no batches from 2025-06-18
    info = json.loads((proxy.data / "api.json").read_text())
    assert mcp_call(proxy, "traffic_stats", {}, headers={"Origin": "http://evil.example"})[0] == 403
    assert mcp_call(proxy, "traffic_stats", {}, headers={"Origin": info["url"]})[0] == 200
    assert mcp_call(proxy, "traffic_stats", {}, headers={"MCP-Protocol-Version": "1999-01-01"})[0] == 400
    batch = json.dumps([{"jsonrpc": "2.0", "id": 1, "method": "ping"}]).encode()
    assert api(proxy, "/mcp", data=batch, headers={"MCP-Protocol-Version": "2025-11-25"})[0] == 400
    assert api(proxy, "/mcp", data=batch, headers={"MCP-Protocol-Version": "2025-03-26"})[0] == 200


def test_report_grep_and_diff(proxy, traffic, upstream):
    up = f"http://127.0.0.1:{upstream}"
    for body in ("x a.b(c y", "x aXb(c y"):  # a literal pattern with regex metacharacters must not match the second
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("bob.poster", traffic["bob"]), "-d", body, up + "/post"], check=True)
    time.sleep(0.6)
    scoped = f"bob:{traffic['bob']}"

    def get(path, token=None):
        status, _, body = api(proxy, path, token=token)
        return status, json.loads(body)

    q = urllib.parse.quote
    status, hits = get(f"/v1/grep?pattern={q('a.b(c')}&side=req")
    assert status == 200 and len(hits) == 1 and hits[0]["req_hits"] == ["x a.b(c y"] and hits[0]["tool"] == "poster"
    status, hits = get(f"/v1/grep?pattern={q('HEL+O')}&regex=1&side=resp&context=3")
    assert status == 200 and {h["session"] for h in hits} == {"alice", "bob"} and hits[0]["resp_hits"] == ["hello wo"]
    assert get(f"/v1/grep?pattern={q('hello')}&ci=0&q=path:/hello", token=scoped)[1][0]["session"] == "bob"
    assert {h["session"] for h in get(f"/v1/grep?pattern=hello", token=scoped)[1]} == {"bob"}
    assert get(f"/v1/grep?pattern={q('(')}&regex=1")[0] == 400
    status, events = get(f"/v1/grep?pattern=token&in=sse&q=session:alice")
    assert status == 200 and events and all(e["session"] == "alice" and e["hits"] for e in events)

    status, rep = get("/v1/report?by=tool")
    groups = {(g["session"], g["tool"]): g for g in rep["groups"]}
    assert groups[("alice", "curl")]["flows"] == 3 and groups[("alice", "curl")]["hosts"] == [["127.0.0.1", 3]]
    assert groups[("bob", "poster")]["statuses"] == {"200": 2} and groups[("bob", "poster")]["failures"] == 0
    assert len(groups[("alice", "curl")]["slowest"]) == 3
    assert {g["session"] for g in get("/v1/report?by=session", token=scoped)[1]["groups"]} == {"bob"}
    assert get("/v1/report?by=nope")[0] == 400

    flows = {f["path"]: f["n"] for f in get("/v1/flows?q=session:alice")[1]["flows"]}
    status, d = get(f"/v1/diff?a={flows['/hello']}&b={flows['/bin']}")
    assert status == 200 and d["same"] is False and d["request"]["url"][1].endswith("/bin")
    assert d["response"]["headers"]["changed"]["content-type"] == [["text/plain"], ["application/octet-stream"]]
    assert "sha256" in d["response"]["body"] or "unified" in d["response"]["body"]
    assert get(f"/v1/diff?a={flows['/hello']}&b={flows['/bin']}", token=scoped)[0] == 404  # alice's flows

    # the same through MCP and the CLI
    _, reply = mcp_call(proxy, "traffic_report", {"by": "tool", "query": "session:bob"})
    text = reply["result"]["content"][0]["text"]
    assert "bob/poster: 2 flows, 0 failed" in text and "status: 200x2" in text
    _, reply = mcp_call(proxy, "traffic_diff", {"a": flows["/hello"], "b": flows["/bin"]})
    assert reply["result"]["structuredContent"]["same"] is False
    m2c = str(__import__("conftest").M2C)
    out = subprocess.run([m2c, "grep", "a.b(c", "tool:poster"], capture_output=True, text=True, env=proxy.env, check=True).stdout
    assert "> x a.b(c y" in out and "aXb" not in out
    out = subprocess.run([m2c, "report", "--by", "call"], capture_output=True, text=True, env=proxy.env, check=True).stdout
    assert "alice/curl#-: 3 flows" in out
    out = subprocess.run([m2c, "diff", str(flows["/hello"]), str(flows["/bin"])], capture_output=True, text=True, env=proxy.env, check=True).stdout
    assert json.loads(out)["a"] == flows["/hello"]


def test_facets_and_suggestions(proxy, traffic, upstream):
    up = f"http://127.0.0.1:{upstream}"
    fuzz = proxy.url("bob.ffuf", traffic["bob"])
    for i in range(30):
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", fuzz, f"{up}/api/v{i % 2}/item{i}"], check=True)
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("bob.curl", traffic["bob"]), "-H", "Authorization: Bearer x",
                    up + "/hello"], check=True)
    time.sleep(0.6)
    scoped = f"bob:{traffic['bob']}"
    q = urllib.parse.quote

    def get(path, token=None):
        status, _, body = api(proxy, path, token=token)
        return status, json.loads(body)

    status, f = get("/v1/facets?key=tool")
    assert status == 200 and {v["value"]: v["count"] for v in f["values"]} == {"ffuf": 30, "curl": 7}
    assert {v["value"] for v in get("/v1/facets?key=session", token=scoped)[1]["values"]} == {"bob"}
    assert [v["value"] for v in get("/v1/facets?key=host&prefix=127")[1]["values"]] == ["127.0.0.1"]
    status_values = {v["value"]: v["count"] for v in get(f"/v1/facets?key=status&q={q('tool:ffuf')}")[1]["values"]}
    assert status_values == {"404": 30}
    paths = get("/v1/facets?key=path&q=tool:ffuf")[1]["values"]
    assert paths == [{"value": "/api", "count": 30, "deeper": True}]
    deeper = {v["value"]: v["count"] for v in get(f"/v1/facets?key=path&prefix={q('/api/')}")[1]["values"]}
    assert deeper == {"/api/v0": 15, "/api/v1": 15}
    hdrs = {v["value"] for v in get("/v1/facets?key=hdr&q=tool:curl", token=scoped)[1]["values"]}
    assert "authorization" in hdrs and "user-agent" in hdrs
    help_ = get("/v1/facets?key=has")[1]
    assert help_["values"] == [] and "fail" in help_["static"]
    assert get("/v1/facets?key=nope")[0] == 400

    status, s = get("/v1/suggest?q=session:bob", token=scoped)
    hints = {h["text"]: h for h in s["hints"]}
    noise = next(h for h in s["hints"] if h["kind"] == "exclude")
    assert status == 200 and s["total"] == 34 and noise["query"] == "session:bob -(tool:ffuf status:404)"
    assert "1 send credentials over plain HTTP" in hints
    assert len(get(f"/v1/flows?q={q(noise['query'])}&limit=100", token=scoped)[1]["flows"]) == 4
    assert get(f"/v1/suggest?q={q('(oops')}")[0] == 400
    _, reply = mcp_call(proxy, "traffic_suggest", {"query": "session:bob"}, token=scoped)
    assert "-(tool:ffuf status:404)" in reply["result"]["content"][0]["text"]


def test_activity_event_counts_and_fixes(proxy, traffic, upstream):
    up = f"http://127.0.0.1:{upstream}"
    t0 = int(time.time() * 1000)
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", f"http://bob.curl:wrong@127.0.0.1:{proxy.port}", up + "/hello"], check=False)
    time.sleep(0.6)
    scoped = f"bob:{traffic['bob']}"

    def get(path, token=None):
        status, _, body = api(proxy, path, token=token)
        return status, json.loads(body)

    status, act = get("/v1/activity?buckets=8")
    assert status == 200 and act["buckets"] == 8 and set(act["sessions"]) == {"alice", "bob"}
    assert sum(c for c, _ in act["sessions"]["alice"]) == 3 and len(act["sessions"]["bob"]) == 8
    assert set(get("/v1/activity", token=scoped)[1]["sessions"]) == {"bob"}
    assert get("/v1/activity?q=session:nobody")[1]["sessions"] == {}

    counts = {(c["kind"], c["severity"]): c for c in get(f"/v1/events/counts?since={t0}")[1]}
    rejected = counts[("auth_rejected", "warn")]
    assert rejected["count"] >= 1 and rejected["recent"] >= 1 and counts[("started", "info")]["recent"] == 0
    assert {c["kind"] for c in get("/v1/events/counts", token=scoped)[1]} == {"auth_rejected"}  # only bob's (claimed)
    status, events = get("/v1/events?severity=warn")
    assert status == 200 and events and all(e["severity"] == "warn" for e in events)
    assert "m2c mint bob" in next(e for e in events if e["kind"] == "auth_rejected")["fix"]
    assert get("/v1/events?severity=loud")[0] == 400

    groups = {g["session"]: g for g in get("/v1/report?by=session")[1]["groups"]}
    assert groups["alice"]["host_count"] == 1


def test_notes(proxy, traffic):
    alice, bob = f"alice:{traffic['alice']}", f"bob:{traffic['bob']}"
    flows = {(f["session"], f["path"]): f["n"] for f in json.loads(api(proxy, "/v1/flows?limit=50")[2])["flows"]}
    a_hello, b_hello = flows[("alice", "/hello")], flows[("bob", "/hello")]

    def call(method, path, body=None, token=None):
        info = json.loads((proxy.data / "api.json").read_text())
        req = urllib.request.Request(info["url"] + path, data=json.dumps(body).encode() if body is not None else None, method=method)
        req.add_header("Authorization", f"Bearer {token or info['token']}")
        try:
            with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=10) as res:
                raw = res.read()
                return res.status, json.loads(raw) if raw else None
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"null")

    # bob labels his own flow; it reads back at once, before any flush
    status, note = call("POST", f"/v1/flows/{b_hello}/notes", {"label": "Vuln", "note": "token reuse", "color": "red"}, bob)
    assert status == 201 and (note["label"], note["author"], note["author_kind"], note["session"]) == ("vuln", "bob", "session", "bob")
    assert [x["id"] for x in call("GET", f"/v1/flows/{b_hello}/notes", token=bob)[1]] == [note["id"]]
    # bob can't touch alice's flows; alice can't see bob's note; the admin sees and edits everything
    assert call("POST", f"/v1/flows/{a_hello}/notes", {"label": "x"}, bob)[0] == 404
    assert call("GET", f"/v1/notes?ns={b_hello}", token=alice)[1] == []
    assert call("PATCH", f"/v1/notes/{note['id']}", {"note": "mine"}, alice)[0] == 404
    status, admin_note = call("POST", f"/v1/flows/{a_hello}/notes", {"label": "todo"})
    assert status == 201 and admin_note["author"] == "admin"
    assert call("PATCH", f"/v1/notes/{admin_note['id']}", {"note": "bob may not"}, bob)[0] == 404  # not his session either
    assert call("POST", f"/v1/flows/{b_hello}/notes", {"label": "Not OK!"}, bob)[0] == 400
    status, edited = call("PATCH", f"/v1/notes/{note['id']}", {"note": "token reuse across sessions"}, bob)
    assert status == 200 and edited["label"] == "vuln" and edited["note"] == "token reuse across sessions"

    # once written: filters, label suggestions, ns lookups, MCP, the CLI
    time.sleep(0.6)
    assert [f["n"] for f in json.loads(api(proxy, "/v1/flows?q=label:vu*")[2])["flows"]] == [b_hello]
    assert [f["n"] for f in json.loads(api(proxy, "/v1/flows?q=" + urllib.parse.quote('note:"across"'))[2])["flows"]] == [b_hello]
    assert {f["n"] for f in json.loads(api(proxy, "/v1/flows?q=has:note")[2])["flows"]} == {a_hello, b_hello}
    assert {f["n"] for f in json.loads(api(proxy, "/v1/flows?q=has:note", token=bob)[2])["flows"]} == {b_hello}
    assert [v["value"] for v in json.loads(api(proxy, "/v1/facets?key=label")[2])["values"]] in (["todo", "vuln"], ["vuln", "todo"])
    assert [x["note"] for x in call("GET", f"/v1/notes?ns={a_hello},{b_hello}", token=bob)[1]] == ["token reuse across sessions"]
    _, reply = mcp_call(proxy, "traffic_get", {"n": b_hello, "include_bodies": False}, token=bob)
    assert reply["result"]["structuredContent"]["notes"][0]["label"] == "vuln"
    _, reply = mcp_call(proxy, "traffic_annotate", {"n": b_hello, "label": "checked"}, token=bob)
    assert reply["result"]["isError"] is False
    m2c = str(__import__("conftest").M2C)
    out = subprocess.run([m2c, "notes", "session:bob"], capture_output=True, text=True, env=proxy.env, check=True).stdout
    assert "[vuln] token reuse across sessions" in out and "[checked]" in out
    subprocess.run([m2c, "note", str(a_hello), "--delete", admin_note["id"][:8]], capture_output=True, text=True, env=proxy.env, check=True)
    assert call("GET", f"/v1/flows/{a_hello}/notes")[1] == []
    time.sleep(0.6)
    assert [f["n"] for f in json.loads(api(proxy, "/v1/flows?q=has:note")[2])["flows"]] == [b_hello]


def test_claude_code_hooks_tag_each_bash_call(proxy, upstream, tmp_path):
    """SessionStart writes the env file; PreToolUse (Bash) names the call; each command's requests carry its id; the
    timeline groups them. Nothing about the calls is recorded but their traffic."""
    m2c = str(__import__("conftest").M2C)
    env = {**proxy.env, "XDG_RUNTIME_DIR": str(tmp_path), "CLAUDE_ENV_FILE": str(tmp_path / "claude.env")}

    def hook(event, payload):
        subprocess.run([m2c, "hook", event, "--proxy", f"127.0.0.1:{proxy.port}"], input=json.dumps(payload), text=True, env=env, check=True)

    def bash(cmd):  # the test server is on localhost, which the proxy variables exempt: curl --noproxy '' overrides that
        cmd = cmd.replace("curl ", "curl --noproxy '' ")
        subprocess.run(["bash", "-c", f'source "{env["CLAUDE_ENV_FILE"]}"; {cmd}'], env={"PATH": os.environ["PATH"]}, check=True)

    up = f"http://127.0.0.1:{upstream}"
    hook("claude-code-session-start", {"session_id": "cc-1"})
    bash(f"curl -sS -o /dev/null {up}/hello")  # before any call: no call id
    hook("claude-code-pre-tool", {"session_id": "cc-1", "tool_name": "Bash", "tool_use_id": "toolu_A", "tool_input": {"command": "x"}})
    bash(f"curl -sS -o /dev/null {up}/hello && curl -sS -o /dev/null {up}/bin")
    hook("claude-code-pre-tool", {"session_id": "cc-1", "tool_name": "Read", "tool_use_id": "toolu_R", "tool_input": {"file_path": "/x"}})
    hook("claude-code-pre-tool", {"session_id": "cc-1", "tool_name": "Bash", "tool_use_id": "toolu_B", "tool_input": {"command": "y"}})
    bash(f'curl -sS -o /dev/null {up}/nope; [ "$M2C_SESSION" = cc-1 ] && [ -n "$M2C_API_TOKEN" ]')
    time.sleep(0.6)

    status, _, body = api(proxy, "/v1/timeline?session=cc-1")
    items = [(i["kind"], i.get("call_id"), [f["path"] for f in i["flows"]]) for i in json.loads(body)["items"]]
    assert status == 200 and items == [("between", None, ["/hello"]), ("call", "toolu_A", ["/hello", "/bin"]), ("call", "toolu_B", ["/nope"])]
    assert json.loads(api(proxy, "/v1/timeline/sessions")[2])[0]["session"] == "cc-1"
    tok = proxy.token("cc-1")
    assert api(proxy, "/v1/timeline?session=cc-1", token=f"cc-1:{tok}")[0] == 200
    assert api(proxy, "/v1/timeline?session=cc-1", token=f"other:{proxy.token('other')}")[0] == 403
    _, reply = mcp_call(proxy, "traffic_timeline", {}, token=f"cc-1:{tok}")
    assert "call toolu_B (bash): 1 flows, 1 failed" in reply["result"]["content"][0]["text"]
    assert not (proxy.data / "hooks.log").exists()
