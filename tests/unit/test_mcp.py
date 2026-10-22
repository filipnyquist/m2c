import io
import json

import pytest

from m2c.mcp import McpServer, serve_stdio


class FakeQueries:
    def stats(self):
        return {"flows": 1}

    scope = None

    def flow(self, n):
        if n != 1:
            return None
        return {"n": 1, "session": "s1", "req_body_stored": 0, "resp_body_stored": 5, "resp_body_size": 5, "resp_content_type": "text/plain",
                "req_headers": [["Authorization", "Bearer sekrit"], ["Accept", "*/*"]], "req_trailers": [],
                "resp_headers": [["Set-Cookie", "sid=1"]], "resp_trailers": []}

    def body(self, n, side, max_bytes=None):
        return (b"hello", "text/plain") if n == 1 else None

    def notes(self, ns=None, q="", ids=None, limit=1000):
        return []

    def hits(self, flt, ns):
        return {n: n % 2 == 0 for n in ns}

    def flows(self, q="", limit=50, cursor=None, order="desc"):
        self.last = (q, limit, cursor, order)
        return {"flows": [], "next": None}

    def sse(self, n, after, limit):
        return []

    def curl(self, n):
        return None


@pytest.fixture
def server():
    return McpServer(FakeQueries(), admin=False)


def call(name, arguments, mid=1):
    return {"jsonrpc": "2.0", "id": mid, "method": "tools/call", "params": {"name": name, "arguments": arguments}}


@pytest.mark.parametrize("msg, code", [
    (1, -32600),
    ("x", -32600),
    ([1], -32600),
    ({"jsonrpc": "2.0", "id": 1, "method": 5}, -32600),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": [1]}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "traffic_get", "arguments": [1]}}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ["traffic_get"]}}, -32602),
    ({"jsonrpc": "2.0", "id": 1, "method": "nope"}, -32601),
])
def test_malformed_messages_are_jsonrpc_errors(server, msg, code):
    reply = server.handle_sync(msg[0] if isinstance(msg, list) else msg)
    assert reply["error"]["code"] == code


@pytest.mark.parametrize("args", [{"n": None}, {"n": "x"}, {"n": [1]}, {}, {"n": 1, "max_bytes": None}])
def test_bad_argument_values_are_tool_errors(server, args):
    reply = server.handle_sync(call("traffic_get", args))
    assert reply["result"]["isError"] is True and reply["result"]["content"][0]["text"].startswith("error:")


def test_search_limit_null(server):
    assert server.handle_sync(call("traffic_search", {"limit": None}))["result"]["isError"] is True


def test_batch_survives_a_bad_element(server):
    replies = server.handle_sync([1, call("traffic_get", {"n": None}, 2), {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                                     {"jsonrpc": "2.0", "method": "notifications/initialized"}])
    assert [r["id"] for r in replies] == [None, 2, 3]
    assert replies[0]["error"]["code"] == -32600 and replies[1]["result"]["isError"] and replies[2]["result"] == {}


def test_empty_batch_is_invalid(server):
    assert server.handle_sync([])["error"]["code"] == -32600
    assert server.handle_sync([{"jsonrpc": "2.0", "method": "notifications/initialized"}]) is None


def _stdio(handle, lines: list[bytes]) -> list[dict]:
    out = io.StringIO()
    serve_stdio(handle, io.BytesIO(b"\n".join(lines) + b"\n"), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_stdio_keeps_serving_after_bad_input(server):
    replies = _stdio(server.handle_sync, [
        b"{not json",
        b"\xff\xfe",
        json.dumps(call("traffic_get", {"n": None}, 1)).encode(),
        json.dumps([{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]).encode(),
        json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/list"}).encode(),
    ])
    assert [r.get("error", {}).get("code") for r in replies[:2]] == [-32700, -32700]
    assert replies[2]["result"]["isError"] is True
    assert isinstance(replies[3], list) and replies[3][0]["id"] == 2
    assert replies[4]["id"] == 3 and replies[4]["result"]["tools"]


def test_stdio_turns_transport_failures_into_error_replies():
    def handle(msg):
        if msg.get("id") == 1:
            raise RuntimeError("500: cannot reach the API")
        return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}

    replies = _stdio(handle, [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode(),
                              json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode(),
                              json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}).encode()])
    assert replies == [{"jsonrpc": "2.0", "id": 1, "error": {"code": -32603, "message": "500: cannot reach the API"}},
                       {"jsonrpc": "2.0", "id": 2, "result": {}}]


def test_search_defaults_and_order(server):
    reply = server.handle_sync(call("traffic_search", {"query": "tool:x", "order": "asc"}))
    assert not reply["result"]["isError"] and server.q.last == ("tool:x", 20, None, "asc")
    assert server.handle_sync(call("traffic_search", {"order": "sideways"}))["result"]["isError"]


def test_tool_descriptions_document_every_filter_key(server):
    from m2c.filters import KEYS

    search = next(t for t in server.handle_sync({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]
                  if t["name"] == "traffic_search")
    for key in KEYS:
        assert f"{key}:" in search["description"]


def _text(reply):
    return reply["result"]["content"][0]["text"]


def test_get_redacts_credentials_and_returns_structured_content(server):
    result = server.handle_sync(call("traffic_get", {"n": 1}))["result"]
    flow = result["structuredContent"]
    assert json.loads(_text({"result": result})) == flow
    assert flow["req_headers"][0][1].startswith("<redacted len=13") and flow["req_headers"][1] == ["Accept", "*/*"]
    assert flow["resp_headers"][0][1].startswith("<redacted") and flow["resp_body"]["text"] == "hello"
    raw = json.loads(_text(server.handle_sync(call("traffic_get", {"n": 1, "redact": False, "headers": "names"}))))
    assert raw["req_headers"] == ["Authorization", "Accept"]
    assert server.handle_sync(call("traffic_get", {"n": 2}))["result"]["isError"]


def test_tool_specs_carry_titles_and_annotations(server):
    tools = {t["name"]: t for t in server.handle_sync({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]}
    assert "traffic_sql" not in tools and "traffic_wait" in tools  # no raw SQL, for anyone
    for t in tools.values():
        assert t["title"] and t["annotations"]["readOnlyHint"] is (t["name"] != "traffic_annotate") and t["inputSchema"]["type"] == "object"
    assert tools["traffic_wait"]["outputSchema"]["required"] == ["flows", "cursor", "timed_out"]


def test_search_lines_format_is_compact():
    class Q(FakeQueries):
        def flows(self, q="", limit=50, cursor=None, order="desc"):
            f = {"n": 9, "ts": 0, "session": "s", "tool": "curl", "call_id": "", "method": "GET", "status": 404, "error": "",
                 "resp_body_size": 3, "duration_ms": 4, "host": "h.test", "path": "/x", "resp_capture": "", "grpc": False}
            return {"flows": [f], "next": 9}

    text = _text(McpServer(Q(), admin=False).handle_sync(call("traffic_search", {})))
    lines = text.splitlines()
    assert len(lines) == 3 and "h.test/x" in lines[1] and "404" in lines[1] and "cursor=9" in lines[2]
    as_json = json.loads(_text(McpServer(Q(), admin=False).handle_sync(call("traffic_search", {"format": "json", "fields": ["n", "status"]}))))
    assert as_json["flows"] == [{"n": 9, "status": 404}]


def test_resources_and_prompts(server):
    def rpc(method, params):
        return server.handle_sync({"jsonrpc": "2.0", "id": 1, "method": method, "params": params})

    assert rpc("resources/templates/list", {})["result"]["resourceTemplates"][0]["uriTemplate"] == "m2c://flow/{n}"
    flow = json.loads(rpc("resources/read", {"uri": "m2c://flow/1"})["result"]["contents"][0]["text"])
    assert flow["n"] == 1 and "resp_body" not in flow and flow["req_headers"][0][1].startswith("<redacted")
    assert rpc("resources/read", {"uri": "m2c://flow/1/body/resp"})["result"]["contents"][0] == {
        "uri": "m2c://flow/1/body/resp", "mimeType": "text/plain", "text": "hello"}
    assert rpc("resources/read", {"uri": "m2c://flow/2"})["error"]["code"] == -32002
    assert rpc("resources/read", {"uri": "file:///etc/passwd"})["error"]["code"] == -32002
    names = {p["name"] for p in rpc("prompts/list", {})["result"]["prompts"]}
    assert names == {"investigate_failures", "summarize_run", "explain_flow"}
    text = rpc("prompts/get", {"name": "investigate_failures", "arguments": {"session": "run1"}})["result"]["messages"][0]["content"]["text"]
    assert "has:fail session:run1" in text
    assert rpc("prompts/get", {"name": "summarize_run", "arguments": {"session": "x y"}})["error"]["code"] == -32602
    assert rpc("prompts/get", {"name": "nope", "arguments": {}})["error"]["code"] == -32602


# ---------------------------------------------------------------------------- traffic_wait against a real LiveFeed


def _summary(n, **kw):
    import time as _t

    return {"n": n, "ts": int(_t.time() * 1000), "duration_ms": 1, "session": "s1", "tool": "curl", "call_id": "", "tag": "",
            "method": "GET", "host": "h.test", "path": "/", "url": "http://h.test/", "status": 200, "error": "", "error_kind": "",
            "resp_capture": "", "grpc": False, "grpc_status": -1, "ua_tool": "curl", "req_body_size": 0, "resp_body_size": 0, **kw}


class GuardedQueries(FakeQueries):
    """Fails a test that reads the database on the event loop instead of through ctx.db."""

    inside = False

    def __getattribute__(self, name):
        attr = object.__getattribute__(self, name)
        if not callable(attr) or name.startswith("_"):
            return attr

        def guarded(*args, **kw):
            if not object.__getattribute__(self, "inside"):
                raise AssertionError(f"Queries.{name} called outside ctx.db")
            return attr(*args, **kw)

        return guarded


def _wait_ctx(live, scope=None):
    from m2c.mcp_tools import Ctx

    q = GuardedQueries()
    object.__setattr__(q, "scope", scope)

    async def db(fn, *args, heavy=False):
        object.__setattr__(q, "inside", True)
        try:
            return fn(*args)
        finally:
            object.__setattr__(q, "inside", False)

    return Ctx(q, scope is None, db, live=live)


def test_wait_returns_a_flow_published_while_waiting():
    import asyncio
    import time as _t

    from m2c.live import LiveFeed
    from m2c.mcp_tools import t_wait

    async def main():
        live = LiveFeed()
        live.publish(_summary(1, tool="other"))
        loop = asyncio.get_running_loop()
        loop.call_later(0.05, live.publish, _summary(2, tool="other"))
        loop.call_later(0.1, live.publish, _summary(3))
        t0 = _t.monotonic()
        got = await t_wait(_wait_ctx(live), {"query": "tool:curl", "timeout": 5, "lookback": 0})
        assert [f["n"] for f in got["flows"]] == [3] and not got["timed_out"] and _t.monotonic() - t0 < 1
        # resume from the cursor: nothing new, so it times out quickly
        again = await t_wait(_wait_ctx(live), {"query": "tool:curl", "timeout": 0.1, "after": got["cursor"]})
        assert again["flows"] == [] and again["timed_out"]
        # lookback: a flow that finished just before the call counts
        live.publish(_summary(4))
        back = await t_wait(_wait_ctx(live), {"query": "tool:curl", "timeout": 0})
        assert [f["n"] for f in back["flows"]] == [3]  # the first match in the window; count=1
        many = await t_wait(_wait_ctx(live), {"query": "tool:curl", "timeout": 0, "count": 5})
        assert [f["n"] for f in many["flows"]] == [3, 4] and many["timed_out"]
        foreign = await t_wait(_wait_ctx(live), {"query": "", "timeout": 0.1, "after": "deadbeef.1"})
        assert "earlier proxy run" in foreign["notes"][0]
        scoped = await t_wait(_wait_ctx(live, scope="other"), {"query": "", "timeout": 0})
        assert scoped["flows"] == []
        assert live.subscribers == set()

    asyncio.run(main())


def test_wait_with_a_database_filter_checks_written_flows():
    import asyncio

    from m2c.live import LiveFeed
    from m2c.mcp_tools import t_wait

    async def main():
        live = LiveFeed()
        loop = asyncio.get_running_loop()
        for n in (5, 6):  # FakeQueries.hits: even n match
            loop.call_later(0.05, live.publish, _summary(n))
        got = await t_wait(_wait_ctx(live), {"query": 'body:"x"', "timeout": 2, "lookback": 0})
        assert [f["n"] for f in got["flows"]] == [6]

    asyncio.run(main())


def test_wait_offline_is_a_tool_error(server):
    reply = server.handle_sync(call("traffic_wait", {"query": ""}))
    assert reply["result"]["isError"] and "running proxy" in _text(reply)
