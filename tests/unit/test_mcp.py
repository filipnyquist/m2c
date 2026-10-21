import io
import json

import pytest

from m2c.mcp import McpServer, serve_stdio


class FakeQueries:
    def stats(self):
        return {"flows": 1}

    def flow(self, n):
        return None if n != 1 else {"n": 1, "req_body_stored": 0, "resp_body_stored": 0}

    def flows(self, q="", limit=50, cursor=None):
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
    reply = server.handle(msg[0] if isinstance(msg, list) else msg)
    assert reply["error"]["code"] == code


@pytest.mark.parametrize("args", [{"n": None}, {"n": "x"}, {"n": [1]}, {}, {"n": 1, "max_bytes": None}])
def test_bad_argument_values_are_tool_errors(server, args):
    reply = server.handle(call("traffic_get", args))
    assert reply["result"]["isError"] is True and reply["result"]["content"][0]["text"].startswith("error:")


def test_search_limit_null(server):
    assert server.handle(call("traffic_search", {"limit": None}))["result"]["isError"] is True


def test_batch_survives_a_bad_element(server):
    replies = server.handle_payload([1, call("traffic_get", {"n": None}, 2), {"jsonrpc": "2.0", "id": 3, "method": "ping"},
                                     {"jsonrpc": "2.0", "method": "notifications/initialized"}])
    assert [r["id"] for r in replies] == [None, 2, 3]
    assert replies[0]["error"]["code"] == -32600 and replies[1]["result"]["isError"] and replies[2]["result"] == {}


def test_empty_batch_is_invalid(server):
    assert server.handle_payload([])["error"]["code"] == -32600
    assert server.handle_payload([{"jsonrpc": "2.0", "method": "notifications/initialized"}]) is None


def _stdio(handle, lines: list[bytes]) -> list[dict]:
    out = io.StringIO()
    serve_stdio(handle, io.BytesIO(b"\n".join(lines) + b"\n"), out)
    return [json.loads(line) for line in out.getvalue().splitlines()]


def test_stdio_keeps_serving_after_bad_input(server):
    replies = _stdio(server.handle_payload, [
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
