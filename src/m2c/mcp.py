"""MCP server logic (JSON-RPC 2.0), transport-free: the API serves it at POST /mcp, `m2c mcp` over stdio.

Outputs are bounded so an agent's context doesn't fill up: lists are summaries, bodies are cut at `max_bytes`
(8 KiB by default) with a note on how to get more.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable

from . import __version__
from .filters import FilterError
from .queries import Forbidden, Queries

PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
FILTER_HELP = (
    "Filter syntax (terms are ANDed, `|` ORs values, `-` negates): session:<id> tool:<name> call:<id> tag:<t> "
    "host:*.example.com method:POST status:5xx|404|>=400 path:/api/* url:<text> ct:json ua:curl has:sse|ws|error|body "
    "err:timeout after:10m before:2026-10-21T12:00 n:100-200 body:\"needle\" and free text (matches the URL)."
)
TEXTY = ("text/", "application/json", "application/xml", "application/javascript", "application/x-www-form-urlencoded", "+json", "+xml", "ndjson", "event-stream", "graphql")


def _schema(props: dict, required=()) -> dict:
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


N = {"type": "integer", "description": "Flow number (#n) from traffic_search"}

TOOLS = [
    {
        "name": "traffic_stats",
        "description": "Totals for the recorded scan: flows, sessions, tools, hosts, errors, SSE events, WebSocket messages.",
        "inputSchema": _schema({}),
    },
    {
        "name": "traffic_sessions",
        "description": "Per session and tool: flows, failures, hosts, bytes, first and last seen. " + FILTER_HELP,
        "inputSchema": _schema({"query": {"type": "string", "description": "Optional filter"}}),
    },
    {
        "name": "traffic_search",
        "description": "List recorded HTTP flows (newest first) as summaries without bodies. " + FILTER_HELP,
        "inputSchema": _schema(
            {
                "query": {"type": "string", "description": "Filter, e.g. 'tool:curl status:5xx host:*.example.com'"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                "cursor": {"type": "integer", "description": "`next` from the previous page"},
            }
        ),
    },
    {
        "name": "traffic_get",
        "description": "One flow in full: request and response headers, bodies (cut at max_bytes), timings, TLS, identity, error.",
        "inputSchema": _schema(
            {
                "n": N,
                "include_bodies": {"type": "boolean", "default": True},
                "max_bytes": {"type": "integer", "minimum": 0, "maximum": 1048576, "default": 8192},
            },
            ["n"],
        ),
    },
    {
        "name": "traffic_sse",
        "description": "Server-Sent Events of one streamed response, in order.",
        "inputSchema": _schema({"n": N, "after": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, ["n"]),
    },
    {
        "name": "traffic_ws",
        "description": "WebSocket messages of one connection, in order (from_client tells the direction).",
        "inputSchema": _schema({"n": N, "after": {"type": "integer", "default": 0}, "limit": {"type": "integer", "default": 100}}, ["n"]),
    },
    {
        "name": "traffic_curl",
        "description": "A curl command that replays the request of one flow (proxy credentials are not included).",
        "inputSchema": _schema({"n": N}, ["n"]),
    },
]
SQL_TOOL = {
    "name": "traffic_sql",
    "description": (
        "Read-only ClickHouse SQL over the scan. Tables: m2c.http_flows (one row per HTTP flow; bodies in req_body/resp_body), "
        "m2c.sse_events, m2c.ws_messages (joined on n), m2c.proxy_events (auth failures, TLS failures, health). "
        "Results are JSON lines, cut at 64 KiB; add LIMIT."
    ),
    "inputSchema": _schema({"sql": {"type": "string"}}, ["sql"]),
}


def _text_body(data: bytes, ctype: str, max_bytes: int, stored: int, total: int) -> dict:
    shown = data[:max_bytes]
    out: dict = {"stored_bytes": stored, "wire_bytes": total}
    is_text = any(t in (ctype or "").lower() for t in TEXTY)
    try:
        out["text"] = shown.decode("utf-8")
    except UnicodeDecodeError:
        if is_text:
            out["text"] = shown.decode("utf-8", "replace")
        else:
            out["base64"] = base64.b64encode(shown).decode()
    if stored > len(shown):
        out["cut"] = f"showing {len(shown)} of {stored} stored bytes; call traffic_get with a larger max_bytes for more"
    return out


class McpServer:
    def __init__(self, queries: Queries, admin: bool):
        self.q = queries
        self.admin = admin

    def tools(self) -> list[dict]:
        return TOOLS + ([SQL_TOOL] if self.admin else [])

    def handle(self, msg) -> dict | None:
        """One JSON-RPC message in, the response (or None for a notification) out. Never raises: a malformed message
        or a failing tool is an error reply, so one bad call cannot fail a batch or end the stdio server."""
        if not isinstance(msg, dict):
            return rpc_error(None, -32600, "invalid request: expected a JSON-RPC object")
        mid = msg.get("id")
        method = msg.get("method", "")
        if mid is None:
            return None  # notifications (initialized, cancelled, ...)
        params = msg.get("params") or {}
        if not isinstance(method, str):
            return rpc_error(mid, -32600, "invalid request: method must be a string")
        if not isinstance(params, dict):
            return rpc_error(mid, -32602, "params must be an object")
        try:
            result = self._dispatch(method, params)
        except _RpcError as e:
            return rpc_error(mid, e.code, str(e))
        except Exception as e:  # noqa: BLE001 - reported to the caller, see above
            return rpc_error(mid, -32603, f"internal error: {e}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    def handle_payload(self, msg) -> dict | list | None:
        """A parsed message or batch in; the reply (an object, a list, or None when there is nothing to answer) out."""
        if isinstance(msg, list):
            if not msg:
                return rpc_error(None, -32600, "invalid request: empty batch")
            replies = [r for r in map(self.handle, msg) if r is not None]
            return replies or None
        return self.handle(msg)

    def _dispatch(self, method: str, params: dict):
        if method == "initialize":
            asked = params.get("protocolVersion")
            return {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "m2c", "version": __version__},
                "instructions": "Recorded proxy traffic of AI agent runs. Start with traffic_stats or traffic_search; "
                "fetch details with traffic_get. " + FILTER_HELP,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.tools()}
        if method == "tools/call":
            name = params.get("name", "")
            args = params.get("arguments") or {}
            if not isinstance(name, str) or name not in {t["name"] for t in self.tools()}:
                raise _RpcError(-32602, f"unknown tool {name}")
            if not isinstance(args, dict):
                raise _RpcError(-32602, "arguments must be an object")
            try:
                value = self.call(name, args)
            except (FilterError, Forbidden, ValueError, RuntimeError) as e:
                return {"content": [{"type": "text", "text": f"error: {e}"}], "isError": True}
            except KeyError as e:
                return {"content": [{"type": "text", "text": f"error: missing argument {e}"}], "isError": True}
            except Exception as e:  # noqa: BLE001 - bad argument types (TypeError), engine errors, ...: the agent sees them
                return {"content": [{"type": "text", "text": f"error: {type(e).__name__}: {e}"}], "isError": True}
            text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
            return {"content": [{"type": "text", "text": text}], "isError": False}
        raise _RpcError(-32601, f"method not found: {method}")

    def call(self, name: str, a: dict):
        q = self.q
        if name == "traffic_stats":
            return q.stats()
        if name == "traffic_sessions":
            return q.sessions(a.get("query", ""))
        if name == "traffic_search":
            return q.flows(a.get("query", ""), limit=min(int(a.get("limit", 50)), 500), cursor=a.get("cursor"))
        if name == "traffic_get":
            flow = q.flow(int(a["n"]))
            if flow is None:
                return f"no flow #{a['n']}"
            if a.get("include_bodies", True):
                max_bytes = int(a.get("max_bytes", 8192))
                for side in ("req", "resp"):
                    if flow[f"{side}_body_stored"]:
                        body = q.body(flow["n"], side, max_bytes=max_bytes + 1)
                        ctype = flow["resp_content_type"] if side == "resp" else ""
                        flow[f"{side}_body"] = _text_body(body[0], ctype or body[1], max_bytes, flow[f"{side}_body_stored"], flow[f"{side}_body_size"])
            return flow
        if name == "traffic_sse":
            return q.sse(int(a["n"]), int(a.get("after", 0)), min(int(a.get("limit", 100)), 1000))
        if name == "traffic_ws":
            return q.ws(int(a["n"]), int(a.get("after", 0)), min(int(a.get("limit", 100)), 1000))
        if name == "traffic_curl":
            return q.curl(int(a["n"])) or f"no flow #{a['n']}"
        if name == "traffic_sql":
            raw = q.sql(a["sql"], "JSONEachRow")
            return raw[:65536].decode("utf-8", "replace") + ("\n... (cut at 64 KiB)" if len(raw) > 65536 else "")
        raise KeyError(name)


class _RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def rpc_error(mid, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


PARSE_ERROR = rpc_error(None, -32700, "parse error")


def serve_stdio(handle: Callable[[object], dict | list | None], stdin, stdout) -> None:
    """Newline-delimited JSON-RPC over stdio. `handle` takes a parsed message or batch; when it raises (the live API
    went away, ...), that request gets an error reply and the server keeps reading."""
    for line in stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:  # bad JSON, or bytes that are not UTF-8
            reply = PARSE_ERROR
        else:
            try:
                reply = handle(msg)
            except Exception as e:  # noqa: BLE001 - see above
                notification = isinstance(msg, dict) and msg.get("id") is None
                reply = None if notification else rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32603, str(e))
        if reply is not None:
            stdout.write(json.dumps(reply) + "\n")
            stdout.flush()
