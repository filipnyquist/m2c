"""MCP server (JSON-RPC 2.0), transport-free: the API serves it at POST /mcp, `m2c mcp` over stdio.

The protocol lives here; the tools, resources and prompts in mcp_tools.py. Handling is async: under the live API it
runs on the event loop (database reads go to reader threads through the context), offline `handle_sync` runs it.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable

from . import __version__
from .filters import FilterError, help_text
from .mcp_tools import PROMPTS, RESOURCE_TEMPLATES, RESOURCES, Ctx, NotFound, ToolError, get_prompt, read_resource, tools
from .queries import Forbidden, Queries

PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
NO_BATCHES_FROM = "2025-06-18"  # JSON-RPC batching was removed from MCP in this version
FILTER_HELP = help_text()
TOOLS = tools(FILTER_HELP)
INSTRUCTIONS = (
    "Recorded proxy traffic of AI agent runs. After making a request, traffic_wait returns it once it finishes; "
    "traffic_search lists flows one line each; traffic_get shows one in full; traffic_events shows auth and TLS failures "
    "that never became flows. " + FILTER_HELP
)


class McpServer:
    def __init__(self, queries: Queries, admin: bool, ctx: Ctx | None = None):
        self.q = queries
        self.admin = admin
        self.ctx = ctx or Ctx(queries, admin)
        self._tools = {t.name: t for t in TOOLS if not t.needs_resend or self.ctx.resend is not None}

    def tools(self) -> list[dict]:
        return [t.spec() for t in self._tools.values()]

    async def handle(self, msg) -> dict | None:
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
            result = await self._dispatch(method, params)
        except _RpcError as e:
            return rpc_error(mid, e.code, str(e))
        except Exception as e:  # noqa: BLE001 - reported to the caller, see above
            return rpc_error(mid, -32603, f"internal error: {e}")
        return {"jsonrpc": "2.0", "id": mid, "result": result}

    async def handle_payload(self, msg) -> dict | list | None:
        """A parsed message or batch in; the reply (an object, a list, or None when there is nothing to answer) out."""
        if isinstance(msg, list):
            if not msg:
                return rpc_error(None, -32600, "invalid request: empty batch")
            replies = [r for r in [await self.handle(m) for m in msg] if r is not None]
            return replies or None
        return await self.handle(msg)

    def handle_sync(self, msg) -> dict | list | None:
        return asyncio.run(self.handle_payload(msg))

    async def _dispatch(self, method: str, params: dict):
        if method == "initialize":
            asked = params.get("protocolVersion")
            return {
                "protocolVersion": asked if asked in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[0],
                "capabilities": {"tools": {"listChanged": False}, "resources": {"listChanged": False}, "prompts": {"listChanged": False}},
                "serverInfo": {"name": "m2c", "title": "m2c proxy traffic", "version": __version__},
                "instructions": INSTRUCTIONS,
            }
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": self.tools()}
        if method == "tools/call":
            return await self._call(params)
        if method == "resources/list":
            return {"resources": RESOURCES}
        if method == "resources/templates/list":
            return {"resourceTemplates": RESOURCE_TEMPLATES}
        if method == "resources/read":
            uri = params.get("uri")
            if not isinstance(uri, str):
                raise _RpcError(-32602, "uri must be a string")
            try:
                return {"contents": [await read_resource(self.ctx, uri)]}
            except NotFound:
                raise _RpcError(-32002, f"resource not found: {uri}") from None
        if method == "prompts/list":
            return {"prompts": PROMPTS}
        if method == "prompts/get":
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                raise _RpcError(-32602, "arguments must be an object")
            try:
                return get_prompt(params.get("name"), args)
            except NotFound:
                raise _RpcError(-32602, f"unknown prompt {params.get('name')}") from None
            except ToolError as e:
                raise _RpcError(-32602, str(e)) from None
        raise _RpcError(-32601, f"method not found: {method}")

    async def _call(self, params: dict) -> dict:
        name = params.get("name", "")
        args = params.get("arguments") or {}
        tool = self._tools.get(name) if isinstance(name, str) else None
        if tool is None:
            raise _RpcError(-32602, f"unknown tool {name}")
        if not isinstance(args, dict):
            raise _RpcError(-32602, "arguments must be an object")
        try:
            value = await tool.fn(self.ctx, args)
        except (ToolError, FilterError, Forbidden, ValueError, RuntimeError) as e:
            return _error_result(f"error: {e}")
        except KeyError as e:
            return _error_result(f"error: missing argument {e}")
        except Exception as e:  # noqa: BLE001 - bad argument types (TypeError), engine errors, ...: the agent sees them
            return _error_result(f"error: {type(e).__name__}: {e}")
        if isinstance(value, str):
            return {"content": [{"type": "text", "text": value}], "isError": False}
        out = {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False, default=str)}], "isError": False}
        if tool.output_schema and isinstance(value, dict):
            out["structuredContent"] = json.loads(out["content"][0]["text"])  # the same JSON types as the text
        return out


def _error_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


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
