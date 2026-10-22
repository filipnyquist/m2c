"""The MCP tools, resources and prompts: what an agent can ask about recorded traffic. mcp.py speaks JSON-RPC.

Tools are async. Under the live API they run on mitmproxy's event loop and every database read goes through
`ctx.db`, which hands it to a reader thread (`heavy=True` is the lane for body scans and decoding), so a tool that
waits (traffic_wait) never holds a reader. Offline (`m2c mcp` on a stopped scan) `ctx.db` just calls the function.

Outputs are bounded so an agent's context doesn't fill up: lists are one line per flow, bodies are cut at
`max_bytes` with a note on how to get more, and credential headers are redacted unless asked for.
"""

from __future__ import annotations

import asyncio
import base64
import json
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from . import fmt
from .filters import heavy, split_matcher
from .identity import SESSION
from .live import SUMMARY_KEYS
from .notes import NoteDenied, NoteError
from .queries import Queries

TEXTY = ("text/", "application/json", "application/xml", "application/javascript", "application/x-www-form-urlencoded", "+json", "+xml", "ndjson", "event-stream", "graphql")
HEADER_KEYS = ("req_headers", "req_trailers", "resp_headers", "resp_trailers")
WAIT_MAX_S = 50  # under the CLI's 60 s HTTP timeout: `m2c mcp` forwards to /mcp


class ToolError(Exception):
    """Reported to the agent as a tool result with isError, not as a protocol error."""


async def inline(fn, *args, heavy: bool = False):
    return fn(*args)


@dataclass
class Ctx:
    q: Queries
    admin: bool
    db: Callable[..., Awaitable] = inline
    live: object | None = None  # the running proxy's LiveFeed; None offline
    db_tail: tuple[Callable[[], None], Callable[[], None]] | None = None  # claim/release a database-filtered wait
    gone: Callable[[], bool] = lambda: False  # the HTTP client went away
    notes: object | None = None  # notes.Notes of the running proxy (writes, and reads that see them at once); None offline
    resend: Callable[[int, dict], Awaitable] | None = None  # the repeater, when this caller may use it

    @property
    def scope(self) -> str | None:
        return self.q.scope


@dataclass
class Tool:
    name: str
    title: str
    description: str
    input_schema: dict
    fn: Callable[[Ctx, dict], Awaitable]
    output_schema: dict | None = None
    needs_resend: bool = False  # listed only when the repeater is on for the caller
    annotations: dict = field(default_factory=lambda: {"readOnlyHint": True, "destructiveHint": False, "idempotentHint": True,
                                                       "openWorldHint": False})

    def spec(self) -> dict:
        out = {"name": self.name, "title": self.title, "description": self.description, "inputSchema": self.input_schema,
               "annotations": {"title": self.title, **self.annotations}}
        if self.output_schema:
            out["outputSchema"] = self.output_schema
        return out


# ---------------------------------------------------------------------------- arguments


def _schema(props: dict, required=()) -> dict:
    return {"type": "object", "properties": props, "required": list(required), "additionalProperties": False}


def _int(a: dict, key: str, default: int | None = None, lo: int = 0, hi: int = (1 << 63) - 1) -> int:
    value = a.get(key, default)
    if value is None:
        raise ToolError(f"missing argument {key}")
    if isinstance(value, str) and value.isascii() and value.isdigit():
        value = int(value)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ToolError(f"{key} must be an integer")
    return max(lo, min(value, hi))


def _num(a: dict, key: str, default: float, lo: float, hi: float) -> float:
    value = a.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ToolError(f"{key} must be a number")
    return max(lo, min(float(value), hi))


def _str(a: dict, key: str, default: str = "", choices: tuple | None = None) -> str:
    value = a.get(key, default)
    if not isinstance(value, str):
        raise ToolError(f"{key} must be a string")
    if choices and value not in choices:
        raise ToolError(f"{key} is one of {', '.join(choices)}")
    return value


def _bool(a: dict, key: str, default: bool) -> bool:
    value = a.get(key, default)
    if not isinstance(value, bool):
        raise ToolError(f"{key} must be true or false")
    return value


N = {"type": "integer", "minimum": 0, "description": "Flow number (#n) from traffic_search"}
QUERY = {"type": "string", "description": "Filter, e.g. 'tool:curl status:5xx host:*.acme.test' (see the filter syntax)"}


# ---------------------------------------------------------------------------- bodies


def text_body(data: bytes, ctype: str, max_bytes: int, stored: int, total: int) -> dict:
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


# ---------------------------------------------------------------------------- tools


async def t_stats(ctx: Ctx, a: dict):
    out = await ctx.db(ctx.q.stats)
    if ctx.live is not None:
        out["open_flows"] = sum(1 for f in ctx.live.open.values() if ctx.scope is None or f["session"] == ctx.scope)
    return out


async def t_sessions(ctx: Ctx, a: dict):
    query = _str(a, "query")
    return await ctx.db(ctx.q.sessions, query, heavy=heavy(query))


LINES_HEADER = "     n  time          session/tool#call         method  status   size  duration  host/path"


def _lines(flows: list[dict], more: str) -> str:
    if not flows:
        return "no flows match"
    return "\n".join([LINES_HEADER, *(fmt.flow_line(f) for f in flows), more])


async def t_search(ctx: Ctx, a: dict):
    query = _str(a, "query")
    limit = _int(a, "limit", 20, 1, 500)
    cursor = _int(a, "cursor") if a.get("cursor") is not None else None
    order = _str(a, "order", "desc", ("desc", "asc"))
    form = _str(a, "format", "lines", ("lines", "json"))
    fields = a.get("fields") or []
    if not isinstance(fields, list) or any(f not in SUMMARY_KEYS for f in fields):
        raise ToolError(f"fields are some of {', '.join(SUMMARY_KEYS)}")
    page = await ctx.db(ctx.q.flows, query, limit, cursor, order, heavy=heavy(query))
    if form == "lines":
        more = f"more: call again with cursor={page['next']}" if page.get("next") else "(end)"
        return _lines(page["flows"], more)
    if fields:
        page["flows"] = [{k: f[k] for k in fields if k in f} for f in page["flows"]]
    return page


async def t_get(ctx: Ctx, a: dict):
    n = _int(a, "n")
    mode = _str(a, "headers", "all", ("all", "names", "none"))
    redact = _bool(a, "redact", True)
    flow = await ctx.db(ctx.q.flow, n)
    if flow is None:
        pending = ctx.live.get(n) if ctx.live is not None else None
        if pending is not None and (ctx.scope is None or pending["session"] == ctx.scope):
            return {**pending, "pending": True,
                    "note": "this flow is still open or not written yet: headers and bodies follow once it is; "
                            f"traffic_wait with query 'n:{n}' returns when it finishes"}
        raise ToolError(f"no flow #{n}")
    for key in HEADER_KEYS:
        flow[key] = fmt.redact_headers(flow[key], mode, redact)
    notes = await _notes(ctx, n)
    if notes:
        flow["notes"] = [{k: x[k] for k in ("id", "label", "color", "note", "author", "updated")} for x in notes]
    if _bool(a, "include_bodies", True):
        max_bytes = _int(a, "max_bytes", 4096, 0, 1 << 20)
        for side in ("req", "resp"):
            if flow[f"{side}_body_stored"]:
                body = await ctx.db(ctx.q.body, flow["n"], side, max_bytes + 1)
                if body is not None:
                    ctype = flow["resp_content_type"] if side == "resp" else ""
                    flow[f"{side}_body"] = text_body(body[0], ctype or body[1], max_bytes, flow[f"{side}_body_stored"], flow[f"{side}_body_size"])
    return flow


async def _notes(ctx: Ctx, n: int) -> list[dict]:
    stored = await ctx.db(ctx.q.notes, [n])
    if ctx.notes is None:
        return [x for x in stored if not x["deleted"]]
    return ctx.notes.merge(stored, lambda v: v["n"] == n and (ctx.scope is None or v["session"] == ctx.scope))


async def t_annotate(ctx: Ctx, a: dict):
    if ctx.notes is None:
        raise ToolError("notes are written through the running proxy; this is a stopped scan")
    n = _int(a, "n")
    flow = await ctx.db(ctx.q.flow, n)
    if flow is None:
        raise ToolError(f"no flow #{n}")
    try:
        if a.get("delete"):
            current = [x for x in await _notes(ctx, n) if x["id"] == str(a["delete"]).lower()]
            if not current:
                raise ToolError(f"no note {a['delete']} on flow #{n}")
            ctx.notes.change(current[0], None, ctx.admin, ctx.scope)
            return {"deleted": current[0]["id"]}
        return ctx.notes.add(flow, {k: a[k] for k in ("label", "color", "note") if k in a}, ctx.admin, ctx.scope)
    except (NoteError, NoteDenied, RuntimeError) as e:
        raise ToolError(str(e)) from None


def _lookback_cursor(live, seconds: float) -> int:
    """The live cursor just before the flows that finished in the last `seconds`."""
    cursor = live.seq
    edge = (time.time() - seconds) * 1000
    for seq, item in reversed(live.ring):
        if item.get("ts", 0) + item.get("duration_ms", 0) < edge:
            break
        cursor = seq - 1
    return cursor


async def t_wait(ctx: Ctx, a: dict):
    live = ctx.live
    if live is None:
        raise ToolError("traffic_wait needs the running proxy; this is a stopped scan, use traffic_search")
    query = _str(a, "query")
    timeout = _num(a, "timeout", 20, 0, WAIT_MAX_S)
    count = _int(a, "count", 1, 1, 100)
    pred, exact = split_matcher(query, ctx.scope)
    notes = []
    after = a.get("after")
    if after:
        epoch, _, seq = str(after).partition(".")
        if epoch == live.epoch and seq.isdigit() and int(seq) <= live.seq:
            cursor = int(seq)
        else:
            cursor = live.seq
            notes.append("the cursor is from an earlier proxy run: waiting for new flows only")
    else:
        cursor = _lookback_cursor(live, _num(a, "lookback", 10, 0, 600))

    if not exact and ctx.db_tail is not None:
        ctx.db_tail[0]()
    sub = live.subscribe(pred, opens=False)
    found: list[dict] = []
    pending: dict[int, tuple[int, dict]] = {}  # needs the database: n -> (seq, summary), until the writer has it
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    try:
        while True:
            sub.take()  # clear the wake-up before reading, so a flow published from here on wakes the wait below
            items, missed = live.since(cursor)
            if missed and not any(x.startswith("missed") for x in notes):
                notes.append(f"missed {missed} flows that left the live feed; traffic_search finds them")
            for seq, item in items:
                cursor = seq
                if _safe(pred, item):
                    if exact:
                        found.append(item)
                        if len(found) >= count:
                            break
                    else:
                        pending[item["n"]] = (seq, item)
            if pending and len(found) < count:
                hits = await ctx.db(ctx.q.hits, query, sorted(pending), heavy=True)
                for n in sorted(hits):
                    _, item = pending.pop(n)
                    if hits[n]:
                        found.append(item)
            left = deadline - loop.time()
            if len(found) >= count or left <= 0 or ctx.gone():
                break
            await sub.wait(min(left, 0.25) if pending else left)
    finally:
        live.unsubscribe(sub)
        if not exact and ctx.db_tail is not None:
            ctx.db_tail[1]()
    if pending:  # not in the database yet: the next call (with this cursor) looks at them again
        cursor = min(seq for seq, _ in pending.values()) - 1
    out = {"flows": found, "cursor": f"{live.epoch}.{cursor}", "timed_out": len(found) < count}
    if notes:
        out["notes"] = notes
    return out


async def t_report(ctx: Ctx, a: dict):
    query = _str(a, "query")
    rep = await ctx.db(ctx.q.report, query, _str(a, "by", "tool", ("session", "tool", "call")), _int(a, "limit", 50, 1, 500), heavy=True)
    return fmt.report_text(rep) if _str(a, "format", "lines", ("lines", "json")) == "lines" else rep


async def t_grep(ctx: Ctx, a: dict):
    pattern = _str(a, "pattern")
    if not pattern:
        raise ToolError("pattern is empty")
    return await ctx.db(ctx.q.grep, pattern, _bool(a, "regex", False), not _bool(a, "case_sensitive", False),
                        _str(a, "side", "both", ("req", "resp", "both")), _str(a, "query"), _str(a, "in", "body", ("body", "sse", "ws")),
                        _int(a, "context", 80, 0, 200), _int(a, "limit", 20, 1, 200), _int(a, "per_flow", 3, 1, 20), heavy=True)


async def t_diff(ctx: Ctx, a: dict):
    na, nb = _int(a, "a"), _int(a, "b")
    out = await ctx.db(ctx.q.diff, na, nb, 256 << 10, _bool(a, "redact", True), heavy=True)
    if out is None:
        raise ToolError(f"no flow #{na} or #{nb}")
    return out


async def t_suggest(ctx: Ctx, a: dict):
    query = _str(a, "query")
    pred, _ = split_matcher(query, ctx.scope)
    open_flows = 0
    if ctx.live is not None:
        open_flows = sum(1 for f in list(ctx.live.open.values()) if _safe(pred, f))
    out = await ctx.db(ctx.q.suggest, query, open_flows, heavy=heavy(query))
    if not out["hints"]:
        return f"{out['total']} flows match; nothing to suggest"
    return "\n".join([f"{out['total']} flows match. Refinements:"] +
                     [f"- {h['text']}" + (f": {h['query']}" if h["query"] else "") for h in out["hints"]])


def _safe(pred, item) -> bool:
    try:
        return bool(pred(item))
    except Exception:  # noqa: BLE001 - a predicate that fails on an odd summary skips it
        return False


async def t_timeline(ctx: Ctx, a: dict):
    session = _str(a, "session") or ctx.scope
    if not session:
        known = await ctx.db(ctx.q.call_sessions)
        if not known:
            raise ToolError("no flows carry call ids yet: name calls in the proxy username (<session>.<tool>.<call>)")
        session = known[0]["session"]
    tl = await ctx.db(ctx.q.timeline, session, _int(a, "limit", 500, 1, 5000), heavy=True)
    lines = [f"session {session}: {tl['flows']} flows, {tl['calls']} calls"]
    for item in tl["items"]:
        if item["kind"] == "call":
            failed = f", {item['failures']} failed" if item["failures"] else ""
            lines.append(f"call {item['call_id']} ({item['tool']}): {len(item['flows'])} flows{failed}, hosts {', '.join(item['hosts'][:5])}")
        else:
            lines.append(f"without a call id: {len(item['flows'])} flows")
        lines += ["  " + fmt.flow_line(f) for f in item["flows"]]
    return "\n".join(lines)


async def t_replay(ctx: Ctx, a: dict):
    if ctx.resend is None:
        raise ToolError("the repeater is off for you (m2c_repeater)")
    n = _int(a, "n")
    overrides = {k: a[k] for k in ("method", "url", "headers", "headers_remove", "body", "body_base64") if k in a}
    try:
        out = await ctx.resend(n, overrides)
    except (ValueError, PermissionError, LookupError, RuntimeError) as e:  # bad edits, off, unknown flow, busy
        raise ToolError(str(e)) from None
    d = await ctx.db(ctx.q.diff, n, out["n"], 64 << 10, True, heavy=True)
    if d is not None:
        out["diff"] = d
    return out


async def t_events(ctx: Ctx, a: dict):
    return await ctx.db(ctx.q.events, _str(a, "kind"), _int(a, "limit", 50, 1, 1000),
                        _str(a, "severity", "", ("", "debug", "info", "warn", "error")))


async def t_sse(ctx: Ctx, a: dict):
    return await ctx.db(ctx.q.sse, _int(a, "n"), _int(a, "after", 0), _int(a, "limit", 100, 1, 1000))


async def t_ws(ctx: Ctx, a: dict):
    return await ctx.db(ctx.q.ws, _int(a, "n"), _int(a, "after", 0), _int(a, "limit", 100, 1, 1000))


async def t_grpc(ctx: Ctx, a: dict):
    out = []
    for m in await ctx.db(ctx.q.grpc, _int(a, "n"), _int(a, "after", 0), _int(a, "limit", 50, 1, 500), heavy=True):
        if m["decoded"]:
            m.pop("base64", None)  # the decoded text says it; keep the context small
        elif len(m.get("base64", "")) > 2048:
            m["base64"], m["cut"] = m["base64"][:2048], "base64 cut at 2 KiB"
        out.append(m)
    return out


async def t_curl(ctx: Ctx, a: dict):
    n = _int(a, "n")
    cmd = await ctx.db(ctx.q.curl, n)
    if cmd is None:
        raise ToolError(f"no flow #{n}")
    return cmd


def tools(filter_help: str) -> list[Tool]:
    children = {"n": N, "after": {"type": "integer", "minimum": 0, "default": 0, "description": "seq of the last one you have"},
                "limit": {"type": "integer", "minimum": 1, "default": 100}}
    summary_obj = {"type": "object", "properties": {"n": {"type": "integer"}, "session": {"type": "string"}, "tool": {"type": "string"},
                                                    "status": {"type": "integer"}}, "required": ["n"]}
    return [
        Tool("traffic_stats", "Scan totals",
             "Totals: flows, sessions, tools, hosts, errors (transport, 5xx, gRPC), failures (errors and 4xx), SSE events, "
             "WebSocket and gRPC messages, and flows still open.",
             _schema({}), t_stats,
             output_schema={"type": "object", "properties": {"flows": {"type": "integer"}, "errors": {"type": "integer"},
                                                             "failures": {"type": "integer"}}, "required": ["flows"]}),
        Tool("traffic_sessions", "Sessions and tools",
             "Per session and tool: flows, failures, hosts, bytes, first and last seen. " + filter_help,
             _schema({"query": QUERY}), t_sessions),
        Tool("traffic_search", "Search flows",
             "Recorded HTTP flows, newest first (order=asc: oldest first), without bodies. format=lines (default) gives one "
             "line per flow: n, time, session/tool#call, method, status, response size, duration, host and path; "
             "format=json gives summaries, cut to `fields` if given. Page with the cursor it returns. " + filter_help,
             _schema({
                 "query": QUERY,
                 "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 20},
                 "cursor": {"type": "integer", "description": "from the previous page"},
                 "order": {"type": "string", "enum": ["desc", "asc"], "default": "desc"},
                 "format": {"type": "string", "enum": ["lines", "json"], "default": "lines"},
                 "fields": {"type": "array", "items": {"type": "string", "enum": list(SUMMARY_KEYS)}, "description": "json format only"},
             }), t_search),
        Tool("traffic_get", "Get one flow",
             "One flow in full: request and response headers, bodies (cut at max_bytes), timings, TLS, identity, error, gRPC "
             "status. Credential headers (Authorization, Cookie, API keys) show as <redacted len sha256> unless redact=false; "
             "headers=names lists names only. A flow still running (a stream) comes back as pending with its summary.",
             _schema({
                 "n": N,
                 "include_bodies": {"type": "boolean", "default": True},
                 "max_bytes": {"type": "integer", "minimum": 0, "maximum": 1048576, "default": 4096},
                 "headers": {"type": "string", "enum": ["all", "names", "none"], "default": "all"},
                 "redact": {"type": "boolean", "default": True},
             }, ["n"]), t_get, output_schema=summary_obj),
        Tool("traffic_wait", "Wait for flows",
             "Wait until a flow matching `query` finishes, and return it: use it right after making a request. By default "
             "it also counts flows that finished in the last `lookback` seconds (10). Returns {flows, cursor, timed_out}; "
             "pass the cursor as `after` to wait for the next ones. Needs the running proxy. " + filter_help,
             _schema({
                 "query": QUERY,
                 "timeout": {"type": "number", "minimum": 0, "maximum": WAIT_MAX_S, "default": 20, "description": "seconds"},
                 "count": {"type": "integer", "minimum": 1, "maximum": 100, "default": 1},
                 "after": {"type": "string", "description": "cursor from an earlier traffic_wait"},
                 "lookback": {"type": "number", "minimum": 0, "maximum": 600, "default": 10, "description": "seconds; ignored with after"},
             }), t_wait,
             output_schema={"type": "object", "properties": {"flows": {"type": "array", "items": summary_obj}, "cursor": {"type": "string"},
                                                             "timed_out": {"type": "boolean"}}, "required": ["flows", "cursor", "timed_out"]}),
        Tool("traffic_report", "Report by session, tool or call",
             "What each session, tool or tool call (by=call: grouped by call id) did: flows, failures, hosts with counts, "
             "status codes, error kinds, the slowest flows and bytes, in order of first flow. format=lines (default) is a "
             "compact text; json has every field. " + filter_help,
             _schema({"query": QUERY, "by": {"type": "string", "enum": ["session", "tool", "call"], "default": "tool"},
                      "limit": {"type": "integer", "minimum": 1, "maximum": 500, "default": 50},
                      "format": {"type": "string", "enum": ["lines", "json"], "default": "lines"}}), t_report),
        Tool("traffic_grep", "Search bodies",
             "Find text in recorded bodies (or SSE event data with in=sse, WebSocket messages with in=ws) and show it in "
             "context: up to per_flow snippets per flow with `context` characters around each match. The pattern is literal "
             "unless regex=true (RE2 syntax); matching ignores case unless case_sensitive=true. `query` narrows the flows.",
             _schema({"pattern": {"type": "string"}, "regex": {"type": "boolean", "default": False},
                      "case_sensitive": {"type": "boolean", "default": False},
                      "side": {"type": "string", "enum": ["req", "resp", "both"], "default": "both"},
                      "in": {"type": "string", "enum": ["body", "sse", "ws"], "default": "body"}, "query": QUERY,
                      "context": {"type": "integer", "minimum": 0, "maximum": 200, "default": 80},
                      "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 20},
                      "per_flow": {"type": "integer", "minimum": 1, "maximum": 20, "default": 3}}, ["pattern"]), t_grep),
        Tool("traffic_diff", "Compare two flows",
             "What differs between flows a and b: method, URL, status, error, headers (added, removed, changed; headers that "
             "differ on every response such as dates and request ids are left out), bodies (JSON paths when both are JSON, "
             "else a unified diff, else sizes and hashes), sizes and timing. Use it to compare a working request with a "
             "failing one.",
             _schema({"a": N, "b": N, "redact": {"type": "boolean", "default": True}}, ["a", "b"]), t_diff,
             output_schema={"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}, "same": {"type": "boolean"}},
                            "required": ["a", "b", "same"]}),
        Tool("traffic_suggest", "Suggest filters",
             "Ways to refine a filter query, from what the matching flows look like: noise to hide (e.g. one tool's 404s), "
             "failures and their main error kind, credentials sent over plain HTTP, the slow tail, a dominant session. "
             "Each comes with the full refined query to pass to traffic_search. " + filter_help,
             _schema({"query": QUERY}), t_suggest),
        Tool("traffic_annotate", "Label or note a flow",
             "Put a label (e.g. vuln, todo, auth-bypass) and/or a note on a flow, for people reading the scan later and for "
             "filters: label:vuln, note:\"text\", has:note. A session token annotates its own session's flows. "
             "delete=<note id> removes one of your notes instead.",
             _schema({"n": N, "label": {"type": "string", "description": "a-z 0-9 _ . -, up to 32"}, "note": {"type": "string"},
                      "color": {"type": "string", "enum": ["red", "orange", "yellow", "green", "blue", "purple", "gray"]},
                      "delete": {"type": "string", "description": "id of a note to remove"}}, ["n"]), t_annotate,
             annotations={"readOnlyHint": False, "destructiveHint": False, "idempotentHint": False, "openWorldHint": False}),
        Tool("traffic_timeline", "Tool-call timeline",
             "A session's flows grouped by the tool call that made them, in order: the call id is the proxy username's "
             "third part (<session>.<tool>.<call>; the Claude Code hooks set it to each Bash call's tool_use_id). Flows "
             "without one are grouped between the calls. Default session: yours, or the one with the latest call.",
             _schema({"session": {"type": "string"}, "limit": {"type": "integer", "minimum": 1, "maximum": 5000, "default": 500,
                                                               "description": "the session's last N flows"}}), t_timeline),
        Tool("traffic_replay", "Resend a request",
             "Resend flow n through the proxy, as recorded or edited: method, url, headers (the whole list of [name, value] "
             "pairs), headers_remove (names), body (text) or body_base64. The new flow is recorded in the same session "
             "(tool repeater, call id = n, replay_of = n); returns its n, status, error and a diff against the original. "
             "Proxy credentials are never sent on. It sends real requests to the target.",
             _schema({"n": N, "method": {"type": "string"}, "url": {"type": "string"},
                      "headers": {"type": "array", "items": {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2}},
                      "headers_remove": {"type": "array", "items": {"type": "string"}}, "body": {"type": "string"},
                      "body_base64": {"type": "string"}}, ["n"]), t_replay, needs_resend=True,
             annotations={"readOnlyHint": False, "destructiveHint": True, "idempotentHint": False, "openWorldHint": True}),
        Tool("traffic_events", "Proxy events",
             "Proxy events, newest first: auth rejections (407), TLS failures (a client that doesn't trust the proxy CA, or "
             "a server certificate the proxy rejected), tunnels that aren't HTTP, health. A session token sees its own, plus "
             "rejected attempts that named its session (claimed=true: the username was not proven). Each event has a `fix`: "
             "what to do about it (e.g. which CA variable a tool that failed TLS reads).",
             _schema({"kind": {"type": "string", "description": "auth_rejected, auth_challenge, tls_failed_client, tls_failed_server, tcp_tunnel, ..."},
                      "severity": {"type": "string", "enum": ["debug", "info", "warn", "error"]},
                      "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "default": 50}}), t_events),
        Tool("traffic_sse", "SSE events", "Server-Sent Events of one streamed response, in order.", _schema(children, ["n"]), t_sse),
        Tool("traffic_ws", "WebSocket messages", "WebSocket messages of one connection, in order (from_client tells the direction).",
             _schema(children, ["n"]), t_ws),
        Tool("traffic_grpc", "gRPC messages",
             "Messages of one gRPC call in order, both directions (from_client tells which), each decoded from protobuf "
             "(field names when the proxy has a .proto file, else field numbers). Calls have grpc_service, grpc_method and "
             "grpc_status (0 = OK) in traffic_get; find them with traffic_search query 'has:grpc' or 'gstatus:!0'.",
             _schema({**children, "limit": {"type": "integer", "minimum": 1, "default": 50}}, ["n"]), t_grpc),
        Tool("traffic_curl", "Flow as curl", "A curl command that replays the request of one flow (proxy credentials are not included).",
             _schema({"n": N}, ["n"]), t_curl),
    ]


# ---------------------------------------------------------------------------- resources

RESOURCE_TEMPLATES = [
    {"uriTemplate": "m2c://flow/{n}", "name": "flow", "title": "Recorded flow",
     "description": "One flow as JSON, as traffic_get without bodies (credential headers redacted)", "mimeType": "application/json"},
    {"uriTemplate": "m2c://flow/{n}/body/{side}", "name": "flow-body", "title": "Flow body",
     "description": "The stored request (side=req) or response (side=resp) body"},
]
RESOURCES = [{"uri": "m2c://scan", "name": "scan", "title": "Scan totals", "description": "traffic_stats as JSON", "mimeType": "application/json"}]
_FLOW_URI = re.compile(r"m2c://flow/([0-9]{1,20})(?:/body/(req|resp))?")


class NotFound(Exception):
    pass


async def read_resource(ctx: Ctx, uri: str) -> dict:
    if uri == "m2c://scan":
        return {"uri": uri, "mimeType": "application/json", "text": json.dumps(await t_stats(ctx, {}), default=str)}
    m = _FLOW_URI.fullmatch(uri)
    if not m:
        raise NotFound(uri)
    n, side = int(m.group(1)), m.group(2)
    if side is None:
        try:
            flow = await t_get(ctx, {"n": n, "include_bodies": False})
        except ToolError:
            raise NotFound(uri) from None
        return {"uri": uri, "mimeType": "application/json", "text": json.dumps(flow, ensure_ascii=False, default=str)}
    got = await ctx.db(ctx.q.body, n, side)
    if got is None:
        raise NotFound(uri)
    body, ctype = got
    mime = ctype.split(";")[0].strip() or "application/octet-stream"
    try:
        return {"uri": uri, "mimeType": mime, "text": body.decode("utf-8")}
    except UnicodeDecodeError:
        return {"uri": uri, "mimeType": mime, "blob": base64.b64encode(body).decode()}


# ---------------------------------------------------------------------------- prompts

PROMPTS = [
    {"name": "investigate_failures", "title": "Investigate failed requests",
     "description": "Find the requests that failed and explain why", "arguments": [{"name": "session", "description": "limit to one session"}]},
    {"name": "summarize_run", "title": "Summarize a run",
     "description": "What a session's tools talked to, what failed, and anything unusual", "arguments": [{"name": "session", "required": True}]},
    {"name": "explain_flow", "title": "Explain one flow",
     "description": "Walk through one recorded request and response", "arguments": [{"name": "n", "required": True}]},
]


def get_prompt(name: str, args: dict) -> dict:
    session = args.get("session") or ""
    if session and not (isinstance(session, str) and SESSION.fullmatch(session)):
        raise ToolError(f"session must match {SESSION.pattern}")
    pin = f" session:{session}" if session else ""
    if name == "investigate_failures":
        text = (f"Look at the failed requests in the recorded proxy traffic{' of session ' + session if session else ''}. "
                f"Call traffic_search with query 'has:fail{pin}', then traffic_get on the most telling ones (bodies explain most "
                f"4xx/5xx). Also check traffic_events for auth and TLS failures (a client that doesn't trust the proxy CA never "
                f"produces a flow). Group the failures by cause and say, for each, what would fix it.")
    elif name == "summarize_run":
        if not session:
            raise ToolError("summarize_run needs a session")
        text = (f"Summarize what session {session} did on the network. Start with traffic_sessions query 'session:{session}' and "
                f"traffic_search query 'session:{session}' order asc (page through it). Report: which tools talked to which hosts, "
                f"how many requests each, what failed (has:fail{pin}) and why, long-running streams, and anything unexpected, such "
                f"as hosts unrelated to the task or credentials sent in clear text.")
    elif name == "explain_flow":
        n = args.get("n")
        if not (isinstance(n, int) or (isinstance(n, str) and n.isascii() and n.isdigit())):
            raise ToolError("n must be a flow number")
        text = (f"Explain recorded flow #{n}. Call traffic_get with n={n}; for streams also traffic_sse, traffic_ws or traffic_grpc. "
                f"Say who sent it (session, tool, call), what it asked for, what came back, how long it took, and whether anything "
                f"looks wrong.")
    else:
        raise NotFound(name)
    return {"description": next(p["description"] for p in PROMPTS if p["name"] == name),
            "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}
