"""The repeater: resend a recorded request, edited or not, through the proxy. The new flow is recorded like any other,
in the original's session, as tool `repeater` with call id = the original's n, and with `replay_of` = that n.

Opt-in (`m2c_repeater`): off (the default), admin (the admin token only) or on (also a session token, for its own
session's flows). It runs mitmproxy's replay handler on the proxy's event loop, so the request leaves from the proxy
with the proxy's upstream settings; proxy credentials and x-m2c-* headers are never sent on. Limits: a few resends in
flight at once, one per caller, and a per-minute budget per caller.
"""

from __future__ import annotations

import asyncio
import base64
import collections
import re
import time
import urllib.parse

from .notes import NoteDenied as Denied  # 403: the same meaning

MAX_INFLIGHT = 4
PER_MINUTE = 60
BODY_MAX = 8 << 20
WAIT_FOR_ROW_S = 3.0
DROP = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "upgrade", "content-length",
        "host"}
TOKEN = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}")


class RepeatError(ValueError):
    """A bad request to resend (400)."""


class Conflict(ValueError):
    """The stored request can't be resent as it is (409)."""


class Busy(RuntimeError):
    """Over the limits (429)."""


def _headers(base: list, overrides: dict) -> list[tuple[str, str]]:
    if "headers" in overrides:
        given = overrides["headers"]
        if not isinstance(given, list) or len(given) > 200 or not all(isinstance(h, list) and len(h) == 2 for h in given):
            raise RepeatError("headers: a list of [name, value] pairs (up to 200)")
        pairs = [(str(k), str(v)) for k, v in given]
    else:
        pairs = [(k, v) for k, v in base]
    remove = overrides.get("headers_remove", [])
    if not isinstance(remove, list) or not all(isinstance(x, str) for x in remove):
        raise RepeatError("headers_remove: a list of header names")
    gone = {x.lower() for x in remove}
    out = []
    for k, v in pairs:
        low = k.lower()
        if low in DROP or low.startswith("x-m2c-") or low in gone:
            continue
        if not TOKEN.fullmatch(k):
            raise RepeatError(f"bad header name {k[:40]!r}")
        if any(c in v for c in "\r\n\0"):
            raise RepeatError(f"header {k}: no line breaks or NUL in a value")
        out.append((k, v))
    if sum(len(k) + len(v) for k, v in out) > 64 << 10:
        raise RepeatError("headers: 64 KiB at most")
    return out


def _body(overrides: dict, stored: bytes | None) -> tuple[bytes, bool]:
    """(body, plain): `plain` when the bytes are the unencoded body (to be encoded per Content-Encoding)."""
    if "body" in overrides and "body_base64" in overrides:
        raise RepeatError("body or body_base64, not both")
    if "body" in overrides:
        if not isinstance(overrides["body"], str):
            raise RepeatError("body: text (body_base64 for bytes)")
        data = overrides["body"].encode("utf-8")
    elif "body_base64" in overrides:
        try:
            data = base64.b64decode(overrides["body_base64"], validate=True)
        except (ValueError, TypeError):
            raise RepeatError("body_base64: not base64") from None
    else:
        return stored or b"", True
    if len(data) > BODY_MAX:
        raise RepeatError(f"body: {BODY_MAX >> 20} MiB at most")
    return data, True


def build(detail: dict, stored_body: bytes | None, overrides: dict):
    """An mitmproxy HTTPFlow for the original `detail` (Queries.flow) with `overrides`: method, url, headers (the whole
    list), headers_remove, body or body_base64. Raises RepeatError / Conflict."""
    from mitmproxy import connection, http

    if not isinstance(overrides, dict):
        raise RepeatError("a JSON object")
    unknown = set(overrides) - {"method", "url", "headers", "headers_remove", "body", "body_base64"}
    if unknown:
        raise RepeatError(f"unknown fields: {', '.join(sorted(unknown))}")
    if detail.get("resp_capture") == "websocket":
        raise RepeatError("a WebSocket can't be resent")
    method = overrides.get("method", detail["method"])
    if not isinstance(method, str) or not TOKEN.fullmatch(method):
        raise RepeatError("method: an HTTP method")
    url = overrides.get("url", detail["url"])
    parts = urllib.parse.urlsplit(url) if isinstance(url, str) else None
    if parts is None or parts.scheme not in ("http", "https") or not parts.hostname or any(c in url for c in " \r\n\0"):
        raise RepeatError("url: an http(s) URL")
    if not any(k in overrides for k in ("body", "body_base64")) and detail.get("req_body_truncated"):
        raise Conflict("the stored request body was cut at m2c_body_cap: give the body to send")
    body, plain = _body(overrides, stored_body)
    pairs = _headers(detail.get("req_headers") or [], overrides)
    enc = lambda x: x.encode("utf-8", "surrogateescape")  # noqa: E731
    req = http.Request.make(method.upper() if method.isalpha() else method, url, b"", http.Headers([(enc(k), enc(v)) for k, v in pairs]))
    if "host" not in req.headers:
        req.headers.insert(0, "Host", parts.netloc.rsplit("@", 1)[-1])
    if detail.get("grpc") and detail.get("http_version", "").startswith("HTTP/2"):
        req.http_version = "HTTP/2.0"  # gRPC needs HTTP/2; everything else goes out as HTTP/1.1
    encoded = "content-encoding" in req.headers
    if encoded and plain and (detail.get("req_body_decoded") or any(k in overrides for k in ("body", "body_base64"))):
        req.content = body  # stored decoded (or given plain): encoded again per Content-Encoding
    else:
        req.raw_content = body
    if req.raw_content or method.upper() in ("POST", "PUT", "PATCH"):
        req.headers["content-length"] = str(len(req.raw_content or b""))
    elif "content-length" in req.headers:
        del req.headers["content-length"]
    client = connection.Client(peername=("127.0.0.1", 0), sockname=("127.0.0.1", 0), timestamp_start=time.time())
    flow = http.HTTPFlow(client, connection.Server(address=(req.host, req.port)))
    flow.request = req
    flow.is_replay = "request"
    flow.metadata["m2c"] = {"session": detail["session"], "tool": "repeater", "call": str(detail["n"]), "user": "", "source": "none",
                            "tag": detail.get("tag") or "", "replay_of": int(detail["n"])}
    return flow


class Repeater:
    def __init__(self, mode: str = "off", timeout: int = 30):
        self.mode = mode
        self.timeout = timeout
        self.inflight = 0
        self.busy: set = set()
        self.recent: dict = collections.defaultdict(collections.deque)

    def allowed(self, admin: bool) -> bool:
        return self.mode == "on" or (self.mode == "admin" and admin)

    def _acquire(self, scope) -> None:
        now = time.monotonic()
        recent = self.recent[scope]
        while recent and recent[0] < now - 60:
            recent.popleft()
        if self.inflight >= MAX_INFLIGHT or scope in self.busy or len(recent) >= PER_MINUTE:
            raise Busy("too many resends: wait for the one in flight (one per caller, a few at once, 60 a minute)")
        self.inflight += 1
        self.busy.add(scope)
        recent.append(now)

    def _release(self, scope) -> None:
        self.inflight -= 1
        self.busy.discard(scope)

    async def send(self, flow) -> str:
        """Replay `flow` through the proxy (on its event loop); on timeout record it as an error and say so."""
        from mitmproxy import ctx
        from mitmproxy import flow as mflow
        from mitmproxy.addons.clientplayback import ReplayHandler
        from mitmproxy.proxy.layers.http import HttpErrorHook

        handler = ReplayHandler(flow, ctx.options)
        try:
            await asyncio.wait_for(handler.replay(), self.timeout)
        except asyncio.TimeoutError:
            # record the timeout first (the recorder writes the row once), then close the server connection, whose
            # own "server closed connection" error then finds the flow already recorded
            flow.error = mflow.Error(f"m2c repeater: no complete response within {self.timeout} s")
            await ctx.master.addons.handle_lifecycle(HttpErrorHook(flow))
            for t in list(handler.transports.values()):
                if t.handler:
                    t.handler.cancel()
            return flow.error.msg if flow.error and flow.error.msg.startswith("m2c repeater") else f"m2c repeater: no complete response within {self.timeout} s"
        return ""

    async def resend(self, db, q, n: int, overrides: dict, admin: bool, scope) -> dict:
        """Resend flow n (as the scoped Queries `q` sees it) with `overrides`; wait until the new flow is stored."""
        if not self.allowed(admin):
            raise Denied("the repeater is off (m2c_repeater=off)" if self.mode == "off" else "the repeater needs the admin token here")
        detail = await db(q.flow, n)
        if detail is None:
            raise LookupError(f"no flow #{n}")
        stored = None
        if detail["req_body_stored"] and not any(k in (overrides or {}) for k in ("body", "body_base64")):
            got = await db(q.body, n, "req")
            stored = got[0] if got else b""
        flow = build(detail, stored, overrides or {})
        self._acquire(scope)
        try:
            timed_out = await self.send(flow)
        finally:
            self._release(scope)
        new_n = (flow.metadata.get("m2c") or {}).get("n")
        if not new_n or new_n == n:
            raise RuntimeError("the resent request was not recorded")
        deadline = time.monotonic() + WAIT_FOR_ROW_S
        while await db(q.flow, new_n) is None and time.monotonic() < deadline:
            await asyncio.sleep(0.1)  # the writer flushes a few times a second: then /v1/flows/N and /v1/diff see it
        resp = flow.response
        return {"n": new_n, "replay_of": n, "method": flow.request.method, "url": flow.request.url,
                "status": resp.status_code if resp else 0, "reason": resp.reason if resp else "",
                "error": timed_out or (flow.error.msg if flow.error else ""),
                "duration_ms": int(((resp.timestamp_end or time.time()) - flow.request.timestamp_start) * 1000) if resp and flow.request.timestamp_start else 0}
