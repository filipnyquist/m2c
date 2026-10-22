"""The live API, served by tornado (a mitmproxy dependency) on mitmproxy's own event loop.

chDB locks the data directory to this process, so every live read comes through here. Queries run on two small
thread pools, each thread with its own read-only chDB session: the heavy lane (body: searches, grep, reports, HAR,
database-filtered tails) is apart from the interactive one, so a slow query never blocks the writer or `ls`.
Session-scoped callers get at most one heavy query and a share of the interactive lane at a time, and work whose
client has gone is skipped. `tail` streams from the in-memory live feed. Auth: `Authorization: Bearer <admin token>`
(everything) or `Bearer <session>:<proxy token>` (that session only, and only the proxy events that concern it).
There is no raw SQL endpoint: everything goes through the filter language and the queries in queries.py.
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import ipaddress
import json
import logging
import os
import secrets
import threading
import time
import urllib.parse
import weakref
from concurrent.futures import ThreadPoolExecutor
from importlib import resources

import tornado.httpserver
import tornado.iostream
import tornado.netutil
import tornado.web

from . import __version__
from .db import open_session
from .filters import SPEC, FilterError, heavy as _heavy_q, help_text, split_matcher
from .identity import SESSION, AuthError, check_token
from .mcp import NO_BATCHES_FROM, PARSE_ERROR, PROTOCOL_VERSIONS, McpServer, rpc_error
from .mcp_tools import Ctx, ToolError
from .notes import NoteDenied, NoteError
from .repeater import Busy, Conflict, RepeatError
from .queries import DB, Forbidden, Queries

log = logging.getLogger("m2c.api")

# Tails whose filter needs the database (body:, source:, has:truncated) query it for every batch of finished flows.
DB_TAILS_PER_SCOPE = 2
DB_TAILS_ADMIN = 4
DB_TAILS_TOTAL = 8
CACHE_TTL = 5  # s
CACHE_MAX = 512
U64_MAX = (1 << 64) - 1  # chDB wraps an out-of-range parameter instead of rejecting it: bound them here


class ClientGone(Exception):
    """The client disconnected before its query started."""


def _matches(pred, item) -> bool:
    try:
        return bool(pred(item))
    except Exception:  # noqa: BLE001 - as in the live feed: a predicate that fails on an odd summary skips it
        return False


def _loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False


class Api:
    def __init__(self, st, listen: str, readers: int = 3, ui: bool = True, allowed_hosts: str = ""):
        self.st = st
        host, _, port = listen.rpartition(":")
        self.host = host.strip("[]") or "127.0.0.1"
        self.port = int(port)
        self.ui = ui
        self.allowed_hosts = {h.strip().lower() for h in allowed_hosts.split(",") if h.strip()}
        self.token = self._admin_token(st.config.data / "api-token")
        self.started = time.time()
        self._local = threading.local()
        heavy = max(1, readers // 3)
        self.pool = ThreadPoolExecutor(max_workers=max(1, readers - heavy), thread_name_prefix="m2c-reader")
        self.heavy_pool = ThreadPoolExecutor(max_workers=heavy, thread_name_prefix="m2c-reader-heavy")
        self.scoped_share = max(1, readers - heavy - 1)  # interactive queries in flight per session-scoped token
        self._limits: weakref.WeakValueDictionary = weakref.WeakValueDictionary()
        self.db_tails: dict[str | None, int] = {}
        self.cache: dict[tuple, tuple[float, object]] = {}  # facets and suggestions, typed fast and asked often
        self.server: tornado.httpserver.HTTPServer | None = None
        self.info_path = st.config.data / "api.json"
        self.proxy_addr = ""

    @staticmethod
    def _admin_token(path) -> str:
        """Kept per data directory, so a restarted proxy keeps open UIs and clients working."""
        try:
            token = path.read_text().strip()
            if len(token) >= 24:
                return token
        except OSError:
            pass
        token = secrets.token_urlsafe(24)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(token + "\n")
        return token

    # ------------------------------------------------------------------ chDB readers

    def _run(self, sql: str, params: dict | None, fmt: str) -> bytes:
        sess = getattr(self._local, "sess", None)
        if sess is None:
            sess = self._local.sess = open_session(self.st.config.data, readonly=True)
        return sess.query(sql, fmt, params=params).bytes()

    @staticmethod
    def _job(fn, args, gone):
        if gone is not None and gone():
            raise ClientGone()
        return fn(*args)

    async def run(self, fn, *args, heavy: bool = False, scope: str | None = None, gone=None):
        """Run `fn` on a reader thread: the heavy or the interactive lane; a session-scoped caller waits for its share."""
        loop = asyncio.get_running_loop()
        pool = self.heavy_pool if heavy else self.pool
        if scope is None:
            return await loop.run_in_executor(pool, self._job, fn, args, gone)
        sem = self._limits.get((scope, heavy))
        if sem is None:
            sem = self._limits[(scope, heavy)] = asyncio.Semaphore(1 if heavy else self.scoped_share)
        async with sem:
            return await loop.run_in_executor(pool, self._job, fn, args, gone)

    def db_tail_slot(self, scope: str | None) -> None:
        """Claim a database-filtered tail; HTTP 429 above the limits."""
        limit = DB_TAILS_ADMIN if scope is None else DB_TAILS_PER_SCOPE
        if sum(self.db_tails.values()) >= DB_TAILS_TOTAL or self.db_tails.get(scope, 0) >= limit:
            raise tornado.web.HTTPError(429, "too many open tails with body:/source: filters; close one or filter without them")
        self.db_tails[scope] = self.db_tails.get(scope, 0) + 1

    def db_tail_release(self, scope: str | None) -> None:
        left = self.db_tails.get(scope, 1) - 1
        if left > 0:
            self.db_tails[scope] = left
        else:
            self.db_tails.pop(scope, None)

    # ------------------------------------------------------------------ lifecycle

    def start(self) -> None:
        logging.getLogger("tornado.access").setLevel(logging.ERROR)
        app = tornado.web.Application(
            [
                (r"/healthz", Health, {"api": self}),
                (r"/v1/scan", ScanHandler, {"api": self}),
                (r"/v1/sessions", SessionsHandler, {"api": self}),
                (r"/v1/filter-help", FilterHelpHandler, {"api": self}),
                (r"/v1/report", ReportHandler, {"api": self}),
                (r"/v1/facets", FacetsHandler, {"api": self}),
                (r"/v1/suggest", SuggestHandler, {"api": self}),
                (r"/v1/grep", GrepHandler, {"api": self}),
                (r"/v1/diff", DiffHandler, {"api": self}),
                (r"/v1/flows", FlowsHandler, {"api": self}),
                (r"/v1/flows/(\d+)", FlowHandler, {"api": self}),
                (r"/v1/flows/(\d+)/body/(req|resp)", BodyHandler, {"api": self}),
                (r"/v1/flows/(\d+)/(sse|ws|grpc)", ChildrenHandler, {"api": self}),
                (r"/v1/flows/(\d+)/curl", CurlHandler, {"api": self}),
                (r"/v1/flows/(\d+)/export", ExportHandler, {"api": self}),
                (r"/v1/filter-check", FilterCheckHandler, {"api": self}),
                (r"/v1/flows/(\d+)/live", FlowLiveHandler, {"api": self}),
                (r"/v1/tail", TailHandler, {"api": self}),
                (r"/v1/har", HarHandler, {"api": self}),
                (r"/v1/events", EventsHandler, {"api": self}),
                (r"/v1/notes", NotesHandler, {"api": self}),
                (r"/v1/timeline/sessions", TimelineSessionsHandler, {"api": self}),
                (r"/v1/timeline", TimelineHandler, {"api": self}),
                (r"/v1/notes/([0-9a-fA-F-]{36})", NoteHandler, {"api": self}),
                (r"/v1/flows/(\d+)/notes", FlowNotesHandler, {"api": self}),
                (r"/v1/flows/(\d+)/resend", ResendHandler, {"api": self}),
                (r"/v1/events/counts", EventCountsHandler, {"api": self}),
                (r"/v1/activity", ActivityHandler, {"api": self}),
                (r"/mcp", McpHandler, {"api": self}),
                (r"/ui", tornado.web.RedirectHandler, {"url": "/ui/"}),
                (r"/ui/(.*)", UiStatic, {"api": self, "path": str(resources.files("m2c").joinpath("ui")), "default_filename": "index.html"}),
                (r"/", tornado.web.RedirectHandler, {"url": "/ui/"}),
            ],
            compress_response=True,
        )
        try:
            sockets = tornado.netutil.bind_sockets(self.port, self.host)
        except OSError as e:
            log.warning("m2c: API port %s is taken (%s); using a random port", self.port, e)
            sockets = tornado.netutil.bind_sockets(0, self.host)
        self.port = sockets[0].getsockname()[1]
        self.server = tornado.httpserver.HTTPServer(app, xheaders=False, max_body_size=8 << 20)
        self.server.add_sockets(sockets)
        info = {"url": self.url, "token": self.token, "pid": os.getpid(), "scan_id": self.st.config.scan_id, "proxy": self.proxy_addr}
        fd = os.open(self.info_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(info, f)
        log.warning("m2c: API on %s  UI: %s/ui/#token=%s", self.url, self.url, self.token)

    @property
    def url(self) -> str:
        host = f"[{self.host}]" if ":" in self.host else self.host
        return f"http://{host}:{self.port}"

    def stop(self) -> None:
        if self.server is not None:
            self.server.stop()
        try:
            if self.info_path.exists() and json.loads(self.info_path.read_text()).get("pid") == os.getpid():
                self.info_path.unlink()
        except (OSError, ValueError):
            pass
        self.pool.shutdown(wait=False, cancel_futures=True)
        self.heavy_pool.shutdown(wait=False, cancel_futures=True)

    # ------------------------------------------------------------------ auth

    def scope_for(self, header: str | None) -> tuple[bool, str | None]:
        """(admin, scope) for an Authorization header; raises PermissionError."""
        if not header or not header.lower().startswith("bearer "):
            raise PermissionError("missing bearer token")
        value = header[7:].strip()
        if not value.isascii():  # compare_digest raises TypeError on non-ASCII str (tornado decodes headers as latin-1)
            raise PermissionError("bad token")
        if hmac.compare_digest(value.encode(), self.token.encode()):
            return True, None
        session, sep, tok = value.partition(":")
        if sep and SESSION.fullmatch(session) and self.st.config.auth == "token":
            try:
                check_token(self.st.auth.secrets, session, tok)
            except AuthError as e:
                raise PermissionError(f"bad session token ({e})") from None
            return False, session
        raise PermissionError("bad token")

    def host_ok(self, host_header: str) -> bool:
        host = host_header.rsplit(":", 1)[0] if not host_header.endswith("]") else host_header
        host = host.strip("[]").lower()
        if _loopback(host) or host == self.host.lower():
            # A literal loopback or bind address is never a rebound DNS name: the health check, `m2c` inside the
            # container (api.json holds the bind address) and local clients keep working with m2c_api_hosts set.
            return True
        if self.allowed_hosts:
            return host in self.allowed_hosts or host_header.lower() in self.allowed_hosts
        if _loopback(self.host):
            return False  # DNS-rebinding guard for a loopback API
        return True


class Base(tornado.web.RequestHandler):
    def initialize(self, api: Api):
        self.api = api
        self.admin = False
        self.scope: str | None = None
        self.gone = False

    def set_default_headers(self):
        self.set_header("Cache-Control", "no-store")
        self.set_header("X-Content-Type-Options", "nosniff")

    def prepare(self):
        if not self.api.host_ok(self.request.host or ""):
            raise tornado.web.HTTPError(421, "host not allowed")
        if getattr(self, "public", False):
            return
        try:
            self.admin, self.scope = self.api.scope_for(self.request.headers.get("Authorization"))
        except PermissionError as e:
            self.set_header("WWW-Authenticate", 'Bearer realm="m2c"')
            raise tornado.web.HTTPError(401, str(e)) from None
        self.q = Queries(self.api._run, self.scope, self.api.st.config.proto_file)

    def write_error(self, status_code, **kwargs):
        exc = kwargs.get("exc_info", (None, None, None))[1]
        message = getattr(exc, "log_message", None) or (str(exc) if exc else self._reason)
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps({"error": message, "status": status_code}))

    def send_json(self, value):
        self.set_header("Content-Type", "application/json")
        self.finish(json.dumps(value, ensure_ascii=False, default=str))

    def on_connection_close(self):
        self.gone = True

    async def call(self, fn, *args, heavy: bool = False):
        try:
            return await self.api.run(fn, *args, heavy=heavy, scope=self.scope, gone=lambda: self.gone)
        except ClientGone:
            raise tornado.web.Finish() from None
        except FilterError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        except Forbidden as e:
            raise tornado.web.HTTPError(403, str(e)) from None
        except (RuntimeError, ValueError) as e:  # engine errors (a bad regex, ...) and bad argument values
            raise tornado.web.HTTPError(400, str(e).strip()[:2000]) from None

    async def cached(self, key: tuple, fn, *args, heavy: bool = False):
        """`fn(*args)` on a reader, remembered for CACHE_TTL seconds per caller scope, or until the writer stores rows."""
        key = (self.scope, sum(self.api.st.writer.counters.written.values()), *key)
        hit = self.api.cache.get(key)
        if hit is not None and time.monotonic() - hit[0] < CACHE_TTL:
            return hit[1]
        value = await self.call(fn, *args, heavy=heavy)
        if len(self.api.cache) >= CACHE_MAX:
            self.api.cache.clear()
        self.api.cache[key] = (time.monotonic(), value)
        return value

    def bool_arg(self, name: str, default: bool) -> bool:
        value = self.get_argument(name, None)
        if value in (None, ""):
            return default
        if value.lower() not in ("1", "0", "true", "false"):
            raise tornado.web.HTTPError(400, f"{name} is 1 or 0")
        return value.lower() in ("1", "true")

    def int_arg(self, name: str, default: int | None = None, hi: int = U64_MAX) -> int | None:
        value = self.get_argument(name, None)
        if value in (None, ""):
            return default
        try:
            out = int(value)
        except ValueError:
            raise tornado.web.HTTPError(400, f"{name} must be an integer") from None
        if not 0 <= out <= hi:
            raise tornado.web.HTTPError(400, f"{name} must be between 0 and {hi}")
        return out

    @staticmethod
    def flow_n(n: str) -> int:
        """The `n` of a /v1/flows/N path (the route allows digits only)."""
        if int(n) > U64_MAX:
            raise tornado.web.HTTPError(404, f"no flow #{n[:30]}")
        return int(n)


class Health(Base):
    public = True

    def get(self):
        self.send_json({"ok": True, "version": __version__})


class ScanHandler(Base):
    async def get(self):
        stats = await self.call(self.q.stats)
        st = self.api.st
        stats.update(scan_id=st.config.scan_id, version=__version__, uptime_s=int(time.time() - self.api.started), scope=self.scope,
                     repeater=st.repeater.allowed(self.admin))
        if self.scope is None:  # process-wide counters: a scoped caller sees its own session's totals only
            stats.update(live_ring=len(st.live.ring), last_n=max(stats.get("last_n") or 0, st.last_n()))
        if self.admin:
            stats["writer"] = st.writer.counters.flat()
            stats["auth"] = st.config.auth
            stats["data"] = str(st.config.data)
        self.send_json(stats)


class SessionsHandler(Base):
    async def get(self):
        q = self.get_argument("q", "")
        self.send_json(await self.call(self.q.sessions, q, heavy=_heavy_q(q)))


class FlowsHandler(Base):
    async def get(self):
        order = self.get_argument("order", "desc")
        if order not in ("asc", "desc"):
            raise tornado.web.HTTPError(400, "order is asc or desc")
        q = self.get_argument("q", "")
        self.send_json(await self.call(self.q.flows, q, self.int_arg("limit", 100), self.int_arg("cursor"), order, heavy=_heavy_q(q)))


class FilterHelpHandler(Base):
    async def get(self):
        # each key's facet is a SQL expression: clients only learn that the key has suggestible values
        keys = [{**{k: v for k, v in s.items() if k != "facet"}, "facets": "facet" in s} for s in SPEC]
        self.send_json({"keys": keys, "text": help_text()})


class FacetsHandler(Base):
    async def get(self):
        key, prefix, q = self.get_argument("key", ""), self.get_argument("prefix", ""), self.get_argument("q", "")
        limit = self.int_arg("limit", 20)
        self.send_json(await self.cached(("facets", key, prefix, q, limit), self.q.facets, key, prefix, q, limit, heavy=_heavy_q(q)))


class SuggestHandler(Base):
    async def get(self):
        q = self.get_argument("q", "")
        try:
            pred, _ = split_matcher(q, self.scope)
        except FilterError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        live = self.api.st.live
        open_flows = sum(1 for f in list(live.open.values()) if _matches(pred, f))
        self.send_json(await self.cached(("suggest", q, open_flows), self.q.suggest, q, open_flows, heavy=_heavy_q(q)))


class ReportHandler(Base):
    async def get(self):
        self.send_json(await self.call(self.q.report, self.get_argument("q", ""), self.get_argument("by", "tool"),
                                       self.int_arg("limit", 50), heavy=True))


class GrepHandler(Base):
    async def get(self):
        self.send_json(await self.call(
            self.q.grep, self.get_argument("pattern", ""), self.bool_arg("regex", False), self.bool_arg("ci", True),
            self.get_argument("side", "both"), self.get_argument("q", ""), self.get_argument("in", "body"),
            self.int_arg("context", 80), self.int_arg("limit", 20), self.int_arg("per_flow", 3), heavy=True))


class DiffHandler(Base):
    async def get(self):
        a, b = self.int_arg("a"), self.int_arg("b")
        if a is None or b is None:
            raise tornado.web.HTTPError(400, "a and b are flow numbers")
        out = await self.call(self.q.diff, a, b, 256 << 10, self.bool_arg("redact", True), heavy=True)
        if out is None:
            raise tornado.web.HTTPError(404, f"no flow #{a} or #{b}")
        self.send_json(out)


class FlowHandler(Base):
    async def get(self, n):
        flow = await self.call(self.q.flow, self.flow_n(n))
        if flow is None:
            pending = self.api.st.live.get(int(n))
            if pending is not None and (self.scope is None or pending["session"] == self.scope):
                return self.send_json({**pending, "pending": True})
            raise tornado.web.HTTPError(404, f"no flow #{n}")
        self.send_json(flow)


class BodyHandler(Base):
    async def get(self, n, side):
        got = await self.call(self.q.body, self.flow_n(n), side, self.int_arg("max"))
        if got is None:
            raise tornado.web.HTTPError(404, f"no flow #{n}")
        body, ctype = got
        # Captured bodies are untrusted: never let a browser render them on the API's origin.
        self.set_header("Content-Type", "application/octet-stream")
        self.set_header("Content-Security-Policy", "sandbox; default-src 'none'")
        self.set_header("Content-Disposition", f'attachment; filename="{n}-{side}.bin"')
        self.set_header("X-M2C-Content-Type", ctype.encode("ascii", "replace").decode() if ctype else "")
        self.finish(body)


class ChildrenHandler(Base):
    async def get(self, n, kind):
        args = [self.flow_n(n), self.int_arg("after", 0, hi=(1 << 32) - 1), self.int_arg("limit", 1000)]
        if kind == "grpc":
            # decoding is CPU work: the heavy lane, so it never slows lists down
            args.append(self.get_argument("decode", "1") != "0")
            self.send_json(await self.call(self.q.grpc, *args, heavy=True))
            return
        fn = self.q.sse if kind == "sse" else self.q.ws
        self.send_json(await self.call(fn, *args))


class ExportHandler(Base):
    async def get(self, n):
        fmt = self.get_argument("format", "curl")
        out = await self.call(self.q.export, self.flow_n(n), fmt)
        if out is None:
            raise tornado.web.HTTPError(404, f"no flow #{n}")
        self.set_header("Content-Type", "application/json" if fmt == "har" else "text/plain; charset=utf-8")
        self.finish(out + ("" if out.endswith("\n") else "\n"))


class FilterCheckHandler(Base):
    """Whether a query parses, without touching the database: the UI checks before it applies one."""

    def get(self):
        try:
            _, exact = split_matcher(self.get_argument("q", ""), self.scope)
        except FilterError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        self.send_json({"ok": True, "live": exact})


class CurlHandler(Base):
    async def get(self, n):
        cmd = await self.call(self.q.curl, self.flow_n(n))
        if cmd is None:
            raise tornado.web.HTTPError(404, f"no flow #{n}")
        self.set_header("Content-Type", "text/plain; charset=utf-8")
        self.finish(cmd + "\n")


class HarHandler(Base):
    async def get(self):
        self.set_header("Content-Disposition", 'attachment; filename="m2c.har"')
        self.send_json(await self.call(self.q.har, self.get_argument("q", ""), self.int_arg("limit", 1000), heavy=True))


NS_MAX = 2000


class NoteBase(Base):
    def json_body(self) -> dict:
        try:
            body = json.loads(self.request.body or b"{}")
        except ValueError:
            raise tornado.web.HTTPError(400, "the body is not JSON") from None
        if not isinstance(body, dict):
            raise tornado.web.HTTPError(400, "the body is a JSON object")
        return body

    def write_note(self, fn, *args):
        try:
            return fn(*args, self.admin, self.scope)
        except NoteError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        except NoteDenied as e:
            raise tornado.web.HTTPError(403, str(e)) from None
        except RuntimeError as e:
            raise tornado.web.HTTPError(503, str(e)) from None

    def mine(self, note: dict) -> bool:
        return self.scope is None or note["session"] == self.scope


class NotesHandler(NoteBase):
    """GET /v1/notes?ns=1,2,3 (the notes on those flows) or ?q= (on the flows a filter matches)."""

    async def get(self):
        raw = self.get_argument("ns", None)
        ns = None
        if raw is not None:
            parts = [p for p in raw.split(",") if p]
            if len(parts) > NS_MAX or not all(p.isascii() and p.isdigit() and len(p) <= 20 for p in parts):
                raise tornado.web.HTTPError(400, f"ns: up to {NS_MAX} flow numbers, comma-separated")
            ns = [int(p) for p in parts]
        q = self.get_argument("q", "")
        notes = self.api.st.notes
        stored = await self.call(self.q.notes, ns, q, None, self.int_arg("limit", 1000), heavy=_heavy_q(q))
        wanted = set(ns or ())
        if ns is None and q:  # a note written a moment ago may not be stored yet: does its flow match q?
            fresh = sorted({v["n"] for _, v in notes.pending.values()} - {x["n"] for x in stored})
            hits = await self.call(self.q.hits, q, fresh, heavy=True) if fresh else {}
            wanted = {x["n"] for x in stored} | {n for n, hit in hits.items() if hit}
        keep = lambda v: self.mine(v) and (v["n"] in wanted if (ns is not None or q) else True)  # noqa: E731
        self.send_json(notes.merge(stored, keep))


class FlowNotesHandler(NoteBase):
    async def get(self, n):
        n = self.flow_n(n)
        stored = await self.call(self.q.notes, [n])
        self.send_json(self.api.st.notes.merge(stored, lambda v: v["n"] == n and self.mine(v)))

    async def post(self, n):
        body = self.json_body()
        flow = await self.call(self.q.flow, self.flow_n(n))
        if flow is None:
            raise tornado.web.HTTPError(404, f"no flow #{n}")
        self.set_status(201)
        self.send_json(self.write_note(self.api.st.notes.add, flow, body))


class NoteHandler(NoteBase):
    async def current(self, nid: str) -> dict:
        nid = nid.lower()
        stored = await self.call(self.q.notes, None, "", nid)
        found = [v for v in self.api.st.notes.merge(stored, lambda v: v["id"] == nid and self.mine(v)) if v["id"] == nid]
        if not found:
            raise tornado.web.HTTPError(404, f"no note {nid}")
        return found[0]

    async def patch(self, nid):
        body = self.json_body()
        self.send_json(self.write_note(self.api.st.notes.change, await self.current(nid), body))

    async def delete(self, nid):
        self.write_note(self.api.st.notes.change, await self.current(nid), None)
        self.set_status(204)
        self.finish()


class TimelineSessionsHandler(Base):
    """The sessions whose flows carry tool call ids (the timeline's session list)."""

    async def get(self):
        self.send_json(await self.call(self.q.call_sessions))


class TimelineHandler(Base):
    async def get(self):
        session = self.get_argument("session", "") or (self.scope or "")
        if not SESSION.fullmatch(session):
            raise tornado.web.HTTPError(400, "session: which session's timeline")
        self.send_json(await self.call(self.q.timeline, session, self.int_arg("limit", 2000), heavy=True))


class ResendHandler(NoteBase):
    """POST {method?, url?, headers?, headers_remove?, body? | body_base64?}: resend flow N through the proxy."""

    async def post(self, n):
        body = self.json_body()
        db = lambda fn, *args, heavy=False: self.api.run(fn, *args, heavy=heavy, scope=self.scope, gone=None)  # noqa: E731
        try:
            out = await self.api.st.repeater.resend(db, self.q, self.flow_n(n), body, self.admin, self.scope)
        except RepeatError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        except NoteDenied as e:
            raise tornado.web.HTTPError(403, str(e)) from None
        except LookupError as e:
            raise tornado.web.HTTPError(404, str(e)) from None
        except Conflict as e:
            raise tornado.web.HTTPError(409, str(e)) from None
        except Busy as e:
            raise tornado.web.HTTPError(429, str(e)) from None
        self.set_status(201)
        self.send_json(out)


class EventsHandler(Base):
    async def get(self):
        severity = self.get_argument("severity", "")
        if severity not in ("", "debug", "info", "warn", "error"):
            raise tornado.web.HTTPError(400, "severity is debug, info, warn or error")
        self.send_json(await self.call(self.q.events, self.get_argument("kind", ""), self.int_arg("limit", 100), severity))


class EventCountsHandler(Base):
    async def get(self):
        since = self.int_arg("since", 0, hi=(1 << 62))
        self.send_json(await self.cached(("event-counts", since), self.q.event_counts, since))


class ActivityHandler(Base):
    async def get(self):
        q = self.get_argument("q", "")
        buckets = self.int_arg("buckets", 24)
        self.send_json(await self.cached(("activity", q, buckets), self.q.activity, q, buckets, heavy=_heavy_q(q)))


def live_stats(api: Api, scope: str | None) -> dict:
    st = api.st
    out = {"scan_id": st.config.scan_id, "open": sum(1 for f in st.live.open.values() if scope is None or f["session"] == scope)}
    if scope is None:  # process-wide counters: not for session-scoped callers
        c = st.writer.counters
        out.update(last_n=st.last_n(), queued=c.queued, written=sum(c.written.values()), dropped=sum(c.dropped.values()), errors=c.hook_errors + c.tee_errors + c.insert_errors)
    return out


class SseStream(Base):
    """Shared plumbing for text/event-stream responses."""

    def start_stream(self):
        self.set_header("Content-Type", "text/event-stream")
        self.set_header("X-Accel-Buffering", "no")

    def send_event(self, kind: str, item: dict, event_id=None):
        self.write(f"event: {kind}\n" + (f"id: {event_id}\n" if event_id is not None else "") + f"data: {json.dumps(item, ensure_ascii=False, default=str)}\n\n")


class TailHandler(SseStream):
    """`event: open` when a long-lived flow starts, `event: flow` when any flow finishes, `event: stats` every 2 s.

    Every `flow` and `stats` event carries `id: <epoch>.<seq>`; reconnecting with `since=` (or `Last-Event-ID`) set to
    the last one replays the flows that finished in between. `event: resync` says that is impossible (the proxy
    restarted, or the client fell more than a ring behind): reload the list from /v1/flows.
    """

    PENDING_TTL = 600  # s: a flow not in the database by then was dropped by the writer
    CHECK_BATCH = 1000

    def _resume(self, live):
        """The cursor to replay from, "resync" when the client's cursor is no use here, or None (a fresh tail)."""
        raw = self.get_argument("since", None) or self.request.headers.get("Last-Event-ID")
        if not raw:
            return None
        epoch, _, seq = raw.strip().partition(".")
        if epoch != live.epoch or not seq.isdigit() or int(seq) > live.seq:
            return "resync"
        return int(seq)

    def _resync(self, reason: str, missed: int = 0):
        self.send_event("resync", {"reason": reason, "missed": missed})

    async def get(self):
        q = self.get_argument("q", "")
        backlog = max(0, self.int_arg("backlog", 0))
        live = self.api.st.live
        try:
            pred, exact = split_matcher(q, self.scope)
        except FilterError as e:
            raise tornado.web.HTTPError(400, str(e)) from None
        resume = self._resume(live)
        if not exact:
            self.api.db_tail_slot(self.scope)
        sub = live.subscribe(pred, opens=exact)
        try:
            self.start_stream()
            await (self._live(live, sub, pred, backlog, resume) if exact else self._db(live, sub, pred, q, backlog, resume))
        except tornado.iostream.StreamClosedError:
            pass
        finally:
            live.unsubscribe(sub)
            if not exact:
                self.api.db_tail_release(self.scope)

    async def _live(self, live, sub, pred, backlog: int, resume):
        cursor = live.seq
        if resume == "resync":
            self._resync("restarted")
        elif resume is not None:
            items, missed = live.since(resume)
            if missed:
                self._resync("behind", missed)
            for seq, item in items:
                if _matches(pred, item):
                    self.send_event("flow", item, f"{live.epoch}.{seq}")
        elif backlog:
            for seq, item in live.recent(pred, backlog):
                self.send_event("flow", item, f"{live.epoch}.{seq}")
        for item in list(live.open.values()):
            if _matches(pred, item):
                self.send_event("open", item)
        self.send_event("stats", live_stats(self.api, self.scope), f"{live.epoch}.{cursor}")
        await self.flush()
        next_stats = time.monotonic() + 2
        while not self.gone:
            await sub.wait(max(0.05, next_stats - time.monotonic()))
            lost_opens = sub.lost
            sub.lost = 0
            for kind, item in sub.take():
                if item["n"] in live.open:  # not finished meanwhile: then only its `flow` event goes out
                    self.send_event(kind, item)
            if lost_opens:  # the queue overflowed: send the open flows again, the client dedupes by n
                for item in list(live.open.values()):
                    if _matches(pred, item):
                        self.send_event("open", item)
            items, missed = live.since(cursor)
            cursor = live.seq
            if missed:
                self._resync("behind", missed)
            for seq, item in items:
                if _matches(pred, item):
                    self.send_event("flow", item, f"{live.epoch}.{seq}")
            if time.monotonic() >= next_stats:
                next_stats = time.monotonic() + 2
                self.send_event("stats", live_stats(self.api, self.scope), f"{live.epoch}.{cursor}")
            await self.flush()

    async def _db(self, live, sub, pred, q: str, backlog: int, resume):
        """The filter needs the database: the live feed says which flows finished (`pred` pre-selects them), and
        once the writer has inserted them one query per batch says which match. Ordered by when flows finish, so a
        slow flow that started before a fast one is not skipped."""
        cursor = live.seq
        pending: dict[int, tuple[int, dict, float]] = {}  # n -> (seq, summary, monotonic time it finished)
        sent: set[int] = set()
        now = time.monotonic()

        def add(items):
            for seq, item in items:
                if item["n"] not in sent and _matches(pred, item):
                    pending[item["n"]] = (seq, item, time.monotonic())

        def event_id():
            return f"{live.epoch}.{min(v[0] for v in pending.values()) - 1 if pending else cursor}"

        if resume == "resync":
            self._resync("restarted")
        elif resume is not None:
            items, missed = live.since(resume)
            if missed:
                self._resync("behind", missed)
            add(items)
        elif backlog:
            page = await self.call(self.q.flows, q, backlog, None, "desc", heavy=True)
            for item in reversed(page["flows"]):
                self.send_event("flow", item)
            sent = {f["n"] for f in page["flows"]}
            # Finished just before this tail started, maybe not inserted yet when the page was read.
            cutoff = time.time() * 1000 - 10_000
            recent = []
            for seq, item in reversed(live.ring):
                if seq > cursor:
                    continue
                if (item.get("ts") or 0) + (item.get("duration_ms") or 0) < cutoff:
                    break
                recent.append((seq, item))
            add(recent[::-1])
        self.send_event("stats", live_stats(self.api, self.scope), event_id())
        await self.flush()
        next_stats = now + 2
        next_check = now
        while not self.gone:
            now = time.monotonic()
            wait = next_stats - now
            if pending:
                wait = min(wait, next_check - now)
            await sub.wait(max(0.05, wait))
            sub.take()
            items, missed = live.since(cursor)
            cursor = live.seq
            if missed:
                self._resync("behind", missed)
            add(items)
            now = time.monotonic()
            if pending and now >= next_check:
                batch = sorted(pending)[: self.CHECK_BATCH]
                try:
                    hits = await self.call(self.q.hits, q, batch, heavy=True)
                    took = time.monotonic() - now
                except tornado.web.HTTPError as e:  # e.g. the memory limit: keep the stream, try again later
                    self.send_event("error", {"error": e.log_message})
                    hits, took = {}, 2.5
                next_check = time.monotonic() + max(0.5, 4 * took)  # back off when the database is busy
                found = [n for n in batch if n in hits]
                for n in found:
                    seq, item, _ = pending.pop(n)
                    if hits[n]:
                        self.send_event("flow", item, event_id())
                for n, (_, _, t) in list(pending.items()):
                    if now - t > self.PENDING_TTL:
                        del pending[n]
            if time.monotonic() >= next_stats:
                next_stats = time.monotonic() + 2
                self.send_event("stats", live_stats(self.api, self.scope), event_id())
            await self.flush()


def _child_json(kind: str, row: dict, proto_file: str | None = None) -> dict:
    if kind == "grpc":
        keys = ("seq", "dir_seq", "ts", "ms_since_req", "from_client", "service", "method", "compressed", "encoding", "size",
                "truncated", "partial")
        out = {k: row.get(k) for k in keys}
        out["preview"] = bool(row.get("_preview"))
        data = row.get("data") or b""
        out["stored"] = len(data)
        out["base64"] = base64.b64encode(data).decode()
        complete = not out["truncated"] and not out["partial"] and not out["compressed"]
        out["decoded"], out["decoded_as"] = "", "" if complete else "incomplete"
        if complete:
            from . import grpc

            path = f"/{row.get('service')}/{row.get('method')}" if row.get("service") else ""
            out["decoded"], out["decoded_as"] = grpc.decode(data, path, bool(row.get("from_client")), proto_file)
        return out
    if kind == "sse":
        keys = ("seq", "ts", "ms_since_req", "event", "id", "retry_ms", "data", "size", "truncated", "partial")
        out = {k: row.get(k) for k in keys}
        out["preview"] = bool(row.get("_preview"))
        return out
    content = row.get("content") or b""
    out = {k: row.get(k) for k in ("seq", "ts", "from_client", "opcode", "size", "truncated", "injected", "dropped")}
    out["preview"] = bool(row.get("_preview"))
    text = None
    if row.get("opcode") == "text":
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            if row.get("_preview"):  # cut inside a character
                text = content.decode("utf-8", "ignore")
    out["text"] = text or ""
    out["base64"] = "" if text is not None else base64.b64encode(content).decode()
    return out


class FlowLiveHandler(SseStream):
    """Live SSE events / WebSocket messages of one open flow, then `event: end` with its final summary.

    The first events come from the in-memory previews (first 4 KiB, `preview: true`). A reader too slow for the
    flow gets `event: lost` {count, after}: fetch the gap from /v1/flows/N/sse|ws?after=. `end` always arrives.
    """

    async def get(self, n):
        n = int(n)
        live = self.api.st.live
        item = live.open.get(n)
        if item is not None and self.scope is not None and item["session"] != self.scope:
            item = None
        self.start_stream()
        if item is None:
            done = live.by_n.get(n)
            self.send_event("end", done if done and (self.scope is None or done["session"] == self.scope) else {"n": n})
            return self.finish()
        sub = live.subscribe_flow(n)
        try:
            self.send_event("open", item)
            last_seq = 0
            for kind, row in list(live.children.get(n, ())):
                self.send_event(kind, _child_json(kind, row, self.api.st.config.proto_file))
                last_seq = row.get("seq") or last_seq
            await self.flush()
            while not self.gone:
                await sub.wait(15)
                ended, lost = sub.ended, sub.lost
                sub.lost = 0
                items = sub.take()
                if not items and ended is None and not lost:
                    self.write(": keepalive\n\n")
                    await self.flush()
                    continue
                for kind, row in items:
                    self.send_event(kind, _child_json(kind, row, self.api.st.config.proto_file))
                    last_seq = row.get("seq") or last_seq
                if lost:
                    self.send_event("lost", {"count": lost, "after": last_seq})
                if ended is not None:
                    self.send_event("end", ended)
                    break
                await self.flush()
            self.finish()
        except tornado.iostream.StreamClosedError:
            pass
        finally:
            live.unsubscribe(sub)


class McpHandler(Base):
    """MCP Streamable HTTP: one JSON-RPC message per POST, answered as application/json."""

    def check_xsrf_cookie(self):
        pass

    def _origin_ok(self) -> bool:
        """A browser page on another origin must not drive the MCP endpoint (DNS rebinding, CSRF): Streamable HTTP
        servers check Origin. Clients that aren't browsers send none."""
        origin = self.request.headers.get("Origin")
        if origin is None:
            return True
        netloc = urllib.parse.urlsplit(origin).netloc
        return bool(netloc) and self.api.host_ok(netloc)

    async def _db(self, fn, *args, heavy: bool = False):
        # not self.call: the tools report filter, permission and engine errors to the agent as tool results
        return await self.api.run(fn, *args, heavy=heavy, scope=self.scope, gone=lambda: self.gone)

    async def _resend(self, n: int, overrides: dict) -> dict:
        db = lambda fn, *args, heavy=False: self.api.run(fn, *args, heavy=heavy, scope=self.scope, gone=None)  # noqa: E731
        return await self.api.st.repeater.resend(db, self.q, n, overrides, self.admin, self.scope)

    def _claim_db_tail(self):
        try:
            self.api.db_tail_slot(self.scope)
        except tornado.web.HTTPError as e:
            raise ToolError(e.log_message) from None

    async def post(self):
        if not self._origin_ok():
            raise tornado.web.HTTPError(403, "cross-origin MCP requests are not allowed")
        version = self.request.headers.get("MCP-Protocol-Version")
        if version is not None and version not in PROTOCOL_VERSIONS:
            self.set_status(400)
            return self.send_json(rpc_error(None, -32600, f"unsupported MCP-Protocol-Version {version[:40]!r}"))
        try:
            msg = json.loads(self.request.body or b"{}")
        except ValueError:  # bad JSON, or bytes that are not UTF-8
            self.set_status(400)
            return self.send_json(PARSE_ERROR)
        if msg == []:
            self.set_status(400)
            return self.send_json(rpc_error(None, -32600, "invalid request: empty batch"))
        if isinstance(msg, list) and version is not None and version >= NO_BATCHES_FROM:
            self.set_status(400)
            return self.send_json(rpc_error(None, -32600, f"MCP {version} has no JSON-RPC batches: send one message per request"))
        st = self.api.st
        ctx = Ctx(self.q, self.admin, self._db, live=st.live, db_tail=(self._claim_db_tail, lambda: self.api.db_tail_release(self.scope)),
                  gone=lambda: self.gone, notes=st.notes,
                  resend=self._resend if st.repeater.allowed(self.admin) else None)
        server = McpServer(self.q, self.admin, ctx)
        replies = []
        for m in msg if isinstance(msg, list) else [msg]:
            reply = await server.handle(m)  # on the event loop: database reads go to the reader lanes through ctx.db
            if reply is not None:
                replies.append(reply)
        if not replies:
            self.set_status(202)
            return self.finish()
        self.send_json(replies if isinstance(msg, list) else replies[0])

    def get(self):
        raise tornado.web.HTTPError(405, "this MCP endpoint has no server-initiated stream")


UI_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
    "base-uri 'none'; form-action 'none'; frame-ancestors 'none'; object-src 'none'; "
    "require-trusted-types-for 'script'; trusted-types 'none'"
)
UI_TYPES = {".js": "text/javascript; charset=utf-8", ".mjs": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8",
            ".html": "text/html; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml"}


class UiStatic(tornado.web.StaticFileHandler):
    """The web UI's files. No inline script or style anywhere: the CSP allows only files from here. Always
    revalidated (ETag), so an upgraded proxy never serves a stale mix of modules."""

    def initialize(self, api: Api, path: str, default_filename: str | None = None):
        super().initialize(path, default_filename)
        self.api = api

    def prepare(self):
        if not self.api.host_ok(self.request.host or ""):
            raise tornado.web.HTTPError(421, "host not allowed")
        if not self.api.ui:
            raise tornado.web.HTTPError(404, "the web UI is off (m2c_ui=false)")

    def compute_etag(self) -> str | None:
        # tornado caches a content hash per path for the process's life: an edited file would keep its old ETag
        if not self.absolute_path:
            return None
        st = os.stat(self.absolute_path)
        return f'"{st.st_mtime_ns:x}-{st.st_size:x}"'

    def get_content_type(self) -> str:
        return UI_TYPES.get(os.path.splitext(self.absolute_path or "")[1], "application/octet-stream")

    def set_extra_headers(self, path):
        self.set_header("Cache-Control", "no-cache")
        self.set_header("X-Content-Type-Options", "nosniff")
        self.set_header("Referrer-Policy", "no-referrer")
        self.set_header("Content-Security-Policy", UI_CSP)
