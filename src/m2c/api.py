"""The live API, served by tornado (a mitmproxy dependency) on mitmproxy's own event loop.

chDB locks the data directory to this process, so every live read comes through here. Queries run on two small
thread pools, each thread with its own read-only chDB session: the heavy lane (ad-hoc SQL, body: searches, HAR,
database-filtered tails) is apart from the interactive one, so a slow query never blocks the writer or `ls`.
Session-scoped callers get at most one heavy query and a share of the interactive lane at a time, and work whose
client has gone is skipped. `tail` streams from the in-memory live feed. Auth: `Authorization: Bearer <admin token>`
(everything) or `Bearer <session>:<proxy token>` (that session only, no SQL, no proxy events).
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
import weakref
from concurrent.futures import ThreadPoolExecutor
from importlib import resources

import tornado.httpserver
import tornado.iostream
import tornado.netutil
import tornado.web

from . import __version__
from .db import open_session
from .filters import FilterError, compile_filter, split_matcher
from .identity import SESSION, AuthError, check_token
from .mcp import PARSE_ERROR, McpServer, rpc_error
from .queries import DB, Forbidden, Queries

log = logging.getLogger("m2c.api")

# Tails whose filter needs the database (body:, source:, has:truncated) query it for every batch of finished flows.
DB_TAILS_PER_SCOPE = 2
DB_TAILS_ADMIN = 4
DB_TAILS_TOTAL = 8
U64_MAX = (1 << 64) - 1  # chDB wraps an out-of-range parameter instead of rejecting it: bound them here


class ClientGone(Exception):
    """The client disconnected before its query started."""


def _heavy_q(q: str) -> bool:
    return "body:" in (q or "").lower()


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
                (r"/v1/flows", FlowsHandler, {"api": self}),
                (r"/v1/flows/(\d+)", FlowHandler, {"api": self}),
                (r"/v1/flows/(\d+)/body/(req|resp)", BodyHandler, {"api": self}),
                (r"/v1/flows/(\d+)/(sse|ws)", ChildrenHandler, {"api": self}),
                (r"/v1/flows/(\d+)/curl", CurlHandler, {"api": self}),
                (r"/v1/flows/(\d+)/live", FlowLiveHandler, {"api": self}),
                (r"/v1/tail", TailHandler, {"api": self}),
                (r"/v1/har", HarHandler, {"api": self}),
                (r"/v1/events", EventsHandler, {"api": self}),
                (r"/v1/sql", SqlHandler, {"api": self}),
                (r"/mcp", McpHandler, {"api": self}),
                (r"/ui/?", UiHandler, {"api": self}),
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
        self.q = Queries(self.api._run, self.scope)

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
        except RuntimeError as e:
            raise tornado.web.HTTPError(400, str(e).strip()[:2000]) from None

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
        stats.update(scan_id=st.config.scan_id, version=__version__, uptime_s=int(time.time() - self.api.started), scope=self.scope)
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
        fn = self.q.sse if kind == "sse" else self.q.ws
        self.send_json(await self.call(fn, self.flow_n(n), self.int_arg("after", 0, hi=(1 << 32) - 1), self.int_arg("limit", 1000)))


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


class EventsHandler(Base):
    async def get(self):
        self.send_json(await self.call(self.q.events, self.get_argument("kind", ""), self.int_arg("limit", 100)))


class SqlHandler(Base):
    async def post(self):
        if not self.admin:
            raise tornado.web.HTTPError(403, "SQL needs the admin token")
        sql = self.request.body.decode("utf-8", "replace").strip()
        fmt = self.get_argument("format", "JSONEachRow")
        if not fmt.replace("_", "").isalnum():
            raise tornado.web.HTTPError(400, "bad format")
        out = await self.call(self.q.sql, sql, fmt, heavy=True)
        self.set_header("Content-Type", "application/json" if fmt.startswith("JSON") else "application/octet-stream")
        self.finish(out)


def live_stats(api: Api, scope: str | None) -> dict:
    st = api.st
    out = {"scan_id": st.config.scan_id, "open": sum(1 for f in st.live.open.values() if scope is None or f["session"] == scope)}
    if scope is None:  # process-wide counters: not for session-scoped callers
        c = st.writer.counters
        out.update(last_n=st.last_n(), queued=c.queued, written=sum(c.written.values()), dropped=sum(c.dropped.values()), errors=c.hook_errors + c.tee_errors + c.insert_errors)
    return out


def tail_hits(q: Queries, flt: str, ns: list[int]) -> dict[int, bool]:
    """For those of `ns` that are in the database: whether they match filter `flt`. Missing ones are not written yet."""
    where, params = compile_filter(flt, q.scope)
    params["tail_ns"] = ns
    pin = ""
    if q.scope is not None:
        pin = " AND session = {tail_scope:String}"
        params["tail_scope"] = q.scope
    rows = q.rows(f"SELECT n, max(toUInt8({where})) AS hit FROM {DB}.http_flows WHERE n IN {{tail_ns:Array(UInt64)}}{pin} GROUP BY n", params)
    return {int(r["n"]): bool(r["hit"]) for r in rows}


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

    def _match(self, pred, item) -> bool:
        try:
            return bool(pred(item))
        except Exception:  # noqa: BLE001 - same as LiveFeed: a bad predicate skips the flow
            return False

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
                if self._match(pred, item):
                    self.send_event("flow", item, f"{live.epoch}.{seq}")
        elif backlog:
            for seq, item in live.recent(pred, backlog):
                self.send_event("flow", item, f"{live.epoch}.{seq}")
        for item in list(live.open.values()):
            if self._match(pred, item):
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
                    if self._match(pred, item):
                        self.send_event("open", item)
            items, missed = live.since(cursor)
            cursor = live.seq
            if missed:
                self._resync("behind", missed)
            for seq, item in items:
                if self._match(pred, item):
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
                if item["n"] not in sent and self._match(pred, item):
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
                    hits = await self.call(tail_hits, self.q, q, batch, heavy=True)
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


def _child_json(kind: str, row: dict) -> dict:
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
                self.send_event(kind, _child_json(kind, row))
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
                    self.send_event(kind, _child_json(kind, row))
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

    async def post(self):
        try:
            msg = json.loads(self.request.body or b"{}")
        except ValueError:  # bad JSON, or bytes that are not UTF-8
            self.set_status(400)
            return self.send_json(PARSE_ERROR)
        if msg == []:
            self.set_status(400)
            return self.send_json(rpc_error(None, -32600, "invalid request: empty batch"))
        server = McpServer(self.q, self.admin)
        msgs = msg if isinstance(msg, list) else [msg]
        replies = []
        for m in msgs:
            params = m.get("params") if isinstance(m, dict) else None
            heavy = isinstance(params, dict) and (params.get("name") == "traffic_sql" or _heavy_q(json.dumps(params.get("arguments"))))
            reply = await self.call(server.handle, m, heavy=heavy)
            if reply is not None:
                replies.append(reply)
        if not replies:
            self.set_status(202)
            return self.finish()
        self.send_json(replies if isinstance(msg, list) else replies[0])

    def get(self):
        raise tornado.web.HTTPError(405, "this MCP endpoint has no server-initiated stream")


class UiHandler(Base):
    public = True

    def get(self):
        if not self.api.ui:
            raise tornado.web.HTTPError(404, "the web UI is off (m2c_ui=false)")
        page = resources.files("m2c").joinpath("ui/index.html").read_bytes()
        self.set_header("Content-Type", "text/html; charset=utf-8")
        self.set_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data: blob:; frame-ancestors 'none'",
        )
        self.set_header("Referrer-Policy", "no-referrer")
        self.finish(page)

