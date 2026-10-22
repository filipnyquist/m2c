"""Process-wide recorder state.

mitmproxy watches `-s` scripts and builds a new add-on instance on every reload, but this module stays imported.
Everything that must outlive a reload lives here: the chDB database, the writer thread, the authenticator,
per-connection identity, the flows in flight and the flow counter. The add-on class itself is stateless.

Flow numbers are never handed out twice for one data directory, even after a crash: SSE and WebSocket rows are
written while their flow is still open, so a reused n would attach them to an unrelated flow. The counter reserves
blocks of numbers in `<data>/n.json` before using them and stores the exact last number at a clean shutdown.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import socket
import threading
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from mitmproxy import http

from . import __version__, rows
from .db import Database
from .identity import Authenticator, Identity, load_secrets, secret_file  # noqa: F401 - re-exported
from .live import LiveFeed
from .notes import Notes
from .repeater import Repeater
from .writer import Writer, spool_files

log = logging.getLogger("m2c")

N_BLOCK = 1000  # flow numbers reserved in <data>/n.json at a time


@dataclass
class Config:
    data: Path
    scan_id: str
    auth: str
    secrets: list[str]
    body_cap: int
    ws_msg_cap: int
    sse_event_cap: int
    sse_max_events: int
    stream_threshold: int
    batch_rows: int
    batch_bytes: int
    flush_interval: float
    queue_max_bytes: int
    memory_limit: int | None
    shutdown_timeout: float
    ws_trim: bool
    api_listen: str = ""
    api_hosts: str = ""
    readers: int = 3
    ui: bool = True
    ring_size: int = 10_000
    push_on_exit: str = ""
    fsync: bool = False
    labels: dict = field(default_factory=dict)
    grpc_msg_cap: int = 256 * 1024
    grpc_max_messages: int = 100_000
    proto_file: str = ""
    annotations: bool = True
    repeater: str = "off"  # off | admin | on
    repeater_timeout: int = 30


@dataclass
class ConnState:
    ident: Identity | None = None
    tool: str = ""
    call: str = ""
    tag: str = ""
    challenged: bool = False


@dataclass
class FlowState:
    """A recorded flow in flight, in State.flows until its row is written. Kept out of flow.metadata, which
    mitmproxy serializes (`-w`, replays); the flow's metadata only gets plain values (recorder._meta)."""

    ident: Identity
    flow: http.HTTPFlow
    n: int = 0
    tag: str = ""
    ws_seq: int = 0
    sse_seq: int = 0
    grpc_seq: int = 0  # both directions
    grpc_req: int = 0
    grpc_resp: int = 0
    grpc_web_trailers: list = field(default_factory=list)
    replay_of: int = 0  # the flow the repeater resent
    recorded: bool = False  # its http_flows row is queued: later SSE events (teardown at shutdown) are not kept
    extra: dict = field(default_factory=dict)


class State:
    def __init__(self, config: Config):
        self.config = config
        self.lock = threading.Lock()
        self.auth = Authenticator(config.auth, config.secrets)
        self.db = Database(config.data, config.memory_limit)
        self._n = self._n_reserved = self._restore_n()
        self.writer = Writer(
            self.db.insert_file,
            config.data,
            body_cap=config.body_cap,
            batch_rows=config.batch_rows,
            batch_bytes=config.batch_bytes,
            flush_interval=config.flush_interval,
            queue_max_bytes=config.queue_max_bytes,
            fsync=config.fsync,
            health_row=lambda counters: rows.event_row(self.config.scan_id, "health", counters=counters),
        )
        self.conns: dict[str, ConnState] = {}
        self.flows: dict[str, FlowState] = {}  # flow.id -> every flow that has an n and no row yet
        self.live_ws: dict[str, http.HTTPFlow] = {}
        self.tunnels: dict[str, dict] = {}  # TCP flows mitmproxy forwards without parsing (not HTTP)
        self.live = LiveFeed(config.ring_size)
        self.notes = Notes(self.writer, config.scan_id, config.annotations)
        self.repeater = Repeater(config.repeater, config.repeater_timeout)
        self.api = None
        self.closed = False

    def _restore_n(self) -> int:
        # Child rows of a flow that never got its http_flows row (kill -9) carry an n too.
        last = self.db.scalar(
            "SELECT greatest((SELECT max(n) FROM m2c.http_flows), (SELECT max(n) FROM m2c.sse_events), (SELECT max(n) FROM m2c.ws_messages))"
        )
        try:
            stored = int(json.loads((self.config.data / "n.json").read_text())["n"])
        except (OSError, ValueError, KeyError, TypeError):
            stored = 0
        return max(int(last or 0), stored)

    def _save_n(self, n: int) -> None:
        path = self.config.data / "n.json"
        tmp = path.with_suffix(".tmp")
        try:
            with open(tmp, "w") as f:
                f.write(json.dumps({"n": n}) + "\n")
                if self.config.fsync:
                    f.flush()
                    os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError as e:
            log.error("m2c: cannot write %s (%s); flow numbers may be reused after a crash", path, e)

    def next_n(self) -> int:
        with self.lock:
            self._n += 1
            if self._n > self._n_reserved:
                self._n_reserved = self._n + N_BLOCK - 1
                self._save_n(self._n_reserved)
            return self._n

    def last_n(self) -> int:
        return self._n

    def conn(self, client_id: str) -> ConnState:
        cs = self.conns.get(client_id)
        if cs is None:
            cs = self.conns[client_id] = ConnState()
        return cs

    def event(self, kind: str, severity: str = "info", **fields) -> None:
        self.writer.put("proxy_events", rows.event_row(self.config.scan_id, kind, severity, **fields))

    def start(self, listeners: list[str]) -> None:
        if self.writer.running:
            return
        self.writer.start()
        if self.config.api_listen:
            from .api import Api

            self.api = Api(self, self.config.api_listen, self.config.readers, self.config.ui, self.config.api_hosts)
            self.api.proxy_addr = proxy_address(listeners)
            self.api.start()
        self.event(
            "started",
            message=json.dumps(
                {
                    "version": __version__,
                    "host": socket.gethostname(),
                    "pid": os.getpid(),
                    "listeners": listeners,
                    "auth": self.config.auth,
                    "data": str(self.config.data),
                    "api": self.api.url if self.api else None,
                }
            ),
        )
        atexit.register(self.shutdown)

    def shutdown(self) -> None:
        """Called after the recorder has queued the rows of every flow still in flight."""
        if self.closed:
            return
        self.closed = True
        try:
            if self.api is not None:
                self.api.stop()
        except Exception:  # noqa: BLE001 - the data matters more than the API
            log.exception("m2c: could not stop the API")
        try:
            flushed = self.writer.stop(self.config.shutdown_timeout)
            with self.lock:
                self._save_n(self._n)
            # Written after the final flush, so its counters are the run's totals.
            stopped = rows.event_row(self.config.scan_id, "stopped", counters=self.writer.counters.flat())
            flushed = self.writer.put_final("proxy_events", stopped) and flushed
            if not flushed:
                log.error("m2c: not everything was inserted within %ss; the rest is kept in %s/spool", self.config.shutdown_timeout, self.config.data)
            if self.config.push_on_exit:
                if flushed:
                    self.push(self.config.push_on_exit)
                else:
                    self._push_skipped(self.config.push_on_exit)
        finally:
            if self.writer.running:
                log.error("m2c: the writer is still inserting; leaving the chDB session open")
            else:
                self.db.close()

    def _push_failed(self, url: str, error: str) -> None:
        marker = self.config.data / "push-failed.json"
        try:
            marker.write_text(json.dumps({"target": url.split("@")[-1], "error": error[:2000]}) + "\n")
        except OSError:
            log.exception("m2c: could not write %s", marker)

    def _push_skipped(self, url: str) -> None:
        left = spool_files(self.config.data / "spool")
        reason = (
            f"not pushed: {len(left)} batches ({sum(n for _, _, n in left)} rows) were not inserted before shutdown and "
            f"are in {self.config.data}/spool; `m2c push --data {self.config.data}` inserts them first"
        )
        log.error("m2c: %s", reason)
        self._push_failed(url, reason)

    def push(self, url: str) -> None:
        from .push import Pusher, Target

        try:
            target = Target.parse(url)
            result = Pusher(lambda sql, fmt: self.db.writer.query(sql, fmt).bytes(), target, progress=lambda m: log.warning("m2c: %s", m)).push(self.config.labels)
            (self.config.data / "push-failed.json").unlink(missing_ok=True)
            log.warning("m2c: pushed scan %s to %s", result["scan_id"], result["target"])
        except Exception as e:  # noqa: BLE001 - whatever went wrong, the marker must say so
            log.error("m2c: push to central ClickHouse failed: %s (run `m2c push` later; the data is kept)", e)
            self._push_failed(url, str(e))


def proxy_address(listeners: list[str]) -> str:
    """host:port of the first HTTP proxy listener, for clients (`m2c env`, `m2c run`)."""
    from mitmproxy.proxy import mode_specs

    for spec in listeners:
        mode = mode_specs.ProxyMode.parse(spec)
        if mode.type_name == "regular":
            host = mode.listen_host() or "127.0.0.1"
            host = "127.0.0.1" if host in ("0.0.0.0", "") else ("::1" if host == "::" else host)
            return f"[{host}]:{mode.listen_port()}" if ":" in host else f"{host}:{mode.listen_port()}"
    return ""


_STATE: State | None = None


def get() -> State | None:
    return _STATE


def init(config: Config) -> State:
    global _STATE
    if _STATE is None:
        _STATE = State(config)
    return _STATE


def new_scan_id() -> str:
    return uuid.uuid4().hex[:12]
