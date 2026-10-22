"""The mitmproxy add-on: authenticate every request, attribute it, and hand finished flows to the writer.

Load it with `mitmdump -s entry.py --set proxyauth=any` (`m2c proxy` does this). mitmproxy's own proxyauth add-on
runs first and only parses the credentials; this add-on decides. Bad or missing credentials get a 407 and a
`proxy_events` row, never an `http_flows` row. Hooks only copy references and enqueue; all decoding and I/O
happens on the writer thread.
"""

from __future__ import annotations

import functools
import ipaddress
import json
import logging
import os
import time
from pathlib import Path

from mitmproxy import ctx, exceptions, http
from mitmproxy.proxy import mode_specs

from . import db, grpc, live, rows, state
from .identity import HEADER_CALL, HEADER_TAG, HEADER_TOOL, MODES, SESSION, TOOL, AuthError, Identity, clean_tag, override
from .sse import SseParser
from .state import Config, ConnState, FlowState
from .tee import BodyTee, GrpcTee, SseTee, wants_tee

log = logging.getLogger("m2c")

REALM = "m2c"
MiB = 1 << 20

# name: (type, default, help). Every option defaults to its M2C_<NAME> environment variable.
OPTIONS: dict[str, tuple[type, object, str]] = {
    "m2c_data": (str, "./m2c-data", "chDB data directory: one per scan"),
    "m2c_scan_id": (str, "", "Scan id stored on every row; default: kept in <data>/scan.json, random on first use"),
    "m2c_auth": (str, "token", "Proxy auth: token (HMAC per session), shared (one secret) or open (no secret)"),
    "m2c_secret_file": (str, "", "File with the auth secret(s), one per line; default <data>/secret, created if missing"),
    "m2c_allow_open_exposed": (bool, False, "Allow m2c_auth=open on a non-loopback listener"),
    "m2c_body_cap": (int, MiB, "Bytes of each body stored (after decoding); sizes always record the full length"),
    "m2c_stream_threshold": (int, MiB, "Bodies above this many bytes are streamed through instead of buffered"),
    "m2c_ws_msg_cap": (int, 256 * 1024, "Bytes stored per WebSocket message"),
    "m2c_ws_trim": (bool, True, "Drop recorded WebSocket messages from memory (keeps long sockets flat)"),
    "m2c_sse_event_cap": (int, 64 * 1024, "Bytes stored per SSE event's data"),
    "m2c_sse_max_events": (int, 100_000, "SSE events stored per response (counting continues)"),
    "m2c_batch_rows": (int, 1000, "Rows per insert"),
    "m2c_batch_bytes": (int, 8 * MiB, "Bytes per insert"),
    "m2c_flush_ms": (int, 250, "Longest a row waits before it is inserted"),
    "m2c_queue_max_bytes": (int, 256 * MiB, "Writer queue budget; above it bodies are dropped, above 1.25x rows are"),
    "m2c_memory_limit": (int, 2048 * MiB, "chDB max_server_memory_usage in bytes (0: engine default, 90% of RAM)"),
    "m2c_shutdown_timeout": (int, 10, "Seconds to flush on shutdown (what is left stays in <data>/spool)"),
    "m2c_fsync": (bool, False, "fsync each spooled batch before inserting it (power-loss safety)"),
    "m2c_api_listen": (str, "127.0.0.1:8124", "Live API, MCP and UI address (host:port; empty: off; port taken: random)"),
    "m2c_api_hosts": (str, "", "Allowed Host headers for the API, comma separated (default: loopback names on a loopback API)"),
    "m2c_readers": (int, 3, "Read-only chDB sessions serving the API"),
    "m2c_ui": (bool, True, "Serve the web UI at /ui/"),
    "m2c_repeater": (str, "off", "Resend edited requests through the API/UI/MCP: off, admin (the admin token only) or on (also a session "
                                 "token, for its own session's flows)"),
    "m2c_repeater_timeout": (int, 30, "Seconds a resent request may take before it is recorded as an error"),
    "m2c_annotations": (bool, True, "Allow labels and notes on flows through the API (admin, or a session token on its own flows)"),
    "m2c_ring_size": (int, 10_000, "Flow summaries kept in memory for the live tail"),
    "m2c_push_on_exit": (str, "", "Push the scan to this central ClickHouse URL at shutdown (password: M2C_PUSH_PASSWORD)"),
    "m2c_labels": (str, "", "key=value,key=value labels for the central scans row"),
    "m2c_grpc_msg_cap": (int, 256 * 1024, "Bytes stored per gRPC message (the declared size is always recorded)"),
    "m2c_grpc_max_messages": (int, 100_000, "gRPC messages stored per call (counting continues)"),
    "m2c_proto_file": (str, "", "A .proto file used to name fields when gRPC messages are read (API, UI, MCP)"),
}


def _env_default(name: str, type_: type, default):
    raw = os.environ.get(name.upper())
    if raw is None:
        return default
    if type_ is bool:
        return raw.strip().lower() in ("1", "true", "yes", "on")
    if type_ is int:
        return int(raw)
    return raw


def guard(fn):
    """Hook errors are logged and counted, never raised into mitmproxy."""

    @functools.wraps(fn)
    def wrapper(self, *args):
        try:
            return fn(self, *args)
        except Exception:  # noqa: BLE001
            st = state.get()
            if st is not None:
                st.writer.counters.hook_errors += 1
            log.exception("m2c: %s hook failed", fn.__name__)

    return wrapper


def guard_closed(fn):
    """For the hooks that authenticate: an unexpected error refuses the request or connection instead of letting it
    through unauthenticated and unrecorded."""

    @functools.wraps(fn)
    def wrapper(self, arg):
        try:
            return fn(self, arg)
        except Exception:  # noqa: BLE001
            st = state.get()
            if st is not None:
                st.writer.counters.hook_errors += 1
            log.exception("m2c: %s hook failed; refusing", fn.__name__)
            if isinstance(arg, http.HTTPFlow):
                arg.response = auth_required("internal")
                if st is not None:
                    st.flows.pop(arg.id, None)  # refused: never an http_flows row
            else:  # socks5_auth data
                arg.valid = False

    return wrapper


def auth_required(reason: str) -> http.Response:
    body = (
        f"m2c proxy: authentication failed ({reason}).\n"
        "Use proxy credentials <session>.<tool>[.<call>]:<token>, e.g. "
        "http://run42.curl:v1.0.<mac>@127.0.0.1:8080 (m2c mint <session> prints a token).\n"
    )
    return http.Response.make(
        407, body.encode(), {"Proxy-Authenticate": f'Basic realm="{REALM}"', "Content-Type": "text/plain", "X-M2C-Auth": reason}
    )


def _is_loopback(host: str) -> bool:
    if host in ("localhost", ""):
        return host == "localhost"
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _meta(ident: Identity, n: int = 0, tag: str = "") -> dict:
    """What a flow's metadata keeps of m2c: plain values only, since mitmproxy serializes metadata (`-w`, replays)."""
    return {"n": n, "session": ident.session, "tool": ident.tool, "call": ident.call, "user": ident.user, "source": ident.source, "tag": tag}


def _meta_ident(meta) -> Identity | None:
    if not isinstance(meta, dict) or not isinstance(meta.get("session"), str) or not SESSION.fullmatch(meta["session"]):
        return None
    tool = meta.get("tool") if isinstance(meta.get("tool"), str) and TOOL.fullmatch(meta["tool"]) else "unknown"
    text = {k: meta[k] if isinstance(meta.get(k), str) else "" for k in ("call", "user", "source")}
    return Identity(meta["session"], tool, text["call"], text["user"], text["source"] or "none")


def parse_labels(text: str) -> dict[str, str]:
    """m2c_labels: a JSON object, or key=value,key=value where a part without '=' continues the previous value
    (`repo=a,b` is {'repo': 'a,b'}, as `m2c push --label repo=a,b` stores it)."""
    text = text.strip()
    if text.startswith("{"):
        try:
            labels = json.loads(text)
        except ValueError as e:
            raise exceptions.OptionsError(f"m2c_labels is not valid JSON: {e}") from None
        if not isinstance(labels, dict):
            raise exceptions.OptionsError("m2c_labels must be a JSON object")
        return {str(k): str(v) for k, v in labels.items()}
    out: dict[str, str] = {}
    key = None
    for part in text.split(",") if text else []:
        if "=" in part:
            key, value = part.split("=", 1)
            out[key] = value
        elif key is not None:
            out[key] += "," + part
    return out


def _scan_id(data: Path, configured: str) -> str:
    meta = data / "scan.json"
    if configured:
        scan_id = configured
    elif meta.exists():
        return json.loads(meta.read_text())["scan_id"]
    else:
        scan_id = state.new_scan_id()
    db.private_dir(data)  # 0700 before scan.json and the secret land in it
    meta.write_text(json.dumps({"scan_id": scan_id}) + "\n")
    return scan_id


class Recorder:
    # ----------------------------------------------------------------- lifecycle

    def load(self, loader):
        for name, (type_, default, help_) in OPTIONS.items():
            loader.add_option(name, type_, _env_default(name, type_, default), help_)

    def configure(self, updated):
        if state.get() is not None:
            return
        opts = ctx.options
        if opts.m2c_repeater not in ("off", "admin", "on"):
            raise exceptions.OptionsError("m2c_repeater must be off, admin or on")
        if opts.m2c_auth not in MODES:
            raise exceptions.OptionsError(f"m2c_auth must be one of {', '.join(MODES)}")
        if opts.proxyauth != "any":
            raise exceptions.OptionsError("m2c needs --set proxyauth=any (it checks the credentials itself)")
        listen_hosts = [mode_specs.ProxyMode.parse(m).listen_host(opts.listen_host) for m in opts.mode]
        if opts.m2c_auth == "open" and not opts.m2c_allow_open_exposed and not all(_is_loopback(h) for h in listen_hosts):
            raise exceptions.OptionsError("m2c_auth=open on a non-loopback listener; set m2c_allow_open_exposed=true to allow it")
        if opts.m2c_push_on_exit:
            from .push import Target

            try:
                Target.parse(opts.m2c_push_on_exit)  # fail now, not after the whole scan
            except Exception as e:  # noqa: BLE001
                raise exceptions.OptionsError(f"m2c_push_on_exit: {e}") from None
        data = Path(opts.m2c_data).expanduser().resolve()
        secrets = []
        if opts.m2c_auth != "open":
            secrets = state.load_secrets(data, opts.m2c_secret_file, os.environ.get("M2C_SECRET", ""), create=True)
        config = Config(
            data=data,
            scan_id=_scan_id(data, opts.m2c_scan_id),
            auth=opts.m2c_auth,
            secrets=secrets,
            body_cap=opts.m2c_body_cap,
            ws_msg_cap=opts.m2c_ws_msg_cap,
            sse_event_cap=opts.m2c_sse_event_cap,
            sse_max_events=opts.m2c_sse_max_events,
            stream_threshold=opts.m2c_stream_threshold,
            batch_rows=opts.m2c_batch_rows,
            batch_bytes=opts.m2c_batch_bytes,
            flush_interval=opts.m2c_flush_ms / 1000,
            queue_max_bytes=opts.m2c_queue_max_bytes,
            memory_limit=opts.m2c_memory_limit or None,
            shutdown_timeout=opts.m2c_shutdown_timeout,
            ws_trim=opts.m2c_ws_trim,
            api_listen=opts.m2c_api_listen,
            api_hosts=opts.m2c_api_hosts,
            readers=opts.m2c_readers,
            ui=opts.m2c_ui,
            repeater=opts.m2c_repeater,
            repeater_timeout=max(1, opts.m2c_repeater_timeout),
            annotations=opts.m2c_annotations,
            ring_size=opts.m2c_ring_size,
            push_on_exit=opts.m2c_push_on_exit,
            fsync=opts.m2c_fsync,
            labels=parse_labels(opts.m2c_labels),
            grpc_msg_cap=opts.m2c_grpc_msg_cap,
            grpc_max_messages=opts.m2c_grpc_max_messages,
            proto_file=str(Path(opts.m2c_proto_file).expanduser().resolve()) if opts.m2c_proto_file else "",
        )
        try:
            state.init(config)
        except Exception as e:
            raise exceptions.OptionsError(f"m2c: cannot open the chDB data directory {data}: {e}") from e
        log.info("m2c: recording scan %s into %s (auth %s)", config.scan_id, data, config.auth)

    def running(self):
        st = state.get()
        if st is not None:
            try:
                st.start(list(ctx.options.mode))
            except OSError as e:
                log.error("m2c: could not start the API: %s", e)

    def done(self):
        st = state.get()
        if st is None:
            return
        master = getattr(ctx, "master", None)
        if master is not None and not master.should_exit.is_set():
            return  # a script reload, not a shutdown: keep recording
        try:
            # Every flow still in flight gets its row now: mitmproxy tears the connections down after this hook,
            # when the writer no longer takes rows.
            for flow in list(st.live_ws.values()):
                self._finish_ws(st, flow, "proxy_shutdown")
            for fs in list(st.flows.values()):
                self._record(st, fs.flow, end_reason="proxy_shutdown")
            for flow_id in list(st.tunnels):
                self._finish_tunnel(st, flow_id, "proxy_shutdown")
        except Exception:  # noqa: BLE001
            st.writer.counters.hook_errors += 1
            log.exception("m2c: recording the open flows at shutdown failed")
        finally:
            st.shutdown()

    # ----------------------------------------------------------------- connections and auth

    @guard
    def client_disconnected(self, client):
        st = state.get()
        if st is not None:
            st.conns.pop(client.id, None)

    def _reject(self, st, client, reason: str, user: str | None, kind: str = "auth_rejected", **fields):
        st.event(
            kind,
            "warn" if kind == "auth_rejected" else "info",
            proxy_user=(user or "")[:256],
            reason=reason,
            listener=client.proxy_mode.full_spec if client.proxy_mode else "",
            client_conn_id=client.id,
            client_ip=client.peername[0] if client.peername else "",
            **fields,
        )

    @guard_closed
    def socks5_auth(self, data):
        st = state.get()
        if st is None:
            return
        try:
            ident = st.auth.check(data.username, data.password, "socks5")
        except AuthError as e:
            data.valid = False
            self._reject(st, data.client_conn, str(e), data.username)
            return
        st.conn(data.client_conn.id).ident = ident

    @guard_closed
    def http_connect(self, flow: http.HTTPFlow):
        st = state.get()
        if st is None:
            return
        cs = st.conn(flow.client_conn.id)
        if flow.response is not None:
            # proxyauth's challenge: the client sent no credentials (browsers and git always try that first)
            if not cs.challenged:
                cs.challenged = True
                self._reject(st, flow.client_conn, "missing", None, kind="auth_challenge", host=flow.request.host, port=flow.request.port)
            return
        user, password = flow.metadata.get("proxyauth") or (None, None)
        try:
            ident = st.auth.check(user, password, "connect")
        except AuthError as e:
            flow.response = auth_required(str(e))
            self._reject(st, flow.client_conn, str(e), user, host=flow.request.host, port=flow.request.port)
            return
        flow.metadata["proxyauth"] = (user, "***")
        cs.ident = ident
        headers = flow.request.headers
        cs.tool, cs.call, cs.tag = headers.get(HEADER_TOOL, ""), headers.get(HEADER_CALL, ""), clean_tag(headers.get(HEADER_TAG))
        flow.metadata["m2c"] = _meta(ident)  # the CONNECT itself is not a recorded flow (not in st.flows)

    @guard
    def http_connect_error(self, flow: http.HTTPFlow):
        st = state.get()
        ident = _meta_ident(flow.metadata.get("m2c"))
        if st is None or ident is None:
            return
        self._reject(
            st, flow.client_conn, "connect_error", ident.user, kind="connect_error",
            session=ident.session, tool=ident.tool, host=flow.request.host, port=flow.request.port,
            message=flow.error.msg if flow.error else "",
        )

    def _identify(self, st, flow: http.HTTPFlow) -> Identity | None:
        """Re-validate the credentials of every request; a CONNECT's identity is only a fallback for SOCKS5."""
        if flow.is_replay:
            # A replay comes from the proxy's operator (replay.client, client_replay), not a client: like mitmproxy's
            # proxyauth, don't authenticate it. It keeps the identity of the flow it replays.
            return _meta_ident(flow.metadata.get("m2c")) or Identity("replay", "replay", "", "", "none")
        cs = st.conns.get(flow.client_conn.id) or ConnState()
        creds = flow.metadata.get("proxyauth")
        if creds and creds[1] != "***":
            source = cs.ident.source if cs.ident is not None and cs.ident.user == creds[0] else "request"
            return st.auth.check(creds[0], creds[1], source)
        if cs.ident is not None:
            return cs.ident
        raise AuthError("missing")

    @guard_closed
    def requestheaders(self, flow: http.HTTPFlow):
        st = state.get()
        if st is None:
            return
        if flow.response is not None:
            # proxyauth's challenge for a plain-HTTP request without credentials
            cs = st.conn(flow.client_conn.id)
            if not cs.challenged:
                cs.challenged = True
                self._reject(st, flow.client_conn, "missing", None, kind="auth_challenge", host=flow.request.host, port=flow.request.port)
            return
        try:
            ident = self._identify(st, flow)
        except AuthError as e:
            user = (flow.metadata.get("proxyauth") or (None, None))[0]
            flow.response = auth_required(str(e))
            self._reject(st, flow.client_conn, str(e), user, host=flow.request.host, port=flow.request.port)
            return
        if flow.metadata.get("proxyauth"):
            flow.metadata["proxyauth"] = (flow.metadata["proxyauth"][0], "***")
        cs = st.conns.get(flow.client_conn.id) or ConnState()
        headers = flow.request.headers
        tool = headers.get(HEADER_TOOL) or cs.tool
        call = headers.get(HEADER_CALL) or cs.call
        meta = flow.metadata.get("m2c")
        replay_tag = meta.get("tag") if flow.is_replay and isinstance(meta, dict) and isinstance(meta.get("tag"), str) else ""
        tag = clean_tag(headers.get(HEADER_TAG)) or cs.tag or clean_tag(replay_tag)
        for name in (HEADER_TOOL, HEADER_CALL, HEADER_TAG):
            if name in headers:
                del headers[name]
        ident = override(ident, tool, call)
        fs = FlowState(ident, flow, n=st.next_n(), tag=tag)
        if flow.is_replay and isinstance(meta, dict) and isinstance(meta.get("replay_of"), int) and meta["replay_of"] > 0:
            fs.replay_of = meta["replay_of"]  # set by the repeater; the metadata is rewritten just below
        st.flows[flow.id] = fs
        flow.metadata["m2c"] = _meta(ident, fs.n, tag)
        req = flow.request
        gkind = grpc.kind(headers.get("content-type"))
        if gkind:
            # gRPC: always streamed, and split into messages on the way (both directions)
            fs.extra["grpc"] = gkind
            framer = grpc.Framer(self._grpc_sink(st, flow, fs, True), st.config.grpc_msg_cap, text=gkind == "grpc-web-text")
            tee = GrpcTee(st.config.body_cap, framer, inner=req.stream, on_error=self._tee_error)
            req.stream = tee
            fs.extra["req_tee"] = tee
            return
        unsized = req.http_version.startswith(("HTTP/2", "HTTP/3")) and "content-length" not in headers
        h2_body = unsized and req.method not in ("GET", "HEAD", "OPTIONS")
        if h2_body or wants_tee(headers, req.method, threshold=st.config.stream_threshold, is_request=True):
            tee = BodyTee(st.config.body_cap, inner=req.stream, on_error=self._tee_error)
            req.stream = tee
            fs.extra["req_tee"] = tee

    @staticmethod
    def _tee_error():
        st = state.get()
        if st is not None:
            st.writer.counters.tee_errors += 1

    @guard
    def responseheaders(self, flow: http.HTTPFlow):
        st = state.get()
        fs: FlowState | None = st.flows.get(flow.id) if st is not None else None
        res = flow.response
        if fs is None or res is None:
            return
        if not (res.stream or wants_tee(res.headers, flow.request.method, res.status_code, st.config.stream_threshold)):
            return
        ctype = (res.headers.get("content-type") or "").split(";", 1)[0].strip().lower()
        gkind = grpc.kind(ctype) or fs.extra.get("grpc")
        if gkind:
            fs.extra["grpc"] = fs.extra.get("grpc") or gkind
            framer = grpc.Framer(self._grpc_sink(st, flow, fs, False), st.config.grpc_msg_cap, text=gkind == "grpc-web-text")
            tee = GrpcTee(st.config.body_cap, framer, inner=res.stream, on_error=self._tee_error)
        elif ctype == "text/event-stream":
            parser = SseParser(self._sse_sink(st, flow, fs), st.config.sse_event_cap)
            tee = SseTee(st.config.body_cap, parser, res.headers.get("content-encoding"), inner=res.stream, on_error=self._tee_error)
        else:
            tee = BodyTee(st.config.body_cap, inner=res.stream, on_error=self._tee_error)
        res.stream = tee
        fs.extra["resp_tee"] = tee
        self._publish_open(st, flow, fs, "sse" if isinstance(tee, SseTee) else "streamed")

    @staticmethod
    def _publish_open(st, flow: http.HTTPFlow, fs: FlowState, capture: str) -> None:
        row = rows.http_row(flow, fs.ident, st.config.scan_id, fs.n, fs.tag, fs.replay_of)
        if fs.extra.get("grpc"):
            service, method = grpc.service_method(flow.request.path)
            row.update(grpc=True, grpc_service=service, grpc_method=method)
        item = live.summary(row)
        item.update(resp_capture=capture, duration_ms=0, resp_body_size=0)
        st.live.publish_open(item)

    @staticmethod
    def _grpc_sink(st, flow: http.HTTPFlow, fs: FlowState, from_client: bool):
        started = flow.request.timestamp_start
        host = flow.request.pretty_host
        service, method = grpc.service_method(flow.request.path)
        message = flow.request if from_client else flow.response
        encoding = (message.headers.get("grpc-encoding") or "identity").lower()[:40] if message is not None else ""
        cap = st.config.grpc_max_messages

        def sink(msg: grpc.Message):
            if fs.recorded:
                return
            if msg.trailer:  # gRPC-Web carries the trailers as a last, flagged frame
                fs.grpc_web_trailers = grpc.parse_trailer_block(msg.data)
                return
            fs.grpc_seq += 1
            if from_client:
                fs.grpc_req += 1
            else:
                fs.grpc_resp += 1
            if fs.grpc_seq > cap:
                return
            now = time.time()
            row = {
                "scan_id": st.config.scan_id,
                "flow_id": flow.id,
                "n": fs.n,
                "seq": fs.grpc_seq,
                "dir_seq": fs.grpc_req if from_client else fs.grpc_resp,
                "ts": rows.ms(now),
                "ms_since_req": max(0, rows.ms(now) - rows.ms(started)),
                "session": fs.ident.session,
                "tool": fs.ident.tool,
                "call_id": fs.ident.call,
                "host": host,
                "service": service,
                "method": method,
                "from_client": from_client,
                "compressed": msg.compressed,
                "encoding": encoding if msg.compressed else "identity",
                "size": msg.size,
                "truncated": msg.truncated,
                "partial": msg.partial,
                "data": msg.data,
            }
            st.live.publish_child(fs.n, "grpc", row)
            st.writer.put("grpc_messages", row)

        return sink

    @staticmethod
    def _grpc_fields(st, flow: http.HTTPFlow, fs: FlowState, row: dict) -> dict:
        """The gRPC columns of a finished (or abandoned) call. Closes the framers first, so a message cut short
        still gets its row."""
        for key in ("req_tee", "resp_tee"):
            tee = fs.extra.get(key)
            if isinstance(tee, GrpcTee):
                tee.close_framer()
                if tee.frame_error:
                    st.event("grpc_framing_stopped", "warn", session=fs.ident.session, tool=fs.ident.tool, host=flow.request.host,
                             port=flow.request.port, flow_id=flow.id, message=f"{key[:-4]}: {tee.frame_error}")
        req, res = flow.request, flow.response
        service, method = grpc.service_method(req.path)
        timeout = grpc.timeout_ms(req.headers.get("grpc-timeout"))
        status = grpc.status_of(
            res.trailers.fields if res is not None and res.trailers else (),
            res.headers.fields if res is not None else (),
            fs.grpc_web_trailers,
            row.get("error_kind", ""),
            timeout,
            row.get("duration_ms", 0),
        )
        return {
            "grpc": True,
            "grpc_service": service,
            "grpc_method": method,
            "grpc_status": status.code,
            "grpc_message": status.message,
            "grpc_status_source": status.source,
            "grpc_timeout_ms": timeout,
            "grpc_encoding": (req.headers.get("grpc-encoding") or (res.headers.get("grpc-encoding") if res is not None else "") or "")[:40],
            "grpc_req_messages": fs.grpc_req,
            "grpc_resp_messages": fs.grpc_resp,
        }

    @staticmethod
    def _sse_sink(st, flow: http.HTTPFlow, fs: FlowState):
        started = flow.request.timestamp_start
        host = flow.request.pretty_host
        cap = st.config.sse_max_events

        def sink(ev):
            if fs.recorded:
                return
            fs.sse_seq += 1
            if fs.sse_seq > cap:
                return
            now = time.time()
            row = {
                    "scan_id": st.config.scan_id,
                    "flow_id": flow.id,
                    "n": fs.n,
                    "seq": fs.sse_seq,
                    "ts": rows.ms(now),
                    "ms_since_req": max(0, rows.ms(now) - rows.ms(started)),
                    "session": fs.ident.session,
                    "tool": fs.ident.tool,
                    "call_id": fs.ident.call,
                    "host": host,
                    "event": ev.event,
                    "id": ev.id,
                    "retry_ms": ev.retry_ms,
                    "data": ev.data,
                    "size": ev.size,
                    "truncated": ev.truncated,
                    "partial": ev.partial,
            }
            st.live.publish_child(fs.n, "sse", row)
            st.writer.put("sse_events", row)

        return sink

    # ----------------------------------------------------------------- recording

    def _record(self, st, flow: http.HTTPFlow, **extra) -> None:
        fs: FlowState | None = st.flows.pop(flow.id, None)
        if fs is None:
            return  # not recorded (refused, a CONNECT) or already written
        row = rows.http_row(flow, fs.ident, st.config.scan_id, fs.n, fs.tag, fs.replay_of)
        if extra.get("end_reason") == "proxy_shutdown":
            # in flight: a body that has not arrived yet is not a streamed one
            for side in ("req", "resp"):
                if f"_{side}_raw" in row and row[f"_{side}_raw"] is None:
                    row[f"{side}_capture"] = "none"
        row.update(extra)  # end_reason/ws fields first: the gRPC status inference reads the final error_kind/duration
        if fs.extra.get("grpc"):
            row.update(self._grpc_fields(st, flow, fs, row))
        req_tee = fs.extra.get("req_tee")
        if req_tee is not None:
            row.update(_req_raw=req_tee.captured, req_body_size=req_tee.size, req_body_truncated=req_tee.truncated, req_capture="streamed")
        resp_tee = fs.extra.get("resp_tee")
        if resp_tee is not None:
            if isinstance(resp_tee, SseTee):
                resp_tee.close_parser()
                if resp_tee.parse_error:  # the raw body is complete, the events stop early: say why
                    st.event("sse_parse_stopped", "warn", session=fs.ident.session, tool=fs.ident.tool,
                             host=flow.request.host, port=flow.request.port, flow_id=flow.id, message=resp_tee.parse_error)
            fs.recorded = True
            row.update(
                _resp_raw=resp_tee.captured,
                resp_body_size=resp_tee.size,
                resp_body_truncated=resp_tee.truncated,
                resp_capture="sse" if isinstance(resp_tee, SseTee) else "streamed",
                sse_event_count=fs.sse_seq,
            )
        fs.recorded = True  # after the tees are closed: their last event or message still counts
        row.update(extra)
        st.live.publish(live.summary(row))
        st.writer.put("http_flows", row)

    @guard
    def response(self, flow: http.HTTPFlow):
        st = state.get()
        if st is None:
            return
        if flow.websocket is not None:
            if flow.id in st.flows:
                st.live_ws[flow.id] = flow
                fs = st.flows[flow.id]
                self._publish_open(st, flow, fs, "websocket")
            return
        self._record(st, flow)

    @guard
    def error(self, flow: http.HTTPFlow):
        st = state.get()
        if st is not None:
            self._record(st, flow)

    @guard
    def websocket_message(self, flow: http.HTTPFlow):
        st = state.get()
        fs: FlowState | None = st.flows.get(flow.id) if st is not None else None
        if fs is None or flow.websocket is None:
            return
        msg = flow.websocket.messages[-1]
        content = msg.content
        fs.ws_seq += 1
        row = {
                "scan_id": st.config.scan_id,
                "flow_id": flow.id,
                "n": fs.n,
                "seq": fs.ws_seq,
                "ts": rows.ms(msg.timestamp),
                "session": fs.ident.session,
                "tool": fs.ident.tool,
                "call_id": fs.ident.call,
                "host": flow.request.pretty_host,
                "from_client": msg.from_client,
                "opcode": "text" if msg.is_text else "binary",
                "size": len(content),
                "truncated": len(content) > st.config.ws_msg_cap,
                "injected": msg.injected,
                "dropped": msg.dropped,
                "content": content[: st.config.ws_msg_cap],
        }
        st.live.publish_child(fs.n, "ws", row)
        st.writer.put("ws_messages", row)
        if st.config.ws_trim and len(flow.websocket.messages) > 1:
            del flow.websocket.messages[:-1]

    def _finish_ws(self, st, flow: http.HTTPFlow, end_reason: str) -> None:
        st.live_ws.pop(flow.id, None)
        fs: FlowState | None = st.flows.get(flow.id)
        ws = flow.websocket
        extra = {"resp_capture": "websocket", "end_reason": end_reason, "ws_message_count": fs.ws_seq if fs else 0}
        if ws is not None:
            extra.update(
                ws_close_code=ws.close_code or 0,
                ws_close_reason=ws.close_reason or "",
                ws_closed_by_client=bool(ws.closed_by_client),
            )
            end = ws.timestamp_end or time.time()  # still open at shutdown: it lasted until now, not the handshake
            extra["ts_end"] = rows.ms(end)
            extra["duration_ms"] = max(0, rows.ms(end) - rows.ms(flow.request.timestamp_start))
        self._record(st, flow, **extra)

    @guard
    def websocket_end(self, flow: http.HTTPFlow):
        st = state.get()
        if st is not None:
            self._finish_ws(st, flow, "ws_closed")

    # ----------------------------------------------------------------- tunnels that are not HTTP

    @guard
    def tcp_start(self, flow):
        st = state.get()
        if st is None:
            return
        cs = st.conns.get(flow.client_conn.id)
        st.tunnels[flow.id] = {"flow": flow, "ident": cs.ident if cs is not None else None, "start": time.time(),
                               "up": 0, "down": 0, "first_up": b"", "first_down": b""}

    @guard
    def tcp_message(self, flow):
        st = state.get()
        t = st.tunnels.get(flow.id) if st is not None else None
        if t is None or not flow.messages:
            return
        msg = flow.messages[-1]
        side = "up" if msg.from_client else "down"
        t[side] += len(msg.content)
        if len(t["first_" + side]) < 64:
            t["first_" + side] += msg.content[: 64 - len(t["first_" + side])]
        if st.config.ws_trim and len(flow.messages) > 1:
            del flow.messages[:-1]  # long tunnels would otherwise keep every chunk in memory

    @guard
    def tcp_end(self, flow):
        st = state.get()
        if st is not None:
            self._finish_tunnel(st, flow.id, "closed")

    @guard
    def tcp_error(self, flow):
        st = state.get()
        if st is not None:
            self._finish_tunnel(st, flow.id, "error")

    @staticmethod
    def _finish_tunnel(st, flow_id: str, how: str) -> None:
        """One proxy_events row per TCP tunnel mitmproxy forwarded as raw bytes: who, where, how much. Plaintext
        HTTP/2 (gRPC without TLS) lands here too, because mitmproxy does not parse it; that gets a warning."""
        t = st.tunnels.pop(flow_id, None)
        if t is None:
            return
        flow, ident = t["flow"], t["ident"]
        up, down = t["first_up"], t["first_down"]
        if up.startswith(b"PRI * HTTP/2.0"):
            looks, severity = "h2c", "warn"
        elif up[:1] == b"\x16" and up[1:2] == b"\x03":
            looks, severity = "tls", "info"
        elif up.startswith(b"SSH-") or down.startswith(b"SSH-"):
            looks, severity = "ssh", "info"
        else:
            looks, severity = "unknown", "info"
        address = flow.server_conn.address if flow.server_conn and flow.server_conn.address else ("", 0)
        note = {
            "h2c": "plaintext HTTP/2 (for example gRPC without TLS): mitmproxy forwards it unparsed, so its requests are not "
                   "recorded as flows; use TLS",
        }.get(looks, f"{looks} tunnel, not HTTP: forwarded and counted, not parsed")
        if flow.error:
            note += f"; error: {flow.error.msg}"
        st.event(
            "tcp_tunnel",
            severity,
            session=ident.session if ident else "",
            tool=ident.tool if ident else "",
            proxy_user=ident.user if ident else "",
            reason=looks,
            listener=flow.client_conn.proxy_mode.full_spec if flow.client_conn.proxy_mode else "",
            client_conn_id=flow.client_conn.id,
            client_ip=flow.client_conn.peername[0] if flow.client_conn.peername else "",
            host=str(address[0]),
            port=int(address[1] or 0),
            flow_id=flow.id,
            message=note,
            counters={"bytes_up": t["up"], "bytes_down": t["down"],
                      "duration_ms": max(0, int((time.time() - t["start"]) * 1000)), "closed": int(how == "closed")},
        )

    @guard
    def tls_failed_client(self, data):
        self._tls_failed(data, "tls_failed_client")

    @guard
    def tls_failed_server(self, data):
        self._tls_failed(data, "tls_failed_server")

    def _tls_failed(self, data, kind: str):
        st = state.get()
        if st is None:
            return
        client = data.context.client
        cs = st.conns.get(client.id)
        ident = cs.ident if cs is not None else None
        server = data.context.server
        st.event(
            kind,
            "warn",
            session=ident.session if ident else "",
            tool=ident.tool if ident else "",
            proxy_user=ident.user if ident else "",
            listener=client.proxy_mode.full_spec if client.proxy_mode else "",
            client_conn_id=client.id,
            client_ip=client.peername[0] if client.peername else "",
            host=(server.address[0] if server and server.address else "") or (client.sni or ""),
            port=server.address[1] if server and server.address else 0,
            sni=client.sni or "",
            message=data.conn.error or "",
        )
