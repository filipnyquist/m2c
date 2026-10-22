"""Flow -> row dicts.

Hooks call the `*_row` builders, which only copy references (header field tuples, raw body bytes) so the event
loop does no real work. The writer thread calls `finalize()`, which decodes and caps bodies. Keys starting with
`_` are inputs for `finalize()` and are ignored by the encoder.
"""

from __future__ import annotations

import time

from mitmproxy import connection, http
from mitmproxy.connection import ConnectionState

from .decode import decode_body
from .identity import Identity, ua_tool


def ms(ts: float | None) -> int:
    return int(round(ts * 1000)) if ts else 0


def _ip(addr) -> str:
    return addr[0] if addr else ""


def _port(addr) -> int:
    return addr[1] if addr and len(addr) > 1 else 0


def conn_fields(client: connection.Client | None, server: connection.Server | None) -> dict:
    row = {}
    if client is not None:
        row.update(
            client_conn_id=client.id,
            client_ip=_ip(client.peername),
            client_port=_port(client.peername),
            listener=client.proxy_mode.full_spec if client.proxy_mode else "",
            tls=client.tls_established,
            sni=client.sni or "",
            tls_version=client.tls_version or "",
            alpn=(client.alpn or b"").decode("ascii", "replace"),
        )
    if server is not None:
        addr = server.peername or server.address
        row.update(server_conn_id=server.id if server.timestamp_start else "", server_ip=_ip(server.peername), server_port=_port(addr))
    return row


def identity_fields(ident: Identity | None) -> dict:
    if ident is None:
        return {}
    return {"session": ident.session, "tool": ident.tool, "call_id": ident.call, "proxy_user": ident.user[:256], "identity_source": ident.source}


def _closed_side(flow: http.HTTPFlow) -> str:
    """For messages that name no side, or the wrong one: the socket that has hit EOF while the other is still
    readable. "" when that does not tell."""
    client, server = flow.client_conn, flow.server_conn
    server_up = server is not None and bool(server.timestamp_tcp_setup)
    client_eof = client is not None and not client.state & ConnectionState.CAN_READ
    server_eof = server_up and not server.state & ConnectionState.CAN_READ
    if server_eof and not client_eof:
        return "upstream_disconnect"
    if client_eof and not server_eof:
        return "client_abort"
    return ""


def error_kind(flow: http.HTTPFlow) -> str:
    if not flow.error:
        return ""
    msg = flow.error.msg.lower()
    server_up = flow.server_conn is not None and bool(flow.server_conn.timestamp_tcp_setup)
    if "client disconnected" in msg or "client closed" in msg:
        # mitmproxy's HTTP/1 layer also says "Client disconnected." when the server hangs up while it waits
        return _closed_side(flow) or "client_abort"
    if "killed" in msg:
        return "killed"
    if "timed out" in msg or "timeout" in msg:
        return "timeout"
    if "tls" in msg or "certificate" in msg or "ssl" in msg:
        return "upstream_tls"
    if "server closed connection" in msg or "server disconnected" in msg:
        return "upstream_disconnect"
    if "stream reset" in msg or "stream closed" in msg:
        # HTTP/2 RST_STREAM ("... by client" whichever peer sent it); a CANCEL is a client giving up
        return "client_abort" if "cancel" in msg else "upstream_disconnect" if server_up else "upstream_connect"
    if any(s in msg for s in ("peer closed", "connection closed", "connection reset", "eof")):
        # h11, HTTP/2 ("HTTP/2 connection closed: ...") and socket errors name no side
        return _closed_side(flow) or ("upstream_disconnect" if server_up else "upstream_connect")
    if not server_up and flow.server_conn is not None:
        return "upstream_connect"
    return "other"


def http_row(flow: http.HTTPFlow, ident: Identity | None, scan_id: str, n: int, tag: str = "") -> dict:
    req, res = flow.request, flow.response
    end = (res.timestamp_end if res is not None else None) or (flow.error.timestamp if flow.error else None) or time.time()
    start = req.timestamp_start or end
    row = {
        "scan_id": scan_id,
        "flow_id": flow.id,
        "n": n,
        "ts_start": ms(start),
        "ts_end": ms(end),
        "duration_ms": max(0, ms(end) - ms(start)),
        "tag": tag,
        "ua_tool": ua_tool(req.headers.get("user-agent")),
        "method": req.method,
        "scheme": req.scheme,
        "host": req.pretty_host,
        "port": req.port,
        "path": req.path,
        "url": req.pretty_url,
        "http_version": req.http_version,
        "req_headers": list(req.headers.fields),
        "req_trailers": list(req.trailers.fields) if req.trailers else [],
        "_req_raw": req.raw_content,
        "_req_ce": req.headers.get("content-encoding"),
        "is_replay": flow.is_replay is not None,
        "grpc_status": -1,  # no gRPC status (the recorder fills the gRPC columns for gRPC calls)
        **identity_fields(ident),
        **conn_fields(flow.client_conn, flow.server_conn),
    }
    if res is not None:
        row.update(
            status=res.status_code,
            reason=res.reason,
            ttfb_ms=max(0, ms(res.timestamp_start) - ms(start)) if res.timestamp_start else 0,
            resp_headers=list(res.headers.fields),
            resp_trailers=list(res.trailers.fields) if res.trailers else [],
            resp_content_type=(res.headers.get("content-type") or "").split(";", 1)[0].strip().lower()[:100],
            _resp_raw=res.raw_content,
            _resp_ce=res.headers.get("content-encoding"),
        )
    if flow.error:
        row.update(error=flow.error.msg, error_kind=error_kind(flow), end_reason="error")
    else:
        row["end_reason"] = "complete"
    return row


def event_row(scan_id: str, kind: str, severity: str = "info", **fields) -> dict:
    row = {"scan_id": scan_id, "ts": ms(time.time()), "kind": kind, "severity": severity}
    row.update(fields)
    return row


def _finalize_body(row: dict, side: str, cap: int) -> None:
    raw_key, ce_key = f"_{side}_raw", f"_{side}_ce"
    capture_key = f"{side}_capture"
    if raw_key not in row:
        return
    raw = row.pop(raw_key)
    coding = row.pop(ce_key, None)
    if raw is None:
        # mitmproxy streamed the body and nothing captured it
        row.setdefault(capture_key, "streamed")
        return
    row.setdefault(f"{side}_body_size", len(raw))
    if not raw:
        row.setdefault(capture_key, "none")
        return
    body, decoded, truncated = decode_body(raw, coding, cap)
    row[f"{side}_body"] = body
    row[f"{side}_body_decoded"] = decoded
    row[f"{side}_body_truncated"] = truncated or row.get(f"{side}_body_truncated", False)
    row.setdefault(capture_key, "buffered")


def _finalize_grpc(row: dict, cap: int) -> None:
    """gRPC compresses each message on its own (grpc-encoding): decompress it, within the same limits as bodies."""
    data = row.get("data")
    if not row.get("compressed") or not data or row.get("partial") or row.get("truncated"):
        return
    coding = (row.get("encoding") or "").lower()
    if coding not in ("gzip", "deflate", "zstd", "br"):
        return  # identity, snappy, unknown: keep the bytes as they are
    body, decoded, truncated = decode_body(data, coding, cap)
    if decoded:
        row["data"], row["decompressed"] = body, True
        row["truncated"] = truncated


def finalize(table: str, row: dict, body_cap: int) -> dict:
    if table == "http_flows":
        _finalize_body(row, "req", body_cap)
        _finalize_body(row, "resp", body_cap)
    elif table == "grpc_messages":
        _finalize_grpc(row, body_cap)
    return row


def strip_bodies(row: dict) -> None:
    """Under memory pressure: keep the row, drop the bytes. Sizes are kept: a streamed body's size is its full
    length (set by the recorder), not the captured prefix. An SSE or WebSocket flow keeps its capture label (it says
    what the flow is) and is marked truncated; other bodies become 'dropped'."""
    for side in ("req", "resp"):
        raw_key, capture_key = f"_{side}_raw", f"{side}_capture"
        if raw_key not in row:
            continue
        raw = row.pop(raw_key)
        row.pop(f"_{side}_ce", None)
        if raw is None:
            row.setdefault(capture_key, "streamed")
        elif raw:
            row.setdefault(f"{side}_body_size", len(raw))
            if row.get(capture_key) in ("sse", "websocket"):
                row[f"{side}_body_truncated"] = True
            else:
                row[capture_key] = "dropped"
    for key in ("content", "data"):
        if row.get(key):
            row[key] = b""
            row["truncated"] = True
