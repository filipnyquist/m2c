"""The read layer shared by the live API (reader sessions inside the proxy) and the offline CLI (a stopped scan).

`Queries(run, scope)` takes `run(sql, params, fmt) -> bytes`. With `scope` set (a session-scoped token), every query
is pinned to that session and raw SQL is refused. Lists never read body columns; bodies are fetched one at a time.
"""

from __future__ import annotations

import base64
import json
import shlex
from collections.abc import Callable
from datetime import datetime, timezone

from .filters import compile_filter

Run = Callable[[str, dict | None, str], bytes]

DB = "m2c"
SUMMARY = (
    "n, toUnixTimestamp64Milli(ts_start) AS ts, session, tool, call_id, tag, method, scheme, host, port, path, status, "
    "duration_ms, req_body_size, resp_body_size, resp_content_type, resp_capture, sse_event_count, ws_message_count, "
    "error, error_kind, ua_tool"
)
DETAIL = (
    "n, toString(flow_id) AS flow_id, scan_id, toUnixTimestamp64Milli(ts_start) AS ts, toUnixTimestamp64Milli(ts_end) AS ts_end, "
    "ttfb_ms, duration_ms, session, tool, call_id, tag, ua_tool, proxy_user, identity_source, listener, "
    "toString(client_ip) AS client_ip, client_port, toString(server_ip) AS server_ip, server_port, tls, sni, tls_version, alpn, "
    "method, scheme, host, port, path, url, http_version, req_headers, req_trailers, req_body_size, req_body_truncated, "
    "req_body_decoded, req_capture, length(req_body) AS req_body_stored, status, reason, resp_headers, resp_trailers, "
    "resp_content_type, resp_body_size, resp_body_truncated, resp_body_decoded, resp_capture, length(resp_body) AS resp_body_stored, "
    "sse_event_count, ws_message_count, ws_close_code, ws_close_reason, ws_closed_by_client, error, error_kind, end_reason, is_replay"
)
HOP_BY_HOP = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "te", "upgrade"}


class Forbidden(Exception):
    pass


def _rows(raw: bytes) -> list[dict]:
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _headers(pairs) -> list[list[str]]:
    return [[p["name"], p["value"]] if isinstance(p, dict) else list(p) for p in pairs or []]


class Queries:
    def __init__(self, run: Run, scope: str | None = None):
        self._run = run
        self.scope = scope

    def rows(self, sql: str, params: dict | None = None) -> list[dict]:
        return _rows(self._run(sql, params, "JSONEachRow"))

    def _where(self, q: str = "") -> tuple[str, dict]:
        return compile_filter(q, self.scope)

    # ------------------------------------------------------------------ lists

    def sessions(self, q: str = "") -> list[dict]:
        where, params = self._where(q)
        return self.rows(
            f"SELECT session, tool, toUnixTimestamp64Milli(min(ts_start)) AS first_seen, toUnixTimestamp64Milli(max(ts_end)) AS last_seen, "
            f"count() AS flows, countIf(status >= 400 OR error != '') AS failures, uniqExact(host) AS hosts, "
            f"sum(req_body_size) AS bytes_up, sum(resp_body_size) AS bytes_down, sum(ws_message_count) AS ws_messages, "
            f"sum(sse_event_count) AS sse_events FROM {DB}.http_flows WHERE {where} GROUP BY session, tool ORDER BY last_seen DESC",
            params,
        )

    def flows(self, q: str = "", limit: int = 100, cursor: int | None = None, order: str = "desc") -> dict:
        where, params = self._where(q)
        limit = max(1, min(int(limit), 5000))
        if cursor is not None:
            where += f" AND n {'<' if order == 'desc' else '>'} {{cursor:UInt64}}"
            params["cursor"] = int(cursor)
        direction = "DESC" if order == "desc" else "ASC"
        # Two steps: the n values (reads n and the filtered columns only), then their summaries through the by_n
        # projection's primary key. One step would read every summary column of every row for the sort.
        ns = [r["n"] for r in self.rows(f"SELECT n FROM {DB}.http_flows WHERE {where} ORDER BY n {direction} LIMIT {limit + 1}", params)]
        rows = []
        if ns:
            rows = self.rows(f"SELECT {SUMMARY} FROM {DB}.http_flows WHERE n IN {{ns:Array(UInt64)}} ORDER BY n {direction}", {"ns": ns})
        more = len(rows) > limit
        rows = rows[:limit]
        return {"flows": rows, "next": rows[-1]["n"] if more and rows else None}

    def count(self, q: str = "") -> int:
        where, params = self._where(q)
        return int(self.rows(f"SELECT count() AS c FROM {DB}.http_flows WHERE {where}", params)[0]["c"])

    # ------------------------------------------------------------------ one flow

    def _locate(self, n: int) -> tuple[str, dict] | None:
        """WHERE clause hitting the primary key (session, ts_start) for flow n, found through the by_n projection."""
        where, params = self._where()
        params["n"] = int(n)
        hit = self.rows(
            f"SELECT session, toUnixTimestamp64Milli(ts_start) AS ts FROM {DB}.http_flows WHERE n = {{n:UInt64}} AND {where} LIMIT 1", params
        )
        if not hit:
            return None
        params.update(loc_session=hit[0]["session"], loc_ts=int(hit[0]["ts"]))
        return (
            f"session = {{loc_session:String}} AND ts_start = fromUnixTimestamp64Milli({{loc_ts:Int64}}) AND n = {{n:UInt64}} AND {where}",
            params,
        )

    def flow(self, n: int) -> dict | None:
        loc = self._locate(n)
        if loc is None:
            return None
        where, params = loc
        rows = self.rows(f"SELECT {DETAIL} FROM {DB}.http_flows WHERE {where} LIMIT 1", params)
        if not rows:
            return None
        row = rows[0]
        for key in ("req_headers", "req_trailers", "resp_headers", "resp_trailers"):
            row[key] = _headers(row[key])
        return row

    def body(self, n: int, side: str, max_bytes: int | None = None) -> tuple[bytes, str] | None:
        """(stored body bytes, content type) for side 'req' or 'resp'."""
        if side not in ("req", "resp"):
            raise ValueError("side is req or resp")
        loc = self._locate(n)
        if loc is None:
            return None
        where, params = loc
        col = f"{side}_body"
        if max_bytes:
            col = f"substring({col}, 1, {int(max_bytes)})"
        sql = f"SELECT {col} AS body, {side}_headers AS h FROM {DB}.http_flows WHERE {where} LIMIT 1"
        raw = self._run(sql, params, "RowBinary")
        if not raw:
            return None
        body, rest = _read_string(raw, 0)
        ctype = ""
        count, pos = _read_varint(raw, rest)
        for _ in range(count):
            name, pos = _read_string(raw, pos)
            value, pos = _read_string(raw, pos)
            if name.lower() == b"content-type":
                ctype = value.decode("latin-1")
        return body, ctype

    def _children(self, table: str, n: int, after: int, limit: int, cols: str) -> list[dict]:
        where, params = self._where()
        params.update(n=int(n), after=int(after))
        limit = max(1, min(int(limit), 10000))
        return self.rows(
            f"SELECT {cols} FROM {DB}.{table} WHERE n = {{n:UInt64}} AND seq > {{after:UInt32}} AND {where} ORDER BY seq LIMIT {limit}",
            params,
        )

    def sse(self, n: int, after: int = 0, limit: int = 1000) -> list[dict]:
        return self._children(
            "sse_events", n, after, limit, "seq, toUnixTimestamp64Milli(ts) AS ts, ms_since_req, event, id, retry_ms, data, size, truncated, partial"
        )

    def ws(self, n: int, after: int = 0, limit: int = 1000) -> list[dict]:
        rows = self._children(
            "ws_messages", n, after, limit,
            "seq, toUnixTimestamp64Milli(ts) AS ts, from_client, opcode, size, truncated, injected, dropped, "
            "if(opcode = 'text' AND isValidUTF8(content), content, '') AS text, if(opcode = 'text' AND isValidUTF8(content), '', base64Encode(content)) AS base64",
        )
        return rows

    # ------------------------------------------------------------------ scan

    def stats(self) -> dict:
        where, params = self._where()
        out = self.rows(
            f"SELECT count() AS flows, uniqExact(session) AS sessions, uniqExact(tool) AS tools, uniqExact(host) AS hosts, "
            f"countIf(error != '') AS errors, max(n) AS last_n, toUnixTimestamp64Milli(min(ts_start)) AS first_ts, "
            f"toUnixTimestamp64Milli(max(ts_end)) AS last_ts, any(scan_id) AS scan_id FROM {DB}.http_flows WHERE {where}",
            params,
        )[0]
        for table in ("sse_events", "ws_messages"):
            out[table] = int(self.rows(f"SELECT count() AS c FROM {DB}.{table} WHERE {where}", params)[0]["c"])
        if self.scope is None:
            out["proxy_events"] = {
                r["kind"]: int(r["c"]) for r in self.rows(f"SELECT kind, count() AS c FROM {DB}.proxy_events GROUP BY kind")
            }
        return out

    def events(self, kind: str = "", limit: int = 100) -> list[dict]:
        if self.scope is not None:
            raise Forbidden("proxy events need an admin token")
        params = {"kind": kind}
        where = "kind = {kind:String}" if kind else "1"
        return self.rows(
            f"SELECT toUnixTimestamp64Milli(ts) AS ts, kind, severity, session, tool, proxy_user, reason, toString(client_ip) AS client_ip, "
            f"host, port, sni, status, message, counters FROM {DB}.proxy_events WHERE {where} ORDER BY ts DESC LIMIT {max(1, min(int(limit), 5000))}",
            params,
        )

    def sql(self, sql: str, fmt: str = "JSONEachRow") -> bytes:
        if self.scope is not None:
            raise Forbidden("SQL needs an admin token")
        return self._run(sql, None, fmt)

    # ------------------------------------------------------------------ exports

    def curl(self, n: int) -> str | None:
        flow = self.flow(n)
        if flow is None:
            return None
        # The captured request is attacker-influenced, and curl gives some argument values a meaning of their own:
        # -g stops [..]/{..} in the URL expanding into many requests, and a body or header starting with '@' would
        # make curl read (and send) a local file. So a text body goes in --data-raw, anything else through stdin.
        args = ["curl", "-sS", "-g"]
        if flow["method"] != "GET":
            args += ["-X", flow["method"]]
        for name, value in flow["req_headers"]:
            if name.lower() not in HOP_BY_HOP and not name.lower().startswith("x-m2c-") and name.lower() != "host" and not name.startswith("@"):
                args += ["-H", f"{name}: {value}"]
        if flow["req_headers"] and any(name.lower() == "host" for name, _ in flow["req_headers"]):
            host = next(v for k, v in flow["req_headers"] if k.lower() == "host")
            if host.split(":")[0] != flow["host"]:
                args += ["-H", f"Host: {host}"]
        args += ["--url", flow["url"]]
        if not flow["req_body_stored"]:
            return shlex.join(args)
        body, _ = self.body(n, "req") or (b"", "")
        note = "# note: the body is decoded; the original was sent with Content-Encoding\n" if flow["req_body_decoded"] else ""
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        if text is not None and "\0" not in text:
            return note + shlex.join([*args, "--data-raw", text])
        return note + f"printf %s {shlex.quote(base64.b64encode(body).decode())} | base64 -d | " + shlex.join([*args, "--data-binary", "@-"])

    def har(self, q: str = "", limit: int = 1000) -> dict:
        page = self.flows(q, limit=limit, order="asc")
        entries = []
        for summary in page["flows"]:
            flow = self.flow(summary["n"])
            if flow is None:
                continue
            req_body = self.body(flow["n"], "req") if flow["req_body_stored"] else None
            resp_body = self.body(flow["n"], "resp") if flow["resp_body_stored"] else None
            entries.append(_har_entry(flow, req_body, resp_body))
        return {"log": {"version": "1.2", "creator": {"name": "m2c", "version": "0.1"}, "entries": entries}}


def _har_text(body: tuple[bytes, str] | None) -> dict:
    if not body:
        return {"size": 0, "text": ""}
    data, ctype = body
    try:
        return {"size": len(data), "mimeType": ctype, "text": data.decode("utf-8")}
    except UnicodeDecodeError:
        return {"size": len(data), "mimeType": ctype, "text": base64.b64encode(data).decode(), "encoding": "base64"}


def _har_entry(flow: dict, req_body, resp_body) -> dict:
    started = datetime.fromtimestamp(flow["ts"] / 1000, tz=timezone.utc).isoformat()
    hdrs = lambda pairs: [{"name": k, "value": v} for k, v in pairs]  # noqa: E731
    entry = {
        "startedDateTime": started,
        "time": flow["duration_ms"],
        "request": {
            "method": flow["method"],
            "url": flow["url"],
            "httpVersion": flow["http_version"],
            "headers": hdrs(flow["req_headers"]),
            "queryString": [],
            "cookies": [],
            "headersSize": -1,
            "bodySize": flow["req_body_size"],
        },
        "response": {
            "status": flow["status"],
            "statusText": flow["reason"],
            "httpVersion": flow["http_version"],
            "headers": hdrs(flow["resp_headers"]),
            "cookies": [],
            "content": _har_text(resp_body),
            "redirectURL": "",
            "headersSize": -1,
            "bodySize": flow["resp_body_size"],
        },
        "cache": {},
        "timings": {"send": 0, "wait": flow["ttfb_ms"], "receive": max(0, flow["duration_ms"] - flow["ttfb_ms"])},
        "serverIPAddress": flow["server_ip"].removeprefix("::ffff:"),
        "_m2c": {"n": flow["n"], "session": flow["session"], "tool": flow["tool"], "call": flow["call_id"], "error": flow["error"]},
    }
    if req_body:
        entry["request"]["postData"] = {"mimeType": req_body[1], **{k: v for k, v in _har_text(req_body).items() if k in ("text", "encoding")}}
    return entry


def _read_varint(buf: bytes, pos: int) -> tuple[int, int]:
    shift = result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7


def _read_string(buf: bytes, pos: int) -> tuple[bytes, int]:
    n, pos = _read_varint(buf, pos)
    return buf[pos : pos + n], pos + n
