"""The read layer shared by the live API (reader sessions inside the proxy) and the offline CLI (a stopped scan).

`Queries(run, scope)` takes `run(sql, params, fmt) -> bytes`. With `scope` set (a session-scoped token), every query
is pinned to that session and raw SQL is refused. Lists never read body columns; bodies are fetched one at a time.
"""

from __future__ import annotations

import base64
import json
import shlex
import time
from collections.abc import Callable
from datetime import datetime, timezone

from . import grpc
from .filters import BY_KEY, compile_filter
from .schema import ERROR, FAILED

Run = Callable[[str, dict | None, str], bytes]

DB = "m2c"
SUMMARY = (
    "n, toUnixTimestamp64Milli(ts_start) AS ts, session, tool, call_id, tag, method, scheme, host, port, path, status, "
    "duration_ms, req_body_size, resp_body_size, resp_content_type, resp_capture, sse_event_count, ws_message_count, "
    "error, error_kind, ua_tool, grpc, grpc_service, grpc_method, grpc_status"
)
DETAIL = (
    "n, toString(flow_id) AS flow_id, scan_id, toUnixTimestamp64Milli(ts_start) AS ts, toUnixTimestamp64Milli(ts_end) AS ts_end, "
    "ttfb_ms, duration_ms, session, tool, call_id, tag, ua_tool, proxy_user, identity_source, listener, "
    "toString(client_ip) AS client_ip, client_port, toString(server_ip) AS server_ip, server_port, tls, sni, tls_version, alpn, "
    "method, scheme, host, port, path, url, http_version, req_headers, req_trailers, req_body_size, req_body_truncated, "
    "req_body_decoded, req_capture, length(req_body) AS req_body_stored, status, reason, resp_headers, resp_trailers, "
    "resp_content_type, resp_body_size, resp_body_truncated, resp_body_decoded, resp_capture, length(resp_body) AS resp_body_stored, "
    "sse_event_count, ws_message_count, ws_close_code, ws_close_reason, ws_closed_by_client, error, error_kind, end_reason, is_replay, replay_of, "
    "grpc, grpc_service, grpc_method, grpc_status, grpc_message, grpc_status_source, grpc_timeout_ms, grpc_encoding, "
    "grpc_req_messages, grpc_resp_messages"
)
EXPORTS = ("curl", "fetch", "python", "raw", "har")
HOP_BY_HOP = {"proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "content-length", "te", "upgrade"}


REPORT_KEYS = {"session": ("session",), "tool": ("session", "tool"), "call": ("session", "tool", "call_id")}
RE2_SPECIAL = set("\\.+*?()|[]{}^$")


def re2_literal(text: str) -> str:
    """`text` as an RE2 pattern that matches it literally."""
    return "".join("\\" + c if c in RE2_SPECIAL else c for c in text)


class Forbidden(Exception):
    pass


def _rows(raw: bytes) -> list[dict]:
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def _headers(pairs) -> list[list[str]]:
    return [[p["name"], p["value"]] if isinstance(p, dict) else list(p) for p in pairs or []]


class Queries:
    def __init__(self, run: Run, scope: str | None = None, proto_file: str | None = None):
        self._run = run
        self.scope = scope
        self.proto_file = proto_file or None  # names protobuf fields when gRPC messages are decoded

    def rows(self, sql: str, params: dict | None = None) -> list[dict]:
        return _rows(self._run(sql, params, "JSONEachRow"))

    def _where(self, q: str = "") -> tuple[str, dict]:
        return compile_filter(q, self.scope)

    # ------------------------------------------------------------------ lists

    def sessions(self, q: str = "") -> list[dict]:
        where, params = self._where(q)
        return self.rows(
            f"SELECT session, tool, toUnixTimestamp64Milli(min(ts_start)) AS first_seen, toUnixTimestamp64Milli(max(ts_end)) AS last_seen, "
            f"count() AS flows, countIf{FAILED} AS failures, uniqExact(host) AS hosts, "
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
        row["grpc_status_name"] = grpc.status_name(row["grpc_status"]) if row.get("grpc") else ""
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

    def grpc(self, n: int, after: int = 0, limit: int = 1000, decode: bool = True) -> list[dict]:
        """The messages of one gRPC call in order (both directions), each decoded as protobuf when it is complete:
        with field names when a .proto file defines the method's types, schemaless otherwise."""
        rows = self._children(
            "grpc_messages", n, after, limit,
            "seq, dir_seq, toUnixTimestamp64Milli(ts) AS ts, ms_since_req, from_client, service, method, compressed, encoding, "
            "decompressed, size, truncated, partial, length(data) AS stored, base64Encode(data) AS base64",
        )
        for r in rows:
            complete = not r["truncated"] and not r["partial"] and (not r["compressed"] or r["decompressed"])
            r["decoded"], r["decoded_as"] = "", "" if complete else "incomplete"
            if decode and complete:
                path = f"/{r['service']}/{r['method']}" if r["service"] else ""
                r["decoded"], r["decoded_as"] = grpc.decode(base64.b64decode(r["base64"]), path, r["from_client"], self.proto_file)
        return rows

    # ------------------------------------------------------------------ scan

    def stats(self) -> dict:
        where, params = self._where()
        out = self.rows(
            f"SELECT count() AS flows, uniqExact(session) AS sessions, uniqExact(tool) AS tools, uniqExact(host) AS hosts, "
            f"countIf{ERROR} AS errors, countIf{FAILED} AS failures, countIf(error != '') AS transport_errors, max(n) AS last_n, toUnixTimestamp64Milli(min(ts_start)) AS first_ts, "
            f"toUnixTimestamp64Milli(max(ts_end)) AS last_ts, any(scan_id) AS scan_id FROM {DB}.http_flows WHERE {where}",
            params,
        )[0]
        for table in ("sse_events", "ws_messages", "grpc_messages"):
            out[table] = int(self.rows(f"SELECT count() AS c FROM {DB}.{table} WHERE {where}", params)[0]["c"])
        if self.scope is None:
            out["proxy_events"] = {
                r["kind"]: int(r["c"]) for r in self.rows(f"SELECT kind, count() AS c FROM {DB}.proxy_events GROUP BY kind")
            }
        return out

    def notes(self, ns: list[int] | None = None, q: str = "", note_id: str | None = None, limit: int = 1000) -> list[dict]:
        """Notes (latest versions, deleted ones too: see notes.Notes.merge) on flows `ns`, on the flows matching `q`,
        or the one with this id; newest first."""
        from .notes import view
        from .schema import NOTES_LATEST

        params: dict = {}
        conds = []
        if self.scope is not None:
            conds.append("session = {notes_scope:String}")
            params["notes_scope"] = self.scope
        if ns is not None:
            conds.append("n IN {notes_ns:Array(UInt64)}")
            params["notes_ns"] = [int(n) for n in ns]
        if note_id is not None:
            conds.append("id = {notes_id:String}")  # (chDB does not quote the strings of an Array(String) parameter)
            params["notes_id"] = note_id
        if q:
            where, p = self._where(q)
            params.update(p)
            conds.append(f"n IN (SELECT n FROM {DB}.http_flows WHERE {where})")
        rows = self.rows(f"SELECT * FROM ({NOTES_LATEST}) WHERE {' AND '.join(conds) or '1'} ORDER BY updated DESC "
                         f"LIMIT {max(1, min(int(limit), 10000))}", params)
        return [view(r) for r in rows]

    def call_sessions(self) -> list[dict]:
        """Sessions whose flows carry call ids: [{session, calls, last_ts}], the most recent first."""
        where, params = self._where()
        return self.rows(f"SELECT session, uniqExact(call_id) AS calls, toUnixTimestamp64Milli(max(ts_start)) AS last_ts "
                         f"FROM {DB}.http_flows WHERE {where} AND call_id != '' GROUP BY session ORDER BY last_ts DESC LIMIT 100", params)

    def timeline(self, session: str, limit: int = 2000) -> dict:
        """A session's last `limit` flows grouped by the tool call that made them (timeline.build)."""
        from . import timeline as tl

        if self.scope is not None and session != self.scope:
            raise Forbidden("a session token sees its own session's timeline only")
        where, params = self._where(f"session:{session}" if session else "")
        flows = self.rows(f"SELECT {SUMMARY} FROM {DB}.http_flows WHERE {where} ORDER BY n DESC LIMIT {max(1, min(int(limit), 5000))}", params)
        flows.reverse()
        items = tl.build(flows)
        return {"session": session, "items": items, "calls": sum(1 for x in items if x["kind"] == "call"), "flows": len(flows)}

    def _events_where(self, params: dict) -> tuple[str, str]:
        """(WHERE, claimed expression): a session-scoped caller sees its own session's events, plus rejected attempts
        whose proxy username names its session: those are `claimed`, since a rejected username proves nothing."""
        if self.scope is None:
            return "1", "false"
        params["scope"] = self.scope
        claimed = "(session = '' AND startsWith(proxy_user, concat({scope:String}, '.')))"
        return f"(session = {{scope:String}} OR {claimed})", claimed

    def events(self, kind: str = "", limit: int = 100, severity: str = "") -> list[dict]:
        """Proxy events, newest first, each with a `fix` (advice.py) when there is something to do."""
        from .advice import for_event

        params = {"kind": kind, "severity": severity}
        where, claimed = self._events_where(params)
        if kind:
            where += " AND kind = {kind:String}"
        if severity:
            where += " AND toString(severity) = {severity:String}"
        rows = self.rows(
            f"SELECT toUnixTimestamp64Milli(ts) AS ts, kind, severity, session, tool, proxy_user, reason, toString(client_ip) AS client_ip, "
            f"host, port, sni, status, message, counters, {claimed} AS claimed FROM {DB}.proxy_events WHERE {where} "
            f"ORDER BY ts DESC LIMIT {max(1, min(int(limit), 5000))}",
            params,
        )
        for r in rows:
            r["fix"] = for_event(r)
        return rows

    def event_counts(self, since_ms: int = 0) -> list[dict]:
        """[{kind, severity, count, recent, last_ts}] over the events the caller may see; `recent` counts those after
        `since_ms` (the UI's "new since you last looked")."""
        params: dict = {"since": int(since_ms)}
        where, _ = self._events_where(params)
        return self.rows(
            f"SELECT kind, toString(severity) AS severity, count() AS count, countIf(toUnixTimestamp64Milli(ts) > {{since:Int64}}) AS recent, "
            f"toUnixTimestamp64Milli(max(ts)) AS last_ts "
            f"FROM {DB}.proxy_events WHERE {where} GROUP BY kind, severity ORDER BY count DESC",
            params,
        )

    def activity(self, q: str = "", buckets: int = 24) -> dict:
        """Flows and failures per session in `buckets` equal time slices of the span the matching flows cover."""
        where, params = self._where(q)
        buckets = max(1, min(int(buckets), 120))
        span = self.rows(f"SELECT toUnixTimestamp64Milli(min(ts_start)) AS lo, toUnixTimestamp64Milli(max(ts_start)) AS hi, count() AS c "
                         f"FROM {DB}.http_flows WHERE {where}", params)[0]
        if not int(span["c"]):
            return {"from": 0, "to": 0, "width_ms": 0, "buckets": buckets, "sessions": {}}
        lo, hi = int(span["lo"]), int(span["hi"])
        width = max(1000, -(-(hi - lo + 1) // buckets))  # at least a second per bucket
        params.update(act_lo=lo, act_w=width)
        rows = self.rows(
            f"SELECT session, intDiv(toUnixTimestamp64Milli(ts_start) - {{act_lo:Int64}}, {{act_w:Int64}}) AS b, count() AS c, "
            f"countIf{FAILED} AS f FROM {DB}.http_flows WHERE {where} GROUP BY session, b ORDER BY session, b",
            params,
        )
        out: dict[str, list] = {}
        for r in rows:
            series = out.setdefault(r["session"], [[0, 0] for _ in range(buckets)])
            b = min(int(r["b"]), buckets - 1)
            series[b][0] += int(r["c"])
            series[b][1] += int(r["f"])
        return {"from": lo, "to": lo + width * buckets, "width_ms": width, "buckets": buckets, "sessions": out}

    def hits(self, flt: str, ns: list[int]) -> dict[int, bool]:
        """For those of `ns` that are in the database: whether they match filter `flt`. Missing ones are not written yet."""
        where, params = compile_filter(flt, self.scope)
        params["hit_ns"] = ns
        pin = ""
        if self.scope is not None:
            pin = " AND session = {hit_scope:String}"
            params["hit_scope"] = self.scope
        rows = self.rows(f"SELECT n, max(toUInt8({where})) AS hit FROM {DB}.http_flows WHERE n IN {{hit_ns:Array(UInt64)}}{pin} GROUP BY n", params)
        return {int(r["n"]): bool(r["hit"]) for r in rows}

    # ------------------------------------------------------------------ analysis

    def report(self, q: str = "", by: str = "tool", limit: int = 50) -> dict:
        """Per session, tool or call: flows, failures, hosts, statuses, error kinds, the slowest flows and bytes.
        Groups in order of their first flow."""
        keys = REPORT_KEYS.get(by)
        if keys is None:
            raise ValueError(f"by is one of {', '.join(REPORT_KEYS)}")
        where, params = self._where(q)
        cols = ", ".join(keys)
        limit = max(1, min(int(limit), 500))
        groups = self.rows(
            f"SELECT {cols}, count() AS flows, countIf{FAILED} AS failures, countIf{ERROR} AS errors, "
            f"toUnixTimestamp64Milli(min(ts_start)) AS first_ts, toUnixTimestamp64Milli(max(ts_end)) AS last_ts, "
            f"sum(req_body_size) AS bytes_up, sum(resp_body_size) AS bytes_down, uniqExact(host) AS host_count, "
            f"groupArraySorted(3)((-toInt64(duration_ms), n, host, path)) AS slow "
            f"FROM {DB}.http_flows WHERE {where} GROUP BY {cols} ORDER BY first_ts LIMIT {limit + 1}",
            params,
        )
        more = len(groups) > limit
        groups = groups[:limit]
        index = {tuple(g[k] for k in keys): g for g in groups}
        for g in groups:
            g["slowest"] = [{"n": n, "duration_ms": -d, "host": h, "path": p} for d, n, h, p in g.pop("slow")]
            g.update(hosts=[], statuses={}, error_kinds={})
        if groups:
            for r in self.rows(f"SELECT {cols}, host, count() AS c FROM {DB}.http_flows WHERE {where} GROUP BY {cols}, host "
                               f"ORDER BY c DESC LIMIT 5 BY {cols}", params):
                g = index.get(tuple(r[k] for k in keys))
                if g is not None:
                    g["hosts"].append([r["host"], int(r["c"])])
            for r in self.rows(f"SELECT {cols}, status, error_kind, count() AS c FROM {DB}.http_flows WHERE {where} "
                               f"GROUP BY {cols}, status, error_kind ORDER BY c DESC LIMIT 12 BY {cols}", params):
                g = index.get(tuple(r[k] for k in keys))
                if g is None:
                    continue
                if r["status"]:
                    g["statuses"][str(r["status"])] = g["statuses"].get(str(r["status"]), 0) + int(r["c"])
                if r["error_kind"]:
                    g["error_kinds"][r["error_kind"]] = g["error_kinds"].get(r["error_kind"], 0) + int(r["c"])
        return {"by": by, "groups": groups, "more": more}

    def facets(self, key: str, prefix: str = "", q: str = "", limit: int = 20) -> dict:
        """Values of filter key `key` among the flows matching `q`, with counts, for autocomplete: those containing
        `prefix` (case-insensitive), the ones starting with it first. `path` suggests one segment more than typed."""
        spec = BY_KEY.get(key)
        if spec is None:
            raise ValueError(f"unknown filter key {key!r}")
        low = prefix.lower()
        out = {"key": key, "values": [], "static": [v for v in spec.get("values", ()) if low in v.lower()]}
        expr = spec.get("facet")
        if not expr:
            return out
        where, params = self._where(q)
        if key == "label":  # labels live in their own table
            from .schema import NOTES_FILTER

            params.update(facet_prefix=prefix, facet_low=low)
            rows = self.rows(
                f"SELECT label AS v, count() AS c FROM ({NOTES_FILTER}) WHERE NOT deleted AND label != '' "
                f"AND positionCaseInsensitiveUTF8(label, {{facet_prefix:String}}) > 0 AND n IN (SELECT n FROM {DB}.http_flows WHERE {where}) "
                f"GROUP BY v ORDER BY startsWith(v, {{facet_low:String}}) DESC, c DESC, v LIMIT {max(1, min(int(limit), 100))}",
                params,
            )
            out["values"] = [{"value": r["v"], "count": int(r["c"])} for r in rows]
            return out
        params.update(facet_prefix=prefix, facet_low=low)
        limit = max(1, min(int(limit), 100))
        deeper = ""
        if key == "path":
            depth = max(1, prefix.count("/")) + 1  # "/api/" -> "/api/v1", "/ap" -> "/api"
            segments = "splitByChar('/', splitByChar('?', path)[1])"
            expr = f"arrayStringConcat(arraySlice({segments}, 1, {depth}), '/')"
            deeper = f", max(length({segments})) > {depth} AS deeper"
        rows = self.rows(
            f"SELECT v, count() AS c{deeper} FROM (SELECT toString({expr}) AS v, path FROM {DB}.http_flows WHERE {where}) "
            f"WHERE v != '' AND positionCaseInsensitiveUTF8(v, {{facet_prefix:String}}) > 0 "
            f"GROUP BY v ORDER BY startsWith(lowerUTF8(v), {{facet_low:String}}) DESC, c DESC, v LIMIT {limit}",
            params,
        )
        out["values"] = [{"value": r["v"], "count": int(r["c"]), **({"deeper": bool(r["deeper"])} if deeper else {})} for r in rows]
        return out

    def suggest(self, q: str = "", open_flows: int = 0) -> dict:
        """Hints for refining `q`, from aggregates over the flows it matches (suggest.py)."""
        from . import suggest

        where, params = self._where(q)
        agg = self.rows(
            f"SELECT count() AS total, countIf{FAILED} AS failures, countIf{ERROR} AS errors, "
            f"topK(3, 3, 'counts')(tool) AS tools, topK(3, 3, 'counts')(host) AS hosts, topK(3, 3, 'counts')(status) AS statuses, "
            f"topK(3, 3, 'counts')((tool, status)) AS tool_status, topK(3, 3, 'counts')(session) AS sessions, "
            f"uniqExact(session) AS n_sessions, topKIf(3, 3, 'counts')(error_kind, error_kind != '') AS error_kinds, "
            f"quantile(0.95)(duration_ms) AS p95, countIf(scheme IN ('http', 'ws') AND arrayExists(h -> lower(h.name) IN "
            f"{suggest.CREDENTIAL_SQL}, req_headers)) AS cleartext_creds FROM {DB}.http_flows WHERE {where}",
            params,
        )[0]
        return {"total": int(agg["total"]), "hints": suggest.hints(q, agg, open_flows)}

    def grep(self, pattern: str, regex: bool = False, ci: bool = True, side: str = "both", q: str = "", where_in: str = "body",
             context: int = 80, limit: int = 20, per_flow: int = 3) -> list[dict]:
        """Bodies (or SSE event data, WebSocket messages) matching `pattern`, with a snippet of context around each match.
        RE2 inside ClickHouse: linear time, so a pattern from an agent cannot hang the server."""
        if not pattern:
            raise ValueError("an empty pattern")
        if side not in ("req", "resp", "both"):
            raise ValueError("side is req, resp or both")
        context = max(0, min(int(context), 200))
        limit, per_flow = max(1, min(int(limit), 200)), max(1, min(int(per_flow), 20))
        body_re = ("(?is)" if ci else "(?s)") + (pattern if regex else re2_literal(pattern))
        # one capture group around everything: extractAll returns the first group, and the pattern may have its own
        snippet_re = f"({'(?is)' if ci else '(?s)'}.{{0,{context}}}(?:{pattern if regex else re2_literal(pattern)}).{{0,{context}}})"
        where, params = self._where(q)
        params.update(grep_re=body_re, grep_snip=snippet_re)
        hits = "arrayMap(x -> toValidUTF8(x), arraySlice(extractAll({col}, {{grep_snip:String}}), 1, %d))" % per_flow
        if where_in == "body":
            sides = ("req", "resp") if side == "both" else (side,)
            cond = " OR ".join(f"match({s}_body, {{grep_re:String}})" for s in sides)
            cols = ", ".join(f"{hits.format(col=s + '_body')} AS {s}_hits" for s in sides)
            return self.rows(
                f"SELECT n, toUnixTimestamp64Milli(ts_start) AS ts, session, tool, call_id, method, host, path, status, {cols} "
                f"FROM {DB}.http_flows WHERE {where} AND ({cond}) ORDER BY n DESC LIMIT {limit}",
                params,
            )
        table, col = {"sse": ("sse_events", "data"), "ws": ("ws_messages", "content")}.get(where_in, (None, None))
        if table is None:
            raise ValueError("in is body, sse or ws")
        pin = ""
        if self.scope is not None:
            pin = " AND session = {grep_scope:String}"
            params["grep_scope"] = self.scope
        return self.rows(
            f"SELECT n, seq, toUnixTimestamp64Milli(ts) AS ts, session, tool, {hits.format(col=col)} AS hits FROM {DB}.{table} "
            f"WHERE n IN (SELECT n FROM {DB}.http_flows WHERE {where}){pin} AND match({col}, {{grep_re:String}}) "
            f"ORDER BY n DESC, seq LIMIT {limit}",
            params,
        )

    def diff(self, a: int, b: int, max_bytes: int = 256 << 10, redact: bool = True) -> dict | None:
        from . import diff

        fa, fb = self.flow(a), self.flow(b)
        if fa is None or fb is None:
            return None
        bodies = {}
        for side in ("req", "resp"):
            pair = []
            for f in (fa, fb):
                got = self.body(f["n"], side, max_bytes) if f[f"{side}_body_stored"] else None
                pair.append(got[0] if got else b"")
            bodies[side] = tuple(pair)
        return diff.compare(fa, fb, bodies, redact)

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

    def export(self, n: int, fmt: str) -> str | None:
        """Flow n's request as `curl`, `fetch` (JavaScript), `python` (requests), `raw` (HTTP/1.1 text) or `har`."""
        if fmt == "curl":
            return self.curl(n)
        if fmt not in EXPORTS:
            raise ValueError(f"format is one of {', '.join(EXPORTS)}")
        flow = self.flow(n)
        if flow is None:
            return None
        body = (self.body(n, "req") or (b"", ""))[0] if flow["req_body_stored"] else b""
        if fmt == "har":
            resp = self.body(n, "resp") if flow["resp_body_stored"] else None
            entry = _har_entry(flow, (body, "") if body else None, resp)
            return json.dumps({"log": {"version": "1.2", "creator": {"name": "m2c", "version": "0.1"}, "entries": [entry]}}, indent=1)
        headers = [(k, v) for k, v in flow["req_headers"] if k.lower() not in HOP_BY_HOP and not k.lower().startswith("x-m2c-")]
        try:
            text = body.decode("utf-8")
        except UnicodeDecodeError:
            text = None
        note = "the body is decoded; the original was sent with Content-Encoding" if flow["req_body_decoded"] else ""
        if fmt == "raw":
            target = flow["path"] or "/"
            lines = [f"{flow['method']} {target} HTTP/1.1"]
            if not any(k.lower() == "host" for k, _ in headers):
                lines.append(f"Host: {flow['host']}")
            lines += [f"{k}: {v}" for k, v in headers]
            payload = text if text is not None else f"<{len(body)} bytes of binary data, base64: {base64.b64encode(body).decode()}>"
            return "\r\n".join(lines) + "\r\n\r\n" + payload
        if fmt == "fetch":
            opts = {"method": flow["method"], "headers": {k: v for k, v in headers if k.lower() != "host"}}
            js = json.dumps(opts, indent=2, ensure_ascii=False)
            if body:
                data = json.dumps(text, ensure_ascii=False) if text is not None else f'Uint8Array.from(atob({json.dumps(base64.b64encode(body).decode())}), (c) => c.charCodeAt(0))'
                js = js[:-2] + f",\n  \"body\": {data}\n}}"
            return (f"// {note}\n" if note else "") + f"const res = await fetch({json.dumps(flow['url'])}, {js});"
        # python
        hdrs = "{" + ", ".join(f"{k!r}: {v!r}" for k, v in headers if k.lower() != "host") + "}"
        data = "" if not body else f", data={text!r}" if text is not None else f", data=base64.b64decode({base64.b64encode(body).decode()!r})"
        head = "import base64\n" if body and text is None else ""
        return (f"# {note}\n" if note else "") + head + "import requests\n\n" + (
            f"r = requests.request({flow['method']!r}, {flow['url']!r}, headers={hdrs}{data})\nprint(r.status_code, r.text[:200])")

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
