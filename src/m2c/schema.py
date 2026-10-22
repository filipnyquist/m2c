"""Table definitions: one list of columns per table drives the DDL, the RowBinary encoder and the central schema.

Rows are dicts keyed by column name; a missing key takes the column type's zero value (see rowbinary.zero).
Migrations only add columns: `ensure()` creates missing tables and runs ADD COLUMN IF NOT EXISTS for every
column, so a newer recorder works on a directory written by an older one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

DB = "m2c"

HEADERS = "Array(Tuple(name String, value String))"
TS = "DateTime64(3, 'UTC')"
TS_CODEC = "Delta, ZSTD(1)"
BIG = "ZSTD(3)"
SMALL = "ZSTD(1)"

IDENTITY_SOURCE = "Enum8('none' = 0, 'connect' = 1, 'request' = 2, 'socks5' = 3, 'header' = 4)"
REQ_CAPTURE = "Enum8('none' = 0, 'buffered' = 1, 'streamed' = 2, 'dropped' = 3)"
RESP_CAPTURE = "Enum8('none' = 0, 'buffered' = 1, 'streamed' = 2, 'dropped' = 3, 'sse' = 4, 'websocket' = 5)"
END_REASON = "Enum8('complete' = 1, 'error' = 2, 'ws_closed' = 3, 'proxy_shutdown' = 4)"
SEVERITY = "Enum8('debug' = 0, 'info' = 1, 'warn' = 2, 'error' = 3)"
OPCODE = "Enum8('text' = 1, 'binary' = 2)"


@dataclass(frozen=True)
class Column:
    name: str
    type: str
    codec: str | None = None


@dataclass(frozen=True)
class Table:
    name: str
    columns: tuple[Column, ...]
    order_by: str
    indexes: tuple[str, ...] = ()
    settings: str = ""
    projections: tuple[str, ...] = ()
    names: tuple[str, ...] = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "names", tuple(c.name for c in self.columns))

    def ddl(self, db: str = DB, engine: str = "MergeTree", partition_by: str | None = None, order_by: str | None = None,
            projections: bool = True) -> str:
        cols = [f"    {c.name} {c.type}" + (f" CODEC({c.codec})" if c.codec else "") for c in self.columns]
        cols += [f"    INDEX {i}" for i in self.indexes]
        if projections:
            cols += [f"    PROJECTION {p}" for p in self.projections]
        sql = f"CREATE TABLE IF NOT EXISTS {db}.{self.name}\n(\n" + ",\n".join(cols) + f"\n)\nENGINE = {engine}\n"
        if partition_by:
            sql += f"PARTITION BY {partition_by}\n"
        sql += f"ORDER BY ({order_by or self.order_by})"
        if self.settings:
            sql += f"\nSETTINGS {self.settings}"
        return sql


def C(name, type_, codec=None):
    return Column(name, type_, codec)


LC = "LowCardinality(String)"
BIG_BLOCKS = "max_compress_block_size = 4194304, min_compress_block_size = 1048576"

IDENTITY = (
    C("session", LC),
    C("tool", LC),
    C("call_id", "String"),
)

HTTP_FLOWS = Table(
    "http_flows",
    (
        C("scan_id", LC),
        C("flow_id", "UUID"),
        C("n", "UInt64"),
        C("ts_start", TS, TS_CODEC),
        C("ts_end", TS, TS_CODEC),
        C("ttfb_ms", "UInt32"),
        C("duration_ms", "UInt32"),
        *IDENTITY,
        C("tag", "String"),
        C("ua_tool", LC),
        C("proxy_user", "String"),
        C("identity_source", IDENTITY_SOURCE),
        C("listener", LC),
        C("client_conn_id", "UUID"),
        C("server_conn_id", "UUID"),
        C("client_ip", "IPv6"),
        C("client_port", "UInt16"),
        C("server_ip", "IPv6"),
        C("server_port", "UInt16"),
        C("tls", "Bool"),
        C("sni", "String"),
        C("tls_version", LC),
        C("alpn", LC),
        C("method", LC),
        C("scheme", LC),
        C("host", LC),
        C("port", "UInt16"),
        C("path", "String", SMALL),
        C("url", "String", SMALL),
        C("http_version", LC),
        C("req_headers", HEADERS, SMALL),
        C("req_trailers", HEADERS, SMALL),
        C("req_body", "String", BIG),
        C("req_body_size", "UInt64"),
        C("req_body_truncated", "Bool"),
        C("req_body_decoded", "Bool"),
        C("req_capture", REQ_CAPTURE),
        C("status", "UInt16"),
        C("reason", LC),
        C("resp_headers", HEADERS, SMALL),
        C("resp_trailers", HEADERS, SMALL),
        C("resp_content_type", LC),
        C("resp_body", "String", BIG),
        C("resp_body_size", "UInt64"),
        C("resp_body_truncated", "Bool"),
        C("resp_body_decoded", "Bool"),
        C("resp_capture", RESP_CAPTURE),
        C("sse_event_count", "UInt32"),
        C("ws_message_count", "UInt32"),
        C("ws_close_code", "UInt16"),
        C("ws_close_reason", "String"),
        C("ws_closed_by_client", "Bool"),
        C("error", "String"),
        C("error_kind", LC),
        C("end_reason", END_REASON),
        C("is_replay", "Bool"),
        C("replay_of", "UInt64"),  # the flow this one resent (m2c's repeater); 0 for others
        # gRPC calls (application/grpc*): status from trailers, a trailers-only response, a gRPC-Web trailer frame,
        # or inferred from how the call ended. grpc_status is -1 when there is none.
        C("grpc", "Bool"),
        C("grpc_service", LC),
        C("grpc_method", LC),
        C("grpc_status", "Int16"),
        C("grpc_message", "String"),
        C("grpc_status_source", LC),
        C("grpc_timeout_ms", "UInt32"),
        C("grpc_encoding", LC),
        C("grpc_req_messages", "UInt32"),
        C("grpc_resp_messages", "UInt32"),
    ),
    order_by="session, ts_start, flow_id",
    # Flow lists are "newest first, maybe filtered": the summary columns sorted by n answer the second step of
    # Queries.flows (n IN (...)) with a primary-key lookup. Small: no bodies or headers.
    projections=(
        "by_n_v2 (SELECT n, ts_start, ts_end, session, tool, call_id, tag, method, scheme, host, port, path, url, status, "
        "duration_ms, req_body_size, resp_body_size, resp_content_type, resp_capture, sse_event_count, ws_message_count, "
        "error, error_kind, ua_tool, grpc, grpc_service, grpc_method, grpc_status ORDER BY n)",
    ),
    indexes=(
        "idx_host host TYPE bloom_filter(0.01) GRANULARITY 4",
        "idx_url url TYPE ngrambf_v1(3, 65536, 2, 0) GRANULARITY 4",
        "idx_n n TYPE minmax GRANULARITY 1",
        "idx_flow flow_id TYPE bloom_filter(0.001) GRANULARITY 1",
    ),
    settings=BIG_BLOCKS,
)

WS_MESSAGES = Table(
    "ws_messages",
    (
        C("scan_id", LC),
        C("flow_id", "UUID"),
        C("n", "UInt64"),
        C("seq", "UInt32"),
        C("ts", TS, TS_CODEC),
        *IDENTITY,
        C("host", LC),
        C("from_client", "Bool"),
        C("opcode", OPCODE),
        C("size", "UInt32"),
        C("truncated", "Bool"),
        C("injected", "Bool"),
        C("dropped", "Bool"),
        C("content", "String", BIG),
    ),
    order_by="session, flow_id, seq",
    indexes=("idx_n n TYPE minmax GRANULARITY 1",),
    settings=BIG_BLOCKS,
)

SSE_EVENTS = Table(
    "sse_events",
    (
        C("scan_id", LC),
        C("flow_id", "UUID"),
        C("n", "UInt64"),
        C("seq", "UInt32"),
        C("ts", TS, TS_CODEC),
        C("ms_since_req", "UInt32"),
        *IDENTITY,
        C("host", LC),
        C("event", LC),
        C("id", "String"),
        C("retry_ms", "UInt32"),
        C("data", "String", BIG),
        C("size", "UInt32"),
        C("truncated", "Bool"),
        C("partial", "Bool"),
    ),
    order_by="session, flow_id, seq",
    indexes=("idx_n n TYPE minmax GRANULARITY 1",),
    settings=BIG_BLOCKS,
)

GRPC_MESSAGES = Table(
    "grpc_messages",
    (
        C("scan_id", LC),
        C("flow_id", "UUID"),
        C("n", "UInt64"),
        C("seq", "UInt32"),  # one counter for both directions: the order of a bidi call
        C("dir_seq", "UInt32"),
        C("ts", TS, TS_CODEC),
        C("ms_since_req", "UInt32"),
        *IDENTITY,
        C("host", LC),
        C("service", LC),
        C("method", LC),
        C("from_client", "Bool"),
        C("compressed", "Bool"),
        C("encoding", LC),
        C("decompressed", "Bool"),
        C("size", "UInt32"),  # as the length prefix declares it
        C("truncated", "Bool"),
        C("partial", "Bool"),
        C("data", "String", BIG),  # the message without its prefix, decompressed when possible
    ),
    order_by="session, flow_id, seq",
    indexes=("idx_n n TYPE minmax GRANULARITY 1",),
    settings=BIG_BLOCKS,
)

PROXY_EVENTS = Table(
    "proxy_events",
    (
        C("scan_id", LC),
        C("ts", TS, TS_CODEC),
        C("kind", LC),
        C("severity", SEVERITY),
        C("session", LC),
        C("tool", LC),
        C("proxy_user", "String"),
        C("reason", LC),
        C("listener", LC),
        C("client_conn_id", "UUID"),
        C("client_ip", "IPv6"),
        C("host", LC),
        C("port", "UInt16"),
        C("sni", "String"),
        C("status", "UInt16"),
        C("flow_id", "UUID"),
        C("message", "String", BIG),
        C("counters", "Map(LowCardinality(String), Int64)"),
    ),
    order_by="kind, ts",
)

# Labels and notes on flows, written by people and agents through the API. Append-only: an edit or a delete is a
# new version of the same id; readers take each id's latest version (argMax by ts).
ANNOTATIONS = Table(
    "annotations",
    (
        C("scan_id", LC),
        C("id", "UUID"),
        C("ts", TS, TS_CODEC),
        C("flow_id", "UUID"),
        C("n", "UInt64"),
        C("session", LC),  # the flow's session: what a session token may see and annotate
        C("author", LC),
        C("author_kind", "Enum8('admin' = 1, 'session' = 2)"),
        C("label", LC),
        C("color", LC),
        C("note", "String", BIG),
        C("deleted", "Bool"),
    ),
    order_by="session, n, id, ts",
)

TABLES = {t.name: t for t in (HTTP_FLOWS, WS_MESSAGES, SSE_EVENTS, GRPC_MESSAGES, PROXY_EVENTS, ANNOTATIONS)}

# What the label:, note: and has:note filters read: each annotation's latest label, text and deleted flag.
NOTES_FILTER = (
    f"SELECT argMax(n, ts) AS n, argMax(label, ts) AS label, argMax(note, ts) AS note, argMax(deleted, ts) AS deleted "
    f"FROM {DB}.annotations GROUP BY id"
)

# Each annotation's latest version, deleted ones included (filter on `deleted`).
NOTES_LATEST = (
    f"SELECT toString(id) AS id, argMax(n, ts) AS n, toString(argMax(flow_id, ts)) AS flow_id, argMax(session, ts) AS session, "
    f"argMax(author, ts) AS author, "
    f"toString(argMax(author_kind, ts)) AS author_kind, argMax(label, ts) AS label, argMax(color, ts) AS color, "
    f"argMax(note, ts) AS note, argMax(deleted, ts) AS deleted, toUnixTimestamp64Milli(min(ts)) AS created, "
    f"toUnixTimestamp64Milli(max(ts)) AS updated FROM {DB}.annotations GROUP BY id"
)

# The failure vocabulary, as SQL and as the same predicate over a flow summary (live tail, UI, MCP):
#   ERROR  - something went wrong: a transport error, a 5xx, or a gRPC call that did not end OK  (has:error)
#   FAILED - ERROR or a 4xx: the request did not succeed                                          (has:fail, "failures")
ERROR = "(error != '' OR status >= 500 OR (grpc AND grpc_status > 0))"
FAILED = "(status >= 400 OR error != '' OR (grpc AND grpc_status > 0))"


def is_error(s: dict) -> bool:
    return bool(s.get("error")) or s.get("status", 0) >= 500 or (bool(s.get("grpc")) and s.get("grpc_status", -1) > 0)


def is_failed(s: dict) -> bool:
    return is_error(s) or s.get("status", 0) >= 400

SESSION_SUMMARY = f"""CREATE OR REPLACE VIEW {DB}.session_summary AS
SELECT session, tool, min(ts_start) AS first_seen, max(ts_end) AS last_seen, count() AS flows,
       countIf{FAILED} AS failures, uniqExact(host) AS hosts,
       sum(req_body_size) AS bytes_up, sum(resp_body_size) AS bytes_down,
       sum(ws_message_count) AS ws_messages, sum(sse_event_count) AS sse_events
FROM {DB}.http_flows GROUP BY session, tool"""


# Projections replaced by a newer definition (a projection cannot be altered in place).
RETIRED_PROJECTIONS = {"http_flows": ("by_n",)}


def statements(db: str = DB) -> list[str]:
    """Everything `ensure` runs, in order. Safe to run on every start."""
    out = [f"CREATE DATABASE IF NOT EXISTS {db}"]
    for t in TABLES.values():
        out.append(t.ddl(db))
        for c in t.columns:
            out.append(
                f"ALTER TABLE {db}.{t.name} ADD COLUMN IF NOT EXISTS {c.name} {c.type}" + (f" CODEC({c.codec})" if c.codec else "")
            )
        for p in t.projections:
            out.append(f"ALTER TABLE {db}.{t.name} ADD PROJECTION IF NOT EXISTS {p}")
        for old in RETIRED_PROJECTIONS.get(t.name, ()):
            out.append(f"ALTER TABLE {db}.{t.name} DROP PROJECTION IF EXISTS {old}")
        # The writer replays spool files with their id as insert_deduplication_token: a replay after a crash is a no-op.
        out.append(f"ALTER TABLE {db}.{t.name} MODIFY SETTING non_replicated_deduplication_window = 10000")
    out.append(SESSION_SUMMARY.replace(f"{DB}.", f"{db}."))
    return out


def quote(value: str) -> str:
    """A ClickHouse single-quoted string literal."""
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


def structure(table: Table) -> str:
    """The table's columns as a table-function structure argument ('name Type, ...')."""
    return ", ".join(f"{c.name} {c.type}" for c in table.columns)


def ensure(query, db: str = DB) -> None:
    """Create or upgrade the schema with `query(sql)`."""
    for sql in statements(db):
        query(sql)
