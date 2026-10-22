"""Push a finished scan to a central ClickHouse, straight from the chDB engine: no rows pass through Python.

    clickhouse://user@host:9000/db     native protocol, via remote()
    clickhouses://user@host:9440/db    native over TLS, via remoteSecure()
    http(s)://user@host:8123/db        HTTP interface, via url() with FORMAT Native (zstd)

The password comes from the URL or $M2C_PUSH_PASSWORD. Each table goes in chunks of `n` ranges. A chunk is skipped
when central holds the same rows (count and sum of key hashes), and only its missing rows go when central holds other
ones; each insert carries `insert_deduplication_token = <scan>:<table>:<range>:<rows>:<hashes>`, so a retried insert
never duplicates rows (central tables keep a deduplication window). Every chunk is checked again after its insert, and
the `scans` row records the result.
"""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from typing import TypeVar

from . import __version__, schema

log = logging.getLogger("m2c.push")

DEFAULT_PORTS = {"clickhouse": 9000, "clickhouses": 9440, "http": 8123, "https": 8443}
CHUNK_BYTES = 64 << 20
CENTRAL_ORDER = {
    "http_flows": ("toYYYYMM(ts_start)", "scan_id, session, ts_start, n"),
    "ws_messages": ("toYYYYMM(ts)", "scan_id, session, n, seq"),
    "sse_events": ("toYYYYMM(ts)", "scan_id, session, n, seq"),
    "grpc_messages": ("toYYYYMM(ts)", "scan_id, session, n, seq"),
    "proxy_events": ("toYYYYMM(ts)", "scan_id, kind, ts"),
    "annotations": ("toYYYYMM(ts)", "scan_id, session, n, id, ts"),
}
# Tables pushed whole (small): no chunks.
SMALL_TABLES = ("proxy_events", "annotations")
# What identifies a row, for the anti-join when a chunk is partly there already.
KEYS = {
    "http_flows": "flow_id",
    "sse_events": "flow_id, seq",
    "grpc_messages": "flow_id, seq",
    "ws_messages": "flow_id, seq",
    "proxy_events": "ts, kind, session, tool, proxy_user, client_conn_id, reason, host, message",
    "annotations": "id, ts",
}
# Approximate bytes of one row, for the chunk size.
SIZES = {
    "http_flows": "length(req_body) + length(resp_body) + 2048",
    "sse_events": "length(data) + 256",
    "grpc_messages": "length(data) + 256",
    "ws_messages": "length(content) + 256",
}
# ClickHouse errors that no retry fixes: bad SQL, unknown table/database/user, authentication, access.
PERMANENT = re.compile(r"\bCode: (47|60|62|81|192|194|497|516)\b")
SCANS_DDL = """CREATE TABLE IF NOT EXISTS {db}.scans
(
    scan_id LowCardinality(String),
    started_at DateTime64(3, 'UTC'),
    ended_at DateTime64(3, 'UTC'),
    host LowCardinality(String),
    m2c_version LowCardinality(String),
    labels Map(LowCardinality(String), String),
    rows Map(LowCardinality(String), UInt64),
    status LowCardinality(String),
    message String,
    pushed_at DateTime64(3, 'UTC')
)
ENGINE = {engine}
ORDER BY scan_id"""

T = TypeVar("T")


class PushError(Exception):
    pass


_q = schema.quote


@dataclass
class Target:
    scheme: str
    host: str
    port: int
    user: str
    password: str
    database: str
    insecure: bool = False

    @classmethod
    def parse(cls, url: str, password: str | None = None) -> Target:
        try:
            u = urllib.parse.urlsplit(url)
            port = u.port
        except ValueError as e:  # a bad port or IPv6 address; the message does not carry the URL (or its password)
            raise PushError(f"bad target URL: {e}") from None
        if u.scheme not in DEFAULT_PORTS:
            raise PushError(f"unsupported target {u.scheme!r}: use clickhouse://, clickhouses://, http:// or https://")
        if not u.hostname:
            raise PushError("the target URL needs a host")
        database = u.path.strip("/") or schema.DB
        if not database.replace("_", "").isalnum():
            raise PushError(f"bad database name {database!r}")
        pw = urllib.parse.unquote(u.password) if u.password else (password if password is not None else os.environ.get("M2C_PUSH_PASSWORD", ""))
        return cls(u.scheme, u.hostname, port or DEFAULT_PORTS[u.scheme], urllib.parse.unquote(u.username or "default"), pw, database)

    @property
    def native(self) -> bool:
        return self.scheme in ("clickhouse", "clickhouses")

    @property
    def address(self) -> str:
        """host:port, with an IPv6 host in brackets (urlsplit drops them)."""
        return f"[{self.host}]:{self.port}" if ":" in self.host else f"{self.host}:{self.port}"

    @property
    def redacted(self) -> str:
        return f"{self.scheme}://{self.user}@{self.address}/{self.database}"

    def scrub(self, text: str) -> str:
        return text.replace(self.password, "***") if self.password else text

    # ------------------------------------------------------------------ the remote table, as seen from chDB

    def table_function(self, table: str, structure: str, insert_query: str | None = None, token: str | None = None) -> str:
        if self.native:
            fn = "remoteSecure" if self.scheme == "clickhouses" else "remote"
            return f"{fn}({_q(self.address)}, {_q(self.database)}, {_q(table)}, {_q(self.user)}, {_q(self.password)})"
        query = insert_query or f"SELECT * FROM {self.database}.{table} FORMAT Native"
        params = {"query": query}
        if token:
            params["insert_deduplication_token"] = token
        url = f"{self.scheme}://{self.address}/?{urllib.parse.urlencode(params, quote_via=urllib.parse.quote)}"
        auth = f"'X-ClickHouse-User' = {_q(self.user)}, 'X-ClickHouse-Key' = {_q(self.password)}"
        if query.lstrip().upper().startswith("INSERT"):
            # Uploads are zstd-compressed; the server decodes them by Content-Encoding.
            return f"url({_q(url)}, 'Native', {_q(structure)}, 'zstd', headers({auth}, 'Content-Encoding' = 'zstd'))"
        return f"url({_q(url)}, 'Native', {_q(structure)}, headers({auth}))"

    # ------------------------------------------------------------------ HTTP: DDL and counts

    def http(self, sql: str, timeout: float = 60) -> bytes:
        if self.native:
            raise PushError("DDL needs the HTTP interface: pass an http(s):// URL to `m2c central init`")
        req = urllib.request.Request(f"{self.scheme}://{self.address}/", data=sql.encode(), method="POST")
        req.add_header("X-ClickHouse-User", self.user)
        req.add_header("X-ClickHouse-Key", self.password)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        try:
            with opener.open(req, timeout=timeout) as res:
                return res.read()
        except urllib.error.HTTPError as e:
            raise PushError(f"ClickHouse said {e.code}: {e.read().decode('utf-8', 'replace').strip()[:500]}") from None
        except urllib.error.URLError as e:
            raise PushError(f"cannot reach {self.redacted}: {e.reason}") from None


def scans_engine(engine: str) -> str:
    """The scans table follows the data tables: ReplicatedMergeTree(args) gives ReplicatedReplacingMergeTree(args, pushed_at)."""
    if "Replicated" not in engine:
        return "ReplacingMergeTree(pushed_at)"
    _, _, args = engine.partition("(")
    args = args.strip().removesuffix(")").strip()
    return f"ReplicatedReplacingMergeTree({args + ', ' if args else ''}pushed_at)"


def central_statements(db: str, engine: str = "MergeTree", ttl_days: int = 0, on_cluster: str = "") -> list[str]:
    cluster = f" ON CLUSTER {on_cluster}" if on_cluster else ""
    out = [f"CREATE DATABASE IF NOT EXISTS {db}{cluster}"]
    for name, t in schema.TABLES.items():
        partition, order = CENTRAL_ORDER[name]
        ddl = t.ddl(db, engine=engine, partition_by=partition, order_by=order, projections=False)
        ts_col = "ts_start" if name == "http_flows" else "ts"
        extra = []
        if "Replicated" not in engine:
            extra.append("non_replicated_deduplication_window = 10000")
        if ttl_days:
            ddl = ddl.replace("\nORDER BY", f"\nTTL toDateTime({ts_col}) + INTERVAL {int(ttl_days)} DAY\nORDER BY", 1)
            extra.append("ttl_only_drop_parts = 1")
        if extra:
            ddl += (", " if "\nSETTINGS " in ddl else "\nSETTINGS ") + ", ".join(extra)
        if cluster:
            ddl = ddl.replace(f"CREATE TABLE IF NOT EXISTS {db}.{name}", f"CREATE TABLE IF NOT EXISTS {db}.{name}{cluster}", 1)
        out.append(ddl)
        for c in t.columns:
            out.append(f"ALTER TABLE {db}.{name}{cluster} ADD COLUMN IF NOT EXISTS {c.name} {c.type}" + (f" CODEC({c.codec})" if c.codec else ""))
    out.append(SCANS_DDL.format(db=db, engine=scans_engine(engine)).replace(f"{db}.scans", f"{db}.scans{cluster}", 1))
    return out


def central_init(target: Target, engine: str = "MergeTree", ttl_days: int = 0, on_cluster: str = "") -> int:
    stmts = central_statements(target.database, engine, ttl_days, on_cluster)
    for sql in stmts:
        target.http(sql)
    return len(stmts)


class Pusher:
    """`run(sql, fmt) -> bytes` executes on a writable chDB session over the scan's data directory."""

    def __init__(self, run: Callable[[str, str], bytes], target: Target, chunk_bytes: int = CHUNK_BYTES, retries: int = 5,
                 progress: Callable[[str], None] | None = None):
        self.run = run
        self.target = target
        self.chunk_bytes = chunk_bytes
        self.retries = retries
        self.progress = progress or (lambda msg: log.info("%s", msg))

    def _local(self, sql: str) -> list[dict]:
        return [json.loads(line) for line in self.run(sql, "JSONEachRow").splitlines() if line.strip()]

    def _retry(self, what: str, fn: Callable[[], T]) -> T:
        """Every remote operation goes through here: retried with backoff, and a failure is a PushError without the password."""
        delay = 1.0
        for attempt in range(1, self.retries + 1):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001
                msg = self.target.scrub(str(e)).strip()
                if attempt == self.retries or PERMANENT.search(msg):
                    raise PushError(f"{what}: {msg[:600]}") from None
                self.progress(f"  {what}: attempt {attempt} failed, retrying in {delay:.0f}s: {msg[:200]}")
                time.sleep(delay)
                delay = min(delay * 2, 30)
        raise AssertionError("unreachable")

    def _chunks(self, table: str) -> list[tuple[str, str]]:
        """(where, label) of at most ~chunk_bytes each: whole n buckets of 1000, and a bucket that alone is bigger split
        on n, or on (n, seq) for sse/ws, whose rows all carry the n of their flow (one long stream is one n)."""
        buckets = self._local(f"SELECT intDiv(n, 1000) AS b, sum({SIZES[table]}) AS bytes FROM {schema.DB}.{table} GROUP BY b ORDER BY b")
        chunks, lo, last, acc = [], None, 0, 0
        for row in buckets:
            b, nbytes = int(row["b"]), int(row["bytes"])
            if lo is not None and (nbytes > self.chunk_bytes or acc + nbytes > self.chunk_bytes):
                chunks.append((f"n BETWEEN {lo * 1000} AND {b * 1000 - 1}", f"{lo * 1000}-{b * 1000 - 1}"))
                lo, acc = None, 0
            if nbytes > self.chunk_bytes:
                chunks += self._split(table, b)
                continue
            if lo is None:
                lo = b
            last, acc = b, acc + nbytes
        if lo is not None:
            chunks.append((f"n BETWEEN {lo * 1000} AND {(last + 1) * 1000 - 1}", f"{lo * 1000}-{(last + 1) * 1000 - 1}"))
        return chunks

    def _split(self, table: str, b: int) -> list[tuple[str, str]]:
        """Sub-ranges of one n bucket: on n for http_flows (one flow is a few MiB at most), on (n, seq/100) for sse/ws,
        and on (n, seq) inside a group of 100 messages that alone is bigger (raised message caps)."""
        fine = "n AS n, 0 AS s" if table == "http_flows" else "n AS n, intDiv(seq, 100) AS s"
        groups = self._local(
            f"SELECT {fine}, sum({SIZES[table]}) AS bytes FROM {schema.DB}.{table} WHERE intDiv(n, 1000) = {b} GROUP BY n, s ORDER BY n, s"
        )
        # Units of (n, first seq, last seq, bytes); seq is unused for http_flows.
        units = []
        for row in groups:
            n, s, nbytes = int(row["n"]), int(row["s"]), int(row["bytes"])
            if table == "http_flows" or nbytes <= self.chunk_bytes:
                units.append((n, s * 100, s * 100 + 99, nbytes))
                continue
            units += [(n, int(r["seq"]), int(r["seq"]), int(r["bytes"])) for r in self._local(
                f"SELECT seq, sum({SIZES[table]}) AS bytes FROM {schema.DB}.{table} "
                f"WHERE n = {n} AND seq BETWEEN {s * 100} AND {s * 100 + 99} GROUP BY seq ORDER BY seq"
            )]
        out, start, end, acc = [], None, None, 0

        def close():
            if table == "http_flows":
                out.append((f"n BETWEEN {start[0]} AND {end[0]}", f"{start[0]}-{end[0]}"))
            else:
                lo, hi = (start[0], start[1]), (end[0], end[2])
                out.append((f"(n, seq) >= ({lo[0]}, {lo[1]}) AND (n, seq) <= ({hi[0]}, {hi[1]})", f"{lo[0]}.{lo[1]}-{hi[0]}.{hi[1]}"))

        for key in units:
            nbytes = key[3]
            if start is not None and acc + nbytes > self.chunk_bytes:
                close()
                start, acc = None, 0
            if start is None:
                start = key
            end, acc = key, acc + nbytes
        if start is not None:
            close()
        return out

    def _remote(self, table: str, where: str, select: str, structure: str) -> str:
        """A chDB table expression reading `select` from the central table (for counts and anti-joins)."""
        if self.target.native:
            return f"(SELECT {select} FROM {self.target.table_function(table, '')} WHERE {where})"
        sql = f"SELECT {select} FROM {self.target.database}.{table} WHERE {where} FORMAT Native"
        return self.target.table_function(table, structure, sql)

    def _remote_rows(self, table: str, select: str, rest: str, what: str) -> list[dict]:
        """`SELECT <select> FROM <the central table> <rest>`, run on central."""
        def go() -> list[dict]:
            if self.target.native:
                raw = self.run(f"SELECT {select} FROM {self.target.table_function(table, '')} {rest}", "JSONEachRow")
            else:
                raw = self.target.http(f"SELECT {select} FROM {self.target.database}.{table} {rest} FORMAT JSONEachRow")
            return [json.loads(line) for line in raw.decode().splitlines() if line.strip()]
        return self._retry(what, go)

    def _remote_count(self, table: str, where: str) -> int:
        rows = self._remote_rows(table, "count() AS c", f"WHERE {where}", f"{table} count")
        return int(rows[0]["c"]) if rows else 0

    def _local_stats(self, table: str, where: str) -> tuple[int, str]:
        row = self._retry(f"{table} {where}", lambda: self._local(
            f"SELECT count() AS c, toString(sum(cityHash64({KEYS[table]}))) AS h FROM {schema.DB}.{table} WHERE {where}"
        ))[0]
        return int(row["c"]), str(row["h"])

    def _remote_stats(self, table: str, where: str) -> tuple[int, str]:
        rows = self._remote_rows(table, f"count() AS c, toString(sum(cityHash64({KEYS[table]}))) AS h", f"WHERE {where}", f"{table} count")
        return (int(rows[0]["c"]), str(rows[0]["h"])) if rows else (0, "0")

    def _missing(self, table: str, where: str, remote_where: str, local: tuple[int, str]) -> tuple[str, int, str, int]:
        """(where, count, hash sum) of the local rows of `where` that central lacks, and central's row count there.

        Equal count and key-hash sum: central holds exactly these rows. Otherwise it holds some of them, or other rows
        under the same scan id and n (another data directory recorded with the same scan id): anti-join on the key."""
        have = self._remote_stats(table, remote_where)
        if have == local:
            return where, 0, "0", have[0]
        if not have[0]:
            return where, local[0], local[1], 0
        key = KEYS[table]
        remote_keys = self._remote(table, remote_where, f"cityHash64({key}) AS k", "k UInt64")
        where = f"{where} AND cityHash64({key}) NOT IN (SELECT k FROM {remote_keys})"
        c, h = self._local_stats(table, where)
        return where, c, h, have[0]

    def _insert(self, table: str, where: str, token: str) -> None:
        t = schema.TABLES[table]
        cols = ", ".join(t.names)
        structure = ", ".join(f"{c.name} {c.type}" for c in t.columns)
        insert_query = f"INSERT INTO {self.target.database}.{table} ({cols}) FORMAT Native"
        fn = self.target.table_function(table, structure, insert_query, token)
        settings = f" SETTINGS insert_deduplication_token = {_q(token)}" if self.target.native else ""
        sql = f"INSERT INTO FUNCTION {fn} ({cols}) SELECT {cols} FROM {schema.DB}.{table} WHERE {where}{settings}"
        self._retry(f"{table} {where}", lambda: self.run(sql, "TSV"))

    def _push_range(self, table: str, scan_ids: str, where: str, label: str) -> tuple[int, int, str]:
        """Insert the local rows of `where` that central lacks, then check again. Returns (rows sent, rows still missing, note)."""
        local = self._local_stats(table, where)
        if not local[0]:
            return 0, 0, ""
        remote_where = f"scan_id IN ({scan_ids}) AND {where}"
        todo, count, hashes, before = self._missing(table, where, remote_where, local)
        if not count:
            return 0, 0, ""
        self._insert(table, todo, f"{label}:{count}:{hashes}")
        todo, left, hashes, after = self._missing(table, where, remote_where, local)
        # `before` may include rows of another data directory with the same scan id: only "nothing arrived" counts.
        for delay in (1, 2, 4):
            if not left or after != before:
                break
            # Nothing arrived. A replica may lag; otherwise the server dropped the insert as a duplicate of an earlier
            # push with the same token, and the rows were deleted centrally since.
            time.sleep(delay)
            todo, left, hashes, after = self._missing(table, where, remote_where, local)
        if left and after == before:
            resend = left
            self._insert(table, todo, f"{label}:{left}:{hashes}:{time.time_ns()}")
            _, left, _, _ = self._missing(table, where, remote_where, local)
            return resend - left, left, "deduplicated by the server (rows deleted centrally since an earlier push?), sent again with a fresh token"
        return count - left, left, ""

    def remote_counts(self, scan_ids: list[str]) -> dict[str, int]:
        ids = ", ".join(_q(s) for s in scan_ids)
        return {table: self._remote_count(table, f"scan_id IN ({ids})") for table in schema.TABLES}

    def _scans_row(self, meta: dict, rows: dict, status: str, message: str = "", retry: bool = True) -> None:
        values = {
            "scan_id": meta["scan_id"],
            "started_at": meta["started_at"],
            "ended_at": meta["ended_at"],
            "host": meta["host"],
            "m2c_version": __version__,
            "labels": meta["labels"],
            "rows": rows,
            "status": status,
            "message": message,
            "pushed_at": int(time.time() * 1000),
        }
        cols = ", ".join(values)
        structure = (
            "scan_id String, started_at DateTime64(3, 'UTC'), ended_at DateTime64(3, 'UTC'), host String, m2c_version String, "
            "labels Map(String, String), rows Map(String, UInt64), status String, message String, pushed_at DateTime64(3, 'UTC')"
        )
        select = (
            f"SELECT {_q(values['scan_id'])}, fromUnixTimestamp64Milli(toInt64({int(values['started_at'])})), "
            f"fromUnixTimestamp64Milli(toInt64({int(values['ended_at'])})), {_q(values['host'])}, {_q(__version__)}, "
            f"map({', '.join(f'{_q(k)}, {_q(v)}' for k, v in values['labels'].items())}), "
            f"map({', '.join(f'{_q(k)}, toUInt64({int(v)})' for k, v in rows.items())}), {_q(status)}, {_q(message)}, "
            f"fromUnixTimestamp64Milli(toInt64({values['pushed_at']}))"
        )
        insert_query = f"INSERT INTO {self.target.database}.scans ({cols}) FORMAT Native"
        fn = self.target.table_function("scans", structure, insert_query)
        sql = f"INSERT INTO FUNCTION {fn} ({cols}) {select}"
        if retry:
            self._retry(f"scans row ({status})", lambda: self.run(sql, "TSV"))
        else:
            self.run(sql, "TSV")

    def meta(self, labels: dict[str, str]) -> dict:
        row = self._local(
            f"SELECT groupUniqArray(scan_id) AS ids, toUnixTimestamp64Milli(min(ts_start)) AS started FROM {schema.DB}.http_flows"
        )[0]
        started = self._local(
            f"SELECT any(scan_id) AS scan_id, any(message) AS message, toUnixTimestamp64Milli(min(ts)) AS ts "
            f"FROM {schema.DB}.proxy_events WHERE kind = 'started'"
        )[0]
        # The last thing recorded in any table (the 'stopped' event, usually); an empty table gives 0.
        ended = self._local(
            "SELECT greatest(" + ", ".join(
                f"(SELECT toUnixTimestamp64Milli(max({col})) FROM {schema.DB}.{table})"
                for table, col in (("http_flows", "ts_end"), ("proxy_events", "ts"), ("ws_messages", "ts"), ("sse_events", "ts"),
                                   ("grpc_messages", "ts"))
            ) + ") AS ts"
        )[0]
        try:
            host = json.loads(started["message"] or "{}").get("host", "")
        except ValueError:
            host = ""
        ids = sorted(set(row["ids"]) | ({started["scan_id"]} if started["scan_id"] else set()))
        if not ids:
            raise PushError("this data directory has no scan rows")
        return {
            "scan_ids": ids,
            "scan_id": ids[0] if len(ids) == 1 else ",".join(ids),
            "started_at": int(started["ts"] or row["started"] or 0),
            "ended_at": int(ended["ts"] or 0),
            "host": host or socket.gethostname(),
            "labels": labels,
        }

    def _remote_scan(self, scan_id: str) -> dict:
        """The scan's latest central scans row (labels, started_at, ended_at), or {} when there is none."""
        select = "labels, toUnixTimestamp64Milli(started_at) AS started_at, toUnixTimestamp64Milli(ended_at) AS ended_at"
        try:
            rows = self._remote_rows("scans", select, f"FINAL WHERE scan_id = {_q(scan_id)} ORDER BY pushed_at DESC LIMIT 1", "scans row")
        except PushError as e:
            if re.search(r"\bCode: (60|81)\b", str(e)):  # no scans table yet: nothing to keep
                return {}
            raise
        return rows[0] if rows else {}

    def push(self, labels: dict[str, str] | None = None) -> dict:
        meta = self.meta(labels or {})
        prev = self._remote_scan(meta["scan_id"])
        meta["labels"] = {**prev.get("labels", {}), **meta["labels"]}
        # Several data directories may share a scan id (one CI pipeline): the scans row spans all of them.
        if int(prev.get("started_at") or 0):
            meta["started_at"] = min(x for x in (meta["started_at"], int(prev["started_at"])) if x)
        meta["ended_at"] = max(meta["ended_at"], int(prev.get("ended_at") or 0))
        local = {t: int(self._local(f"SELECT count() AS c FROM {schema.DB}.{t}")[0]["c"]) for t in schema.TABLES}
        self.progress(f"pushing scan {meta['scan_id']} to {self.target.redacted}: " + ", ".join(f"{t} {n}" for t, n in local.items()))
        try:
            self._scans_row(meta, local, "pushing")
            ids = ", ".join(_q(s) for s in meta["scan_ids"])
            left = dict.fromkeys(local, 0)
            for table in ("http_flows", "sse_events", "ws_messages", "grpc_messages"):
                for where, label in self._chunks(table):
                    sent, gap, note = self._push_range(table, ids, where, f"{meta['scan_id']}:{table}:{label}")
                    left[table] += gap
                    msg = f"{sent} rows sent" if sent else "already there"
                    self.progress(f"  {table} {label}: {msg}" + (f" ({note})" if note else "") + (f", {gap} still missing" if gap else ""))
            for table in SMALL_TABLES:
                sent, gap, note = self._push_range(table, ids, "1", f"{meta['scan_id']}:{table}")
                left[table] += gap
                self.progress(f"  {table}: {sent} rows sent" + (f" ({note})" if note else "") + (f", {gap} still missing" if gap else ""))
            remote = self.remote_counts(meta["scan_ids"])
        except BaseException as e:  # Ctrl-C too: the row must not stay 'pushing'
            try:
                self._scans_row(meta, local, "failed", self.target.scrub(str(e) or type(e).__name__)[:1000], retry=False)
            except Exception as e2:  # noqa: BLE001 - best effort: central is likely what failed
                log.debug("m2c: could not record the failed push: %s", self.target.scrub(str(e2))[:300])
            raise
        missing = {t: n for t in local if (n := max(left[t], local[t] - remote.get(t, 0))) > 0}
        status = "pushed" if not missing else "incomplete"
        message = "" if not missing else "missing rows: " + json.dumps(missing)
        self._scans_row(meta, remote, status, message)
        self.progress(f"{status}: " + ", ".join(f"{t} {remote.get(t, 0)}/{local[t]}" for t in local))
        if missing:
            raise PushError(f"central lacks rows of the scan: {missing}")
        return {"scan_id": meta["scan_id"], "target": self.target.redacted, "local": local, "remote": remote, "status": status}
