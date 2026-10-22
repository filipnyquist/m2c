"""The filter language shared by the CLI, the API (`q=`), MCP and the web UI, compiled to parameterized SQL.

    session:abc tool:nuclei call:c7 tag:x host:*.acme.test method:POST|PUT status:5xx|404 status:>=400
    path:/api/* ct:json ua:curl has:sse|ws|grpc|error|fail|body err:timeout after:10m before:2026-10-21T12:00 n:100-200
    grpc:demo.v1.Demo/* gstatus:!0|INVALID_ARGUMENT|14 scheme:http dur:>2s size:>1m hdr:authorization
    rhdr:set-cookie body:"needle" -status:404 -(tool:ffuf status:404) "free text"

Terms are ANDed; `|` ORs values inside one term; a leading `-` negates a term, and `-( ... )` negates a group of
terms (all of them together). Free text matches the URL. Values never reach the SQL text: every one becomes a
`{pN:Type}` parameter.

`parse` keeps every term's position in the query, so the web UI's tokenizer (ui/lib/query.js) is tested against the
same cases (tests/fixtures/queries.json).
"""

from __future__ import annotations

import operator
import re
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import schema
from .grpc import CODES

STATUS_CLASS = re.compile(r"^([1-5])xx$", re.I)
STATUS_CMP = re.compile(r"^(>=|<=|>|<|=)?(\d{3})$")
DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smhd])$")
N_RANGE = re.compile(r"^([0-9]{1,20})(?:-([0-9]{1,20}))?$")  # ASCII digits: "²".isdigit() is True, int("²") raises
U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
CMP = re.compile(r"^(>=|<=|>|<|=)?(\d+(?:\.\d+)?)([a-z]*)$", re.I)
DUR_UNITS = {"": 1, "ms": 1, "s": 1000, "m": 60_000, "h": 3_600_000}
SIZE_UNITS = {"": 1, "b": 1, "k": 1 << 10, "kb": 1 << 10, "m": 1 << 20, "mb": 1 << 20, "g": 1 << 30, "gb": 1 << 30}
OPS = {"=": operator.eq, ">": operator.gt, "<": operator.lt, ">=": operator.ge, "<=": operator.le}
SINGLE = ("body", "after", "before", "url", "err", "note")  # values that may contain `|`: not split into alternatives

# has:<value> -> (SQL condition, predicate over a flow summary or None when only the database can tell, help)
HAS = {
    "error": (schema.ERROR, schema.is_error, "a transport error, a 5xx, or a gRPC call that did not end OK"),
    "fail": (schema.FAILED, schema.is_failed, "has:error or a 4xx: the request did not succeed"),
    "sse": ("resp_capture = 'sse'", lambda s: s.get("resp_capture") == "sse", "a Server-Sent Events stream"),
    "ws": ("resp_capture = 'websocket'", lambda s: s.get("resp_capture") == "websocket", "a WebSocket"),
    "grpc": ("grpc", lambda s: bool(s.get("grpc")), "a gRPC call"),
    "body": ("(req_body_size > 0 OR resp_body_size > 0)", lambda s: s.get("req_body_size", 0) > 0 or s.get("resp_body_size", 0) > 0,
             "a request or response body"),
    "reqbody": ("req_body_size > 0", lambda s: s.get("req_body_size", 0) > 0, "a request body"),
    "truncated": ("(req_body_truncated OR resp_body_truncated)", None, "a body cut at m2c_body_cap"),
    "replay": ("is_replay", None, "sent by the proxy itself (the repeater, or mitmproxy's replay)"),
    "note": ("n IN (SELECT n FROM (" + schema.NOTES_FILTER + ") WHERE NOT deleted)", None, "a label or note (see label: and note:)"),
}

# The filter language as data: CLI help, MCP tool descriptions, GET /v1/filter-help and the UI autocomplete all
# come from it. `live`: the live tail can evaluate it in memory; otherwise it needs the database.
SPEC = (
    {"key": "session", "example": "session:run42", "help": "agent session (globs: run*)", "live": True, "kind": "glob", "facet": "session"},
    {"key": "tool", "example": "tool:nuclei|ffuf", "help": "tool from the proxy username or x-m2c-tool", "live": True, "kind": "glob",
     "facet": "tool"},
    {"key": "call", "example": "call:toolu_01ab", "help": "call id (the third part of the username, or x-m2c-call)", "live": True,
     "kind": "glob", "facet": "call_id"},
    {"key": "tag", "example": "tag:phase-1", "help": "x-m2c-tag", "live": True, "kind": "glob", "facet": "tag"},
    {"key": "host", "example": "host:*.acme.test", "help": "host (globs)", "live": True, "kind": "glob", "facet": "host"},
    {"key": "method", "example": "method:POST|PUT", "help": "HTTP method", "live": True, "kind": "enum", "facet": "method",
     "values": ("GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS")},
    {"key": "status", "example": "status:5xx|404|>=400", "help": "HTTP status: code, class or comparison; 0 = none", "live": True,
     "kind": "status", "facet": "status", "values": ("2xx", "3xx", "4xx", "5xx", ">=400", "0")},
    {"key": "path", "example": "path:/api/*", "help": "path prefix (globs)", "live": True, "kind": "path", "facet": "path"},
    {"key": "url", "example": "url:token=", "help": "text in the URL", "live": True, "kind": "text"},
    {"key": "scheme", "example": "scheme:http", "help": "http, https, ws or wss", "live": True, "kind": "enum", "facet": "scheme",
     "values": ("http", "https")},
    {"key": "ct", "example": "ct:json", "help": "text in the response content type", "live": True, "kind": "text",
     "facet": "splitByChar(';', resp_content_type)[1]"},
    {"key": "ua", "example": "ua:curl", "help": "tool guessed from the User-Agent", "live": True, "kind": "glob", "facet": "ua_tool"},
    {"key": "has", "example": "has:" + "|".join(HAS), "help": "; ".join(f"{k}: {v[2]}" for k, v in HAS.items()), "live": True,
     "kind": "enum", "values": tuple(HAS)},
    {"key": "err", "example": "err:timeout", "help": "text in the error, or an error kind; err: alone = any transport error", "live": True,
     "kind": "text", "facet": "error_kind"},
    {"key": "dur", "example": "dur:>2s", "help": "duration: >2s, <100ms, >=1m (a bare value means at least)", "live": True,
     "kind": "number", "values": (">100ms", ">1s", ">5s", ">30s")},
    {"key": "size", "example": "size:>1m", "help": "response body size on the wire: >10k, <1m (a bare value means at least)", "live": True,
     "kind": "number", "values": (">10k", ">100k", ">1m")},
    {"key": "after", "example": "after:10m", "help": "started after: 30s, 10m, 2h, 1d or an ISO time", "live": True, "kind": "time",
     "values": ("5m", "15m", "1h", "1d")},
    {"key": "before", "example": "before:2026-10-21T12:00", "help": "started before (as after:)", "live": True, "kind": "time",
     "values": ("5m", "15m", "1h", "1d")},
    {"key": "n", "example": "n:100-200", "help": "flow number or range", "live": True, "kind": "number"},
    {"key": "grpc", "example": "grpc:demo.v1.Demo/*", "help": "gRPC service/method (globs)", "live": True, "kind": "glob",
     "facet": "if(grpc, concat(grpc_service, '/', grpc_method), '')"},
    {"key": "gstatus", "example": "gstatus:!0|INVALID_ARGUMENT|14", "help": "gRPC status: code, name, !0 (not OK) or none", "live": True,
     "kind": "enum", "values": ("!0", "none", *CODES)},
    {"key": "hdr", "example": "hdr:authorization", "help": "a request header by name (globs), or name=value (globs: x-key=*abc*)",
     "live": False, "kind": "header", "facet": "arrayJoin(arrayMap(h -> lower(h.name), req_headers))"},
    {"key": "rhdr", "example": "rhdr:set-cookie", "help": "a response header (as hdr:)", "live": False, "kind": "header",
     "facet": "arrayJoin(arrayMap(h -> lower(h.name), resp_headers))"},
    {"key": "label", "example": "label:vuln|todo", "help": "a label on the flow (globs)", "live": False, "kind": "glob", "facet": "label"},
    {"key": "note", "example": 'note:"token reuse"', "help": "text in a note on the flow", "live": False, "kind": "text"},
    {"key": "body", "example": 'body:"needle"', "help": "text in the request or response body (case-sensitive)", "live": False, "kind": "text"},
    {"key": "source", "example": "source:connect", "help": "how the identity was found: connect, request, socks5, header", "live": False,
     "kind": "enum", "facet": "toString(identity_source)"},
)
BY_KEY = {s["key"]: s for s in SPEC}
KEYS = {s["key"] for s in SPEC}


def heavy(q: str | None) -> bool:
    """Whether a filter scans bodies: such queries go to the heavy reader lane, so they never slow lists down."""
    return "body:" in (q or "").lower()


def help_text() -> str:
    """One paragraph for tool descriptions and --help."""
    return ("Filter syntax: terms are ANDed, `|` ORs values in one term, a leading `-` negates a term, -( ... ) negates "
            "a group of terms together, free text matches the URL. "
            + " ".join(f"{s['example']} ({s['help']})" for s in SPEC) + ".")


class FilterError(ValueError):
    pass


def _grpc_code(value: str) -> int | None:
    """A gRPC status by number or name ('3', 'INVALID_ARGUMENT', 'invalid_argument'); None for 'ok'/'err' forms."""
    if value.isdigit() and value.isascii():
        code = int(value)
        if code > 255:
            raise FilterError(f"bad gRPC status {value!r}")
        return code
    if value.upper() in CODES:
        return CODES[value.upper()]
    raise FilterError(f"gstatus: takes a code (3), a name (INVALID_ARGUMENT), !0 or none")


# ---------------------------------------------------------------------------- parsing


@dataclass
class Term:
    neg: bool
    key: str | None  # None: free text, matched against the URL
    values: list[str]
    start: int  # the term's span in the query, quotes and the leading `-` included
    end: int


@dataclass
class Group:
    neg: bool
    items: list = field(default_factory=list)
    start: int = 0
    end: int = 0


def _lex(q: str) -> list[tuple[str, str, int, int]]:
    """(kind, text, start, end) with kind 'open' (text '-' when negated), 'close' or 'word'. Quotes and backslashes
    work as in a POSIX shell (shlex): `body:"two words"` is one word. `(` opens a group at the start of a word,
    `)` closes one at the end of a word, and both are literal anywhere else or inside quotes."""
    out, i, n, depth = [], 0, len(q), 0
    while i < n:
        if q[i].isspace():
            i += 1
            continue
        start = i
        j = i + 1 if q[i] == "-" else i
        if j < n and q[j] == "(":
            out.append(("open", "-" if j > i else "", start, j + 1))
            depth += 1
            i = j + 1
            continue
        if q[i] == ")" and depth:
            out.append(("close", "", i, i + 1))
            depth -= 1
            i += 1
            continue
        buf, quote = [], None
        while i < n:
            c = q[i]
            if quote == "'":
                if c == "'":
                    quote = None
                else:
                    buf.append(c)
            elif quote == '"':
                if c == '"':
                    quote = None
                elif c == "\\" and i + 1 < n and q[i + 1] in '"\\':
                    i += 1
                    buf.append(q[i])
                else:
                    buf.append(c)
            elif c.isspace() or (c == ")" and depth):
                break
            elif c in "'\"":
                quote = c
            elif c == "\\" and i + 1 < n:
                i += 1
                buf.append(q[i])
            else:
                buf.append(c)
            i += 1
        if quote:
            raise FilterError("bad quoting: No closing quotation")
        out.append(("word", "".join(buf), start, i))
    return out


def _word(text: str, start: int, end: int) -> Term:
    neg = text.startswith("-") and ":" in text
    body = text[1:] if neg else text
    key, sep, value = body.partition(":")
    if sep and key.lower() in KEYS:
        key = key.lower()
        values = value.split("|") if key not in SINGLE else [value]
        if not values or (values == [""] and key != "err"):
            raise FilterError(f"{key}: needs a value")
        return Term(neg, key, values, start, end)
    return Term(neg, None, [body], start, end)


def parse(q: str | None) -> list:
    """The query as a list of Term and Group nodes; FilterError for bad quoting or brackets."""
    toks = _lex(q or "")
    pos = 0

    def items(depth: int) -> list:
        nonlocal pos
        out = []
        while pos < len(toks):
            kind, text, start, end = toks[pos]
            if kind == "close":
                return out
            pos += 1
            if kind == "word":
                out.append(_word(text, start, end))
                continue
            inner = items(depth + 1)
            if pos >= len(toks):
                raise FilterError("unclosed (")
            if not inner:
                raise FilterError("empty ( )")
            out.append(Group(text == "-", inner, start, toks[pos][3]))
            pos += 1
        return out

    return items(0)


def terms(nodes) -> list[Term]:
    """Every term, also those inside groups."""
    out = []
    for node in nodes:
        out += terms(node.items) if isinstance(node, Group) else [node]
    return out


def _cmp(value: str, units: dict, key: str, hi: int) -> tuple[str, int]:
    """(operator, number in base units) for dur:/size: values; a bare value means at least."""
    m = CMP.match(value)
    unit = (m.group(3) or "").lower() if m else ""
    if not m or unit not in units:
        raise FilterError(f"bad {key}: {value[:40]!r}: use " + ("2s, >100ms, <1m" if key == "dur" else "10k, >1m, <512"))
    number = int(float(m.group(2)) * units[unit])
    if number > hi:
        raise FilterError(f"bad {key}: {value[:40]!r}: out of range")
    return m.group(1) or ">=", number


def _header(c: "Compiler", column: str, value: str) -> str:
    name, sep, want = value.partition("=")
    if not name:
        raise FilterError("hdr: takes a header name, or name=value")
    cond = _glob(c, "lower(h.name)", name.lower())
    if sep:
        cond += " AND " + _glob(c, "h.value", want)
    return f"arrayExists(h -> {cond}, {column})"


class Compiler:
    def __init__(self):
        self.params: dict[str, object] = {}

    def p(self, value, type_: str = "String") -> str:
        name = f"p{len(self.params)}"
        self.params[name] = value
        return f"{{{name}:{type_}}}"


def _glob(c: Compiler, column: str, value: str) -> str:
    if "*" in value or "?" in value:
        like = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%").replace("?", "_")
        return f"{column} ILIKE {c.p(like)}"
    return f"{column} = {c.p(value)}"


def _time(value: str) -> int:
    m = DURATION.match(value)
    try:
        if m:
            ms = (time.time() - float(m.group(1)) * UNITS[m.group(2)]) * 1000
        else:
            dt = datetime.fromisoformat(value)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            ms = dt.timestamp() * 1000
        ms = int(ms)  # OverflowError for 1e400d
    except (ValueError, OverflowError):
        raise FilterError(f"bad time {value[:40]!r}: use 10m, 2h, 1d or an ISO date") from None
    if abs(ms) > I64_MAX:  # chDB wraps an out-of-range Int64 parameter instead of rejecting it
        raise FilterError(f"bad time {value[:40]!r}: out of range")
    return ms


def _n_range(value: str) -> tuple[int, int]:
    m = N_RANGE.match(value)
    if not m or int(m.group(1)) > U64_MAX or int(m.group(2) or 0) > U64_MAX:  # UInt64 wraps in chDB, too
        raise FilterError("n: takes 42 or 100-200")
    lo = int(m.group(1))
    return lo, int(m.group(2)) if m.group(2) else lo


def _status(c: Compiler, value: str) -> str:
    m = STATUS_CLASS.match(value)
    if m:
        lo = int(m.group(1)) * 100
        return f"(status >= {c.p(lo, 'UInt16')} AND status < {c.p(lo + 100, 'UInt16')})"
    m = STATUS_CMP.match(value)
    if m:
        return f"status {m.group(1) or '='} {c.p(int(m.group(2)), 'UInt16')}"
    if value in ("0", "none"):
        return "status = 0"
    raise FilterError(f"bad status {value!r}: use 404, 5xx or >=400")


def _term(c: Compiler, key: str, value: str) -> str:
    if key == "session":
        return _glob(c, "session", value)
    if key == "tool":
        return _glob(c, "tool", value.lower())
    if key == "call":
        return _glob(c, "call_id", value)
    if key == "tag":
        return _glob(c, "tag", value)
    if key == "host":
        return _glob(c, "host", value.lower())
    if key == "method":
        return f"method = {c.p(value.upper())}"
    if key == "status":
        return _status(c, value)
    if key == "path":
        return _glob(c, "path", value if "*" in value else value + "*")
    if key == "url":
        return _glob(c, "url", value if "*" in value else f"*{value}*")
    if key == "ct":
        return f"positionCaseInsensitive(resp_content_type, {c.p(value)}) > 0"
    if key == "ua":
        return _glob(c, "ua_tool", value.lower())
    if key == "source":
        return f"toString(identity_source) = {c.p(value)}"
    if key == "scheme":
        return f"scheme = {c.p(value.lower())}"
    if key == "dur":
        op, ms = _cmp(value, DUR_UNITS, "dur", (1 << 32) - 1)
        return f"duration_ms {op} {c.p(ms, 'UInt32')}"
    if key == "size":
        op, size = _cmp(value, SIZE_UNITS, "size", U64_MAX)
        return f"resp_body_size {op} {c.p(size, 'UInt64')}"
    if key in ("hdr", "rhdr"):
        return _header(c, "req_headers" if key == "hdr" else "resp_headers", value)
    if key in ("label", "note"):
        cond = _glob(c, "label", value.lower()) if key == "label" else f"positionCaseInsensitive(note, {c.p(value)}) > 0"
        return f"n IN (SELECT n FROM ({schema.NOTES_FILTER}) WHERE NOT deleted AND {cond})"
    if key == "has":
        if value not in HAS:
            raise FilterError(f"has: takes {', '.join(HAS)}")
        return HAS[value][0]
    if key == "err":
        return "error != ''" if value in ("", "*") else f"(positionCaseInsensitive(error, {c.p(value)}) > 0 OR error_kind = {c.p(value)})"
    if key == "after":
        return f"ts_start >= fromUnixTimestamp64Milli({c.p(_time(value), 'Int64')})"
    if key == "before":
        return f"ts_start < fromUnixTimestamp64Milli({c.p(_time(value), 'Int64')})"
    if key == "n":
        lo, hi = _n_range(value)
        if lo == hi:
            return f"n = {c.p(lo, 'UInt64')}"
        return f"n BETWEEN {c.p(lo, 'UInt64')} AND {c.p(hi, 'UInt64')}"
    if key == "body":
        needle = c.p(value)
        return f"(position(req_body, {needle}) > 0 OR position(resp_body, {needle}) > 0)"
    if key == "grpc":
        target = value if "/" in value else (value + "/*" if value else "*")
        return f"(grpc AND " + _glob(c, "concat(grpc_service, '/', grpc_method)", target) + ")"
    if key == "gstatus":
        if value in ("!0", "err", "error"):
            return "(grpc AND grpc_status > 0)"
        if value == "none":
            return "(grpc AND grpc_status = -1)"
        return f"(grpc AND grpc_status = {c.p(_grpc_code(value), 'Int16')})"
    raise FilterError(f"unknown filter {key}:")


def _sql(c: Compiler, node) -> str:
    if isinstance(node, Group):
        cond = "(" + " AND ".join(_sql(c, x) for x in node.items) + ")"
    elif node.key is None:
        cond = f"positionCaseInsensitive(url, {c.p(node.values[0])}) > 0"
    else:
        cond = " OR ".join(_term(c, node.key, v) for v in node.values)
        cond = f"({cond})" if len(node.values) > 1 else cond
    return f"NOT ({cond})" if node.neg else cond


def compile_filter(q: str | None, scope: str | None = None) -> tuple[str, dict]:
    """(WHERE clause without the keyword, params). `scope` pins one session (session-scoped tokens)."""
    c = Compiler()
    parts: list[str] = []
    if scope is not None:
        parts.append(f"session = {c.p(scope)}")
    parts += [_sql(c, node) for node in parse(q)]
    return (" AND ".join(parts) or "1"), c.params


# ---------------------------------------------------------------------------- in-memory matching (live tail)


def _glob_re(value: str) -> re.Pattern:
    if "*" in value or "?" in value:
        return re.compile("^" + re.escape(value).replace(r"\*", ".*").replace(r"\?", ".") + "$", re.I | re.S)
    return re.compile("^" + re.escape(value) + "$", re.S)


def _py_status(value: str):
    m = STATUS_CLASS.match(value)
    if m:
        lo = int(m.group(1)) * 100
        return lambda s: lo <= s.get("status", 0) < lo + 100
    m = STATUS_CMP.match(value)
    if m:
        op, num = m.group(1) or "=", int(m.group(2))
        ops = {"=": num.__eq__, ">": num.__lt__, "<": num.__gt__, ">=": num.__le__, "<=": num.__ge__}
        return lambda s: ops[op](s.get("status", 0))
    if value in ("0", "none"):
        return lambda s: not s.get("status")
    raise FilterError(f"bad status {value!r}")


def _py_term(key: str, value: str):
    field_globs = {"session": "session", "tool": "tool", "call": "call_id", "tag": "tag", "host": "host", "ua": "ua_tool"}
    if key in field_globs:
        rx = _glob_re(value.lower() if key in ("tool", "host", "ua") else value)
        col = field_globs[key]
        return lambda s: bool(rx.match(str(s.get(col, ""))))
    if key == "method":
        return lambda s: s.get("method", "") == value.upper()
    if key == "status":
        return _py_status(value)
    if key == "path":
        rx = _glob_re(value if "*" in value else value + "*")
        return lambda s: bool(rx.match(s.get("path", "")))
    if key == "url":
        rx = _glob_re(value if "*" in value else f"*{value}*")
        return lambda s: bool(rx.match(s.get("url", "")))
    if key == "ct":
        return lambda s: value.lower() in s.get("resp_content_type", "").lower()
    if key == "has":
        return HAS[value][1] if value in HAS else None
    if key == "err":
        if value in ("", "*"):
            return lambda s: bool(s.get("error"))
        return lambda s: value.lower() in s.get("error", "").lower() or s.get("error_kind") == value
    if key in ("after", "before"):
        t = _time(value)
        return (lambda s: s.get("ts", 0) >= t) if key == "after" else (lambda s: s.get("ts", 0) < t)
    if key == "n":
        lo_i, hi_i = _n_range(value)
        return lambda s: lo_i <= s.get("n", 0) <= hi_i
    if key == "grpc":
        rx = _glob_re(value if "/" in value else (value + "/*" if value else "*"))
        return lambda s: bool(s.get("grpc")) and bool(rx.match(f"{s.get('grpc_service', '')}/{s.get('grpc_method', '')}"))
    if key == "gstatus":
        if value in ("!0", "err", "error"):
            return lambda s: bool(s.get("grpc")) and s.get("grpc_status", -1) > 0
        if value == "none":
            return lambda s: bool(s.get("grpc")) and s.get("grpc_status", -1) == -1
        code = _grpc_code(value)
        return lambda s: bool(s.get("grpc")) and s.get("grpc_status", -1) == code
    if key == "scheme":
        return lambda s: s.get("scheme", "") == value.lower()
    if key in ("dur", "size"):
        op, number = _cmp(value, DUR_UNITS if key == "dur" else SIZE_UNITS, key, (1 << 32) - 1 if key == "dur" else U64_MAX)
        col, fn = ("duration_ms" if key == "dur" else "resp_body_size"), OPS[op]
        return lambda s: fn(s.get(col, 0), number)
    return None  # body:, source:, hdr:, rhdr:, has:truncated need the database


def matcher(q: str | None, scope: str | None = None):
    """A predicate over flow summaries for the live tail, or None when `q` needs the database."""
    pred, exact = split_matcher(q, scope)
    return pred if exact else None


def _pred(node):
    """(predicate or None, exact) for one node. None: nothing to check in memory (the term needs the database)."""
    if isinstance(node, Group):
        subs = [_pred(x) for x in node.items]
        exact = all(e for _, e in subs)
        preds = [p for p, _ in subs if p is not None]
        if node.neg and not exact:
            return None, False  # NOT of a partly known group: any flow may match, so pre-select nothing out
        both = (lambda preds: lambda s: all(p(s) for p in preds))(preds)
        return ((lambda p: lambda s: not p(s))(both) if node.neg else both), exact
    if node.key is None:
        needle = node.values[0].lower()
        pred = lambda s: needle in s.get("url", "").lower()  # noqa: E731
    else:
        alts = [_py_term(node.key, v) for v in node.values]
        if any(a is None for a in alts):
            return None, False
        pred = (lambda alts: lambda s: any(a(s) for a in alts))(alts)
    return ((lambda p: lambda s: not p(s))(pred) if node.neg else pred), True


def split_matcher(q: str | None, scope: str | None = None):
    """(predicate, exact): the predicate checks every term it can on a flow summary; `exact` is False when some
    term needs the database, and then the predicate only pre-selects (it never rejects a flow that matches `q`)."""
    compile_filter(q, scope)  # the same validation (FilterError) as the SQL path
    exact = True
    preds = []
    if scope is not None:
        preds.append(lambda s: s.get("session") == scope)
    for node in parse(q):
        pred, ok = _pred(node)
        exact = exact and ok
        if pred is not None:
            preds.append(pred)
    return (lambda s: all(p(s) for p in preds)), exact
