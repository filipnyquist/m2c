"""The filter language shared by the CLI, the API (`q=`), MCP and the web UI, compiled to parameterized SQL.

    session:abc tool:nuclei call:c7 tag:x host:*.acme.test method:POST|PUT status:5xx|404 status:>=400
    path:/api/* ct:json ua:curl has:sse|ws|error|body err:timeout after:10m before:2026-10-21T12:00 n:100-200
    body:"needle" -status:404 "free text"

Terms are ANDed; `|` ORs values inside one term; a leading `-` negates a term. Free text matches the URL.
Values never reach the SQL text: every one becomes a `{pN:Type}` parameter.
"""

from __future__ import annotations

import re
import shlex
import time
from datetime import datetime, timezone

STATUS_CLASS = re.compile(r"^([1-5])xx$", re.I)
STATUS_CMP = re.compile(r"^(>=|<=|>|<|=)?(\d{3})$")
DURATION = re.compile(r"^(\d+(?:\.\d+)?)([smhd])$")
N_RANGE = re.compile(r"^([0-9]{1,20})(?:-([0-9]{1,20}))?$")  # ASCII digits: "²".isdigit() is True, int("²") raises
U64_MAX = (1 << 64) - 1
I64_MAX = (1 << 63) - 1
UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}
KEYS = {"session", "tool", "call", "tag", "host", "method", "status", "path", "url", "ct", "ua", "has", "err", "after", "before", "n", "body", "source"}


class FilterError(ValueError):
    pass


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
    if key == "has":
        conds = {
            "sse": "resp_capture = 'sse'",
            "ws": "resp_capture = 'websocket'",
            "error": "(error != '' OR status >= 500)",
            "body": "(req_body_size > 0 OR resp_body_size > 0)",
            "reqbody": "req_body_size > 0",
            "truncated": "(req_body_truncated OR resp_body_truncated)",
        }
        if value not in conds:
            raise FilterError(f"has: takes {', '.join(conds)}")
        return conds[value]
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
    raise FilterError(f"unknown filter {key}:")


def compile_filter(q: str | None, scope: str | None = None) -> tuple[str, dict]:
    """(WHERE clause without the keyword, params). `scope` pins one session (session-scoped tokens)."""
    c = Compiler()
    parts: list[str] = []
    if scope is not None:
        parts.append(f"session = {c.p(scope)}")
    try:
        tokens = shlex.split(q or "")
    except ValueError as e:
        raise FilterError(f"bad quoting: {e}") from None
    for tok in tokens:
        neg = tok.startswith("-") and ":" in tok
        if neg:
            tok = tok[1:]
        key, sep, value = tok.partition(":")
        if sep and key.lower() in KEYS:
            key = key.lower()
            values = value.split("|") if key not in ("body", "after", "before", "url", "err") else [value]
            if not values or (values == [""] and key != "err"):
                raise FilterError(f"{key}: needs a value")
            cond = " OR ".join(_term(c, key, v) for v in values)
            cond = f"({cond})" if len(values) > 1 else cond
        else:
            cond = f"positionCaseInsensitive(url, {c.p(tok)}) > 0"
        parts.append(f"NOT ({cond})" if neg else cond)
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
        preds = {
            "sse": lambda s: s.get("resp_capture") == "sse",
            "ws": lambda s: s.get("resp_capture") == "websocket",
            "error": lambda s: bool(s.get("error")) or s.get("status", 0) >= 500,
            "body": lambda s: s.get("req_body_size", 0) > 0 or s.get("resp_body_size", 0) > 0,
            "reqbody": lambda s: s.get("req_body_size", 0) > 0,
        }
        if value not in preds:
            return None
        return preds[value]
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
    return None  # body:, source:, has:truncated need the database


def matcher(q: str | None, scope: str | None = None):
    """A predicate over flow summaries for the live tail, or None when `q` needs the database."""
    pred, exact = split_matcher(q, scope)
    return pred if exact else None


def split_matcher(q: str | None, scope: str | None = None):
    """(predicate, exact): the predicate checks every term it can on a flow summary; `exact` is False when some
    term needs the database, and then the predicate only pre-selects (it never rejects a flow that matches `q`)."""
    compile_filter(q, scope)  # the same validation (FilterError) as the SQL path
    exact = True
    preds = []
    if scope is not None:
        preds.append(lambda s: s.get("session") == scope)
    try:
        tokens = shlex.split(q or "")
    except ValueError as e:
        raise FilterError(f"bad quoting: {e}") from None
    for tok in tokens:
        neg = tok.startswith("-") and ":" in tok
        if neg:
            tok = tok[1:]
        key, sep, value = tok.partition(":")
        if sep and key.lower() in KEYS:
            key = key.lower()
            values = value.split("|") if key not in ("body", "after", "before", "url", "err") else [value]
            alts = [_py_term(key, v) for v in values]
            if any(a is None for a in alts):
                exact = False
                continue
            pred = (lambda alts: lambda s: any(a(s) for a in alts))(alts)
        else:
            needle = tok.lower()
            pred = (lambda needle: lambda s: needle in s.get("url", "").lower())(needle)
        preds.append((lambda p: lambda s: not p(s))(pred) if neg else pred)
    return (lambda s: all(p(s) for p in preds)), exact
