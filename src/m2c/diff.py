"""Compare two recorded flows: what changed in the request, the response, timing and size.

Pure: it takes the flow details (as Queries.flow returns them) and their bodies. Headers that differ on every
response (dates, request ids, tracing) are left out; bodies are compared as JSON paths when both sides are JSON,
else as a unified text diff, else by size and hash. Every list is capped so an agent's context doesn't fill up.
"""

from __future__ import annotations

import difflib
import hashlib
import json

from . import fmt

NOISY = frozenset({
    "date", "age", "expires", "last-modified", "etag", "x-request-id", "x-amzn-requestid", "x-amzn-trace-id", "x-amz-cf-id",
    "x-amz-request-id", "x-amz-id-2", "cf-ray", "server-timing", "report-to", "nel", "content-length", "x-runtime",
    "x-trace-id", "traceparent", "tracestate", "request-id", "x-cloud-trace-context", "x-envoy-upstream-service-time",
    "x-served-by", "x-timer", "x-cache-hits", "set-cookie",
})
MAX_PATHS = 100
MAX_LINES = 200
MAX_TEXT = 16 << 10
VALUE_CHARS = 200


def _headers(pairs) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, value in pairs or []:
        out.setdefault(name.lower(), []).append(value)
    return out


def _show(name: str, values: list[str], redact: bool) -> list[str]:
    return [fmt.redact_value(v) if redact and name in fmt.SENSITIVE else v for v in values]


def headers(a_pairs, b_pairs, redact: bool = True) -> dict:
    a, b = _headers(a_pairs), _headers(b_pairs)
    out: dict = {"added": {}, "removed": {}, "changed": {}}
    ignored = 0
    for name in sorted(set(a) | set(b)):
        if a.get(name) == b.get(name):
            continue
        if name in NOISY:
            ignored += 1
            continue
        if name not in a:
            out["added"][name] = _show(name, b[name], redact)
        elif name not in b:
            out["removed"][name] = _show(name, a[name], redact)
        else:
            out["changed"][name] = [_show(name, a[name], redact), _show(name, b[name], redact)]
    out = {k: v for k, v in out.items() if v}
    if ignored:
        out["ignored"] = ignored  # changed headers that differ on every response anyway (dates, ids, cookies)
    return out


def _brief(value) -> object:
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False)
        return text if len(text) <= VALUE_CHARS else text[:VALUE_CHARS] + "..."
    if isinstance(value, str) and len(value) > VALUE_CHARS:
        return value[:VALUE_CHARS] + "..."
    return value


def json_paths(a, b, path: str = "$", out: list | None = None) -> list[dict]:
    """[{path, a, b}] where the documents differ; a missing side is absent from its entry."""
    out = [] if out is None else out
    if len(out) >= MAX_PATHS:
        return out
    if isinstance(a, dict) and isinstance(b, dict):
        for key in list(a) + [k for k in b if k not in a]:
            sub = f"{path}.{key}" if isinstance(key, str) and key.isidentifier() else f"{path}[{json.dumps(key)}]"
            if key not in b:
                out.append({"path": sub, "a": _brief(a[key])})
            elif key not in a:
                out.append({"path": sub, "b": _brief(b[key])})
            else:
                json_paths(a[key], b[key], sub, out)
            if len(out) >= MAX_PATHS:
                break
    elif isinstance(a, list) and isinstance(b, list):
        for i in range(max(len(a), len(b))):
            sub = f"{path}[{i}]"
            if i >= len(b):
                out.append({"path": sub, "a": _brief(a[i])})
            elif i >= len(a):
                out.append({"path": sub, "b": _brief(b[i])})
            else:
                json_paths(a[i], b[i], sub, out)
            if len(out) >= MAX_PATHS:
                break
    elif a != b or type(a) is not type(b):
        out.append({"path": path, "a": _brief(a), "b": _brief(b)})
    return out


def _json(data: bytes):
    try:
        return True, json.loads(data)
    except ValueError:
        return False, None


def _text(data: bytes) -> str | None:
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def body(a: bytes, b: bytes, a_truncated: bool = False, b_truncated: bool = False) -> dict:
    if a == b:
        return {"same": True, "bytes": len(a)} if a else {"same": True}
    out: dict = {"same": False, "bytes": [len(a), len(b)]}
    if a_truncated or b_truncated:
        out["note"] = "a stored body was cut at m2c_body_cap: the comparison covers the stored part"
    if a and b:
        ok_a, doc_a = _json(a)
        ok_b, doc_b = _json(b)
        if ok_a and ok_b:
            paths = json_paths(doc_a, doc_b)
            out["json"] = paths
            if len(paths) >= MAX_PATHS:
                out["cut"] = f"first {MAX_PATHS} differences"
            return out
    text_a, text_b = _text(a), _text(b)
    if text_a is not None and text_b is not None:
        lines, size = [], 0
        for line in difflib.unified_diff(text_a.splitlines(), text_b.splitlines(), "a", "b", lineterm="", n=2):
            size += len(line) + 1
            if len(lines) >= MAX_LINES or size > MAX_TEXT:
                out["cut"] = f"diff cut at {MAX_LINES} lines or {MAX_TEXT // 1024} KiB"
                break
            lines.append(line)
        out["unified"] = "\n".join(lines)
        return out
    out["sha256"] = [hashlib.sha256(a).hexdigest()[:16], hashlib.sha256(b).hexdigest()[:16]]
    return out


def _pair(fa: dict, fb: dict, key: str):
    va, vb = fa.get(key), fb.get(key)
    return None if va == vb else [va, vb]


def compare(fa: dict, fb: dict, bodies: dict[str, tuple[bytes, bytes]], redact: bool = True) -> dict:
    """`bodies` maps 'req'/'resp' to (body of a, body of b)."""
    req = {k: v for k, v in (("method", _pair(fa, fb, "method")), ("url", _pair(fa, fb, "url")),
                             ("headers", headers(fa.get("req_headers"), fb.get("req_headers"), redact))) if v}
    resp = {k: v for k, v in (("status", _pair(fa, fb, "status")), ("error", _pair(fa, fb, "error")),
                              ("grpc_status", _pair(fa, fb, "grpc_status")),
                              ("headers", headers(fa.get("resp_headers"), fb.get("resp_headers"), redact))) if v}
    for side, target in (("req", req), ("resp", resp)):
        a, b = bodies.get(side, (b"", b""))
        result = body(a, b, bool(fa.get(f"{side}_body_truncated")), bool(fb.get(f"{side}_body_truncated")))
        if not result["same"]:
            target["body"] = result
    timing = {}
    for key in ("duration_ms", "ttfb_ms", "req_body_size", "resp_body_size"):
        va, vb = int(fa.get(key) or 0), int(fb.get(key) or 0)
        if va != vb:
            timing[key] = {"a": va, "b": vb, "delta": vb - va}
    out = {"a": fa["n"], "b": fb["n"], "same": not req and not resp}
    for key, value in (("request", req), ("response", resp), ("sizes_and_timing", timing)):
        if value:
            out[key] = value
    who = {k: [fa.get(k), fb.get(k)] for k in ("session", "tool", "call_id") if fa.get(k) != fb.get(k)}
    if who:
        out["identity"] = who
    return out
