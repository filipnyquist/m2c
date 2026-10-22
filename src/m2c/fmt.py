"""Presentation shared by the CLI, MCP and the API: compact flow lines, sizes, times, and header redaction."""

from __future__ import annotations

import hashlib
from datetime import datetime

# Header values that carry credentials. Redacted, they still compare: same value, same hash.
SENSITIVE = frozenset({
    "authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "api-key", "x-auth-token",
    "x-amz-security-token", "x-goog-api-key", "x-csrf-token", "x-xsrf-token", "anthropic-api-key", "openai-api-key",
})


def when(ms: int) -> str:
    if not ms:
        return "-"
    t = datetime.fromtimestamp(ms / 1000)
    return t.strftime("%H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def size(n: int) -> str:
    n = int(n or 0)
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def status_text(f: dict) -> str:
    if f.get("grpc") and f.get("grpc_status", -1) > 0:
        return f"{f['status'] or 'ERR'}/g{f['grpc_status']}"
    return str(f["status"]) if f.get("status") else ("ERR" if f.get("error") else "-")


def flow_line(f: dict, width: int = 0) -> str:
    """One line per flow: `n  time  session/tool#call  METHOD status size duration [sse|ws|grpc]  host/path`."""
    flags = {"sse": " sse", "websocket": " ws"}.get(f.get("resp_capture", ""), "") + (" grpc" if f.get("grpc") else "")
    who = f"{f['session']}/{f['tool']}" + (f"#{f['call_id']}" if f.get("call_id") else "")
    target = f"{f['host']}{f['path']}"
    line = (f"{f['n']:>6}  {when(f['ts'])}  {who:<24.24}  {f['method']:<7} {status_text(f):<4} {size(f['resp_body_size']):>7} "
            f"{f['duration_ms']:>6}ms{flags}  {target}")
    return line[:width] if width else line


def redact_value(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8", "surrogateescape")).hexdigest()[:8]
    return f"<redacted len={len(value)} sha256:{digest}>"


def redact_headers(pairs, mode: str = "all", redact: bool = True) -> list:
    """Headers for display: mode 'all' (name, value), 'names' (names only) or 'none'; credential values redacted."""
    if mode == "none":
        return []
    if mode == "names":
        return [name for name, _ in pairs]
    return [[name, redact_value(value) if redact and name.lower() in SENSITIVE else value] for name, value in pairs]


def report_text(rep: dict) -> str:
    """A compact report: one block per group."""
    if not rep["groups"]:
        return "no flows match"
    out = []
    for g in rep["groups"]:
        who = g["session"] + (f"/{g['tool']}" if "tool" in g else "") + (f"#{g['call_id'] or '-'}" if "call_id" in g else "")
        statuses = " ".join(f"{k}x{v}" for k, v in sorted(g["statuses"].items()))
        line = (f"{who}: {g['flows']} flows, {g['failures']} failed ({g['errors']} errors), up {size(g['bytes_up'])} "
                f"down {size(g['bytes_down'])}, {when(g['first_ts'])}-{when(g['last_ts'])}")
        out.append(line)
        out.append("  hosts: " + ", ".join(f"{h} ({c})" for h, c in g["hosts"]))
        if statuses:
            out.append("  status: " + statuses)
        if g["error_kinds"]:
            out.append("  errors: " + ", ".join(f"{k} ({v})" for k, v in g["error_kinds"].items()))
        out.append("  slowest: " + ", ".join(f"#{s['n']} {s['duration_ms']}ms {s['host']}{s['path'][:60]}" for s in g["slowest"]))
    if rep.get("more"):
        out.append("(more groups: narrow the query or raise limit)")
    return "\n".join(out)
