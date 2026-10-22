"""Hints for refining a filter query, from aggregates over the flows it matches (Queries.suggest).

Pure. Each hint is `{kind, text, query, count}`: kind `narrow` (look closer), `exclude` (hide noise) or `info`;
`query` is the whole new query (None for info). A hint never repeats a term the query already has, and never
narrows on a key the query already pins.
"""

from __future__ import annotations

import re

from .filters import parse, terms

CREDENTIALS = ("authorization", "cookie", "x-api-key", "api-key")
CREDENTIAL_SQL = "(" + ", ".join(f"'{h}'" for h in CREDENTIALS) + ")"
MIN_FLOWS = 20  # below this, everything fits on a screen: no noise hints
NOISE_SHARE = 0.4
LOUD_SHARE = 0.6
MAX_HINTS = 6
SAFE = re.compile(r"^[A-Za-z0-9_.:/*?<>=!|@%+-]+$")


def _value(v) -> str:
    v = str(v)
    return v if SAFE.match(v) else '"' + v.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _top(agg: dict, key: str) -> tuple[object, int] | None:
    items = agg.get(key) or []
    return (items[0]["item"], int(items[0]["count"])) if items else None


def _seconds(ms: float) -> str:
    s = ms / 1000
    return f"{s:.0f}s" if s >= 10 else f"{s:.1f}".rstrip("0").rstrip(".") + "s"


def hints(q: str, agg: dict, open_flows: int = 0) -> list[dict]:
    q = (q or "").strip()
    present = terms(parse(q))
    pinned = {t.key for t in present if t.key and not t.neg}
    total = int(agg.get("total") or 0)
    out: list[dict] = []

    def add(kind: str, text: str, term: str | None, count: int | None = None):
        if term is not None and term in q:
            return
        out.append({"kind": kind, "text": text, "query": f"{q} {term}".strip() if term else None, "count": count})

    creds = int(agg.get("cleartext_creds") or 0)
    if creds and "hdr" not in pinned:
        add("narrow", f"{creds} send credentials over plain HTTP", f"scheme:http hdr:{'|'.join(CREDENTIALS)}", creds)

    failures, errors = int(agg.get("failures") or 0), int(agg.get("errors") or 0)
    if failures and failures < total and "has" not in pinned and "status" not in pinned:
        add("narrow", f"{failures} of {total} failed (4xx, 5xx or errors)", "has:fail", failures)
    kind = _top(agg, "error_kinds")
    if kind and kind[0] != "other" and kind[1] >= 3 and kind[1] * 2 >= errors and "err" not in pinned:  # "other" says nothing
        add("narrow", f"{kind[1]} {kind[0]} errors", f"err:{_value(kind[0])}", kind[1])

    if total >= MIN_FLOWS:
        candidates = []  # (count, what, term), the most specific first
        pair = _top(agg, "tool_status")
        if pair and "tool" not in pinned and "status" not in pinned and pair[0][1]:
            tool, status = pair[0]
            candidates.append((pair[1], f"{tool} {status}s", f"-(tool:{_value(tool)} status:{status})"))
        for key, label in (("statuses", "status"), ("hosts", "host"), ("tools", "tool")):
            top = _top(agg, key)
            if top and label not in pinned and top[0] not in (0, ""):
                what = f"{top[0]} responses" if label == "status" else f"{label} {top[0]}"
                candidates.append((top[1], what, f"-{label}:{_value(top[0])}"))
        for count, what, term in candidates:
            if NOISE_SHARE <= count / total < 1:
                add("exclude", f"{count} of {total} are {what}: hide them", term, count)
                break

        p95 = float(agg.get("p95") or 0)
        if p95 >= 1000 and "dur" not in pinned:
            add("narrow", f"the slowest 5% take over {_seconds(p95)}", f"dur:>{_seconds(p95)}", max(1, total // 20))

    if total >= MIN_FLOWS and int(agg.get("n_sessions") or 0) >= 2 and "session" not in pinned:
        top = _top(agg, "sessions")
        if top and top[1] / max(total, 1) >= LOUD_SHARE:
            add("narrow", f"{round(100 * top[1] / total)}% come from session {top[0]}", f"session:{_value(top[0])}", top[1])

    if open_flows:
        add("info", f"{open_flows} flow{'s' if open_flows > 1 else ''} still open (streams): shown live in the list", None, open_flows)
    return out[:MAX_HINTS]
