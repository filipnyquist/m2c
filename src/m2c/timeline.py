"""A session's flows grouped by the tool call that made them: the call id is the proxy username's third part
(`<session>.<tool>.<call>`), set per Bash call by the Claude Code hooks, or by any harness that names its calls.

Built from recorded flows only: m2c knows a call through its traffic and nothing else, so a call that sent nothing
through the proxy does not appear. Flows without a call id are grouped between the calls around them.
"""

from __future__ import annotations

from .schema import is_failed


def build(flows: list[dict]) -> list[dict]:
    """Items in time order: {"kind": "call", call_id, tool, start_ts, end_ts, failures, hosts, flows} and
    {"kind": "between", flows}. `flows` are summaries in time order."""
    items: list[dict] = []
    calls: dict[str, dict] = {}
    loose: list[dict] = []
    for f in flows:
        cid = f.get("call_id") or ""
        if not cid:
            loose.append(f)
            continue
        call = calls.get(cid)
        if call is None:
            if loose:
                items.append({"kind": "between", "flows": loose})
                loose = []
            call = calls[cid] = {"kind": "call", "call_id": cid, "tool": f.get("tool", ""), "start_ts": f["ts"], "end_ts": f["ts"],
                                 "failures": 0, "hosts": [], "flows": []}
            items.append(call)
        call["flows"].append(f)
        call["end_ts"] = max(call["end_ts"], f["ts"] + int(f.get("duration_ms") or 0))
        call["failures"] += is_failed(f)
        if f.get("host") and f["host"] not in call["hosts"]:
            call["hosts"].append(f["host"])
    if loose:
        items.append({"kind": "between", "flows": loose})
    return items
