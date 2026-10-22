from m2c.timeline import build


def f(n, call="", ts=None, status=200, host="h.test", dur=10):
    return {"n": n, "ts": ts if ts is not None else n * 100, "call_id": call, "tool": "bash", "status": status, "error": "", "grpc": False,
            "grpc_status": -1, "host": host, "duration_ms": dur}


def test_flows_group_by_call_id_in_time_order():
    items = build([f(1), f(2, "a"), f(3, "a", host="x.test", status=500), f(4), f(5, "b"), f(6, "a")])
    assert [(i["kind"], i.get("call_id"), [x["n"] for x in i["flows"]]) for i in items] == [
        ("between", None, [1]), ("call", "a", [2, 3, 6]), ("between", None, [4]), ("call", "b", [5])]
    a = items[1]
    assert a["failures"] == 1 and a["hosts"] == ["h.test", "x.test"] and (a["start_ts"], a["end_ts"]) == (200, 610)


def test_no_call_ids_no_calls():
    assert build([f(1), f(2)]) == [{"kind": "between", "flows": [f(1), f(2)]}]
    assert build([]) == []
