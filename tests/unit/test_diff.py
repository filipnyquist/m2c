import json

from m2c import diff
from m2c.queries import re2_literal


def _flow(n, **kw):
    base = {"n": n, "method": "GET", "url": "https://h.test/a", "status": 200, "error": "", "grpc_status": -1, "duration_ms": 10,
            "ttfb_ms": 5, "req_body_size": 0, "resp_body_size": 2, "session": "s", "tool": "t", "call_id": "",
            "req_headers": [["Accept", "*/*"], ["Authorization", "Bearer one"]],
            "resp_headers": [["Date", "Mon"], ["Content-Type", "application/json"], ["X-Request-Id", "1"]]}
    return {**base, **kw}


def test_identical_flows_are_the_same():
    out = diff.compare(_flow(1), _flow(2), {"resp": (b"{}", b"{}")})
    assert out == {"a": 1, "b": 2, "same": True}


def test_noisy_headers_are_ignored_and_credentials_redacted():
    b = _flow(2, req_headers=[["Accept", "*/*"], ["Authorization", "Bearer two"], ["X-New", "1"]],
              resp_headers=[["Date", "Tue"], ["Content-Type", "application/json"], ["X-Request-Id", "2"]])
    out = diff.compare(_flow(1), b, {})
    h = out["request"]["headers"]
    assert h["added"] == {"x-new": ["1"]}
    a_val, b_val = h["changed"]["authorization"]
    assert a_val[0].startswith("<redacted") and a_val != b_val and "two" not in json.dumps(out)
    assert out["response"]["headers"] == {"ignored": 2}
    assert diff.compare(_flow(1), b, {}, redact=False)["request"]["headers"]["changed"]["authorization"] == [["Bearer one"], ["Bearer two"]]


def test_json_bodies_diff_by_path():
    a = json.dumps({"user": {"id": 1, "roles": ["a", "b"]}, "gone": True}).encode()
    b = json.dumps({"user": {"id": 2, "roles": ["a"]}, "new": "x" * 500}).encode()
    out = diff.compare(_flow(1), _flow(2, status=403, duration_ms=30), {"resp": (a, b)})
    paths = {p["path"]: p for p in out["response"]["body"]["json"]}
    assert paths["$.user.id"] == {"path": "$.user.id", "a": 1, "b": 2}
    assert paths["$.user.roles[1]"] == {"path": "$.user.roles[1]", "a": "b"}
    assert "a" not in paths["$.new"] and paths["$.new"]["b"].endswith("...")
    assert out["response"]["status"] == [200, 403] and out["sizes_and_timing"]["duration_ms"] == {"a": 10, "b": 30, "delta": 20}


def test_caps_text_and_binary():
    many_a = json.dumps({str(i): i for i in range(500)}).encode()
    many_b = json.dumps({str(i): -i for i in range(500)}).encode()
    body = diff.body(many_a, many_b)
    assert len(body["json"]) == diff.MAX_PATHS and "cut" in body
    text = diff.body("\n".join(map(str, range(2000))).encode(), "\n".join(str(-i) for i in range(2000)).encode())
    assert text["unified"].startswith("--- a") and text["unified"].count("\n") < diff.MAX_LINES and "cut" in text
    binary = diff.body(b"\xff\x00", b"\xfe\x00", a_truncated=True)
    assert len(binary["sha256"]) == 2 and "note" in binary


def test_re2_literal_escapes_metacharacters():
    assert re2_literal("a.b*(c)") == r"a\.b\*\(c\)"
    assert re2_literal("ünï code") == "ünï code"
