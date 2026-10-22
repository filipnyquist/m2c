import gzip

import pytest

from m2c.repeater import Busy, Conflict, Repeater, RepeatError, build

DETAIL = {"n": 7, "session": "s1", "tag": "", "method": "POST", "url": "https://api.test/v1/x?y=1", "resp_capture": "buffered", "grpc": False,
          "http_version": "HTTP/2.0", "req_body_truncated": False, "req_body_decoded": True, "req_body_stored": 5,
          "req_headers": [["Host", "api.test"], ["Proxy-Authorization", "Basic Zm9v"], ["Content-Encoding", "gzip"], ["X-M2C-Tool", "x"],
                          ["Content-Length", "99"], ["Authorization", "Bearer t"], ["Connection", "keep-alive"]]}


def test_as_recorded_drops_proxy_and_hop_headers_and_reencodes_the_body():
    flow = build(DETAIL, b"hello", {})
    req = flow.request
    names = [k.lower() for k in req.headers.keys()]
    assert "proxy-authorization" not in names and "x-m2c-tool" not in names and "connection" not in names
    assert req.headers["authorization"] == "Bearer t" and req.headers["host"] == "api.test"
    assert gzip.decompress(req.raw_content) == b"hello" and req.headers["content-length"] == str(len(req.raw_content))
    assert req.http_version == "HTTP/1.1" and flow.is_replay == "request"
    assert flow.metadata["m2c"] == {"session": "s1", "tool": "repeater", "call": "7", "user": "", "source": "none", "tag": "", "replay_of": 7}


def test_edits():
    flow = build(DETAIL, b"hello", {"method": "put", "url": "http://other.test:8080/p", "headers": [["X-A", "1"], ["X-B", "2"]],
                                    "headers_remove": ["x-b"], "body_base64": "AAE="})
    req = flow.request
    assert (req.method, req.host, req.port, req.path) == ("PUT", "other.test", 8080, "/p")
    assert [k for k in req.headers.keys()] == ["Host", "X-A", "content-length"] and req.raw_content == b"\x00\x01"


@pytest.mark.parametrize("overrides, error", [
    ({"url": "file:///etc/passwd"}, RepeatError), ({"method": "G ET"}, RepeatError), ({"headers": [["Bad Name", "x"]]}, RepeatError),
    ({"headers": [["X", "a\nb"]]}, RepeatError), ({"headers": "x"}, RepeatError), ({"body": 5}, RepeatError), ({"body_base64": "!!"}, RepeatError),
    ({"other": 1}, RepeatError)])
def test_bad_edits(overrides, error):
    with pytest.raises(error):
        build(DETAIL, b"hello", overrides)


def test_truncated_bodies_and_websockets():
    with pytest.raises(Conflict):
        build({**DETAIL, "req_body_truncated": True}, b"hel", {})
    build({**DETAIL, "req_body_truncated": True}, b"hel", {"body": "whole"})
    with pytest.raises(RepeatError):
        build({**DETAIL, "resp_capture": "websocket"}, b"", {})


def test_modes_and_limits():
    assert not Repeater("off").allowed(True) and Repeater("admin").allowed(True) and not Repeater("admin").allowed(False)
    assert Repeater("on").allowed(False)
    r = Repeater("on")
    r._acquire("bob")
    with pytest.raises(Busy):
        r._acquire("bob")  # one at a time per caller
    r._acquire("alice")
    r._release("bob")
    r._release("alice")
    for _ in range(60):
        r._acquire("carol")
        r._release("carol")
    with pytest.raises(Busy):
        r._acquire("carol")  # 60 a minute
