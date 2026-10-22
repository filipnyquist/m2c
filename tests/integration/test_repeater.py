"""The repeater: resend recorded requests, edited or not, through a real proxy; who may; what gets recorded."""

import gzip
import json
import subprocess
import time
import urllib.error
import urllib.request

import pytest

from conftest import M2C, Proxy

pytestmark = pytest.mark.integration


def call(p: Proxy, method: str, path: str, body=None, token=None):
    info = json.loads((p.data / "api.json").read_text())
    req = urllib.request.Request(info["url"] + path, data=json.dumps(body).encode() if body is not None else None, method=method)
    req.add_header("Authorization", f"Bearer {token or info['token']}")
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=20) as res:
            raw = res.read()
            return res.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        return e.code, json.loads(raw) if raw else None


@pytest.fixture
def rp(tmp_path):
    p = Proxy(tmp_path, extra=["--repeater", "on", "--", "--set", "m2c_repeater_timeout=2"])
    yield p
    p.stop()


def curl(p, user, tok, url, *extra):
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", p.url(user, tok), *extra, url], check=True)


def flows(p, q):
    return {f["path"]: f for f in call(p, "GET", "/v1/flows?limit=100&q=" + urllib.request.quote(q))[1]["flows"]}


def test_resend_as_recorded_and_edited(rp, upstream, tmp_path):
    tok = rp.token("alice")
    up = f"http://127.0.0.1:{upstream}"
    curl(rp, "alice.curl.c1", tok, up + "/hello", "-H", "Authorization: Bearer app-secret", "-H", "x-m2c-tag: t1")
    zipped = tmp_path / "body.gz"
    zipped.write_bytes(gzip.compress(b"hello gzip body " * 20))
    curl(rp, "alice.curl", tok, up + "/post", "-H", "Content-Encoding: gzip", "--data-binary", f"@{zipped}")
    time.sleep(0.6)
    orig = flows(rp, "session:alice")

    # as recorded: same session, tool repeater, call id = the original n, replay_of
    status, out = call(rp, "POST", f"/v1/flows/{orig['/hello']['n']}/resend", {})
    assert status == 201 and out["status"] == 200 and out["replay_of"] == orig["/hello"]["n"]
    status, new = call(rp, "GET", f"/v1/flows/{out['n']}")
    assert (new["session"], new["tool"], new["call_id"], new["replay_of"], new["is_replay"]) == ("alice", "repeater", str(orig["/hello"]["n"]), orig["/hello"]["n"], True)
    sent = {k.lower(): v for k, v in new["req_headers"]}
    assert sent["authorization"] == "Bearer app-secret" and "proxy-authorization" not in sent and not any(k.startswith("x-m2c") for k in sent)
    assert new["tag"] == "t1"

    # a gzip body stored decoded goes out gzip-encoded again (the recorder decodes what the server got)
    status, out = call(rp, "POST", f"/v1/flows/{orig['/post']['n']}/resend", {})
    status, new = call(rp, "GET", f"/v1/flows/{out['n']}")
    assert out["status"] == 200 and new["req_body_decoded"] and new["req_body_size"] < len(b"hello gzip body " * 20)
    body = urllib.request.build_opener(urllib.request.ProxyHandler({})).open(urllib.request.Request(
        json.loads((rp.data / "api.json").read_text())["url"] + f"/v1/flows/{out['n']}/body/req",
        headers={"Authorization": "Bearer " + json.loads((rp.data / "api.json").read_text())["token"]}), timeout=10).read()
    assert body == b"hello gzip body " * 20

    # edited: method, url, body, a header replaced and one dropped
    status, out = call(rp, "POST", f"/v1/flows/{orig['/hello']['n']}/resend", {
        "method": "PUT", "url": up + "/post?x=1", "body": "abc", "headers": [["Authorization", "Bearer other"], ["X-Extra", "1"]],
        "headers_remove": ["x-extra"]})
    status, new = call(rp, "GET", f"/v1/flows/{out['n']}")
    sent = {k.lower(): v for k, v in new["req_headers"]}
    assert (new["method"], new["path"], new["status"]) == ("PUT", "/post?x=1", 200) and sent["authorization"] == "Bearer other" and "x-extra" not in sent
    status, d = call(rp, "GET", f"/v1/diff?a={orig['/hello']['n']}&b={out['n']}")
    assert d["request"]["method"] == ["GET", "PUT"]
    assert [f["n"] for f in call(rp, "GET", "/v1/flows?q=has:replay")[1]["flows"]] == sorted((f["n"] for f in flows(rp, "has:replay").values()), reverse=True)

    # bad edits are 400s; an unknown flow 404
    for bad in ({"url": "ftp://x/"}, {"method": "GE T"}, {"headers": [["X", "a\r\nInjected: 1"]]}, {"body": "x", "body_base64": "eA=="}, {"nope": 1}):
        assert call(rp, "POST", f"/v1/flows/{orig['/hello']['n']}/resend", bad)[0] == 400, bad
    assert call(rp, "POST", "/v1/flows/99999/resend", {})[0] == 404


def test_scopes_timeouts_and_mcp(rp, upstream):
    alice, bob = rp.token("alice"), rp.token("bob")
    up = f"http://127.0.0.1:{upstream}"
    curl(rp, "alice.curl", alice, up + "/hello")
    curl(rp, "bob.curl", bob, up + "/hello")
    curl(rp, "bob.curl", bob, up + "/slow-headers?wait=1")
    time.sleep(0.6)
    a, b = flows(rp, "session:alice")["/hello"]["n"], flows(rp, "session:bob")
    # m2c_repeater=on: a session token resends its own flows, not another session's
    assert call(rp, "POST", f"/v1/flows/{b['/hello']['n']}/resend", {}, token=f"bob:{bob}")[0] == 201
    assert call(rp, "POST", f"/v1/flows/{a}/resend", {}, token=f"bob:{bob}")[0] == 404

    # no response within m2c_repeater_timeout: recorded as an error, nothing left in flight
    status, out = call(rp, "POST", f"/v1/flows/{b['/slow-headers?wait=1']['n']}/resend", {"url": up + "/slow-headers?wait=5"})
    assert status == 201 and out["status"] == 0 and "no complete response" in out["error"]
    status, new = call(rp, "GET", f"/v1/flows/{out['n']}")
    assert status == 200 and "no complete response" in new["error"] and new["replay_of"] == b["/slow-headers?wait=1"]["n"]

    # MCP: traffic_replay is listed for the caller, and returns the diff
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "traffic_replay", "arguments": {"n": a, "method": "HEAD"}}}
    status, reply = call(rp, "POST", "/mcp", msg)
    result = reply["result"]["structuredContent"] if "structuredContent" in reply["result"] else json.loads(reply["result"]["content"][0]["text"])
    assert result["replay_of"] == a and result["diff"]["request"]["method"] == ["GET", "HEAD"]
    # the CLI
    out = subprocess.run([M2C, "resend", str(a), "-H", "X-Try: 2"], capture_output=True, text=True, env=rp.env, check=True).stdout
    assert f"(resent #{a})" in out and f"m2c diff {a} " in out


def test_off_by_default(proxy, upstream):
    tok = proxy.token("alice")
    curl(proxy, "alice.curl", tok, f"http://127.0.0.1:{upstream}/hello")
    time.sleep(0.6)
    n = flows(proxy, "session:alice")["/hello"]["n"]
    status, body = call(proxy, "POST", f"/v1/flows/{n}/resend", {})
    assert status == 403 and "off" in body["error"]
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
    tools = {t["name"] for t in call(proxy, "POST", "/mcp", msg)[1]["result"]["tools"]}
    assert "traffic_replay" not in tools
