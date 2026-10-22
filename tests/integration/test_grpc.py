"""gRPC through a real m2c proxy: a grpcio server over TLS and a grpcio client using the proxy with credentials.
Raw-bytes handlers (no generated code): the messages are hand-encoded protobuf."""

import base64
import datetime
import json
import socket
import threading
import time
import urllib.request
from concurrent import futures

import pytest

import servers

grpc = pytest.importorskip("grpc")
pytestmark = pytest.mark.integration


def pb(text: bytes, n: int | None = None) -> bytes:
    """protobuf {1: text, 2: n}"""
    out = b"\x0a" + bytes([len(text)]) + text if len(text) < 128 else b"\x0a" + _varint(len(text)) + text
    if n is not None:
        out += b"\x10" + _varint(n)
    return out


def _varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _tls_files(tmp_path):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM))


def _server(tmp_path):
    def unary(req, ctx):
        return pb(b"hello " + req[2:], 7)

    def stream(req, ctx):
        for i in range(3):
            time.sleep(0.2)
            yield pb(b"tick", i)

    def bidi(reqs, ctx):
        for r in reqs:
            yield pb(b"echo " + r[2:])

    def fail(req, ctx):
        ctx.abort(grpc.StatusCode.INVALID_ARGUMENT, "bad arg")

    def big(req, ctx):
        ctx.set_compression(grpc.Compression.Gzip)
        return pb(b"z" * 5000)

    handlers = {
        "Unary": grpc.unary_unary_rpc_method_handler(unary),
        "Stream": grpc.unary_stream_rpc_method_handler(stream),
        "Bidi": grpc.stream_stream_rpc_method_handler(bidi),
        "Fail": grpc.unary_unary_rpc_method_handler(fail),
        "Big": grpc.unary_unary_rpc_method_handler(big),
    }
    server = grpc.server(futures.ThreadPoolExecutor(8))
    server.add_generic_rpc_handlers((grpc.method_handlers_generic_handler("demo.v1.Demo", handlers),))
    key, cert = _tls_files(tmp_path)
    port = server.add_secure_port("127.0.0.1:0", grpc.ssl_server_credentials([(key, cert)]))
    server.start()
    return server, port


def test_grpc_calls_messages_status_and_decoding(proxy, tmp_path, monkeypatch):
    for var in ("no_proxy", "NO_PROXY", "http_proxy", "https_proxy", "grpc_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        monkeypatch.delenv(var, raising=False)
    server, port = _server(tmp_path)
    tok = proxy.token("g1")
    ca = (proxy.conf / "mitmproxy-ca-cert.pem").read_bytes()
    ch = grpc.secure_channel(f"localhost:{port}", grpc.ssl_channel_credentials(root_certificates=ca),
                             options=[("grpc.http_proxy", f"http://g1.grpcclient:{tok}@127.0.0.1:{proxy.port}")])
    try:
        assert ch.unary_unary("/demo.v1.Demo/Unary")(pb(b"ann"), timeout=10) == pb(b"hello ann", 7)
        t0, arrivals = time.time(), []
        for _ in ch.unary_stream("/demo.v1.Demo/Stream")(pb(b"go"), timeout=10):
            arrivals.append(time.time() - t0)
        assert len(arrivals) == 3 and arrivals[0] < 0.6  # streamed live, not buffered to the end
        assert list(ch.stream_stream("/demo.v1.Demo/Bidi")(iter([pb(b"a"), pb(b"b")]), timeout=10)) == [pb(b"echo a"), pb(b"echo b")]
        with pytest.raises(grpc.RpcError) as err:
            ch.unary_unary("/demo.v1.Demo/Fail")(pb(b"x"), timeout=10)
        assert err.value.code() == grpc.StatusCode.INVALID_ARGUMENT
        assert ch.unary_unary("/demo.v1.Demo/Big")(pb(b"b"), timeout=10) == pb(b"z" * 5000)
    finally:
        ch.close()
        server.stop(0)
    time.sleep(0.6)

    # live API: the messages, decoded from protobuf (schemaless: field numbers)
    info = json.loads((proxy.data / "api.json").read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def api(path):
        req = urllib.request.Request(info["url"] + path, headers={"Authorization": f"Bearer {info['token']}"})
        with opener.open(req, timeout=10) as res:
            return json.loads(res.read())

    flows = {f["grpc_method"]: f for f in api("/v1/flows?q=has:grpc&limit=10")["flows"]}
    assert set(flows) == {"Unary", "Stream", "Bidi", "Fail", "Big"}
    unary_msgs = api(f"/v1/flows/{flows['Unary']['n']}/grpc")
    assert [m["from_client"] for m in unary_msgs] == [True, False]
    assert "hello ann" in unary_msgs[1]["decoded"] and unary_msgs[1]["decoded_as"] == "schemaless"
    assert [f["n"] for f in api("/v1/flows?q=gstatus:!0")["flows"]] == [flows["Fail"]["n"]]
    proxy.stop()

    rows = {r["grpc_method"]: r for r in proxy.rows(
        "SELECT grpc_method, grpc_service, grpc_status, grpc_message, grpc_status_source, grpc_req_messages, grpc_resp_messages, "
        "session, tool, http_version FROM m2c.http_flows WHERE grpc")}
    assert rows["Unary"] == {"grpc_method": "Unary", "grpc_service": "demo.v1.Demo", "grpc_status": 0, "grpc_message": "",
                             "grpc_status_source": "trailers", "grpc_req_messages": 1, "grpc_resp_messages": 1,
                             "session": "g1", "tool": "grpcclient", "http_version": "HTTP/2.0"}
    assert (rows["Fail"]["grpc_status"], rows["Fail"]["grpc_message"]) == (3, "bad arg")
    assert (rows["Stream"]["grpc_resp_messages"], rows["Bidi"]["grpc_req_messages"], rows["Bidi"]["grpc_resp_messages"]) == (3, 2, 2)
    bidi = proxy.rows(f"SELECT seq, from_client FROM m2c.grpc_messages WHERE method = 'Bidi' ORDER BY seq")
    assert [r["from_client"] for r in bidi][:2] == [True, False] or [r["from_client"] for r in bidi].count(True) == 2
    big = proxy.rows("SELECT compressed, encoding, decompressed, size, length(data) AS stored, hex(data) AS h FROM m2c.grpc_messages "
                     "WHERE method = 'Big' AND NOT from_client")[0]
    assert big["compressed"] and big["encoding"] == "gzip" and big["decompressed"] and big["stored"] == len(pb(b"z" * 5000))
    assert bytes.fromhex(big["h"]) == pb(b"z" * 5000) and big["size"] < big["stored"]  # size is the compressed wire size
    summary = {r["tool"]: r for r in proxy.rows("SELECT tool, failures FROM m2c.session_summary")}
    assert summary["grpcclient"]["failures"] == 1


def test_plaintext_tunnel_is_an_event(proxy):
    """Plaintext HTTP/2 (gRPC without TLS) is forwarded by mitmproxy as raw TCP: it gets a tcp_tunnel event."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        conn, _ = srv.accept()
        conn.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")  # an HTTP/2 SETTINGS frame: the server speaks first
        conn.recv(4096)
        conn.sendall(b"pong")
        time.sleep(0.2)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    tok = proxy.token("t1")
    s = socket.create_connection(("127.0.0.1", proxy.port), 5)
    auth = base64.b64encode(f"t1.grpcplain:{tok}".encode()).decode()
    s.sendall(f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: Basic {auth}\r\n\r\n".encode())
    assert s.recv(4096).startswith(b"HTTP/1.1 200")
    time.sleep(0.3)
    s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + b"\x00" * 9)
    got = b""
    while b"pong" not in got:
        chunk = s.recv(4096)
        if not chunk:
            break
        got += chunk
    s.close()
    time.sleep(0.5)
    proxy.stop()
    ev = proxy.rows("SELECT session, tool, reason, severity, host, port, counters FROM m2c.proxy_events WHERE kind = 'tcp_tunnel'")
    assert len(ev) == 1
    e = ev[0]
    assert (e["session"], e["tool"], e["reason"], e["severity"], e["port"]) == ("t1", "grpcplain", "h2c", "warn", port)
    assert e["counters"]["bytes_up"] == 33 and e["counters"]["bytes_down"] == 13
    assert proxy.rows("SELECT count() AS c FROM m2c.http_flows")[0]["c"] == 0
    srv.close()
