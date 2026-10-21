"""Local upstream servers for integration tests: HTTP routes, chunked SSE, large bodies and a WebSocket echo."""

import base64
import gzip
import hashlib
import os
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BINARY = bytes(range(256)) * 16 + os.urandom(1000)
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_frame(payload: bytes, opcode: int = 1, mask: bool = False) -> bytes:
    head = bytes([0x80 | opcode])
    n = len(payload)
    mbit = 0x80 if mask else 0
    if n < 126:
        head += bytes([mbit | n])
    elif n < 65536:
        head += bytes([mbit | 126]) + struct.pack(">H", n)
    else:
        head += bytes([mbit | 127]) + struct.pack(">Q", n)
    if mask:
        key = os.urandom(4)
        payload = bytes(b ^ key[i % 4] for i, b in enumerate(payload))
        head += key
    return head + payload


def ws_read(sock) -> tuple[int, bytes]:
    def exact(n):
        buf = b""
        while len(buf) < n:
            part = sock.recv(n - len(buf))
            if not part:
                raise ConnectionError("closed")
            buf += part
        return buf

    b0, b1 = exact(2)
    n = b1 & 0x7F
    if n == 126:
        n = struct.unpack(">H", exact(2))[0]
    elif n == 127:
        n = struct.unpack(">Q", exact(8))[0]
    key = exact(4) if b1 & 0x80 else None
    data = exact(n)
    if key:
        data = bytes(b ^ key[i % 4] for i, b in enumerate(data))
    return b0 & 0x0F, data


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/plain", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _chunk(self, data: bytes):
        self.wfile.write(b"%x\r\n%s\r\n" % (len(data), data))
        self.wfile.flush()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/hello":
            return self._send(200, b"hello world\n")
        if path == "/bin":
            return self._send(200, BINARY, "application/octet-stream")
        if path == "/gzip":
            return self._send(200, gzip.compress(b"compressed " * 1000), extra={"Content-Encoding": "gzip"})
        if path in ("/sse", "/sse-gzip"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            zip_ = path == "/sse-gzip"
            if zip_:
                self.send_header("Content-Encoding", "gzip")
            self.end_headers()
            events = [b"event: start\ndata: {\"n\": 0}\n\n"] + [b"data: token %d\n\n" % i for i in range(1, 20)] + [b"data: [DONE]\n\n"]
            comp = __import__("zlib").compressobj(wbits=31) if zip_ else None
            for i, ev in enumerate(events):
                data = comp.compress(ev) + comp.flush(__import__("zlib").Z_SYNC_FLUSH) if comp else ev
                self._chunk(data)
                if i == 0:
                    time.sleep(0.6)
            if comp:
                self._chunk(comp.flush())
            self.wfile.write(b"0\r\n\r\n")
            return
        if path == "/sse-badgzip":
            # labelled gzip but sent plain: event parsing stops, the raw body is still captured
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for i in range(10):
                self._chunk(b"data: plain %d\n\n" % i)
            self.wfile.write(b"0\r\n\r\n")
            return
        if path == "/slow-sse":
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            count = int((self.path.split("count=")[1:] or ["10"])[0])
            for i in range(count):
                self._chunk(b"data: slow %d\n\n" % i)
                time.sleep(0.5)
            self.wfile.write(b"0\r\n\r\n")
            return
        if path == "/slow-headers":
            # answers only after `wait` seconds (default 20): a request still in flight when the proxy stops
            time.sleep(float((self.path.split("wait=")[1:] or ["20"])[0]))
            return self._send(200, b"late\n")
        if path == "/big":
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            for _ in range(48):
                self._chunk(b"z" * 65536)
            self.wfile.write(b"0\r\n\r\n")
            return
        if path == "/ws":
            key = self.headers["Sec-WebSocket-Key"].encode()
            accept = base64.b64encode(hashlib.sha1(key + WS_GUID).digest()).decode()
            self.send_response(101)
            self.send_header("Upgrade", "websocket")
            self.send_header("Connection", "Upgrade")
            self.send_header("Sec-WebSocket-Accept", accept)
            self.end_headers()
            self.wfile.flush()
            sock = self.connection
            while True:
                op, data = ws_read(sock)
                if op == 8:
                    sock.sendall(ws_frame(data, 8))
                    break
                sock.sendall(ws_frame(b"echo:" + data, op))
            self.close_connection = True
            return
        self._send(404, b"no\n")

    def do_POST(self):
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            total = 0
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline()
                    break
                total += len(self.rfile.read(size))
                self.rfile.readline()
        else:
            total = len(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        self._send(200, b"got %d\n" % total)

    do_PUT = do_POST  # curl -T


def start() -> tuple[ThreadingHTTPServer, int]:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def start_tls(tmp_dir) -> tuple[ThreadingHTTPServer, int]:
    """The same routes over TLS (HTTP/1.1 only, no ALPN), with a throwaway self-signed certificate."""
    import datetime
    import ssl

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=2))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(__import__("ipaddress").ip_address("127.0.0.1"))]), False)
        .sign(key, hashes.SHA256())
    )
    cert_file, key_file = os.path.join(tmp_dir, "upstream-cert.pem"), os.path.join(tmp_dir, "upstream-key.pem")
    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_file, key_file)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
