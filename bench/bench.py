"""m2c benchmarks: proxy overhead, ingest capacity, query latency, storage, push. Results go to JSON.

    .venv/bin/python bench/bench.py all [--quick] [--out bench/results.json] [--central http://m2c:pw@127.0.0.1:18123]
    .venv/bin/python bench/bench.py proxy|ingest|queries|storage|push|startup

Everything runs locally: an asyncio upstream (HTTP and TLS), an asyncio load client, and proxies started as real
processes. "baseline" is plain mitmdump with the same options m2c uses, so the difference is the recorder's cost.
Data lives in bench/.work on the real disk (not tmpfs). chDB allows one data directory per process, so anything that
opens chDB runs in a subprocess of its own.
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import datetime
import http.client
import json
import os
import platform
import shutil
import signal
import socket
import ssl
import statistics
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv" / "bin"
WORK = ROOT / "bench" / ".work"
CONF = WORK / "conf"
PY = str(VENV / "python")


def log(msg: str) -> None:
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def pct(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    values = sorted(values)
    return values[min(len(values) - 1, int(len(values) * p))]


def ms(v: float) -> float:
    return round(v * 1000, 2)


# --------------------------------------------------------------------------- upstream


TEXT = (b'{"id":"msg_01","type":"message","role":"assistant","content":[{"type":"text","text":"'
        + b"The quick brown fox jumps over the lazy dog. " * 40 + b'"}],"usage":{"input_tokens":1200,"output_tokens":310}}\n')


def body_of(n: int) -> bytes:
    return (TEXT * (n // len(TEXT) + 1))[:n]


BODIES: dict[int, bytes] = {}


async def upstream_handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            line, _, rest = head.partition(b"\r\n")
            method, target, _ = line.split(b" ", 2)
            length = 0
            for h in rest.split(b"\r\n"):
                if h.lower().startswith(b"content-length:"):
                    length = int(h.split(b":", 1)[1])
            if length:
                await reader.readexactly(length)
            path, _, query = target.partition(b"?")
            q = dict(kv.split(b"=", 1) for kv in query.split(b"&") if b"=" in kv)
            if path == b"/sse":
                count, interval = int(q.get(b"count", b"20")), float(q.get(b"interval", b"0.01"))
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                for i in range(count):
                    ev = b'data: {"t":%f,"i":%d,"text":"token"}\n\n' % (time.time(), i)
                    writer.write(b"%x\r\n%s\r\n" % (len(ev), ev))
                    await writer.drain()
                    await asyncio.sleep(interval)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
                continue
            n = int(q.get(b"n", b"200"))
            if n not in BODIES:
                BODIES[n] = body_of(n)
            body = BODIES[n]
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n" % len(body))
            writer.write(body)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()


def tls_context() -> ssl.SSLContext:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    d = Path(tempfile.mkdtemp(prefix="m2c-bench-tls-"))
    (d / "c.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (d / "k.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(d / "c.pem", d / "k.pem")
    return ctx


class Upstream:
    """HTTP and HTTPS upstream on a background event loop."""

    def __init__(self):
        self.port, self.tls_port = free_port(), free_port()
        ready = threading.Event()

        def run():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(asyncio.start_server(upstream_handler, "127.0.0.1", self.port, backlog=1024))
            self.loop.run_until_complete(
                asyncio.start_server(upstream_handler, "127.0.0.1", self.tls_port, ssl=tls_context(), backlog=1024))
            ready.set()
            self.loop.run_forever()

        threading.Thread(target=run, daemon=True).start()
        ready.wait(10)


# --------------------------------------------------------------------------- load client


async def read_response(reader: asyncio.StreamReader) -> int:
    head = await reader.readuntil(b"\r\n\r\n")
    status = int(head.split(b" ", 2)[1])
    length, chunked = 0, False
    for h in head.split(b"\r\n")[1:]:
        lh = h.lower()
        if lh.startswith(b"content-length:"):
            length = int(h.split(b":", 1)[1])
        elif lh.startswith(b"transfer-encoding:") and b"chunked" in lh:
            chunked = True
    if chunked:
        while True:
            size = int((await reader.readline()).strip(), 16)
            await reader.readexactly(size + 2)
            if size == 0:
                break
    elif length:
        await reader.readexactly(length)
    return status


async def open_via(proxy: tuple[str, int] | None, host: str, port: int, tls: bool, auth: str | None):
    if proxy is None:
        if tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            return await asyncio.open_connection(host, port, ssl=ctx, server_hostname="localhost")
        return await asyncio.open_connection(host, port)
    reader, writer = await asyncio.open_connection(*proxy)
    if tls:
        writer.write(f"CONNECT localhost:{port} HTTP/1.1\r\nHost: localhost:{port}\r\nProxy-Authorization: {auth}\r\n\r\n".encode())
        await writer.drain()
        head = await reader.readuntil(b"\r\n\r\n")
        if b" 200 " not in head.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"CONNECT failed: {head[:80]!r}")
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        await writer.start_tls(ctx, server_hostname="localhost")
    return reader, writer


async def load(proxy, port: int, path: str, total: int, conc: int, tls: bool = False, auth: str | None = None) -> dict:
    lat: list[float] = []
    errors = 0
    per = total // conc

    async def worker():
        nonlocal errors
        reader, writer = await open_via(proxy, "127.0.0.1", port, tls, auth)
        for _ in range(per):
            if proxy is not None and not tls:
                req = f"GET http://127.0.0.1:{port}{path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nProxy-Authorization: {auth}\r\n\r\n"
            else:
                req = f"GET {path} HTTP/1.1\r\nHost: localhost:{port}\r\n\r\n"
            t0 = time.perf_counter()
            writer.write(req.encode())
            try:
                status = await read_response(reader)
            except (asyncio.IncompleteReadError, ConnectionError):
                errors += 1
                reader, writer = await open_via(proxy, "127.0.0.1", port, tls, auth)
                continue
            if status != 200:
                errors += 1
            lat.append(time.perf_counter() - t0)
        writer.close()

    t0 = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(conc)))
    elapsed = time.perf_counter() - t0
    return {
        "requests": len(lat), "errors": errors, "seconds": round(elapsed, 2), "rps": round(len(lat) / elapsed, 1),
        "p50_ms": ms(pct(lat, 0.5)), "p95_ms": ms(pct(lat, 0.95)), "p99_ms": ms(pct(lat, 0.99)),
    }


async def sse_timing(proxy, port: int, auth: str | None, count: int = 50, interval: float = 0.02) -> dict:
    """Delay between the upstream writing an event and the client reading it."""
    reader, writer = await open_via(proxy, "127.0.0.1", port, False, auth)
    target = f"http://127.0.0.1:{port}" if proxy else ""
    writer.write(f"GET {target}/sse?count={count}&interval={interval} HTTP/1.1\r\nHost: x\r\nProxy-Authorization: {auth}\r\n\r\n".encode())
    t_req = time.perf_counter()
    await reader.readuntil(b"\r\n\r\n")
    delays, first = [], None
    while True:
        size = int((await reader.readline()).strip(), 16)
        chunk = await reader.readexactly(size + 2)
        if size == 0:
            break
        now = time.time()
        if first is None:
            first = time.perf_counter() - t_req
        # A proxy that buffers the stream sends all events in one chunk at the end: count each of them.
        for line in chunk.split(b"\n"):
            if line.startswith(b"data: "):
                delays.append(now - float(json.loads(line[6:])["t"]))
    writer.close()
    return {"events": len(delays), "first_event_ms": ms(first or 0), "delay_p50_ms": ms(pct(delays, 0.5)), "delay_p99_ms": ms(pct(delays, 0.99))}


# --------------------------------------------------------------------------- proxies


class Proc:
    def __init__(self, kind: str, data: Path | None = None, extra: list[str] | None = None):
        self.kind = kind
        self.port = free_port()
        self.data = data
        self.env = {**os.environ, "M2C_CONFDIR": str(CONF)}
        if kind == "baseline":
            argv = [str(VENV / "mitmdump"), "-q", "--listen-host", "127.0.0.1", "--listen-port", str(self.port), "--set", "proxyauth=any",
                    "--set", "connection_strategy=eager", "--set", "ssl_insecure=true", "--set", f"confdir={CONF}", "--set", "flow_detail=0"]
        else:
            self.env["M2C_DATA"] = str(data)
            argv = [str(VENV / "m2c"), "proxy", "--listen", f"127.0.0.1:{self.port}", "--api", "127.0.0.1:0", "--data", str(data), *(extra or [])]
        self.t_launch = time.perf_counter()
        self.proc = subprocess.Popen(argv, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                if kind == "baseline" or (data / "api.json").exists():
                    break
            except OSError:
                pass
            time.sleep(0.05)
        self.startup_s = time.perf_counter() - self.t_launch
        self.auth = "Basic " + base64.b64encode(b"bench.load:x").decode()
        if kind == "m2c":
            tok = subprocess.run([str(VENV / "m2c"), "mint", "bench", "--data", str(data)], env=self.env, capture_output=True, text=True).stdout.strip()
            self.auth = "Basic " + base64.b64encode(f"bench.load:{tok}".encode()).decode()

    def cpu_s(self) -> float:
        fields = Path(f"/proc/{self.proc.pid}/stat").read_text().rsplit(")", 1)[1].split()
        return (int(fields[11]) + int(fields[12])) / os.sysconf("SC_CLK_TCK")

    def rss_mb(self) -> tuple[float, float]:
        status = Path(f"/proc/{self.proc.pid}/status").read_text()
        get = lambda k: int(next(line.split()[1] for line in status.splitlines() if line.startswith(k))) / 1024  # noqa: E731
        return round(get("VmRSS:"), 1), round(get("VmHWM:"), 1)

    def api(self) -> tuple[str, str]:
        info = json.loads((self.data / "api.json").read_text())
        return info["url"], info["token"]

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
            self.proc.wait(60)


def api_get(url: str, token: str, path: str):
    u = urllib.parse.urlsplit(url)
    c = http.client.HTTPConnection(u.hostname, u.port, timeout=60)
    c.request("GET", path, headers={"Authorization": f"Bearer {token}"})
    r = c.getresponse()
    return r.status, r.read()


# --------------------------------------------------------------------------- scenarios


def bench_proxy(quick: bool) -> dict:
    up = Upstream()
    n_small = 4000 if quick else 20000
    cases = [
        ("http_small_200B", up.port, "/x?n=200", n_small, 32, False),
        ("https_small_200B", up.tls_port, "/x?n=200", n_small // 2, 32, True),
        ("http_64KiB", up.port, "/x?n=65536", n_small // 4, 16, False),
        ("http_4MiB_streamed", up.port, "/x?n=4194304", 100 if quick else 400, 8, False),
    ]
    out: dict = {"cases": {}, "sse": {}}
    for name, port, path, total, conc, tls in cases:
        if not tls:
            out["cases"].setdefault(name, {})["direct"] = asyncio.run(load(None, port, path, total, conc, tls))
        for kind in ("baseline", "m2c"):
            data = WORK / f"proxy-{name}"
            shutil.rmtree(data, ignore_errors=True)
            p = Proc(kind, data if kind == "m2c" else None)
            warm = asyncio.run(load(("127.0.0.1", p.port), port, path, max(conc * 10, total // 20), conc, tls, p.auth))["requests"]
            cpu0 = p.cpu_s()
            r = asyncio.run(load(("127.0.0.1", p.port), port, path, total, conc, tls, p.auth))
            cpu = p.cpu_s() - cpu0
            r["proxy_cpu_ms_per_request"] = round(cpu * 1000 / max(r["requests"], 1), 3)
            r["proxy_cpu_cores"] = round(cpu / r["seconds"], 2)
            r["rss_mb"], r["peak_rss_mb"] = p.rss_mb()
            if kind == "m2c":
                time.sleep(1)
                url, token = p.api()
                stats = json.loads(api_get(url, token, "/v1/scan")[1])
                r["rows_recorded"] = stats["flows"]
                r["rows_expected"] = r["requests"] + warm
                r["dropped"] = sum(v for k, v in stats["writer"].items() if k.startswith("dropped."))
                r["insert_batches"] = stats["writer"]["batches"]
                r["max_batch_ms"] = stats["writer"]["max_batch_ms"]
            p.stop()
            out["cases"].setdefault(name, {})[kind] = r
            log(f"proxy {name} {kind}: {r['rps']} req/s p50 {r['p50_ms']} ms p99 {r['p99_ms']} ms cpu/req {r['proxy_cpu_ms_per_request']} ms")
    out["sse"]["direct"] = asyncio.run(sse_timing(None, up.port, None))
    for kind in ("baseline", "m2c"):
        data = WORK / "proxy-sse"
        shutil.rmtree(data, ignore_errors=True)
        p = Proc(kind, data if kind == "m2c" else None)
        out["sse"][kind] = asyncio.run(sse_timing(("127.0.0.1", p.port), up.port, p.auth))
        p.stop()
        log(f"sse {kind}: {out['sse'][kind]}")
    return out


def bench_latency(quick: bool) -> dict:
    """One connection, one request at a time: the latency a single agent tool sees through an idle proxy."""
    up = Upstream()
    n = 300 if quick else 2000
    out = {"direct": asyncio.run(load(None, up.port, "/x?n=200", n, 1))}
    for kind in ("baseline", "m2c"):
        data = WORK / "latency"
        shutil.rmtree(data, ignore_errors=True)
        p = Proc(kind, data if kind == "m2c" else None)
        asyncio.run(load(("127.0.0.1", p.port), up.port, "/x?n=200", 200, 1, False, p.auth))
        out[kind] = asyncio.run(load(("127.0.0.1", p.port), up.port, "/x?n=200", n, 1, False, p.auth))
        p.stop()
    log(f"latency: {out}")
    return out


def bench_ingest(quick: bool) -> dict:
    """Writer capacity without mitmproxy, and the per-flow cost the hooks put on the event loop."""
    script = textwrap.dedent("""
        import json, sys, time, uuid
        from pathlib import Path
        from mitmproxy.test import tflow
        from m2c.db import Database
        from m2c.writer import Writer
        from m2c import rows, live
        from m2c.identity import Identity

        data, n, body = Path(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3])
        db = Database(data, 2 << 30)
        w = Writer(db.insert_file, data)
        w.start()
        ident = Identity("s1", "curl", "", "s1.curl", "request")
        payload = (b'{"role":"user","content":"' + b"hello world " * 100000)[:body] if body else b""
        f = tflow.tflow(resp=True)
        f.response.content = payload
        # hook-side cost: build the row and the live summary, queue it
        t0 = time.perf_counter()
        for i in range(n):
            row = rows.http_row(f, ident, "bench", i + 1, "")
            row["flow_id"] = uuid.uuid4()
            live.summary(row)
            w.put("http_flows", row)
        hook_s = time.perf_counter() - t0
        while sum(w.counters.written.values()) + sum(w.counters.dropped.values()) < n:
            time.sleep(0.01)
        total_s = time.perf_counter() - t0
        w.stop(30)
        stored = int(db.scalar("SELECT count() FROM m2c.http_flows"))
        print(json.dumps({"rows": n, "body_bytes": body, "hook_us_per_flow": round(hook_s / n * 1e6, 1),
                          "rows_per_s": round(n / total_s), "mb_per_s": round(n * body / total_s / 1e6, 1),
                          "stored": stored, "dropped": sum(w.counters.dropped.values()), "batches": w.counters.batches,
                          "max_batch_ms": round(w.counters.max_batch_ms, 1)}))
    """)
    out = {}
    for label, n, body in [("small_rows", 20000 if quick else 100000, 0), ("2KiB_bodies", 20000 if quick else 100000, 2048),
                           ("64KiB_bodies", 2000 if quick else 10000, 65536)]:
        data = WORK / f"ingest-{label}"
        shutil.rmtree(data, ignore_errors=True)
        res = subprocess.run([PY, "-c", script, str(data), str(n), str(body)], capture_output=True, text=True, cwd=ROOT)
        if res.returncode:
            raise RuntimeError(res.stderr[-2000:])
        out[label] = json.loads(res.stdout.strip().splitlines()[-1])
        log(f"ingest {label}: {out[label]}")
    return out


GEN_SCRIPT = textwrap.dedent("""
    import json, os, random, sys, time, uuid
    from pathlib import Path
    from m2c.db import Database
    from m2c import schema, rowbinary

    data, n, kind = Path(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
    d = Database(data)
    enc = rowbinary.encoder(schema.HTTP_FLOWS)
    rnd = random.Random(1)
    sessions = [f"run{i}" for i in range(50)]
    tools = ["curl", "nuclei", "python-requests", "sqlmap", "ffuf", "browser"]
    hosts = [f"h{i}.acme.test" for i in range(300)]
    base = int(time.time() * 1000) - 3_600_000
    history = {}
    t0 = time.time(); batch = []
    for n_ in range(1, n + 1):
        s = rnd.choice(sessions)
        if kind == "llm":
            # an agent conversation: every request resends the growing history, the answer is a new message
            msgs = history.setdefault(s, [])
            msgs.append({"role": "user", "content": f"Step {len(msgs)}: check {rnd.choice(hosts)} for issues and report."})
            req = json.dumps({"model": "claude-x", "max_tokens": 4096, "messages": msgs[-40:]}).encode()
            answer = f"I checked the target. Finding {n_ % 97}: the endpoint /api/v{n_ % 5}/items returned {rnd.choice([200, 403, 500])}. " * 6
            msgs.append({"role": "assistant", "content": answer})
            resp = json.dumps({"id": f"msg_{n_}", "content": [{"type": "text", "text": answer}], "usage": {"input_tokens": len(req) // 4}}).encode()
            host, path = "api.llm.example", "/v1/messages"
        else:
            req = b""
            resp = b'{"ok":true,"id":%d,"items":[1,2,3]}' % n_ + os.urandom(rnd.randint(0, 600))
            host, path = rnd.choice(hosts), f"/api/v1/items/{n_}"
        batch.append(enc({"scan_id": "bench", "flow_id": uuid.uuid4(), "n": n_, "ts_start": base + n_ * 3, "ts_end": base + n_ * 3 + 20,
            "session": s, "tool": rnd.choice(tools), "method": "POST" if req else rnd.choice(["GET", "GET", "POST"]), "host": host,
            "path": path, "url": f"https://{host}{path}", "status": rnd.choice([200] * 8 + [404, 500]),
            "req_headers": [(b"User-Agent", b"curl/8"), (b"Accept", b"*/*"), (b"Content-Type", b"application/json")],
            "resp_headers": [(b"Content-Type", b"application/json"), (b"Server", b"bench")],
            "req_body": req, "req_body_size": len(req), "resp_body": resp, "resp_body_size": len(resp), "resp_capture": "buffered",
            "end_reason": "complete", "duration_ms": 20}))
        if len(batch) == 5000:
            d.insert("http_flows", schema.HTTP_FLOWS.names, b"".join(batch)); batch = []
    if batch:
        d.insert("http_flows", schema.HTTP_FLOWS.names, b"".join(batch))
    d.writer.query("OPTIMIZE TABLE m2c.http_flows FINAL")
    parts = d.scalar("SELECT sum(rows), sum(data_compressed_bytes), sum(data_uncompressed_bytes) FROM system.parts WHERE active AND table = 'http_flows'").split("\\t")
    bodies = d.scalar("SELECT sum(length(req_body) + length(resp_body)) FROM m2c.http_flows")
    print(json.dumps({"rows": int(parts[0]), "compressed_bytes": int(parts[1]), "uncompressed_bytes": int(parts[2]),
                      "body_bytes": int(bodies), "seconds": round(time.time() - t0, 1)}))
""")


def generate(data: Path, n: int, kind: str) -> dict:
    shutil.rmtree(data, ignore_errors=True)
    res = subprocess.run([PY, "-c", GEN_SCRIPT, str(data), str(n), kind], capture_output=True, text=True, cwd=ROOT)
    if res.returncode:
        raise RuntimeError(res.stderr[-2000:])
    return json.loads(res.stdout.strip().splitlines()[-1])


def bench_storage(quick: bool) -> dict:
    out = {}
    for kind, n in (("llm", 20000 if quick else 50000), ("mixed", 50000 if quick else 200000)):
        g = generate(WORK / f"storage-{kind}", n, kind)
        g["bytes_per_flow_on_disk"] = round(g["compressed_bytes"] / g["rows"])
        g["compression_ratio"] = round(g["uncompressed_bytes"] / g["compressed_bytes"], 1)
        g["disk_bytes"] = sum(f.stat().st_size for f in (WORK / f"storage-{kind}").rglob("*") if f.is_file())
        out[kind] = g
        log(f"storage {kind}: {g}")
    return out


def timed(fn, runs: int = 9) -> dict:
    times = []
    for _ in range(runs):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    return {"median_ms": ms(statistics.median(times)), "best_ms": ms(min(times))}


def bench_queries(quick: bool) -> dict:
    out: dict = {}
    sizes = [100_000] if quick else [100_000, 1_000_000]
    for n in sizes:
        data = WORK / f"queries-{n}"
        gen = generate(data, n, "mixed")
        log(f"generated {n} flows in {gen['seconds']} s")
        p = Proc("m2c", data)
        url, token = p.api()
        u = urllib.parse.urlsplit(url)
        conn = http.client.HTTPConnection(u.hostname, u.port, timeout=60)

        def get(path):
            conn.request("GET", path, headers={"Authorization": f"Bearer {token}"})
            r = conn.getresponse()
            body = r.read()
            assert r.status == 200, (path, r.status, body[:200])
            return body

        mid = n // 2
        res = {
            "ls_newest_50": timed(lambda: get("/v1/flows?limit=50")),
            "ls_session_filter": timed(lambda: get("/v1/flows?limit=50&q=session:run7")),
            "ls_host_method": timed(lambda: get("/v1/flows?limit=50&q=host:h17.acme.test%20method:POST")),
            "ls_status_tool": timed(lambda: get("/v1/flows?limit=50&q=status:5xx%20tool:ffuf")),
            "ls_url_text": timed(lambda: get(f"/v1/flows?limit=50&q=items/{mid}")),
            "ls_page_cursor": timed(lambda: get(f"/v1/flows?limit=50&cursor={mid}")),
            "flow_detail": timed(lambda: get(f"/v1/flows/{mid}")),
            "flow_body": timed(lambda: get(f"/v1/flows/{mid}/body/resp")),
            "sessions": timed(lambda: get("/v1/sessions")),
            "scan_stats": timed(lambda: get("/v1/scan")),
            "body_search": timed(lambda: get("/v1/flows?limit=20&q=body:%22%5C%22id%5C%22:" + str(mid) + ",%22"), 5),
        }
        env = {**os.environ, "M2C_DATA": str(data)}
        res["cli_ls_online"] = timed(lambda: subprocess.run([str(VENV / "m2c"), "ls", "-n", "20"], env=env, capture_output=True, check=True), 5)
        p.stop()
        res["cli_ls_offline"] = timed(lambda: subprocess.run([str(VENV / "m2c"), "ls", "-n", "20"], env=env, capture_output=True, check=True), 3)
        out[str(n)] = res
        log(f"queries {n}: " + ", ".join(f"{k} {v['median_ms']}" for k, v in res.items()))
    return out


def bench_tail(quick: bool) -> dict:
    """From the client receiving its response to a /v1/tail subscriber receiving the flow."""
    up = Upstream()
    data = WORK / "tail"
    shutil.rmtree(data, ignore_errors=True)
    p = Proc("m2c", data)
    url, token = p.api()
    u = urllib.parse.urlsplit(url)
    sub = socket.create_connection((u.hostname, u.port))
    sub.sendall(f"GET /v1/tail HTTP/1.1\r\nHost: {u.hostname}:{u.port}\r\nAuthorization: Bearer {token}\r\n\r\n".encode())
    f = sub.makefile("rb")
    arrivals: dict[int, float] = {}

    def reader():
        kind = None
        for line in f:
            if line.startswith(b"event:"):
                kind = line[6:].strip()
            elif line.startswith(b"data:") and kind == b"flow":
                arrivals[json.loads(line[5:])["n"]] = time.perf_counter()

    threading.Thread(target=reader, daemon=True).start()
    time.sleep(0.5)
    done: dict[int, float] = {}
    c = http.client.HTTPConnection("127.0.0.1", p.port)
    for i in range(1, (50 if quick else 200) + 1):
        c.request("GET", f"http://127.0.0.1:{up.port}/x?n=200", headers={"Proxy-Authorization": p.auth})
        c.getresponse().read()
        done[i] = time.perf_counter()
        time.sleep(0.01)
    time.sleep(1)
    delays = [arrivals[n] - t for n, t in done.items() if n in arrivals]
    p.stop()
    return {"flows": len(done), "seen": len(delays), "p50_ms": ms(pct(delays, 0.5)), "p99_ms": ms(pct(delays, 0.99)), "max_ms": ms(max(delays))}


def bench_startup(quick: bool) -> dict:
    out = {}
    for label in ("empty_dir", "reopen_dir"):
        data = WORK / "startup"
        if label == "empty_dir":
            shutil.rmtree(data, ignore_errors=True)
        times = []
        for _ in range(3):
            p = Proc("m2c", data)
            times.append(p.startup_s)
            out.setdefault("idle_rss_mb", p.rss_mb()[0])
            p.stop()
            if label == "empty_dir":
                shutil.rmtree(data, ignore_errors=True)
        out[label] = {"median_s": round(statistics.median(times), 2)}
    b = Proc("baseline")
    out["baseline_mitmdump_s"] = round(b.startup_s, 2)
    out["baseline_idle_rss_mb"] = b.rss_mb()[0]
    b.stop()
    log(f"startup: {out}")
    return out


def bench_push(quick: bool, central: str, native_port: int) -> dict:
    u = urllib.parse.urlsplit(central)
    n = 100_000 if quick else 1_000_000
    data = WORK / f"queries-{n}"
    if not (data / "metadata").exists():
        generate(data, n, "mixed")
    out = {"rows": n}

    def ch(sql):
        req = urllib.request.Request(f"{u.scheme}://{u.hostname}:{u.port}/", data=sql.encode())
        req.add_header("X-ClickHouse-User", u.username)
        req.add_header("X-ClickHouse-Key", u.password)
        return urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=600).read()

    env = {**os.environ, "M2C_PUSH_PASSWORD": u.password}
    for label, target in (("native", f"clickhouse://{u.username}@{u.hostname}:{native_port}"), ("http", f"{u.scheme}://{u.username}@{u.hostname}:{u.port}")):
        db = f"m2c_bench_{label}"
        ch(f"DROP DATABASE IF EXISTS {db}")
        subprocess.run([str(VENV / "m2c"), "central", "init", "--to", f"{target}/{db}" if label == "http" else f"{u.scheme}://{u.username}@{u.hostname}:{u.port}/{db}"],
                       env=env, check=True, capture_output=True)
        t0 = time.perf_counter()
        subprocess.run([str(VENV / "m2c"), "push", "--data", str(data), "--to", f"{target}/{db}"], env=env, check=True, capture_output=True)
        first = time.perf_counter() - t0
        t0 = time.perf_counter()
        subprocess.run([str(VENV / "m2c"), "push", "--data", str(data), "--to", f"{target}/{db}"], env=env, check=True, capture_output=True)
        again = time.perf_counter() - t0
        stored = int(ch(f"SELECT count() FROM {db}.http_flows").decode())
        size = int(ch(f"SELECT sum(data_compressed_bytes) FROM system.parts WHERE active AND database = '{db}' AND table = 'http_flows'").decode())
        out[label] = {"seconds": round(first, 1), "rows_per_s": round(n / first), "stored": stored,
                      "mb_per_s_compressed": round(size / first / 1e6, 1), "repush_noop_s": round(again, 1)}
        ch(f"DROP DATABASE IF EXISTS {db}")
        log(f"push {label}: {out[label]}")
    return out


def environment() -> dict:
    """Software versions only: the results are meant to be shared, so they say nothing about the host."""
    versions = subprocess.run([PY, "-c", "import mitmproxy.version as m, importlib.metadata as md, m2c as x; "
                               "print(m.VERSION, md.version('chdb-core'), x.__version__)"], capture_output=True, text=True).stdout.split()
    return {"date": time.strftime("%Y-%m-%d %H:%M"), "python": platform.python_version(), "mitmproxy": versions[0],
            "chdb_core": versions[1], "m2c": versions[2]}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("what", choices=("all", "proxy", "latency", "ingest", "queries", "tail", "storage", "push", "startup"))
    ap.add_argument("--quick", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "bench" / "results.json"))
    ap.add_argument("--central", default=os.environ.get("M2C_BENCH_CENTRAL", "http://m2c:centralpw@127.0.0.1:18123"))
    ap.add_argument("--native-port", type=int, default=int(os.environ.get("M2C_BENCH_NATIVE_PORT", "19000")),
                    help="the central server's native protocol port (the dev container maps 9000 to 19000)")
    args = ap.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    CONF.mkdir(parents=True, exist_ok=True)
    results: dict = {}
    if args.what != "all" and Path(args.out).exists():
        results = json.loads(Path(args.out).read_text())  # one part: update it in the existing results
    env = environment()
    if args.what == "all" or "environment" not in results:
        results.update(environment=env, quick=args.quick)
    steps = ["startup", "proxy", "latency", "ingest", "tail", "storage", "queries", "push"] if args.what == "all" else [args.what]
    for step in steps:
        log(f"--- {step}")
        results.setdefault("environment_by_step", {})[step] = {"date": env["date"]}
        if step == "push":
            try:
                results["push"] = bench_push(args.quick, args.central, args.native_port)
            except OSError as e:
                results["push"] = {"skipped": str(e)}
        else:
            results[step] = globals()[f"bench_{step}"](args.quick)
        Path(args.out).write_text(json.dumps(results, indent=1) + "\n")
    print(json.dumps(results, indent=1))


if __name__ == "__main__":
    main()
