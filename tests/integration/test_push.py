"""Needs a ClickHouse server: M2C_TEST_CH_HTTP (default http://m2c:centralpw@127.0.0.1:18123) and
M2C_TEST_CH_NATIVE (default clickhouse://m2c:centralpw@127.0.0.1:19000). Skipped when it is not reachable."""

import json
import os
import subprocess
import sys
import textwrap
import urllib.parse
import urllib.request
import uuid

import pytest

import servers
from conftest import M2C, Proxy

pytestmark = pytest.mark.integration

HTTP = os.environ.get("M2C_TEST_CH_HTTP", "http://m2c:centralpw@127.0.0.1:18123")
NATIVE = os.environ.get("M2C_TEST_CH_NATIVE", "clickhouse://m2c:centralpw@127.0.0.1:19000")


def ch(sql: str) -> str:
    u = urllib.parse.urlsplit(HTTP)
    req = urllib.request.Request(f"{u.scheme}://{u.hostname}:{u.port}/", data=sql.encode())
    req.add_header("X-ClickHouse-User", u.username or "default")
    req.add_header("X-ClickHouse-Key", u.password or "")
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=30) as res:
        return res.read().decode().strip()


@pytest.fixture(scope="module")
def central():
    try:
        ch("SELECT 1")
    except OSError:
        pytest.skip("no ClickHouse server for push tests")
    db = "m2c_test_" + uuid.uuid4().hex[:8]
    u = urllib.parse.urlsplit(HTTP)
    url = f"{u.scheme}://{u.username}:{u.password}@{u.hostname}:{u.port}/{db}"
    subprocess.run([M2C, "central", "init", "--to", url], check=True, capture_output=True)
    yield db
    ch(f"DROP DATABASE IF EXISTS {db}")


def target(base: str, db: str) -> str:
    return f"{base}/{db}"


# chDB allows one data directory per process: scans built by hand, and in-process pushes, run in a child process.
PRELUDE = """
import json, sys, time
from m2c import push, schema
from m2c.db import open_session
s = open_session(sys.argv[1])
schema.ensure(lambda q: s.query(q))
run = lambda sql, fmt: s.query(sql, fmt).bytes()
q = s.query
"""


def py(data, code: str, *args: str) -> str:
    out = subprocess.run([sys.executable, "-c", PRELUDE + textwrap.dedent(code), str(data), *args], capture_output=True, text=True, check=False)
    assert out.returncode == 0, out.stderr
    return out.stdout


def flows(data, scan: str, count: int, tag: str = "", body: int = 0) -> None:
    py(data, f"""
        q('''INSERT INTO m2c.http_flows (scan_id, flow_id, n, ts_start, ts_end, path, req_body) SELECT '{scan}', generateUUIDv4(),
           number + 1, now64(3), now64(3), '{tag}', repeat('x', {body}) FROM numbers({count})''')
    """)


def push(data, url: str, check: bool = True) -> subprocess.CompletedProcess:
    out = subprocess.run([M2C, "push", "--data", str(data), "--to", url], capture_output=True, text=True, check=False,
                         env={**os.environ, "M2C_DATA": str(data)})
    if check:
        assert out.returncode == 0, out.stderr
    return out


def traffic(p: Proxy, upstream: int, session: str, paths):
    tok = p.token(session)
    for path in paths:
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", p.url(f"{session}.curl", tok), f"http://127.0.0.1:{upstream}{path}"], check=True)


@pytest.mark.parametrize("base", [NATIVE, HTTP], ids=["native", "http"])
def test_push_exact_idempotent_and_incremental(tmp_path, upstream, central, base):
    p = Proxy(tmp_path)
    traffic(p, upstream, "push1", ["/hello", "/bin", "/sse"])
    p.stop()
    scan = p.rows("SELECT any(scan_id) AS s FROM m2c.http_flows")[0]["s"]
    url = target(base, central)
    for _ in range(2):  # a second push sends nothing
        subprocess.run([M2C, "push", "--data", str(p.data), "--to", url, "--label", "ci=1"], check=True, capture_output=True, env=p.env)
    assert ch(f"SELECT count() FROM {central}.http_flows WHERE scan_id = '{scan}'") == "3"
    assert ch(f"SELECT count() FROM {central}.sse_events WHERE scan_id = '{scan}'") == "21"
    body = ch(f"SELECT hex(resp_body) FROM {central}.http_flows WHERE scan_id = '{scan}' AND path = '/bin'")
    assert bytes.fromhex(body) == servers.BINARY
    # the scan grows (restart, more traffic): only the new rows go out
    p = Proxy(tmp_path)
    traffic(p, upstream, "push1", ["/hello", "/gzip"])
    p.stop()
    out = subprocess.run([M2C, "push", "--data", str(p.data), "--to", url], check=True, capture_output=True, text=True, env=p.env)
    assert "2 rows sent" in out.stderr
    assert ch(f"SELECT count(), uniqExact(flow_id) FROM {central}.http_flows WHERE scan_id = '{scan}'") == "5\t5"
    assert ch(f"SELECT status, labels['ci'] FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "pushed\t1"


def test_push_on_exit(tmp_path, upstream, central):
    u = urllib.parse.urlsplit(HTTP)
    p = Proxy(tmp_path, extra=["--push-on-exit", f"{u.scheme}://{u.username}@{u.hostname}:{u.port}/{central}", "--label", "job=exit,b=c"],
              env={"M2C_PUSH_PASSWORD": u.password})
    traffic(p, upstream, "exit1", ["/hello"])
    p.stop()
    # the password went through the environment of the proxy process
    scan = p.rows("SELECT any(scan_id) AS s FROM m2c.http_flows")[0]["s"]
    assert ch(f"SELECT count() FROM {central}.http_flows WHERE scan_id = '{scan}'") == "1"
    assert ch(f"SELECT labels['job'] FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "exit,b=c"  # a value may hold ',' and '='
    assert not (p.data / "push-failed.json").exists()


@pytest.mark.parametrize("base", [NATIVE, HTTP], ids=["native", "http"])
def test_push_same_scan_id_from_two_directories(tmp_path, central, base):
    # parallel CI jobs sharing one --scan-id: every directory numbers its flows from 1
    scan = "ci-" + uuid.uuid4().hex[:8]
    for job in ("a", "b"):
        flows(tmp_path / job, scan, 10, f"/job-{job}")
        out = push(tmp_path / job, target(base, central))
        assert "10 rows sent" in out.stderr
    assert ch(f"SELECT path, count() FROM {central}.http_flows WHERE scan_id = '{scan}' GROUP BY path ORDER BY path") == "/job-a\t10\n/job-b\t10"
    assert ch(f"SELECT status, rows['http_flows'] FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "pushed\t20"
    assert "already there" in push(tmp_path / "a", target(base, central)).stderr
    assert ch(f"SELECT count() FROM {central}.http_flows WHERE scan_id = '{scan}'") == "20"


def test_repush_after_central_rows_were_deleted(tmp_path, central):
    scan = "del-" + uuid.uuid4().hex[:8]
    flows(tmp_path, scan, 50)
    push(tmp_path, target(HTTP, central))
    ch(f"ALTER TABLE {central}.http_flows DELETE WHERE scan_id = '{scan}' SETTINGS mutations_sync = 2")
    # the same rows give the same dedup token, which the server still remembers
    out = push(tmp_path, target(HTTP, central))
    assert "deduplicated by the server" in out.stderr
    assert ch(f"SELECT count(), uniqExact(flow_id) FROM {central}.http_flows WHERE scan_id = '{scan}'") == "50\t50"


def test_push_to_unreachable_server_fails_cleanly(tmp_path):
    flows(tmp_path, "unreach", 3)
    out = subprocess.run([M2C, "push", "--data", str(tmp_path), "--to", "http://m2c@127.0.0.1:1/m2c"], capture_output=True, text=True, check=False,
                         env={**os.environ, "M2C_PUSH_PASSWORD": "Secret-pw-123"})
    assert out.returncode == 1
    assert "m2c: push failed:" in out.stderr and "Traceback" not in out.stderr
    assert "attempt 1 failed, retrying" in out.stderr
    assert "Secret-pw-123" not in out.stderr


def test_transient_remote_errors_are_retried(tmp_path, central):
    scan = "flaky-" + uuid.uuid4().hex[:8]
    flows(tmp_path, scan, 5)
    out = py(tmp_path, """
        failed = set()
        def flaky(sql, fmt):
            # the first insert of each kind (scans row, chunk) fails once
            kind = "scans" if ".scans" in sql else "chunk" if sql.startswith("INSERT") else ""
            if kind and kind not in failed:
                failed.add(kind)
                raise RuntimeError("Code: 210. DB::NetException: Connection reset by peer")
            return run(sql, fmt)
        msgs = []
        result = push.Pusher(flaky, push.Target.parse(sys.argv[2]), progress=msgs.append).push()
        print(json.dumps({"status": result["status"], "msgs": msgs}))
    """, target(HTTP, central))
    result = json.loads(out)
    assert result["status"] == "pushed"
    assert sum("attempt 1 failed" in m for m in result["msgs"]) == 2
    assert ch(f"SELECT count() FROM {central}.http_flows WHERE scan_id = '{scan}'") == "5"
    assert ch(f"SELECT status FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "pushed"


@pytest.mark.parametrize("base", [NATIVE, HTTP], ids=["native", "http"])
def test_push_splits_buckets_larger_than_a_chunk(tmp_path, central, base):
    scan = "big-" + uuid.uuid4().hex[:8]
    flows(tmp_path, scan, 30, body=100_000)  # one n bucket of ~3 MiB
    py(tmp_path, f"""
        # one WebSocket of 3000 messages: all of them carry the flow's n
        q('''INSERT INTO m2c.ws_messages (scan_id, flow_id, n, seq, ts, content) SELECT '{scan}', toUUID('00000000-0000-0000-0000-000000000001'),
           5000, number, now64(3), repeat('y', 1000) FROM numbers(3000)''')
    """)
    code = """
        msgs = []
        result = push.Pusher(run, push.Target.parse(sys.argv[2]), chunk_bytes=1 << 20, progress=msgs.append).push()
        print(json.dumps(msgs))
    """
    msgs = json.loads(py(tmp_path, code, target(base, central)))
    flow_chunks = [m for m in msgs if m.startswith("  http_flows") and "rows sent" in m]
    ws_chunks = [m for m in msgs if m.startswith("  ws_messages") and "rows sent" in m]
    assert len(flow_chunks) >= 3 and len(ws_chunks) >= 3, msgs
    assert ch(f"SELECT count(), uniqExact(flow_id) FROM {central}.http_flows WHERE scan_id = '{scan}'") == "30\t30"
    assert ch(f"SELECT count(), uniqExact(seq), min(seq), max(seq) FROM {central}.ws_messages WHERE scan_id = '{scan}'") == "3000\t3000\t0\t2999"
    msgs = json.loads(py(tmp_path, code, target(base, central)))  # nothing goes twice
    assert not [m for m in msgs if "rows sent" in m and not m.endswith(": 0 rows sent")], msgs


def test_scan_without_flows_ends_at_its_last_event(tmp_path):
    out = py(tmp_path, """
        q("INSERT INTO m2c.proxy_events (scan_id, ts, kind) VALUES ('ev', '2026-09-30 09:00:00', 'started'), ('ev', '2026-09-30 11:00:00', 'stopped')")
        meta = push.Pusher(run, push.Target.parse("http://m2c@127.0.0.1:1/m2c")).meta({})
        print(json.dumps([meta["started_at"], meta["ended_at"]]))
    """)
    assert json.loads(out) == [1790758800000, 1790766000000]  # 09:00 and 11:00 UTC, not 1970


def test_target_brackets_ipv6_hosts():
    from m2c.push import Target

    t = Target.parse("http://m2c:pw@[::1]:8123/m2c")
    assert t.redacted == "http://m2c@[::1]:8123/m2c"
    assert "url('http://[::1]:8123/?" in t.table_function("scans", "x String")
    n = Target.parse("clickhouse://m2c:pw@[fd00::5]/m2c")
    assert n.table_function("scans", "").startswith("remote('[fd00::5]:9000', ")


def test_scans_table_follows_a_replicated_engine():
    from m2c.push import central_statements

    def scans(engine):
        return next(s for s in central_statements("m2c", engine, on_cluster="c1") if "m2c.scans" in s)

    assert "ENGINE = ReplacingMergeTree(pushed_at)" in scans("MergeTree")
    assert "ENGINE = ReplicatedReplacingMergeTree(pushed_at)" in scans("ReplicatedMergeTree")
    assert "ENGINE = ReplicatedReplacingMergeTree('/ch/{database}/{table}', '{replica}', pushed_at)" in scans(
        "ReplicatedMergeTree('/ch/{database}/{table}', '{replica}')")
    assert "CREATE TABLE IF NOT EXISTS m2c.scans ON CLUSTER c1" in scans("ReplicatedMergeTree")


@pytest.mark.parametrize("base", [NATIVE, HTTP], ids=["native", "http"])
def test_repush_after_one_directorys_rows_were_deleted(tmp_path, central, base):
    # central still holds as many rows of the scan (job b's) as job a has: the resend must not depend on the count
    scan = "deltwo-" + uuid.uuid4().hex[:8]
    for job in ("a", "b"):
        flows(tmp_path / job, scan, 10, f"/job-{job}")
        push(tmp_path / job, target(base, central))
    ch(f"ALTER TABLE {central}.http_flows DELETE WHERE scan_id = '{scan}' AND path = '/job-a' SETTINGS mutations_sync = 2")
    out = push(tmp_path / "a", target(base, central))
    assert "deduplicated by the server" in out.stderr
    assert ch(f"SELECT path, count() FROM {central}.http_flows WHERE scan_id = '{scan}' GROUP BY path ORDER BY path") == "/job-a\t10\n/job-b\t10"
    assert ch(f"SELECT status FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "pushed"


def test_push_splits_a_group_of_large_messages(tmp_path, central):
    # 100 SSE events of 50 KB share one (n, seq / 100) group: 5 MB, five times a 1 MiB chunk
    scan = "bigev-" + uuid.uuid4().hex[:8]
    flows(tmp_path, scan, 1)
    py(tmp_path, f"""
        q('''INSERT INTO m2c.sse_events (scan_id, flow_id, n, seq, ts, data) SELECT '{scan}', toUUID('00000000-0000-0000-0000-000000000002'),
           1, number, now64(3), repeat('z', 50000) FROM numbers(100)''')
    """)
    msgs = json.loads(py(tmp_path, """
        msgs = []
        push.Pusher(run, push.Target.parse(sys.argv[2]), chunk_bytes=1 << 20, progress=msgs.append).push()
        print(json.dumps(msgs))
    """, target(HTTP, central)))
    chunks = [m for m in msgs if m.startswith("  sse_events") and "rows sent" in m]
    assert len(chunks) >= 5, msgs
    assert ch(f"SELECT count(), uniqExact(seq) FROM {central}.sse_events WHERE scan_id = '{scan}'") == "100\t100"


def test_interrupted_push_marks_the_scan_failed(tmp_path, central):
    scan = "intr-" + uuid.uuid4().hex[:8]
    flows(tmp_path, scan, 5)
    py(tmp_path, """
        def interrupt(sql, fmt):
            if sql.startswith("INSERT") and ".scans" not in sql:
                raise KeyboardInterrupt
            return run(sql, fmt)
        try:
            push.Pusher(interrupt, push.Target.parse(sys.argv[2])).push()
        except KeyboardInterrupt:
            pass
    """, target(HTTP, central))
    assert ch(f"SELECT status, message FROM {central}.scans FINAL WHERE scan_id = '{scan}'") == "failed\tKeyboardInterrupt"


def test_manual_push_clears_the_marker_and_reports_rejected_spool_rows(tmp_path, central):
    data = tmp_path / "data"
    flows(data, "manual-" + uuid.uuid4().hex[:8], 3)
    (data / "spool").mkdir()
    (data / "spool" / "http_flows.1-1.2.rowbinary").write_bytes(b"\x07torn")  # cut off mid-row by a crash
    (data / "push-failed.json").write_text('{"error": "push-on-exit failed"}\n')
    u = urllib.parse.urlsplit(HTTP)
    out = push(data, f"{u.scheme}://{u.username}:{u.password}@{u.hostname}:{u.port}/{central}")
    assert "rows from" in out.stderr and "rejected" in out.stderr and "they are not pushed" in out.stderr
    assert not (data / "push-failed.json").exists()
    assert list((data / "dead").glob("*.rowbinary"))


def test_push_carries_annotations(central, tmp_path):
    data = tmp_path / "data"
    flows(data, "scan-notes", 3)
    py(data, """
        q('''INSERT INTO m2c.annotations (scan_id, id, ts, n, session, author, author_kind, label, note, deleted) VALUES
             ('scan-notes', '6f1c1c55-0000-4000-8000-000000000001', now64(3), 1, 's', 'admin', 'admin', 'vuln', 'first', false),
             ('scan-notes', '6f1c1c55-0000-4000-8000-000000000001', now64(3) + 1, 1, 's', 'admin', 'admin', 'vuln', 'edited', false)''')
    """)
    url = target(HTTP, central)
    push(data, url)
    push(data, url)  # again: nothing doubles
    assert ch(f"SELECT count() FROM {central}.annotations WHERE scan_id = 'scan-notes'") == "2"
    assert ch(f"SELECT argMax(note, ts) FROM {central}.annotations WHERE scan_id = 'scan-notes' GROUP BY id") == "edited"
