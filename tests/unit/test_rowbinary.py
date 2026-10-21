import os
import uuid

import pytest

from m2c import rowbinary, schema
from m2c.db import Database


@pytest.fixture(scope="module")
def db(tmp_path_factory):
    d = Database(tmp_path_factory.mktemp("rb") / "data")
    yield d
    d.close()


def test_every_table_roundtrips(db):
    for name, table in schema.TABLES.items():
        enc = rowbinary.encoder(table)
        db.insert(name, table.names, enc({}) + enc({"scan_id": "x"}))
        assert db.scalar(f"SELECT count() FROM m2c.{name} WHERE scan_id IN ('', 'x')") == "2"


def test_bytes_and_types_exact(db):
    body = os.urandom(5000) + bytes(range(256))
    fid = uuid.uuid4()
    row = {
        "scan_id": "exact", "flow_id": fid, "n": 2**40, "ts_start": 1_700_000_000_123, "ts_end": 1_700_000_000.5,
        "client_ip": "10.0.0.1", "server_ip": "2001:db8::2", "port": 70000, "resp_body": body,
        "req_headers": [(b"A", b"\xff\x00"), ("B", "é")], "status": 404, "tls": True,
        "identity_source": "socks5", "resp_capture": "websocket", "end_reason": "proxy_shutdown",
    }
    db.insert("http_flows", schema.HTTP_FLOWS.names, rowbinary.encoder(schema.HTTP_FLOWS)(row))
    got = db.scalar(
        "SELECT toString(flow_id), n, toUnixTimestamp64Milli(ts_start), toUnixTimestamp64Milli(ts_end), toString(client_ip), "
        "toString(server_ip), port, hex(resp_body) = {h:String}, hex(req_headers[1].value), req_headers[2].value, status, tls, "
        "identity_source, resp_capture, end_reason FROM m2c.http_flows WHERE scan_id = 'exact'",
        {"h": body.hex().upper()},
    ).split("\t")
    assert got == [str(fid), str(2**40), "1700000000123", "1700000000500", "::ffff:10.0.0.1", "2001:db8::2", "65535", "1",
                   "FF00", "é", "404", "true", "socks5", "websocket", "proxy_shutdown"]


def test_unknown_type_rejected():
    with pytest.raises(ValueError):
        rowbinary.type_encoder("Float64")


def test_memory_limit_ignores_the_cgroup(db):
    # Otherwise a desktop session's other processes count against m2c_memory_limit (seen: 1.9 GiB of Chrome + agent).
    assert db.scalar("SELECT value FROM system.server_settings WHERE name = 'memory_worker_use_cgroup'") == "0"


def test_insert_file_dedups_by_token(db, tmp_path):
    enc = rowbinary.encoder(schema.PROXY_EVENTS)
    path = tmp_path / "batch.rowbinary"
    path.write_bytes(b"".join(enc({"scan_id": "dedup", "kind": f"k{i}"}) for i in range(5)))
    for token in ("t1", "t1", "t2"):
        db.insert_file("proxy_events", schema.PROXY_EVENTS.names, path, token)
    assert db.scalar("SELECT count() FROM m2c.proxy_events WHERE scan_id = 'dedup'") == "10"
