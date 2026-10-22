import base64
import gzip
import struct

import pytest
from hypothesis import given, settings, strategies as st

from m2c import grpc
from m2c.filters import FilterError, compile_filter, matcher
from m2c.rows import finalize


def frame(payload: bytes, flags: int = 0) -> bytes:
    return struct.pack(">BI", flags, len(payload)) + payload


MESSAGES = [b"\x0a\x03ann\x10\x07", b"", b"x" * 300, b"\x00\xff" * 10]
BODY = b"".join(frame(m) for m in MESSAGES)


def split(body: bytes, cuts, **kw):
    out = []
    f = grpc.Framer(out.append, **kw)
    last = 0
    for c in sorted(set(cuts)):
        f.feed(body[last:c])
        last = c
    f.feed(body[last:])
    f.close()
    return out


def test_messages_in_order():
    got = split(BODY, [])
    assert [m.data for m in got] == MESSAGES
    assert [m.size for m in got] == [len(m) for m in MESSAGES]
    assert not any(m.partial or m.truncated or m.compressed for m in got)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.integers(min_value=0, max_value=len(BODY)), max_size=25))
def test_any_chunking_gives_the_same_messages(cuts):
    assert [m.data for m in split(BODY, cuts)] == MESSAGES


def test_cap_keeps_prefix_and_declared_size():
    got = split(frame(b"a" * 1000), [], msg_cap=10)
    assert got[0].data == b"a" * 10 and got[0].size == 1000 and got[0].truncated


def test_huge_declared_length_does_not_allocate():
    # a prefix claiming 4 GiB: the framer keeps at most msg_cap bytes and reports a partial message at the end
    got = split(struct.pack(">BI", 0, 0xFFFFFFFF) + b"abc", [], msg_cap=16)
    assert len(got) == 1 and got[0].partial and got[0].size == 0xFFFFFFFF and got[0].data == b"abc"


def test_cut_short_and_garbage():
    assert split(frame(b"hello")[:-2], [])[0].partial
    assert split(b"\x00\x00", []) == []  # a prefix cut short is not a message
    with pytest.raises(grpc.FramingError):
        grpc.Framer(lambda m: None).feed(b"\x42\x00\x00\x00\x01x")


def test_compressed_flag_and_web_trailer_frame():
    got = split(frame(gzip.compress(b"payload"), 1) + frame(b"grpc-status: 5\r\ngrpc-message: not%20here\r\n", 0x80), [])
    assert got[0].compressed and not got[0].trailer
    assert got[1].trailer
    status = grpc.status_of((), (), grpc.parse_trailer_block(got[1].data))
    assert (status.code, status.message, status.source) == (5, "not here", "web-trailer")


def test_grpc_web_text_is_base64_in_any_chunks():
    text = base64.b64encode(BODY)
    for step in (1, 3, 7, 64):
        out = []
        f = grpc.Framer(out.append, text=True)
        for i in range(0, len(text), step):
            f.feed(text[i : i + step])
        f.close()
        assert [m.data for m in out] == MESSAGES


def test_status_sources_and_inference():
    assert grpc.status_of([(b"grpc-status", b"0")], [], []).source == "trailers"
    s = grpc.status_of([], [("grpc-status", "3"), ("grpc-message", "bad%20arg")], [])
    assert (s.code, s.message, s.source) == (3, "bad arg", "headers")
    assert grpc.status_of([], [], [], "client_abort", timeout=1000, duration_ms=1005).code == grpc.CODES["DEADLINE_EXCEEDED"]
    assert grpc.status_of([], [], [], "client_abort", timeout=1000, duration_ms=100).code == grpc.CODES["CANCELLED"]
    assert grpc.status_of([], [], [], "upstream_connect").code == grpc.CODES["UNAVAILABLE"]
    assert grpc.status_of([], [], []).code == grpc.NO_STATUS
    assert grpc.status_name(3) == "INVALID_ARGUMENT" and grpc.status_name(-1) == "" and grpc.status_name(99) == "99"


def test_small_parsers():
    assert grpc.kind("application/grpc") == "grpc" and grpc.kind("application/grpc+proto; charset=x") == "grpc"
    assert grpc.kind("application/grpc-web+proto") == "grpc-web" and grpc.kind("application/grpc-web-text") == "grpc-web-text"
    assert grpc.kind("application/json") is None and grpc.kind("application/grpcx") is None
    assert grpc.service_method("/pkg.Svc/Do") == ("pkg.Svc", "Do") and grpc.service_method("/x") == ("", "")
    assert [grpc.timeout_ms(v) for v in ("1010m", "5S", "2M", "100u", "x", "", None)] == [1010, 5000, 120000, 0, 0, 0, 0]


def test_decode_schemaless_and_errors():
    text, how = grpc.decode(b"\x0a\x03ann\x10\x07", "/demo.Demo/Unary", True)
    assert how == "schemaless" and "ann" in text and "7" in text
    assert grpc.decode(b"", "/a/b", True) == ("", "empty")
    _, how = grpc.decode(b"\x0a\x03ann", "/demo.Demo/Unary", True, "/nonexistent.proto")
    assert how.startswith("error")


def test_writer_side_decompression_is_bounded():
    row = finalize("grpc_messages", {"compressed": True, "encoding": "gzip", "data": gzip.compress(b"z" * 100_000)}, 1000)
    assert row["decompressed"] and len(row["data"]) == 1000 and row["truncated"]
    row = finalize("grpc_messages", {"compressed": True, "encoding": "snappy", "data": b"raw"}, 1000)
    assert row["data"] == b"raw" and not row.get("decompressed")


SUMMARY = {"grpc": True, "grpc_service": "demo.v1.Demo", "grpc_method": "Fail", "grpc_status": 3, "status": 200, "error": ""}


@pytest.mark.parametrize("q,expected", [
    ("has:grpc", True), ("grpc:demo.v1.Demo/*", True), ("grpc:demo.v1.Demo/Fail", True), ("grpc:other.Svc", False),
    ("gstatus:3", True), ("gstatus:INVALID_ARGUMENT", True), ("gstatus:!0", True), ("gstatus:0", False), ("has:error", True),
    ("gstatus:ok", False), ("gstatus:nope", None), ("gstatus:999", None),
])
def test_grpc_filters(q, expected):
    if expected is None:
        with pytest.raises(FilterError):
            compile_filter(q)
        return
    assert matcher(q)(SUMMARY) is expected
    where, _ = compile_filter(q)
    assert "grpc" in where or "error" in where
