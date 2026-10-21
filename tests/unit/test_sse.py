import gzip
import random
import time
import zlib

from hypothesis import given, settings, strategies as st

from m2c.sse import SseParser
from m2c.tee import BodyTee, SseTee

STREAM = (
    "﻿: hello comment\r\n"
    "event: message_start\r\n"
    "data: {\"a\": 1}\r\n\r\n"
    "data: line one\n"
    "data:line two\n"
    "id: 42\n\n"
    "retry: 3000\r\r"
    "event: done\n"
    "data: é😀 multi-byte\n\n"
    "data: [DONE]\n\n"
).encode()


def parse(chunks, cap=64 * 1024):
    out = []
    p = SseParser(out.append, cap)
    for c in chunks:
        p.feed(c)
    p.close()
    return out, p


def test_events():
    events, p = parse([STREAM])
    assert [(e.event, e.data, e.id, e.retry_ms) for e in events] == [
        ("message_start", '{"a": 1}', "", 0),
        ("", "line one\nline two", "42", 0),
        ("", "", "", 3000),
        ("done", "é😀 multi-byte", "", 0),
        ("", "[DONE]", "", 0),
    ]
    assert p.comments == 1
    assert not any(e.partial for e in events)


@settings(max_examples=300, deadline=None)
@given(st.lists(st.integers(min_value=1, max_value=len(STREAM)), max_size=20))
def test_any_chunking_gives_same_events(cuts):
    cuts = sorted(set(cuts))
    chunks, last = [], 0
    for c in cuts:
        chunks.append(STREAM[last:c])
        last = c
    chunks.append(STREAM[last:])
    assert parse(chunks)[0] == parse([STREAM])[0]


def test_partial_and_caps():
    events, _ = parse([b"data: unterminated"])
    assert len(events) == 1 and events[0].partial and events[0].data == "unterminated"
    events, _ = parse([b"data: " + b"x" * 5000 + b"\n\n"], cap=100)
    assert events[0].truncated and len(events[0].data) <= 100 and events[0].size == 5000
    events, _ = parse([b"data: " + b"y" * 300 + b"\ndata: next\n\n"], cap=50)
    assert events[0].truncated and events[0].data.startswith("y")


def test_sse_tee_gzip_passthrough_and_past_cap():
    body = b"".join(b"data: %d\n\n" % i for i in range(5000))
    gz = gzip.compress(body)
    got = []
    tee = SseTee(cap=100, parser=SseParser(got.append), content_encoding="gzip")
    out = b""
    rnd = random.Random(1)
    i = 0
    while i < len(gz):
        step = rnd.randint(1, 300)
        out += tee(gz[i : i + step])
        i += step
    assert tee(b"") == b""
    assert out == gz
    assert len(got) == 5000 and got[-1].data == "4999"
    assert tee.kept == 100 and tee.size == len(gz) and tee.truncated


def test_tee_never_breaks_stream():
    errors = []

    class Boom(BodyTee):
        def observe(self, chunk):
            raise ValueError("bug")

    tee = Boom(10, on_error=lambda: errors.append(1))
    assert tee(b"abc") == b"abc" and tee(b"def") == b"def"
    assert tee.broken and errors == [1]


def test_tee_chains_inner():
    tee = BodyTee(4, inner=lambda c: c.upper())
    assert tee(b"abcdef") == b"ABCDEF"
    assert tee.captured == b"ABCD" and tee.size == 6


@settings(max_examples=200, deadline=None)
@given(st.lists(st.integers(min_value=1, max_value=len(STREAM)), max_size=20))
def test_any_chunking_gives_same_events_with_tiny_cap(cuts):
    cuts = sorted(set(cuts))
    chunks = [STREAM[a:b] for a, b in zip([0, *cuts], [*cuts, len(STREAM)])]
    assert parse(chunks, cap=5)[0] == parse([STREAM], cap=5)[0]


def test_parse_time_is_linear_on_lf_only_streams():
    # Regression: one find("\r") per line scanned to the end of an LF-only chunk, so 1 MiB took over a second.
    def best(size):
        chunk = (b'data: {"tok": 1}\n\n' * (size // 19 + 1))[:size]
        times = []
        for _ in range(3):
            p = SseParser(lambda e: None)
            t0 = time.perf_counter()
            p.feed(chunk)
            times.append(time.perf_counter() - t0)
        return min(times)

    small, big = best(64 << 10), best(1 << 20)
    assert big < 2 and big / small < 40, (small, big)  # linear is ~16x; quadratic was ~80x


def test_data_cap_holds_for_many_data_lines():
    events, p = parse([b"data: a\n" * 200_000 + b"\n"], cap=1000)
    e = events[0]
    assert e.truncated and e.data == "\n".join(["a"] * 500)  # a 501st "a" would need 1001 characters
    assert e.size == 200_000 * 2 - 1  # size counts every line and joining LF past the cap
    p = SseParser(lambda e: None, event_cap=100)
    for _ in range(20):
        p.feed(b"data:\n" * 10_000)  # an event that never ends must not grow the parser
    assert len(p._data) <= 101 and p._data_len <= 100
    events, _ = parse([b"data: abc\ndata: def\n\n"], cap=7)
    assert events[0].data == "abc\ndef" and not events[0].truncated
    events, _ = parse([b"data: abc\ndata: defg\n\n"], cap=7)
    assert events[0].data == "abc\ndef" and events[0].truncated


def test_lone_cr_at_eof_is_partial():
    for stream in (b"data: x\r", b"data: x\n", b"data: x\r\n"):
        events, _ = parse([stream])
        assert [(e.data, e.partial) for e in events] == [("x", True)], stream
    events, _ = parse([b"data: x\r", b"\r"])
    assert [(e.data, e.partial) for e in events] == [("x", False)]
    events, _ = parse([b"data: x\r", b"\ndata: y\r\n\r\n"])
    assert [(e.data, e.partial) for e in events] == [("x\ny", False)]


def test_tee_chains_generator_inner():
    tee = BodyTee(10, inner=lambda c: (x for x in [c.upper()]))
    assert tee(b"abc") == b"ABC" and tee(b"") == b""
    assert tee.captured == b"ABC" and tee.ended


def test_tee_end_is_the_input_end_not_the_inner_output():
    held = []

    def buffering(c):  # holds everything back until mitmproxy's end-of-body call
        if c:
            held.append(c)
            return b""
        return b"".join(held)

    got = []
    tee = SseTee(100, SseParser(got.append), None, inner=buffering)
    assert tee(b"data: 1\n\n") == b"" and not tee.ended and not tee.closed
    assert tee(b"data: 2\n\n") == b""
    assert tee(b"") == b"data: 1\n\ndata: 2\n\n"
    assert tee.ended and tee.closed and [e.data for e in got] == ["1", "2"]
    assert tee.captured == b"data: 1\n\ndata: 2\n\n"


def test_sse_decode_error_keeps_raw_capture_and_size():
    errors = []
    body = b"".join(b"data: %d\n\n" % i for i in range(50))  # plain text labelled gzip
    tee = SseTee(10_000, SseParser(lambda e: None), "gzip", on_error=lambda: errors.append(1))
    for i in range(0, len(body), 15):
        tee(body[i : i + 15])
    tee(b"")
    assert tee.size == len(body) and tee.captured == body and not tee.truncated
    assert not tee.broken and not tee.parsing and "decoding failed" in tee.parse_error
    assert errors == []  # the server's fault, not a tee error


def test_sse_parser_bug_keeps_raw_capture():
    errors = []

    def boom(e):
        raise ValueError("sink bug")

    tee = SseTee(5, SseParser(boom), None, on_error=lambda: errors.append(1))
    for c in (b"data: 1\n\n", b"data: 2\n\n", b""):
        tee(c)
    assert tee.size == 18 and tee.captured == b"data:" and tee.truncated
    assert not tee.broken and tee.parse_error == "parser failed" and errors == [1]


def test_sse_bomb_stops_parsing_quickly():
    c = zlib.compressobj(wbits=31)
    bomb = c.compress(b"data: x\n\n" * 1_000_000) + c.flush(zlib.Z_SYNC_FLUSH)
    seen = []
    tee = SseTee(1 << 20, SseParser(lambda e: seen.append(1)), "gzip")
    t0 = time.perf_counter()
    assert tee(bomb) == bomb
    assert time.perf_counter() - t0 < 2
    assert not tee.parsing and "decoded bytes" in tee.parse_error
    assert 0 < len(seen) <= SseTee.DECODE_LIMIT // 9 and tee.size == len(bomb)
