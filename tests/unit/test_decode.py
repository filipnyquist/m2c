import gzip
import os
import zlib

import brotli
import zstandard

from m2c.decode import StreamDecoder, decode_body

DATA = os.urandom(2000) + b"hello world " * 5000


def test_codings_roundtrip():
    deflate_raw = zlib.compressobj(wbits=-15)
    for raw, coding in [
        (gzip.compress(DATA), "gzip"),
        (zlib.compress(DATA), "deflate"),
        (deflate_raw.compress(DATA) + deflate_raw.flush(), "deflate"),
        (brotli.compress(DATA), "br"),
        (zstandard.ZstdCompressor().compress(DATA), "zstd"),
    ]:
        body, decoded, truncated = decode_body(raw, coding, len(DATA) + 10)
        assert (body, decoded, truncated) == (DATA, True, False), coding


def test_stacked_codings():
    raw = brotli.compress(gzip.compress(DATA))
    assert decode_body(raw, "gzip, br", 1 << 20)[0] == DATA


def test_bomb_is_bounded():
    bomb = gzip.compress(b"\0" * (50 << 20))
    body, decoded, truncated = decode_body(bomb, "gzip", 1000)
    assert len(body) == 1000 and decoded and truncated
    body, decoded, truncated = decode_body(zstandard.ZstdCompressor().compress(b"\0" * (50 << 20)), "zstd", 1000)
    assert len(body) == 1000 and truncated
    body, _, truncated = decode_body(brotli.compress(b"\0" * (50 << 20)), "br", 1000)
    assert len(body) == 1000 and truncated


def test_undecodable_keeps_raw():
    assert decode_body(b"not gzip at all", "gzip", 100) == (b"not gzip at all", False, False)
    assert decode_body(b"abc", "compress", 2) == (b"ab", False, True)
    assert decode_body(b"abc", None, 10) == (b"abc", False, False)


def test_stream_decoder_any_split():
    raw = gzip.compress(DATA)
    for step in (1, 7, 100, 4096):
        dec = StreamDecoder("gzip", 1 << 22)
        out = b"".join(dec.feed(raw[i : i + step]) for i in range(0, len(raw), step))
        assert out == DATA


def test_multi_member_gzip():
    raw = gzip.compress(b"A" * 1000) + gzip.compress(b"B" * 1000)
    assert decode_body(raw, "gzip", 1 << 20) == (b"A" * 1000 + b"B" * 1000, True, False)
    assert decode_body(raw, "gzip", 1500) == (b"A" * 1000 + b"B" * 500, True, True)
    assert decode_body(raw + b"\0" * 10, "gzip", 1 << 20)[:2] == (b"A" * 1000 + b"B" * 1000, True)  # zero padding
    assert decode_body(raw + b"junk", "gzip", 1 << 20) == (raw + b"junk", False, False)  # as gzip.decompress fails
    for step in (1, 3, 50, len(raw)):
        dec = StreamDecoder("gzip", 1 << 20)
        out = b"".join(dec.feed(raw[i : i + step]) for i in range(0, len(raw), step))
        assert out == gzip.decompress(raw), step
    dec = StreamDecoder("gzip", 1200)  # the per-feed limit spans members
    assert len(dec.feed(raw)) == 1200 and dec.overflow
