"""Bounded Content-Encoding decoding (gzip, deflate, br, zstd), run on the writer thread, never in a hook.

Every decoder caps its output, so a compression bomb costs at most the cap plus one chunk. When a body cannot be
decoded (unknown coding, corrupt data), the raw bytes are stored instead and `decoded` is False.
"""

from __future__ import annotations

import io
import zlib

import brotli
import zstandard


class DecodeError(Exception):
    pass


class StreamDecoder:
    """Incremental decoder for one coding. `feed()` returns at most `limit` bytes per call; `overflow` is set when
    output was cut off, after which the decoder refuses more input (the stream is out of sync)."""

    def __init__(self, coding: str, limit: int):
        self.coding = coding
        self.limit = limit
        self.overflow = False
        self._first = b""
        if coding in ("gzip", "x-gzip"):
            self._z = zlib.decompressobj(16 + zlib.MAX_WBITS)
        elif coding == "deflate":
            self._z = None  # zlib-wrapped or raw deflate; decided on the first bytes
        elif coding == "br":
            self._br = brotli.Decompressor()
        else:
            raise DecodeError(f"unsupported coding {coding!r}")

    def feed(self, data: bytes) -> bytes:
        if self.overflow or not data:
            return b""
        if self.coding == "br":
            out = self._br.process(data, output_buffer_limit=self.limit)
            if not self._br.can_accept_more_data():
                self.overflow = True
            return out[: self.limit]
        if self._z is None:
            # "deflate" is meant to be zlib-wrapped, but many servers send raw deflate.
            self._first += data
            if len(self._first) < 2:
                return b""
            data, self._first = self._first, b""
            wrapped = (data[0] & 0x0F) == 8 and ((data[0] << 8) | data[1]) % 31 == 0
            self._z = zlib.decompressobj(zlib.MAX_WBITS if wrapped else -zlib.MAX_WBITS)
        out: list[bytes] = []
        total = 0
        while data:
            if self._z.eof:
                if self.coding == "deflate":
                    break  # bytes after the end of a deflate stream are ignored
                # A gzip body may hold several members (RFC 1952), as gzip.decompress and mitmproxy decode them;
                # zero padding after the last one is skipped like gzip does.
                data = data.lstrip(b"\0")
                if not data:
                    break
                self._z = zlib.decompressobj(16 + zlib.MAX_WBITS)
            room = self.limit - total
            if room <= 0:
                self.overflow = True
                break
            try:
                out.append(self._z.decompress(data, room))
            except zlib.error as e:
                raise DecodeError(str(e)) from e
            total += len(out[-1])
            if self._z.unconsumed_tail:
                self.overflow = True
                break
            data = self._z.unused_data if self._z.eof else b""
        return b"".join(out)

def _zstd(raw: bytes, cap: int) -> bytes:
    reader = zstandard.ZstdDecompressor().stream_reader(io.BytesIO(raw), read_across_frames=True)
    parts, total = [], 0
    try:
        while total <= cap:
            chunk = reader.read(min(65536, cap + 1 - total))
            if not chunk:
                break
            parts.append(chunk)
            total += len(chunk)
    except zstandard.ZstdError as e:
        raise DecodeError(str(e)) from e
    return b"".join(parts)


def decode_one(raw: bytes, coding: str, cap: int) -> bytes:
    """Up to cap+1 decoded bytes (the extra byte tells the caller it was truncated)."""
    if coding == "zstd":
        return _zstd(raw, cap)
    dec = StreamDecoder(coding, cap + 1)
    return dec.feed(raw)


def codings(content_encoding: str | None) -> list[str]:
    if not content_encoding:
        return []
    return [c.strip().lower() for c in content_encoding.split(",") if c.strip() and c.strip().lower() != "identity"]


def decode_body(raw: bytes, content_encoding: str | None, cap: int) -> tuple[bytes, bool, bool]:
    """(stored bytes, decoded, truncated) for a complete or capped raw body."""
    layers = codings(content_encoding)
    if not layers:
        return raw[:cap], False, len(raw) > cap
    data = raw
    try:
        # Codings are listed in the order they were applied; undo them last to first.
        for i, coding in enumerate(reversed(layers)):
            inner_cap = cap if i == len(layers) - 1 else max(cap * 64, 1 << 20)
            data = decode_one(data, coding, inner_cap)
    except DecodeError:
        return raw[:cap], False, len(raw) > cap
    return data[:cap], True, len(data) > cap
