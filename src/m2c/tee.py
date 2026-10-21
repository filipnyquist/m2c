"""Stream tees: observe a body as mitmproxy streams it through, without changing a byte.

mitmproxy does not catch exceptions raised by a stream callable; one would kill the client connection (and every
HTTP/2 stream on it). So every tee catches its own errors, stops observing, counts the failure and still returns
the chunk unchanged.
"""

from __future__ import annotations

import logging
from collections.abc import Callable

from .decode import DecodeError, StreamDecoder, codings
from .sse import SseParser

log = logging.getLogger("m2c.tee")

STREAMING_TYPES = ("text/event-stream", "application/x-ndjson", "application/jsonl", "application/grpc", "application/vnd.amazon.eventstream")


class BodyTee:
    """Keeps the first `cap` raw bytes and counts the rest. Chains to a previously installed stream callable."""

    def __init__(self, cap: int, inner=None, on_error: Callable[[], None] | None = None):
        self.cap = cap
        self.inner = inner if callable(inner) else None
        self.on_error = on_error
        self.parts: list[bytes] = []
        self.kept = 0
        self.size = 0
        self.ended = False
        self.broken = False

    def __call__(self, chunk: bytes):
        end = not chunk  # mitmproxy's end-of-body call; an inner callable may still return buffered bytes for it
        if self.inner is not None:
            chunk = self.inner(chunk)
            if isinstance(chunk, (bytearray, memoryview)):
                chunk = bytes(chunk)
            elif not isinstance(chunk, bytes):
                chunk = b"".join(chunk)  # a generator can be read only once: observe and forward the same bytes
        if not self.broken:
            try:
                if chunk:
                    self.observe(chunk)
                if end:
                    self.observe(b"")
            except Exception:  # noqa: BLE001 - never break the stream
                self.broken = True
                log.exception("m2c: stream observer failed; the rest of this body is not recorded")
                if self.on_error is not None:
                    self.on_error()
        return chunk

    def observe(self, chunk: bytes) -> None:
        if not chunk:
            self.ended = True
            self.finish()
            return
        self.size += len(chunk)
        if self.kept < self.cap:
            part = chunk[: self.cap - self.kept]
            self.parts.append(part)
            self.kept += len(part)

    def finish(self) -> None:
        pass

    @property
    def captured(self) -> bytes:
        return b"".join(self.parts)

    @property
    def truncated(self) -> bool:
        return self.size > self.kept


class SseTee(BodyTee):
    """BodyTee that also parses SSE events, decoding Content-Encoding incrementally and past the capture cap."""

    # Decoded bytes parsed per wire chunk. Parsing runs on mitmproxy's event loop, so this bounds how long one
    # chunk can hold every other connection (a few KB of gzip can inflate to megabytes of tiny events). Past it
    # the parser stops; raw capture and counting go on.
    DECODE_LIMIT = 1 << 20

    def __init__(self, cap: int, parser: SseParser, content_encoding: str | None, inner=None, on_error=None):
        super().__init__(cap, inner, on_error)
        self.parser = parser
        self.decoders: list[StreamDecoder] = []
        self.parsing = True
        self.closed = False
        self.parse_error: str | None = None
        layers = codings(content_encoding)
        try:
            self.decoders = [StreamDecoder(c, self.DECODE_LIMIT) for c in reversed(layers)]
        except DecodeError:
            self.parsing = False  # zstd or unknown: keep the raw body, no events

    def observe(self, chunk: bytes) -> None:
        super().observe(chunk)
        if chunk and self.parsing:
            # A failure here only stops event parsing; the raw body is still captured and counted.
            try:
                data = chunk
                for dec in self.decoders:
                    data = dec.feed(data)
                    if dec.overflow:
                        self.stop_parsing(f"more than {self.DECODE_LIMIT} decoded bytes in one chunk")
                self.parser.feed(data)
            except DecodeError as e:  # corrupt data, or a server that labels plain text as compressed
                self.stop_parsing(f"content decoding failed: {e}")
            except Exception:  # noqa: BLE001 - a parser bug must not cost the raw body
                self.stop_parsing("parser failed")
                self.closed = True  # its state is unknown: do not flush it at the end either
                log.exception("m2c: SSE parser failed; events of this response are no longer recorded")
                if self.on_error is not None:
                    self.on_error()

    def stop_parsing(self, why: str) -> None:
        if self.parse_error is None:
            self.parse_error = why
            log.warning("m2c: SSE events of this response are no longer parsed (%s); the raw body is still recorded", why)
        self.parsing = False

    def finish(self) -> None:
        self.close_parser()

    def close_parser(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                self.parser.close()
            except Exception:  # noqa: BLE001 - also called from the recording hook; the flow row matters more
                log.exception("m2c: SSE parser failed at the end of the stream")
                if self.on_error is not None:
                    self.on_error()


def wants_tee(headers, method: str = "", status: int = 0, threshold: int = 1 << 20, is_request: bool = False) -> bool:
    """Stream (and tee) this body instead of buffering it?"""
    if not is_request and (method == "HEAD" or 100 <= status < 200 or status in (204, 304)):
        return False
    te = headers.get("transfer-encoding", "")
    length = headers.get("content-length")
    if is_request:
        if "chunked" in te.lower():
            return True
        if length is None:
            return False
    elif (headers.get("content-type") or "").split(";", 1)[0].strip().lower().startswith(STREAMING_TYPES):
        return True
    if length is None:
        return True
    try:
        return int(length) > threshold
    except ValueError:
        return True
