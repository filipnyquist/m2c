"""gRPC: split a streamed body into length-prefixed messages, work out a call's status, decode messages for reading.

A gRPC body is a sequence of messages, each prefixed by 5 bytes: a flag byte (bit 0 = compressed; gRPC-Web adds
bit 7 = a trailer frame) and a 4-byte big-endian length. The framer works on whatever chunks the stream delivers and
never keeps more than `msg_cap` bytes of one message, whatever length the prefix claims. Protobuf decoding happens
only when someone reads a message (API, UI, MCP, CLI), with mitmproxy's decoder: schemaless by default, with field
names when a .proto file is given.
"""

from __future__ import annotations

import base64
import binascii
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass

STATUS = (
    "OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
    "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED",
    "INTERNAL", "UNAVAILABLE", "DATA_LOSS", "UNAUTHENTICATED",
)
CODES = {name: i for i, name in enumerate(STATUS)}
NO_STATUS = -1


def status_name(code: int) -> str:
    if code == NO_STATUS:
        return ""
    return STATUS[code] if 0 <= code < len(STATUS) else str(code)


def kind(content_type: str | None) -> str | None:
    """'grpc', 'grpc-web' or 'grpc-web-text' for a gRPC content type, else None."""
    ct = (content_type or "").split(";", 1)[0].strip().lower()
    if ct.startswith("application/grpc-web-text"):
        return "grpc-web-text"
    if ct.startswith("application/grpc-web"):
        return "grpc-web"
    if ct == "application/grpc" or ct.startswith("application/grpc+"):
        return "grpc"
    return None


def service_method(path: str) -> tuple[str, str]:
    """('demo.v1.Demo', 'Unary') from '/demo.v1.Demo/Unary'."""
    parts = path.split("?", 1)[0].strip("/").split("/")
    if len(parts) == 2 and all(parts):
        return parts[0][:200], parts[1][:200]
    return "", ""


def timeout_ms(value: str | None) -> int:
    """grpc-timeout ('1010m', '5S', '100u') in milliseconds; 0 when absent or malformed."""
    if not value or len(value) < 2 or not value[:-1].isdigit():
        return 0
    n = int(value[:-1])
    scale = {"H": 3_600_000, "M": 60_000, "S": 1000, "m": 1, "u": 0.001, "n": 0.000001}.get(value[-1])
    return min(int(n * scale), 2**32 - 1) if scale is not None else 0


def parse_trailer_block(data: bytes) -> list[tuple[str, str]]:
    """The HTTP/1-style header block of a gRPC-Web trailer frame."""
    out = []
    for line in data.decode("latin-1").split("\r\n"):
        name, sep, value = line.partition(":")
        if sep and name.strip():
            out.append((name.strip().lower(), value.strip()))
    return out


@dataclass
class Status:
    code: int = NO_STATUS
    message: str = ""
    source: str = "none"  # trailers | headers | web-trailer | inferred | none


def _find(pairs, name: str) -> str | None:
    for k, v in pairs or ():
        k = k.decode("latin-1") if isinstance(k, bytes) else k
        if k.lower() == name:
            return v.decode("latin-1") if isinstance(v, bytes) else v
    return None


def status_of(trailers, headers, web_trailers, error_kind: str = "", timeout: int = 0, duration_ms: int = 0) -> Status:
    """The call's status: trailers first, then a trailers-only response (in the headers), then a gRPC-Web trailer
    frame; without any, inferred from how the call ended (a client cancel at its deadline is DEADLINE_EXCEEDED)."""
    for pairs, source in ((trailers, "trailers"), (headers, "headers"), (web_trailers, "web-trailer")):
        raw = _find(pairs, "grpc-status")
        if raw is not None and raw.strip().lstrip("-").isdigit():
            message = urllib.parse.unquote(_find(pairs, "grpc-message") or "")
            return Status(max(-1, min(int(raw), 32767)), message[:2000], source)
    if error_kind == "client_abort":
        if timeout and duration_ms >= timeout * 0.9:
            return Status(CODES["DEADLINE_EXCEEDED"], "", "inferred")
        return Status(CODES["CANCELLED"], "", "inferred")
    if error_kind in ("upstream_connect", "upstream_tls", "upstream_disconnect", "timeout"):
        return Status(CODES["UNAVAILABLE"], "", "inferred")
    if error_kind:
        return Status(CODES["UNKNOWN"], "", "inferred")
    return Status()


@dataclass
class Message:
    flags: int
    size: int  # as the prefix declares it
    data: bytes  # the first msg_cap bytes
    partial: bool = False  # the body ended before the message did

    @property
    def compressed(self) -> bool:
        return bool(self.flags & 0x01)

    @property
    def trailer(self) -> bool:
        return bool(self.flags & 0x80)

    @property
    def truncated(self) -> bool:
        return len(self.data) < self.size


class FramingError(Exception):
    pass


class Framer:
    """Incremental gRPC message splitter. O(len(chunk)) per feed; at most msg_cap bytes kept per message."""

    def __init__(self, on_message: Callable[[Message], None], msg_cap: int = 256 * 1024, text: bool = False):
        self.on_message = on_message
        self.msg_cap = msg_cap
        self.text = text  # grpc-web-text: the frames are base64
        self._b64 = b""
        self._head = bytearray()
        self._need = 0  # bytes still to come of the current message
        self._flags = 0
        self._size = 0
        self._parts: list[bytes] = []
        self._kept = 0
        self.messages = 0

    def feed(self, chunk: bytes) -> None:
        if self.text:
            data = self._b64 + bytes(b for b in chunk if b not in b"\r\n ")
            usable = len(data) - len(data) % 4
            self._b64 = data[usable:]
            try:
                chunk = base64.b64decode(data[:usable], validate=True) if usable else b""
            except binascii.Error as e:
                raise FramingError(f"bad base64: {e}") from None
        i, n = 0, len(chunk)
        while i < n:
            if self._need == 0 and len(self._head) < 5:
                take = min(5 - len(self._head), n - i)
                self._head += chunk[i : i + take]
                i += take
                if len(self._head) < 5:
                    return
                self._flags = self._head[0]
                if self._flags & 0x7E:
                    raise FramingError(f"unexpected flag byte {self._flags:#04x}")
                self._size = int.from_bytes(self._head[1:5], "big")
                self._need = self._size
                if self._size == 0:
                    self._emit(False)
                continue
            take = min(self._need, n - i)
            room = self.msg_cap - self._kept
            if room > 0:
                part = chunk[i : i + min(take, room)]
                self._parts.append(part)
                self._kept += len(part)
            self._need -= take
            i += take
            if self._need == 0:
                self._emit(False)

    def close(self) -> None:
        """End of body: a message cut short is still reported (partial)."""
        if self._head and (self._need or len(self._head) < 5):
            if len(self._head) == 5:
                self._emit(True)
            self._head = bytearray()

    def _emit(self, partial: bool) -> None:
        msg = Message(self._flags, self._size, b"".join(self._parts), partial)
        self._head, self._parts, self._kept, self._need = bytearray(), [], 0, 0
        self.messages += 1
        self.on_message(msg)


# --------------------------------------------------------------------------- reading


def decode(data: bytes, path: str, from_client: bool, proto_file: str | None = None) -> tuple[str, str]:
    """(text, how) for one decompressed message: mitmproxy's protobuf view, with field names when `proto_file` defines
    the method's types. `how` is 'proto', 'schemaless' or 'error: …'. Never raises."""
    if not data:
        return "", "empty"
    try:
        from pathlib import Path

        import mitmproxy_rs.contentviews as cv
        from mitmproxy import http
        from mitmproxy.contentviews import Metadata

        meta = Metadata(content_type="application/grpc")
        if proto_file:
            req = http.Request.make("POST", "http://grpc" + (path if path.startswith("/") else "/" + path), b"",
                                    {"content-type": "application/grpc"})
            res = http.Response.make(200, b"", {"content-type": "application/grpc"})
            flow = http.HTTPFlow(None, None)
            flow.request, flow.response = req, res
            meta = Metadata(flow=flow, http_message=req if from_client else res, content_type="application/grpc",
                            protobuf_definitions=Path(proto_file))
        text = cv.protobuf.prettify(data, meta)
        return text, "proto" if proto_file else "schemaless"
    except Exception as e:  # noqa: BLE001 - not protobuf, or a broken .proto: show the bytes instead
        return "", f"error: {e}"[:300]
