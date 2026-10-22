"""ClickHouse RowBinary encoding with the standard library only.

`encoder(table)` compiles one function per table that turns a row dict into RowBinary bytes, in column order.
Missing keys take the type's zero value. Strings accept str (UTF-8 encoded) or bytes (stored as is), so bodies
round-trip byte for byte. Only the types used in schema.py are supported.
"""

from __future__ import annotations

import ipaddress
import re
import struct
import uuid
from collections.abc import Callable

from .schema import Table

_i64 = struct.Struct("<q").pack
_u64 = struct.Struct("<Q").pack
_u32 = struct.Struct("<I").pack
_u16 = struct.Struct("<H").pack
_i16 = struct.Struct("<h").pack
_ZERO_UUID = b"\x00" * 16
_ZERO_IP = b"\x00" * 16


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def string(v) -> bytes:
    if v is None:
        return b"\x00"
    if isinstance(v, str):
        v = v.encode("utf-8", "surrogateescape")
    elif not isinstance(v, (bytes, bytearray, memoryview)):
        v = str(v).encode()
    return varint(len(v)) + bytes(v)


def uuid_(v) -> bytes:
    if not v:
        return _ZERO_UUID
    b = (v if isinstance(v, uuid.UUID) else uuid.UUID(str(v))).bytes
    return b[7::-1] + b[15:7:-1]


def ipv6(v) -> bytes:
    if not v:
        return _ZERO_IP
    try:
        ip = ipaddress.ip_address(v.split("%", 1)[0] if isinstance(v, str) else v)
    except ValueError:
        return _ZERO_IP
    if ip.version == 4:
        return b"\x00" * 10 + b"\xff\xff" + ip.packed
    return ip.packed


def headers(v) -> bytes:
    """Array(Tuple(String, String)) from [(name, value), ...]; bytes or str."""
    if not v:
        return b"\x00"
    return varint(len(v)) + b"".join(string(k) + string(val) for k, val in v)


def counters(v) -> bytes:
    """Map(String, Int64) from a dict."""
    if not v:
        return b"\x00"
    return varint(len(v)) + b"".join(string(k) + _i64(int(n)) for k, n in v.items())


def _enum(type_: str) -> Callable:
    values = {name: int(num) for name, num in re.findall(r"'([^']*)'\s*=\s*(-?\d+)", type_)}

    def enc(v):
        if v is None or v == "":
            return b"\x00"
        if isinstance(v, int):
            return struct.pack("<b", v)
        return struct.pack("<b", values[v])

    return enc


def _ts(v) -> bytes:
    """DateTime64(3) from epoch seconds (float) or milliseconds (int)."""
    if not v:
        return _i64(0)
    return _i64(int(round(v * 1000)) if isinstance(v, float) else int(v))


def _clamp(pack, hi):
    def enc(v):
        n = int(v or 0)
        return pack(0 if n < 0 else hi if n > hi else n)

    return enc


def _bool(v) -> bytes:
    return b"\x01" if v else b"\x00"


def type_encoder(type_: str) -> Callable:
    base = type_.strip()
    if base.startswith("LowCardinality(") and base.endswith(")"):
        base = base[len("LowCardinality(") : -1]
    if base == "String":
        return string
    if base == "UUID":
        return uuid_
    if base == "IPv6":
        return ipv6
    if base.startswith("DateTime64"):
        return _ts
    if base == "Bool":
        return _bool
    if base == "UInt64":
        return _clamp(_u64, 2**64 - 1)
    if base == "UInt32":
        return _clamp(_u32, 2**32 - 1)
    if base == "Int16":
        return lambda v: _i16(max(-32768, min(32767, int(v or 0))))
    if base == "UInt16":
        return _clamp(_u16, 2**16 - 1)
    if base.startswith("Enum8("):
        return _enum(base)
    if base.startswith("Array(Tuple("):
        return headers
    if base.startswith("Map("):
        return counters
    raise ValueError(f"no RowBinary encoder for {type_}")


def encoder(table: Table) -> Callable[[dict], bytes]:
    plan = [(c.name, type_encoder(c.type)) for c in table.columns]

    def encode(row: dict) -> bytes:
        get = row.get
        return b"".join([enc(get(name)) for name, enc in plan])

    return encode
