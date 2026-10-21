"""Incremental Server-Sent Events parser (WHATWG event-stream rules), fed arbitrary chunk boundaries.

Lines end with CRLF, LF or CR; a blank line dispatches the event. `data` lines are joined with LF, a single space
after the colon is dropped, lines starting with ':' are comments (counted, not stored). Event data is capped at
`event_cap` characters' worth of UTF-8, joining LFs included (flagged `truncated`; `size` keeps counting); a line
that never ends is cut at the same size (plus a "data: " prefix) and the rest is discarded until the next line
break. `close()` flushes an event that ended without a blank line (`partial`).
"""

from __future__ import annotations

import codecs
import re
from collections.abc import Callable
from dataclasses import dataclass

_EOL = re.compile(r"\r\n|\r|\n")


@dataclass
class SseEvent:
    event: str
    data: str
    id: str
    retry_ms: int
    size: int
    truncated: bool
    partial: bool


class SseParser:
    def __init__(self, on_event: Callable[[SseEvent], None], event_cap: int = 64 * 1024):
        self.on_event = on_event
        self.event_cap = event_cap
        self._line_cap = event_cap + len("data: ")  # so a data value of exactly event_cap is kept whole
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._line: list[str] = []
        self._line_len = 0
        self._line_cut = False
        self._line_dropped = 0
        self._held_cr = False
        self._first = True
        self.events = 0
        self.comments = 0
        self._reset()

    def _reset(self):
        self._data: list[str] = []
        self._data_len = 0  # length of "\n".join(self._data)
        self._data_lines = 0
        self._data_full = False
        self._size = 0
        self._truncated = False
        self._event = ""
        self._id = ""
        self._retry = 0
        self._touched = False

    def feed(self, chunk: bytes) -> None:
        text = self._decoder.decode(chunk)
        if self._first and text:
            self._first = False
            if text.startswith("﻿"):
                text = text[1:]
        self._scan(text)

    def close(self) -> None:
        self._scan(self._decoder.decode(b"", final=True))
        # A held CR already ended its line; it only waited to swallow a following LF.
        self._held_cr = False
        if self._line or self._line_cut:
            self._end_line()
        if self._touched:
            self._dispatch(partial=True)

    def _scan(self, text: str) -> None:
        # One regex pass per chunk: searching for CR and LF separately from every line start is quadratic on the
        # usual LF-only stream (no CR anywhere, so each search runs to the end of the chunk).
        i, n = 0, len(text)
        if self._held_cr and n:
            self._held_cr = False
            if text[0] == "\n":
                i = 1
        m = None
        for m in _EOL.finditer(text, i):
            self._end_line(text[i : m.start()])
            i = m.end()
        if i < n:
            self._append(text[i:])
        elif m is not None and m.end() == n and m.group() == "\r":
            self._held_cr = True  # the LF of a CRLF may start the next chunk

    def _append(self, part: str) -> None:
        if not part:
            return
        if self._line_cut:
            self._line_dropped += len(part.encode("utf-8", "replace"))
            return
        room = self._line_cap - self._line_len
        if len(part) > room:
            self._line_dropped += len(part[max(room, 0) :].encode("utf-8", "replace"))
            part = part[: max(room, 0)]
            self._line_cut = True
        if part:
            self._line.append(part)
            self._line_len += len(part)

    def _end_line(self, tail: str = "") -> None:
        if not self._line and not self._line_cut and len(tail) <= self._line_cap:
            line, cut, dropped = tail, False, 0  # the common case: the whole line arrived in one chunk
        else:
            self._append(tail)
            line = "".join(self._line)
            cut, dropped = self._line_cut, self._line_dropped
            self._line, self._line_len, self._line_cut, self._line_dropped = [], 0, False, 0
        if not line:
            if not cut:
                self._dispatch(partial=False)
            return
        if line.startswith(":"):
            self.comments += 1
            return
        name, sep, value = line.partition(":")
        if sep and value.startswith(" "):
            value = value[1:]
        if name == "data":
            self._touched = True
            joint = 1 if self._data_lines else 0
            self._data_lines += 1
            self._size += len(value.encode("utf-8", "replace")) + dropped + joint
            if cut:
                self._truncated = True
            if self._data_full:
                return  # past the cap only the size grows, so an event with endless data lines stays bounded
            room = self.event_cap - self._data_len - joint  # the joining LF counts against the cap too
            if len(value) > room:
                self._truncated = self._data_full = True
                value = value[: max(room, 0)]
                if joint and not value:
                    return
            self._data.append(value)
            self._data_len += joint + len(value)
        elif name == "event":
            self._touched = True
            self._event = value[:200]
        elif name == "id":
            if "\0" not in value:
                self._touched = True
                self._id = value[:200]
        elif name == "retry":
            if value.isdigit():
                self._touched = True
                self._retry = int(value)

    def _dispatch(self, partial: bool) -> None:
        if not self._touched:
            return
        if self._data_lines or self._event or self._id or self._retry:
            self.events += 1
            self.on_event(
                SseEvent(self._event, "\n".join(self._data), self._id, self._retry, self._size, self._truncated, partial)
            )
        self._reset()
