"""Live feed: recent flow summaries in memory, open (still streaming) flows, and subscribers for the SSE endpoints.

Hooks publish the moment something happens, before the writer has inserted anything, so the live tail and the UI
see it within a millisecond:
  `open`  a long-lived response started (SSE, WebSocket, streamed body); its summary has no final status/size yet
  `flow`  a flow finished (also replaces its `open` entry)
  `sse` / `ws`  one event or message of an open flow, sent only to subscribers of that flow
Everything here runs on mitmproxy's event loop thread.

Finished flows get a feed sequence number (`seq`, in the order they finished; `n` is the order they started). Tail
subscribers are only woken and read the ring from their own cursor, so a slow reader loses nothing until it is a
whole ring behind, and a reconnecting client resumes from `<epoch>.<seq>`.
"""

from __future__ import annotations

import asyncio
import collections
import secrets

SUMMARY_KEYS = (
    "n", "ts", "session", "tool", "call_id", "tag", "method", "scheme", "host", "port", "path", "url", "status",
    "duration_ms", "req_body_size", "resp_body_size", "resp_content_type", "resp_capture", "sse_event_count",
    "ws_message_count", "error", "error_kind", "ua_tool", "grpc", "grpc_service", "grpc_method", "grpc_status",
)
TEXT_KEYS = ("session", "tool", "call_id", "tag", "error", "error_kind", "ua_tool", "grpc_service", "grpc_method")


def summary(row: dict) -> dict:
    out = {k: row.get(k, "" if k in TEXT_KEYS else 0) for k in SUMMARY_KEYS}
    out["grpc"] = bool(row.get("grpc"))
    out["grpc_status"] = row.get("grpc_status", -1)
    out["ts"] = row.get("ts_start", 0)
    for side in ("req", "resp"):
        if not out[f"{side}_body_size"]:
            raw = row.get(f"_{side}_raw")
            out[f"{side}_body_size"] = len(raw) if raw else 0
    if not out["resp_capture"]:
        out["resp_capture"] = "buffered" if out["resp_body_size"] else "none"
    if isinstance(out["error"], bytes):
        out["error"] = out["error"].decode("utf-8", "replace")
    return out


# The children ring keeps previews: the full event or message is in chDB (or the writer queue) already.
PREVIEW_BYTES = 4096
CHILDREN_PER_FLOW = 200
CHILDREN_BYTES = 32 << 20  # all open flows together; past it a flow keeps fewer previews (the rest is in the database)


def _preview(kind: str, row: dict) -> dict:
    key = "content" if kind == "ws" else "data"
    value = row.get(key)
    if value is None or len(value) <= PREVIEW_BYTES:
        return row
    return {**row, key: value[:PREVIEW_BYTES], "truncated": True, "_preview": True}


def _size(item: dict) -> int:
    value = item.get("content") if "content" in item else item.get("data")
    return 200 + (len(value) if value else 0)


class Subscriber:
    """Items for one stream handler, bounded in count and bytes. `wake` is set whenever there is something to read:
    an item, a finished flow in the ring (tails), a loss or the end (flow subscribers)."""

    def __init__(self, predicate, maxsize: int = 2000, max_bytes: int = 16 << 20, opens: bool = True):
        self.predicate = predicate
        self.opens = opens
        self.items: collections.deque = collections.deque()
        self.bytes = 0
        self.maxsize = maxsize
        self.max_bytes = max_bytes
        self.lost = 0
        self.ended: dict | None = None
        self.wake = asyncio.Event()

    def offer(self, kind: str, item: dict) -> None:
        size = _size(item)
        if len(self.items) >= self.maxsize or self.bytes + size > self.max_bytes:
            self.lost += 1
        else:
            self.items.append((kind, item))
            self.bytes += size
        self.wake.set()

    def end(self, item: dict) -> None:
        """Never dropped, however full the queue is."""
        self.ended = item
        self.wake.set()

    def take(self) -> list:
        out = list(self.items)
        self.items.clear()
        self.bytes = 0
        self.wake.clear()
        return out

    async def wait(self, timeout: float) -> None:
        try:
            await asyncio.wait_for(self.wake.wait(), timeout)
        except asyncio.TimeoutError:
            pass


class LiveFeed:
    def __init__(self, size: int = 10_000):
        self.epoch = secrets.token_hex(4)  # a cursor from another process (a restarted proxy) is no use here
        self.seq = 0
        self.ring: collections.deque[tuple[int, dict]] = collections.deque(maxlen=size)
        self.by_n: dict[int, dict] = {}
        self.open: dict[int, dict] = {}
        self.subscribers: set[Subscriber] = set()
        self.flow_subscribers: dict[int, set[Subscriber]] = {}
        # Previews of the newest events of each open flow: they may not be in chDB yet (writer flush interval), so a
        # late subscriber gets them from here and the older ones (and the full payloads) from the database.
        self.children: dict[int, collections.deque] = {}
        self.children_bytes = 0
        self.children_max_bytes = CHILDREN_BYTES
        self._flow_bytes: dict[int, int] = {}  # n -> bytes of its previews

    def _match(self, sub: Subscriber, item: dict) -> bool:
        try:
            return bool(sub.predicate(item))
        except Exception:  # noqa: BLE001 - a bad predicate must not break publishing
            return False

    def publish_open(self, item: dict) -> None:
        item = {**item, "open": True}
        self.open[item["n"]] = item
        for sub in list(self.subscribers):
            if sub.opens and self._match(sub, item):
                sub.offer("open", item)

    def publish(self, item: dict) -> None:
        """A finished flow."""
        n = item["n"]
        if len(self.ring) == self.ring.maxlen:
            old = self.ring[0][1]
            if self.by_n.get(old["n"]) is old:
                del self.by_n[old["n"]]
        self.seq += 1
        self.ring.append((self.seq, item))
        self.by_n[n] = item
        self.open.pop(n, None)
        self._drop_children(n)
        for sub in list(self.subscribers):
            if self._match(sub, item):
                sub.wake.set()
        for sub in self.flow_subscribers.pop(n, ()):
            sub.end(item)

    def publish_child(self, n: int, kind: str, item: dict) -> None:
        """An SSE event or WebSocket message of open flow `n`."""
        if n in self.open:  # a late child of a finished flow would never be freed
            recent = self.children.get(n)
            if recent is None:
                recent = self.children[n] = collections.deque()
            preview = _preview(kind, item)
            recent.append((kind, preview))
            self._account(n, _size(preview))
            if len(recent) > CHILDREN_PER_FLOW:
                self._evict(n)
            # Over the shared budget: this flow's oldest preview goes while it holds more than its fair share,
            # otherwise the biggest flow's (some flow is over its share whenever the total is over the budget).
            while self.children_bytes > self.children_max_bytes:
                share = self.children_max_bytes // len(self.children)
                self._evict(n if self._flow_bytes[n] > share else max(self._flow_bytes, key=self._flow_bytes.__getitem__))
        subs = self.flow_subscribers.get(n)
        if subs:
            for sub in list(subs):
                sub.offer(kind, item)

    def _account(self, n: int, size: int) -> None:
        self._flow_bytes[n] = self._flow_bytes.get(n, 0) + size
        self.children_bytes += size

    def _evict(self, n: int) -> None:
        """Drop flow n's oldest preview."""
        self._account(n, -_size(self.children[n].popleft()[1]))

    def _drop_children(self, n: int) -> None:
        self.children.pop(n, None)
        self.children_bytes -= self._flow_bytes.pop(n, 0)

    def subscribe(self, predicate, opens: bool = True) -> Subscriber:
        """A tail: woken for each matching finished flow (read them with `since`), queued `open` items."""
        sub = Subscriber(predicate, opens=opens)
        self.subscribers.add(sub)
        return sub

    def subscribe_flow(self, n: int) -> Subscriber:
        sub = Subscriber(None)
        self.flow_subscribers.setdefault(n, set()).add(sub)
        return sub

    def unsubscribe(self, sub: Subscriber) -> None:
        self.subscribers.discard(sub)
        for n, subs in list(self.flow_subscribers.items()):
            subs.discard(sub)
            if not subs:
                del self.flow_subscribers[n]

    def get(self, n: int) -> dict | None:
        return self.open.get(n) or self.by_n.get(n)

    def since(self, cursor: int) -> tuple[list[tuple[int, dict]], int]:
        """(seq, item) of the flows that finished after `cursor`, oldest first, and how many of them the ring no
        longer holds."""
        out = []
        for seq, item in reversed(self.ring):
            if seq <= cursor:
                break
            out.append((seq, item))
        out.reverse()
        first = self.ring[0][0] if self.ring else self.seq + 1
        return out, max(0, first - cursor - 1)

    def recent(self, predicate, limit: int = 100) -> list[tuple[int, dict]]:
        out = []
        for seq, item in reversed(self.ring):
            if predicate(item):
                out.append((seq, item))
                if len(out) >= limit:
                    break
        return out[::-1]
