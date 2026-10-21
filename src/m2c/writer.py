"""The writer thread: hooks enqueue row dicts; one thread decodes, encodes RowBinary and inserts batches into chDB
through a write-ahead spool.

`put()` never blocks. Rows waiting in the queue and in the encoded per-table buffers count against the queue's
byte budget. Above it a row loses its bodies (sizes kept, capture='dropped'); above 1.25x the budget, or at the
item limit, the row is dropped. After `stop()` rows are refused. All of these are counted.

Each table has its own buffer, flushed at `batch_rows`, `batch_bytes` or `flush_interval` seconds after its first
row. A flushed batch is first written to `<data>/spool/<table>.<id>.<rows>.rowbinary`, then inserted from that file
with the file's id as `insert_deduplication_token`, and the file is deleted only after the insert succeeded:

- chDB's streaming insert can report success and store nothing when the memory limit is hit; an INSERT ... SELECT
  FROM file() raises properly, so the spool path is the one that can be trusted.
- A transient engine error (memory limit, too many parts, disk full) leaves the file in the spool and recording goes
  on; the spool is retried with backoff, oldest first, and memory stays flat however long the outage lasts.
- A file that keeps failing with a transient error is split in two (a batch can be too big for the memory limit).
  A single row that keeps failing while other batches get in goes to `<data>/dead/`, so one batch never wedges the
  writer; during an outage that refuses every insert nothing is dead-lettered.
- Any other error bisects the file until the bad rows are isolated in `<data>/dead/`. An error that does not
  depend on the rows (read-only disk, schema drift) dead-letters the batch whole, and so does an error that every
  piece of a level of WHOLE_AFTER pieces fails the same way (15 inserts, not 2n-1 for an n-row batch); fewer bad
  rows than that never take good rows with them.
- A split writes `<id>-0` and `<id>-1` and then deletes `<id>`; a start that finds both drops the halves, so a crash
  in between does not insert anything twice. A crash between insert and delete replays the file at the next start;
  the token makes that a no-op.
- At shutdown nothing is inserted after the deadline: whatever is left stays in the spool instead of being lost.
"""

from __future__ import annotations

import collections
import itertools
import logging
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from . import rowbinary, rows, schema

log = logging.getLogger("m2c.writer")

# timeout, cannot allocate memory, too many queries, aborted, memory limit, not enough space, too many parts, cancelled
TRANSIENT = {159, 173, 202, 236, 241, 243, 252, 394}
# no such column, unknown identifier/table/database, read-only, system error: not about particular rows
WHOLE_BATCH = {16, 47, 60, 81, 164, 425}
MAX_ATTEMPTS = 6  # transient failures of one spool file before it is split
WHOLE_AFTER = 8  # pieces of one rejected batch that all fail the same way: the error is not about particular rows
_CODE = re.compile(r"Code:\s*(\d+)")
_SPOOL_NAME = re.compile(r"^(?P<table>[a-z_]+)\.(?P<id>\d+(?:-\d+)+)\.(?P<rows>\d+)\.rowbinary$")

Insert = Callable[[str, tuple[str, ...], Path, str], None]


def error_code(e: Exception) -> int | None:
    m = _CODE.search(str(e))
    return int(m.group(1)) if m else None


@dataclass
class Counters:
    queued: int = 0
    written: collections.Counter = field(default_factory=collections.Counter)
    batches: int = 0
    dropped: collections.Counter = field(default_factory=collections.Counter)
    bodies_stripped: int = 0
    dead: int = 0
    insert_errors: int = 0
    hook_errors: int = 0
    tee_errors: int = 0
    spooled_files: int = 0
    spooled_bytes: int = 0
    max_batch_ms: float = 0.0

    def flat(self) -> dict[str, int]:
        out = {
            "queued": self.queued,
            "batches": self.batches,
            "bodies_stripped": self.bodies_stripped,
            "dead": self.dead,
            "insert_errors": self.insert_errors,
            "hook_errors": self.hook_errors,
            "tee_errors": self.tee_errors,
            "spooled_files": self.spooled_files,
            "spooled_bytes": self.spooled_bytes,
            "max_batch_ms": int(self.max_batch_ms),
        }
        out.update({f"written.{t}": n for t, n in self.written.items()})
        out.update({f"dropped.{t}": n for t, n in self.dropped.items()})
        return out


def approx_size(row: dict) -> int:
    size = 512
    for key in ("_req_raw", "_resp_raw", "content", "data"):
        v = row.get(key)
        if v:
            size += len(v)
    return size


# ----------------------------------------------------------------- RowBinary row boundaries (for splitting files)


def _varint(data: bytes, pos: int) -> tuple[int, int]:
    n = shift = 0
    while True:
        b = data[pos]
        pos += 1
        n |= (b & 0x7F) << shift
        if b < 0x80:
            return n, pos
        shift += 7


def _skip_string(data: bytes, pos: int) -> int:
    n, pos = _varint(data, pos)
    return pos + n


def _skip_headers(data: bytes, pos: int) -> int:
    n, pos = _varint(data, pos)
    for _ in range(n):
        pos = _skip_string(data, _skip_string(data, pos))
    return pos


def _skip_counters(data: bytes, pos: int) -> int:
    n, pos = _varint(data, pos)
    for _ in range(n):
        pos = _skip_string(data, pos) + 8
    return pos


def _fixed(width: int) -> Callable[[bytes, int], int]:
    return lambda data, pos: pos + width


def _skipper(type_: str) -> Callable[[bytes, int], int]:
    """The reading side of rowbinary.type_encoder: skips one value."""
    base = type_.strip()
    if base.startswith("LowCardinality(") and base.endswith(")"):
        base = base[len("LowCardinality(") : -1]
    widths = {"UUID": 16, "IPv6": 16, "UInt64": 8, "UInt32": 4, "UInt16": 2, "Bool": 1}
    if base == "String":
        return _skip_string
    if base in widths:
        return _fixed(widths[base])
    if base.startswith("DateTime64"):
        return _fixed(8)
    if base.startswith("Enum8("):
        return _fixed(1)
    if base.startswith("Array(Tuple("):
        return _skip_headers
    if base.startswith("Map("):
        return _skip_counters
    raise ValueError(f"no RowBinary reader for {type_}")


_SKIPPERS = {name: [_skipper(c.type) for c in t.columns] for name, t in schema.TABLES.items()}


def row_offsets(table: str, data: bytes) -> list[int]:
    """Where each row of a RowBinary batch starts, plus len(data). ValueError when the data does not parse."""
    plan = _SKIPPERS[table]
    out, pos, end = [0], 0, len(data)
    try:
        while pos < end:
            for skip in plan:
                pos = skip(data, pos)
            if pos > end:
                raise ValueError("truncated RowBinary row")
            out.append(pos)
    except IndexError:
        raise ValueError("truncated RowBinary row") from None
    return out


# ----------------------------------------------------------------- spool directory


def _ident(path: Path) -> str:
    return _SPOOL_NAME.match(path.name)["id"]


def spool_files(spool_dir: Path) -> list[tuple[Path, str, int]]:
    """(path, table, rows) of the spool, oldest first."""
    out = []
    try:
        entries = sorted(spool_dir.iterdir())
    except FileNotFoundError:
        return []
    for path in entries:
        m = _SPOOL_NAME.match(path.name)
        if m and m["table"] in schema.TABLES:
            out.append((path, m["table"], int(m["rows"])))
    return sorted(out, key=lambda item: tuple(int(x) for x in _ident(item[0]).split("-")))


def live_spool(spool_dir: Path) -> list[tuple[Path, str, int]]:
    """spool_files() without the halves of an interrupted split: while `<id>` exists it holds all of their rows."""
    files = spool_files(spool_dir)
    ids = {_ident(p) for p, _, _ in files}
    out = []
    for item in files:
        parts = _ident(item[0]).split("-")
        if any("-".join(parts[:k]) in ids for k in range(2, len(parts))):
            log.warning("m2c: dropping %s: the batch it was split from is still in the spool", item[0].name)
            item[0].unlink(missing_ok=True)
        else:
            out.append(item)
    return out


class Writer:
    def __init__(
        self,
        insert: Insert,
        data_dir: Path,
        body_cap: int = 1 << 20,
        batch_rows: int = 1000,
        batch_bytes: int = 8 << 20,
        flush_interval: float = 0.25,
        queue_max_items: int = 100_000,
        queue_max_bytes: int = 256 << 20,
        spool_max_bytes: int = 4 << 30,
        fsync: bool = False,
        health_interval: float = 30.0,
        health_row: Callable[[dict], dict] | None = None,
        max_attempts: int = MAX_ATTEMPTS,
    ):
        self.insert = insert
        self.spool_dir = Path(data_dir) / "spool"
        self.dead_dir = Path(data_dir) / "dead"
        self.body_cap = body_cap
        self.batch_rows = batch_rows
        self.batch_bytes = batch_bytes
        self.flush_interval = flush_interval
        self.queue_max_items = queue_max_items
        self.queue_max_bytes = queue_max_bytes
        self.spool_max_bytes = spool_max_bytes
        self.fsync = fsync
        self.health_interval = health_interval
        self.health_row = health_row
        self.max_attempts = max_attempts
        self.encoders = {name: rowbinary.encoder(t) for name, t in schema.TABLES.items()}
        self.counters = Counters()
        self._q: collections.deque[tuple[str, dict, int]] = collections.deque()
        self._q_bytes = 0  # rows queued or taken by the writer thread and not yet encoded
        self._buffered = 0  # encoded bytes in the per-table buffers
        self._cond = threading.Condition()
        self._stop = False
        self._warned_stopped = False
        self._abandon_at: float | None = None
        self._buffers: dict[str, list[bytes]] = {}
        self._buffer_bytes: dict[str, int] = {}
        self._buffer_since: dict[str, float] = {}
        # Spool files waiting for a retry, oldest first: (path, table, rows).
        self._pending: collections.deque[tuple[Path, str, int]] = collections.deque()
        self._attempts: dict[Path, int] = {}
        self._errors: dict[Path, Exception] = {}
        self._retry_at = 0.0
        self._retry_delay = 0.2
        self._last_error: Exception | None = None
        self._last_code: int | None = None
        self._ids = itertools.count()
        self._thread = threading.Thread(target=self._run, name="m2c-writer", daemon=True)
        self._last_health = time.monotonic()
        self._last_health_state: dict | None = None

    # ----------------------------------------------------------------- hook side

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._load_spool()
        self._thread.start()

    def _load_spool(self) -> None:
        self.spool_dir.mkdir(parents=True, exist_ok=True)
        leftover = live_spool(self.spool_dir)
        if leftover:
            log.warning("m2c: replaying %d spooled batches from an earlier run", len(leftover))
        for item in leftover:
            self._pending.append(item)
            self._count_spool(item[0], +1)

    @property
    def running(self) -> bool:
        return self._thread.is_alive()

    def put(self, table: str, row: dict) -> bool:
        size = approx_size(row)
        with self._cond:
            if self._stop:
                self.counters.dropped[table] += 1
                if not self._warned_stopped:
                    self._warned_stopped = True
                    log.warning("m2c: %s row arrived after the writer stopped; dropped (counted in dropped.%s)", table, table)
                return False
            held = self._q_bytes + self._buffered
            if len(self._q) >= self.queue_max_items or held > self.queue_max_bytes * 1.25:
                self.counters.dropped[table] += 1
                return False
            if held + size > self.queue_max_bytes:
                rows.strip_bodies(row)
                self.counters.bodies_stripped += 1
                size = 512
            self._q.append((table, row, size))
            self._q_bytes += size
            self.counters.queued = len(self._q)
            if len(self._q) == 1:
                self._cond.notify()
        return True

    def stop(self, timeout: float = 10.0) -> bool:
        """Flush everything; True when it was all inserted. Nothing is inserted after `timeout` seconds: the rest is
        written to the spool, where the next start (or `m2c push`) finds it. An insert already running then is not
        interrupted, so this can take a little longer; False while the thread is still busy."""
        with self._cond:
            self._stop = True
            self._abandon_at = time.monotonic() + timeout
            self._cond.notify()
        if self._thread.ident is None:
            # never started: drain on this thread
            self.spool_dir.mkdir(parents=True, exist_ok=True)
            self._run()
        else:
            self._thread.join(timeout + 5)
        return not self._thread.is_alive() and not self._pending

    def put_final(self, table: str, row: dict) -> bool:
        """After stop(): spool one row and insert it on the calling thread (for the 'stopped' event, whose counters
        must include the final flush). False when it stays in the spool for the next start."""
        try:
            rows.finalize(table, row, self.body_cap)
            data = self.encoders[table](row)
        except Exception:  # noqa: BLE001
            log.exception("m2c: could not encode a %s row", table)
            self.counters.dropped[table] += 1
            return False
        path = self._spool(table, [data])
        if path is None or self._thread.is_alive() or self._pending:
            return False  # never insert next to a writer thread that is still busy, nor ahead of older batches
        result = self._try(path, table, 1)
        if result == "bad":
            self._dead_file(path, table, 1, self._last_error)
        return result == "ok"

    # ----------------------------------------------------------------- writer side

    def _run(self) -> None:
        while True:
            with self._cond:
                if not self._q and not self._stop:
                    self._cond.wait(self._next_wait())
                # Bounded slices: rows taken out of the queue keep counting against the budget until encoded.
                items = [self._q.popleft() for _ in range(min(len(self._q), self.batch_rows))]
                stopping = self._stop
            for table, row, size in items:
                self._add(table, row)
                with self._cond:
                    self._q_bytes -= size
                    self.counters.queued = len(self._q)
            with self._cond:
                drained = not self._q
            self._maybe_health()
            self._flush(force=stopping and drained)
            self._replay(force=stopping)
            if stopping and drained:
                if not self._pending:
                    return
                if self._past_deadline():
                    log.error(
                        "m2c: %d batches could not be inserted before shutdown; they stay in %s and are inserted at the next start "
                        "(or by `m2c push`)", len(self._pending), self.spool_dir,
                    )
                    return
                time.sleep(min(self._retry_delay, max(0.05, self._abandon_at - time.monotonic())))

    def _past_deadline(self) -> bool:
        return self._abandon_at is not None and time.monotonic() >= self._abandon_at

    def _next_wait(self) -> float:
        waits = [min(self.health_interval, 1.0)]
        if self._buffer_since:
            waits.append(min(self._buffer_since.values()) + self.flush_interval - time.monotonic())
        if self._pending:
            waits.append(self._retry_at - time.monotonic())
        return max(0.0, min(waits))

    def _add(self, table: str, row: dict) -> None:
        try:
            rows.finalize(table, row, self.body_cap)
            data = self.encoders[table](row)
        except Exception:  # noqa: BLE001 - one bad row must not stop recording
            log.exception("m2c: could not encode a %s row", table)
            self.counters.dropped[table] += 1
            return
        buf = self._buffers.setdefault(table, [])
        if not buf:
            self._buffer_since[table] = time.monotonic()
            self._buffer_bytes[table] = 0
        buf.append(data)
        self._buffer_bytes[table] += len(data)
        self._buffered += len(data)
        if len(buf) >= self.batch_rows or self._buffer_bytes[table] >= self.batch_bytes:
            self._flush_table(table)

    def _flush(self, force: bool = False) -> None:
        now = time.monotonic()
        for table in list(self._buffers):
            if self._buffers[table] and (force or now - self._buffer_since[table] >= self.flush_interval):
                self._flush_table(table)

    def _flush_table(self, table: str) -> None:
        batch = self._buffers.pop(table, [])
        self._buffer_since.pop(table, None)
        self._buffered -= self._buffer_bytes.pop(table, 0)
        if not batch:
            return
        t0 = time.perf_counter()
        self.counters.batches += 1
        self._submit(table, batch)
        self.counters.max_batch_ms = max(self.counters.max_batch_ms, (time.perf_counter() - t0) * 1000)

    # ----------------------------------------------------------------- spool

    def _write(self, path: Path, payload: bytes) -> bool:
        tmp = path.with_suffix(".tmp")
        try:
            with os.fdopen(os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "wb") as f:  # captured bodies
                f.write(payload)
                if self.fsync:
                    f.flush()
                    os.fsync(f.fileno())
            tmp.rename(path)
        except OSError as e:
            log.error("m2c: cannot write the spool (%s)", e)
            tmp.unlink(missing_ok=True)
            return False
        self._count_spool(path, +1)
        return True

    def _spool(self, table: str, batch: list[bytes]) -> Path | None:
        if self.counters.spooled_bytes > self.spool_max_bytes:
            self.counters.dropped[table] += len(batch)
            log.error("m2c: the spool is over %d bytes; dropping %d %s rows", self.spool_max_bytes, len(batch), table)
            return None
        path = self.spool_dir / f"{table}.{time.time_ns()}-{next(self._ids)}.{len(batch)}.rowbinary"
        if not self._write(path, b"".join(batch)):
            # Disk full or similar: keep recording; without a file there is nothing to insert from.
            log.error("m2c: dropping %d %s rows", len(batch), table)
            self.counters.dropped[table] += len(batch)
            return None
        return path

    def _count_spool(self, path: Path, sign: int) -> None:
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        self.counters.spooled_files += sign
        self.counters.spooled_bytes = max(0, self.counters.spooled_bytes + sign * size)

    def _forget(self, path: Path) -> None:
        self._attempts.pop(path, None)
        self._errors.pop(path, None)

    def _unspool(self, path: Path) -> None:
        self._forget(path)
        self._count_spool(path, -1)
        path.unlink(missing_ok=True)

    def _submit(self, table: str, batch: list[bytes]) -> None:
        path = self._spool(table, batch)
        if path is not None:
            # Keep order: older spooled batches go first.
            self._pending.append((path, table, len(batch)))
            self._replay()

    def _try(self, path: Path, table: str, nrows: int) -> str:
        """'ok', 'transient' (keep the file and retry later) or 'bad' (the data itself is rejected)."""
        token = _ident(path)
        try:
            self.insert(table, schema.TABLES[table].names, path, token)
        except Exception as e:  # noqa: BLE001
            self.counters.insert_errors += 1
            code = error_code(e)
            self._last_error, self._last_code = e, code
            self._errors[path] = e
            if code in TRANSIENT or code is None and "memory" in str(e).lower():
                self._attempts[path] = self._attempts.get(path, 0) + 1
                if self._retry_at <= time.monotonic():
                    log.warning("m2c: insert into %s failed (code %s); %d batches spooled, retrying in %.1fs: %s",
                                table, code, len(self._pending), self._retry_delay, str(e)[:200])
                self._retry_at = time.monotonic() + self._retry_delay
                self._retry_delay = min(self._retry_delay * 2, 10.0)
                return "transient"
            log.warning("m2c: insert into %s rejected (code %s): %s", table, code, str(e)[:300])
            return "bad"
        self.counters.written[table] += nrows
        self._unspool(path)
        self._retry_delay = 0.2
        self._retry_at = 0.0
        return "ok"

    def _replay(self, force: bool = False) -> None:
        if not self._pending or (not force and time.monotonic() < self._retry_at):
            return
        while self._pending and not self._past_deadline():
            path, table, nrows = self._pending[0]
            result = self._try(path, table, nrows)
            if result == "transient":
                if self._attempts.get(path, 0) < self.max_attempts or not self._unstick():
                    return
                continue
            self._pending.popleft()
            if result == "bad":
                self._bisect(path, table, nrows, self._last_code, self._last_error)

    def _unstick(self) -> bool:
        """The oldest file failed `max_attempts` times with a transient error. Split it, as it may be too big for the
        memory limit; a single row goes to dead letters once a newer batch gets in, which shows that the error is
        about this row and not an outage. True when the queue moved."""
        path, table, nrows = self._pending[0]
        error = self._errors.get(path)
        halves = self._split(path, table, nrows) if nrows > 1 else None
        if halves is not None:
            log.warning("m2c: %s keeps failing (%s); split it in two", path.name, str(error)[:200])
            self._pending.popleft()
            self._pending.extendleft((h, table, n) for h, n in reversed(halves))
            self._retry_delay = 0.2  # a smaller insert is a new attempt
            return True
        # one row (or a file that cannot be split)
        if len(self._pending) < 2:
            return False
        probe, ptable, prows = self._pending[1]
        result = self._try(probe, ptable, prows)
        if result == "transient":
            return False  # nothing gets in: an outage, keep waiting
        del self._pending[1]
        if result == "bad":
            self._bisect(probe, ptable, prows, self._last_code, self._last_error)
            return True
        self._pending.popleft()
        self._dead_file(path, table, nrows, error)
        return True

    def _split(self, path: Path, table: str, nrows: int) -> list[tuple[Path, int]] | None:
        """Write the two halves of a spool file as `<id>-0` and `<id>-1`, then delete it. None when it cannot."""
        try:
            data = path.read_bytes()
            offsets = row_offsets(table, data)
        except (OSError, ValueError) as e:
            log.error("m2c: cannot split %s: %s", path.name, e)
            return None
        count = len(offsets) - 1
        if count < 2:
            return None
        if count != nrows:
            log.warning("m2c: %s holds %d rows, not %d", path.name, count, nrows)
        mid = count // 2
        out = []
        for k, (a, b) in enumerate(((0, mid), (mid, count))):
            half = self.spool_dir / f"{table}.{_ident(path)}-{k}.{b - a}.rowbinary"
            if not self._write(half, data[offsets[a] : offsets[b]]):
                for written, _ in out:
                    self._unspool(written)
                return None
            out.append((half, b - a))
        error = self._errors.get(path)
        self._unspool(path)
        if error is not None:
            self._errors.update((half, error) for half, _ in out)
        return out

    def _bisect(self, path: Path, table: str, nrows: int, code: int | None, error: Exception | None) -> None:
        """`path` was rejected with `code`: isolate the bad rows in dead letters and insert the rest, one level of
        halves at a time. When every piece of a level of WHOLE_AFTER pieces fails with `code`, the error is not about
        particular rows (k bad rows can fail at most k pieces): those pieces go to dead letters as they are."""
        level = [(path, nrows, code, error)]
        uniform = True  # every piece so far failed with `code`
        while level:
            if uniform and len(level) >= WHOLE_AFTER:
                log.warning("m2c: all %d pieces of a %d-row %s batch fail the same way; not trying each row", len(level), nrows, table)
                for piece, n, _, e in level:
                    self._dead_file(piece, table, n, e)
                return
            failed = []
            for piece, n, c, e in level:
                halves = None if n <= 1 or c in WHOLE_BATCH else self._split(piece, table, n)
                if halves is None:
                    self._dead_file(piece, table, n, e)
                    uniform = False
                    continue
                for half, hn in halves:
                    result = "transient" if self._past_deadline() else self._try(half, table, hn)
                    if result == "transient":
                        self._pending.append((half, table, hn))
                    elif result == "bad":
                        failed.append((half, hn, self._last_code, self._last_error))
                    if result != "bad" or self._last_code != code:
                        uniform = False
            level = failed

    def _dead_file(self, path: Path, table: str, nrows: int, error: Exception | None) -> None:
        self._forget(path)
        self._count_spool(path, -1)
        self.counters.dead += nrows
        try:
            self.dead_dir.mkdir(parents=True, exist_ok=True)
            path.rename(self.dead_dir / path.name)
            (self.dead_dir / f"{path.name}.error.txt").write_text(f"{nrows} rows\n{error}\n")
        except OSError:
            log.exception("m2c: could not move %s to dead letters", path)
        log.error("m2c: %d %s rows could not be inserted: %s", nrows, table, str(error)[:300])

    def _maybe_health(self) -> None:
        if self.health_row is None or time.monotonic() - self._last_health < self.health_interval:
            return
        self._last_health = time.monotonic()
        state = self.counters.flat()
        if state == self._last_health_state:
            return
        self._last_health_state = dict(state)
        if any(v for k, v in state.items() if k.startswith("dropped.")):
            log.warning("m2c: rows were dropped: %s", {k: v for k, v in state.items() if k.startswith("dropped.")})
        self._add("proxy_events", self.health_row(state))


def replay_spool(insert: Insert, data_dir: Path, timeout: float = 60.0) -> tuple[int, int]:
    """Insert what an earlier run left in `<data>/spool` (for offline use, e.g. before `m2c push`), by the writer's
    rules: transient errors are retried for up to `timeout` seconds, rejected rows go to `<data>/dead` so one bad
    batch cannot block a push forever. Returns (files inserted, files left)."""
    done = 0

    def counted(*args) -> None:
        nonlocal done
        insert(*args)
        done += 1

    w = Writer(counted, data_dir)
    w._load_spool()
    if not w._pending:
        return 0, 0
    w.stop(timeout)  # never started: drains on this thread
    return done, len(w._pending)
