"""The chDB database: one data directory per process, a writer session and read-only reader sessions.

chDB allows one data path per process and locks it against other processes (`<path>/status`), so everything
that reads a live scan goes through this process. One session serializes its queries; readers therefore get
their own sessions, each switched to `readonly=1` (which cannot be switched back).
"""

from __future__ import annotations

import os
import threading
from pathlib import Path

from . import schema

_lock = threading.Lock()
_conn_str: str | None = None

# Applied to reader sessions before `readonly = 1`, which then forbids changing any setting, writing, and table
# functions such as file() and url() (readonly = 2 would still allow reading local files).
READER_SETTINGS = (
    "output_format_json_validate_utf8 = 1",
    "output_format_json_quote_64bit_integers = 0",
    "output_format_json_named_tuples_as_objects = 1",
    "max_execution_time = 30",
    "max_result_bytes = 536870912",
    "max_memory_usage = 1073741824",
)


def conn_str(path: str | os.PathLike, memory_limit: int | None = None, background_pool: int = 2) -> str:
    # memory_worker_use_cgroup=0: ClickHouse otherwise measures the whole cgroup's memory as its own RSS. On a desktop
    # that cgroup is the terminal's scope (the agent, browsers, ...), and max_server_memory_usage fails every query
    # once their total passes the limit, though this process uses a fraction of it.
    args = [f"background_pool_size={background_pool}", "mark_cache_size=268435456", "memory_worker_use_cgroup=0"]
    if memory_limit:
        args.append(f"max_server_memory_usage={int(memory_limit)}")
    return f"{Path(path).resolve()}?" + "&".join(args)


def private_dir(path: str | os.PathLike) -> None:
    """Create `path` as 0700, or take group and other access away from an existing one this user owns: the part files
    hold every captured body, cookie and target credential, so they must not follow the umask (often 022)."""
    p = Path(path)
    p.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        st = p.stat()
        if st.st_uid == os.geteuid() and st.st_mode & 0o077:
            p.chmod(st.st_mode & 0o700)
    except OSError:
        pass


def open_session(path: str | os.PathLike, memory_limit: int | None = None, readonly: bool = False):
    """A chDB session on `path`. The first call fixes the process's engine settings."""
    from chdb import session as chs

    global _conn_str
    if readonly:
        Path(path).mkdir(parents=True, exist_ok=True)
    else:
        private_dir(path)
    with _lock:
        if _conn_str is None:
            _conn_str = conn_str(path, memory_limit)
        sess = chs.Session(_conn_str)
    if readonly:
        for setting in READER_SETTINGS:
            sess.query(f"SET {setting}")
        sess.query("SET readonly = 1")
    return sess


def insert_file(query, table: str, columns: tuple[str, ...], path: os.PathLike, token: str, db: str = schema.DB) -> None:
    """INSERT ... SELECT FROM file(): unlike chDB's streaming insert, it raises when the engine refuses the data
    (the streaming insert has been seen to report success and store nothing at the memory limit)."""
    cols = ", ".join(columns)
    query(
        f"INSERT INTO {db}.{table} ({cols}) SELECT * FROM file({schema.quote(str(path))}, 'RowBinary', "
        f"{schema.quote(schema.structure(schema.TABLES[table]))}) SETTINGS insert_deduplication_token = {schema.quote(token)}"
    )


class Database:
    """Writer session plus schema; `reader()` hands out read-only sessions on the same path."""

    def __init__(self, path: str | os.PathLike, memory_limit: int | None = None, db: str = schema.DB):
        self.path = Path(path)
        self.db = db
        self.memory_limit = memory_limit
        self.writer = open_session(self.path, memory_limit)
        schema.ensure(lambda sql: self.writer.query(sql), db)

    def reader(self):
        return open_session(self.path, self.memory_limit, readonly=True)

    def insert_file(self, table: str, columns: tuple[str, ...], path: os.PathLike, token: str) -> None:
        insert_file(self.writer.query, table, columns, path, token, self.db)

    def insert(self, table: str, columns: tuple[str, ...], payload: bytes) -> None:
        """Direct insert for tools and tests; recording goes through the writer's spool (see writer.py for why)."""
        with self.writer.send_insert(f"INSERT INTO {self.db}.{table} ({', '.join(columns)})", "RowBinary") as ins:
            ins.append(payload)
            ins.finish()

    def scalar(self, sql: str, params: dict | None = None):
        out = self.writer.query(sql, "TSV", params=params).bytes().decode().strip()
        return out

    def close(self):
        try:
            self.writer.close()
        except Exception:  # noqa: BLE001 - closing on shutdown, nothing to do about it
            pass
