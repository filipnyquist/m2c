"""How the CLI and the stdio MCP shim reach a scan: the live API (stdlib urllib only, no chDB import) while the proxy
runs, or the data directory itself once it has stopped. Both expose the same methods.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterator
from pathlib import Path


class ClientError(Exception):
    pass


class Online:
    online = True

    def __init__(self, url: str, token: str):
        self.url = url.rstrip("/")
        self.token = token
        self._opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # never through a proxy

    def _req(self, path: str, params: dict | None = None, data: bytes | None = None, timeout: float = 60):
        query = urllib.parse.urlencode({k: v for k, v in (params or {}).items() if v not in (None, "")})
        req = urllib.request.Request(self.url + path + ("?" + query if query else ""), data=data, method="POST" if data is not None else "GET")
        req.add_header("Authorization", f"Bearer {self.token}")
        try:
            return self._opener.open(req, timeout=timeout)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", "replace")
            try:
                body = json.loads(body).get("error", body)
            except ValueError:
                pass
            raise ClientError(f"{e.code}: {body}") from None
        except urllib.error.URLError as e:
            raise ClientError(f"cannot reach the API at {self.url}: {e.reason}") from None

    def reachable(self, timeout: float = 5) -> bool:
        """Whether this API answers /healthz: api.json can outlive a killed proxy, and its pid be reused."""
        try:
            with self._opener.open(self.url + "/healthz", timeout=timeout) as res:
                return res.status == 200
        except (OSError, ValueError):  # URLError and HTTPError are OSErrors
            return False

    def _json(self, path: str, params: dict | None = None):
        with self._req(path, params) as res:
            return json.loads(res.read())

    def stats(self):
        return self._json("/v1/scan")

    def sessions(self, q=""):
        return self._json("/v1/sessions", {"q": q})

    def flows(self, q="", limit=100, cursor=None, order="desc"):
        return self._json("/v1/flows", {"q": q, "limit": limit, "cursor": cursor, "order": order})

    def flow(self, n):
        try:
            return self._json(f"/v1/flows/{int(n)}")
        except ClientError as e:
            if str(e).startswith("404"):
                return None
            raise

    def body(self, n, side, max_bytes=None):
        try:
            with self._req(f"/v1/flows/{int(n)}/body/{side}", {"max": max_bytes}) as res:
                return res.read(), res.headers.get("X-M2C-Content-Type", "")
        except ClientError as e:
            if str(e).startswith("404"):
                return None
            raise

    def sse(self, n, after=0, limit=1000):
        return self._json(f"/v1/flows/{int(n)}/sse", {"after": after, "limit": limit})

    def ws(self, n, after=0, limit=1000):
        return self._json(f"/v1/flows/{int(n)}/ws", {"after": after, "limit": limit})

    def curl(self, n):
        try:
            with self._req(f"/v1/flows/{int(n)}/curl") as res:
                return res.read().decode().rstrip("\n")
        except ClientError as e:
            if str(e).startswith("404"):
                return None
            raise

    def har(self, q="", limit=1000):
        return self._json("/v1/har", {"q": q, "limit": limit})

    def events(self, kind="", limit=100):
        return self._json("/v1/events", {"kind": kind, "limit": limit})

    def sql(self, sql, fmt="JSONEachRow"):
        with self._req("/v1/sql", {"format": fmt}, data=sql.encode(), timeout=300) as res:
            return res.read()

    def tail(self, q="", backlog=0) -> Iterator[dict]:
        res = self._req("/v1/tail", {"q": q, "backlog": backlog}, timeout=None)
        data, kind = [], "message"
        for raw in res:
            line = raw.decode("utf-8", "replace").rstrip("\r\n")
            if line.startswith("event:"):
                kind = line[6:].strip()
            elif line.startswith("data:"):
                data.append(line[5:].lstrip())
            elif not line:
                if data and kind in ("flow", "open"):
                    yield {**json.loads("\n".join(data)), "_event": kind}
                data, kind = [], "message"

    def mcp(self, msg) -> dict | list | None:
        with self._req("/mcp", data=json.dumps(msg).encode()) as res:
            body = res.read()
        return json.loads(body) if body else None


class Offline:
    """Reads a stopped scan's directory directly (imports chDB)."""

    online = False

    def __init__(self, data: Path):
        from .db import open_session
        from .queries import Queries

        if not data.exists() or not any(data.iterdir()):
            raise ClientError(f"no scan data in {data}")
        try:
            sess = open_session(data, readonly=True)
        except RuntimeError as e:
            if "lock" in str(e).lower() or "already running" in str(e).lower():
                raise ClientError(f"{data} is in use by a running proxy, but its API was not found (is m2c_api_listen off?)") from None
            raise
        self.q = Queries(lambda sql, params, fmt: sess.query(sql, fmt, params=params).bytes())

    def __getattr__(self, name):
        return getattr(self.q, name)

    def tail(self, q="", backlog=0):
        raise ClientError("tail needs a running proxy")

    def mcp(self, msg):
        from .mcp import McpServer

        return McpServer(self.q, admin=True).handle_payload(msg)


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def connect(data: Path, api: str | None = None, token: str | None = None, offline: bool = False):
    """The live API when one is reachable (explicit, or found in <data>/api.json), else the data directory."""
    api = api or os.environ.get("M2C_API")
    token = token or os.environ.get("M2C_API_TOKEN")
    if offline:
        return Offline(data)
    info = data / "api.json"
    try:
        meta = json.loads(info.read_text()) if info.exists() else {}
    except (OSError, ValueError):
        meta = {}
    if not isinstance(meta, dict):
        meta = {}
    if api:
        token = token or meta.get("token")
        if not token:
            raise ClientError("--api needs a token (--token or M2C_API_TOKEN)")
        return Online(api, token)
    pid = meta.get("pid")
    if isinstance(pid, int) and pid > 0 and pid != os.getpid() and _alive(pid) and meta.get("url"):
        online = Online(meta["url"], token or meta.get("token", ""))
        if online.reachable():
            return online
        # A proxy killed without cleaning up (SIGKILL, OOM, a container crash where the next `m2c` is pid 1 again):
        # read the directory, which still refuses if a live process holds it.
        try:
            return Offline(data)
        except ClientError as e:
            raise ClientError(f"cannot reach the API at {online.url} (from {info}), and {e}") from None
    return Offline(data)
