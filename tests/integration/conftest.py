import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import servers  # noqa: E402

M2C = str(Path(sys.executable).parent / "m2c")
ROWS = ("import sys; from m2c.db import open_session; "
        "sys.stdout.buffer.write(open_session(sys.argv[1], readonly=True).query(sys.argv[2], 'JSONEachRow').bytes())")


class Proxy:
    def __init__(self, tmp: Path, auth: str = "token", extra=(), env=None):
        self.tmp = tmp
        self.port = servers.free_port()
        self.data = tmp / "data"
        self.conf = tmp / "conf"
        self.env = {**os.environ, "M2C_DATA": str(self.data), "M2C_CONFDIR": str(self.conf), **(env or {})}
        self.log = open(tmp / "proxy.log", "wb")
        self.proc = subprocess.Popen(
            [M2C, "proxy", "--listen", f"127.0.0.1:{self.port}", "--api", "127.0.0.1:0", "--auth", auth, *extra], env=self.env, stdout=self.log, stderr=subprocess.STDOUT
        )
        deadline = time.time() + 30
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("proxy exited: " + (tmp / "proxy.log").read_text())
            try:
                socket.create_connection(("127.0.0.1", self.port), 0.2).close()
                if (self.conf / "mitmproxy-ca-cert.pem").exists() and (self.data / "api.json").exists():
                    break
            except OSError:
                time.sleep(0.1)
        time.sleep(0.3)

    def m2c(self, *args) -> str:
        return subprocess.run([M2C, *args], env=self.env, check=True, capture_output=True, text=True).stdout

    def token(self, session: str) -> str:
        return self.m2c("mint", session).strip()

    def url(self, user: str, token: str) -> str:
        return f"http://{user}:{token}@127.0.0.1:{self.port}"

    def stop(self, sig=signal.SIGTERM) -> int:
        if self.proc.poll() is None:
            self.proc.send_signal(sig)
            self.proc.wait(30)
        self.log.close()
        return self.proc.returncode

    def rows(self, sql: str) -> list[dict]:
        """Query the stopped proxy's data directory (m2c has no SQL command; one chDB data path per process, so not here)."""
        out = subprocess.run([sys.executable, "-c", ROWS, str(self.data), sql], env=self.env, check=True, capture_output=True).stdout
        return [json.loads(line) for line in out.splitlines() if line.strip()]


@pytest.fixture(scope="module")
def upstream():
    srv, port = servers.start()
    yield port
    srv.shutdown()


@pytest.fixture
def proxy(tmp_path):
    p = Proxy(tmp_path)
    yield p
    p.stop()
