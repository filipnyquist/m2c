import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from m2c import cli, client
from m2c.queries import Queries

CLEAN_ENV = {k: v for k, v in os.environ.items() if not k.lower().endswith("_proxy") and not k.startswith("M2C_")}


@pytest.fixture(autouse=True)
def _no_m2c_env(monkeypatch):
    for k in list(os.environ):
        if k.startswith("M2C_"):
            monkeypatch.delenv(k)


def _exit_message(argv) -> str:
    with pytest.raises(SystemExit) as e:
        cli.main(argv)
    return str(e.value.code)


# ------------------------------------------------------------------ credentials


def test_mint_does_not_create_a_secret_elsewhere(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    msg = _exit_message(["mint", "s1"])
    assert "no secret at" in msg and "m2c mint --init" in msg
    assert not (tmp_path / "m2c-data").exists()
    assert "no secret at" in _exit_message(["env", "--session", "s1", "--tool", "curl"])
    assert "no secret at" in _exit_message(["run", "--session", "s1", "--tool", "curl", "--", "true"])


def test_mint_init_creates_the_secret(tmp_path, capsys):
    cli.main(["mint", "s1", "--init", "--data", str(tmp_path / "d")])
    assert capsys.readouterr().out.startswith("v1.")
    assert (tmp_path / "d" / "secret").stat().st_mode & 0o777 == 0o600
    cli.main(["mint", "s1", "--data", str(tmp_path / "d")])  # uses the existing one


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads anything")
def test_env_with_a_proxy_owned_by_another_user(tmp_path, monkeypatch, capsys):
    data, conf = tmp_path / "data", tmp_path / "conf"
    data.mkdir()
    conf.mkdir()
    (data / "secret").write_text("s3cret\n")
    (data / "secret").chmod(0)
    (conf / "mitmproxy-ca-cert.pem").write_text("-----BEGIN CERTIFICATE-----\nproxy\n-----END CERTIFICATE-----\n")
    data.chmod(0o555)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    common = ["--session", "s1", "--tool", "curl", "--data", str(data), "--confdir", str(conf)]
    try:
        assert "cannot read" in _exit_message(["env", *common]) and "--token" in _exit_message(["env", *common])
        cli.main(["env", *common, "--token", "v1.0.tok", "--json"])
        env = json.loads(capsys.readouterr().out)
    finally:
        data.chmod(0o755)
    bundle = env["SSL_CERT_FILE"]
    assert bundle.startswith(str(tmp_path / "cache" / "m2c")) and "proxy" in open(bundle).read()
    assert env["HTTP_PROXY"] == "http://s1.curl:v1.0.tok@127.0.0.1:8080"


def test_env_writes_the_bundle_into_its_own_data_dir(tmp_path, capsys):
    data, conf = tmp_path / "data", tmp_path / "conf"
    data.mkdir()
    conf.mkdir()
    (conf / "mitmproxy-ca-cert.pem").write_text("CA\n")
    cli.main(["env", "--session", "s1", "--tool", "curl", "--token", "t", "--data", str(data), "--confdir", str(conf), "--json"])
    assert json.loads(capsys.readouterr().out)["SSL_CERT_FILE"] == str(data / "ca-bundle.pem")


@pytest.mark.parametrize("call", ["a@b", "a:b", "a/b", "a b", "x" * 97])
def test_call_is_validated(call, tmp_path):
    msg = _exit_message(["env", "--session", "s1", "--tool", "curl", "--call", call, "--token", "t", "--data", str(tmp_path)])
    assert "--call must match" in msg


def test_good_call_ends_up_in_the_user(tmp_path, capsys):
    cli.main(["env", "--session", "s1", "--tool", "curl", "--call", "step-1.a~b", "--token", "t", "--data", str(tmp_path / "none"),
              "--confdir", str(tmp_path / "none"), "--json"])
    assert json.loads(capsys.readouterr().out)["HTTP_PROXY"] == "http://s1.curl.step-1.a~b:t@127.0.0.1:8080"


# ------------------------------------------------------------------ m2c run tool flags


def _exe(path, content: bytes):
    path.write_bytes(content)
    path.chmod(0o755)
    return str(path)


def test_tool_flags(tmp_path):
    url = "http://s.t:tok@127.0.0.1:8080"
    assert cli.tool_flags(["nuclei", "-u", "x"], url) == ["nuclei", "-proxy", url, "-duc", "-u", "x"]
    assert cli.tool_flags(["naabu", "-host", "x"], url) == ["naabu", "-host", "x"]  # -proxy is SOCKS5 only
    assert cli.tool_flags(["ffuf", "-u", "x"], url) == ["ffuf", "-x", url, "-u", "x"]
    assert cli.tool_flags(["sqlmap", "-u", "x"], url) == ["sqlmap", "--proxy", "http://127.0.0.1:8080", "--proxy-cred", "s.t:tok", "-u", "x"]
    (tmp_path / "pd").mkdir()
    pd = _exe(tmp_path / "pd" / "httpx", b"\x7fELF\x02\x01\x01")
    assert cli.tool_flags([pd, "-u", "x"], url) == [pd, "-proxy", url, "-duc", "-u", "x"]
    py = _exe(tmp_path / "httpx", b"#!/usr/bin/python3\nimport httpx\n")
    assert cli.tool_flags([py, "https://x"], url) == [py, "https://x"]  # the encode/httpx CLI reads the environment


# ------------------------------------------------------------------ cwd module planting


def test_mitmdump_argv_ignores_the_working_directory(tmp_path):
    (tmp_path / "json.py").write_text("print('PLANTED')\n")
    argv = cli.mitmdump_argv()
    assert argv[:3] == [sys.executable, "-P", "-c"]
    out = subprocess.run([*argv[:2], "-c", "import json"], cwd=tmp_path, capture_output=True, text=True, env=CLEAN_ENV)
    assert "PLANTED" not in out.stdout


# ------------------------------------------------------------------ connect(): stale api.json


class _Health(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200 if self.path == "/healthz" else 404)
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *a):
        pass


@pytest.fixture
def offline_stub(monkeypatch):
    made = []

    class FakeOffline:
        online = False

        def __init__(self, data, proto_file=None):
            made.append(data)

    monkeypatch.setattr(client, "Offline", FakeOffline)
    return made


def _api_json(data, pid, url):
    data.mkdir(exist_ok=True)
    (data / "api.json").write_text(json.dumps({"url": url, "token": "tok", "pid": pid}))


def _closed_port() -> int:
    import socket

    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_stale_api_json_with_a_live_pid_falls_back_offline(tmp_path, offline_stub):
    _api_json(tmp_path, os.getppid(), f"http://127.0.0.1:{_closed_port()}")  # a live pid that is not the proxy
    assert client.connect(tmp_path).online is False and offline_stub == [tmp_path]


def test_api_json_naming_this_process_is_stale(tmp_path, offline_stub):
    _api_json(tmp_path, os.getpid(), "http://127.0.0.1:1")  # m2c as pid 1 in a container after the proxy (pid 1) died
    assert client.connect(tmp_path).online is False


def test_reachable_api_is_used(tmp_path, offline_stub):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        _api_json(tmp_path, os.getppid(), f"http://127.0.0.1:{srv.server_address[1]}")
        c = client.connect(tmp_path)
    finally:
        srv.shutdown()
    assert c.online is True and c.token == "tok" and not offline_stub


def test_unreachable_api_and_locked_directory_says_both(tmp_path, monkeypatch):
    def locked(data, proto_file=None):
        raise client.ClientError(f"{data} is in use by a running proxy")

    monkeypatch.setattr(client, "Offline", locked)
    _api_json(tmp_path, os.getppid(), f"http://127.0.0.1:{_closed_port()}")
    with pytest.raises(client.ClientError, match="cannot reach the API at .* and .* in use"):
        client.connect(tmp_path)


def test_explicit_api_with_unreadable_api_json(tmp_path):
    (tmp_path / "api.json").write_text("not json")
    with pytest.raises(client.ClientError, match="needs a token"):
        client.connect(tmp_path, api="http://127.0.0.1:1")


# ------------------------------------------------------------------ curl replay


class _FakeQueries(Queries):
    def __init__(self, url, body: bytes, method="POST", decoded=False):
        super().__init__(lambda *a: b"")
        self._flow = {"method": method, "url": url, "host": "127.0.0.1", "req_headers": [["Host", "127.0.0.1"], ["Content-Type", "text/plain"]],
                      "req_body_stored": len(body), "req_body_decoded": decoded}
        self._body = body

    def flow(self, n):
        return dict(self._flow)

    def body(self, n, side, max_bytes=None):
        return self._body, "text/plain"


class _Echo(BaseHTTPRequestHandler):
    got: list = []

    def do_POST(self):
        _Echo.got.append((self.path, self.rfile.read(int(self.headers.get("Content-Length") or 0))))
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, *a):
        pass


@pytest.fixture
def echo():
    _Echo.got = []
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Echo)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", _Echo.got
    srv.shutdown()


def _replay(cmd: str):
    return subprocess.run(["bash", "-c", cmd], capture_output=True, timeout=30, env=CLEAN_ENV)


@pytest.mark.parametrize("body", [b"@/etc/hostname", b"a=1&b=@/etc/passwd", b"line1\nline2\r\n", "café 'q' $HOME `id`".encode()])
def test_curl_replays_the_body_literally(echo, tmp_path, body):
    base, got = echo
    cmd = _FakeQueries(base + "/post", body).curl(1)
    assert _replay(cmd).returncode == 0, cmd
    assert got == [("/post", body)]


def test_curl_binary_body_and_note_keep_the_body(echo):
    base, got = echo
    body = b"@\x00\xff\xfe binary"
    cmd = _FakeQueries(base + "/bin", body, decoded=True).curl(1)
    assert cmd.startswith("# note:") and "\n" in cmd
    assert _replay(cmd).returncode == 0, cmd
    assert got == [("/bin", body)]


def test_curl_does_not_glob_the_url(echo):
    base, got = echo
    cmd = _FakeQueries(base + "/x[1-3]{a,b}", b"").curl(1)
    _replay(cmd)
    assert len(got) == 1 and got[0][0] == "/x[1-3]{a,b}"


def test_curl_skips_header_lines_curl_would_read_as_a_file():
    q = _FakeQueries("http://h/", b"", method="GET")
    q._flow["req_headers"].append(["@/etc/passwd", "x"])
    assert "/etc/passwd" not in q.curl(1)


def test_proxy_passes_labels_as_json(tmp_path, capsys):
    cli.main(["proxy", "--print", "--data", str(tmp_path), "--label", "q=a,b=c", "--label", "k=v"])
    argv = __import__("shlex").split(capsys.readouterr().out)
    labels = next(a for a in argv if a.startswith("m2c_labels="))
    from m2c.recorder import parse_labels

    assert parse_labels(labels.split("=", 1)[1]) == {"q": "a,b=c", "k": "v"}


# ------------------------------------------------------------------ version


def test_version_prints_the_package_version(capsys):
    from m2c import __version__

    with pytest.raises(SystemExit) as e:
        cli.main(["--version"])
    assert e.value.code == 0
    assert capsys.readouterr().out.strip() == f"m2c {__version__}"


# ------------------------------------------------------------------ data directory permissions


def test_data_dir_is_private(tmp_path):
    from m2c.db import private_dir

    private_dir(tmp_path / "new" / "data")
    assert (tmp_path / "new" / "data").stat().st_mode & 0o777 == 0o700
    old = tmp_path / "old"
    old.mkdir()
    old.chmod(0o775)
    private_dir(old)
    assert old.stat().st_mode & 0o777 == 0o700
