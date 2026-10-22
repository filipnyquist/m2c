import subprocess

import pytest

from m2c import hooks


@pytest.fixture(autouse=True)
def runtime(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    return tmp_path


ENV = {"HTTP_PROXY": "http://s1.bash:v1.0.TOKEN@127.0.0.1:8080", "HTTPS_PROXY": "http://s1.bash:v1.0.TOKEN@127.0.0.1:8080",
       "NO_PROXY": "localhost", "SSL_CERT_FILE": "/tmp/ca bundle.pem"}


def shell(snippet: str, tmp_path, expr: str) -> str:
    env_file = tmp_path / "claude.env"
    env_file.write_text(snippet)
    return subprocess.run(["bash", "-c", f'source "{env_file}"; echo "{expr}"'], capture_output=True, text=True, check=True).stdout.strip()


def test_the_env_file_tags_each_bash_call(tmp_path):
    snippet = hooks.env_snippet(ENV, "s1", "bash", {"M2C_SESSION": "s1"})
    assert shell(snippet, tmp_path, "$HTTPS_PROXY $M2C_SESSION $SSL_CERT_FILE") == "http://s1.bash:v1.0.TOKEN@127.0.0.1:8080 s1 /tmp/ca bundle.pem"
    hooks.mark_call({"session_id": "s1", "tool_name": "Bash", "tool_use_id": "toolu_01AB"})
    assert shell(snippet, tmp_path, "$HTTPS_PROXY|$HTTP_PROXY") == (
        "http://s1.bash.toolu_01AB:v1.0.TOKEN@127.0.0.1:8080|http://s1.bash.toolu_01AB:v1.0.TOKEN@127.0.0.1:8080")
    assert shell(snippet, tmp_path, "${m2c_c-unset}") == "unset"  # its helper variables don't leak into the command
    hooks.call_file("s1").write_text("$(touch pwned); x y")  # whatever the file holds, it is never run
    assert shell(snippet, tmp_path, "$HTTPS_PROXY") == "http://s1.bash:v1.0.TOKEN@127.0.0.1:8080"
    assert not (tmp_path / "pwned").exists()


def test_only_bash_calls_with_a_valid_id_mark_the_call():
    hooks.mark_call({"session_id": "s1", "tool_name": "Read", "tool_use_id": "toolu_R"})
    assert not hooks.call_file("s1").exists()
    hooks.mark_call({"session_id": "s1", "tool_name": "Bash", "tool_use_id": "bad id; rm -rf"})
    assert not hooks.call_file("s1").exists()
    hooks.mark_call({"session_id": "weird/../id", "tool_name": "Bash", "tool_use_id": "toolu_B"})
    assert hooks.call_file("weird----id").read_text() == "toolu_B"


def test_session_ids():
    assert hooks.session_id("8c1f2e4a-0b9d-4c55-9f1e-3e2a1b0c9d8e") == "8c1f2e4a-0b9d-4c55-9f1e-3e2a1b0c9d8e"
    assert hooks.session_id(None) == "session" and hooks.session_id("../..") == "session"
