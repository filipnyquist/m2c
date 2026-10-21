import time

import pytest

from m2c import identity
from m2c.identity import AuthError, Authenticator


def test_token_roundtrip_and_session_binding():
    tok = identity.mint("s3cret", "run42")
    auth = Authenticator("token", ["s3cret"])
    ident = auth.check("run42.curl.step1", tok)
    assert (ident.session, ident.tool, ident.call) == ("run42", "curl", "step1")
    with pytest.raises(AuthError, match="bad_mac"):
        auth.check("run43.curl", tok)


def test_token_expiry_rechecked_on_cache_hit():
    auth = Authenticator("token", ["k"])
    tok = identity.mint("k", "s1", ttl=60)
    assert auth.check("s1.curl", tok).session == "s1"
    auth.cache[("s1.curl", tok)] = (auth.cache[("s1.curl", tok)][0], identity._b36(int(time.time()) - 5))
    with pytest.raises(AuthError, match="expired"):
        auth.check("s1.curl", tok)
    with pytest.raises(AuthError, match="expired"):
        auth.check("s1.curl", identity.mint("k", "s1", ttl=1, now=time.time() - 10))


def test_secret_rotation():
    tok = identity.mint("old", "s1")
    assert Authenticator("token", ["new", "old"]).check("s1.x", tok).tool == "x"


@pytest.mark.parametrize("user", ["", "nodot", "a.b c", "a..", "x" * 300 + ".curl", "s.tool!"])
def test_bad_usernames(user):
    auth = Authenticator("shared", ["pw"])
    with pytest.raises(AuthError):
        auth.check(user, "pw")


def test_shared_and_open_modes():
    assert Authenticator("shared", ["pw"]).check("s.Curl", "pw").tool == "curl"
    with pytest.raises(AuthError, match="bad_secret"):
        Authenticator("shared", ["pw"]).check("s.curl", "nope")
    open_ = Authenticator("open")
    ident = open_.check("run42", "nuclei")
    assert (ident.session, ident.tool) == ("run42", "nuclei")
    assert open_.check("run42.curl", "whatever").tool == "curl"
    with pytest.raises(ValueError):
        Authenticator("token", [])


def test_override_never_changes_session():
    base = identity.Identity("s1", "bash", "", "s1.bash", "connect")
    new = identity.override(base, "Curl", "call-7")
    assert (new.session, new.tool, new.call, new.source) == ("s1", "curl", "call-7", "header")
    assert identity.override(base, "bad tool!", None) is base


def test_ua_tool():
    assert identity.ua_tool("curl/8.5.0") == "curl"
    assert identity.ua_tool("python-requests/2.32") == "python-requests"
    assert identity.ua_tool(None) == ""
    assert identity.ua_tool("Something/1") == "other"


@pytest.mark.parametrize("password", ["v1.0.é", "v1.0.�", "é", "v1.zz.abc\udcff", "\x00"])
def test_non_ascii_or_odd_passwords_are_rejections_not_crashes(password):
    for mode, secrets in (("token", ["k"]), ("shared", ["k"])):
        with pytest.raises(AuthError):
            Authenticator(mode, secrets).check("run1.curl", password)
