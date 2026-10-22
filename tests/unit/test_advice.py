from m2c.advice import for_event


def test_tls_client_failures_name_the_tools_ca_setting():
    npm = for_event({"kind": "tls_failed_client", "tool": "npm", "session": "build-7"})
    assert "NODE_EXTRA_CA_CERTS" in npm and "m2c env --session build-7 --tool npm" in npm
    chrome = for_event({"kind": "tls_failed_client", "tool": "chrome", "session": "b1"})
    assert "trust store" in chrome and "m2c env" not in chrome  # browsers don't read the variables
    unknown = for_event({"kind": "tls_failed_client", "tool": "", "session": ""})
    assert "m2c ca path" in unknown and "<session>" in unknown


def test_auth_rejections_say_how_to_get_a_token():
    expired = for_event({"kind": "auth_rejected", "reason": "token expired", "proxy_user": "run1.curl"})
    assert "m2c mint run1" in expired
    assert "mint one with `m2c mint run2`" in for_event({"kind": "auth_rejected", "reason": "bad signature", "proxy_user": "run2.x"})


def test_kinds_without_advice():
    assert for_event({"kind": "health"}) == "" and for_event({"kind": "started"}) == ""
    assert "raw TCP" in for_event({"kind": "tcp_tunnel", "reason": "h2c"})
