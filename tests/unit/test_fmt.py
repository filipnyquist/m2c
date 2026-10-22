from m2c import fmt


def test_redaction_hides_credentials_but_keeps_them_comparable():
    pairs = [("Authorization", "Bearer abc"), ("Accept", "*/*"), ("cookie", "a=1")]
    out = fmt.redact_headers(pairs)
    assert out[1] == ["Accept", "*/*"]
    assert out[0][1].startswith("<redacted len=10 sha256:") and "abc" not in out[0][1]
    assert fmt.redact_headers([("authorization", "Bearer abc")])[0][1] == out[0][1]
    assert fmt.redact_headers(pairs, redact=False)[0] == ["Authorization", "Bearer abc"]
    assert fmt.redact_headers(pairs, "names") == ["Authorization", "Accept", "cookie"]
    assert fmt.redact_headers(pairs, "none") == []


def test_flow_line_marks_grpc_failures():
    f = {"n": 7, "ts": 0, "session": "s", "tool": "t", "call_id": "", "method": "POST", "status": 200, "error": "",
         "resp_body_size": 2048, "duration_ms": 12, "host": "h", "path": "/demo.v1.Demo/Fail", "grpc": True, "grpc_status": 3}
    line = fmt.flow_line(f)
    assert "200/g3" in line and " grpc " in line and "2.0K" in line
    assert fmt.status_text({"status": 0, "error": "reset"}) == "ERR"
