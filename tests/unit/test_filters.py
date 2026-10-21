import pytest

from m2c.filters import FilterError, compile_filter, matcher, split_matcher

SUMMARY = {"n": 5, "ts": 2_000_000_000_000, "session": "run1", "tool": "nuclei", "call_id": "c1", "tag": "", "method": "POST",
           "host": "api.acme.test", "path": "/v1/users", "url": "https://api.acme.test/v1/users", "status": 503,
           "resp_content_type": "application/json", "resp_capture": "sse", "error": "", "error_kind": "", "ua_tool": "other",
           "req_body_size": 10, "resp_body_size": 0}


@pytest.mark.parametrize("q,expected", [
    ("", True), ("session:run1", True), ("session:run2", False), ("tool:NUC*", True), ("host:*.acme.test", True),
    ("method:get|post", True), ("status:5xx", True), ("status:>=500", True), ("status:<500", False), ("status:404|503", True),
    ("-status:503", False), ("path:/v1", True), ("ct:json", True), ("has:sse", True), ("has:ws", False), ("has:error", True),
    ("n:1-10", True), ("n:6", False), ("users", True), ("USERS session:run1", True), ('"v1/users"', True), ("call:c1", True),
    ("after:10m", True), ("before:1h", False),
])
def test_matcher(q, expected):
    assert matcher(q)(SUMMARY) is expected


def test_matcher_needs_db_for_body():
    assert matcher('body:"secret"') is None


def test_compile_params_never_inline():
    where, params = compile_filter('host:"evil\'--" "x\' OR 1=1"', scope="s1")
    assert "evil" not in where and "OR 1=1" not in where
    assert params["p0"] == "s1" and "evil'--" in params.values()


@pytest.mark.parametrize("q", ["status:abc", "has:nope", "unknownkey:x n:a-b", "after:yesterday", '"unbalanced'])
def test_bad_filters(q):
    with pytest.raises(FilterError):
        compile_filter(q)


@pytest.mark.parametrize("q", ["n:abc", "n:5-", "n:1|x", "host:", "status:abc"])
def test_matcher_rejects_what_compile_rejects(q):
    with pytest.raises(FilterError):
        matcher(q)


def test_split_matcher_preselects_for_db_terms():
    pred, exact = split_matcher('session:run1 body:"secret" -source:header')
    assert not exact and pred(SUMMARY) and not pred({**SUMMARY, "session": "run2"})
    assert split_matcher("has:truncated status:5xx")[1] is False
    pred, exact = split_matcher("status:5xx", scope="other")
    assert exact and not pred(SUMMARY)


@pytest.mark.parametrize("q", ["n:\u00b2", "n:1-\u00b2", "n:\u0664", "n:18446744073709551616", "n:1-" + "9" * 30,
                               "after:" + "9" * 400 + "d", "before:99999999999999999999d"])
def test_out_of_range_values_are_filter_errors(q):
    # "²".isdigit() is True but int("²") raises; 1e400d overflows; chDB would wrap an out-of-range UInt64/Int64
    for fn in (compile_filter, split_matcher):
        with pytest.raises(FilterError):
            fn(q)


def test_n_range_bounds():
    assert compile_filter("n:18446744073709551615")[1] == {"p0": (1 << 64) - 1}
    assert compile_filter("n:7-7")[0] == "n = {p0:UInt64}"
    assert matcher("n:3-9")(SUMMARY) and not matcher("n:6-9")(SUMMARY)
