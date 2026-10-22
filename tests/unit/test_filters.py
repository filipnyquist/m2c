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


def test_spec_documents_every_key_and_has_value():
    from m2c.filters import HAS, KEYS, SPEC, help_text

    assert {s["key"] for s in SPEC} == KEYS
    text = help_text()
    for s in SPEC:
        assert s["example"] in text
    assert set(next(s for s in SPEC if s["key"] == "has")["values"]) == set(HAS)
    for value in HAS:
        compile_filter(f"has:{value}")


FAILURE_SAMPLES = [
    {"status": 200, "error": "", "grpc": False, "grpc_status": -1},
    {"status": 404, "error": "", "grpc": False, "grpc_status": -1},
    {"status": 503, "error": "", "grpc": False, "grpc_status": -1},
    {"status": 0, "error": "connection reset", "grpc": False, "grpc_status": -1},
    {"status": 200, "error": "", "grpc": True, "grpc_status": 0},
    {"status": 200, "error": "", "grpc": True, "grpc_status": 3},
    {"status": 200, "error": "", "grpc": True, "grpc_status": -1},
]


@pytest.mark.parametrize("sample", FAILURE_SAMPLES)
def test_error_and_fail_agree_in_sql_and_python(sample):
    chdb = pytest.importorskip("chdb")
    from m2c import schema

    row = (f"SELECT {sample['status']}::UInt16 AS status, '{sample['error']}' AS error, {str(sample['grpc']).lower()} AS grpc, "
           f"{sample['grpc_status']}::Int16 AS grpc_status")
    got = chdb.query(f"SELECT {schema.ERROR} AS e, {schema.FAILED} AS f FROM ({row})", "JSONEachRow").bytes()
    import json

    sql = json.loads(got)
    assert bool(sql["e"]) is schema.is_error(sample) is matcher("has:error")(sample)
    assert bool(sql["f"]) is schema.is_failed(sample) is matcher("has:fail")(sample)
    assert schema.is_failed(sample) or not schema.is_error(sample)  # every error is a failure


def _serialize(nodes):
    from m2c.filters import Group

    out = []
    for n in nodes:
        if isinstance(n, Group):
            out.append({"neg": n.neg, "group": _serialize(n.items), "start": n.start, "end": n.end})
        else:
            out.append({"neg": n.neg, "key": n.key, "values": n.values, "start": n.start, "end": n.end})
    return out


def test_parse_matches_the_shared_fixture():
    """tests/fixtures/queries.json pins the tokenizer: the web UI's ui/lib/query.js is tested against it too."""
    import json
    import pathlib

    from m2c.filters import parse

    for case in json.loads((pathlib.Path(__file__).parents[1] / "fixtures" / "queries.json").read_text()):
        if "error" in case:
            with pytest.raises(FilterError, match=__import__("re").escape(case["error"])):
                parse(case["q"])
        else:
            assert _serialize(parse(case["q"])) == case["nodes"], case["q"]


ROW = {"n": 3, "session": "s1", "tool": "ffuf", "status": 404, "duration_ms": 2500, "resp_body_size": 2048, "scheme": "http",
       "url": "http://h.test/admin", "host": "h.test", "path": "/admin", "error": "", "grpc": False, "grpc_status": -1}


@pytest.mark.parametrize("q,expected", [
    ("scheme:http", True), ("scheme:HTTPS", False), ("dur:>2s", True), ("dur:>=2500", True), ("dur:<2.5s", False), ("dur:2s", True),
    ("dur:3s", False), ("size:>1k", True), ("size:<2k", False), ("size:2kb", True), ("size:>1m", False),
    ("-(tool:ffuf status:404)", False), ("-(tool:ffuf status:500)", True), ("(tool:ffuf status:404) host:h.test", True),
    ("-(tool:x -(status:404))", True), ("-(admin)", False),
])
def test_new_keys_and_groups_agree_in_sql_and_python(q, expected):
    chdb = pytest.importorskip("chdb")
    from chdb import session as chs

    assert matcher(q)(ROW) is expected
    where, params = compile_filter(q)
    row = ("SELECT 3::UInt64 AS n, 's1' AS session, 'ffuf' AS tool, 404::UInt16 AS status, 2500::UInt32 AS duration_ms, "
           "2048::UInt64 AS resp_body_size, 'http' AS scheme, 'http://h.test/admin' AS url, 'h.test' AS host, '/admin' AS path")
    sess = chs.Session()
    got = sess.query(f"SELECT count() AS c FROM ({row}) WHERE {where}", "JSONEachRow", params=params).bytes()
    assert bool(__import__("json").loads(got)["c"]) is expected


@pytest.mark.parametrize("q,expected", [
    ("hdr:authorization", True), ("hdr:AUTH*", True), ("hdr:cookie", False), ("hdr:authorization=Bearer*", True),
    ("hdr:authorization=bearer", False), ("rhdr:set-cookie", True), ("-hdr:authorization", False),
])
def test_header_keys(q, expected):
    pytest.importorskip("chdb")
    from chdb import session as chs

    where, params = compile_filter(q)
    row = ("SELECT CAST([('Authorization', 'Bearer abc')] AS Array(Tuple(name String, value String))) AS req_headers, "
           "CAST([('Set-Cookie', 'a=1')] AS Array(Tuple(name String, value String))) AS resp_headers")
    got = chs.Session().query(f"SELECT count() AS c FROM ({row}) WHERE {where}", "JSONEachRow", params=params).bytes()
    assert bool(__import__("json").loads(got)["c"]) is expected
    assert split_matcher(q)[1] is False  # headers are not in the live summaries


@pytest.mark.parametrize("q", ["dur:fast", "dur:>2y", "size:>1t", "dur:99999999h", "hdr:", "hdr:=x", "(a", "()", "-(b"])
def test_new_bad_filters(q):
    with pytest.raises(FilterError):
        compile_filter(q)


def test_negated_group_with_a_database_term_preselects_nothing_out():
    pred, exact = split_matcher('-(tool:ffuf body:"x")')
    assert not exact and pred(ROW)  # the body may not contain x: the flow can match
    pred, exact = split_matcher('(tool:ffuf body:"x")')
    assert not exact and pred(ROW) and not pred({**ROW, "tool": "curl"})
