from m2c.filters import compile_filter
from m2c.suggest import hints


def top(*pairs):
    return [{"item": item, "count": count, "error": 0} for item, count in pairs]


AGG = {"total": 410, "failures": 330, "errors": 12, "tools": top(("ffuf", 320), ("curl", 60)), "hosts": top(("h.test", 400)),
       "statuses": top((404, 312), (200, 80)), "tool_status": top((["ffuf", 404], 312)), "sessions": top(("recon-1", 380), ("b", 30)),
       "n_sessions": 2, "error_kinds": top(("timeout", 9)), "p95": 2340.0, "cleartext_creds": 4}


def test_hints_for_noisy_fuzzing():
    got = {h["text"]: h for h in hints("", AGG, open_flows=2)}
    texts = list(got)
    assert texts[0] == "4 send credentials over plain HTTP"
    noise = got["312 of 410 are ffuf 404s: hide them"]
    assert noise["kind"] == "exclude" and noise["query"] == "-(tool:ffuf status:404)"
    assert got["330 of 410 failed (4xx, 5xx or errors)"]["query"] == "has:fail"
    assert got["9 timeout errors"]["query"] == "err:timeout"
    assert got["the slowest 5% take over 2.3s"]["query"] == "dur:>2.3s"
    assert len(got) == 6  # capped: the session and open-flow hints don't fit
    for h in got.values():
        if h["query"]:
            compile_filter(h["query"])  # every suggested query is valid


def test_hints_respect_the_query():
    q = "tool:ffuf has:fail"
    got = hints(q, {**AGG, "cleartext_creds": 0})
    assert all(h["query"].startswith(q) for h in got if h["query"])
    assert not any("failed" in h["text"] for h in got)  # has: is pinned
    noise = [h for h in got if h["kind"] == "exclude"]
    assert noise and noise[0]["query"] == q + " -status:404"  # tool is pinned: the single-key form
    again = hints(noise[0]["query"], AGG)
    assert not any(h["query"] and h["query"].count("-status:404") > 1 for h in again)


def test_no_noise_hints_on_small_or_uniform_results():
    small = {**AGG, "total": 10, "tool_status": top((["ffuf", 404], 9)), "statuses": top((404, 9)), "cleartext_creds": 0, "p95": 5000}
    assert not any(h["kind"] == "exclude" for h in hints("", small))
    uniform = {**AGG, "tool_status": top((["ffuf", 404], 410)), "statuses": top((404, 410)), "hosts": top(("h", 410)), "tools": top(("ffuf", 410))}
    assert not any(h["kind"] == "exclude" for h in hints("", uniform))  # hiding everything is no hint
    quoted = hints("", {**AGG, "cleartext_creds": 0, "failures": 0, "error_kinds": [], "p95": 0,
                        "tool_status": top((["my tool", 404], 300))})
    assert quoted[0]["query"] == '-(tool:"my tool" status:404)'
    compile_filter(quoted[0]["query"])
