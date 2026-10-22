"""The web UI in a real browser (Playwright): loading under the strict CSP, live rows, the filter box's suggestions,
the context menu, hints, deep links and history, the virtual table, and the JS tokenizer against the shared fixture.

Skipped when Playwright or a Chromium build is not available. A cached build of another Playwright version works too.
"""

import glob
import json
import os
import subprocess
import threading
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.integration
sync_api = pytest.importorskip("playwright.sync_api")
FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "queries.json"


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception:  # noqa: BLE001 - this Playwright's own build is missing: try a cached one
            cached = sorted(glob.glob(os.path.expanduser("~/.cache/ms-playwright/chromium_headless_shell-*/*/chrome-headless-shell")))
            if not cached:
                pytest.skip("no Chromium for Playwright (run: playwright install chromium)")
            b = p.chromium.launch(executable_path=cached[-1])
        yield b
        b.close()


@pytest.fixture
def ui(browser, proxy):
    info = json.loads((proxy.data / "api.json").read_text())
    ctx = browser.new_context(viewport={"width": 1400, "height": 900})
    page = ctx.new_page()
    page.add_init_script("window.__csp = []; document.addEventListener('securitypolicyviolation', "
                         "(e) => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI));")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"{info['url']}/ui/#token={info['token']}")
    page.wait_for_selector(".top", timeout=10000)
    page.errors = errors
    page.base = info["url"]
    yield page
    assert page.evaluate("window.__csp") == [], "CSP violations"
    assert errors == [], errors
    ctx.close()


def curl(proxy, user, tok, url, *extra):
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url(user, tok), *extra, url], check=True)


Q = "new URLSearchParams(location.hash.split('?')[1] || '').get('q') || ''"  # the applied query, as JS


def q_of(page) -> str:
    return page.evaluate(f"() => {Q}")


def test_loads_shows_live_rows_and_deep_links(ui, proxy, upstream):
    tok = proxy.token("s1")
    up = f"http://127.0.0.1:{upstream}"
    for path in ("/hello", "/bin", "/sse"):
        curl(proxy, "s1.curl", tok, up + path)
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length >= 3", timeout=10000)
    assert ui.evaluate("location.hash").startswith("#/flows")  # the token left the address bar
    curl(proxy, "s1.late", tok, up + "/hello")  # arrives live, no reload
    ui.wait_for_selector(".vbody .row:has-text('s1 / late')", timeout=5000)
    ui.keyboard.press("j")
    ui.wait_for_selector(".detail .title")
    n = ui.evaluate("new URLSearchParams(location.hash.split('?')[1]).get('n')")
    ui.keyboard.press("]")
    assert "tab=req" in ui.evaluate("location.hash")
    ui.wait_for_selector(".detail h3:has-text('Request headers')")
    # a deep link opens the same flow and tab after a reload
    ui.goto(f"{ui.base}/ui/?again#/flows?n={n}&tab=resp")
    ui.wait_for_selector(f".detail .title:has-text('#{n}')", timeout=10000)
    assert ui.locator(".tab.on").inner_text() == "Response"


def test_filter_box_suggests_keys_and_values_and_rejects_bad_queries(ui, proxy, upstream):
    tok = proxy.token("s2")
    up = f"http://127.0.0.1:{upstream}"
    for tool in ("curl", "curl", "wget"):
        curl(proxy, f"s2.{tool}", tok, up + "/hello")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length >= 3", timeout=10000)
    time.sleep(0.6)  # value suggestions come from the database: one writer flush
    box = ui.locator("#q")
    box.click()
    box.press_sequentially("too")
    ui.wait_for_selector("#q-list li:has-text('tool:')")
    box.press("Tab")
    ui.wait_for_selector("#q-list li:has-text('curl')")
    counts = ui.locator("#q-list li").all_inner_texts()
    assert any("curl" in c and "2" in c for c in counts) and any("wget" in c for c in counts)
    box.press("Tab")  # the first value: curl, applied at once
    ui.wait_for_function("() => location.hash.includes('q=tool%3Acurl')")
    ui.wait_for_function("() => [...document.querySelectorAll('.vbody .c-who')].every((c) => c.textContent.includes('curl'))")
    assert box.input_value() == "tool:curl "
    box.press_sequentially("(oops")
    box.press("Enter")
    ui.wait_for_selector(".filter-error:has-text('unclosed')")
    assert q_of(ui) == "tool:curl"  # the bad query was not applied
    box.press("Escape")
    box.press("Escape")  # closes the list, then reverts the text
    assert box.input_value() == "tool:curl"


def test_context_menu_hints_and_back(ui, proxy, upstream):
    tok = proxy.token("s3")
    up = f"http://127.0.0.1:{upstream}"
    paths = " ".join(f"{up}/nope{i}" for i in range(24)).split()
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("s3.ffuf", tok), *paths], check=True)
    curl(proxy, "s3.curl", tok, up + "/hello")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length >= 25", timeout=10000)
    # hints come from the database: reload once the writer has the rows
    time.sleep(0.6)
    ui.reload()
    hint = ui.locator(".hint:has-text('hide them')")
    hint.wait_for(timeout=10000)
    hint.click()
    ui.wait_for_function(f"() => ({Q}).includes('-(tool:ffuf status:404)')")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length === 1")
    ui.go_back()
    ui.wait_for_function("() => !location.hash.includes('ffuf')")
    # right-click a status cell: exclude it
    ui.locator(".vbody .row:has-text('s3 / ffuf') .c-status").first.click(button="right")
    ui.locator(".menu li:has-text('Exclude')").first.click()
    ui.wait_for_function(f"() => ({Q}).includes('-status:404')")
    assert "-status:404" in q_of(ui)


def test_an_open_stream_survives_a_filter_change(ui, proxy, upstream):
    tok = proxy.token("s4")
    stream = threading.Thread(target=curl, args=(proxy, "s4.stream", tok, f"http://127.0.0.1:{upstream}/slow-sse?count=12"))
    stream.start()
    ui.wait_for_selector(".vbody .row.open", timeout=10000)
    box = ui.locator("#q")
    for q in ("session:s4", ""):
        box.fill(q)
        box.press("Enter")
        ui.wait_for_function(f"() => ({Q}) === {json.dumps(q)}")
        ui.wait_for_selector(".vbody .row.open", timeout=5000)  # still listed while it streams
    ui.locator(".vbody .row.open").click()
    ui.wait_for_function("() => document.querySelectorAll('.detail .ev').length >= 2", timeout=10000)
    stream.join()


def test_the_table_renders_only_the_rows_in_view(ui, proxy, upstream):
    tok = proxy.token("s5")
    up = f"http://127.0.0.1:{upstream}"
    for batch in range(3):
        subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", proxy.url("s5.bulk", tok), *[f"{up}/hello?{batch}-{i}" for i in range(200)]], check=True)
    time.sleep(0.6)
    ui.reload()
    ui.wait_for_selector(".vbody .row")
    for _ in range(20):  # each scroll to the bottom loads one older page
        ui.locator(".vbody").evaluate("(el) => { el.scrollTop = el.scrollHeight; }")
        time.sleep(0.3)
        if int(ui.locator("[role=grid]").get_attribute("aria-rowcount")) > 600:
            break
    assert int(ui.locator("[role=grid]").get_attribute("aria-rowcount")) > 600
    assert ui.evaluate("document.querySelectorAll('.vbody .row').length") < 100


def test_js_tokenizer_matches_the_shared_fixture(ui):
    from m2c.filters import KEYS

    mismatches = ui.evaluate(
        """async ([cases, keys]) => {
          const { parse } = await import('/ui/lib/query.js');
          const set = new Set(keys), bad = [];
          for (const c of cases) {
            let got;
            try { got = { nodes: parse(c.q, set) }; } catch (e) { got = { error: e.message }; }
            const want = c.error ? { error: c.error } : { nodes: c.nodes };
            if (JSON.stringify(got) !== JSON.stringify(want)) bad.push(c.q);
          }
          return bad;
        }""",
        [json.loads(FIXTURE.read_text()), sorted(KEYS)],
    )
    assert mismatches == []


def test_theme_persists(ui):
    ui.keyboard.press("t")
    ui.wait_for_function("() => document.documentElement.dataset.theme === 'light'")  # applied after the next paint
    ui.reload()
    ui.wait_for_selector(".top")
    ui.wait_for_function("() => document.documentElement.dataset.theme === 'light'")


def test_sessions_events_and_compare_views(ui, proxy, upstream):
    up = f"http://127.0.0.1:{upstream}"
    toks = {s: proxy.token(s) for s in ("alpha", "beta")}
    for s, paths in (("alpha", ("/hello", "/bin")), ("beta", ("/hello", "/nope"))):
        for path in paths:
            curl(proxy, f"{s}.curl", toks[s], up + path)
    subprocess.run(["curl", "-sS", "-o", "/dev/null", "-x", f"http://beta.curl:wrong@127.0.0.1:{proxy.port}", up + "/hello"], check=False)
    time.sleep(0.6)

    # Sessions: a row per session, a report for the selected one, Show flows filters the flows view
    ui.locator("a.view-tab", has_text="Sessions").click()
    ui.wait_for_selector(".sgroup:has-text('alpha')")
    assert ui.locator(".sgroup").count() == 2
    ui.locator(".sgroup", has_text="beta").locator(".srow").first.click()
    ui.wait_for_selector(".report h2:has-text('beta')")
    ui.locator(".pill-btn", has_text="last hour").click()
    ui.wait_for_function(f"() => ({Q}) === 'after:1h'")
    ui.locator(".report button", has_text="Show flows").click()
    ui.wait_for_function(f"() => location.hash.startsWith('#/flows') && ({Q}).includes('session:beta')")

    # Events: the rejected login, with what to do about it
    ui.locator("a.view-tab", has_text="Events").click()
    ui.wait_for_selector(".erow:has-text('auth_rejected')")
    ui.locator(".erow", has_text="auth_rejected").first.click()
    ui.wait_for_selector(".fix:has-text('m2c mint beta')")

    # Compare: select one flow, right-click another, "Compare with #N"
    ui.locator("a.view-tab", has_text="Flows").click()
    box = ui.locator("#q")
    box.fill("session:beta")
    box.press("Enter")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length === 2")
    rows = ui.locator(".vbody .row")
    rows.nth(0).click()
    a = int(rows.nth(0).locator(".c-n").inner_text())
    b = int(rows.nth(1).locator(".c-n").inner_text())
    rows.nth(1).locator(".c-url").click(button="right")
    ui.locator(".menu li", has_text=f"Compare with #{a}").click()
    ui.wait_for_function(f"() => location.hash === '#/diff/{a}/{b}'")
    ui.wait_for_selector(".chip:has-text('status')")
    ui.wait_for_selector(".dl:has-text('url')")
    ui.locator("button.swap").click()
    ui.wait_for_function(f"() => location.hash === '#/diff/{b}/{a}'")
    ui.go_back()
    ui.wait_for_function(f"() => location.hash === '#/diff/{a}/{b}'")


def test_too_many_database_tails_shows_a_banner_and_recovers(ui, proxy):
    """Tails with body: filters need the database; past the limit the API answers 429 and the UI says so, backs off,
    and reconnects once a slot is free."""
    info = json.loads((proxy.data / "api.json").read_text())
    hogs = [subprocess.Popen(["curl", "-sN", "--noproxy", "*", "-o", "/dev/null", "-H", f"Authorization: Bearer {info['token']}",
                              info["url"] + "/v1/tail?q=body:x"]) for _ in range(4)]  # the admin's limit
    try:
        time.sleep(0.8)
        box = ui.locator("#q")
        box.fill('body:"needle"')
        box.press("Enter")
        ui.wait_for_selector(".banner:has-text('too many open tails')", timeout=10000)
    finally:
        for h in hogs:
            h.kill()
    ui.wait_for_selector(".banner", state="detached", timeout=20000)  # a slot is free again: live
    assert ui.locator(".btn .dot-live").count() == 1


def test_notes_label_a_flow_and_filter_by_it(ui, proxy, upstream):
    tok = proxy.token("s6")
    for path in ("/hello", "/bin"):
        curl(proxy, "s6.curl", tok, f"http://127.0.0.1:{upstream}{path}")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length >= 2", timeout=10000)
    ui.locator(".vbody .row", has_text="/bin").click()
    ui.keyboard.press("a")  # annotate: the Notes tab, label field focused
    ui.wait_for_function("() => document.activeElement && document.activeElement.getAttribute('list') === 'note-labels'")
    ui.keyboard.type("todo")
    ui.locator(".note-editor textarea").fill("binary download: check what it is")
    ui.locator(".note-editor select").select_option("orange")
    ui.locator(".note-editor button", has_text="Add").click()
    ui.wait_for_selector(".note-card:has-text('binary download')")
    ui.wait_for_selector(".vbody .row:has-text('/bin') .nlabel.nc-orange:has-text('todo')", timeout=5000)  # the chip in the list
    time.sleep(0.6)
    box = ui.locator("#q")
    box.fill("label:todo")
    box.press("Enter")
    ui.wait_for_function("() => document.querySelectorAll('.vbody .row').length === 1")
    assert "/bin" in ui.locator(".vbody .row").inner_text()
    ui.locator(".vbody .row").click()
    ui.locator(".tab", has_text="Notes").click()
    ui.locator(".note-card button", has_text="delete").click()
    ui.wait_for_selector(".notes:has-text('No notes on this flow yet')")


def test_repeat_tab_resends_an_edited_request_and_compares(browser, tmp_path, upstream):
    from conftest import Proxy

    p = Proxy(tmp_path, extra=["--repeater", "admin"])
    try:
        tok = p.token("s7")
        curl(p, "s7.curl", tok, f"http://127.0.0.1:{upstream}/post", "-H", "Content-Type: application/json", "-d", '{"user": "a", "pin": "1111"}')
        time.sleep(0.6)
        info = json.loads((p.data / "api.json").read_text())
        ctx = browser.new_context(viewport={"width": 1400, "height": 900})
        page = ctx.new_page()
        page.goto(f"{info['url']}/ui/#token={info['token']}")
        page.wait_for_selector(".vbody .row")
        page.locator(".vbody .row").first.click()
        page.locator(".tab", has_text="Repeat").click()
        body = page.locator(".repeat textarea").nth(1)
        body.wait_for()
        page.wait_for_function("() => document.querySelectorAll('.repeat textarea')[1].value.includes('1111')")
        body.fill('{"user": "a", "pin": "2222"}')
        page.locator(".repeat button", has_text="Send").click()
        page.wait_for_selector(".repeat-result:has-text('200')", timeout=15000)
        page.locator(".repeat-result button", has_text="Compare").click()
        page.wait_for_selector(".prow:has-text('$.pin')", timeout=10000)
        assert "2222" in page.locator(".prow", has_text="$.pin").inner_text()
        ctx.close()
    finally:
        p.stop()
