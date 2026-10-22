"""Record docs/demo.gif: the web UI while two agent runs send traffic through m2c.

    uv run --with playwright python docs/demo/make_gif.py      # uses the installed Google Chrome; needs ffmpeg

A local upstream plays the *.acme.test sites. demo_hosts.py (loaded before m2c's add-on) sends their traffic to it
and puts the original host back before m2c records the flow, so the UI shows real-looking URLs. Screenshots are
taken while a scripted mouse clicks through the UI; ffmpeg turns them into a GIF with one shared palette.
"""

from __future__ import annotations

import asyncio
import base64
import http.client
import json
import os
import random
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from playwright.async_api import async_playwright

ROOT = Path(__file__).resolve().parents[2]
M2C = str(ROOT / ".venv" / "bin" / "m2c")
OUT = ROOT / "docs" / "demo.gif"
WIDTH, HEIGHT, FPS = 1280, 720, 10

DEMO_HOSTS = '''
"""Demo only: send *.acme.test to the local demo upstream, and show the original host again before m2c records."""
import os
UP = int(os.environ["M2C_DEMO_UPSTREAM"])
class DemoHosts:
    def requestheaders(self, flow):
        if flow.request.host.endswith(".acme.test"):
            flow.metadata["demo_host"] = (flow.request.host, flow.request.port)
            flow.request.host, flow.request.port = "127.0.0.1", UP
            flow.request.headers["Host"] = flow.metadata["demo_host"][0]
    def responseheaders(self, flow):
        self._restore(flow)
    def response(self, flow):
        self._restore(flow)
    def error(self, flow):
        self._restore(flow)
    def _restore(self, flow):
        orig = flow.metadata.pop("demo_host", None)
        if orig:
            flow.request.host, flow.request.port = orig
addons = [DemoHosts()]
'''


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- the demo upstream

USERS = [{"id": i, "email": f"user{i}@acme.test", "role": r} for i, r in enumerate(["admin", "member", "member", "billing", "member"], 1)]


def route(method: str, host: str, path: str, body: bytes) -> tuple[int, str, bytes]:
    j = lambda o: json.dumps(o, indent=None).encode()  # noqa: E731
    if host == "api.acme.test":
        if path.startswith("/v1/users/"):
            uid = path.rsplit("/", 1)[1]
            return (200, "application/json", j(USERS[int(uid) % 5])) if uid.isdigit() else (404, "application/json", j({"error": "not found"}))
        if path == "/v1/users":
            return 200, "application/json", j({"data": USERS, "next": None})
        if path == "/v1/orders":
            return 200, "application/json", j({"data": [{"id": 4410 + i, "total": round(19.99 * i, 2), "status": "paid"} for i in range(1, 4)]})
        if path == "/login":
            return (500, "application/json", j({"error": "internal", "trace": "NullReferenceException at AuthService.Login"})) if b"'" in body else (401, "application/json", j({"error": "invalid credentials"}))
        if path == "/graphql":
            return 200, "application/json", j({"data": {"__schema": {"types": [{"name": "User"}, {"name": "Order"}, {"name": "Query"}]}}})
        if path.startswith("/admin"):
            return 403, "application/json", j({"error": "forbidden"})
        return 404, "text/plain", b"not found\n"
    if host == "app.acme.test":
        if path == "/":
            return 200, "text/html", b"<!doctype html><title>Acme</title><h1>Acme dashboard</h1><script src='https://cdn.acme.test/app.js'></script>"
        return 404, "text/html", b"<h1>404</h1>"
    if host == "cdn.acme.test":
        return 200, "application/javascript", b"console.log('acme app');" * 40
    return 502, "text/plain", b"unknown host\n"


async def handler(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while True:
            head = await reader.readuntil(b"\r\n\r\n")
            line, _, rest = head.decode("latin-1").partition("\r\n")
            method, target, _ = line.split(" ", 2)
            headers = {k.strip().lower(): v.strip() for k, _, v in (h.partition(":") for h in rest.split("\r\n") if h)}
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            host = headers.get("host", "").split(":")[0]
            path = target.split("?")[0]
            if path == "/events":
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                kinds = ["order.created", "order.paid", "user.login", "order.shipped", "user.updated"]
                for i in range(30):
                    ev = f'event: {kinds[i % 5]}\ndata: {{"seq": {i}, "id": {4410 + i}, "at": "{time.strftime("%H:%M:%S")}"}}\n\n'.encode()
                    writer.write(b"%x\r\n%s\r\n" % (len(ev), ev))
                    await writer.drain()
                    await asyncio.sleep(0.45)
                writer.write(b"0\r\n\r\n")
                await writer.drain()
                continue
            status, ctype, data = route(method, host, path, body)
            await asyncio.sleep(random.uniform(0.01, 0.12))
            writer.write(f"HTTP/1.1 {status} {http.client.responses[status]}\r\nContent-Type: {ctype}\r\nContent-Length: {len(data)}\r\n"
                         f"Server: acme/1.4\r\n\r\n".encode() + data)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError, ValueError):
        pass
    finally:
        writer.close()


def start_upstream() -> int:
    port = free_port()
    ready = threading.Event()

    def run():
        loop = asyncio.new_event_loop()
        loop.run_until_complete(asyncio.start_server(handler, "127.0.0.1", port))
        ready.set()
        loop.run_forever()

    threading.Thread(target=run, daemon=True).start()
    ready.wait(5)
    return port


# --------------------------------------------------------------------------- traffic


class Agent:
    def __init__(self, proxy_port: int, data: Path, session: str):
        token = subprocess.run([M2C, "mint", session, "--data", str(data)], capture_output=True, text=True, check=True).stdout.strip()
        self.port, self.session, self.token = proxy_port, session, token
        self.calls: dict[str, str] = {}  # tool -> the current call id (what the Claude Code hooks set per Bash call)

    def send(self, tool: str, method: str, url: str, body: dict | str | None = None, call: str = "") -> None:
        call = call or self.calls.get(tool, "")
        user = f"{self.session}.{tool}" + (f".{call}" if call else "")
        auth = "Basic " + base64.b64encode(f"{user}:{self.token}".encode()).decode()
        headers = {"Proxy-Authorization": auth, "User-Agent": {"curl": "curl/8.5.0", "nuclei": "Nuclei - Open-source project",
                   "ffuf": "Fuzz Faster U Fool v2.1", "python": "python-requests/2.32", "browser": "Mozilla/5.0 Chrome/131"}.get(tool, tool)}
        data = None
        if body is not None:
            data = json.dumps(body).encode() if isinstance(body, dict) else body.encode()
            headers["Content-Type"] = "application/json" if isinstance(body, dict) else "application/x-www-form-urlencoded"
        c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
        c.request(method, url, body=data, headers=headers)
        c.getresponse().read()
        c.close()

    def stream(self, tool: str, url: str) -> None:
        threading.Thread(target=self.send, args=(tool, "GET", url), daemon=True).start()


def background(a: Agent, b: Agent) -> list:
    """Work for the run before recording starts, and a script that keeps traffic flowing while it records."""
    before = [
        (b, "browser", "GET", "http://app.acme.test/", None), (b, "browser", "GET", "http://cdn.acme.test/app.js", None),
        (a, "curl", "GET", "http://api.acme.test/v1/users", None), (a, "curl", "GET", "http://api.acme.test/v1/users/1", None),
        (a, "nuclei", "GET", "http://api.acme.test/admin", None), (a, "nuclei", "GET", "http://api.acme.test/.env", None),
        (a, "nuclei", "POST", "http://api.acme.test/graphql", {"query": "{ __schema { types { name } } }"}),
        (b, "python", "GET", "http://api.acme.test/v1/orders", None), (a, "ffuf", "GET", "http://api.acme.test/backup.zip", None),
        (a, "ffuf", "GET", "http://api.acme.test/.git/config", None), (a, "curl", "POST", "http://api.acme.test/login", {"user": "admin", "password": "admin"}),
    ]
    during = [
        (a, "ffuf", "GET", "http://api.acme.test/api/v2", None), (b, "python", "GET", "http://api.acme.test/v1/users/2", None),
        (a, "nuclei", "GET", "http://api.acme.test/admin/settings", None), (a, "curl", "POST", "http://api.acme.test/login", {"user": "admin' OR '1'='1", "password": "x"}),
        (a, "ffuf", "GET", "http://api.acme.test/server-status", None), (b, "browser", "GET", "http://app.acme.test/", None),
        (b, "python", "GET", "http://api.acme.test/v1/orders", None), (a, "nuclei", "GET", "http://api.acme.test/v1/users/9999", None),
        (a, "ffuf", "GET", "http://api.acme.test/wp-admin", None), (b, "python", "GET", "http://api.acme.test/v1/users/3", None),
        (a, "curl", "GET", "http://api.acme.test/v1/users", None), (a, "ffuf", "GET", "http://api.acme.test/.svn/entries", None),
    ]
    a.calls = {"curl": "toolu_01KxR3", "nuclei": "toolu_01NvQ8", "ffuf": "toolu_01FzW2"}
    for agent, tool, method, url, body in before:
        agent.send(tool, method, url, body)
    a.calls = {"curl": "toolu_01Lp6M", "nuclei": "toolu_01Tq4D", "ffuf": "toolu_01Hc9J"}
    return during


# --------------------------------------------------------------------------- recording

CURSOR_JS = """
(() => {
  const c = document.createElement('div');
  c.id = 'demo-cursor';
  c.style.cssText = 'position:fixed;left:0;top:0;width:18px;height:18px;z-index:99999;pointer-events:none;transition:transform .05s linear;';
  // built with DOM calls: the UI's CSP (Trusted Types) refuses innerHTML
  const ns = 'http://www.w3.org/2000/svg', svg = document.createElementNS(ns, 'svg'), path = document.createElementNS(ns, 'path');
  for (const [k, v] of [['width', '18'], ['height', '18'], ['viewBox', '0 0 18 18']]) svg.setAttribute(k, v);
  for (const [k, v] of [['d', 'M2 1 L2 15 L6 11 L9 17 L11 16 L8 10 L14 10 Z'], ['fill', 'white'], ['stroke', 'black'], ['stroke-width', '1.2']]) path.setAttribute(k, v);
  svg.appendChild(path);
  c.appendChild(svg);
  document.body.appendChild(c);
  document.addEventListener('mousemove', e => { c.style.transform = `translate(${e.clientX - 2}px, ${e.clientY - 1}px)`; });
})();
"""


async def glide(page, x: float, y: float, steps: int = 12) -> None:
    await page.mouse.move(x, y, steps=steps)
    await asyncio.sleep(0.15)


async def click_on(page, locator) -> None:
    await locator.wait_for(state="visible", timeout=10000)
    box = await locator.bounding_box()
    await glide(page, box["x"] + min(box["width"] / 2, 220), box["y"] + box["height"] / 2)
    await asyncio.sleep(0.25)
    await locator.click()


async def record(ui: str, frames: Path, during: list, agents: tuple[Agent, Agent]) -> list[float]:
    a, b = agents
    stamps: list[float] = []
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome")
        page = await browser.new_page(viewport={"width": WIDTH, "height": HEIGHT}, color_scheme="dark", device_scale_factor=1)
        await page.goto(ui)
        await page.wait_for_selector(".vbody .row")
        await page.evaluate(CURSOR_JS)
        await page.mouse.move(640, 420)
        stop = asyncio.Event()

        async def shoot():
            i = 0
            while not stop.is_set():
                t = time.perf_counter()
                await page.screenshot(path=str(frames / f"f{i:04d}.png"))
                stamps.append(t)
                i += 1
                await asyncio.sleep(max(0, 1 / FPS - (time.perf_counter() - t)))

        def trickle():
            for agent, tool, method, url, body in during:
                agent.send(tool, method, url, body)
                time.sleep(random.uniform(0.35, 0.8))

        shooter = asyncio.create_task(shoot())
        await asyncio.sleep(0.8)
        threading.Thread(target=trickle, daemon=True).start()
        await asyncio.sleep(1.2)
        b.stream("browser", "http://app.acme.test/events")              # a long-lived SSE stream opens
        await page.wait_for_selector(".vbody .row.open", timeout=10000)
        await asyncio.sleep(0.8)
        await click_on(page, page.locator(".vbody .row.open").first)     # watch its events arrive live
        await asyncio.sleep(4.5)
        await click_on(page, page.locator(".vbody .row", has_text="/v1/users").first)  # a JSON response as a tree
        await click_on(page, page.locator(".tabs .tab", has_text="Response"))
        await asyncio.sleep(2.2)
        await click_on(page, page.locator(".vbody .row", has_text="/login").first)
        await click_on(page, page.locator(".tabs .tab", has_text="Request"))     # what the tool sent
        await asyncio.sleep(1.8)
        await click_on(page, page.locator(".tabs .tab", has_text="Repeat"))      # edit it and send it again
        body = page.locator(".repeat textarea").nth(1)
        await page.wait_for_function("() => (document.querySelectorAll('.repeat textarea')[1] || {}).value?.includes('OR')")
        await click_on(page, body)
        await body.press("Control+a")
        await body.press_sequentially('{"user": "admin", "password": "x"}', delay=45)
        await asyncio.sleep(0.6)
        await click_on(page, page.locator(".repeat button", has_text="Send"))
        await page.wait_for_selector(".repeat-result", timeout=10000)
        await asyncio.sleep(1.2)
        await click_on(page, page.locator(".repeat-result button", has_text="Compare"))  # what the quote changed
        await page.wait_for_selector(".prow", timeout=10000)
        await asyncio.sleep(3.2)
        await click_on(page, page.locator(".view-tab", has_text="Flows"))
        await page.wait_for_selector(".vbody .row")
        await asyncio.sleep(0.8)
        q = page.locator("#q")
        await click_on(page, q)
        await q.press_sequentially("tool:", delay=90)                    # the values seen, with counts
        await asyncio.sleep(1.4)
        await q.press_sequentially("nu", delay=90)
        await asyncio.sleep(0.6)
        await q.press("Tab")                                             # picked and applied
        await asyncio.sleep(2.2)
        await q.fill("")
        await q.press("Enter")
        await asyncio.sleep(1.2)
        hint = page.locator("button.hint", has_text="hide them")         # a suggested refinement
        if await hint.count():
            await click_on(page, hint.first)
            await asyncio.sleep(2.2)
        await click_on(page, q)
        await q.fill("")
        await asyncio.sleep(0.3)
        await q.press("Enter")
        await page.wait_for_function("() => !location.hash.includes('q=')")
        await asyncio.sleep(0.6)
        await click_on(page, page.locator(".view-tab", has_text="Timeline"))  # flows grouped by the tool call that made them
        await page.wait_for_selector(".tl-call", timeout=10000)
        await asyncio.sleep(3.0)
        await click_on(page, page.locator(".view-tab", has_text="Sessions"))
        await asyncio.sleep(3.0)
        stop.set()
        await shooter
        await browser.close()
    return stamps


def to_gif(frames: Path, stamps: list[float], out: Path) -> None:
    listing = frames / "frames.txt"
    lines = []
    for i, t in enumerate(stamps):
        dur = (stamps[i + 1] - t) if i + 1 < len(stamps) else 1.5
        lines += [f"file 'f{i:04d}.png'", f"duration {dur:.3f}"]
    lines.append(f"file 'f{len(stamps) - 1:04d}.png'")
    listing.write_text("\n".join(lines) + "\n")
    scale = "scale=1100:-1:flags=lanczos"
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(listing), "-vf",
                    f"{scale},palettegen=max_colors=192:stats_mode=diff", str(frames / "palette.png")], check=True)
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-f", "concat", "-safe", "0", "-i", str(listing), "-i", str(frames / "palette.png"),
                    "-lavfi", f"{scale}[x];[x][1:v]paletteuse=dither=none:diff_mode=rectangle", "-loop", "0", str(out)], check=True)


def main() -> None:
    if not shutil.which("ffmpeg"):
        sys.exit("needs ffmpeg")
    work = Path(tempfile.mkdtemp(prefix="m2c-demo-"))
    data, frames = work / "data", work / "frames"
    frames.mkdir()
    (work / "demo_hosts.py").write_text(DEMO_HOSTS)
    up = start_upstream()
    proxy_port = free_port()
    # m2c's mitmdump command, with the demo add-on loaded first (so it restores hosts before m2c records)
    printed = subprocess.run([M2C, "proxy", "--listen", f"127.0.0.1:{proxy_port}", "--api", "127.0.0.1:0", "--data", str(data), "--repeater", "admin",
                              "--print"],
                             capture_output=True, text=True, check=True).stdout.strip()
    argv = shlex.split(printed)
    s = argv.index("-s")
    argv[s:s] = ["-s", str(work / "demo_hosts.py")]
    env = {**os.environ, "M2C_DEMO_UPSTREAM": str(up), "M2C_DATA": str(data)}
    proxy = subprocess.Popen(argv, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while not (data / "api.json").exists():
            time.sleep(0.1)
        info = json.loads((data / "api.json").read_text())
        agents = (Agent(proxy_port, data, "run-7f3a"), Agent(proxy_port, data, "run-2c91"))
        during = background(*agents)
        time.sleep(0.5)
        stamps = asyncio.run(record(f"{info['url']}/ui/#token={info['token']}", frames, during, agents))
        to_gif(frames, stamps, OUT)
        print(f"{OUT} ({OUT.stat().st_size / 1e6:.1f} MB, {len(stamps)} frames, {stamps[-1] - stamps[0]:.1f} s)")
    finally:
        proxy.terminate()
        proxy.wait(30)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
