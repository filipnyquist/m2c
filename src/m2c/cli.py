"""m2c: run the recording proxy, hand out credentials, and query a scan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import identity, state

DEFAULT_PROXY = "127.0.0.1:8080"
DEFAULT_DATA = "./m2c-data"
SYSTEM_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/cert.pem",
)


def _data(args) -> Path:
    return Path(args.data or os.environ.get("M2C_DATA") or DEFAULT_DATA).expanduser().resolve()


def _confdir(args) -> Path:
    return Path(args.confdir or os.environ.get("M2C_CONFDIR") or "~/.mitmproxy").expanduser()


def _secrets(args, create: bool = False) -> list[str]:
    """The proxy's secrets. Client commands never create one: a secret made next to the wrong data directory mints
    tokens the proxy rejects with 407 and nothing to say why."""
    data, configured = _data(args), args.secret_file or os.environ.get("M2C_SECRET_FILE", "")
    path = state.secret_file(data, configured)
    try:
        secrets = state.load_secrets(data, configured, os.environ.get("M2C_SECRET", ""), create=create)
    except PermissionError:
        sys.exit(f"m2c: cannot read {path} (the proxy runs as another user?); pass --token or M2C_TOKEN")
    if not secrets:
        sys.exit(f"m2c: no secret at {path}; point --data/M2C_DATA (or --secret-file, M2C_SECRET) at the proxy's, "
                 "or start `m2c proxy` once (or `m2c mint --init`) to create it")
    return secrets


def mitmdump_argv() -> list[str]:
    """mitmdump run by this same interpreter: works in a venv, a pipx/uv tool install and a relocated bundle
    (console-script shebangs would point at the build machine). -P: `-c` would put the working directory first on
    sys.path, and a json.py planted there would run with access to the secret."""
    return [sys.executable, "-P", "-c", "import sys; from mitmproxy.tools.main import mitmdump; sys.argv[0] = 'mitmdump'; sys.exit(mitmdump())"]


# --------------------------------------------------------------------------- proxy


def cmd_proxy(args) -> None:
    entry = Path(__file__).with_name("entry.py")
    data = _data(args)
    argv = [*mitmdump_argv(), "--mode", f"regular@{args.listen}"]
    if args.socks:
        argv += ["--mode", f"socks5@{args.socks}"]
    # eager (mitmproxy's default): the upstream's ALPN is known before the client's, so an HTTP/2 client is never
    # paired with an HTTP/1 server (lazy breaks HTTP/2 uploads without Content-Length to HTTP/1 servers with a 502).
    argv += ["-s", str(entry), "--set", "proxyauth=any", "--set", "connection_strategy=eager", "--set", f"confdir={_confdir(args)}"]
    argv += ["--set", f"m2c_data={data}", "--set", f"m2c_auth={args.auth}", "--set", f"m2c_api_listen={args.api}"]
    if args.no_ui:
        argv += ["--set", "m2c_ui=false"]
    if args.scan_id:
        argv += ["--set", f"m2c_scan_id={args.scan_id}"]
    if args.push_on_exit:
        argv += ["--set", f"m2c_push_on_exit={args.push_on_exit}"]
    if args.label:
        argv += ["--set", "m2c_labels=" + json.dumps(_labels(args.label))]  # JSON: values may hold ',' and '='
    if not args.verify_upstream:
        argv += ["--set", "ssl_insecure=true"]
    if not args.verbose:
        argv += ["--set", "flow_detail=0", "--set", "termlog_verbosity=warn"]
    argv += args.mitmproxy_args
    if args.print:
        print(shlex.join(argv))
        return
    os.execv(argv[0], argv)


# --------------------------------------------------------------------------- credentials


def cmd_mint(args) -> None:
    secret = _secrets(args, create=args.init)[0]
    ttl = parse_duration(args.ttl) if args.ttl else None
    token = identity.mint(secret, args.session, ttl)
    if args.json:
        print(json.dumps({"session": args.session, "token": token, "proxy_url": proxy_url(args.proxy, args.session, "tool", token)}))
    else:
        print(token)


def parse_duration(text: str) -> float:
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    text = text.strip().lower()
    if text[-1] in units:
        return float(text[:-1]) * units[text[-1]]
    return float(text)


def proxy_url(proxy: str, session: str, tool: str, token: str, call: str = "", scheme: str = "http") -> str:
    user = f"{session}.{tool}" + (f".{call}" if call else "")
    return f"{scheme}://{user}:{token}@{proxy}"


def ca_cert(confdir: Path) -> Path:
    return confdir / "mitmproxy-ca-cert.pem"


def ca_bundle(args) -> Path | None:
    """System CAs plus the proxy's CA in one PEM file (for SSL_CERT_FILE, REQUESTS_CA_BUNDLE, ...): in the data
    directory, or in the user's cache when that is not ours to write (a proxy running as another user)."""
    ca = ca_cert(_confdir(args))
    try:
        ca_text = ca.read_text() if ca.exists() else None
    except OSError as e:
        print(f"m2c: warning: cannot read the proxy CA {ca} ({e.strerror}); no CA bundle variables set", file=sys.stderr)
        return None
    if ca_text is None:
        return None
    system = next((Path(p) for p in SYSTEM_BUNDLES if Path(p).exists()), None)
    if system is None:
        try:
            import certifi

            system = Path(certifi.where())
        except ImportError:
            system = None
    parts = [system.read_text()] if system else []
    parts.append(ca_text)
    text = "\n".join(parts)
    data = _data(args)
    cache = Path(os.environ.get("XDG_CACHE_HOME") or "~/.cache").expanduser() / "m2c"
    candidates = [data / "ca-bundle.pem"] if os.path.isdir(data) else []
    candidates.append(cache / f"ca-bundle-{hashlib.sha256(text.encode()).hexdigest()[:16]}.pem")
    for out in candidates:
        try:
            if not out.exists() or out.read_text() != text:
                out.parent.mkdir(parents=True, exist_ok=True)
                out.write_text(text)
            return out
        except OSError:
            continue
    print(f"m2c: warning: cannot write a CA bundle to {' or '.join(map(str, candidates))}", file=sys.stderr)
    return None


def proxy_env(args) -> dict[str, str]:
    token = args.token or os.environ.get("M2C_TOKEN") or identity.mint(_secrets(args)[0], args.session)
    url = proxy_url(args.proxy, args.session, args.tool.lower(), token, args.call or "")
    bypass = ",".join(["localhost", "127.0.0.1", "::1", *(args.no_proxy or [])])
    env = {
        "HTTP_PROXY": url,
        "HTTPS_PROXY": url,
        "http_proxy": url,
        "https_proxy": url,
        "ALL_PROXY": url,
        "all_proxy": url,
        "NO_PROXY": bypass,
        "no_proxy": bypass,
        "NODE_USE_ENV_PROXY": "1",
    }
    bundle = ca_bundle(args)
    if bundle is not None:
        env.update(
            NODE_EXTRA_CA_CERTS=str(ca_cert(_confdir(args))),
            SSL_CERT_FILE=str(bundle),
            REQUESTS_CA_BUNDLE=str(bundle),
            CURL_CA_BUNDLE=str(bundle),
            GIT_SSL_CAINFO=str(bundle),
            AWS_CA_BUNDLE=str(bundle),
        )
    return env


def cmd_env(args) -> None:
    env = proxy_env(args)
    if args.json:
        print(json.dumps(env))
        return
    for k, v in env.items():
        print(f"export {k}={shlex.quote(v)}")


def _is_script(cmd: str) -> bool:
    path = shutil.which(cmd)
    try:
        with open(path, "rb") as f:  # type: ignore[arg-type]
            return f.read(2) == b"#!"
    except (OSError, TypeError):
        return False


# Tools that ignore the proxy environment variables, and the flags that make them use it. Not naabu: its -proxy is
# SOCKS5 only, with the credentials in another flag, and a port scan is not HTTP anyway.
def tool_flags(argv: list[str], url: str) -> list[str]:
    name = Path(argv[0]).name
    if name == "httpx" and _is_script(argv[0]):
        return argv  # the Python httpx CLI (ProjectDiscovery's is a Go binary): no such flags, it reads the environment
    if name in ("nuclei", "katana", "httpx", "subfinder"):
        extra = ["-proxy", url]
        if name in ("nuclei", "katana", "httpx"):
            extra.append("-duc")
        return [argv[0], *extra, *argv[1:]]
    if name == "sqlmap":
        bare = url.split("@", 1)
        creds = bare[0].split("://", 1)[1]
        return [argv[0], "--proxy", f"http://{bare[1]}", "--proxy-cred", creds, *argv[1:]]
    if name == "ffuf":
        return [argv[0], "-x", url, *argv[1:]]
    return argv


def cmd_run(args) -> None:
    if not args.command:
        sys.exit("m2c run: give a command after --")
    env = proxy_env(args)
    argv = tool_flags(args.command, env["HTTP_PROXY"]) if not args.no_tool_flags else args.command
    os.environ.update(env)
    try:
        os.execvp(argv[0], argv)
    except FileNotFoundError:
        sys.exit(f"m2c run: {argv[0]}: command not found")


# --------------------------------------------------------------------------- query


def _client(args):
    from .client import ClientError, connect

    try:
        client = connect(_data(args), getattr(args, "api", None), getattr(args, "token", None), getattr(args, "offline", False))
    except ClientError as e:
        sys.exit(f"m2c: {e}")
    if not client.online:
        from .writer import spool_files

        left = spool_files(_data(args) / "spool")
        if left:
            print(f"m2c: note: {sum(r for _, _, r in left)} rows are still in {_data(args)}/spool and not shown; "
                  "starting the proxy again (or `m2c push`) inserts them", file=sys.stderr)
    return client


def _when(ms: int) -> str:
    if not ms:
        return "-"
    t = datetime.fromtimestamp(ms / 1000)
    return t.strftime("%H:%M:%S.") + f"{t.microsecond // 1000:03d}"


def _size(n: int) -> str:
    n = int(n or 0)
    for unit in ("B", "K", "M", "G"):
        if n < 1024 or unit == "G":
            return f"{n}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return str(n)


def _flow_line(f: dict, width: int = 0) -> str:
    status = str(f["status"]) if f["status"] else ("ERR" if f.get("error") else "-")
    flags = {"sse": " sse", "websocket": " ws"}.get(f.get("resp_capture", ""), "")
    who = f"{f['session']}/{f['tool']}" + (f"#{f['call_id']}" if f.get("call_id") else "")
    target = f"{f['host']}{f['path']}"
    line = f"{f['n']:>6}  {_when(f['ts'])}  {who:<24.24}  {f['method']:<7} {status:<4} {_size(f['resp_body_size']):>7} {f['duration_ms']:>6}ms{flags}  {target}"
    return line[:width] if width else line


def _out_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, default=str))


def _run_client(fn):
    from .client import ClientError

    try:
        return fn()
    except ClientError as e:
        sys.exit(f"m2c: {e}")
    except Exception as e:  # noqa: BLE001 - offline query errors (bad filter, bad SQL)
        sys.exit(f"m2c: {e}")


def cmd_stats(args) -> None:
    stats = _run_client(lambda: _client(args).stats())
    if args.json:
        return _out_json(stats)
    for k, v in stats.items():
        print(f"{k:>16}: {v}")


def cmd_sessions(args) -> None:
    rows = _run_client(lambda: _client(args).sessions(args.query or ""))
    if args.json:
        for r in rows:
            _out_json(r)
        return
    print(f"{'session':<24} {'tool':<16} {'flows':>6} {'fail':>5} {'hosts':>5} {'up':>8} {'down':>8}  last seen")
    for r in rows:
        print(f"{r['session']:<24.24} {r['tool']:<16.16} {r['flows']:>6} {r['failures']:>5} {r['hosts']:>5} {_size(r['bytes_up']):>8} {_size(r['bytes_down']):>8}  {_when(r['last_seen'])}")


def cmd_ls(args) -> None:
    c = _client(args)
    page = _run_client(lambda: c.flows(args.query or "", args.limit, args.cursor, "desc"))
    flows = page["flows"][::-1]
    if args.json:
        for f in flows:
            _out_json(f)
        return
    width = shutil.get_terminal_size((200, 20)).columns if sys.stdout.isatty() else 0
    for f in flows:
        print(_flow_line(f, width))
    if page.get("next") and sys.stdout.isatty():
        print(f"... more: m2c ls --cursor {page['next']}" + (f" {shlex.quote(args.query)}" if args.query else ""), file=sys.stderr)


def _print_headers(title: str, pairs) -> None:
    print(title)
    for name, value in pairs:
        print(f"  {name}: {value}")


def _preview(data: bytes, limit: int) -> str:
    shown = data[:limit]
    try:
        text = shown.decode("utf-8")
    except UnicodeDecodeError:
        return f"  <{len(data)} bytes binary; m2c show N --body resp > file>"
    more = f"\n  ... {len(data) - limit} more bytes" if len(data) > limit else ""
    return "\n".join("  " + line for line in text.splitlines()) + more


def cmd_show(args) -> None:
    c = _client(args)
    if args.body or args.req_body:
        side = "req" if args.req_body else "resp"
        got = _run_client(lambda: c.body(args.n, side))
        if got is None:
            sys.exit(f"m2c: no flow #{args.n}")
        sys.stdout.buffer.write(got[0])
        return
    flow = _run_client(lambda: c.flow(args.n))
    if flow is None:
        sys.exit(f"m2c: no flow #{args.n}")
    if args.json:
        return _out_json(flow)
    if flow.get("pending"):
        print(f"#{flow['n']} is still being written; summary only:")
        return _out_json(flow)
    print(f"#{flow['n']}  {flow['method']} {flow['url']}")
    print(f"  {flow['status']} {flow['reason']}   {flow['duration_ms']}ms (ttfb {flow['ttfb_ms']}ms)   {_when(flow['ts'])}")
    print(f"  session {flow['session']}  tool {flow['tool']}" + (f"  call {flow['call_id']}" if flow["call_id"] else "")
          + (f"  tag {flow['tag']}" if flow["tag"] else "") + f"  via {flow['identity_source']}  ua {flow['ua_tool'] or '-'}")
    tls = f"  tls {flow['tls_version']} sni={flow['sni']} alpn={flow['alpn']}" if flow["tls"] else "  plain"
    print(f"{tls}   server {flow['server_ip']}:{flow['server_port']}   client {flow['client_ip']}:{flow['client_port']}")
    if flow["error"]:
        print(f"  error ({flow['error_kind']}): {flow['error']}")
    if flow["resp_capture"] == "websocket":
        print(f"  websocket: {flow['ws_message_count']} messages, closed {flow['ws_close_code']} {flow['ws_close_reason']} by {'client' if flow['ws_closed_by_client'] else 'server'}  (m2c ws {flow['n']})")
    if flow["resp_capture"] == "sse":
        print(f"  sse: {flow['sse_event_count']} events  (m2c sse {flow['n']})")
    print()
    _print_headers("> request headers", flow["req_headers"])
    if flow["req_body_stored"]:
        body = _run_client(lambda: c.body(args.n, "req", args.max))
        print(f"> request body ({_size(flow['req_body_size'])} on the wire{', truncated' if flow['req_body_truncated'] else ''})")
        print(_preview(body[0] if body else b"", args.max))
    print()
    _print_headers("< response headers", flow["resp_headers"])
    if flow["resp_body_stored"]:
        body = _run_client(lambda: c.body(args.n, "resp", args.max))
        print(f"< response body ({_size(flow['resp_body_size'])} on the wire{', decoded' if flow['resp_body_decoded'] else ''}{', truncated' if flow['resp_body_truncated'] else ''})")
        print(_preview(body[0] if body else b"", args.max))


def cmd_tail(args) -> None:
    c = _client(args)
    if not c.online:
        sys.exit("m2c: tail needs a running proxy")
    width = shutil.get_terminal_size((200, 20)).columns if sys.stdout.isatty() else 0
    try:
        for f in c.tail(args.query or "", args.backlog):
            if f.pop("_event") == "open":
                if args.json:
                    print(json.dumps({**f, "open": True}, ensure_ascii=False), flush=True)
                elif not args.no_open:
                    print(_flow_line({**f, "status": 0, "error": ""}, width).replace(" -    ", " ...  ", 1) + "  (open)", flush=True)
                continue
            print(json.dumps(f, ensure_ascii=False) if args.json else _flow_line(f, width), flush=True)
    except KeyboardInterrupt:
        pass


def cmd_children(args) -> None:
    c = _client(args)
    rows = _run_client(lambda: (c.sse if args.cmd == "sse" else c.ws)(args.n, args.after, args.limit))
    for r in rows:
        if args.json:
            _out_json(r)
        elif args.cmd == "sse":
            print(f"{r['seq']:>5} +{r['ms_since_req']}ms" + (f" [{r['event']}]" if r["event"] else "") + ("  (partial)" if r["partial"] else "") + f"  {r['data']}")
        else:
            arrow = ">" if r["from_client"] else "<"
            text = r["text"] if r["text"] else f"<{r['size']} bytes {r['opcode']}>"
            print(f"{r['seq']:>5} {_when(r['ts'])} {arrow} {text}")


def cmd_curl(args) -> None:
    cmd = _run_client(lambda: _client(args).curl(args.n))
    if cmd is None:
        sys.exit(f"m2c: no flow #{args.n}")
    print(cmd)


def cmd_har(args) -> None:
    _out_json(_run_client(lambda: _client(args).har(args.query or "", args.limit)))


def cmd_events(args) -> None:
    rows = _run_client(lambda: _client(args).events(args.kind or "", args.limit))
    for r in rows[::-1]:
        if args.json:
            _out_json(r)
        else:
            who = f"{r['session']}/{r['tool']}" if r["session"] else (r["proxy_user"] or "-")
            print(f"{_when(r['ts'])}  {r['kind']:<16} {r['severity']:<5} {who:<24.24} {r['reason']:<10} {r['host']}{':' + str(r['port']) if r['port'] else ''} {r['message'][:120]}")


def cmd_sql(args) -> None:
    out = _run_client(lambda: _client(args).sql(args.query, args.format))
    sys.stdout.buffer.write(out)
    sys.stdout.flush()


def cmd_mcp(args) -> None:
    from .mcp import serve_stdio

    c = _client(args)
    serve_stdio(c.mcp, sys.stdin.buffer, sys.stdout)  # a failing request gets an error reply; the server keeps going


# --------------------------------------------------------------------------- setup helpers


def cmd_ca(args) -> None:
    ca = ca_cert(_confdir(args))
    if not ca.exists():
        sys.exit(f"m2c: no CA yet at {ca}; start `m2c proxy` once (it creates it)")
    if args.action == "path":
        print(ca)
    elif args.action == "pem":
        sys.stdout.write(ca.read_text())
    else:
        bundle = ca_bundle(args)
        if bundle is None:
            sys.exit("m2c: no CA bundle written (see above)")
        print(bundle)


CLAUDE_HOOK = {
    "hooks": {
        "SessionStart": [
            {"hooks": [{"type": "command", "command": "m2c hook claude-code-session-start"}]}
        ]
    }
}


def cmd_hooks(args) -> None:
    if args.harness == "claude-code":
        print("# Add to .claude/settings.json (project) or ~/.claude/settings.json. Bash commands Claude runs then go")
        print("# through the proxy as <session_id>.bash; Claude Code's own API traffic does not.", file=sys.stderr)
        print(json.dumps(CLAUDE_HOOK, indent=2))
    else:
        print("# Generic harness: give each agent run its own session id and run tools with")
        print("#   m2c run --session <run id> --tool <tool> -- <command ...>")
        print("# or export the variables once per run (only into the tools' environment, never the agent's own):")
        print("#   eval \"$(m2c env --session <run id> --tool <tool>)\"")
        print("# A long-lived client can name the tool per request with the header  x-m2c-tool: <tool>")


def _session_id(raw: str) -> str:
    import re

    cleaned = re.sub(r"[^A-Za-z0-9_-]", "-", raw)[:64].strip("-")
    return cleaned or "session"


def cmd_hook(args) -> None:
    """Called by a harness hook; reads the hook's JSON on stdin."""
    if args.event != "claude-code-session-start":
        sys.exit(f"m2c: unknown hook {args.event}")
    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if not env_file:
        print("m2c: CLAUDE_ENV_FILE is not set; nothing to do", file=sys.stderr)
        return
    args.session = _session_id(str(event.get("session_id") or "session"))
    args.tool, args.call, args.token, args.no_proxy = args.tool or "bash", "", None, None
    env = proxy_env(args)
    with open(env_file, "a") as f:
        for k, v in env.items():
            f.write(f"export {k}={shlex.quote(v)}\n")


def cmd_doctor(args) -> None:
    ok = True

    def check(label: str, good: bool, detail: str = "") -> None:
        nonlocal ok
        ok &= good
        print(f"{'ok ' if good else 'BAD'}  {label}" + (f": {detail}" if detail else ""))

    try:
        import mitmproxy.version

        check("mitmproxy", True, mitmproxy.version.VERSION)
    except ImportError as e:
        check("mitmproxy", False, str(e))
    try:
        import importlib.metadata as md

        check("chdb", True, md.version("chdb-core") if md.packages_distributions().get("chdb") else "")
    except Exception as e:  # noqa: BLE001
        check("chdb", False, str(e))
    data = _data(args)
    check("data directory", data.exists() or os.access(data.parent, os.W_OK), str(data))
    ca = ca_cert(_confdir(args))
    check("proxy CA", ca.exists(), str(ca) if ca.exists() else f"{ca} (created on first `m2c proxy`)")
    info = data / "api.json"
    if info.exists():
        from .client import ClientError, Online

        meta = json.loads(info.read_text())
        try:
            Online(meta["url"], meta["token"]).stats()
            check("live API", True, meta["url"])
        except ClientError as e:
            check("live API", False, str(e))
    else:
        print("-    live API: no running proxy for this data directory")
    leaked = {k: v.split("@")[-1] for k, v in os.environ.items() if k.lower() in ("http_proxy", "https_proxy", "all_proxy")}
    if leaked:
        print(f"warn this shell has proxy variables set ({', '.join(sorted(leaked))} -> {next(iter(leaked.values()))}).")
        print("     Only tool subprocesses should get them: if this is the agent harness's own environment, its LLM API")
        print("     traffic would go through the proxy (and be recorded).")
    sys.exit(0 if ok else 1)


# --------------------------------------------------------------------------- central ClickHouse


def _labels(items) -> dict[str, str]:
    out = {}
    for item in items or []:
        key, sep, value = item.partition("=")
        if not sep or not key:
            sys.exit(f"m2c: --label takes key=value, got {item!r}")
        out[key] = value
    return out


def _replay_spool(sess, data: Path) -> None:
    """Insert batches a stopped proxy left in <data>/spool, so a push or export sees them."""
    from .db import insert_file
    from .writer import replay_spool

    dead = data / "dead"
    before = set(dead.glob("*.error.txt")) if dead.is_dir() else set()
    try:
        done, left = replay_spool(lambda table, cols, path, token: insert_file(sess.query, table, cols, path, token), data)
    except Exception as e:  # noqa: BLE001 - a push without those rows would report a complete scan
        sys.exit(f"m2c: could not insert the batches left in {data}/spool, nothing was pushed: {str(e).strip()[:500]}")
    if done:
        print(f"inserted {done} batches left in {data}/spool by the proxy", file=sys.stderr)
    rejected = 0
    for note in (set(dead.glob("*.error.txt")) if dead.is_dir() else set()) - before:
        try:
            rejected += int(note.read_text().split(" ", 1)[0])
        except (OSError, ValueError):
            pass
    if rejected:
        print(f"m2c: {rejected} rows from {data}/spool were rejected by chDB and moved to {dead}; they are not pushed",
              file=sys.stderr)
    if left:
        sys.exit(f"m2c: {left} batches are still in {data}/spool, nothing was pushed; run it again")


def cmd_push(args) -> None:
    from .db import open_session
    from .push import Pusher, PushError, Target

    data = _data(args)
    if not (data / "store").exists() and not (data / "metadata").exists():
        sys.exit(f"m2c: no scan data in {data}")
    try:
        target = Target.parse(args.to)
        if args.create and not target.native:
            from .push import central_init

            central_init(target)
        sess = open_session(data)
        _replay_spool(sess, data)
    except PushError as e:
        sys.exit(f"m2c: {e}")
    except RuntimeError as e:
        if "lock" in str(e).lower() or "already running" in str(e).lower():
            sys.exit(f"m2c: {data} is in use by a running proxy; stop it first, or start it with --push-on-exit")
        raise
    pusher = Pusher(lambda sql, fmt: sess.query(sql, fmt).bytes(), target, chunk_bytes=args.chunk_mb << 20,
                    progress=lambda msg: print(msg, file=sys.stderr))
    labels = _labels(args.label)
    try:
        result = pusher.push(labels)
    except (PushError, RuntimeError) as e:  # RuntimeError: a chDB error on the local side
        sys.exit(f"m2c: push failed: {target.scrub(str(e)).strip()[:1000]}")
    except KeyboardInterrupt:
        sys.exit("m2c: push interrupted; running it again sends only what is missing")
    (data / "push-failed.json").unlink(missing_ok=True)  # a push-on-exit that failed is now done by hand
    if args.json:
        _out_json(result)


def cmd_central(args) -> None:
    from .push import PushError, Target, central_init, central_statements

    if args.action == "ddl":
        db = args.database
        for sql in central_statements(db, args.engine, args.ttl_days, args.on_cluster):
            print(sql + ";\n")
        return
    try:
        target = Target.parse(args.to)
        n = central_init(target, args.engine, args.ttl_days, args.on_cluster)
    except PushError as e:
        sys.exit(f"m2c: {e}")
    print(f"central schema ready in {target.redacted} ({n} statements)", file=sys.stderr)


# --------------------------------------------------------------------------- main


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="m2c", description=__doc__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp, proxy=False):
        sp.add_argument("--data", help=f"scan data directory (env M2C_DATA, default {DEFAULT_DATA})")
        sp.add_argument("--secret-file", help="auth secret file (env M2C_SECRET_FILE, default <data>/secret)")
        sp.add_argument("--confdir", help="mitmproxy confdir holding the CA (env M2C_CONFDIR, default ~/.mitmproxy)")
        if proxy:
            sp.add_argument("--proxy", default=os.environ.get("M2C_PROXY"), help=f"proxy host:port (env M2C_PROXY; default: the running proxy from <data>/api.json, else {DEFAULT_PROXY})")

    sp = sub.add_parser("proxy", help="run the recording proxy (mitmdump with the recorder)")
    common(sp)
    sp.add_argument("--listen", default=os.environ.get("M2C_LISTEN", DEFAULT_PROXY), help="HTTP proxy listen address")
    sp.add_argument("--socks", default=os.environ.get("M2C_SOCKS", ""), help="also listen as SOCKS5 on host:port")
    sp.add_argument("--auth", default=os.environ.get("M2C_AUTH", "token"), choices=identity.MODES)
    sp.add_argument("--scan-id", default=os.environ.get("M2C_SCAN_ID", ""))
    sp.add_argument("--api", default=os.environ.get("M2C_API_LISTEN", "127.0.0.1:8124"), help="API/MCP/UI address; empty to turn it off")
    sp.add_argument("--no-ui", action="store_true", help="don't serve the web UI")
    sp.add_argument("--push-on-exit", default=os.environ.get("M2C_PUSH_ON_EXIT", ""), help="central ClickHouse URL to push to at shutdown")
    sp.add_argument("--label", action="append", help="key=value for the central scans row (repeatable)")
    sp.add_argument("--verify-upstream", action="store_true", help="verify upstream TLS certificates (default: don't)")
    sp.add_argument("--verbose", action="store_true", help="mitmproxy's normal flow output")
    sp.add_argument("--print", action="store_true", help="print the mitmdump command instead of running it")
    sp.add_argument("mitmproxy_args", nargs=argparse.REMAINDER, help="extra mitmdump arguments after --")
    sp.set_defaults(fn=cmd_proxy)

    sp = sub.add_parser("mint", help="print a session token (the proxy password)")
    common(sp, proxy=True)
    sp.add_argument("session")
    sp.add_argument("--ttl", help="expiry, e.g. 72h, 30m (default: none)")
    sp.add_argument("--init", action="store_true", help="create the secret if there is none yet (before the first `m2c proxy`)")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_mint)

    for name, fn, help_ in (
        ("env", cmd_env, "print proxy environment variables for one session and tool"),
        ("run", cmd_run, "run a command through the proxy as one session and tool"),
    ):
        sp = sub.add_parser(name, help=help_)
        common(sp, proxy=True)
        sp.add_argument("--session", required=True)
        sp.add_argument("--tool", required=True)
        sp.add_argument("--call", default="")
        sp.add_argument("--token", help="session token (env M2C_TOKEN; default: minted from the secret)")
        sp.add_argument("--no-proxy", action="append", help="extra NO_PROXY entries")
        if name == "env":
            sp.add_argument("--json", action="store_true")
        else:
            sp.add_argument("--no-tool-flags", action="store_true", help="don't add -proxy/--proxy flags for known tools")
            sp.add_argument("command", nargs=argparse.REMAINDER)
        sp.set_defaults(fn=fn)

    def reader(name, help_, fn):
        sp = sub.add_parser(name, help=help_)
        common(sp)
        sp.add_argument("--api", help="API URL (env M2C_API; default: from <data>/api.json, else read the data directory)")
        sp.add_argument("--token", help="API token: admin, or <session>:<proxy token> (env M2C_API_TOKEN)")
        sp.add_argument("--offline", action="store_true", help="read the data directory even if a proxy is running")
        sp.add_argument("--json", action="store_true", help="JSON lines")
        sp.set_defaults(fn=fn)
        return sp

    reader("stats", "scan totals and writer counters", cmd_stats)
    sp = reader("sessions", "per session and tool summary", cmd_sessions)
    sp.add_argument("query", nargs="?", default="")
    sp = reader("ls", "list flows (newest last); QUERY uses the filter language", cmd_ls)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("-n", "--limit", type=int, default=50)
    sp.add_argument("--cursor", type=int)
    sp = reader("show", "one flow in full", cmd_show)
    sp.add_argument("n", type=int)
    sp.add_argument("--body", action="store_true", help="write the response body to stdout")
    sp.add_argument("--req-body", action="store_true", help="write the request body to stdout")
    sp.add_argument("--max", type=int, default=4096, help="body preview bytes")
    sp = reader("tail", "follow new flows", cmd_tail)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("-b", "--backlog", type=int, default=10)
    sp.add_argument("-f", "--follow", action="store_true", help="(always on)")
    sp.add_argument("--no-open", action="store_true", help="don't show long-lived flows when they start, only when they end")
    for name in ("sse", "ws"):
        sp = reader(name, f"{'SSE events' if name == 'sse' else 'WebSocket messages'} of one flow", cmd_children)
        sp.add_argument("n", type=int)
        sp.add_argument("--after", type=int, default=0)
        sp.add_argument("--limit", type=int, default=1000)
    sp = reader("curl", "a curl command replaying one request", cmd_curl)
    sp.add_argument("n", type=int)
    sp = reader("har", "HAR export of matching flows", cmd_har)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("--limit", type=int, default=1000)
    sp = reader("events", "proxy events: auth failures, TLS failures, health", cmd_events)
    sp.add_argument("--kind", default="")
    sp.add_argument("--limit", type=int, default=100)
    sp = reader("sql", "read-only SQL", cmd_sql)
    sp.add_argument("query")
    sp.add_argument("--format", default="PrettyCompactMonoBlock", help="any ClickHouse output format")
    reader("mcp", "MCP server over stdio (forwards to the live API, or reads a stopped scan)", cmd_mcp)

    sp = sub.add_parser("ca", help="the proxy's CA certificate: path, pem, or a combined system+proxy bundle")
    common(sp)
    sp.add_argument("action", nargs="?", default="bundle", choices=("bundle", "path", "pem"))
    sp.set_defaults(fn=cmd_ca)

    sp = sub.add_parser("hooks", help="print the integration snippet for a harness")
    sp.add_argument("harness", choices=("claude-code", "generic"))
    sp.set_defaults(fn=cmd_hooks)

    sp = sub.add_parser("hook", help="entry point for harness hooks (reads the hook event on stdin)")
    common(sp, proxy=True)
    sp.add_argument("event", choices=("claude-code-session-start",))
    sp.add_argument("--tool", default="bash")
    sp.set_defaults(fn=cmd_hook)

    sp = sub.add_parser("doctor", help="check the installation, the CA, the data directory and the live API")
    common(sp)
    sp.set_defaults(fn=cmd_doctor)

    sp = sub.add_parser("push", help="push a stopped scan to a central ClickHouse (safe to run again)")
    common(sp)
    sp.add_argument("--to", default=os.environ.get("M2C_PUSH_URL"), required="M2C_PUSH_URL" not in os.environ,
                    help="clickhouse[s]://user@host:port/db or http(s)://user@host:port/db (env M2C_PUSH_URL; password: URL or M2C_PUSH_PASSWORD)")
    sp.add_argument("--label", action="append", help="key=value stored on the central scans row (repeatable)")
    sp.add_argument("--create", action="store_true", help="create or upgrade the central schema first (http(s) targets)")
    sp.add_argument("--chunk-mb", type=int, default=64, help="approximate size of one insert")
    sp.add_argument("--json", action="store_true")
    sp.set_defaults(fn=cmd_push)

    sp = sub.add_parser("central", help="central ClickHouse schema: `init` creates or upgrades it, `ddl` prints it")
    sp.add_argument("action", choices=("init", "ddl"))
    sp.add_argument("--to", default=os.environ.get("M2C_PUSH_URL"), help="http(s)://user@host:port/db (init)")
    sp.add_argument("--database", default="m2c", help="database name (ddl)")
    sp.add_argument("--engine", default="MergeTree", help="table engine, e.g. ReplicatedMergeTree")
    sp.add_argument("--ttl-days", type=int, default=0)
    sp.add_argument("--on-cluster", default="")
    sp.set_defaults(fn=cmd_central)
    return p


def _default_proxy(args) -> str:
    try:
        addr = json.loads((_data(args) / "api.json").read_text()).get("proxy")
    except (OSError, ValueError):
        addr = None
    return addr or DEFAULT_PROXY


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    if hasattr(args, "proxy") and not args.proxy:
        args.proxy = _default_proxy(args)
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if getattr(args, "mitmproxy_args", None) and args.mitmproxy_args[:1] == ["--"]:
        args.mitmproxy_args = args.mitmproxy_args[1:]
    for key in ("session",):
        value = getattr(args, key, None)
        if value is not None and not identity.SESSION.fullmatch(value):
            sys.exit(f"m2c: --{key} must match {identity.SESSION.pattern}")
    if getattr(args, "tool", None) and not identity.TOOL.fullmatch(args.tool):
        sys.exit(f"m2c: --tool must match {identity.TOOL.pattern}")
    if getattr(args, "call", None) and not identity.CALL.fullmatch(args.call):
        sys.exit(f"m2c: --call must match {identity.CALL.pattern}")
    args.fn(args)


if __name__ == "__main__":
    main()
