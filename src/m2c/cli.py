"""m2c: run the recording proxy, hand out credentials, and query a scan."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import shutil
import sys
from pathlib import Path

from . import __version__, identity
from .fmt import flow_line as _flow_line, report_text, size as _size, when as _when

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
    path = identity.secret_file(data, configured)
    try:
        secrets = identity.load_secrets(data, configured, os.environ.get("M2C_SECRET", ""), create=create)
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
    if args.repeater != "off":
        argv += ["--set", f"m2c_repeater={args.repeater}"]
    if args.scan_id:
        argv += ["--set", f"m2c_scan_id={args.scan_id}"]
    if args.push_on_exit:
        argv += ["--set", f"m2c_push_on_exit={args.push_on_exit}"]
    if args.proto:
        argv += ["--set", f"m2c_proto_file={Path(args.proto).expanduser().resolve()}"]
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
            GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=str(bundle),  # gRPC's own TLS ignores SSL_CERT_FILE
            REQUESTS_CA_BUNDLE=str(bundle),
            CURL_CA_BUNDLE=str(bundle),
            GIT_SSL_CAINFO=str(bundle),
            AWS_CA_BUNDLE=str(bundle),
            NPM_CONFIG_CAFILE=str(bundle),
            PIP_CERT=str(bundle),
            CARGO_HTTP_CAINFO=str(bundle),
            DENO_CERT=str(bundle),
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
        client = connect(_data(args), getattr(args, "api", None), getattr(args, "token", None), getattr(args, "offline", False),
                         getattr(args, "proto", None))
    except ClientError as e:
        sys.exit(f"m2c: {e}")
    if not client.online:
        from .writer import spool_files

        left = spool_files(_data(args) / "spool")
        if left:
            print(f"m2c: note: {sum(r for _, _, r in left)} rows are still in {_data(args)}/spool and not shown; "
                  "starting the proxy again (or `m2c push`) inserts them", file=sys.stderr)
    return client


def _out_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, default=str))


def _run_client(fn):
    from .client import ClientError

    try:
        return fn()
    except ClientError as e:
        sys.exit(f"m2c: {e}")
    except Exception as e:  # noqa: BLE001 - offline query errors (a bad filter, a bad regex)
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


def cmd_report(args) -> None:
    rep = _run_client(lambda: _client(args).report(args.query or "", args.by, args.limit))
    if args.json:
        _out_json(rep)
    else:
        print(report_text(rep))


def cmd_grep(args) -> None:
    hits = _run_client(lambda: _client(args).grep(args.pattern, args.regex, not args.case_sensitive, args.side, args.query or "",
                                                 args.where_in, args.context, args.limit, args.per_flow))
    if args.json:
        for h in hits:
            _out_json(h)
        return
    for h in hits:
        where = f" event {h['seq']}" if "seq" in h else ""
        print(f"#{h['n']}{where}  {h['session']}/{h['tool']}  " + (f"{h['method']} {h['status'] or '-'} {h['host']}{h['path']}" if "method" in h else ""))
        for key, mark in (("req_hits", ">"), ("resp_hits", "<"), ("hits", "|")):
            for snippet in h.get(key, []):
                print(f"  {mark} " + snippet.replace("\r", "").replace("\n", "\u23ce "))


def cmd_diff(args) -> None:
    out = _run_client(lambda: _client(args).diff(args.a, args.b, 256 << 10, not args.no_redact))
    if out is None:
        sys.exit(f"m2c: no flow #{args.a} or #{args.b}")
    print(json.dumps(out, ensure_ascii=False, indent=None if args.json else 2, default=str))


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
    if flow.get("grpc"):
        code = flow["grpc_status"]
        status = "no status" if code == -1 else f"{flow.get('grpc_status_name') or code} ({code}, from {flow['grpc_status_source']})"
        print(f"  grpc: {flow['grpc_service']}/{flow['grpc_method']}  {status}" + (f": {flow['grpc_message']}" if flow["grpc_message"] else "")
              + f"   {flow['grpc_req_messages']} > / {flow['grpc_resp_messages']} <  (m2c grpc {flow['n']})")
    print()
    _print_headers("> request headers", flow["req_headers"])
    if flow.get("req_trailers"):
        _print_headers("> request trailers", flow["req_trailers"])
    if flow["req_body_stored"]:
        body = _run_client(lambda: c.body(args.n, "req", args.max))
        print(f"> request body ({_size(flow['req_body_size'])} on the wire{', truncated' if flow['req_body_truncated'] else ''})")
        print(_preview(body[0] if body else b"", args.max))
    print()
    _print_headers("< response headers", flow["resp_headers"])
    if flow.get("resp_trailers"):
        _print_headers("< response trailers", flow["resp_trailers"])
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


def cmd_grpc(args) -> None:
    c = _client(args)
    local = bool(args.proto) and c.online  # the proxy decodes with its own .proto; with --proto, decode here
    rows = _run_client(lambda: c.grpc(args.n, args.after, args.limit, decode=not local and not args.raw))
    if local and not args.raw:
        import base64

        from . import grpc

        for r in rows:
            if r.get("decoded_as") != "incomplete":
                path = f"/{r['service']}/{r['method']}" if r["service"] else ""
                r["decoded"], r["decoded_as"] = grpc.decode(base64.b64decode(r["base64"]), path, r["from_client"], args.proto)
    for r in rows:
        if args.json:
            _out_json(r)
            continue
        arrow = ">" if r["from_client"] else "<"
        notes = [n for n, on in (("compressed", r["compressed"] and not r.get("decompressed", True)), ("truncated", r["truncated"]),
                                 ("partial", r["partial"])) if on]
        print(f"{r['seq']:>5} +{r['ms_since_req']}ms {arrow} #{r['dir_seq']} {_size(r['size'])}" + (f"  ({', '.join(notes)})" if notes else ""))
        if r.get("decoded"):
            print("\n".join("      " + line for line in r["decoded"].rstrip("\n").splitlines()))
        elif r.get("base64"):
            print(f"      base64 {r['base64'][:120]}" + ("…" if len(r["base64"]) > 120 else ""))


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
            if r.get("fix"):
                print(f"{'':14}fix: {r['fix']}")


def cmd_notes(args) -> None:
    notes = [x for x in _run_client(lambda: _client(args).notes(None, args.query or "", None, args.limit)) if not x["deleted"]]
    for x in sorted(notes, key=lambda x: (x["n"], x["created"])):
        if args.json:
            _out_json(x)
        else:
            label = f"[{x['label']}] " if x["label"] else ""
            print(f"#{x['n']:<6} {_when(x['updated'])}  {x['session']:<16.16} {label}{x['note'][:200]}  ({x['author']}, {x['id'][:8]})")


def cmd_note(args) -> None:
    c = _client(args)
    if args.delete:
        _run_client(lambda: c.delete_note(_note_id(c, args.n, args.delete)))
        print(f"deleted note {args.delete} on #{args.n}")
        return
    fields = {k: v for k, v in (("label", args.label), ("color", args.color), ("note", " ".join(args.text) if args.text else None)) if v is not None}
    if args.edit:
        note = _run_client(lambda: c.change_note(_note_id(c, args.n, args.edit), fields))
    else:
        note = _run_client(lambda: c.add_note(args.n, fields))
    print(json.dumps(note) if args.json else f"#{note['n']} note {note['id']}" + (f" [{note['label']}]" if note["label"] else ""))


def _note_id(c, n: int, prefix: str) -> str:
    """A note on flow n by id or id prefix (as `m2c notes` prints it)."""
    found = [x["id"] for x in _run_client(lambda: c.notes([n])) if x["id"].startswith(prefix.lower()) and not x["deleted"]]
    if len(found) != 1:
        sys.exit(f"m2c: {'no' if not found else 'more than one'} note {prefix} on #{n}")
    return found[0]


def cmd_timeline(args) -> None:
    c = _client(args)
    session = args.session
    if not session:
        known = _run_client(lambda: c.call_sessions())
        if not known:
            sys.exit("m2c: no flows carry call ids yet (see `m2c hooks claude-code`)")
        session = known[0]["session"]
    tl = _run_client(lambda: c.timeline(session, args.limit))
    if args.json:
        _out_json(tl)
        return
    for item in tl["items"]:
        if item["kind"] == "call":
            failed = f", {item['failures']} failed" if item["failures"] else ""
            print(f"{_when(item['start_ts'])}  call {item['call_id']} ({item['tool']}): {len(item['flows'])} flows{failed}, "
                  f"{item['end_ts'] - item['start_ts']} ms")
        else:
            print(f"{'':14}without a call id: {len(item['flows'])} flows")
        for f in item["flows"]:
            print("    " + _flow_line(f))


def cmd_resend(args) -> None:
    overrides: dict = {}
    if args.method:
        overrides["method"] = args.method
    if args.url:
        overrides["url"] = args.url
    if args.header or args.drop_header:
        c = _client(args)
        flow = _run_client(lambda: c.flow(args.n))
        if flow is None:
            sys.exit(f"m2c: no flow #{args.n}")
        headers = [list(h) for h in flow["req_headers"]]
        for h in args.header or []:
            name, sep, value = h.partition(":")
            if not sep:
                sys.exit(f"m2c: -H takes 'Name: value', got {h!r}")
            headers = [x for x in headers if x[0].lower() != name.strip().lower()] + [[name.strip(), value.strip()]]
        overrides["headers"] = headers
        if args.drop_header:
            overrides["headers_remove"] = args.drop_header
    if args.body is not None:
        overrides["body"] = sys.stdin.read() if args.body == "@-" else args.body
    out = _run_client(lambda: _client(args).resend(args.n, overrides))
    if args.json:
        _out_json(out)
        return
    print(f"#{out['n']} (resent #{out['replay_of']}): {out['method']} {out['url']} -> {out['status'] or 'ERR'} {out['reason']}"
          + (f" ({out['error']})" if out["error"] else "") + f", {out['duration_ms']} ms")
    print(f"compare: m2c diff {out['replay_of']} {out['n']}")


def cmd_mcp(args) -> None:
    from .mcp import serve_stdio

    c = _client(args)
    if args.session:
        if not identity.SESSION.fullmatch(args.session):
            sys.exit(f"m2c mcp: --session must match {identity.SESSION.pattern}")
        if c.online:  # a session-scoped API token: needs `m2c proxy --auth token` (the default)
            c.token = f"{args.session}:{identity.mint(_secrets(args)[0], args.session)}"
        else:
            c.scoped(args.session)
    elif not (args.token or os.environ.get("M2C_API_TOKEN")):
        print("m2c mcp: serving as admin (every session); --session S limits it to one agent session", file=sys.stderr)
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


def claude_hooks(m2c: str, data: Path) -> dict:
    """Claude Code settings: the proxy for Bash commands, each Bash call's requests tagged with its tool_use_id."""
    cmd = lambda event: f"{shlex.quote(m2c)} hook {event} --data {shlex.quote(str(data))}"  # noqa: E731
    return {"hooks": {
        "SessionStart": [{"hooks": [{"type": "command", "command": cmd("claude-code-session-start")}]}],
        "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": cmd("claude-code-pre-tool"), "timeout": 5}]}],
    }}


def cmd_hooks(args) -> None:
    if args.harness == "claude-code":
        m2c = shutil.which("m2c") or os.path.abspath(sys.argv[0])
        print("# Add to .claude/settings.json (project) or ~/.claude/settings.json.", file=sys.stderr)
        print("# Bash commands then go through the proxy as <session_id>.bash.<tool_use_id>: the timeline groups each", file=sys.stderr)
        print("# call's flows. Nothing about the calls themselves is recorded, and Claude Code's own API traffic never", file=sys.stderr)
        print("# goes through the proxy.", file=sys.stderr)
        print(json.dumps(claude_hooks(m2c, _data(args).resolve()), indent=2))
    else:
        print("# Generic harness: give each agent run its own session id and run tools with")
        print("#   m2c run --session <run id> --tool <tool> -- <command ...>")
        print("# or export the variables once per run (only into the tools' environment, never the agent's own):")
        print("#   eval \"$(m2c env --session <run id> --tool <tool>)\"")
        print("# A long-lived client can name the tool per request with the header  x-m2c-tool: <tool>")
        print("# Name each tool call in the proxy username (<session>.<tool>.<call id>) to group its flows in the timeline.")


def cmd_hook(args) -> None:
    """Called by a harness hook; reads the hook's JSON on stdin. Tool hooks never fail the tool call."""
    from . import hooks

    try:
        event = json.load(sys.stdin)
    except ValueError:
        event = {}
    if not isinstance(event, dict):
        event = {}
    if args.event == "claude-code-session-start":
        env_file = os.environ.get("CLAUDE_ENV_FILE")
        if not env_file:
            print("m2c: CLAUDE_ENV_FILE is not set; nothing to do", file=sys.stderr)
            return
        args.session = hooks.session_id(event.get("session_id"))
        args.tool, args.call, args.token, args.no_proxy = args.tool or "bash", "", None, None
        env = proxy_env(args)
        extra = {"M2C_SESSION": args.session, "M2C_DATA": str(_data(args).resolve())}
        try:
            meta = json.loads((_data(args) / "api.json").read_text())
            extra.update(M2C_API=meta["url"], M2C_API_TOKEN=f"{args.session}:{identity.mint(_secrets(args)[0], args.session)}")
        except (OSError, ValueError, KeyError, SystemExit):
            pass  # no running proxy (yet) or no secret here: the tools still get the proxy
        with open(env_file, "a") as f:
            f.write(hooks.env_snippet(env, args.session, args.tool, extra))
        return
    try:  # claude-code-pre-tool
        hooks.mark_call(event)
    except Exception as e:  # noqa: BLE001 - a hook must never get in the way of the tool call
        hooks.log_problem(_data(args), f"{args.event}: {type(e).__name__}: {e}")


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
    if info.exists():
        _doctor_tls(meta)
    sys.exit(0 if ok else 1)


def _doctor_tls(meta: dict) -> None:
    """Tools whose TLS handshakes failed because they don't trust the proxy CA, with where each reads its CAs."""
    from .advice import ca_hint
    from .client import ClientError, Online

    try:
        events = Online(meta["url"], meta["token"]).events("tls_failed_client", 1000)
    except (ClientError, KeyError):
        return
    by_tool: dict[tuple[str, str], int] = {}
    for e in events:
        key = (e.get("session") or "-", e.get("tool") or "")
        by_tool[key] = by_tool.get(key, 0) + 1
    for (session, tool), count in sorted(by_tool.items(), key=lambda x: -x[1])[:10]:
        print(f"warn {session}/{tool or '?'}: {count} TLS handshakes failed (the client doesn't trust the m2c CA). {ca_hint(tool)}")


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
    p.add_argument("--version", action="version", version=f"m2c {__version__}")
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
    sp.add_argument("--repeater", choices=("off", "admin", "on"), default=os.environ.get("M2C_REPEATER", "off"),
                    help="let the API/UI/MCP resend recorded requests: admin token only, or also session tokens for their own flows")
    sp.add_argument("--push-on-exit", default=os.environ.get("M2C_PUSH_ON_EXIT", ""), help="central ClickHouse URL to push to at shutdown")
    sp.add_argument("--proto", default=os.environ.get("M2C_PROTO_FILE", ""), help="a .proto file naming gRPC message fields in the API, UI and MCP")
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
    sp = reader("resend", "resend a recorded request through the proxy, edited or not (needs m2c proxy --repeater)", cmd_resend)
    sp.add_argument("n", type=int)
    sp.add_argument("-X", "--method")
    sp.add_argument("--url")
    sp.add_argument("-H", "--header", action="append", help="'Name: value' (replaces that header; repeatable)")
    sp.add_argument("--drop-header", action="append", help="a header name to leave out (repeatable)")
    sp.add_argument("-d", "--body", help="the body to send ('@-' reads stdin); default: the recorded body")
    sp = reader("notes", "labels and notes on the flows a query matches", cmd_notes)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("--limit", type=int, default=1000)
    sp = reader("note", "label or note a flow (or --edit / --delete one); needs the running proxy", cmd_note)
    sp.add_argument("n", type=int)
    sp.add_argument("text", nargs="*", help="the note's text")
    sp.add_argument("-l", "--label")
    sp.add_argument("--color", choices=("red", "orange", "yellow", "green", "blue", "purple", "gray"))
    sp.add_argument("--edit", metavar="ID", help="change this note (id or prefix) instead of adding one")
    sp.add_argument("--delete", metavar="ID", help="delete this note (id or prefix)")
    sp = reader("timeline", "a session's flows grouped by the tool call that made them (the proxy username's call id)", cmd_timeline)
    sp.add_argument("session", nargs="?", default="", help="default: the session with the latest call")
    sp.add_argument("--limit", type=int, default=2000, help="the session's last N flows")
    sp = reader("report", "per session, tool or call: flows, failures, hosts, statuses, slowest", cmd_report)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("--by", choices=("session", "tool", "call"), default="tool")
    sp.add_argument("--limit", type=int, default=50)
    sp = reader("grep", "find text in bodies (or SSE/WebSocket data) and show it in context", cmd_grep)
    sp.add_argument("pattern")
    sp.add_argument("query", nargs="?", default="", help="narrow the flows (filter language)")
    sp.add_argument("-E", "--regex", action="store_true", help="PATTERN is an RE2 regular expression")
    sp.add_argument("-s", "--case-sensitive", action="store_true")
    sp.add_argument("--side", choices=("req", "resp", "both"), default="both")
    sp.add_argument("--in", dest="where_in", choices=("body", "sse", "ws"), default="body")
    sp.add_argument("-C", "--context", type=int, default=80)
    sp.add_argument("--limit", type=int, default=20)
    sp.add_argument("--per-flow", type=int, default=3)
    sp = reader("diff", "what differs between two flows", cmd_diff)
    sp.add_argument("a", type=int)
    sp.add_argument("b", type=int)
    sp.add_argument("--no-redact", action="store_true", help="show credential header values")
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
    sp = reader("grpc", "the messages of one gRPC call, decoded from protobuf", cmd_grpc)
    sp.add_argument("n", type=int)
    sp.add_argument("--after", type=int, default=0)
    sp.add_argument("--limit", type=int, default=1000)
    sp.add_argument("--proto", help="a .proto file for field names (default: the proxy's m2c_proto_file, else field numbers)")
    sp.add_argument("--raw", action="store_true", help="don't decode; show the bytes (base64)")
    sp = reader("curl", "a curl command replaying one request", cmd_curl)
    sp.add_argument("n", type=int)
    sp = reader("har", "HAR export of matching flows", cmd_har)
    sp.add_argument("query", nargs="?", default="")
    sp.add_argument("--limit", type=int, default=1000)
    sp = reader("events", "proxy events: auth failures, TLS failures, health", cmd_events)
    sp.add_argument("--kind", default="")
    sp.add_argument("--limit", type=int, default=100)
    sp = reader("mcp", "MCP server over stdio (forwards to the live API, or reads a stopped scan)", cmd_mcp)
    sp.add_argument("--session", help="scope the server to one session (a session token minted from the secret); default: admin")

    sp = sub.add_parser("ca", help="the proxy's CA certificate: path, pem, or a combined system+proxy bundle")
    common(sp)
    sp.add_argument("action", nargs="?", default="bundle", choices=("bundle", "path", "pem"))
    sp.set_defaults(fn=cmd_ca)

    sp = sub.add_parser("hooks", help="print the integration snippet for a harness")
    common(sp)
    sp.add_argument("harness", choices=("claude-code", "generic"))
    sp.set_defaults(fn=cmd_hooks)

    sp = sub.add_parser("hook", help="entry point for harness hooks (reads the hook event on stdin)")
    common(sp, proxy=True)
    sp.add_argument("event", choices=("claude-code-session-start", "claude-code-pre-tool"))
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
