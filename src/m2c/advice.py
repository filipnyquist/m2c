"""What to do about a proxy event: one line per kind, specific to the tool when that helps.

Used by the API (each event in /v1/events carries `fix`), so the web UI, MCP and later `m2c doctor` say the same.
"""

from __future__ import annotations

# Where common tools read their trusted CAs from; `m2c env` and `m2c run` set all of these.
CA_VARS = (
    (("node", "npm", "npx", "yarn", "pnpm", "bun"), "NODE_EXTRA_CA_CERTS (npm also NPM_CONFIG_CAFILE)"),
    (("pip", "pip3", "uv", "python", "python3", "requests", "httpx", "poetry"), "REQUESTS_CA_BUNDLE (or SSL_CERT_FILE; pip also takes --cert)"),
    (("curl",), "CURL_CA_BUNDLE"),
    (("git",), "GIT_SSL_CAINFO"),
    (("aws",), "AWS_CA_BUNDLE"),
    (("grpcurl", "grpc"), "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH"),
    (("go", "gh", "terraform", "kubectl", "helm", "docker"), "SSL_CERT_FILE"),
    (("deno",), "DENO_CERT"),
    (("cargo",), "CARGO_HTTP_CAINFO"),
)

# Tools that ignore environment variables for trust: the fix is theirs alone.
OWN_TRUST = (
    (("java", "gradle", "mvn"), "Java trusts its own keystore: run it with -Djavax.net.ssl.trustStore=<a keystore holding the m2c CA>."),
    (("chrome", "chromium", "browser", "playwright", "firefox", "edge"),
     "Browsers keep their own trust store: import the m2c CA (`m2c ca path`) into the profile, or for a throwaway profile start it "
     "with --ignore-certificate-errors."),
)


def _match(tool: str, table) -> str | None:
    t = (tool or "").lower()
    for names, where in table:
        if t in names or any(t.startswith(n + "-") for n in names):
            return where
    return None


def ca_hint(tool: str) -> str:
    where = _match(tool, CA_VARS)
    if where:
        return f"{tool} reads trusted CAs from {where}."
    return "Point the tool at the m2c CA (`m2c ca path`), or start it with `m2c run`, which sets the usual variables."


def for_event(e: dict) -> str:
    """A fix for proxy event `e` (a row of Queries.events), or "" when there is nothing to do."""
    kind, reason, tool = e.get("kind", ""), (e.get("reason") or "").lower(), e.get("tool", "")
    session = e.get("session") or (e.get("proxy_user") or "").split(".")[0] or "<session>"
    if kind == "tls_failed_client":
        own = _match(tool, OWN_TRUST)
        if own:
            return f"The client gave up during the TLS handshake: it doesn't trust the m2c CA. {own}"
        return (f"The client gave up during the TLS handshake: it doesn't trust the m2c CA. {ca_hint(tool)} "
                f"`eval \"$(m2c env --session {session}{' --tool ' + tool if tool else ''})\"` sets them for a shell.")
    if kind == "tls_failed_server":
        return ("The proxy could not complete TLS with the server: an invalid or expired certificate (with --verify-upstream), "
                "a client-certificate requirement, or a server that refused the handshake.")
    if kind == "auth_rejected":
        if "expired" in reason:
            return f"The token has expired: mint a new one with `m2c mint {session}`."
        if "missing" in reason:
            return "The client sent no proxy credentials; give it a proxy URL with `<session>.<tool>:<token>@`."
        return (f"The proxy password does not verify for this session: mint one with `m2c mint {session}` against this "
                "proxy's data directory (tokens from another data directory or secret don't work).")
    if kind == "auth_challenge":
        return "A client connected without credentials and got a 407; most clients retry with them. Nothing to do if one follows."
    if kind == "tcp_tunnel":
        if reason == "h2c":
            return "Plaintext HTTP/2 (h2c, e.g. gRPC without TLS) passes through as raw TCP: only byte counts are recorded. Use TLS to record it."
        return "Traffic that isn't HTTP passed through as raw TCP: only byte counts are recorded."
    if kind == "connect_error":
        return "The proxy could not connect to the server (refused, unreachable or DNS)."
    if kind in ("sse_parse_stopped", "grpc_framing_stopped"):
        return "The stream stopped parsing as such; the body is still recorded as bytes."
    return ""
