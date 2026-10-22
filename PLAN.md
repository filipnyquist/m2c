# m2c (mitmproxy2chDB) plan

## Status (2026-10-21)

M0–M7 are implemented. 79 tests cover them: unit tests, plus integration tests against real `m2c proxy` processes and a dockerized ClickHouse.

**Changes from the plan below:**
- **Live feed:** the API also streams events typed `open` (a long-lived flow started), `stats`, and `/v1/flows/N/live`, which streams an open flow's SSE events or WebSocket messages. The UI uses all of these, so streams are visible while they run.
- **Admin API token:** kept per data directory (`<data>/api-token`).
- **Lists:** a `by_n` projection (summary columns ordered by `n`) plus two-step queries keep `ls` at 20–55 ms on 1M flows.
- **Push is per chunk:** a chunk already in central is skipped, a partial chunk only sends what is missing, and tokens are content-hashed, so a scan that grew after a push never loses or duplicates rows.
- **Bundle:** chDB is installed without pandas, pyarrow and numpy (about 240 MB smaller).
- **mitmdump** is launched as `python -c …mitmdump()`, which keeps the bundle relocatable.
- - **Review:** an adversarial review across five areas confirmed 52 issues (one more was refuted), among them one critical (non-ASCII proxy passwords bypassed auth). All are fixed, 215 tests.
- **Writer:** goes through a write-ahead spool and `INSERT … SELECT FROM file()`, because chDB's streaming insert can report success and store nothing at the memory limit. `memory_worker_use_cgroup=0`, because chDB otherwise counts the whole desktop cgroup as its own memory.
- **Connections:** `connection_strategy=eager` (lazy broke HTTP/2 uploads without Content-Length).
- **gRPC (2026-10-22):**
  - Calls get status, service and method columns.
  - Each message is a `grpc_messages` row, decompressed and decoded from protobuf at read time (schemaless, or with a `.proto`).
  - gRPC errors count as failures.
  - Tunnels that aren't HTTP are `tcp_tunnel` events (plaintext gRPC gets a warning).
- **HTTP/3:** investigated and not built. Proxy clients never use it; capturing it needs UDP interception, with WireGuard listeners per session as the candidate design.
- **Not built:** Codex and Playwright example files (the README covers them), and the `CLAUDE_CODE_SHELL_PREFIX` per-command tool naming.

A general-purpose recording proxy for **any AI agent or harness**: Claude Code, Codex, custom agents, LangChain apps, browser agents. It is not tied to one product.

It is a mitmproxy add-on that records every flow into an embedded **chDB** database:

- HTTP requests and responses, with headers and bodies
- SSE events and WebSocket messages
- errors, auth rejections and TLS failures

Each row is tagged with the agent session and the tool that sent it. One proxy runs per scan or run.

**Ways to run it:**
- as a container image
- as a self-contained Linux bundle that drops into any existing glibc container
- as a Python project, installed with `uv tool install` or `pipx`

**Querying:**
- while the scan runs: a fast API, a CLI, MCP and a small web UI
- at the end: the scan is pushed to a central ClickHouse server

**Proxy-side principles:**

- identity carried in the proxy username, and a 407 for bad credentials
- a tag header that is recorded and then stripped
- a background writer, so storage never stalls traffic
- one command that prints the proxy environment for a tool's shell

**Fixed decisions:**
- token auth, with the proxy running as its own Unix user
- tool = program name, plus an optional call id
- live querying is required
- container *and* embeddable bundle
- push to a central ClickHouse
- the agent's own LLM API traffic **never** goes through the proxy

---

## 1. Identity and credentials

```
username = <session>.<tool>[.<call>]        split('.', 2)
  session : [A-Za-z0-9_-]{1,64}             one id per agent run (e.g. Claude Code session_id)
  tool    : [A-Za-z0-9_-]{1,48}             lower-cased: curl, nuclei, sqlmap, browser, bash-curl, ...
  call    : [A-Za-z0-9._~-]{1,96}           optional: tool_use_id, step counter
password = auth secret (never a label, never stored)
```

- Only RFC 3986 unreserved characters are allowed, so no client ever needs to percent-encode. axios does not percent-decode userinfo, and a `:` in the password makes mitmproxy answer 407.
- The username stays within SOCKS5's 255-byte limit.

**Auth modes** (`m2c_auth`):

| Mode | Password | Use |
|---|---|---|
| `token` (default) | `v1.<exp>.<mac>`, where mac = base64url(HMAC-SHA256(secret, `m2c\|v1\|<session>\|<exp>`))[:22] | Agents can't write rows under another session |
| `shared` | one secret generated at boot | Simple setups where every client may use any session |
| `open` | anything. A username with no dot means session = username and **tool = password** | Your original idea. Loopback only, unless `m2c_allow_open_exposed=true` |

Examples:
```
curl -x "http://r6x4kq8m2a9t.curl:v1.mzb0x1c.4fJk2LwQ9aZp0cXe1TuV7g@127.0.0.1:8080" https://target
nuclei -proxy "http://r6x4kq8m2a9t.nuclei.step7:<token>@127.0.0.1:8080" -duc -u https://target
newContext({proxy:{server:'http://127.0.0.1:8080', username:'r6x4kq8m2a9t.browser', password:TOKEN}})  // Playwright
```

**How auth works.**

mitmproxy runs with `proxyauth=any`, which only parses the credentials. Our add-on checks them:

- **When:** in `http_connect` and `socks5_auth`, the identity is bound to the client connection. Plain-HTTP requests carry their own credentials, and these are checked on every request through an LRU cache.
- **Bad credentials:** 407 with a body that explains the format, plus one `auth_rejected` event.
- **Missing credentials:** the challenge a browser or git sends first is recorded as at most one `auth_challenge` event per connection, and never as a flow.
- **The password itself:** it is replaced in `flow.metadata['proxyauth']` immediately, so it never reaches the stored rows.

**One process running many tools.**

A pooled tunnel keeps the identity it had at its first CONNECT. To refine it, in order of precedence:

1. the request headers `x-m2c-tool`, `x-m2c-call`, `x-m2c-tag`, which are read and then **stripped** (this works inside HTTPS because TLS is intercepted)
2. the same headers sent on the CONNECT
3. the tool part of the username
4. `unknown`

A header can never change the session. `identity_source` records which of these won. `ua_tool` holds a guess from the User-Agent, for forensics only.

**Getting credentials.**

The CLI uses the secret held by the proxy or the harness:

| Command | What it does |
|---|---|
| `m2c mint <session>` | prints the token |
| `m2c env --session S --tool T` | prints the `HTTP(S)_PROXY`/`ALL_PROXY`/`NO_PROXY`/`NODE_USE_ENV_PROXY` variables and the CA-bundle variables |
| `m2c run --session S --tool T -- cmd…` | runs the command with that environment, and adds the flags that environment variables can't cover: nuclei/katana `-proxy`, sqlmap `--proxy-cred` |

**Harness integrations** (all of them generic; the proxy is never wired into the agent process itself):
- **Claude Code:** a SessionStart hook writes `m2c env` into `$CLAUDE_ENV_FILE`. This affects Bash subprocesses only.
- **Codex and other CLIs:** a shell-prefix or wrapper.
- **Browser agents:** Playwright or Puppeteer context proxy options.
- **Anything else:** `m2c env` / `m2c run`.

**The agent's own LLM traffic never uses the proxy.**
- Integrations only set proxy variables for tool subprocesses, never for the harness process.
- `m2c doctor` warns when it sees the harness's own process environment carrying `HTTP(S)_PROXY`.

**Trust boundary.** An agent running as the same Unix user as the proxy can read the secret. Then `token` mode protects no better than `shared`. For real isolation, the proxy and the minter run as their own user.

---

## 2. Architecture and packaging (chDB in-process)

- **Dependencies:** mitmproxy (12.2 or later, below 13) and `chdb` (4.4 / chdb-core 26.9) in one Python 3.12+ environment. The standalone mitmproxy binary cannot load chDB.
  - The `chdb-core` wheel is `manylinux_2_17`: any glibc 2.17+ distro, x86_64 or aarch64. There is no musl/Alpine build.
  - The API server uses **tornado**, which mitmproxy already depends on, so it adds nothing.
- **Three ways to ship it, all from one codebase:**

| Form | What it is | Use |
|---|---|---|
| **Python project** | `uv tool install m2c` or `pipx install` | dev machines, CI |
| **Self-contained Linux bundle** | `m2c-<ver>-linux-<arch>.tar.zst`: python-build-standalone plus a pre-built venv, relocatable, entry point `bin/m2c` | embed in an existing container: `COPY --from=ghcr.io/…/m2c:<ver> /opt/m2c /opt/m2c`, or untar to `/opt/m2c` |
| **Container image** | `python:3.12-slim` plus the bundle, `ENTRYPOINT m2c proxy`, volume `/data` | standalone sidecar or base image |

  - PyInstaller onefile is rejected: it would unpack a 555 MB `.so` into `/tmp` on every start.
  - **Size** is about 800 MB, because the `chdb` wrapper hard-requires pandas and pyarrow.
  - **M0 spike:** drive `chdb-core` directly without the pandas/pyarrow wrapper, which could cut the size roughly in half.
- **Process:** one `mitmdump` process with `-s entry.py`. `m2c proxy` `exec`s it with:
  ```
  mitmdump --mode regular@127.0.0.1:8080 [--mode socks5@127.0.0.1:1080] -s <pkg>/entry.py \
    --set proxyauth=any --set connection_strategy=eager --set ssl_insecure=true --set flow_detail=0
  ```
- **State survives a reload.** A singleton module holds the queue, the writer thread, the chDB session, the connection state and the live WebSocket/SSE flows, so an add-on reload doesn't re-initialise chDB. chDB allows only one data path per process. `done()` drains only when `ctx.master.should_exit` is set.
- **No `fork()` after `import chdb`:** a forked child hangs on its first query. `subprocess` is fine, but no `multiprocessing` with fork, and nothing that daemonizes.
- **Write path:**
  1. Hooks only build a tuple of references (raw body bytes, `headers.fields`, identity) and call `put_nowait` on a bounded queue.
  2. One `m2c-writer` thread encodes **RowBinary** with stdlib `struct` and inserts through `session.send_insert("INSERT INTO t (...)", "RowBinary")`.
  3. It flushes each table at 1000 rows, 8 MiB or 250 ms, whichever comes first.
  4. chDB releases the GIL during inserts. The measured event-loop lag was p50 0.08 ms, max about 5 ms.
  5. Under real proxied load it cost about 6% throughput (1515 against 1604 requests/s) and p99 51 ms against 42 ms.
- **Why batching and RowBinary:**
  - Each insert creates one part and costs about 4–5 ms. chDB's `async_insert` does nothing.
  - RowBinary stores binary bodies losslessly and is the fastest path: about 21k rows/s at batch 200, 41k rows/s at batch 1000.
  - JSON through `query()` mangles non-UTF-8 bodies.
- **chDB settings** (in the connection path, e.g. `path?max_server_memory_usage=…&background_pool_size=2&mark_cache_size=…`): cap memory, because the default is 90% of RAM and a 5 GB mark cache. Expect about 500 MB RSS at idle and 1–1.8 GB while ingesting heavily. `m2c_fsync=true` adds `fsync_after_insert` (about 3 ms per batch) for power-loss safety.
- **Reading during the scan:** a second process **cannot** open the data directory, even read-only, because chDB holds a lock on `<path>/status`. So all live reads go through the **in-process API** (§6).
- **End of scan:** push to central ClickHouse (§7). As fallbacks:
  - `m2c export --parquet <dir>`
  - ship the directory, which opens in stock `clickhouse-local --path`

---

## 3. Schema (chDB / ClickHouse 26.x)

Each scan gets its own directory, so there is no TTL. Partitioning is a single partition. `scan_id` is kept on every row so that scans can be merged centrally later. The DDL is applied by the add-on at startup with `CREATE … IF NOT EXISTS`, and versions are tracked in `schema_migrations`.

```sql
CREATE DATABASE IF NOT EXISTS m2c;

CREATE TABLE IF NOT EXISTS m2c.http_flows
(
    scan_id             LowCardinality(String),
    flow_id             UUID,
    n                   UInt64,                        -- per-scan sequence: "#1042" in CLI/UI/MCP
    ts_start            DateTime64(3,'UTC') CODEC(Delta, ZSTD(1)),
    ts_end              DateTime64(3,'UTC') CODEC(Delta, ZSTD(1)),
    ttfb_ms             UInt32,
    duration_ms         UInt32,
    -- identity
    session             LowCardinality(String),
    tool                LowCardinality(String),
    call_id             String,
    tag                 String,
    ua_tool             LowCardinality(String),
    proxy_user          String,                        -- username only, capped 256
    identity_source     Enum8('connect'=1,'request'=2,'socks5'=3,'header'=4),
    -- connection
    listener            LowCardinality(String),
    client_conn_id      UUID,
    server_conn_id      UUID,
    client_ip           IPv6,
    server_ip           IPv6,
    server_port         UInt16,
    tls                 Bool,
    sni                 String,
    tls_version         LowCardinality(String),
    alpn                LowCardinality(String),
    -- request
    method              LowCardinality(String),
    scheme              LowCardinality(String),
    host                LowCardinality(String),
    port                UInt16,
    path                String CODEC(ZSTD(1)),
    url                 String CODEC(ZSTD(1)),
    http_version        LowCardinality(String),
    req_headers         Array(Tuple(name String, value String)) CODEC(ZSTD(1)),   -- wire order, duplicates kept
    req_trailers        Array(Tuple(name String, value String)) CODEC(ZSTD(1)),
    req_body            String CODEC(ZSTD(3)),                                  -- raw bytes, capped
    req_body_size       UInt64,                                                 -- full wire size
    req_body_truncated  Bool,
    req_body_decoded    Bool,
    req_capture         Enum8('none'=0,'buffered'=1,'streamed'=2,'dropped'=3),
    -- response
    status              UInt16,                                                 -- 0 = no response
    reason              LowCardinality(String),
    resp_headers        Array(Tuple(name String, value String)) CODEC(ZSTD(1)),
    resp_trailers       Array(Tuple(name String, value String)) CODEC(ZSTD(1)),
    resp_content_type   LowCardinality(String),
    resp_body           String CODEC(ZSTD(3)),
    resp_body_size      UInt64,
    resp_body_truncated Bool,
    resp_body_decoded   Bool,
    resp_capture        Enum8('none'=0,'buffered'=1,'streamed'=2,'dropped'=3,'sse'=4,'websocket'=5),
    -- long-lived streams
    sse_event_count     UInt32,
    ws_message_count    UInt32,
    ws_close_code       UInt16,
    ws_close_reason     String,
    ws_closed_by_client Bool,
    -- outcome
    error               String,
    error_kind          LowCardinality(String),   -- client_abort|upstream_connect|upstream_disconnect|upstream_tls|timeout|killed|other
    end_reason          Enum8('complete'=1,'error'=2,'ws_closed'=3,'proxy_shutdown'=4),
    INDEX idx_host host    TYPE bloom_filter(0.01)      GRANULARITY 4,
    INDEX idx_url  url     TYPE ngrambf_v1(3,65536,2,0) GRANULARITY 4,
    INDEX idx_n    n       TYPE minmax                  GRANULARITY 1,   -- point lookups by #n
    INDEX idx_flow flow_id TYPE bloom_filter(0.001)     GRANULARITY 1
)
ENGINE = MergeTree
ORDER BY (session, ts_start, flow_id)
SETTINGS max_compress_block_size = 4194304, min_compress_block_size = 1048576;

CREATE TABLE IF NOT EXISTS m2c.ws_messages
(
    scan_id LowCardinality(String), flow_id UUID, seq UInt32,
    ts DateTime64(3,'UTC') CODEC(Delta, ZSTD(1)),
    session LowCardinality(String), tool LowCardinality(String), call_id String, host LowCardinality(String),
    from_client Bool, opcode Enum8('text'=1,'binary'=2),
    size UInt32, truncated Bool, injected Bool, dropped Bool,
    content String CODEC(ZSTD(3))
)
ENGINE = MergeTree ORDER BY (session, flow_id, seq)
SETTINGS max_compress_block_size = 4194304, min_compress_block_size = 1048576;

CREATE TABLE IF NOT EXISTS m2c.sse_events
(
    scan_id LowCardinality(String), flow_id UUID, seq UInt32,
    ts DateTime64(3,'UTC') CODEC(Delta, ZSTD(1)),
    ms_since_req UInt32,                          -- first event = time to first token
    session LowCardinality(String), tool LowCardinality(String), call_id String, host LowCardinality(String),
    event LowCardinality(String), id String, retry_ms UInt32,
    data String CODEC(ZSTD(3)),
    size UInt32, truncated Bool,
    partial Bool                                  -- flushed at end/error without a blank line
)
ENGINE = MergeTree ORDER BY (session, flow_id, seq);

CREATE TABLE IF NOT EXISTS m2c.proxy_events
(
    scan_id LowCardinality(String),
    ts DateTime64(3,'UTC') CODEC(Delta, ZSTD(1)),
    kind LowCardinality(String),   -- auth_challenge|auth_rejected|connect_error|tls_failed_client|tls_failed_server|health|started|stopped
    severity Enum8('debug'=0,'info'=1,'warn'=2,'error'=3),
    session LowCardinality(String), tool LowCardinality(String),
    proxy_user String, reason LowCardinality(String),
    client_conn_id UUID, client_ip IPv6,
    host LowCardinality(String), port UInt16, sni String, status UInt16, flow_id UUID,
    message String CODEC(ZSTD(3)),
    counters Map(LowCardinality(String), Int64)   -- health: queued, written, dropped, hook_errors, tee_errors, ...
)
ENGINE = MergeTree ORDER BY (kind, ts);

CREATE VIEW IF NOT EXISTS m2c.session_summary AS
SELECT session, tool, min(ts_start) first_seen, max(ts_end) last_seen, count() flows,
       countIf(status >= 400 OR error != '') failures, uniqExact(host) hosts,
       sum(req_body_size) bytes_up, sum(resp_body_size) bytes_down,
       sum(ws_message_count) ws_messages, sum(sse_event_count) sse_events
FROM m2c.http_flows GROUP BY session, tool;
```

- **Bodies** are stored as raw bytes. Headers and encoding are interpreted at query time.
- **Compression:**
  - ZSTD(3) with the larger compress block sizes measured 4.7x on mixed traffic and 42x on LLM conversations, which resend their history every turn.
  - `ORDER BY session, ts` puts those repeats next to each other, which is what drives the 42x.
- **Tuple fields are named** so that Parquet export gets real column names rather than `1`/`2`.

---

## 4. Capture, hook by hook

**Rules for every hook:**
- Each hook body runs inside `guard()`, which catches errors and counts them in `hook_errors`.
- Each stream callback catches its own exceptions and always returns the chunk unchanged. mitmproxy does not catch exceptions in stream callbacks, so one uncaught error would kill the client connection, including every HTTP/2 stream on it.
- `metadata['m2c'].done` guarantees one `http_flows` row per flow.

**Lifecycle and connections**

| Hook | Behaviour |
|---|---|
| `load` / `configure` | Register the `m2c_*` options, each defaulting to its `M2C_*` env var, and validate them. In `token` mode a missing secret raises `OptionsError`. |
| `running` | Open chDB once, apply the schema, start the writer and the query endpoint, write a `started` event. |
| `done` | On a real shutdown: write `proxy_shutdown` rows for live WS/SSE flows, drain the queue (up to 10 s), close the session. |
| `client_connected` / `client_disconnected` | Create and drop the per-connection state. |
| `http_connect` / `socks5_auth` | Authentication (see §1). Read CONNECT `x-m2c-*` headers, then strip them. |
| `http_connect_error`, `tls_failed_client` / `tls_failed_server` | `proxy_events` rows. These are the only trace left by pinned clients and clients that don't trust the CA. |

**HTTP**
- **`requestheaders`:**
  - resolve and re-validate the identity
  - apply and strip the header overrides
  - install a request tee for chunked bodies, bodies of unknown length, or bodies above `m2c_stream_threshold`
- **`responseheaders`:** install a tee for `text/event-stream` (SSE parser), for ndjson, gRPC or the AWS event stream, and for any body without a Content-Length or above the threshold. Tees are always installed up front, so mitmproxy never switches to streaming partway through a body and leaves part of it unrecorded.
- **`response`:** if the flow is ours (a 407) or has no identity, write an event. If it is a WebSocket upgrade, add it to the live set. Otherwise enqueue the row.
- **`error`:** flush the tee and the SSE parser (the trailing event gets `partial=1`), then enqueue the row with an `error_kind`.

**HTTP/2 and decoding**
- **HTTP/2:** the proxy hop is HTTP/1.1. Inside a tunnel, ALPN negotiates h2, and its streams inherit the tunnel's identity. Trailers are recorded.
- **Decompression** runs on the writer thread, never in a hook: gzip, deflate (including raw deflate), br and zstd.
- **Bounds:** decompression output never exceeds `m2c_body_cap`, so a compression bomb is bounded.
- **Caps:** `m2c_body_cap` defaults to 1 MiB. `*_size` always records the full wire size.

**SSE**
- An incremental parser runs on the stream. It handles any chunk boundary, `\r\n` and `\r`, multi-line `data`, and `id`/`retry`, and it counts comment lines.
- It keeps parsing past the body capture cap.
- Each event is enqueued as soon as it completes, so it is visible within about 250 ms.
- Limits: event data is capped at `m2c_sse_event_cap` (64 KiB), and rows stop after `m2c_sse_max_events` (100k) while counting continues.

**WebSocket**
- **`websocket_message`:** enqueue `messages[-1]` (capped at 256 KiB), then `del messages[:-1]`, so long-lived sockets keep memory flat.
- **`websocket_end`:** enqueue the summary row with the close code and reason, and which side closed.
- **Limitation:** ping and pong are not visible in mitmproxy 12.

**Redaction**
- Proxy credentials are never stored.
- `m2c_redact_headers` takes a list of header names, with `hash`, `drop` or `none`. The default stores everything, which suits security testing.

---

## 5. Delivery and failure behaviour

- **Queue:** bounded at 100k items and 256 MiB. `put` never blocks.
  - Over the limit, bodies are stripped first and marked `capture='dropped'`, with sizes kept.
  - Over 1.25× the limit, the row is dropped.
  - Both are counted.
- **Writer:**
  - one buffer per table
  - a failed insert, such as `MEMORY_LIMIT_EXCEEDED`, is retried with backoff
  - a batch that keeps failing is bisected until the bad row is isolated, and that row goes to `dead/` as a RowBinary file with an event logged
  - there is no network spool and no dedup tokens, because chDB is local
- **Health:** every 30 s a `proxy_events kind=health` row with the counters, plus a warning log whenever drops are non-zero.
- **Durability, as measured:**
  - SIGTERM or SIGINT flushes everything.
  - `kill -9` loses at most the last batch window (about 250 ms) plus the summary rows of streams still open. Their `sse_events` and `ws_messages` rows were already written live.
  - Data on disk is always a consecutive prefix, with no gaps.
  - A stale lock does not block reopening.
- **Fail open:** if chDB cannot open, the proxy refuses to start. If writing is impaired later, traffic keeps flowing and drops are counted.

---

## 6. Live querying: API, CLI, MCP, web UI

The proxy process holds the chDB lock, so **it** serves every read. Everything else (CLI, MCP, UI) is a thin client of one HTTP API.

```
            mitmdump process
 ┌───────────────────────────────────────────────────┐
 │ hooks ─► queue ─► writer thread ─► chDB (writer)  │
 │             └──► live ring buffer + pub/sub ──┐   │
 │ tornado API (same asyncio loop)               │   │
 │   /v1/*  /mcp  /ui  ◄── reader pool (N chDB   ◄───┘
 │                          sessions, readonly=1)    │
 └───────────────────────────────────────────────────┘
   ▲ m2c CLI (urllib, no chDB import)   ▲ MCP clients   ▲ browser
```

**What makes it fast**
- **Live tail never touches the DB.** Hooks also push a body-less summary of each flow into an in-memory ring (last 10k flows) with pub/sub. `tail` and the UI's live view stream from it, so a flow shows up in about a millisecond, before the writer has flushed it.
- **Lists never read body columns.** It is a columnar store, so `ls` reads only the summary columns. It filters on the `ORDER BY (session, ts)` prefix and uses the skip indexes, and pages with a keyset cursor `(ts_start, n)`, not OFFSET.
- **Point lookups by `#n`.** `n` is a per-scan counter, restored from `max(n)` on restart, with a minmax index on it. Bodies are fetched lazily, separately, and capped.
- **A pool of reader sessions.** One chDB session serializes its queries, so there are 2–4 reader sessions in threads. Each runs `SET readonly=1`, which is verified to stick and cannot be undone, plus `max_execution_time`, `max_result_rows` and `max_result_bytes`. A slow ad-hoc query never blocks `ls`, `tail` or the writer.
- **The CLI client is stdlib only** (urllib). It never imports chDB, which saves about 270 MB and seconds of startup. It only imports chDB in offline mode.

**One filter language everywhere** (CLI, API `q=`, MCP, UI search box):

`session:abc tool:nuclei host:*.acme.test method:POST status:5xx|404 ct:json has:sse has:ws err: "free text" after:10m`

It is compiled to parameterized SQL, never string-built. Free text searches `url`; `body:"..."` searches bodies explicitly.

**API** (`m2c_api_listen`, default `127.0.0.1:8124`, plus an optional unix socket)

| Endpoint | Returns |
|---|---|
| `GET /v1/scan` | scan id, uptime, counters (queued, written, dropped, errors), sessions, tools |
| `GET /v1/sessions` | per session and tool: flows, failures, hosts, bytes, first and last seen |
| `GET /v1/flows?q=&limit=&cursor=` | summaries (`n`, ts, session, tool, method, host, path, status, sizes, duration, flags) |
| `GET /v1/flows/{n}` | full detail: headers, trailers, TLS, timings, identity, error |
| `GET /v1/flows/{n}/body/{req\|resp}?decode=1&max=` | the body bytes with their original Content-Type, or decoded |
| `GET /v1/flows/{n}/sse`, `/ws` | events or messages, paged |
| `GET /v1/flows/{n}/curl` | a curl command that replays the request (credentials stripped) |
| `GET /v1/tail?q=` | SSE stream of new flows matching `q`, from the ring |
| `GET /v1/har?q=` | HAR export of a filter |
| `POST /v1/sql` | read-only SQL, `format=` JSONEachRow, TSV, Parquet or Arrow, streamed (admin only) |

**API auth: two kinds of token**
- **Admin token.** Made at startup and written to `<data>/api.json` (mode 0600, with the URL). It can do everything, including SQL.
- **Session token.** The same HMAC token the agent already uses as its proxy password. The API scopes it to that session: the server adds `session = …` to every query, and SQL is refused. So an agent can inspect *its own* traffic through MCP, and nobody else's.

**CLI** (`m2c`)
- **Finding the API:** `$M2C_API`, else `<data>/api.json`, else **offline mode**, which opens the directory directly once the proxy has stopped. The same query module serves both modes.
- **Commands:**

| Command | What it does |
|---|---|
| `m2c sessions` | the per-session summary |
| `m2c ls [query]` | flow summaries |
| `m2c show 1042 [--body] [--raw]` | one flow in full |
| `m2c tail [-f] [query]` | new flows as they arrive |
| `m2c sse 1042` / `m2c ws 1042` | SSE events or WebSocket messages of one flow |
| `m2c curl 1042` | a curl command that replays the request |
| `m2c har [query] > x.har` | HAR export |
| `m2c sql "…" [--format parquet]` | read-only SQL |
| `m2c stats` | counters |

- **Output:** human tables on a TTY, `--json` (JSON lines) for agents and scripts.

**MCP**
- **Two transports:**
  - Streamable HTTP served by the same API at `/mcp`, so a harness only needs a URL and a token. No extra process.
  - `m2c mcp` as a stdio shim that forwards to the API, for clients that only speak stdio.
- **Tools:** `traffic_sessions`, `traffic_search(query, limit, cursor)`, `traffic_get(n, include_bodies, max_bytes)`, `traffic_sse(n)`, `traffic_ws(n)`, `traffic_stats`, plus `traffic_sql(sql)` with an admin token only.
- **Bounded output:** bodies are truncated (8 KB by default) with a hint on how to fetch more, and lists are summaries, so an agent's context doesn't fill up.
- **Hand-rolled:** the JSON-RPC is a few hundred lines, so the `mcp` SDK isn't needed (it pulls in pydantic and starlette). Decide in M5.

**Web UI** (`m2c_ui=true`, served at `/ui` by the same API)
- **No build step:** one static HTML page with vanilla JS, shipped inside the package.
- **Layout:**
  - sessions and tools sidebar with counts
  - virtualized flow table with the filter bar
  - detail pane: headers, body (pretty JSON, hex for binary, image preview), timings, SSE timeline, WebSocket message list
  - live-tail toggle (streamed from `/v1/tail`), curl and HAR buttons
- **Login:** `m2c proxy` prints `http://127.0.0.1:8124/ui#token=…`. The token is in the fragment, so it never appears in server logs.
- **Exposing the UI outside the container:** bind `m2c_api_listen=0.0.0.0:8124`. That requires the admin token and checks the Host header.

---

## 7. Push to central ClickHouse at end of scan

- **How:** chDB has `remote()` and `remoteSecure()` (verified), so the push is done by the **engine itself, over the native protocol**: `INSERT INTO FUNCTION remoteSecure('ch.example:9440', 'm2c', 'http_flows', user, pw) SELECT * FROM m2c.http_flows`. It is compressed, it streams, and no rows go through Python.
- **HTTPS-only egress:** a fallback uses the HTTP interface (`url()` table function, or a streamed POST with `FORMAT Native`).
- **Central schema:** `m2c central init --url …` creates it.
  - The same columns as local, but `PARTITION BY toYYYYMM(ts_start)`, `ORDER BY (scan_id, session, ts_start, n)` and an optional TTL.
  - A `m2c.scans` table: scan_id, started and ended, host, m2c version, labels (`--label env=ci`), row counts per table, push status.
  - Migrations only add columns, so an older scan can still be pushed to a newer central schema, with an explicit column list.
- **Idempotency:**
  - Each table is pushed in chunks of `n` or row ranges, each with `insert_deduplication_token = <scan_id>:<table>:<chunk>`. Re-running a push after a failure never duplicates rows.
  - Afterwards, the counts are compared per table and the `scans` row is updated to `pushed`.
- **When it runs:**
  - `m2c push [--data dir] --to clickhouse[s]://user@host:port/db`
  - or `m2c_push_on_exit=<url>`, which runs in `done()` after the final drain
  - credentials come from env or a file, never argv
- **When it fails:** the local directory stays intact and the proxy exits non-zero. `m2c push --data dir` can be re-run later from anywhere, because offline mode needs no running proxy.
- **Later:** a periodic push during long scans. The chunked, idempotent design makes that a scheduling change only.

---

## 8. Repo, configuration, tests

```
pyproject.toml            # deps: mitmproxy>=12.2,<13, chdb>=4.4; script m2c
src/m2c/
  entry.py                # -s shim: addons = [Recorder()]
  recorder.py             # stateless hook class
  state.py                # singleton: queue, writer, chDB sessions, conn state, live ring
  identity.py             # grammar, HMAC mint/verify, overrides, ua_tool
  tee.py sse.py decode.py # guarded tees, SSE parser, bounded decoders (pure)
  rows.py rowbinary.py    # flow -> row tuples; stdlib RowBinary encoder (pure)
  writer.py               # batching, retry, bisection, dead letters
  schema.py               # local + central DDL, migrations
  filters.py              # filter language -> parameterized SQL (pure)
  queries.py              # shared read layer (online API and offline CLI)
  api.py mcp.py           # tornado API, /mcp, reader pool, tail pub/sub
  ui/index.html           # static web UI, no build step
  push.py                 # central ClickHouse push (remoteSecure / HTTP)
  client.py cli.py        # stdlib API client; m2c proxy|mint|env|run|ls|show|tail|sql|har|push|export|mcp|doctor|hooks
packaging/bundle.sh       # python-build-standalone + venv -> tar.zst (x86_64, aarch64)
Dockerfile                # python:3.12-slim + bundle
integrations/claude-code/ integrations/codex/ integrations/playwright/ integrations/generic/
tests/unit tests/integration tests/servers   # http, chunked+gzip SSE, ws echo, central CH (docker)
```

**Main options:**

| Option | Default |
|---|---|
| `m2c_data` | `./m2c-data` |
| `m2c_scan_id` | random |
| `m2c_auth` | `token` |
| `m2c_secret_file` | — |
| `m2c_body_cap` | 1 MiB |
| `m2c_stream_threshold` | 1 MiB |
| `m2c_ws_msg_cap` | 256 KiB |
| `m2c_sse_event_cap` | 64 KiB |
| `m2c_batch_rows` | 1000 |
| `m2c_batch_bytes` | 8 MiB |
| `m2c_flush_interval` | 0.25 |
| `m2c_queue_max_bytes` | 256 MiB |
| `m2c_memory_limit` | 2 GiB |
| `m2c_fsync` | `false` |
| `m2c_api_listen` | `127.0.0.1:8124` |
| `m2c_api_socket` | — |
| `m2c_readers` | 3 |
| `m2c_ui` | `false` |
| `m2c_ring_size` | 10000 |
| `m2c_push_on_exit` | — |
| `m2c_labels` | — |
| `m2c_redact_headers` | `""` |

**Tests**
- **Unit:** the pure modules, plus Recorder tests with `mitmproxy.test.tflow` and `taddons`.
- **RowBinary round-trip:** the encoder, read back through chDB, preserves arbitrary bytes exactly.
- **Property tests (hypothesis):** any way of splitting an SSE corpus into chunks gives the same events, decoders split at random points give the same output, and an exception in a tee never breaks forwarding.
- **Integration:** a real mitmdump with chDB in a temp directory, driven by curl (HTTP, HTTPS, SOCKS5), requests, httpx, Node fetch with `NODE_USE_ENV_PROXY`, git and Playwright. Checks: SSE still streams live with the proxy in the path, WS close codes are recorded, 407 handling, binary bodies come back byte for byte.
- **Chaos and load:** SIGTERM flush, `kill -9` leaves a consecutive prefix, a hot reload doesn't re-initialise chDB, about 500 rps plus 50 SSE streams with memory flat.

---

## 9. Milestones

- **M0, scaffold and spikes:**
  - pyproject, schema module, `m2c proxy` launching mitmdump with chDB opened
  - spikes: `chdb-core` without pandas/pyarrow; reader-pool latency while the writer is under load; `remoteSecure` push to a dockerized ClickHouse
  - *Done when:* `m2c sql "select 1"` works.
- **M1, HTTP end to end:**
  - the state singleton, the writer (RowBinary, batching, retry), `http_flows` and `proxy_events`, `n` numbering
  - the 407 rules, `m2c env`
  - *Done when:* curl over HTTP and HTTPS gives correct rows, a bad credential gives a 407 and an event, and a binary body round-trips exactly.
- **M2, attribution:**
  - HMAC tokens, `m2c mint`, `m2c run` with the per-tool flags, `x-m2c-*` overrides, SOCKS5
  - the credential scrub, `ua_tool`, the CA bundle
  - *Done when:* the client matrix passes and a token can't be used for another session.
- **M3, streaming:**
  - tees, bounded decoders, the SSE parser, WebSocket with trimming, trailers, `error_kind`
  - *Done when:* SSE stays live through the proxy and a 1-hour stream keeps memory flat.
- **M4, API and CLI:**
  - reader pool, filter language, `/v1/*`, the live ring and `tail`, admin and session-scoped tokens
  - the CLI, online and offline
  - *Done when:* `ls` and `show` return in under 50 ms on 1M flows, and `tail` latency is under 10 ms.
- **M5, MCP and web UI:**
  - `/mcp` and the `m2c mcp` stdio shim, with bounded outputs
  - the static UI with live tail
- **M6, central push:**
  - `m2c central init`, `m2c push` with chunked dedup tokens and count verification, `m2c_push_on_exit`, the `scans` table
  - *Done when:* a push killed midway and re-run ends with exact counts.
- **M7, ship:**
  - the bundle (x86_64 and aarch64), the container image, integrations (Claude Code, Codex, Playwright, generic)
  - load test, health rows, chaos tests, docs
- **Later, if wanted:**
  - raw TCP/UDP/DNS tables
  - LLM-call extraction (JSON columns)
  - periodic push during long scans
  - egress enforcement so tools can't bypass the proxy

---

## 10. Open questions

1. **API exposure.** Loopback only by default, with `0.0.0.0` an opt-in that requires the admin token? Or should the UI and API be reachable from outside the container by default?
2. **Agents querying their own traffic.** Should MCP be available to the agents under test (scoped to their own session), or only to people and supervising agents?
3. **Web UI scope for v1.** A read-only viewer (list, filter, detail, live tail)? Or also Repeater-style edit-and-resend?
4. **Central ClickHouse access.** Native protocol (9440) reachable from scan containers, or HTTPS (8443) only? Is there an existing central cluster and schema to match?
5. **Redaction and caps.** *Default: full fidelity with a 1 MiB body cap. Should known LLM hosts get 8 MiB?*
6. **Fail open or fail closed** when capture is impaired. *Default: fail open and count the drops.*
