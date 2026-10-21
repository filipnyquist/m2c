<p align="center"><img src="docs/banner.svg" alt="m2c — mitmproxy2chDB: record every request your AI agents make, per session and per tool, into embedded ClickHouse" width="100%"></p>

A recording proxy for AI agents. Run it once per scan or agent run, point the tools your agents use at it, and
every request they make lands in an embedded ClickHouse database ([chDB](https://clickhouse.com/chdb)). That
covers HTTP requests and responses with bodies, SSE events one by one, WebSocket messages, errors, auth
failures and TLS failures. Each row records **which agent session and which tool** sent it.

You can watch it live while the scan runs: there is an API, a CLI, an MCP server and a small web UI. At the end,
the scan is pushed to a central ClickHouse, or kept as a directory that `clickhouse-local` opens.

<p align="center"><img src="docs/demo.gif" alt="The m2c web UI: flows from two agent runs arrive live, an SSE stream's events appear while it is open, a 500 response and the SQL-injection request behind it are inspected, and the table is filtered by status, tool and session" width="100%"></p>
<p align="center"><sub>Two agent runs through m2c, seen in the web UI (<code>docs/demo/make_gif.py</code> records it).</sub></p>

```
 agent tools ──HTTP(S)/SOCKS5──►  mitmdump + m2c recorder  ──► upstream
 (curl, nuclei, python,          │  hooks → queue → writer thread → chDB (one data dir per scan)
  browsers, …)                   │  live feed (memory) ─► API :8124  /v1/*  /mcp  /ui/
                                 └─ at exit (optional) ──► central ClickHouse (native or HTTPS)
```

## Quick start

```bash
uv tool install .            # or: pipx install . ; or the bundle / container below
m2c proxy                    # proxy on 127.0.0.1:8080, API/UI on 127.0.0.1:8124, data in ./m2c-data
```

In another shell, in the same directory (or with the same `M2C_DATA`, so the commands find the proxy's secret
and API):

```bash
TOKEN=$(m2c mint run42)                       # a token for session "run42"
curl -x "http://run42.curl:$TOKEN@127.0.0.1:8080" --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://example.com/
m2c run --session run42 --tool nuclei -- nuclei -u https://example.com   # adds -proxy for you
m2c ls                                        # newest flows
m2c tail                                      # follow live
m2c show 1                                    # one flow in full
```

The UI link, with its token, is printed when the proxy starts: `http://127.0.0.1:8124/ui/#token=…`.

## Who sent it: credentials

Each client authenticates to the proxy with **proxy credentials that name the sender**:

```
username = <session>.<tool>[.<call>]     e.g. run42.nuclei   or   8f2c…e1.bash.toolu_01ab
password = <token for that session>      from `m2c mint <session>`
```

- **`session`:** one id per agent run. Use the harness's own id, e.g. Claude Code's `session_id`.
- **`tool`:** the program, e.g. `curl`, `nuclei`, `bash-curl`, `browser`.
- **`call`:** optional, e.g. a tool-call id or a step counter.
- **Allowed characters:** letters, digits, `_` and `-` (and `.`/`~` in `call`), so no client ever needs to percent-encode anything.
- **The token is an HMAC of the session.** An agent can name any tool inside its own session but cannot write rows into another session. Tokens can expire (`m2c mint --ttl 24h`).
- **The secret** lives in `<data>/secret` or `$M2C_SECRET`. The proxy creates it at start. `m2c mint`, `env`, `run` and `hook` never create one; they say so when they can't find it. `m2c mint --init` creates it before the first `m2c proxy`.

**Auth modes** (`--auth`):

| Mode | Password | Use |
|---|---|---|
| `token` (default) | the session's HMAC token | normal use |
| `shared` | one shared secret for everyone | simple setups |
| `open` | anything; `user:tool` (no dot) means session = user, tool = password | trusted local use only; refused on a non-loopback listener unless `m2c_allow_open_exposed=true` |

**One process, many tools.** A long-lived client can name the tool for each request with the headers
`x-m2c-tool`, `x-m2c-call` and `x-m2c-tag`. The proxy records them and strips them before forwarding, and a
header can never change the session. `ua_tool` also records a guess from the User-Agent, for forensics only.

**Failed auth.** Missing or bad credentials get a `407` and a row in `proxy_events`, never a row in
`http_flows`. Passwords are never stored.

**Trust boundary.** An agent that runs as the same Unix user as the proxy can read the secret. For real
isolation, run the proxy as its own user or in its own container. The data directory is mode 0700 (reset at every
proxy start) and spool files are 0600, because they hold every captured body, cookie and credential.

### Wiring agents

| Harness | How |
|---|---|
| Any | `m2c run --session S --tool T -- cmd …`, or `eval "$(m2c env --session S --tool T)"` in the tool's shell. This sets `HTTP(S)_PROXY`, `ALL_PROXY`, `NO_PROXY`, `NODE_USE_ENV_PROXY=1` and the CA bundle variables (`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `GIT_SSL_CAINFO`). The CA bundle goes to `<data>/ca-bundle.pem`, or to `~/.cache/m2c/` when the data directory isn't writable (a proxy running as another user). |
| Claude Code | `m2c hooks claude-code` prints a SessionStart hook. Its Bash commands then go through the proxy as `<session_id>.bash`. |
| Browsers (Playwright and others) | context proxy option: `{server: 'http://127.0.0.1:8080', username: 'run42.browser', password: TOKEN}` |
| nuclei, katana, httpx, sqlmap, ffuf | they ignore the environment variables; `m2c run` adds their proxy flags. httpx here means ProjectDiscovery's; the Python httpx CLI reads the environment and gets no flags. naabu gets none either, because its `-proxy` is SOCKS5 only. |

**The agent's own LLM API traffic must not go through the proxy.** Set the variables only for the tools an agent
runs, never for the harness process itself. `m2c doctor` warns when the current shell has them.

`m2c env` and `m2c run` find a running proxy's address in `<data>/api.json`. Otherwise pass `--proxy` or set
`M2C_PROXY`.

## What is recorded

**Tables in database `m2c`:**

| Table | One row per |
|---|---|
| `http_flows` | HTTP flow: identity, timings, TLS (SNI, version, ALPN), method/URL, headers and trailers in wire order, bodies (decoded, capped at 1 MiB, full size kept), status, error and error kind, SSE/WebSocket summary |
| `sse_events` | SSE event of a streamed response, written as it arrives (`ms_since_req` of the first event is the time to first token) |
| `ws_messages` | WebSocket message, either direction, text or binary |
| `proxy_events` | `auth_challenge`, `auth_rejected`, `connect_error` (a CONNECT whose upstream could not be reached), `tls_failed_client` (a client that doesn't trust the CA or pins certificates), `tls_failed_server`, `sse_parse_stopped` (SSE parsing of a flow stopped early; the reason is in `message`), `health` counters, `started`/`stopped` |

**Streaming stays streaming.**
- SSE, ndjson, gRPC, chunked bodies and bodies over 1 MiB pass straight through.
- The recorder tees them, keeps the first `m2c_body_cap` bytes, counts the rest and parses SSE events on the way.
- A failure in that code never breaks the client's connection.

**WebSocket messages are not kept in memory.** Long sockets stay flat.

**Rows go to chDB in batches** (1000 rows, 8 MiB or 250 ms) from one writer thread. The hooks only queue rows,
so a slow insert never delays traffic.
- If the queue fills up, bodies are dropped first, then rows. Both are counted and visible in `m2c stats` and the `health` events.
- **The spool.** Every batch is written to `<data>/spool` first and inserted from there; the file is deleted only once the insert succeeded. chDB's streaming insert can report success and store nothing at the memory limit, so m2c doesn't rely on it.
  - During an outage (for example the memory limit), batches wait on disk and recording goes on.
  - A batch that keeps failing is split, so one batch never stalls the writer.
  - Rows the engine rejects go to `<data>/dead/` and are counted as `dead` in `m2c stats`. An outage that refuses every insert dead-letters nothing.
- **Shutdown.** SIGTERM or SIGINT records every flow still in flight, with `end_reason = proxy_shutdown`, and keeps inserting for up to `m2c_shutdown_timeout` (10 s). What isn't in by then stays in `<data>/spool`; it's inserted at the next start or by `m2c push`. In that case `--push-on-exit` is skipped, and `push-failed.json` says why.
- **After `kill -9`,** at most the last ~250 ms of rows are lost. Batches already in the spool are inserted at the next start, and flow numbers are never reused.

## Looking at a scan

chDB locks its data directory to the proxy process, so **all live reads go through the proxy's API**. Once the
proxy has stopped, the CLI reads the directory directly, with the same commands and the same output. That also
works after a crash: an `api.json` whose API doesn't answer is ignored.

### Filter language

Used by the CLI, the API (`q=`), MCP and the UI:

```
session:run42 tool:nuclei|ffuf call:c7 host:*.example.com method:POST status:5xx|404|>=400 path:/api/*
ct:json ua:curl has:sse|ws|error|body err:timeout after:10m before:2026-10-21T12:00 n:100-200
body:"needle" -status:404 "free text in the URL"
```

`n:` takes `42` or `100-200` (decimal digits). Out-of-range numbers and times are rejected with HTTP 400.

### CLI

| Command | What it does |
|---|---|
| `m2c ls [query] [-n 50] [--cursor N]` | flows, newest last |
| `m2c tail [query]` | live: long-lived flows when they start, every flow when it ends |
| `m2c show N [--body\|--req-body] [--max B]` | one flow; `--body` writes the raw response body to stdout |
| `m2c sessions [query]` | per session and tool: flows, failures, hosts, bytes |
| `m2c sse N`, `m2c ws N` | SSE events or WebSocket messages of a flow |
| `m2c curl N` | a curl command that replays the request. The body goes in `--data-raw` (or through stdin when binary) and the URL isn't globbed, so replaying a captured payload never reads local files. |
| `m2c har [query] > out.har` | HAR export |
| `m2c events [--kind auth_rejected]` | proxy events |
| `m2c sql "SELECT …" [--format Parquet]` | read-only SQL |
| `m2c stats` | totals and writer counters |

Every lookup command takes `--json` (JSON lines) for scripts and agents. The CLI talks to the API with the standard
library only and never loads chDB while a proxy is running.

### API

The API listens on `m2c_api_listen`, `127.0.0.1:8124` by default. Requests need `Authorization: Bearer <token>`:

- **Admin token:** in `<data>/api.json` and printed at startup; it stays the same across restarts of one data directory. It can do everything, including SQL.
- **`<session>:<proxy token>`:** sees only that session. No SQL, no proxy events.

| Endpoint | Returns |
|---|---|
| `GET /v1/scan` | totals, writer counters |
| `GET /v1/sessions?q=` | per session and tool summary |
| `GET /v1/flows?q=&limit=&cursor=&order=` | summaries, newest first, with a `next` cursor |
| `GET /v1/flows/N` | full detail (`pending: true` while a flow is still being written) |
| `GET /v1/flows/N/body/req\|resp?max=` | the body bytes. Always sent as `application/octet-stream` with a sandbox CSP; the original type is in `X-M2C-Content-Type`. |
| `GET /v1/flows/N/sse`, `/ws` | events or messages, paged with `after=` |
| `GET /v1/flows/N/curl`, `GET /v1/har?q=` | replay command, HAR export |
| `GET /v1/tail?q=&backlog=` | **SSE stream:** `open` when a long-lived flow starts, `flow` when any flow ends, `stats` every 2 s |
| `GET /v1/flows/N/live` | **SSE stream:** the SSE events or WebSocket messages of an open flow as they happen, then `end` |
| `POST /v1/sql?format=` | read-only SQL (admin) |
| `POST /mcp` | MCP over Streamable HTTP |
| `GET /ui/` | the web UI |

**How the live parts work.** They run from memory:
- the newest 10 000 flow summaries
- the open flows
- previews (the first 4 KiB) of the last 200 events of each open flow, at most 32 MiB for all open flows together

A flow shows up in about a millisecond, before it's even written to disk. Everything else comes from the database.
A reconnecting tail resumes from its `Last-Event-ID`.

**Queries** run on two small pools of read-only chDB sessions (`readonly=1`): one for interactive reads, one for
heavy work (SQL, HAR, `body:` searches). A slow query never blocks `ls` or the UI, and a session token gets a
limited share of each pool.

The sessions can't write, change settings or read local files with `file()`/`url()`.

**On a 1M-flow scan:**

| Query | Time |
|---|---|
| `ls` | 20–55 ms |
| one flow | about 40 ms |
| a body | about 20 ms |

### MCP

- **Over HTTP:** `POST /mcp` on the API, with the same tokens.
- **Over stdio:** `m2c mcp`. It forwards to the live API, or reads a stopped scan.

**Tools:**
- `traffic_stats`, `traffic_sessions`, `traffic_search`
- `traffic_get`: bodies are cut at `max_bytes`, 8 KiB by default
- `traffic_sse`, `traffic_ws`, `traffic_curl`
- `traffic_sql`: admin token only

An agent given its own `<session>:<token>` can inspect its own traffic and nothing else.

Over HTTP, a body that isn't JSON gets HTTP 400 with JSON-RPC error -32700, and an empty batch gets -32600. A bad
element in a batch only gets its own error reply.

```json
{"mcpServers": {"traffic": {"command": "m2c", "args": ["mcp", "--data", "/data/scan"]}}}
```

### Web UI

**Layout:**
- left: sessions and tools
- middle: a live flow table, filtered with the same filter language
- right: details, with headers, pretty JSON, hex for binary data and image previews

**Streams:** SSE and WebSocket flows appear while they are still open. Selecting one streams its events live and
backfills what came before. curl and HAR export are one click.

**No build step:** it is one static page, served at `/ui/` (turn it off with `--no-ui`).

## Push to a central ClickHouse

```bash
export M2C_PUSH_PASSWORD=…
m2c central init --to https://m2c@ch.example.com:8443/m2c     # create or upgrade the central schema
m2c push --to clickhouses://m2c@ch.example.com:9440/m2c --label env=ci --label repo=foo
m2c proxy --push-on-exit https://m2c@ch.example.com:8443/m2c  # or push automatically at shutdown
```

**How it works:**
- chDB itself streams the rows to the server. Native targets go through `remote()`/`remoteSecure()`; HTTP(S) targets go through `url()` with zstd `FORMAT Native`.
- Tables are sent in chunks, compared with central by content, not only by count.
  - A chunk that is already central is skipped.
  - A chunk that is partly there only sends the missing rows.
  - A re-run push, a scan that grew after an earlier push, or two data directories sharing a scan id never duplicate or lose rows.
- Chunk inserts carry dedup tokens for safe retries. If the server drops a re-push as a duplicate (the rows were deleted centrally since), the missing rows are sent again with a fresh token.
- `m2c push` inserts the spool first, and says how many rejected rows went to `<data>/dead`; those are not pushed.
- Counts are verified per table. The `m2c.scans` table records each scan's labels, row counts and status.
- If the push fails, nothing is deleted: `<data>/push-failed.json` says why, and `m2c push --data DIR` can run later. A successful `m2c push` removes that file.
- `--label` values may contain `,` and `=`.

**Central tables** are partitioned by month and ordered by `(scan_id, session, ts…)`. `--engine
ReplicatedMergeTree`, `--on-cluster` and `--ttl-days` are available. `m2c central ddl` prints the SQL instead of
running it.

**Without a central server:**
- `m2c sql "…" --format Parquet > x.parquet` exports a table
- or ship the directory: it opens with `clickhouse local --path <data>`

## Install and run

| Form | How |
|---|---|
| Python project | `uv tool install m2c` or `pipx install`; Python 3.12 or later |
| Linux bundle | `packaging/bundle.sh` builds `dist/m2c-<v>-linux-<arch>.tar.zst`. It contains a standalone CPython with everything installed, relocatable (the scripts in `m2c/python/bin` too), for glibc 2.17 or later (no Alpine). Untar it anywhere and run `m2c/bin/m2c`. |
| Container | `docker build -t m2c .` then `docker run -p 127.0.0.1:8080:8080 -p 127.0.0.1:8124:8124 -v m2c:/data m2c` |
| Inside another image | `COPY --from=m2c /opt/m2c /opt/m2c` and `ENV PATH=/opt/m2c/bin:$PATH` |

**Sizes:** the bundle is about 205 MB compressed and 725 MB unpacked, almost all of it chDB's engine. The bundle
leaves out chDB's pandas and pyarrow dependencies, which m2c never uses.

**Memory:** the proxy uses about 350 MB of RSS at idle and up to about 1 GB under heavy ingest. `m2c_memory_limit`
caps chDB at 2 GiB by default.

**Speed:** recording adds about 0.17 ms per request, every request is recorded, SSE streams pass through live, and
a 1 M-flow scan answers `ls` in 20–35 ms. Details, method and how to rerun: `PERFORMANCE.md`.

**Upstream certificates** are not verified by default, because test targets often use self-signed ones. Pass
`m2c proxy --verify-upstream` to verify them. The proxy's CA is in `~/.mitmproxy` (or `--confdir`), and
`m2c ca bundle` writes a system+proxy bundle.

Every `m2c_*` option can be set with `--set m2c_x=…` or the `M2C_X` environment variable. Run `m2c proxy --print`
to see the mitmdump command. Commonly used options:

| Option | Default |
|---|---|
| `m2c_data` | `./m2c-data` (one directory per scan) |
| `m2c_auth` | `token` |
| `m2c_body_cap`, `m2c_stream_threshold` | 1 MiB |
| `m2c_ws_msg_cap` | 256 KiB |
| `m2c_sse_event_cap` | 64 KiB of characters of an event's joined data; past it only `size` keeps growing |
| `m2c_batch_rows`, `m2c_batch_bytes`, `m2c_flush_ms` | 1000, 8 MiB, 250 |
| `m2c_queue_max_bytes` | 256 MiB |
| `m2c_memory_limit` | 2 GiB |
| `m2c_api_listen` | `127.0.0.1:8124` |
| `m2c_api_hosts` | — |
| `m2c_readers` | 3 |
| `m2c_ui` | `true` |
| `m2c_push_on_exit` | — |
| `m2c_labels` | — |

## Limits

- Agents use the proxy because they are told to. A tool that ignores the proxy settings goes out directly and is not recorded; enforcing it needs a firewall or network namespace around the agent.
- `m2c proxy` uses mitmproxy's eager connection strategy (lazy breaks HTTP/2 uploads without Content-Length to HTTP/1 servers). A CONNECT to an unreachable host gets a 502 and a `connect_error` row in `proxy_events`, not an `http_flows` row.
- WebSocket ping and pong frames are not visible.
- zstd-encoded SSE streams are stored raw and not parsed into events.
- SSE event parsing stops after a content-decoding error, or when one network chunk decodes to more than 1 MiB, so a compression bomb can't stall the proxy. The raw body is still stored and counted, and a `sse_parse_stopped` row records why.
- Raw TCP, UDP and DNS are not recorded.
- Nothing may `fork()` inside the proxy process after chDB has loaded.

## Development

```bash
uv sync
uv run pytest                 # unit + integration (starts real proxies); push tests need a ClickHouse:
docker run -d --name m2c-central -p 127.0.0.1:18123:8123 -p 127.0.0.1:19000:9000 \
  -e CLICKHOUSE_USER=m2c -e CLICKHOUSE_PASSWORD=centralpw clickhouse/clickhouse-server:26.3-alpine
```

The design and its reasoning are in `PLAN.md`; benchmarks are in `PERFORMANCE.md` (`bench/bench.py`).

## Author

Made by Filip Nyquist <fnyquist@pm.me>.
