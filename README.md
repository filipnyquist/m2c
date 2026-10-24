<p align="center"><img src="docs/banner.svg" alt="m2c — mitmproxy2chDB: record every request your AI agents make, per session and per tool, into embedded ClickHouse" width="100%"></p>

A recording proxy for AI agents. Run it once per scan or agent run, point the tools your agents use at it, and
every request they make lands in an embedded ClickHouse database ([chDB](https://clickhouse.com/chdb)). That
covers HTTP requests and responses with bodies, SSE events one by one, WebSocket messages, errors, auth
failures and TLS failures. Each row records **which agent session and which tool** sent it.

You can watch it live while the scan runs: there is an API, a CLI, an MCP server and a small web UI. At the end,
the scan is pushed to a central ClickHouse, or kept as a directory that `clickhouse-local` opens.

<p align="center"><img src="docs/demo.gif" alt="The m2c web UI: flows from two agent runs arrive live, an SSE stream's events appear while it is open, the SQL-injection request behind a 500 is inspected, resent without the quote and compared with the original, the table is filtered with suggested values and a hint, and the timeline groups a run's flows by tool call before the sessions overview" width="100%"></p>
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
curl -x "http://run42.curl:$TOKEN@127.0.0.1:8080" --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://api.acme.test/
m2c run --session run42 --tool nuclei -- nuclei -u https://api.acme.test  # adds -proxy for you
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
| Claude Code | `m2c hooks claude-code` prints a SessionStart hook and a PreToolUse hook for Bash. Each Bash call's requests then go through the proxy as `<session_id>.bash.<tool_use_id>`, so the timeline groups them per call. |
| Pi | `pi install git:github.com/filipnyquist/m2c` installs the pi extension: it starts a recording proxy per session, runs the session's bash commands through it, and gives the model m2c's MCP tools. See [Pi](#pi) below. |
| Browsers (Playwright and others) | context proxy option: `{server: 'http://127.0.0.1:8080', username: 'run42.browser', password: TOKEN}` |
| nuclei, katana, httpx, sqlmap, ffuf | they ignore the environment variables; `m2c run` adds their proxy flags. httpx here means ProjectDiscovery's; the Python httpx CLI reads the environment and gets no flags. naabu gets none either, because its `-proxy` is SOCKS5 only. |

**The agent's own LLM API traffic must not go through the proxy.** Set the variables only for the tools an agent
runs, never for the harness process itself. `m2c doctor` warns when the current shell has them.

`m2c env` and `m2c run` find a running proxy's address in `<data>/api.json`. Otherwise pass `--proxy` or set
`M2C_PROXY`.

### Pi

`pi install git:github.com/filipnyquist/m2c` installs the pi extension (and the `m2c-traffic` skill) from this
repository: the root `package.json` is the pi package, its manifest points at `integrations/pi/`. The extension
needs the m2c CLI on `PATH` (`uv tool install git+https://github.com/filipnyquist/m2c`).

On every session it starts a recording proxy (or attaches to one that already runs for the same scan directory),
runs the session's bash commands through it, and registers m2c's MCP server for that session. Each bash command's
requests carry the tool call's id, so the timeline groups them per call. The model reads the traffic back with the
`traffic_*` tools, and `/m2c` prints the proxy's address, the scan directory, the UI link and the scan's counters.

The proxy it starts has the repeater on, so the model can resend a recorded request (`traffic_replay`) and get the
diff against the original. That sends a real request to the target. The extension's configuration
(`M2C_BRIDGE`, `M2C_DATA`, `M2C_BIN`, `M2C_LISTEN`, `M2C_API_LISTEN`, `M2C_REPEATER`) is in
`integrations/pi/README.md`.

## What is recorded

**Tables in database `m2c`:**

| Table | One row per |
|---|---|
| `http_flows` | HTTP flow: identity, timings, TLS (SNI, version, ALPN), method/URL, headers and trailers in wire order, bodies (decoded, capped at 1 MiB, full size kept), status, error and error kind, SSE/WebSocket summary, gRPC service, method, status and message counts |
| `sse_events` | SSE event of a streamed response, written as it arrives (`ms_since_req` of the first event is the time to first token) |
| `ws_messages` | WebSocket message, either direction, text or binary |
| `grpc_messages` | gRPC message, either direction, in call order: size, compression, the message bytes (decompressed) |
| `proxy_events` | `auth_challenge`, `auth_rejected`, `connect_error` (a CONNECT whose upstream could not be reached), `tls_failed_client` (a client that doesn't trust the CA or pins certificates), `tls_failed_server`, `sse_parse_stopped` (SSE parsing of a flow stopped early; the reason is in `message`), `tcp_tunnel` (a tunnel that isn't HTTP: who, where, bytes each way; see gRPC below), `grpc_framing_stopped`, `health` counters, `started`/`stopped` |

**Streaming stays streaming.**
- SSE, ndjson, gRPC, chunked bodies and bodies over 1 MiB pass straight through.
- The recorder tees them, keeps the first `m2c_body_cap` bytes, counts the rest and parses SSE events on the way.
- A failure in that code never breaks the client's connection.

**WebSocket messages are not kept in memory.** Long sockets stay flat.

### gRPC

gRPC over TLS goes through the proxy like any HTTPS client:
- **Pointing clients at the proxy:** set `grpc_proxy` or `https_proxy`, or the `grpc.http_proxy` channel option, with the credentials in the URL.
- **Trusting the proxy's CA:** gRPC ignores `SSL_CERT_FILE`, so `m2c env` also sets `GRPC_DEFAULT_SSL_ROOTS_FILE_PATH`.

Every call is one `http_flows` row with `grpc = true`.
- **Service and method:** `grpc_service` and `grpc_method`.
- **Status:**
  - `grpc_status` and `grpc_message` come from the trailers, from a trailers-only response or from a gRPC-Web trailer frame.
  - Without any of those, the status is inferred from how the call ended: a client cancel at its `grpc-timeout` is DEADLINE_EXCEEDED.
  - `grpc_status_source` says which, and `-1` means no status.
  - A call that didn't end OK counts as a failure in `sessions`, `has:error` and the UI, even though its HTTP status is 200.
- **Messages:** each message in either direction is a `grpc_messages` row, written as it streams.
  - The `seq` numbering keeps the order of a bidirectional call.
  - Compressed messages (`grpc-encoding` gzip, deflate or zstd) are decompressed.
  - Each message keeps up to `m2c_grpc_msg_cap` (256 KiB) and its full size.
- **Decoding:** protobuf is decoded when you read a call, with mitmproxy's decoder, not while recording.
  - Fields are numbered unless the proxy has a `.proto` file: `m2c proxy --proto api.proto`, or `m2c grpc N --proto api.proto`.
  - Recording never pays for decoding, and a `.proto` added later applies to old scans too.

**Variants:** gRPC-Web (binary and `-text`) is split the same way. The Connect protocol is recorded as plain
streamed bodies.

**Plaintext gRPC (h2c) is not recorded as calls.** mitmproxy forwards plaintext HTTP/2 inside a tunnel as raw TCP.
m2c records such a tunnel as a `tcp_tunnel` event with a warning (`reason = h2c`), so it shows up, but its calls
don't. Use TLS for traffic you want recorded.

### HTTP/3

HTTP/3 runs over QUIC, which is UDP. An HTTP or SOCKS5 proxy carries only TCP, and mitmproxy supports neither SOCKS5
UDP nor CONNECT-UDP, so clients that use m2c as their proxy speak HTTP/1.1 or HTTP/2 and are recorded completely.
HTTP/3 only appears when a client bypasses the proxy, the same gap as any tool that ignores its proxy settings.

Capturing it would need a mode that intercepts UDP, such as one WireGuard listener per session. That isn't
built yet.

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
session:run42 tool:nuclei|ffuf call:c7 host:*.acme.test method:POST status:5xx|404|>=400 path:/api/*
ct:json ua:curl has:sse|ws|grpc|error|fail|body err:timeout after:10m before:2026-10-21T12:00 n:100-200
grpc:demo.v1.Demo/* gstatus:!0|INVALID_ARGUMENT|14 scheme:http dur:>2s size:>1m
hdr:authorization hdr:x-api-key=*abc* rhdr:set-cookie label:vuln|todo note:"token reuse" has:note
body:"needle" -status:404 -(tool:ffuf status:404) "free text in the URL"
```

- Terms are ANDed, and `|` ORs the values of one term.
- `-` negates a term, and `-( … )` negates a group of terms together: `-(tool:ffuf status:404)` hides ffuf's 404s and nothing else.
- `dur:` (duration) and `size:` (response body) take `>`, `<`, `>=`, `<=` or `=`; a bare value means "at least". Units are ms/s/m/h, and k/m/g (1024-based).
- `hdr:` and `rhdr:` match a request or response header by name, or by `name=value`; both parts take globs.

`n:` takes `42` or `100-200` (decimal digits). Out-of-range numbers and times are rejected with HTTP 400.

Two words for things going wrong, used the same way everywhere:
- **error** (`has:error`, `errors` in the scan stats): a transport error, a 5xx, or a gRPC call that did not end OK.
- **failure** (`has:fail`, `failures` in sessions and stats, red in the UI): an error or a 4xx.

`transport_errors` in the stats counts only flows with no usable response. `GET /v1/filter-help` lists every key
with an example; the MCP tool descriptions and the UI are built from the same list.

**Suggestions** (`/v1/suggest`, `traffic_suggest`) come from aggregates over the flows a query matches:
- noise to hide: a tool and status pair, a status, a host or a tool making up 40% or more of at least 20 flows, e.g. `-(tool:ffuf status:404)`;
- failures (`has:fail`) and their main error kind (`err:timeout`);
- credentials sent over plain HTTP (`scheme:http hdr:authorization|cookie|…`);
- the slow tail (`dur:>2.3s`);
- a session that makes up most of the traffic;
- flows still open.

A hint never repeats a term the query already has. Facets and suggestions are cached for 5 seconds per token.

### CLI

| Command | What it does |
|---|---|
| `m2c ls [query] [-n 50] [--cursor N]` | flows, newest last |
| `m2c tail [query]` | live: long-lived flows when they start, every flow when it ends |
| `m2c show N [--body\|--req-body] [--max B]` | one flow; `--body` writes the raw response body to stdout |
| `m2c sessions [query]` | per session and tool: flows, failures, hosts, bytes |
| `m2c resend N [-X METHOD] [--url U] [-H 'Name: value'] [--drop-header NAME] [-d BODY]` | resend a recorded request, edited or not (`m2c proxy --repeater`) |
| `m2c timeline [session]` | a session's flows grouped by the tool call that made them |
| `m2c notes [query]` | labels and notes on the flows a query matches |
| `m2c note N [-l LABEL] [--color C] [text…]`, `--edit ID`, `--delete ID` | label or note a flow (through the running proxy) |
| `m2c report [query] [--by session\|tool\|call]` | per group: flows, failures, hosts, status codes, error kinds, the slowest flows |
| `m2c grep PATTERN [query] [-E] [-s] [--side req\|resp] [--in sse\|ws]` | text in bodies (or SSE/WebSocket data), shown in context; literal unless `-E` (RE2) |
| `m2c diff A B` | what differs between two flows: request, status, headers, bodies (JSON paths or a text diff), timing |
| `m2c sse N`, `m2c ws N` | SSE events or WebSocket messages of a flow |
| `m2c grpc N [--proto F]` | the messages of a gRPC call, decoded from protobuf |
| `m2c curl N` | a curl command that replays the request. The body goes in `--data-raw` (or through stdin when binary) and the URL isn't globbed, so replaying a captured payload never reads local files. |
| `m2c har [query] > out.har` | HAR export |
| `m2c events [--kind auth_rejected]` | proxy events |
| `m2c stats` | totals and writer counters |

Every lookup command takes `--json` (JSON lines) for scripts and agents. The CLI talks to the API with the standard
library only and never loads chDB while a proxy is running.

### API

The API listens on `m2c_api_listen`, `127.0.0.1:8124` by default. Requests need `Authorization: Bearer <token>`:

- **Admin token:** in `<data>/api.json` and printed at startup; it stays the same across restarts of one data directory. It can see every session.
- **`<session>:<proxy token>`:** sees only that session, and only the proxy events that concern it.

| Endpoint | Returns |
|---|---|
| `GET /v1/scan` | totals, writer counters |
| `GET /v1/sessions?q=` | per session and tool summary |
| `GET /v1/flows?q=&limit=&cursor=&order=` | summaries, newest first, with a `next` cursor |
| `GET /v1/flows/N` | full detail (`pending: true` while a flow is still being written) |
| `GET /v1/flows/N/body/req\|resp?max=` | the body bytes. Always sent as `application/octet-stream` with a sandbox CSP; the original type is in `X-M2C-Content-Type`. |
| `GET /v1/flows/N/sse`, `/ws`, `/grpc` | events or messages, paged with `after=`; gRPC messages decoded (`decode=0` for raw only) |
| `GET /v1/flows/N/curl`, `GET /v1/har?q=` | replay command, HAR export |
| `GET /v1/tail?q=&backlog=` | **SSE stream:** `open` when a long-lived flow starts, `flow` when any flow ends, `stats` every 2 s |
| `GET /v1/flows/N/live` | **SSE stream:** the SSE events or WebSocket messages of an open flow as they happen, then `end` |
| `GET /v1/events?kind=&severity=&limit=` | proxy events, each with a `fix` (what to do); a session token sees its own and the rejected attempts that named it (`claimed`) |
| `POST /v1/flows/N/resend` | resend flow N: `{method?, url?, headers?, headers_remove?, body? \| body_base64?}` → the new flow's `n`, status, error |
| `GET /v1/timeline?session=&limit=` | a session's last flows grouped by call id; `/v1/timeline/sessions` lists the sessions that have call ids |
| `GET /v1/notes?ns=1,2,3` or `?q=` | notes on those flows, or on the flows a filter matches |
| `GET`/`POST /v1/flows/N/notes` | a flow's notes; add one: `{"label": "vuln", "color": "red", "note": "…"}` |
| `PATCH`/`DELETE /v1/notes/ID` | change or delete a note (its author, or the admin token) |
| `GET /v1/events/counts?since=` | per kind and severity: count, and `recent` (after `since`, ms) |
| `GET /v1/activity?q=&buckets=` | per session, flows and failures in equal time slices of the span the matching flows cover |
| `GET /v1/filter-help` | every filter key with an example, help text, its kind and preset values |
| `GET /v1/facets?key=&prefix=&q=&limit=` | autocomplete: the values of one key among the flows matching `q`, with counts; `path` suggests one more segment than typed |
| `GET /v1/suggest?q=` | hints for refining `q`, each with the full refined query (see below) |
| `GET /v1/report?q=&by=session\|tool\|call` | grouped summary (see `m2c report`) |
| `GET /v1/grep?pattern=&regex=&ci=&side=&in=&q=&context=` | matches with context snippets; RE2, so a pattern cannot stall the server |
| `GET /v1/diff?a=&b=&redact=` | the comparison of two flows; noisy headers (dates, request ids) are left out |
| `POST /mcp` | MCP over Streamable HTTP |
| `GET /ui/` | the web UI |

**How the live parts work.** They run from memory:
- the newest 10 000 flow summaries
- the open flows
- previews (the first 4 KiB) of the last 200 events of each open flow, at most 32 MiB for all open flows together

A flow shows up in about a millisecond, before it's even written to disk. Everything else comes from the database.
A reconnecting tail resumes from its `Last-Event-ID`.

**Queries** run on two small pools of read-only chDB sessions (`readonly=1`): one for interactive reads, one for
heavy work (HAR, reports, grep, `body:` searches). A slow query never blocks `ls` or the UI, and a session token gets a
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
  - Without `--token`, it runs as **admin**: every session. It says so on stderr.
  - `m2c mcp --session S` mints S's token from the secret and sees only S's flows. Give an agent this form.

**Tools:**
- `traffic_wait`: returns once a flow matching a filter finishes. Call it right after making a request.
  - By default it also counts flows that finished in the last 10 seconds.
  - It returns a cursor; pass it as `after` to wait for the next ones.
  - It waits on the event loop, not on a database reader, for up to 50 seconds.
- `traffic_search`: one line per flow (`format: json` for summaries, cut to `fields`); 20 by default, newest first (`order: asc` for oldest first).
- `traffic_get`: one flow in full.
  - Bodies are cut at `max_bytes`, 4 KiB by default.
  - Credential headers (Authorization, Cookie, API keys) show as `<redacted len=N sha256:…>`, so two values can still be compared. `redact: false` shows them.
  - A flow that is still running, such as a stream, comes back as `pending` with its summary.
- `traffic_replay`: resend a flow, edited or not, and get a diff against the original; listed only when the repeater is on for the caller
- `traffic_timeline`: a session's flows grouped by the tool call that made them
- `traffic_annotate`: put a label and/or a note on a flow (or delete one of yours); `traffic_get` shows a flow's notes
- `traffic_suggest`: ways to refine a filter, each with the full query (the same hints as `/v1/suggest`)
- `traffic_report` (by session, tool or call id), `traffic_grep` (body text in context), `traffic_diff` (two flows compared)
- `traffic_events`: auth rejections, TLS failures and tunnels. A session token sees its own, plus rejected attempts that named its session (`claimed`, because a rejected username proves nothing).
- `traffic_stats`, `traffic_sessions`, `traffic_sse`, `traffic_ws`, `traffic_grpc` (decoded gRPC messages), `traffic_curl`

Every tool has a title and read-only annotations. `traffic_get`, `traffic_wait` and `traffic_stats` also return
structured content.

**Resources and prompts:**
- Resources: `m2c://scan`, `m2c://flow/{n}` (a flow as JSON, without bodies), and `m2c://flow/{n}/body/{req|resp}`.
- Prompts: `investigate_failures`, `summarize_run` and `explain_flow`.

An agent given its own `<session>:<token>` can inspect its own traffic and nothing else.

**Over HTTP:**
- A body that isn't JSON gets HTTP 400 with JSON-RPC error -32700, and an empty batch gets -32600.
- A bad element in a batch only gets its own error reply.
- Batches are refused when `MCP-Protocol-Version` is 2025-06-18 or later, because the spec dropped them.
- A request with a foreign `Origin` gets 403.
- Protocol versions supported: 2025-11-25, 2025-06-18, 2025-03-26 and 2024-11-05.

```json
{"mcpServers": {"traffic": {"command": "m2c", "args": ["mcp", "--data", "/data/scan", "--session", "run42"]}}}
```

### Tool calls: the timeline

A flow's call id is the third part of its proxy username, `<session>.<tool>.<call>` (or the `x-m2c-call` header).
The timeline (`m2c timeline`, `/v1/timeline`, `traffic_timeline`, the UI's Timeline tab) groups a session's flows by
it, in order; flows without one sit between the calls.

For Claude Code, `m2c hooks claude-code` sets the call id to each Bash call's `tool_use_id`:
- **SessionStart** writes `CLAUDE_ENV_FILE`, which Claude Code runs as shell code before every Bash command. Next to
  the usual proxy variables it builds the proxy URL from a one-line local file (in `$XDG_RUNTIME_DIR/m2c/`) holding the
  current call's id. It also exports `M2C_SESSION`, `M2C_API` and a session-scoped `M2C_API_TOKEN`, so the tools
  can look up their own traffic.
- **PreToolUse** (Bash only) writes that file. It sends nothing anywhere and takes about 60 ms.

m2c records only what goes through the proxy. It never stores prompts, tool inputs, commands, tool output, or
calls that made no requests: a call exists in m2c only through its traffic. With parallel Bash calls the file holds
the latest call's id, so a flow can carry a sibling call's id.

### The repeater

Resend a recorded request, as recorded or edited: method, URL, headers, body. It is off by default:
- `m2c proxy --repeater admin`: the admin token only;
- `--repeater on`: also a session token, for its own session's flows. That is no more than the session could do through the proxy itself.

**How it works:**
- The request leaves from the proxy, through mitmproxy's own replay, with the proxy's upstream settings.
- It is recorded in the original's session as tool `repeater`, with call id and `replay_of` set to the original's number. `has:replay` finds such flows.
- Proxy credentials, `x-m2c-*` and hop-by-hop headers are never sent on. A body stored decoded is encoded again per its `Content-Encoding`.
- A request whose stored body was cut at the body cap needs its body given.
- Without a complete response within `m2c_repeater_timeout`, it is recorded as an error.

**Limits:** four at once, one per caller, 60 a minute per caller.

**Where:** the UI's Repeat tab (then *Compare*), `m2c resend`, `POST /v1/flows/N/resend`, MCP `traffic_replay`.

### Labels and notes

The one thing m2c lets its readers write. A note has a label (`vuln`, `todo`, `auth-bypass`: lower case, up to 32
characters), a color, and text, and belongs to one flow.
- **Who:** the admin token on any flow; a session token on its own session's flows, and it edits only its own notes.
  An agent can label what it found with `traffic_annotate`, and a person reviewing the run sees it in the UI.
- **Finding them:** `label:vuln`, `note:"token reuse"`, `has:note`; label values are suggested in the filter box.
- **Storage:** the `annotations` table, append-only: an edit or a delete is a new version of the same id. A note
  reads back at once, before the writer's next flush. It is pushed to central with the scan. Upgrading a central
  database: run `m2c central init` again, which adds the table.

### Web UI

Served at `/ui/` (turn it off with `--no-ui`). Open the link `m2c proxy` prints: it carries the admin token once, then
keeps it in the tab's session storage.

**Views** (tabs in the header):
- **Flows:**
  - left: sessions and tools, with flow and failure counts;
  - middle: the flow table, live; it stays fast with any number of flows, because only the rows in view are drawn;
  - right: one flow: overview (timing, identity, connection, gRPC), request, response, stream, export.
- **Timeline:** a session's flows grouped by the tool call that made them (see above), with hosts, failures and duration per call.
- **Sessions:**
  - every session with an activity strip (flows and failures over time), flows, failure rate, hosts, bytes, first and last seen;
  - expand one for its tools; the selected one gets a report on the right (status mix, per tool, hosts, slowest flows);
  - the filter box and the quick ranges (all, last hour, 15 min) narrow every number.
- **Events:**
  - what never became a flow: rejected logins, failed TLS handshakes, tunnels that aren't HTTP, health;
  - by kind and severity, each with what to do (e.g. which CA variable the tool that failed TLS reads);
  - the tab's badge counts new warnings since you last looked.
- **Compare** (`#/diff/A/B`):
  - two flows side by side: status, timing, sizes, identity, headers with credentials redacted, and bodies as JSON paths, a unified diff or side by side;
  - open it by right-clicking a flow while another is selected (*Compare with #N*), or with *Compare with…* in a flow's overview.

**Filtering while you type:**
- The filter box completes keys with their help, then the values seen among the current results, with counts.
  - `tool:` lists the tools; `path:` offers one more segment at a time.
  - Tab accepts a suggestion, Enter runs the query, Esc closes the list or reverts.
- The query is highlighted, and one the server rejects shows its message without being applied.
- Under the box, suggested refinements from the data come as one-click chips, e.g. "312 of 410 are ffuf 404s: hide them".
- Right-click any value (a cell, an overview field, a header) to filter to it, exclude it, or copy it. Alt+click filters, Alt+Shift+click excludes.
- The detail view has *More like this*, *Same call* and *Hide these*.
- The query, the selected flow and the tab are in the address (`#/flows?q=…&n=…&tab=…`): links can be shared, and Back undoes a filter.

**Notes:** the selected flow's Notes tab (or `a`) adds a label and a note; labels show as chips in the flow list.

**Bodies:** a collapsible JSON tree, text with search, a hex view for binary data, and image previews. Captured
content is only ever shown as text.

**Streams:** SSE, WebSocket and gRPC flows appear while they are still open. Selecting one streams its events live
and backfills what came before.

**Export:** a flow's request as curl, `fetch`, Python `requests`, raw HTTP or HAR; the filtered list as HAR.

**Keys:** `/` filter, `j`/`k` or arrows to move, `[`/`]` tabs, `g`/`G` first/last, `l` live on/off, `t` theme
(auto, light, dark), `?` help.

**No build step:** Preact and htm are vendored as ES modules in `src/m2c/ui/vendor/`, pinned with checksums
(`scripts/vendor_ui.py` fetches and checks them).
- The CSP allows only those files: no inline script or style, no `eval`, Trusted Types on.
- Files are revalidated on every load, so an upgraded proxy never serves a stale mix.

## Push to a central ClickHouse

```bash
export M2C_PUSH_PASSWORD=…
m2c central init --to https://m2c@ch.acme.test:8443/m2c     # create or upgrade the central schema
m2c push --to clickhouses://m2c@ch.acme.test:9440/m2c --label env=ci --label repo=foo
m2c proxy --push-on-exit https://m2c@ch.acme.test:8443/m2c  # or push automatically at shutdown
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

**Without a central server:** ship the stopped scan's directory; it opens with `clickhouse local --path <data>`, and
`m2c har` exports the flows a filter matches.

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
| `m2c_annotations` | `true` (labels and notes through the API; `false` makes them read-only) |
| `m2c_repeater` | `off`; `admin` or `on` (`m2c proxy --repeater`) |
| `m2c_repeater_timeout` | 30 s |
| `m2c_push_on_exit` | — |
| `m2c_labels` | — |
| `m2c_grpc_msg_cap`, `m2c_grpc_max_messages` | 256 KiB, 100 000 per call |
| `m2c_proto_file` | — (`m2c proxy --proto`) |

## Limits

- Agents use the proxy because they are told to. A tool that ignores the proxy settings goes out directly and is not recorded; enforcing it needs a firewall or network namespace around the agent.
- `m2c proxy` uses mitmproxy's eager connection strategy (lazy breaks HTTP/2 uploads without Content-Length to HTTP/1 servers). A CONNECT to an unreachable host gets a 502 and a `connect_error` row in `proxy_events`, not an `http_flows` row.
- WebSocket ping and pong frames are not visible.
- zstd-encoded SSE streams are stored raw and not parsed into events.
- SSE event parsing stops after a content-decoding error, or when one network chunk decodes to more than 1 MiB, so a compression bomb can't stall the proxy. The raw body is still stored and counted, and a `sse_parse_stopped` row records why.
- HTTP/3 (QUIC) isn't recorded; clients going through the proxy use HTTP/1.1 or HTTP/2 (see HTTP/3 above).
- Tunnels that aren't HTTP (plaintext HTTP/2, SSH, TLS that isn't intercepted) are only counted, as `tcp_tunnel` events. UDP and DNS are not recorded.
- Nothing may `fork()` inside the proxy process after chDB has loaded.

## Development

```bash
uv sync
uv run pytest                 # unit + integration (starts real proxies); push tests need a ClickHouse:
docker run -d --name m2c-central -p 127.0.0.1:18123:8123 -p 127.0.0.1:19000:9000 \
  -e CLICKHOUSE_USER=m2c -e CLICKHOUSE_PASSWORD=centralpw clickhouse/clickhouse-server:26.3-alpine
```

The UI tests (`tests/integration/test_ui.py`) drive a real Chromium through Playwright; they are skipped when no
browser is available (`uv run playwright install chromium`).

The design and its reasoning are in `PLAN.md`; benchmarks are in `PERFORMANCE.md` (`bench/bench.py`).

## Author

Made by Filip Nyquist <fnyquist@pm.me>.
