---
name: m2c-traffic
description: Read and analyze the HTTP traffic this session produced, through the m2c recording proxy. Use when a request was made with curl, a script, or another tool and you need the exact request and response (bodies, headers, status, timing, SSE events, WebSocket messages, gRPC calls), want to compare two requests, replay one, or find the requests that failed. The m2c MCP tools are traffic_search, traffic_get, traffic_wait, traffic_events, traffic_report, traffic_curl.
---

# Recorded traffic (m2c)

Every HTTP request a tool in this session makes goes through the m2c recording proxy, so
the request and the response are recorded with their bodies, headers, timings and the
identity of the caller.

The traffic tools are MCP tools named `traffic_*` (`mcp__m2c__traffic_*`).

## The loop

1. Make the request with the tool that fits the job (`curl`, a script, `nuclei`, …).
2. `traffic_wait` — returns once a matching flow finishes. Call it right after the
   request; it waits on the event loop, not on a database read.
3. `traffic_get` — one flow in full: method, URL, status, timings, headers, body.

`traffic_search` lists flows one line each when you do not know the flow number, and
`traffic_report` groups them by session, tool or call. `traffic_timeline` groups a
session's flows by the tool call that made them: every bash command in this session has
an id, so "which call sent this" is one call away.

## Reading a flow

- Bodies are cut at 4 KiB by default; raise `max_bytes` when you need more.
- Credential headers (`Authorization`, `Cookie`, API keys) come back as
  `<redacted len=N sha256:…>`: two values can still be compared, but not read. Ask for
  `redact: false` only when the value itself is the point.
- A flow that is still running (a stream) comes back as `pending`.

## Filters

The same filter language is used by every tool:

```
session:run42 tool:curl method:POST status:5xx host:*.acme.test path:/api/*
has:sse|ws|grpc|error|fail body:"needle" hdr:authorization dur:>2s size:>1m
```

Terms are ANDed, `|` ORs the values of one term, `-` negates, and `-( … )` negates a
group. `traffic_suggest` proposes refinements from the data itself.

## What is worth knowing

- **Two words, two meanings.** `error` is a transport error, a 5xx, or a gRPC call that
  did not end OK. `failure` is an error or a 4xx. `has:error` and `has:fail` filter on
  those.
- **Not every request is recorded.** A tool that ignores the proxy settings goes out
  directly. `traffic_events` shows what never became a flow: rejected logins, failed TLS
  handshakes, tunnels that are not HTTP.
- **Only traffic is recorded.** No prompts, no commands, no tool inputs. A call appears
  in the timeline only through the requests it made.
- **The proxy is not the model's own traffic.** The agent's LLM calls never go through
  it.

## Comparing and replaying

- `traffic_diff` — two flows side by side: status, timing, headers (noisy ones left
  out), bodies as JSON paths or a text diff.
- `traffic_curl` — a curl command that replays a recorded request, with the body
  inline, so it never reads local files.
- `traffic_replay` — resend a flow through the proxy and get the diff against the
  original. The repeater is on for this session, so the tool is there. It sends a real
  request to the target: use it to test one changed header, not to repeat a request the
  server already answered.
- `traffic_grep` — text in bodies, SSE events or WebSocket messages, in context.

## Outside the model

The same scan is a directory. The CLI reads it without a running proxy:

```bash
m2c ls                       # newest flows
m2c show 1                   # one flow in full
m2c har > out.har            # HAR export of what a filter matches
```

In the session, `/m2c` prints the proxy's address, the scan directory, the web UI link
(with its token) and the scan's counters.
