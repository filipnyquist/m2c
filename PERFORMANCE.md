# Performance

Measured on 2026-10-22 with `bench/bench.py`. The raw numbers are in `bench/results.json`.

## Summary

| Area | Result |
|---|---|
| Recording overhead | **+0.17 ms per request** through an idle proxy (0.86 vs 0.69 ms p50). About 0.2 ms more proxy CPU per request, so a saturated proxy handles 17–20% fewer small requests (1 321 vs 1 651 req/s). |
| Completeness | **every request recorded** in every load test: 37 168 flows, 0 dropped |
| SSE streaming | events reach the client **0.3 ms** after the upstream writes them, against 0.1 ms with no proxy. Plain mitmdump holds the whole stream until it ends (about 1 s here). |
| Writer capacity | 14 500–17 000 rows/s, or 380 MB/s of bodies, on its own: **about 10× more than the proxy can deliver** |
| Live view | a flow reaches `/v1/tail` subscribers **before the client has finished reading the response** |
| Queries | **20–35 ms** for a list, **50 ms** for a flow's details and **21 ms** for a body, on a 1 M-flow scan |
| Storage | **142 bytes per flow** for LLM conversation traffic (87× compression); 355 bytes for small random bodies |
| Push to central | **1 M flows in 12 s** (native) or 14 s (HTTP); a re-push with nothing new takes 1.5 s |
| Cost | 350 MB RSS at idle against 73 MB for plain mitmdump; startup 1.6 s against 0.4 s |

For AI agents, a busy agent makes tens of requests per second, and a scanner like nuclei or ffuf at an
aggressive rate makes a few hundred. Recording is far from being the bottleneck. When the proxy is saturated, the
limit is mitmproxy's single Python event loop. m2c adds about a third to its CPU time per request.

## Setup

Software: Python 3.12.13, mitmproxy 12.2.3, chDB 26.9.0 (`chdb-core`), m2c 0.1.0. Other work was running at the
same time, so treat the numbers as ±10%.

**How it was measured:**
- Everything runs on one host over loopback, with data on a regular disk (not tmpfs).
- The upstream is an asyncio server in the benchmark process. It serves JSON bodies of a given size, SSE streams, and HTTPS with a self-signed certificate.
- The load generator is an asyncio client with keep-alive connections.
- Proxies run as separate processes. Every case runs a warm-up first.

**What was compared:**
- **direct**: client → upstream, which shows the limit of the client and upstream themselves.
- **baseline**: plain `mitmdump` with the options m2c uses (`proxyauth=any`, eager connections, `ssl_insecure`, `flow_detail=0`).
- **m2c**: `m2c proxy`, recording into chDB, with the API running.

The difference between baseline and m2c is the recorder's cost.

**Proxy CPU** is the proxy process's user and system time (`/proc/<pid>/stat`) during the timed run, divided by
the number of requests.

## 1. Proxy overhead

Throughput, latency and proxy CPU per request:

| Case | Connections | Direct | Baseline | m2c | m2c / baseline |
|---|---|---|---|---|---|
| HTTP, 200 B response | 32 | 16 274 req/s | 1 651 req/s | 1 321 req/s | 80% |
| HTTPS (intercepted), 200 B | 32 | — | 1 377 req/s | 1 145 req/s | 83% |
| HTTP, 64 KiB response | 16 | 24 059 req/s | 1 473 req/s | 1 069 req/s | 73% |
| HTTP, 4 MiB response (streamed) | 8 | 306 req/s | 205 req/s | 130 req/s | 64% |

| Case | Baseline p50 / p99 | m2c p50 / p99 | Baseline CPU/req | m2c CPU/req |
|---|---|---|---|---|
| HTTP, 200 B | 18.2 / 44.2 ms | 22.5 / 62.3 ms | 0.61 ms | 0.82 ms |
| HTTPS, 200 B | 21.3 / 50.4 ms | 25.6 / 62.9 ms | 0.73 ms | 0.94 ms |
| HTTP, 64 KiB | 10.6 / 14.3 ms | 14.0 / 27.3 ms | 0.68 ms | 1.40 ms |
| HTTP, 4 MiB | 36.6 / 63.0 ms | 59.5 / 89.1 ms | 4.9 ms | 16.7 ms |

The latencies are measured under full load with 8–32 connections in parallel, so most of each figure is time
spent queueing. One connection sending one request at a time sees this (2 000 requests, 200 B responses; the
`latency` step):

| | p50 | p95 | p99 |
|---|---|---|---|
| Direct | 0.07 ms | 0.11 ms | 0.14 ms |
| Plain mitmdump | 0.69 ms | 0.81 ms | 0.92 ms |
| m2c | 0.86 ms | 1.20 ms | 1.60 ms |

**Where the time goes.** A py-spy profile under load puts about 9% of samples in m2c code:
- 4.6% in the response hook, mostly copying headers and building the row
- 1.6% in `requestheaders` (authentication)
- 0.6% in `responseheaders`
- 2.2% in the writer thread (decoding, RowBinary encoding, spool writes)

Most of the rest is mitmproxy itself, parsing HTTP and dispatching hooks, which baseline mitmdump does as well.
Building a row, the live summary and the queue entry costs **21 µs per flow** on the event loop (section 3).

**Large bodies** cost more. m2c keeps the first `m2c_body_cap` bytes (1 MiB by default) of every body, writes them
to the spool and compresses them into chDB. At 130 responses/s of 4 MiB, that is about 130 MB/s of stored body. The
writer thread does this work, which is why m2c uses 2.2 cores there against 1.0 for baseline. A smaller body cap
lowers the cost.

**Completeness.** After every case, the number of rows in `http_flows` was compared with the number of requests
sent, warm-up included. They matched exactly: 20 992, 10 464, 5 232 and 480 rows, with nothing dropped.

**Optimizations not yet done:**
- The User-Agent guess (`ua_tool`, 23 regexes) and the header copies could move from the response hook to the writer thread.
- mitmproxy dispatches every hook an add-on defines, so dropping hooks m2c doesn't need would save a little.

## 2. Streaming (SSE)

An upstream sends 50 events, 20 ms apart. For each event, the delay is measured from the upstream writing it to the
client reading it:

| | First event after the request | Delay per event p50 | p99 |
|---|---|---|---|
| Direct | 0.2 ms | 0.12 ms | 0.23 ms |
| m2c | 3.0 ms | 0.32 ms | 0.58 ms |
| Plain mitmdump | 1 013 ms | 526 ms | 1 010 ms |

m2c passes the stream through while it parses and records each event, so recording LLM traffic doesn't change how
it streams. Plain mitmdump buffers the whole response unless `stream_large_bodies` is set, so its "first event"
arrives when the stream ends.

## 3. Ingest capacity (writer only)

These measure the writer and chDB with mitmproxy out of the way. Rows are built from a real mitmproxy flow, queued
and written through the spool into chDB on the real disk.

| Rows | Body | Rows/s | Body MB/s | Event-loop cost per flow | Largest batch |
|---|---|---|---|---|---|
| 100 000 | none | 16 916 | — | 21.3 µs | 411 ms |
| 100 000 | 2 KiB | 14 460 | 29.6 | 21.8 µs | 413 ms |
| 10 000 | 64 KiB | 5 818 | 381 | 19.1 µs | 128 ms |

Every row was stored, with nothing dropped. The writer handles ten times what the proxy produces at full speed, so
in practice the queue stays near empty. A batch that takes long, up to 0.4 s for 1 000 rows here, runs on the
writer thread and never delays traffic.

## 4. Live view

The tail latency is measured from the client receiving its response to a `/v1/tail` subscriber receiving the flow,
over 200 flows:

| p50 | p99 | Worst |
|---|---|---|
| −0.21 ms | −0.10 ms | −0.05 ms |

The summary is published from the response hook, before mitmproxy sends the response to the client. The
subscriber therefore sees every flow before the client has finished reading it. The UI and `m2c tail` show traffic
in real time, without waiting for the database.

## 5. Queries

These are API calls on a running proxy: the median of 9 runs, data in the page cache. The scans are synthetic, with
50 sessions, 6 tools, 300 hosts and bodies of 30–630 bytes.

| Query | 100 000 flows | 1 000 000 flows |
|---|---|---|
| `ls`, newest 50 | 13.9 ms | 27.0 ms |
| `ls session:run7` | 13.4 ms | 19.6 ms |
| `ls host:… method:POST` | 15.9 ms | 34.2 ms |
| `ls status:5xx tool:ffuf` | 14.1 ms | 31.9 ms |
| `ls` text in the URL | 15.8 ms | 25.1 ms |
| `ls --cursor` (a page in the middle) | 12.5 ms | 21.6 ms |
| one flow's details (`show N`) | 40.0 ms | 52.1 ms |
| one flow's body | 15.6 ms | 20.9 ms |
| `sessions` | 15.6 ms | 100.3 ms |
| `stats` | 15.6 ms | 93.0 ms |
| `body:"…"` search over all bodies | 14.9 ms | 24.5 ms |
| CLI `m2c ls` against the API, wall clock | 149 ms | 159 ms |
| CLI `m2c ls` on a stopped scan, wall clock | 389 ms | 524 ms |

**Why lists are fast.** They run in two steps. The first finds the matching `n`, reading only `n` and the filtered
columns. The second reads the summaries through the `by_n` projection's primary key.

**Why flow details are slower.** Their columns sit in 4 MiB compression blocks, which buy compression at the cost
of decompressing a whole block per lookup.

**Aggregates over the whole scan.** `sessions` and `stats` scan everything, about 0.1 s at 1 M flows.

**The CLI.** Its wall clock is mostly Python starting up. Against a running proxy, the CLI imports only urllib. On
a stopped scan it loads chDB, which adds about 0.25 s.

**Body search** is fast here because all bodies (330 MB compressed) are in the page cache and the search runs on
all cores. A one-off cold search of the same scan, startup included, took 0.54 s.

## 6. Storage

These are generated scans, measured after merging. "On disk" is the compressed size of `http_flows`; the whole
data directory adds the `by_n` projection, skip indexes and metadata.

| Corpus | Flows | Body bytes | On disk | Per flow | Compression | Whole directory |
|---|---|---|---|---|---|---|
| LLM agent conversations: every request resends the growing history, answers are new text | 50 000 | 597 MB | 7.1 MB | **142 B** | 86.8× | 21.5 MB |
| Mixed API traffic with random bytes in bodies (incompressible) | 200 000 | 68 MB | 70.9 MB | 355 B | 2.0× | 262 MB |

Agent traffic compresses very well because rows are sorted by `(session, ts)`. A session's requests sit next to
each other, and each one repeats the history of the one before, so ZSTD(3) with 1–4 MiB blocks stores the history
about once. Random bodies don't compress, so the second corpus is close to the worst case.

## 7. Push to a central ClickHouse

The 1 M-flow scan from section 5 was pushed into a ClickHouse 26.3 container on the same host (port 9000
inside the container, mapped to 19000). The bodies are
329 MB compressed.

| Transport | Time | Rows/s | Compressed MB/s | Re-push (nothing new) |
|---|---|---|---|---|
| Native (`remote()`) | 12.0 s | 83 381 | 29.6 | 1.5 s |
| HTTP (`url()`, zstd Native) | 14.2 s | 70 290 | 25.0 | 1.3 s |

The re-push compares every chunk's row count and content hash with central and sends nothing. Over a real network,
the push is bounded by the bandwidth to the server: about 330 MB for this scan.

## 8. Start, memory and footprint

| | Plain mitmdump | m2c |
|---|---|---|
| Start until it accepts connections and serves the API | 0.40 s | 1.66 s with an empty data directory, 1.56 s when reopening one |
| RSS at idle | 73 MB | 350 MB |
| RSS under load, 200 B responses | 77 MB | 386 MB (peak 456 MB) |
| RSS under load, 4 MiB responses | 295 MB (peak 474 MB) | 647 MB (peak 910 MB) |

**Memory.** About 280 MB of m2c's idle RSS is chDB's engine. `m2c_memory_limit` (2 GiB by default) caps the engine;
since `memory_worker_use_cgroup=0`, it counts this process only, not the whole cgroup.

**Startup** is chDB loading its 555 MB library, plus the schema check.

## Running it

```bash
.venv/bin/python bench/bench.py all            # about 4 minutes; writes bench/results.json
.venv/bin/python bench/bench.py all --quick    # about 1 minute, smaller sizes
.venv/bin/python bench/bench.py proxy          # one part: startup, proxy, latency, ingest, tail, storage, queries, push
```

Running one part updates its section in the existing `bench/results.json`.

The push part needs a ClickHouse server: `--central http://user:password@host:8123`, plus `--native-port` for the
native test. The defaults match the development container from the README (HTTP on 18123, native on 19000). Scratch data goes to `bench/.work/`
(gitignored, on the real disk, not tmpfs) and can be deleted afterwards.

When comparing runs, compare against the baseline column of the same run: absolute numbers depend on the hardware
and on what else is running.
