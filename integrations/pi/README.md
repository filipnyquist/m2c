# m2c for pi

Record every HTTP request your pi session's tools make, and give the model the recorded
traffic back.

This is the pi integration of [m2c](https://github.com/filipnyquist/m2c), the recording
proxy that writes every flow it sees into an embedded ClickHouse. It lives in the m2c
repository, so the extension and the proxy it drives are versioned together.

## Install

```bash
pi install git:github.com/filipnyquist/m2c
```

That installs the extension and the `m2c-traffic` skill from this repository's root
package. From a clone of the repository, the package in this directory works on its own:

```bash
pi install ./integrations/pi
```

The extension needs the m2c CLI on `PATH`:

```bash
uv tool install git+https://github.com/filipnyquist/m2c
```

## What it does

1. **On session start** it starts a recording proxy for the session (or attaches to one
   that is already running for the same scan directory) and registers m2c's MCP server,
   scoped to this session.
2. **Every bash command** runs with the proxy in its environment, so the requests it makes
   are recorded. Each command's requests carry the tool call's id, which is what m2c's
   timeline groups by.
3. **The model reads the traffic back** through the MCP tools: `traffic_wait` right after
   a request, `traffic_get` for one flow in full, `traffic_search` for the rest, and
   `traffic_diff`, `traffic_grep`, `traffic_replay` and the rest one search away.

The web UI comes with it: `/m2c` prints the UI link (with its token), the proxy's
address, the scan directory and the scan's counters.

**The repeater is on.** `traffic_replay` resends a recorded request through the proxy,
edited or not, and returns the diff against the original. It sends real requests to the
target, so the model can change one header and see what the server answers.

## Configuration

| Variable | Meaning |
|---|---|
| `M2C_BRIDGE` | `off` disables the extension, `manual` only attaches to a proxy that is already running |
| `M2C_DATA` | the scan directory (default: `<agent-dir>/m2c/<session id>`) |
| `M2C_BIN` | the m2c executable (default: `m2c` on `PATH`) |
| `M2C_LISTEN` | the proxy's listen address (default: a free port on `127.0.0.1`) |
| `M2C_API_LISTEN` | the API's listen address (default: a free port on `127.0.0.1`) |
| `M2C_REPEATER` | `off`, `admin` or `on` (default: `on`): who may resend recorded requests |

The proxy's own output goes to `<data>/proxy.log`; `/m2c` shows the tail of it.

## What is not recorded

- The model's own LLM traffic never goes through the proxy.
- Only traffic is recorded: no prompts, no commands, no tool inputs. A call shows up in
  the timeline through the requests it made.
- A tool that ignores the proxy settings goes out directly and is not recorded.
