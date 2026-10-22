// One flow: Overview, Request, Response, Stream and Export tabs. Details are cached per flow, so switching tabs or
// coming back to a flow does not ask the server again. Values in the overview can be filtered on (right-click).

import { download, getJson, getText, qs } from "../lib/api.js";
import { pathOnly, size, statusClass, statusText, time, who } from "../lib/format.js";
import { html, useEffect, useState } from "../lib/html.js";
import { quoteValue } from "../lib/query.js";
import { app, applyQuery, compare, feed, navigate } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { Body } from "./body.js";
import { openMenu } from "./menu.js";
import { NotesTab } from "./notes.js";
import { Repeat } from "./repeat.js";
import { LiveStream, Stream, streamKind } from "./stream.js";

const LRU = 50;
const details = new Map(); // n -> finished flow detail

async function loadFlow(n) {
  if (details.has(n)) {
    const f = details.get(n);
    details.delete(n);
    details.set(n, f); // most recently used last
    return f;
  }
  const f = await getJson(`/v1/flows/${n}`);
  if (!f.pending) {
    details.set(n, f);
    if (details.size > LRU) details.delete(details.keys().next().value);
  }
  return f;
}

function tabsFor(f, repeater) {
  const tabs = [["overview", "Overview"], ["req", "Request"], ["resp", "Response"], ["split", "Split"]];
  const kind = streamKind(f);
  if (kind) tabs.push(["stream", kind === "sse" ? `SSE (${f.sse_event_count})` : kind === "ws" ? `WebSocket (${f.ws_message_count})` : `gRPC (${f.grpc_req_messages + f.grpc_resp_messages})`]);
  tabs.push(["notes", "Notes"], ["export", "Export"]);
  if (repeater && f.resp_capture !== "websocket") tabs.push(["repeat", "Repeat"]);
  return tabs;
}

function Value({ k, v, label }) {
  if (v === "" || v == null) return html`<span class="muted">-</span>`;
  return html`<span class="val" onContextMenu=${(e) => openMenu(e, [{ key: k, value: v }])} title="right-click to filter">${label ?? v}</span>`;
}

function Headers({ title, pairs }) {
  if (!pairs || !pairs.length) return null;
  return html`<h3>${title} <span class="muted">· ${pairs.length}</span></h3>
    <div class="hdrs">${pairs.map(([k, v]) => html`<div onContextMenu=${(e) => openMenu(e, [{ key: title.startsWith("Request") ? "hdr" : "rhdr", value: k.toLowerCase(), label: k.toLowerCase() }])}>
      <b>${k}</b>: ${v}</div>`)}</div>`;
}

function Timing({ f }) {
  const total = Math.max(f.duration_ms, 1);
  const ttfb = Math.min(f.ttfb_ms || 0, total);
  return html`<div class="timing" title=${`first byte after ${f.ttfb_ms} ms, done after ${f.duration_ms} ms`}>
    <span class="t-wait" style=${{ width: (100 * ttfb) / total + "%" }}></span><span class="t-recv" style=${{ width: (100 * (total - ttfb)) / total + "%" }}></span>
  </div><div class="muted small">waiting ${f.ttfb_ms} ms · receiving ${Math.max(0, f.duration_ms - f.ttfb_ms)} ms · total ${f.duration_ms} ms</div>`;
}

function similar(f) {
  const path = pathOnly(f.path);
  const dir = path.replace(/\/[^/]*$/, "") || "";
  return { more: `host:${quoteValue(f.host)} method:${f.method}` + (dir ? ` path:${quoteValue(dir + "/*")}` : ""),
    call: `session:${quoteValue(f.session)} ` + (f.call_id ? `call:${quoteValue(f.call_id)}` : `tool:${quoteValue(f.tool)}`),
    hide: `-(host:${quoteValue(f.host)}${dir ? ` path:${quoteValue(dir + "/*")}` : ""})` };
}

function CompareWith({ n }) {
  const [open, setOpen] = useState(false);
  const [other, setOther] = useState("");
  // the newest earlier flow to the same host and path is the usual thing to compare with
  const prev = feed.list.order.map((m) => feed.list.get(m)).find((x) => x && x.n < n && !x.open && x.host === feed.list.get(n)?.host
    && pathOnly(x.path) === pathOnly(feed.list.get(n)?.path));
  if (!open) return html`<button class="btn" onClick=${() => { setOpen(true); setOther(prev ? String(prev.n) : ""); }}>Compare with…</button>`;
  const go = () => /^\d+$/.test(other) && +other !== n && compare(+other, n);
  return html`<span class="compare-with"><label>flow # <input class="num-input" inputmode="numeric" value=${other} autofocus
    onInput=${(e) => setOther(e.target.value.trim())} onKeyDown=${(e) => (e.key === "Enter" ? go() : e.key === "Escape" && setOpen(false))} /></label>
    <button class="btn on" onClick=${go}>Compare</button></span>`;
}

function Overview({ f }) {
  const q = useStore(app, (s) => s.route.q);
  const s = similar(f);
  const rows = [
    ["Identity", html`<${Value} k="session" v=${f.session} /> / <${Value} k="tool" v=${f.tool} />${f.call_id ? html` #<${Value} k="call" v=${f.call_id} />` : null}
      ${f.tag ? html` · tag <${Value} k="tag" v=${f.tag} />` : null} · via <${Value} k="source" v=${f.identity_source} />
      ${f.ua_tool ? html` · user agent <${Value} k="ua" v=${f.ua_tool} />` : null}`],
    ["Request", html`${f.method} <${Value} k="host" v=${f.host} /><${Value} k="path" v=${pathOnly(f.path)} label=${f.path} /> · ${f.http_version} · body ${size(f.req_body_size)}`],
    ["Response", html`<span class=${statusClass(f)}>${f.status} ${f.reason}</span> · <${Value} k="ct" v=${(f.resp_content_type || "").split(";")[0]} /> · body ${size(f.resp_body_size)} · ${f.resp_capture}`],
    ["Connection", html`client ${f.client_ip.replace("::ffff:", "")}:${f.client_port} → server ${(f.server_ip || "").replace("::ffff:", "")}:${f.server_port}
      · ${f.tls ? `${f.tls_version} · SNI ${f.sni || "-"} · ALPN ${f.alpn || "-"}` : html`<${Value} k="scheme" v=${f.scheme || "http"} label="plain HTTP" />`}`],
    ["Time", `${time(f.ts)} → ${time(f.ts_end)}` + (f.end_reason ? ` · ended: ${f.end_reason}` : "")],
  ];
  if (f.grpc) rows.push(["gRPC", html`<${Value} k="grpc" v=${`${f.grpc_service}/${f.grpc_method}`} /> · status ${f.grpc_status === -1 ? "none"
    : html`<span class=${f.grpc_status ? "s-bad" : "s-ok"}>${f.grpc_status_name} (${f.grpc_status})</span>`}${f.grpc_status_source === "inferred" ? " inferred" : ""}
    ${f.grpc_message ? ` · ${f.grpc_message}` : ""} · ${f.grpc_req_messages} → ${f.grpc_resp_messages} messages`]);
  if (f.resp_capture === "websocket") rows.push(["WebSocket", `closed ${f.ws_close_code} ${f.ws_close_reason} by ${f.ws_closed_by_client ? "client" : "server"}`]);
  if (f.is_replay) rows.push(["Replay", "this flow was sent by the proxy (a replay)"]);
  return html`
    <${Timing} f=${f} />
    <dl class="facts">${rows.map(([k, v]) => html`<dt>${k}</dt><dd>${v}</dd>`)}</dl>
    <div class="actions">
      <button class="btn" title=${s.more} onClick=${() => applyQuery(s.more)}>More like this</button>
      <button class="btn" title=${s.call} onClick=${() => applyQuery(s.call)}>${f.call_id ? "Same call" : "Same tool"}</button>
      <button class="btn" title=${`${q} ${s.hide}`.trim()} onClick=${() => applyQuery(`${q} ${s.hide}`.trim())}>Hide these</button>
      <${CompareWith} n=${f.n} />
    </div>`;
}

const FORMATS = ["curl", "fetch", "python", "raw", "har"];

function Export({ n }) {
  const [fmt, setFmt] = useState("curl");
  const [text, setText] = useState("");
  useEffect(() => {
    setText("");
    getText(`/v1/flows/${n}/export${qs({ format: fmt })}`).then(setText, (e) => setText("error: " + e.message));
  }, [n, fmt]);
  return html`
    <div class="body-bar">${FORMATS.map((f) => html`<button class="btn small ${f === fmt ? "on" : ""}" onClick=${() => setFmt(f)}>${f}</button>`)}
      <span class="grow"></span>
      <button class="btn small" onClick=${() => navigator.clipboard?.writeText(text)}>copy</button>
      <button class="btn small" onClick=${() => download(`/v1/flows/${n}/export${qs({ format: fmt })}`, `${n}.${fmt === "har" ? "har" : fmt === "python" ? "py" : fmt === "fetch" ? "js" : "txt"}`)}>download</button>
    </div>
    <pre class="body-text">${text || "…"}</pre>
    <div class="note">Proxy credentials are never included. The request goes straight to the server, not through m2c.</div>`;
}

export function Detail() {
  const n = useStore(app, (s) => s.route.n);
  const tab = useStore(app, (s) => s.route.tab);
  const repeater = useStore(app, (s) => !!s.scan?.repeater);
  const [f, setF] = useState(null);
  const [error, setError] = useState("");
  const [reload, setReload] = useState(0);

  useEffect(() => {
    if (n == null) return;
    let stale = false, timer = null;
    setError("");
    const get = () => loadFlow(n).then((x) => {
      if (stale) return;
      setF(x);
      if (x.pending && !x.open) timer = setTimeout(get, 400); // finished, not written yet
    }, (e) => !stale && setError(e.message));
    get();
    return () => { stale = true; clearTimeout(timer); };
  }, [n, reload]);

  useEffect(() => {
    const keys = (e) => {
      if (!f || e.target.closest?.("input, textarea, select") || (e.key !== "[" && e.key !== "]")) return;
      const tabs = tabsFor(f, repeater).map(([k]) => k);
      const i = Math.max(0, tabs.indexOf(tab || "overview"));
      navigate({ tab: tabs[(i + (e.key === "]" ? 1 : tabs.length - 1)) % tabs.length] });
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  }, [f, tab, repeater]);

  if (n == null) return html`<section class="detail empty"><p>Select a flow.</p><p class="muted">j / k move · / filter · ? help</p></section>`;
  if (error) return html`<section class="detail"><div class="s-bad pad">${error}</div></section>`;
  if (!f || f.n !== n) return html`<section class="detail"><div class="note pad">Loading #${n}…</div></section>`;
  const title = html`<div class="title">#${f.n} ${f.method} ${f.url}</div>`;
  if (f.pending && f.open) {
    return html`<section class="detail">${title}
      <div class="meta"><span class="s-open">running</span> <span>${who(f)}</span> <span>${time(f.ts)}</span></div>
      <${LiveStream} n=${n} flow=${f} onEnd=${() => setReload((x) => x + 1)} /></section>`;
  }
  if (f.pending) return html`<section class="detail">${title}<div class="note pad">Still being written…</div></section>`;
  const tabs = tabsFor(f, repeater);
  const current = tabs.some(([k]) => k === tab) ? tab : "overview";
  return html`
    <section class="detail">
      ${title}
      <div class="meta">
        <span class=${statusClass(f)}>${statusText(f)} ${f.reason}</span><span>${f.duration_ms} ms</span><span>${who(f)}</span><span>${time(f.ts)}</span>
      </div>
      ${f.error ? html`<div class="s-bad">error (${f.error_kind}): ${f.error}</div>` : null}
      <div class="tabs" role="tablist">
        ${tabs.map(([k, label]) => html`<button role="tab" aria-selected=${k === current} class="tab ${k === current ? "on" : ""}" onClick=${() => navigate({ tab: k })}>${label}</button>`)}
      </div>
      <div role="tabpanel">
        ${current === "overview" ? html`<${Overview} f=${f} />` : null}
        ${current === "req" ? html`<${Headers} title="Request headers" pairs=${f.req_headers} /><${Headers} title="Request trailers" pairs=${f.req_trailers} /><${Body} n=${n} side="req" flow=${f} />` : null}
        ${current === "resp" ? html`<${Headers} title="Response headers" pairs=${f.resp_headers} /><${Headers} title="Response trailers" pairs=${f.resp_trailers} /><${Body} n=${n} side="resp" flow=${f} />` : null}
        ${current === "split" ? html`<div class="split-view">
          <div><${Headers} title="Request headers" pairs=${f.req_headers} /><${Body} n=${n} side="req" flow=${f} /></div>
          <div><${Headers} title="Response headers" pairs=${f.resp_headers} /><${Body} n=${n} side="resp" flow=${f} /></div>
        </div>` : null}
        ${current === "stream" ? html`<${Stream} n=${n} flow=${f} kind=${streamKind(f)} />` : null}
        ${current === "notes" ? html`<${NotesTab} n=${n} autofocus=${true} />` : null}
        ${current === "repeat" ? html`<${Repeat} key=${n} f=${f} />` : null}
        ${current === "export" ? html`<${Export} n=${n} />` : null}
      </div>
    </section>`;
}
