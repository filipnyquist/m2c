// #/timeline?session=: a session's flows grouped by the tool call that made them (the proxy username's call id; the
// Claude Code hooks set it to each Bash call's tool_use_id). Only proxied traffic: a call without any is not here.

import { getJson, qs } from "../lib/api.js";
import { clock, size, statusClass, statusText } from "../lib/format.js";
import { html, useEffect, useState } from "../lib/html.js";
import { quoteValue } from "../lib/query.js";
import { app, navigate } from "../lib/state.js";
import { useStore } from "../lib/store.js";

function FlowRow({ f }) {
  return html`<a class="tl-flow" href=${`#/flows?n=${f.n}`} onClick=${(e) => { e.preventDefault(); navigate({ view: "flows", n: f.n }, true); }}>
    <span class="muted">#${f.n}</span><span>${f.method}</span><span class=${statusClass(f)}>${statusText(f)}</span>
    <span class="ellipsis">${f.host}${f.path}</span><span class="num muted">${size(f.resp_body_size)}</span><span class="num muted">${f.duration_ms} ms</span></a>`;
}

function Between({ item }) {
  const [open, setOpen] = useState(false);
  return html`<div class="tl-between">
    <button class="link small" aria-expanded=${open} onClick=${() => setOpen(!open)}>${open ? "▾" : "▸"} ${item.flows.length} flow${item.flows.length > 1 ? "s" : ""} without a call id</button>
    ${open ? item.flows.map((f) => html`<${FlowRow} f=${f} />`) : null}
  </div>`;
}

export function TimelineView() {
  const routeSession = useStore(app, (s) => s.route.session);
  const side = useStore(app, (s) => s.sideVersion);
  const [sessions, setSessions] = useState(null);
  const [tl, setTl] = useState(null);
  const [error, setError] = useState("");
  const session = routeSession || sessions?.[0]?.session || "";

  useEffect(() => {
    getJson("/v1/timeline/sessions").then(setSessions, (e) => setError(e.message));
  }, [side]);
  useEffect(() => {
    if (!session) return;
    let stale = false;
    getJson(`/v1/timeline${qs({ session })}`).then((x) => !stale && setTl(x), (e) => !stale && setError(e.message));
    return () => { stale = true; };
  }, [session, side]);

  if (error) return html`<div class="page"><div class="banner" role="alert">${error}</div></div>`;
  if (sessions && !sessions.length) {
    return html`<div class="page"><section class="panel pad pick"><h2>No tool calls yet</h2>
      <p class="note">The timeline groups a session's flows by the tool call that made them: the third part of the proxy username,
        <code>&lt;session&gt;.&lt;tool&gt;.&lt;call&gt;</code>. For Claude Code, <code>m2c hooks claude-code</code> prints hooks that set it
        to each Bash call's id. Nothing but the calls' traffic is recorded.</p></section></div>`;
  }
  const calls = tl ? tl.items.filter((i) => i.kind === "call") : [];
  return html`
    <div class="page timeline-page">
      <main class="page-main">
        <div class="tl-head">
          <label>Session <select value=${session} onChange=${(e) => navigate({ session: e.target.value }, true)}>
            ${(sessions || []).map((s) => html`<option value=${s.session}>${s.session} · ${s.calls} calls · ${clock(s.last_ts)}</option>`)}
          </select></label>
          ${tl ? html`<span class="muted small">${tl.flows} flows · ${calls.length} calls</span>` : null}
          <span class="grow"></span>
          ${session ? html`<button class="btn" onClick=${() => navigate({ view: "flows", q: `session:${quoteValue(session)}`, n: null }, true)}>Flows of this session</button>` : null}
        </div>
        ${!tl ? html`<p class="note pad">Loading…</p>` : null}
        <ol class="tl">
          ${(tl?.items || []).map((item) => item.kind === "between" ? html`<li><${Between} item=${item} /></li>` : html`
            <li class="tl-call panel">
              <div class="tl-call-head">
                <span class="mono">${item.call_id}</span><span class="tag">${item.tool}</span>
                <span class="muted small">${clock(item.start_ts)} · ${Math.max(0, item.end_ts - item.start_ts)} ms</span>
                <span class="grow"></span>
                <span class="small">${item.flows.length} flow${item.flows.length > 1 ? "s" : ""}${item.failures ? html` · <span class="s-bad">${item.failures} failed</span>` : null}</span>
                <button class="link small" onClick=${() => navigate({ view: "flows", q: `session:${quoteValue(session)} call:${quoteValue(item.call_id)}`, n: null }, true)}>in the list</button>
              </div>
              <div class="muted small">${item.hosts.join(", ")}</div>
              <div class="tl-flows">${item.flows.map((f) => html`<${FlowRow} f=${f} />`)}</div>
            </li>`)}
        </ol>
      </main>
    </div>`;
}
