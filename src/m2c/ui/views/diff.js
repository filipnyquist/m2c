// #/diff/A/B: what differs between two flows (GET /v1/diff): status, timing, sizes, identity, headers (noisy ones
// counted, not listed; credentials redacted unless asked), and bodies as JSON paths, a unified diff or side by side.

import { getJson, qs } from "../lib/api.js";
import { size, statusClass, statusText, time, who } from "../lib/format.js";
import { html, useEffect, useState } from "../lib/html.js";
import { app, compare, navigate } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { loadBody } from "./body.js";

function decodePretty(bytes) {
  let text;
  try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (e) { return `<${bytes.length} bytes of binary data>`; }
  try { return JSON.stringify(JSON.parse(text), null, 2); } catch (e) { return text; }
}

function Card({ label, f, cls }) {
  if (!f) return html`<div class="panel flow-card ${cls}"><b>${label}</b><span class="note">Loading…</span></div>`;
  return html`<div class="panel flow-card ${cls}">
    <div class="card-head"><b>${label} · #${f.n}</b><a href=${`#/flows?n=${f.n}`} onClick=${(e) => { e.preventDefault(); navigate({ view: "flows", n: f.n }, true); }}>open</a></div>
    <div class="mono small ellipsis" title=${f.url}>${f.method} ${f.url}</div>
    <div class="small">${who(f)} · <span class=${statusClass(f)}>${statusText(f)} ${f.reason || ""}</span> · ${f.duration_ms} ms · ${size(f.resp_body_size)} · ${time(f.ts)}</div>
  </div>`;
}

function Headers({ h }) {
  if (!h) return html`<p class="note">Headers are the same.</p>`;
  const rows = [];
  for (const [name, vals] of Object.entries(h.removed || {})) rows.push(html`<div class="dl dl-del"><b>−</b> ${name}: ${vals.join(", ")}</div>`);
  for (const [name, vals] of Object.entries(h.added || {})) rows.push(html`<div class="dl dl-add"><b>+</b> ${name}: ${vals.join(", ")}</div>`);
  for (const [name, [a, b]] of Object.entries(h.changed || {})) rows.push(html`<div class="dl dl-chg"><b>~</b> ${name}: ${a.join(", ")} <span class="muted">→</span> ${b.join(", ")}</div>`);
  return html`<div class="dlines">${rows}</div>
    ${h.ignored ? html`<p class="note">${h.ignored === 1 ? "1 header that differs" : `${h.ignored} headers that differ`} on every response (dates, request ids, cookies…) not listed.</p>` : null}`;
}

function Body({ body, side, a, b }) {
  const modes = [body.json && ["paths", "JSON paths"], body.unified !== undefined && ["unified", "Unified"], !body.sha256 && ["sides", "Side by side"]].filter(Boolean);
  const [mode, setMode] = useState(modes[0]?.[0] || "");
  const [sides, setSides] = useState(null);
  useEffect(() => {
    if (mode !== "sides" || sides) return;
    Promise.all([loadBody(a, side).catch(() => null), loadBody(b, side).catch(() => null)])
      .then(([x, y]) => setSides([x ? decodePretty(x.bytes) : "(no body)", y ? decodePretty(y.bytes) : "(no body)"]));
  }, [mode]);
  return html`
    <div class="body-head"><h3>Body <span class="muted">· ${body.bytes ? body.bytes.join(" → ") + " bytes" : ""}</span></h3>
      <div class="seg" role="tablist" aria-label="Body comparison">${modes.map(([k, label]) => html`<button role="tab" aria-selected=${mode === k}
        class="btn small ${mode === k ? "on" : ""}" onClick=${() => setMode(k)}>${label}</button>`)}</div></div>
    ${body.note ? html`<p class="note">${body.note}</p>` : null}
    ${body.sha256 ? html`<p class="note">Binary bodies differ: sha256 ${body.sha256[0]}… → ${body.sha256[1]}…</p>` : null}
    ${mode === "paths" ? html`<div class="paths"><div class="prow phead"><span>JSON path</span><span>A</span><span>B</span></div>
      ${body.json.map((p) => html`<div class="prow mono"><span class="q-key">${p.path}</span>
        <span class=${"a" in p ? "s-bad" : "muted"}>${"a" in p ? JSON.stringify(p.a) : "(absent)"}</span>
        <span class=${"b" in p ? "s-ok" : "muted"}>${"b" in p ? JSON.stringify(p.b) : "(absent)"}</span></div>`)}</div>` : null}
    ${mode === "unified" ? html`<pre class="body-text">${(body.unified || "").split("\n").map((l) => html`<span class="uline ${l.startsWith("+") && !l.startsWith("+++") ? "s-ok" : l.startsWith("-") && !l.startsWith("---") ? "s-bad" : ""}">${l || " "}</span>`)}</pre>` : null}
    ${mode === "sides" ? (sides ? html`<div class="sides"><pre class="body-text">${sides[0]}</pre><pre class="body-text">${sides[1]}</pre></div>` : html`<p class="note">Loading…</p>`) : null}
    ${body.cut ? html`<p class="note">${body.cut}</p>` : null}`;
}

function Section({ title, part, side, a, b, extra }) {
  return html`<section class="panel diff-part" aria-label=${title}>
    <h2>${title}</h2>
    ${extra}
    <${Headers} h=${part?.headers} />
    ${part?.body ? html`<${Body} key=${`${a}-${b}-${side}`} body=${part.body} side=${side} a=${a} b=${b} />` : html`<p class="note">Bodies are the same.</p>`}
  </section>`;
}

function Pick() {
  const [a, setA] = useState("");
  const [b, setB] = useState("");
  const go = () => /^\d+$/.test(a) && /^\d+$/.test(b) && compare(+a, +b);
  return html`<div class="page"><section class="panel pad pick">
    <h2>Compare two flows</h2>
    <p class="note">Right-click a flow in the list and choose <b>Compare with #N (selected)</b>, use <b>Compare with…</b> in a flow's overview, or give two flow numbers:</p>
    <div class="actions"><label>A <input class="num-input" inputmode="numeric" value=${a} onInput=${(e) => setA(e.target.value.trim())} /></label>
      <label>B <input class="num-input" inputmode="numeric" value=${b} onInput=${(e) => setB(e.target.value.trim())} onKeyDown=${(e) => e.key === "Enter" && go()} /></label>
      <button class="btn on" onClick=${go}>Compare</button></div>
  </section></div>`;
}

export function DiffView() {
  const a = useStore(app, (s) => s.route.a);
  const b = useStore(app, (s) => s.route.b);
  const [redact, setRedact] = useState(true);
  const [d, setD] = useState(null);
  const [flows, setFlows] = useState([null, null]);
  const [error, setError] = useState("");

  useEffect(() => {
    if (a == null || b == null) return;
    let stale = false;
    setD(null);
    setError("");
    getJson(`/v1/diff${qs({ a, b, redact: redact ? 1 : 0 })}`).then((x) => !stale && setD(x), (e) => !stale && setError(e.message));
    Promise.all([getJson(`/v1/flows/${a}`), getJson(`/v1/flows/${b}`)]).then((x) => !stale && setFlows(x), () => {});
    return () => { stale = true; };
  }, [a, b, redact]);

  if (a == null || b == null) return html`<${Pick} />`;
  const chips = [];
  if (d) {
    const r = d.response || {}, q = d.request || {}, t = d.sizes_and_timing || {};
    if (r.status) chips.push(["bad", html`status <b>${r.status[0]} → ${r.status[1]}</b>`]);
    if (r.error) chips.push(["bad", html`error ${r.error[0] || "none"} → ${r.error[1] || "none"}`]);
    if (r.grpc_status) chips.push(["bad", html`gRPC status ${r.grpc_status[0]} → ${r.grpc_status[1]}`]);
    if (q.method) chips.push(["", html`method ${q.method[0]} → ${q.method[1]}`]);
    if (t.duration_ms) chips.push(["", html`duration ${t.duration_ms.a} → ${t.duration_ms.b} ms <span class=${t.duration_ms.delta > 0 ? "s-warn" : "s-ok"}>(${t.duration_ms.delta > 0 ? "+" : ""}${t.duration_ms.delta})</span>`]);
    if (t.resp_body_size) chips.push(["", html`response ${size(t.resp_body_size.a)} → ${size(t.resp_body_size.b)}`]);
    for (const [k, [x, y]] of Object.entries(d.identity || {})) chips.push(["", html`${k} ${x || "-"} → ${y || "-"}`]);
  }
  return html`
    <div class="page diff-page">
      <section class="pair" aria-label="The two flows">
        <${Card} label="A" f=${flows[0]} cls="card-a" />
        <button class="swap" aria-label="Swap A and B" title="Swap A and B" onClick=${() => compare(b, a)}>⇄</button>
        <${Card} label="B" f=${flows[1]} cls="card-b" />
      </section>
      ${error ? html`<div class="banner" role="alert">${error}</div>` : null}
      ${!d && !error ? html`<p class="note pad">Comparing…</p>` : null}
      ${d ? html`
        <section class="chips" aria-label="Summary">
          ${d.same ? html`<span class="chip">Same request and response, as far as m2c compares them.</span>` : chips.map(([cls, c]) => html`<span class="chip ${cls}">${c}</span>`)}
          <span class="grow"></span>
          <label class="small"><input type="checkbox" checked=${redact} onChange=${(e) => setRedact(e.target.checked)} /> redact credentials</label>
        </section>
        <div class="diff-grid">
          <${Section} title="Request" part=${d.request} side="req" a=${a} b=${b}
            extra=${d.request?.url ? html`<div class="dlines"><div class="dl dl-chg"><b>~</b> url: ${d.request.url[0]} <span class="muted">→</span> ${d.request.url[1]}</div></div>` : html`<p class="note">Method and URL are the same.</p>`} />
          <${Section} title="Response" part=${d.response} side="resp" a=${a} b=${b} extra=${null} />
        </div>` : null}
    </div>`;
}
