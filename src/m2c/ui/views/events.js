// #/events: what never became a flow (rejected logins, failed TLS handshakes, tunnels that aren't HTTP, health),
// by kind and severity, each with what to do about it. Refreshed every few seconds while it is in view.

import { getJson, qs } from "../lib/api.js";
import { clock } from "../lib/format.js";
import { html, useEffect, useState } from "../lib/html.js";
import { quoteValue } from "../lib/query.js";
import { markEventsSeen, navigate } from "../lib/state.js";

const POLL = 4000;
const LIMIT = 500;
const SEVERITIES = ["warn", "info"];
const dotClass = (e) => (e.severity === "error" || e.kind === "auth_rejected" || e.kind === "tls_failed_client" ? "dot-bad"
  : e.severity === "warn" ? "dot-warn" : e.kind === "health" || e.kind === "started" || e.kind === "stopped" ? "dot-ok" : "dot-info");
const who = (e) => (e.session ? `${e.session} / ${e.tool || "-"}` : e.proxy_user || (e.kind.startsWith("auth") ? "(no credentials)" : "proxy"));
const target = (e) => (e.host ? `${e.host}${e.port ? ":" + e.port : ""}` : e.sni || "");

/** `text` with `backticked` parts as <code>, as text nodes only. */
const codeSpans = (text) => text.split("`").map((part, i) => (i % 2 ? html`<code>${part}</code>` : part));

export function EventsView() {
  const [kind, setKind] = useState("");
  const [severity, setSeverity] = useState("");
  const [text, setText] = useState("");
  const [rows, setRows] = useState(null);
  const [counts, setCounts] = useState([]);
  const [error, setError] = useState("");
  const [selected, setSelected] = useState(null);

  useEffect(() => { markEventsSeen(); return markEventsSeen; }, []); // the badge restarts from leaving this view

  useEffect(() => {
    let stale = false, timer = null;
    const load = async () => {
      if (!document.hidden) {
        try {
          const [r, c] = await Promise.all([getJson(`/v1/events${qs({ kind, severity, limit: LIMIT })}`), getJson("/v1/events/counts")]);
          if (stale) return;
          setRows(r);
          setCounts(c);
          setError("");
        } catch (e) {
          if (!stale) setError(e.message);
        }
      }
      if (!stale) timer = setTimeout(load, POLL);
    };
    load();
    return () => { stale = true; clearTimeout(timer); };
  }, [kind, severity]);

  const byKind = {};
  for (const c of counts) byKind[c.kind] = (byKind[c.kind] || 0) + c.count;
  const bySeverity = {};
  for (const c of counts) bySeverity[c.severity] = (bySeverity[c.severity] || 0) + c.count;
  const total = Object.values(byKind).reduce((a, b) => a + b, 0);
  const needle = text.trim().toLowerCase();
  const shown = (rows || []).filter((e) => !needle || [who(e), target(e), e.message, e.reason, e.kind].join(" ").toLowerCase().includes(needle));
  const key = (e) => `${e.ts}-${e.kind}-${e.client_ip}-${e.message}`;
  const sel = shown.find((e) => key(e) === selected) || shown[0];
  const flowsOf = (e) => navigate({ view: "flows", q: `session:${quoteValue(e.session)}` + (e.tool ? ` tool:${quoteValue(e.tool)}` : ""), n: null }, true);

  return html`
    <div class="page events-page">
      <nav class="facets" aria-label="Event kinds">
        <h2>Kind</h2>
        <ul>
          ${[["", total], ...Object.entries(byKind).sort((a, b) => b[1] - a[1])].map(([k, c]) => html`
            <li><button class="facet ${kind === k ? "on" : ""}" aria-pressed=${kind === k} onClick=${() => setKind(k)}>
              <span class="dot ${k ? dotClass({ kind: k }) : "dot-info"}"></span><span class="mono grow">${k || "all"}</span><span class="muted">${c}</span></button></li>`)}
        </ul>
        <h2>Severity</h2>
        <div class="pills">${SEVERITIES.map((s) => html`<button class="pill-btn ${severity === s ? "on" : ""}" aria-pressed=${severity === s}
          onClick=${() => setSeverity(severity === s ? "" : s)}>${s} ${bySeverity[s] || 0}</button>`)}</div>
        <p class="note">Events are what never became a flow: rejected logins, failed TLS handshakes, tunnels that aren't HTTP, and the proxy's health.</p>
      </nav>

      <main class="page-main">
        <input class="search" type="search" placeholder="find in these events: build-7, npmjs, expired…" aria-label="Find in events" value=${text}
          onInput=${(e) => setText(e.target.value)} />
        ${error ? html`<div class="banner" role="alert">${error}</div>` : null}
        <section class="panel table-wrap" aria-label="Events">
          <div class="erow ehead"><span>time</span><span>kind</span><span>who</span><span>reason</span><span>target</span><span>message</span></div>
          ${rows === null ? html`<p class="note pad">Loading…</p>` : !shown.length ? html`<p class="note pad">No events${kind || severity || needle ? " match" : " yet"}.</p>` : null}
          ${shown.map((e) => html`
            <div class="erow ${sel && key(e) === key(sel) ? "sel" : ""}" onClick=${() => setSelected(key(e))} role="button" tabindex="0"
              onKeyDown=${(ev) => ev.key === "Enter" && setSelected(key(e))}>
              <span class="muted">${clock(e.ts)}</span>
              <span class="mono"><span class="dot ${dotClass(e)}"></span>${e.kind}</span>
              <span class="ellipsis">${who(e)}${e.claimed ? html` <span class="tag warn-tag" title="the username named this session, but was not proven">claimed</span>` : null}</span>
              <span class="muted ellipsis">${e.reason}</span>
              <span class="mono ellipsis">${target(e)}</span>
              <span class="muted ellipsis">${e.message}</span>
            </div>`)}
        </section>
        ${rows && rows.length >= LIMIT ? html`<p class="note">The newest ${LIMIT} are shown; pick a kind to see further back.</p>` : null}
      </main>

      ${sel ? html`
        <aside class="panel event-detail" aria-label="Selected event">
          <h2 class="mono"><span class="dot ${dotClass(sel)}"></span>${sel.kind}</h2>
          <dl class="facts">
            <dt>when</dt><dd>${clock(sel.ts)}</dd>
            <dt>who</dt><dd>${who(sel)}${sel.claimed ? " (claimed)" : ""}</dd>
            ${sel.client_ip ? html`<dt>client</dt><dd class="mono">${sel.client_ip.replace("::ffff:", "")}</dd>` : null}
            ${target(sel) ? html`<dt>server</dt><dd class="mono">${target(sel)}${sel.sni && sel.sni !== sel.host ? ` · SNI ${sel.sni}` : ""}</dd>` : null}
            ${sel.reason ? html`<dt>reason</dt><dd>${sel.reason}</dd>` : null}
            ${sel.message ? html`<dt>message</dt><dd>${sel.message}</dd>` : null}
            ${Object.keys(sel.counters || {}).length ? html`<dt>counters</dt><dd class="mono">${Object.entries(sel.counters).map(([k, v]) => `${k} ${v}`).join(" · ")}</dd>` : null}
          </dl>
          ${sel.fix ? html`<div class="fix"><b>What to do</b><p>${codeSpans(sel.fix)}</p></div>` : null}
          <div class="actions">
            ${sel.session ? html`<button class="btn" onClick=${() => flowsOf(sel)}>Flows of ${sel.session}${sel.tool ? " / " + sel.tool : ""}</button>` : null}
            <button class="btn" onClick=${() => navigator.clipboard?.writeText(JSON.stringify(sel, null, 2))}>Copy as JSON</button>
          </div>
        </aside>` : null}
    </div>`;
}
