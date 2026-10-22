// #/sessions: every session with its activity over time, flows, failures, hosts and bytes, its tools on expanding,
// and a report for the selected one. The filter box narrows every number (after:1h, host:…, -tool:ffuf).

import { getJson, qs } from "../lib/api.js";
import { clock, size } from "../lib/format.js";
import { html, useEffect, useState } from "../lib/html.js";
import { parse, quoteValue } from "../lib/query.js";
import { app, applyQuery, navigate } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { openMenu } from "./menu.js";

const BUCKETS = 32;
const pct = (part, whole) => (whole ? Math.round((100 * part) / whole) : 0);

function Bars({ series, max, label }) {
  return html`<div class="bars" role="img" aria-label=${label}>
    ${(series || []).map(([c, f]) => {
      const h = max && c ? Math.max(2, Math.round(28 * Math.sqrt(c / max))) : 0, bad = c ? Math.round((h * f) / c) : 0; // sqrt: one burst can't flatten the rest
      return html`<span class="bar" title=${`${c} flows, ${f} failed`}><span class="bar-bad" style=${{ height: bad + "px" }}></span><span class="bar-ok" style=${{ height: h - bad + "px" }}></span></span>`;
    })}
  </div>`;
}

function Split({ ok, bad }) {
  const total = ok + bad;
  return html`<span class="split" aria-hidden="true"><span class="split-ok" style=${{ width: pct(ok, total) + "%" }}></span><span class="split-bad" style=${{ width: pct(bad, total) + "%" }}></span></span>`;
}

function useData(q, side) {
  const [data, setData] = useState({ groups: null, tools: [], activity: null, error: "" });
  useEffect(() => {
    let stale = false;
    Promise.all([getJson(`/v1/report${qs({ q, by: "session", limit: 500 })}`), getJson(`/v1/sessions${qs({ q })}`), getJson(`/v1/activity${qs({ q, buckets: BUCKETS })}`)])
      .then(([report, tools, activity]) => !stale && setData({ groups: report.groups, more: report.more, tools, activity, error: "" }))
      .catch((e) => !stale && setData((d) => ({ ...d, error: e.message })));
    return () => { stale = true; };
  }, [q, side]);
  return data;
}

function Report({ session, q }) {
  const [rep, setRep] = useState(null);
  const scoped = `${q} session:${quoteValue(session)}`.trim();
  useEffect(() => {
    let stale = false;
    setRep(null);
    getJson(`/v1/report${qs({ q: scoped, by: "tool" })}`).then((r) => !stale && setRep(r), () => !stale && setRep({ groups: [] }));
    return () => { stale = true; };
  }, [scoped]);
  if (!rep) return html`<aside class="panel report"><h2>${session}</h2><p class="note">Loading…</p></aside>`;
  const g = rep.groups;
  const flows = g.reduce((a, t) => a + t.flows, 0), failures = g.reduce((a, t) => a + t.failures, 0);
  const statuses = {}, hosts = {}, errors = {};
  for (const t of g) {
    for (const [s, c] of Object.entries(t.statuses)) statuses[s] = (statuses[s] || 0) + c;
    for (const [h, c] of t.hosts) hosts[h] = (hosts[h] || 0) + c;
    for (const [k, c] of Object.entries(t.error_kinds)) errors[k] = (errors[k] || 0) + c;
  }
  const slowest = g.flatMap((t) => t.slowest).sort((a, b) => b.duration_ms - a.duration_ms).slice(0, 5);
  const first = Math.min(...g.map((t) => t.first_ts)), last = Math.max(...g.map((t) => t.last_ts));
  const statusRows = Object.entries(statuses).sort((a, b) => b[1] - a[1]);
  const statusClass = (s) => (+s >= 500 ? "s-bad" : +s >= 400 ? "s-warn" : +s >= 300 ? "s-muted" : "s-ok");
  return html`
    <aside class="panel report" aria-label=${`Report for ${session}`}>
      <div class="report-head"><h2>${session}</h2><span class="muted small">${clock(first)} → ${clock(last)}</span></div>
      <div class="actions">
        <button class="btn on" onClick=${() => navigate({ view: "flows", q: scoped, n: null }, true)}>Show flows</button>
        <button class="btn" onClick=${() => navigate({ view: "flows", q: `${scoped} has:fail`, n: null }, true)}>Only failures</button>
      </div>
      <p class="small">${flows} flows · <span class=${failures ? "s-bad" : ""}>${failures} failed</span> · up ${size(g.reduce((a, t) => a + t.bytes_up, 0))} · down ${size(g.reduce((a, t) => a + t.bytes_down, 0))}</p>
      <h3>Status</h3>
      <div class="stack" role="img" aria-label=${statusRows.map(([s, c]) => `${s}: ${c}`).join(", ")}>
        ${statusRows.map(([s, c]) => html`<span class="stack-${statusClass(s)}" style=${{ width: pct(c, flows) + "%" }}></span>`)}
      </div>
      <div class="legend">${statusRows.slice(0, 6).map(([s, c]) => html`<span><b class=${statusClass(s)}>${s}</b> × ${c}</span>`)}
        ${Object.keys(errors).length ? html`<span>errors: ${Object.entries(errors).map(([k, c]) => `${k} ${c}`).join(", ")}</span>` : html`<span class="muted">no transport errors</span>`}</div>
      <h3>By tool</h3>
      ${g.map((t) => html`<div class="tool-row" onContextMenu=${(e) => openMenu(e, [{ key: "tool", value: t.tool }])}>
        <span>${t.tool}</span><${Split} ok=${t.flows - t.failures} bad=${t.failures} /><span class="num">${t.flows}</span></div>`)}
      <h3>Hosts</h3>
      ${Object.entries(hosts).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([h, c]) => html`<div class="kv mono" onContextMenu=${(e) => openMenu(e, [{ key: "host", value: h }])}><span>${h}</span><span class="muted">${c}</span></div>`)}
      <h3>Slowest</h3>
      ${slowest.map((f) => html`<a class="kv mono" href=${`#/flows?n=${f.n}`} onClick=${(e) => { e.preventDefault(); navigate({ view: "flows", q: scoped, n: f.n }, true); }}>
        <span>#${f.n} ${f.host}${f.path}</span><span class="muted">${f.duration_ms} ms</span></a>`)}
    </aside>`;
}

export function SessionsView() {
  const q = useStore(app, (s) => s.route.q);
  const side = useStore(app, (s) => s.sideVersion);
  const live = useStore(app, (s) => s.liveStats);
  const { groups, tools, activity, error, more } = useData(q, side);
  const [selected, setSelected] = useState(null);
  const [open, setOpen] = useState(new Set());

  const keys = useStore(app, (s) => s.keys);
  if (error) return html`<div class="page"><div class="banner" role="alert">${error}</div></div>`;
  if (!groups) return html`<div class="page"><p class="note pad">Loading…</p></div>`;
  const sorted = [...groups].sort((x, y) => y.last_ts - x.last_ts); // the most recently active first
  const current = selected && groups.some((g) => g.session === selected) ? selected : sorted[0]?.session;
  const series = activity?.sessions || {};
  const max = Math.max(1, ...Object.values(series).flatMap((s) => s.map(([c]) => c)));
  const totals = groups.reduce((a, g) => ({ flows: a.flows + g.flows, failures: a.failures + g.failures, errors: a.errors + g.errors }), { flows: 0, failures: 0, errors: 0 });
  const toggle = (s) => setOpen((o) => { const n = new Set(o); n.has(s) ? n.delete(s) : n.add(s); return n; });
  const kpis = [["Sessions", groups.length, more ? "more than shown" : ""], ["Flows", totals.flows, ""],
    ["Failed", totals.failures, `${pct(totals.failures, totals.flows)}% · ${totals.errors} error${totals.errors === 1 ? "" : "s"}`, totals.failures ? "s-bad" : ""],
    ["Open", live?.open ?? 0, "streams still running"]];
  const span = activity && activity.from ? `${clock(activity.from)} → ${clock(Math.min(activity.to, Date.now()))}` : "";
  // quick ranges replace any after:/before: term at the top level of the query
  let base = q;
  try {
    for (const t of parse(q, keys).filter((n) => !n.group && (n.key === "after" || n.key === "before")).reverse()) base = base.slice(0, t.start) + base.slice(t.end);
  } catch (e) { /* the query is checked when applied */ }
  base = base.replace(/\s+/g, " ").trim();
  const ranges = [["all", ""], ["last hour", "after:1h"], ["15 min", "after:15m"]];
  const range = ranges.find(([, term]) => term && q.includes(term))?.[1] || "";
  return html`
    <div class="page sessions-page">
      <main class="page-main">
        <div class="kpis">${kpis.map(([label, value, sub, cls]) => html`<div class="kpi"><div class="kpi-label">${label}</div><div class="kpi-value ${cls || ""}">${value}</div><div class="kpi-sub">${sub}</div></div>`)}</div>
        <div class="pills" role="group" aria-label="Time range">${ranges.map(([label, term]) => html`<button class="pill-btn ${range === term ? "on" : ""}"
          aria-pressed=${range === term} onClick=${() => applyQuery(`${base} ${term}`.trim())}>${label}</button>`)}</div>
        <section class="panel table-wrap" aria-label="Sessions">
          <div class="srow shead"><span>session / tools</span><span>activity ${span ? html`<span class="muted">· ${span}</span>` : null}</span><span class="num">flows</span><span>failed</span><span class="num">hosts</span><span class="num">up / down</span><span>first</span><span>last</span></div>
          ${groups.length ? null : html`<p class="note pad">No sessions match.</p>`}
          ${sorted.map((g) => {
            const own = tools.filter((t) => t.session === g.session);
            const isOpen = open.has(g.session);
            return html`
              <div class="sgroup ${g.session === current ? "sel" : ""}">
                <div class="srow" onClick=${() => setSelected(g.session)} onDblClick=${() => navigate({ view: "flows", q: `${q} session:${quoteValue(g.session)}`.trim(), n: null }, true)}
                  onContextMenu=${(e) => openMenu(e, [{ key: "session", value: g.session }])}>
                  <span class="sname">
                    <button class="caret" aria-expanded=${isOpen} aria-label=${`${isOpen ? "Hide" : "Show"} the tools of ${g.session}`} onClick=${(e) => { e.stopPropagation(); toggle(g.session); }}>${isOpen ? "▾" : "▸"}</button>
                    <span><b>${g.session}</b><span class="chips">${own.map((t) => html`<span class="tag">${t.tool}</span>`)}</span></span>
                  </span>
                  <${Bars} series=${series[g.session]} max=${max} label=${`${g.session}: ${g.flows} flows, ${g.failures} failed`} />
                  <span class="num">${g.flows}</span>
                  <span><span class=${g.failures ? "s-bad" : "muted"}>${g.failures}</span> <span class="muted">· ${pct(g.failures, g.flows)}%</span>
                    <span class="meter"><span style=${{ width: pct(g.failures, g.flows) + "%" }}></span></span></span>
                  <span class="num">${g.host_count}</span>
                  <span class="num muted">${size(g.bytes_up)} / ${size(g.bytes_down)}</span>
                  <span class="muted">${clock(g.first_ts)}</span>
                  <span class="muted">${clock(g.last_ts)}</span>
                </div>
                ${isOpen ? own.map((t) => html`
                  <div class="srow tool" onContextMenu=${(e) => openMenu(e, [{ key: "tool", value: t.tool }])}
                    onDblClick=${() => navigate({ view: "flows", q: `${q} session:${quoteValue(g.session)} tool:${quoteValue(t.tool)}`.trim(), n: null }, true)}>
                    <span>${t.tool}</span><${Split} ok=${t.flows - t.failures} bad=${t.failures} />
                    <span class="num">${t.flows}</span><span class=${t.failures ? "s-bad" : "muted"}>${t.failures}</span><span class="num">${t.hosts}</span>
                    <span class="num muted">${size(t.bytes_up)} / ${size(t.bytes_down)}</span><span class="muted">${clock(t.first_seen)}</span><span class="muted">${clock(t.last_seen)}</span>
                  </div>`) : null}
              </div>`;
          })}
        </section>
        <p class="note">Click a session for its report, double-click to open its flows, right-click to filter. The filter box narrows every number.</p>
      </main>
      ${current ? html`<${Report} session=${current} q=${q} />` : null}
    </div>`;
}
