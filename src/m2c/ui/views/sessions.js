// Sessions and their tools, with flow and failure counts; a click filters to one.

import { html } from "../lib/html.js";
import { quoteValue } from "../lib/query.js";
import { app, applyQuery } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { openMenu } from "./menu.js";

export function Sessions() {
  const rows = useStore(app, (s) => s.sessions);
  const q = useStore(app, (s) => s.route.q);
  const by = new Map();
  for (const r of rows) {
    if (!by.has(r.session)) by.set(r.session, []);
    by.get(r.session).push(r);
  }
  const item = (query, label, flows, failures, cls, terms) => html`
    <li class="sess ${cls} ${q === query ? "on" : ""}" onClick=${() => applyQuery(query)} onContextMenu=${(e) => openMenu(e, terms)}>
      <span class="name">${label}</span>
      ${failures ? html`<span class="fail" title="failed">${failures}</span>` : null}<span class="count">${flows}</span>
    </li>`;
  return html`
    <nav class="rail" aria-label="Sessions">
      <h2>Sessions</h2>
      <ul>
        ${item("", "all", rows.reduce((a, r) => a + r.flows, 0), rows.reduce((a, r) => a + r.failures, 0), "", [])}
        ${[...by].map(([s, tools]) => html`
          ${item(`session:${quoteValue(s)}`, s, tools.reduce((a, t) => a + t.flows, 0), tools.reduce((a, t) => a + t.failures, 0), "", [{ key: "session", value: s }])}
          ${tools.map((t) => item(`session:${quoteValue(s)} tool:${quoteValue(t.tool)}`, t.tool, t.flows, t.failures, "tool", [{ key: "tool", value: t.tool }]))}`)}
      </ul>
    </nav>`;
}
