// Keyboard shortcuts and the filter language, from GET /v1/filter-help.

import { html } from "../lib/html.js";
import { app } from "../lib/state.js";
import { useStore } from "../lib/store.js";

const KEYS = [["/", "focus the filter"], ["Tab", "accept a suggestion"], ["Enter", "apply the filter"], ["Esc", "close, revert, deselect"],
  ["j / k, ↓ / ↑", "next / previous flow"], ["g / G", "first / last loaded flow"], ["[ / ]", "previous / next tab"], ["l", "live on or off"],
  ["a", "label or note the selected flow"], ["t", "theme"], ["Alt+click", "filter to a value"], ["Alt+Shift+click", "exclude a value"], ["right-click", "filter, exclude or copy"], ["?", "this help"]];

export function Help() {
  const help = useStore(app, (s) => s.help);
  const close = () => app.set({ showHelp: false });
  return html`
    <div class="overlay" onClick=${close}>
      <div class="dialog" role="dialog" aria-modal="true" aria-label="Help" onClick=${(e) => e.stopPropagation()}>
        <button class="btn close" onClick=${close}>close</button>
        <h2>Keys</h2>
        <dl class="facts">${KEYS.map(([k, v]) => html`<dt><kbd>${k}</kbd></dt><dd>${v}</dd>`)}</dl>
        <h2>Filter language</h2>
        <p class="note">Terms are ANDed; <code>|</code> ORs values; <code>-</code> negates a term and <code>-( … )</code> a group; free text matches the URL.</p>
        <dl class="facts">${help.keys.map((k) => html`<dt><code>${k.example}</code></dt><dd>${k.help}${k.live ? "" : html` <span class="muted">(not in the live tail's fast path)</span>`}</dd>`)}</dl>
      </div>
    </div>`;
}
