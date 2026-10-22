// A context menu for "filter to / exclude / copy" on any value. Open it with openMenu(event, terms).

import { html, useEffect } from "../lib/html.js";
import { app, refine } from "../lib/state.js";
import { useStore } from "../lib/store.js";

/** terms: [{key, value, label?}]; also `extra`: [{label, action}] */
export function openMenu(e, terms, extra = []) {
  e.preventDefault();
  const items = [];
  for (const t of terms) {
    const shown = t.label || `${t.key}:${t.value}`;
    items.push({ label: html`Filter to <code>${shown}</code>`, action: () => refine(t.key, t.value, false) });
    items.push({ label: html`Exclude <code>-${shown}</code>`, action: () => refine(t.key, t.value, true) });
  }
  if (terms.length) items.push({ sep: true });
  for (const t of terms) items.push({ label: html`Copy <code>${String(t.value).slice(0, 60)}</code>`, action: () => navigator.clipboard?.writeText(String(t.value)) });
  for (const x of extra) items.push(x);
  app.set({ menu: { x: e.clientX, y: e.clientY, items } });
}

/** Alt+click adds the first term, Alt+Shift+click excludes it; true when it handled the click. */
export function altClick(e, terms) {
  if (!e.altKey || !terms.length) return false;
  e.preventDefault();
  e.stopPropagation();
  refine(terms[0].key, terms[0].value, e.shiftKey);
  return true;
}

export function Menu() {
  const menu = useStore(app, (s) => s.menu);
  useEffect(() => {
    if (!menu) return;
    const close = () => app.set({ menu: null });
    const key = (e) => e.key === "Escape" && close();
    window.addEventListener("click", close);
    window.addEventListener("blur", close);
    window.addEventListener("keydown", key);
    window.addEventListener("scroll", close, true);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("blur", close);
      window.removeEventListener("keydown", key);
      window.removeEventListener("scroll", close, true);
    };
  }, [menu]);
  if (!menu) return null;
  const x = Math.min(menu.x, window.innerWidth - 300), y = Math.min(menu.y, window.innerHeight - 30 * menu.items.length - 10);
  return html`
    <ul class="menu" role="menu" style=${{ left: x + "px", top: Math.max(4, y) + "px" }}>
      ${menu.items.map((it) => it.sep ? html`<li class="menu-sep" role="separator"></li>`
        : html`<li role="menuitem" tabindex="-1" onClick=${() => { app.set({ menu: null }); it.action(); }}>${it.label}</li>`)}
    </ul>`;
}
