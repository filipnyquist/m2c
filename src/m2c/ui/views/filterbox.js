// The filter box: a combobox over the filter language. Typing a key lists keys with their help; after `key:` it
// lists the values seen among the current results, with counts (GET /v1/facets). The query is highlighted by a layer
// behind the input. Tab accepts a suggestion, Enter runs the query (or accepts one picked with the arrows), Esc
// closes the list or reverts the text. A query the server rejects shows its message and is not applied.

import { getJson, qs } from "../lib/api.js";
import { html, useEffect, useLayoutEffect, useRef, useState } from "../lib/html.js";
import { highlight, quoteValue, replaceRange, tokenAt, without } from "../lib/query.js";
import { app, applyQuery, recentQueries } from "../lib/state.js";
import { useStore } from "../lib/store.js";

const DEBOUNCE = 120;

function keyItems(text, tok, help) {
  const p = tok.prefix.toLowerCase();
  const starts = help.keys.filter((s) => s.key.startsWith(p));
  const contains = p ? help.keys.filter((s) => !s.key.startsWith(p) && s.key.includes(p)) : [];
  const items = [...starts, ...contains].map((s) => ({
    label: s.key + ":",
    detail: s.help,
    example: s.example,
    apply: () => ({ ...replaceRange(text, tok.start, tok.end, (tok.neg ? "-" : "") + s.key + ":"), reopen: true }),
  }));
  if (!text.trim()) {
    const recent = recentQueries().map((r) => ({ label: r, detail: "recent", apply: () => ({ q: r, cursor: r.length, run: true }) }));
    return [...recent.slice(0, 6), ...items];
  }
  return p && !items.length ? [] : items;
}

async function valueItems(text, cursor, tok, spec) {
  const pick = (value, deeper) => () => {
    const insert = quoteValue(value) + (deeper ? "/" : "");
    const r = replaceRange(text, tok.altStart, tok.altEnd, insert);
    if (deeper) return { ...r, reopen: true }; // drill down into the path
    const atEnd = r.q.slice(r.cursor).trim() === "" && tok.altEnd === tok.end;
    return atEnd ? { q: r.q + " ", cursor: r.cursor + 1, run: true } : { ...r, run: true };
  };
  let facet = { values: [], static: (spec.values || []).filter((v) => v.toLowerCase().includes(tok.prefix.toLowerCase())) };
  if (spec.facets) {
    const params = { key: tok.key, prefix: tok.prefix, limit: 30 };
    const context = without(text, tok.start, tok.end);
    // The rest of the query narrows the values; when it doesn't parse yet (an open group), ask without it.
    facet = await getJson(`/v1/facets${qs({ ...params, q: context })}`).catch(() => getJson(`/v1/facets${qs(params)}`)).catch(() => facet);
  }
  const seen = new Set();
  const items = [];
  for (const v of facet.values) {
    seen.add(v.value);
    items.push({ label: v.value + (v.deeper ? "/…" : ""), count: v.count, apply: pick(v.value, v.deeper) });
  }
  for (const v of facet.static) if (!seen.has(v)) items.push({ label: v, detail: "preset", apply: pick(v, false) });
  if (!items.length) items.push({ label: spec.example, detail: spec.help, disabled: true });
  return items;
}

export function FilterBox() {
  const applied = useStore(app, (s) => s.route.q);
  const help = useStore(app, (s) => s.help);
  const keys = useStore(app, (s) => s.keys);
  const byKey = useStore(app, (s) => s.byKey);
  const [text, setText] = useState(applied);
  const [items, setItems] = useState([]);
  const [open, setOpen] = useState(false);
  const [active, setActive] = useState(-1);
  const [error, setError] = useState("");
  const input = useRef(null);
  const layer = useRef(null);
  const seq = useRef(0);
  const timer = useRef(null);
  const caret = useRef(null);
  const shownFor = useRef(null); // the text the shown suggestions were computed for

  // A query applied from elsewhere (a hint, a menu, Back) replaces the text. One this box applied leaves it alone:
  // the user may have typed on while it was checked.
  const ours = useRef(null);
  useEffect(() => {
    if (ours.current !== null && ours.current === applied.trim()) ours.current = null;
    else setText(applied);
    setError("");
  }, [applied]);

  useLayoutEffect(() => {
    if (caret.current != null && input.current) {
      input.current.setSelectionRange(caret.current, caret.current);
      caret.current = null;
    }
    syncScroll();
  });

  function syncScroll() {
    if (layer.current && input.current) layer.current.style.transform = `translateX(${-input.current.scrollLeft}px)`;
  }

  async function compute(value, cursor) {
    const tok = tokenAt(value, cursor, keys);
    if (tok.mode === "key") return keyItems(value, tok, help);
    if (tok.mode === "value" && byKey[tok.key]) return valueItems(value, cursor, tok, byKey[tok.key]);
    return [];
  }

  /** Suggestions for value/cursor, after DEBOUNCE ms unless `now`; resolves to the list (or null if superseded). */
  function suggest(value, cursor, now = false) {
    clearTimeout(timer.current);
    const id = ++seq.current;
    const run = async () => {
      const next = await compute(value, cursor);
      if (id !== seq.current) return null; // a newer keystroke won
      shownFor.current = value;
      setItems(next);
      setActive(-1);
      setOpen(next.length > 0);
      return next;
    };
    if (now) return run();
    timer.current = setTimeout(run, DEBOUNCE);
    return null;
  }

  async function runQuery(q) {
    setOpen(false);
    seq.current++;
    ours.current = q.trim() === applied.trim() ? null : q.trim(); // the same query again changes no route
    const err = await applyQuery(q);
    if (err) ours.current = null;
    setError(err);
  }

  function accept(item) {
    if (!item || item.disabled) return;
    const r = item.apply();
    setText(r.q);
    caret.current = r.cursor;
    if (r.run) runQuery(r.q);
    else if (r.reopen) suggest(r.q, r.cursor, true);
    else setOpen(false);
  }

  function onKeyDown(e) {
    if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (!open) return suggest(text, input.current.selectionStart, true);
      const step = e.key === "ArrowDown" ? 1 : -1;
      setActive((a) => (a + step + items.length) % items.length);
    } else if (e.key === "Tab" && open && items.length) {
      e.preventDefault();
      if (shownFor.current === text) accept(items[active >= 0 ? active : 0]);
      else suggest(text, input.current.selectionStart, true).then((fresh) => fresh && fresh.length && accept(fresh[0])); // typed faster than the debounce
    } else if (e.key === "Enter") {
      e.preventDefault();
      if (open && active >= 0) accept(items[active]);
      else runQuery(text);
    } else if (e.key === "Escape") {
      e.stopPropagation();
      if (open) setOpen(false);
      else if (text !== applied) { setText(applied); setError(""); }
      else input.current.blur();
    } else if (e.key === " " && e.ctrlKey) {
      e.preventDefault();
      suggest(text, input.current.selectionStart, true);
    }
  }

  const dirty = text.trim() !== applied.trim();
  const segments = highlight(text, keys);
  return html`
    <div class="filter ${error ? "has-error" : ""}">
      <div class="filter-field">
        <div class="filter-layer" aria-hidden="true" ref=${layer}>${segments.map((s) => html`<span class=${s.cls}>${s.text}</span>`)}</div>
        <input id="q" ref=${input} value=${text} spellcheck="false" autocomplete="off" role="combobox" aria-label="Filter"
          aria-expanded=${open} aria-controls="q-list" aria-autocomplete="list" aria-activedescendant=${open && active >= 0 ? `q-opt-${active}` : undefined}
          placeholder="filter: tool:curl status:5xx host:*.acme.test -(tool:ffuf status:404)   ( / to focus, ? for help )"
          onInput=${(e) => { setText(e.target.value); setError(""); suggest(e.target.value, e.target.selectionStart); }}
          onKeyDown=${onKeyDown} onScroll=${syncScroll} onSelect=${syncScroll}
          onFocus=${(e) => suggest(e.target.value, e.target.selectionStart, true)}
          onClick=${(e) => suggest(e.target.value, e.target.selectionStart)}
          onBlur=${() => setTimeout(() => setOpen(false), 120)} />
        ${dirty && !open ? html`<span class="filter-hint">↵ apply · esc revert</span>` : null}
      </div>
      ${error ? html`<div class="filter-error" role="alert">${error}</div>` : null}
      ${open ? html`
        <ul class="suggest" id="q-list" role="listbox">
          ${items.map((it, i) => html`
            <li id=${`q-opt-${i}`} role="option" aria-selected=${i === active} class="${i === active ? "active" : ""} ${it.disabled ? "disabled" : ""}"
              onMouseDown=${(e) => { e.preventDefault(); accept(it); }} onMouseEnter=${() => setActive(i)}>
              <span class="s-label">${it.label}</span>
              ${it.count != null ? html`<span class="s-count">${it.count}</span>` : null}
              ${it.detail ? html`<span class="s-detail">${it.detail}${it.example && it.example !== it.label ? html` · <code>${it.example}</code>` : null}</span>` : null}
            </li>`)}
        </ul>` : null}
    </div>`;
}

const ICON = { narrow: "↘", exclude: "⊘", info: "ℹ" };

/** Suggested refinements of the applied query (GET /v1/suggest), refreshed when it changes or flows finish. */
export function Hints() {
  const q = useStore(app, (s) => s.route.q);
  const side = useStore(app, (s) => s.sideVersion);
  const [hints, setHints] = useState([]);
  const last = useRef({ q: null, at: 0 });

  useEffect(() => {
    const now = Date.now();
    if (last.current.q === q && (now - last.current.at < 10000 || document.hidden)) return;
    last.current = { q, at: now };
    let stale = false;
    getJson(`/v1/suggest${qs({ q })}`).then((r) => !stale && setHints(r.hints)).catch(() => !stale && setHints([]));
    return () => { stale = true; };
  }, [q, side]);

  if (!hints.length) return null;
  return html`
    <div class="hints" aria-label="Suggested filters">
      ${hints.map((h) => h.query
        ? html`<button class="hint hint-${h.kind}" title=${h.query} onClick=${() => applyQuery(h.query)}><span class="hint-icon">${ICON[h.kind]}</span>${h.text}</button>`
        : html`<span class="hint hint-info"><span class="hint-icon">${ICON.info}</span>${h.text}</span>`)}
    </div>`;
}
