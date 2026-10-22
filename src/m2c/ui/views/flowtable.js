// The flow list: a virtual table (only the rows in view are in the DOM, so 20 000 flows cost the same as 20). New
// flows appear on top while the list is scrolled to the top; scrolled down, the rows in view stay put and a pill
// counts what arrived above. Right-click a cell (or Alt+click) to filter by its value.

import { html, useEffect, useLayoutEffect, useRef, useState } from "../lib/html.js";
import { pathOnly, size, statusClass, statusText, statusTitle, time } from "../lib/format.js";
import { app, compare, feed, select } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { altClick, openMenu } from "./menu.js";
import { Label, useNotesFor } from "./notes.js";

export const ROW_H = 24;
const OVERSCAN = 10;

/** The filter terms a cell offers. */
export function termsFor(f, col) {
  const out = [];
  if (col === "n") out.push({ key: "n", value: f.n });
  if (col === "who") {
    out.push({ key: "session", value: f.session }, { key: "tool", value: f.tool });
    if (f.call_id) out.push({ key: "call", value: f.call_id });
  }
  if (col === "method") out.push({ key: "method", value: f.method });
  if (col === "status") {
    if (f.status) out.push({ key: "status", value: f.status });
    if (f.grpc && f.grpc_status >= 0) out.push({ key: "gstatus", value: f.grpc_status });
    if (f.error_kind) out.push({ key: "err", value: f.error_kind });
  }
  if (col === "url") {
    const path = pathOnly(f.path);
    out.push({ key: "host", value: f.host }, { key: "path", value: path });
    const dir = path.replace(/\/[^/]*$/, "");
    if (dir && dir !== path) out.push({ key: "path", value: dir + "/*" });
  }
  if (col === "ms" && f.duration_ms) out.push({ key: "dur", value: ">=" + f.duration_ms + "ms" });
  if (col === "size" && f.resp_body_size) out.push({ key: "size", value: ">=" + f.resp_body_size });
  return out;
}

const COLS = [["n", "#"], ["time", "time"], ["who", "session / tool"], ["method", "method"], ["status", "status"], ["url", "url"], ["size", "size"], ["ms", "ms"]];

function Cell({ f, col, children, cls = "", title = "" }) {
  const terms = () => termsFor(f, col);
  const extra = () => {
    const sel = app.get().route.n;
    return sel != null && sel !== f.n ? [{ sep: true }, { label: `Compare with #${sel} (selected)`, action: () => compare(sel, f.n) }] : [];
  };
  return html`<div role="gridcell" class="c c-${col} ${cls}" title=${title}
    onContextMenu=${(e) => openMenu(e, terms(), extra())} onClick=${(e) => altClick(e, terms())}>${children}</div>`;
}

function Row({ f, index, selected, notes }) {
  const tags = [f.resp_capture === "sse" && "sse", f.resp_capture === "websocket" && "ws", f.grpc && "grpc"].filter(Boolean);
  return html`
    <div role="row" id=${`row-${f.n}`} aria-rowindex=${index + 2} aria-selected=${selected}
      class="row ${selected ? "sel" : ""} ${f.open ? "open" : ""}" style=${{ transform: `translateY(${index * ROW_H}px)` }}
      onClick=${() => select(f.n)}>
      <${Cell} f=${f} col="n">${f.n}<//>
      <${Cell} f=${f} col="time">${time(f.ts)}<//>
      <${Cell} f=${f} col="who" title=${`${f.session} / ${f.tool}${f.call_id ? " #" + f.call_id : ""}`}>
        ${f.session} / ${f.tool}${f.call_id ? html`<span class="tag">${f.call_id}</span>` : null}<//>
      <${Cell} f=${f} col="method">${f.method}<//>
      <${Cell} f=${f} col="status" cls=${statusClass(f)} title=${statusTitle(f)}>${statusText(f)}<//>
      <${Cell} f=${f} col="url" title=${f.url || f.host + f.path}>${(notes || []).map((x) => html`<${Label} note=${x} />`)}${tags.map((t) => html`<span class="tag">${t}</span>`)}${f.host}${f.path}<//>
      <${Cell} f=${f} col="size">${size(f.resp_body_size)}<//>
      <${Cell} f=${f} col="ms">${f.open ? "" : f.duration_ms}<//>
    </div>`;
}

export function FlowTable() {
  useStore(app, (s) => s.version);
  const selected = useStore(app, (s) => s.route.n);
  const query = useStore(app, (s) => s.route.q);
  const status = useStore(app, (s) => s.feedStatus);
  const box = useRef(null);
  const [view, setView] = useState({ top: 0, height: 600 });
  const anchor = useRef(null);
  const [above, setAbove] = useState(0);
  const list = feed.list;
  const total = list.size;

  useEffect(() => {
    const el = box.current;
    const ro = new ResizeObserver(() => setView((v) => ({ ...v, height: el.clientHeight })));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Keep the rows in view where they are when flows arrive above them: the anchor is the top row of the last
  // render; if it moved down, scroll by as much.
  useLayoutEffect(() => {
    const el = box.current, a = anchor.current;
    if (!el) return;
    if (a && el.scrollTop > 0) {
      const i = list.indexOf(a.n);
      if (i > a.index) {
        el.scrollTop += (i - a.index) * ROW_H;
        setAbove((x) => x + i - a.index);
      }
    }
    const t = Math.min(Math.floor(el.scrollTop / ROW_H), total - 1);
    anchor.current = total && el.scrollTop > 0 ? { n: list.order[t], index: t } : null;
  });

  useEffect(() => {
    if (box.current) box.current.scrollTop = 0;
    setAbove(0);
  }, [query]);

  // The selected row stays in view (keyboard navigation, deep links).
  useEffect(() => {
    const el = box.current;
    if (!el || selected == null) return;
    const i = list.indexOf(selected);
    if (i < 0) return;
    if (i * ROW_H < el.scrollTop) el.scrollTop = i * ROW_H;
    else if ((i + 1) * ROW_H > el.scrollTop + el.clientHeight) el.scrollTop = (i + 1) * ROW_H - el.clientHeight;
  }, [selected]);

  const onScroll = () => {
    const el = box.current;
    setView({ top: el.scrollTop, height: el.clientHeight });
    if (el.scrollTop === 0) setAbove(0);
    if (el.scrollTop + el.clientHeight > total * ROW_H - 8 * ROW_H) feed.loadOlder();
  };

  const first = Math.max(0, Math.floor(view.top / ROW_H) - OVERSCAN);
  const last = Math.min(total, Math.ceil((view.top + view.height) / ROW_H) + OVERSCAN);
  const notes = useNotesFor(list.order.slice(first, last));
  const rows = [];
  for (let i = first; i < last; i++) {
    const f = list.get(list.order[i]);
    if (f) rows.push(html`<${Row} key=${f.n} f=${f} index=${i} selected=${f.n === selected} notes=${notes[f.n]} />`);
  }
  const foot = status === "loading" ? "Loading…" : !total ? "No flows match." : list.capped ? `Showing the newest ${total} flows: narrow the filter to see older ones.`
    : list.hasOlder ? "Loading older…" : `${total} flows`;
  return html`
    <section class="flows" role="grid" aria-label="Flows" aria-rowcount=${total + 1} aria-activedescendant=${selected != null ? `row-${selected}` : undefined}>
      <div role="row" class="row head" aria-rowindex="1">${COLS.map(([c, label]) => html`<div role="columnheader" class="c c-${c}">${label}</div>`)}</div>
      <div class="vbody" ref=${box} onScroll=${onScroll} tabindex="0">
        <div class="spacer" style=${{ height: total * ROW_H + "px" }}>${rows}</div>
        <div class="foot">${foot}</div>
      </div>
      ${above > 0 ? html`<button class="pill" onClick=${() => { box.current.scrollTop = 0; setAbove(0); }}>↑ ${above} new</button>` : null}
    </section>`;
}
