// SSE events, WebSocket messages and gRPC messages of one flow: paged from the database for a finished flow, and
// live (GET /v1/flows/N/live) for an open one, with the already-written ones backfilled. Items are kept in seq
// order by binary-search inserts; an in-memory preview is replaced by the full copy when it arrives.

import { getJson, qs, readSse } from "../lib/api.js";
import { insertAtAsc, size, time } from "../lib/format.js";
import { html, useEffect, useRef, useState } from "../lib/html.js";

const PAGE = 500;

export const streamKind = (f) => (f.resp_capture === "sse" ? "sse" : f.resp_capture === "websocket" ? "ws" : f.grpc ? "grpc" : null);

function pretty(data) {
  if (!/^\s*[[{]/.test(data)) return null;
  try { return JSON.stringify(JSON.parse(data), null, 2); } catch (e) { return null; }
}

function SseItem({ ev }) {
  const [open, setOpen] = useState(false);
  const p = open ? pretty(ev.data) : null;
  return html`<div class="ev" onClick=${() => setOpen(!open)}>
    <span class="at">+${ev.ms_since_req}ms</span>${ev.event ? html`<span class="tag">${ev.event}</span>` : null}
    ${p ? html`<pre>${p}</pre>` : html`<span class="ev-data">${ev.data}</span>`}
    ${ev.partial ? html`<span class="muted"> (partial)</span>` : null}${ev.truncated ? html`<span class="muted"> (truncated)</span>` : null}
  </div>`;
}

function WsItem({ m }) {
  return html`<div class="ev ${m.from_client ? "client" : "server"}">
    <span class="at">${time(m.ts)}</span><span class="dir">${m.from_client ? "→ " : "← "}</span>
    <span class="ev-data">${m.text || `<${m.size} bytes ${m.opcode}> ${(m.base64 || "").slice(0, 160)}`}</span>
  </div>`;
}

function GrpcItem({ m }) {
  const notes = [m.compressed && !m.decompressed && "compressed", m.truncated && "truncated", m.partial && "partial", m.preview && "preview",
    m.decoded_as && !["proto", "incomplete"].includes(m.decoded_as) && m.decoded_as].filter(Boolean);
  return html`<div class="ev ${m.from_client ? "client" : "server"}">
    <div><span class="at">+${m.ms_since_req}ms</span><span class="dir">${m.from_client ? "→ " : "← "}</span>#${m.dir_seq} · ${size(m.size)}${notes.length ? " · " + notes.join(", ") : ""}</div>
    <pre>${m.decoded || (m.base64 ? `base64 ${m.base64.slice(0, 600)}${m.base64.length > 600 ? "…" : ""}` : "(empty)")}</pre>
  </div>`;
}

const ITEM = { sse: (x) => html`<${SseItem} key=${x.seq} ev=${x} />`, ws: (x) => html`<${WsItem} key=${x.seq} m=${x} />`, grpc: (x) => html`<${GrpcItem} key=${x.seq} m=${x} />` };

/** Insert or replace by seq; returns a new array. */
function merge(items, add) {
  const out = items.slice();
  for (const x of add) {
    const i = insertAtAsc(out, x.seq, (y) => y.seq);
    if (out[i] && out[i].seq === x.seq) {
      if (out[i].preview && !x.preview) out[i] = x;
    } else out.splice(i, 0, x);
  }
  return out;
}

export function Stream({ n, flow, kind }) {
  const [items, setItems] = useState([]);
  const [more, setMore] = useState(false);
  const [error, setError] = useState("");
  const load = async (after) => {
    try {
      const page = await getJson(`/v1/flows/${n}/${kind}${qs({ after, limit: PAGE })}`);
      setItems((x) => merge(x, page));
      setMore(page.length === PAGE);
    } catch (e) { setError(e.message); }
  };
  useEffect(() => { setItems([]); setError(""); load(0); }, [n, kind]);
  const total = kind === "sse" ? flow.sse_event_count : kind === "ws" ? flow.ws_message_count : flow.grpc_req_messages + flow.grpc_resp_messages;
  return html`
    <h3>${kind === "sse" ? "SSE events" : kind === "ws" ? "WebSocket messages" : "gRPC messages"} <span class="muted">· ${items.length} of ${total}</span></h3>
    ${error ? html`<div class="s-bad">${error}</div>` : null}
    <div class="events">${items.map(ITEM[kind])}</div>
    ${more ? html`<button class="btn" onClick=${() => load(items[items.length - 1].seq)}>Load ${PAGE} more</button>` : null}
    ${kind === "ws" ? html`<div class="note">closed ${flow.ws_close_code} ${flow.ws_close_reason} by ${flow.ws_closed_by_client ? "client" : "server"}</div>` : null}`;
}

/** An open flow: its stream as it happens. `onEnd` runs when the flow finishes. */
export function LiveStream({ n, flow, onEnd }) {
  const kind = streamKind(flow);
  const [items, setItems] = useState([]);
  const box = useRef(null);
  useEffect(() => {
    const ctl = new AbortController();
    let backfilled = false;
    const backfill = (after = 0) => kind && getJson(`/v1/flows/${n}/${kind}${qs({ after, limit: 2000 })}`).then((rows) => setItems((x) => merge(x, rows))).catch(() => {});
    // Subscribe first, then backfill what was already written, so nothing falls between the two.
    readSse(`/v1/flows/${n}/live`, ctl.signal, (ev, item) => {
      if (ev === "open" && !backfilled) { backfilled = true; backfill(); }
      else if (ev === kind) setItems((x) => merge(x, [item]));
      else if (ev === "lost") setTimeout(() => backfill(item.after), 800); // fell behind: the writer has the gap soon
      else if (ev === "end") { ctl.abort(); setTimeout(onEnd, 300); }
    }).catch(() => {});
    return () => ctl.abort();
  }, [n]);
  useEffect(() => {
    const el = box.current?.closest(".detail");
    if (el && el.scrollHeight - el.scrollTop - el.clientHeight < 120) el.scrollTop = el.scrollHeight;
  }, [items]);
  return html`
    <h3>${kind ? `${kind === "sse" ? "SSE events" : kind === "ws" ? "WebSocket messages" : "gRPC messages"} (live)` : "The body is streaming; details when it ends"}
      <span class="muted"> · ${items.length} so far</span></h3>
    <div class="events" ref=${box}>${kind ? items.map(ITEM[kind]) : null}</div>`;
}
