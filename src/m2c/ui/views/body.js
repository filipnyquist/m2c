// A captured body: a collapsible JSON tree, text with search, a virtual hex view, or an image preview. Bodies are
// untrusted: they are only ever rendered as text nodes (never as HTML), and images come from blob URLs that are
// revoked when the view goes away.

import { download, request } from "../lib/api.js";
import { size } from "../lib/format.js";
import { html, useEffect, useMemo, useRef, useState } from "../lib/html.js";

const MAX = 262144; // bytes fetched for display; Download gets the whole stored body
const IMAGE = /^image\/(png|jpeg|gif|webp|avif|bmp|x-icon)/;
const HEX_ROW = 18;
const ARRAY_PAGE = 200;

const cache = new Map(); // `${n}/${side}` -> Promise<{bytes, ctype}>, a few at most

export function loadBody(n, side) {
  const key = `${n}/${side}`;
  if (!cache.has(key)) {
    cache.set(key, request(`/v1/flows/${n}/body/${side}?max=${MAX}`).then(async (res) => ({
      bytes: new Uint8Array(await res.arrayBuffer()), ctype: res.headers.get("X-M2C-Content-Type") || "",
    })));
    if (cache.size > 12) cache.delete(cache.keys().next().value);
  }
  return cache.get(key).catch((e) => { cache.delete(key); throw e; });
}

function decode(bytes) {
  try { return new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch (e) { return null; }
}

function JsonNode({ k, v, depth }) {
  const [open, setOpen] = useState(depth < 2);
  const [shown, setShown] = useState(ARRAY_PAGE);
  const label = k != null ? html`<span class="j-key">${k}</span>: ` : null;
  if (v === null || typeof v !== "object") {
    const cls = v === null ? "j-null" : typeof v === "string" ? "j-str" : typeof v === "number" ? "j-num" : "j-bool";
    return html`<div class="j-row">${label}<span class=${cls}>${typeof v === "string" ? JSON.stringify(v) : String(v)}</span></div>`;
  }
  const entries = Array.isArray(v) ? v.map((x, i) => [i, x]) : Object.entries(v);
  const brackets = Array.isArray(v) ? ["[", "]"] : ["{", "}"];
  if (!entries.length) return html`<div class="j-row">${label}${brackets.join("")}</div>`;
  return html`
    <div class="j-row">
      <button class="j-toggle" aria-expanded=${open} onClick=${() => setOpen(!open)}>${open ? "▾" : "▸"}</button>${label}${brackets[0]}
      ${open ? null : html`<span class="j-more" onClick=${() => setOpen(true)}> ${entries.length} ${Array.isArray(v) ? "items" : "keys"} ${brackets[1]}</span>`}
      ${open ? html`<div class="j-kids">
        ${entries.slice(0, shown).map(([ck, cv]) => html`<${JsonNode} key=${ck} k=${ck} v=${cv} depth=${depth + 1} />`)}
        ${entries.length > shown ? html`<button class="link" onClick=${() => setShown(shown + ARRAY_PAGE * 5)}>… ${entries.length - shown} more</button>` : null}
      </div>${brackets[1]}` : null}
    </div>`;
}

function Marked({ text, needle }) {
  if (!needle) return html`<pre class="body-text">${text}</pre>`;
  const parts = [];
  const low = text.toLowerCase(), want = needle.toLowerCase();
  let at = 0, count = 0;
  for (let i = low.indexOf(want); i >= 0 && count < 1000; i = low.indexOf(want, i + want.length)) {
    parts.push(text.slice(at, i), html`<mark>${text.slice(i, i + want.length)}</mark>`);
    at = i + want.length;
    count++;
  }
  parts.push(text.slice(at));
  return html`<pre class="body-text">${parts}</pre>`;
}

function Hex({ bytes }) {
  const box = useRef(null);
  const [top, setTop] = useState(0);
  const rows = Math.ceil(bytes.length / 16);
  const first = Math.max(0, Math.floor(top / HEX_ROW) - 5);
  const last = Math.min(rows, first + 60);
  const lines = [];
  for (let r = first; r < last; r++) {
    const row = bytes.subarray(r * 16, r * 16 + 16);
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(48);
    const ascii = Array.from(row, (b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : ".")).join("");
    lines.push(html`<div class="hex-row" style=${{ transform: `translateY(${r * HEX_ROW}px)` }}>${(r * 16).toString(16).padStart(8, "0")}  ${hex}  ${ascii}</div>`);
  }
  return html`<div class="hex" ref=${box} onScroll=${() => setTop(box.current.scrollTop)}>
    <div class="hex-spacer" style=${{ height: rows * HEX_ROW + "px" }}>${lines}</div></div>`;
}

function Image({ bytes, ctype }) {
  const url = useMemo(() => URL.createObjectURL(new Blob([bytes], { type: ctype.split(";")[0] })), [bytes, ctype]);
  useEffect(() => () => URL.revokeObjectURL(url), [url]);
  return html`<img class="preview" src=${url} alt="response image" />`;
}

export function Body({ n, side, flow }) {
  const stored = flow[side + "_body_stored"], wire = flow[side + "_body_size"];
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    setData(null);
    setError("");
    if (stored) loadBody(n, side).then(setData, (e) => setError(e.message));
  }, [n, side, stored]);

  const notes = [`${size(wire)} on the wire`, flow[side + "_body_decoded"] && "decoded", flow[side + "_body_truncated"] && "cut at the body cap",
    `capture ${flow[side + "_capture"]}`].filter(Boolean).join(" · ");
  return html`
    <h3>${side === "req" ? "Request" : "Response"} body <span class="muted">· ${notes}</span></h3>
    ${!stored ? html`<div class="note">No body stored.</div>`
      : error ? html`<div class="s-bad">${error}</div>`
      : !data ? html`<div class="note">Loading…</div>`
      : html`<${Loaded} key=${`${n}/${side}`} n=${n} side=${side} bytes=${data.bytes} ctype=${data.ctype} stored=${stored} />`}`;
}

function Loaded({ n, side, bytes, ctype, stored }) {
  const [mode, setMode] = useState("auto");
  const [needle, setNeedle] = useState("");
  const text = useMemo(() => decode(bytes), [bytes]);
  const json = useMemo(() => {
    if (text === null || !(/json/.test(ctype) || /^\s*[[{]/.test(text))) return undefined;
    try { return JSON.parse(text); } catch (e) { return undefined; }
  }, [text, ctype]);
  const kinds = [IMAGE.test(ctype) && "image", json !== undefined && "json", text !== null && "text", "hex"].filter(Boolean);
  const shown = mode === "auto" || !kinds.includes(mode) ? kinds[0] : mode;
  const pretty = useMemo(() => (json !== undefined ? JSON.stringify(json, null, 2) : text), [json, text]);
  return html`
    <div class="body-bar">
      ${kinds.length > 1 ? kinds.map((k) => html`<button class="btn small ${k === shown ? "on" : ""}" onClick=${() => setMode(k)}>${k}</button>`) : null}
      ${shown === "text" || shown === "json" ? html`<input class="find" placeholder="find" aria-label="Find in body" value=${needle}
        onInput=${(e) => { setNeedle(e.target.value); if (shown === "json") setMode("text"); }} />` : null}
      <span class="grow"></span>
      ${text !== null ? html`<button class="btn small" onClick=${() => navigator.clipboard?.writeText(text)}>copy</button>` : null}
      <button class="btn small" onClick=${() => download(`/v1/flows/${n}/body/${side}`, `${n}-${side}.bin`)}>download</button>
    </div>
    ${shown === "image" ? html`<${Image} bytes=${bytes} ctype=${ctype} />`
      : shown === "json" ? html`<div class="json"><${JsonNode} v=${json} depth=${0} /></div>`
      : shown === "text" ? html`<${Marked} text=${pretty} needle=${needle} />`
      : html`<${Hex} bytes=${bytes} />`}
    ${stored > bytes.length ? html`<div class="note">Showing ${size(bytes.length)} of ${size(stored)} stored; download for all of it.</div>` : null}`;
}
