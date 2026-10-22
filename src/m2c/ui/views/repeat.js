// The repeater: edit a recorded request and send it again through the proxy (POST /v1/flows/N/resend). The new
// flow is recorded in the same session, as tool "repeater", and can be compared with the original at once.

import { request } from "../lib/api.js";
import { html, useEffect, useState } from "../lib/html.js";
import { compare, navigate } from "../lib/state.js";
import { loadBody } from "./body.js";

const HIDDEN = new Set(["host", "content-length", "proxy-authorization", "proxy-connection", "connection", "keep-alive", "transfer-encoding", "te", "upgrade"]);

const headerText = (pairs) => pairs.filter(([k]) => !HIDDEN.has(k.toLowerCase()) && !k.toLowerCase().startsWith("x-m2c-")).map(([k, v]) => `${k}: ${v}`).join("\n");

function parseHeaders(text) {
  const out = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    const i = line.indexOf(":");
    if (i <= 0) throw new Error(`a header line is "Name: value": ${line.slice(0, 40)}`);
    out.push([line.slice(0, i).trim(), line.slice(i + 1).trim()]);
  }
  return out;
}

export function Repeat({ f }) {
  const [method, setMethod] = useState(f.method);
  const [url, setUrl] = useState(f.url);
  const original = headerText(f.req_headers || []);
  const [headers, setHeaders] = useState(original);
  const [body, setBody] = useState(null); // null: not loaded; {text} editable, {binary} kept as recorded
  const [bodyText, setBodyText] = useState("");
  const [sending, setSending] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!f.req_body_stored) { setBody({ text: "" }); return; }
    loadBody(f.n, "req").then(({ bytes }) => {
      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
        setBody({ text });
        setBodyText(text);
      } catch (e) { setBody({ binary: bytes.length }); }
    }, () => setBody({ binary: 0 }));
  }, [f.n]);

  const send = async () => {
    setError("");
    setResult(null);
    const overrides = {};
    try {
      if (method !== f.method) overrides.method = method.trim();
      if (url !== f.url) overrides.url = url.trim();
      if (headers !== original) overrides.headers = parseHeaders(headers);
      if (body && "text" in body && bodyText !== body.text) overrides.body = bodyText;
    } catch (e) { setError(e.message); return; }
    setSending(true);
    try {
      const res = await request(`/v1/flows/${f.n}/resend`, { method: "POST", body: JSON.stringify(overrides), headers: { "Content-Type": "application/json" } });
      setResult(await res.json());
    } catch (e) { setError(e.message); } finally { setSending(false); }
  };

  const truncated = f.req_body_truncated && !(body && "text" in body && bodyText !== body.text);
  return html`
    <div class="repeat">
      <div class="repeat-line">
        <label>Method <input class="mono" value=${method} size="8" onInput=${(e) => setMethod(e.target.value)} /></label>
        <label class="grow">URL <input class="mono" value=${url} onInput=${(e) => setUrl(e.target.value)} /></label>
      </div>
      <label>Headers <span class="muted">(Host and Content-Length are set from the URL and body; proxy credentials are never sent)</span>
        <textarea class="mono" rows="8" value=${headers} onInput=${(e) => setHeaders(e.target.value)}></textarea></label>
      ${!body ? html`<p class="note">Loading the body…</p>`
        : "binary" in body ? html`<p class="note">The body (${body.binary} bytes) isn't text: it is sent as recorded.</p>`
        : html`<label>Body <textarea class="mono" rows="8" value=${bodyText} onInput=${(e) => setBodyText(e.target.value)}></textarea></label>`}
      ${truncated ? html`<p class="s-warn small">The recorded body was cut at the body cap: edit it (or paste the whole body) to resend.</p>` : null}
      <div class="actions">
        <button class="btn on" disabled=${sending || truncated} onClick=${send}>${sending ? "Sending…" : "Send"}</button>
        <button class="btn" onClick=${() => { setMethod(f.method); setUrl(f.url); setHeaders(original); if (body && "text" in body) setBodyText(body.text); }}>Reset</button>
        <span class="muted small">Goes out through the proxy, to the real target, and is recorded as a new flow.</span>
      </div>
      ${error ? html`<div class="s-bad" role="alert">${error}</div>` : null}
      ${result ? html`<div class="repeat-result panel">
        <b>#${result.n}</b> <span class=${result.status >= 400 || !result.status ? "s-bad" : "s-ok"}>${result.status || "no response"} ${result.reason}</span>
        <span class="muted"> · ${result.duration_ms} ms</span>${result.error ? html` <span class="s-bad">· ${result.error}</span>` : null}
        <div class="actions"><button class="btn on" onClick=${() => compare(f.n, result.n)}>Compare with #${f.n}</button>
          <button class="btn" onClick=${() => navigate({ n: result.n, tab: "resp" })}>Open #${result.n}</button></div>
      </div>` : null}
    </div>`;
}
