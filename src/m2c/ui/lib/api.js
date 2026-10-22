// The live API: bearer token, JSON and SSE over fetch (EventSource cannot send an Authorization header).

const KEY = "m2c-token";
let token = "";
const unauthorized = new Set();

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

/** The token from `#token=…` (then removed from the address bar) or from this tab's session storage. */
export function loadToken() {
  const m = location.hash.match(/[#&]token=([^&]+)/);
  if (m) {
    setToken(decodeURIComponent(m[1]));
    const rest = location.hash.replace(/[#&]?token=[^&]+/, "").replace(/^#&?/, "#");
    history.replaceState(null, "", location.pathname + location.search + (rest.length > 1 ? rest : "#/flows"));
    return token;
  }
  try { token = sessionStorage.getItem(KEY) || ""; } catch (e) { /* storage blocked: memory only */ }
  return token;
}

export function setToken(t) {
  token = t || "";
  try { if (token) sessionStorage.setItem(KEY, token); else sessionStorage.removeItem(KEY); } catch (e) { /* see above */ }
}

export const hasToken = () => !!token;
export const onUnauthorized = (fn) => { unauthorized.add(fn); return () => unauthorized.delete(fn); };

export function qs(params) {
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== null && v !== "") p.set(k, v);
  const s = p.toString();
  return s ? "?" + s : "";
}

export async function request(path, { signal, method, body, headers } = {}) {
  const res = await fetch(path, { signal, method, body, headers: { Authorization: "Bearer " + token, ...(headers || {}) } });
  if (res.ok) return res;
  let message = String(res.status);
  try { message = (await res.json()).error || message; } catch (e) { /* not JSON */ }
  if (res.status === 401) unauthorized.forEach((fn) => fn(message));
  throw new ApiError(res.status, message);
}

export const getJson = async (path, opts) => (await request(path, opts)).json();
export const getText = async (path, opts) => (await request(path, opts)).text();

/** Read a text/event-stream; `onEvent(kind, data, id)` per event. Resolves when the server ends the stream. */
export async function readSse(path, signal, onEvent) {
  const res = await request(path, { signal });
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buf += dec.decode(value, { stream: true });
    let i;
    while ((i = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, i);
      buf = buf.slice(i + 2);
      let kind = "message", id = null;
      const data = [];
      for (const line of block.split("\n")) {
        if (line.startsWith("event:")) kind = line.slice(6).trim();
        else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        else if (line.startsWith("id:")) id = line.slice(3).trim();
      }
      if (data.length) onEvent(kind, JSON.parse(data.join("\n")), id);
    }
  }
}

/** Download `path` as a file; the blob URL is revoked right after the click. */
export async function download(path, name) {
  const blob = await (await request(path)).blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
