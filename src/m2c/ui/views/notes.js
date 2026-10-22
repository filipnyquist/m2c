// Labels and notes on flows: the Notes tab of a flow, and the label chips the flow table shows. Saved through the
// API (the admin token anywhere, a session token on its own flows); the filter language finds them again:
// label:vuln, note:"text", has:note.

import { getJson, qs, request } from "../lib/api.js";
import { clock } from "../lib/format.js";
import { html, useEffect, useRef, useState } from "../lib/html.js";
import { app, applyQuery } from "../lib/state.js";
import { useStore } from "../lib/store.js";

export const COLORS = ["", "red", "orange", "yellow", "green", "blue", "purple", "gray"];
const WINDOW_MS = 250;

async function send(method, path, body) {
  const res = await request(path, { method, body: body === undefined ? undefined : JSON.stringify(body), headers: { "Content-Type": "application/json" } });
  return res.status === 204 ? null : res.json();
}

/** After a write: the table's chips and the counts reload. */
function changed() {
  app.set({ notesVersion: app.get().notesVersion + 1 });
}

export function Label({ note, onClick }) {
  if (!note.label) return html`<span class="nlabel nlabel-text" title=${note.note}>✎</span>`;
  return html`<span class="nlabel ${note.color ? "nc-" + note.color : ""}" title=${note.note || note.label}
    onClick=${onClick}>${note.label}</span>`;
}

/** {n: [note]} for the flows in view, refetched when the window moves or notes change. */
export function useNotesFor(ns) {
  const version = useStore(app, (s) => s.notesVersion);
  const side = useStore(app, (s) => s.sideVersion);
  const [byN, setByN] = useState({});
  const key = ns.join(",");
  useEffect(() => {
    if (!ns.length) return;
    let stale = false;
    const timer = setTimeout(() => {
      getJson(`/v1/notes${qs({ ns: key })}`).then((notes) => {
        if (stale) return;
        const out = {};
        for (const x of notes) (out[x.n] ||= []).push(x);
        setByN(out);
      }, () => {});
    }, WINDOW_MS);
    return () => { stale = true; clearTimeout(timer); };
  }, [key, version, side]);
  return byN;
}

function Editor({ initial, labels, onSave, onCancel, autofocus }) {
  const [label, setLabel] = useState(initial?.label || "");
  const [color, setColor] = useState(initial?.color || "");
  const [text, setText] = useState(initial?.note || "");
  const [error, setError] = useState("");
  const first = useRef(null);
  useEffect(() => { if (autofocus) first.current?.focus(); }, []);
  const save = async () => {
    try {
      await onSave({ label: label.trim().toLowerCase(), color, note: text });
      if (!initial) { setLabel(""); setText(""); setColor(""); }
      setError("");
    } catch (e) { setError(e.message); }
  };
  return html`
    <div class="note-editor">
      <div class="note-row">
        <label class="grow">Label <input ref=${first} list="note-labels" value=${label} placeholder="vuln, todo, auth-bypass…" maxlength="32"
          onInput=${(e) => setLabel(e.target.value)} onKeyDown=${(e) => e.key === "Enter" && save()} /></label>
        <label>Color <select value=${color} onChange=${(e) => setColor(e.target.value)}>
          ${COLORS.map((c) => html`<option value=${c}>${c || "none"}</option>`)}</select></label>
      </div>
      <datalist id="note-labels">${labels.map((l) => html`<option value=${l} />`)}</datalist>
      <label>Note <textarea rows="3" value=${text} placeholder="what you saw, what to check next…" onInput=${(e) => setText(e.target.value)}
        onKeyDown=${(e) => e.key === "Enter" && (e.ctrlKey || e.metaKey) && save()}></textarea></label>
      ${error ? html`<div class="s-bad small" role="alert">${error}</div>` : null}
      <div class="actions"><button class="btn on" onClick=${save}>${initial ? "Save" : "Add"}</button>
        ${onCancel ? html`<button class="btn" onClick=${onCancel}>Cancel</button>` : html`<span class="muted small">Ctrl+Enter saves</span>`}</div>
    </div>`;
}

export function NotesTab({ n, autofocus }) {
  const scope = useStore(app, (s) => s.scan?.scope ?? null);
  const version = useStore(app, (s) => s.notesVersion);
  const [notes, setNotes] = useState(null);
  const [labels, setLabels] = useState([]);
  const [editing, setEditing] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    let stale = false;
    getJson(`/v1/flows/${n}/notes`).then((x) => !stale && setNotes(x), (e) => !stale && setError(e.message));
    getJson(`/v1/facets${qs({ key: "label", limit: 50 })}`).then((f) => !stale && setLabels(f.values.map((v) => v.value)), () => {});
    return () => { stale = true; };
  }, [n, version]);
  const mayEdit = (x) => scope === null || (x.author_kind === "session" && x.author === scope);
  const act = async (fn) => {
    try { await fn(); setError(""); changed(); } catch (e) { setError(e.message); }
  };
  return html`
    <div class="notes">
      ${error ? html`<div class="s-bad" role="alert">${error}</div>` : null}
      ${notes === null ? html`<p class="note">Loading…</p>` : !notes.length ? html`<p class="note">No notes on this flow yet.</p>` : null}
      ${(notes || []).map((x) => editing === x.id
        ? html`<${Editor} key=${x.id} initial=${x} labels=${labels} onCancel=${() => setEditing(null)}
            onSave=${async (f) => { await send("PATCH", `/v1/notes/${x.id}`, f); setEditing(null); changed(); }} />`
        : html`<div class="note-card" key=${x.id}>
            <div class="note-head">${x.label ? html`<${Label} note=${x} onClick=${() => applyQuery(`label:${x.label}`)} />` : null}
              <span class="muted small">${x.author} · ${clock(x.updated)}</span><span class="grow"></span>
              ${mayEdit(x) ? html`<button class="link small" onClick=${() => setEditing(x.id)}>edit</button>
                <button class="link small" onClick=${() => act(() => send("DELETE", `/v1/notes/${x.id}`))}>delete</button>` : null}</div>
            ${x.note ? html`<p class="note-text">${x.note}</p>` : null}
          </div>`)}
      <h3>Add a note</h3>
      <${Editor} labels=${labels} autofocus=${autofocus} onSave=${async (f) => { await send("POST", `/v1/flows/${n}/notes`, f); changed(); }} />
      <p class="note">Find them again with <code>label:</code>, <code>note:"…"</code> or <code>has:note</code>.</p>
    </div>`;
}
