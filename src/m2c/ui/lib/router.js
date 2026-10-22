// Hash routes: #/flows?q=&n=&tab=, #/sessions?q=, #/timeline?session=, #/events, #/diff/A/B. A changed query or view is a new history
// entry (Back undoes it); a selected flow or tab replaces the current one.

export const VIEWS = ["flows", "sessions", "timeline", "events", "diff"];
export const FILTERED = new Set(["flows", "sessions"]); // the views the filter box applies to

export function parseHash(hash = location.hash) {
  const [path, search = ""] = hash.replace(/^#\/?/, "").split("?");
  const parts = path.split("/").filter(Boolean);
  const p = new URLSearchParams(search);
  const view = VIEWS.includes(parts[0]) ? parts[0] : "flows";
  const num = (v) => (v && /^\d+$/.test(v) ? +v : null);
  return { view, q: p.get("q") || "", n: num(p.get("n")), tab: p.get("tab") || "", a: num(parts[1]), b: num(parts[2]),
    session: p.get("session") || "" };
}

export function formatHash(r) {
  const p = new URLSearchParams();
  if (r.q && FILTERED.has(r.view)) p.set("q", r.q);
  if (r.view === "flows" && r.n != null) p.set("n", r.n);
  if (r.view === "flows" && r.tab) p.set("tab", r.tab);
  if (r.view === "timeline" && r.session) p.set("session", r.session);
  const path = r.view === "diff" ? `diff/${r.a ?? ""}/${r.b ?? ""}` : r.view;
  const s = p.toString();
  return `#/${path}${s ? "?" + s : ""}`;
}

/** Navigate: `push` for changes Back should undo. Returns the new route. */
export function go(current, patch, push = false) {
  const next = { ...current, ...patch };
  const hash = formatHash(next);
  if (hash !== location.hash) history[push ? "pushState" : "replaceState"](null, "", hash);
  return next;
}
