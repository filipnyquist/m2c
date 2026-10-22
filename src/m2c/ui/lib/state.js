// App state and the actions views share: the store, the flow feed, navigation, query changes, side refreshes.

import { getJson, qs } from "./api.js";
import { FlowFeed } from "./flows.js";
import { addTerm } from "./query.js";
import { FILTERED, go, parseHash } from "./router.js";
import { createStore } from "./store.js";

const THEME_KEY = "m2c-theme";
const HISTORY_KEY = "m2c-history";
const SIDE_EVERY = 10000; // ms: sessions, scan totals and hints refresh at most this often, and only when visible

function stored(key, fallback) {
  try { return JSON.parse(localStorage.getItem(key)) ?? fallback; } catch (e) { return fallback; }
}

function store(key, value) {
  try { localStorage.setItem(key, JSON.stringify(value)); } catch (e) { /* blocked storage: this page only */ }
}

export const app = createStore({
  authed: null, // null: checking the token
  loginMessage: "",
  route: parseHash(),
  scan: null,
  liveStats: null,
  sessions: [],
  help: { keys: [], text: "" },
  keys: new Set(),
  byKey: {},
  version: 0, // bumped when the flow list changes
  feedStatus: "idle",
  feedMessage: "",
  live: true,
  theme: stored(THEME_KEY, "auto"),
  menu: null, // {x, y, items}
  showHelp: false,
  sideVersion: 0, // bumped when new flows finished: what the side panels and hints read may have changed
  announce: "",
  eventCounts: [], // [{kind, severity, count, last_ts}]
  notesVersion: 0, // bumped after a note is written here: chips and lists reload
});

export const feed = new FlowFeed({
  onChange({ added, finished, reset }) {
    const s = app.get();
    app.set({ version: s.version + 1, sideVersion: finished ? s.sideVersion + 1 : s.sideVersion });
    if (!reset && added.length) announce(added.length);
  },
  onStats(stats) { app.set({ liveStats: stats }); },
  onStatus(status, message) { app.set({ feedStatus: status, feedMessage: message }); },
});

let announced = 0, announceTimer = null;
function announce(count) {
  // For screen readers: at most one message every 5 s, not one per flow.
  announced += count;
  if (announceTimer) return;
  announceTimer = setTimeout(() => {
    app.set({ announce: `${announced} new flow${announced === 1 ? "" : "s"}` });
    announced = 0;
    announceTimer = null;
  }, 5000);
}

export function navigate(patch, push = false) {
  app.set({ route: go(app.get().route, patch, push) });
}

export function syncRoute() {
  app.set({ route: parseHash() });
}

/** Check a query on the server, then apply it (a new history entry). Resolves to an error message or "". */
export async function applyQuery(q) {
  q = (q || "").trim();
  try {
    await getJson(`/v1/filter-check${qs({ q })}`);
  } catch (e) {
    return e.message;
  }
  if (q) {
    const recent = [q, ...stored(HISTORY_KEY, []).filter((x) => x !== q)].slice(0, 15);
    store(HISTORY_KEY, recent);
  }
  const view = app.get().route.view;
  navigate({ view: FILTERED.has(view) ? view : "flows", q, n: null }, true);
  return "";
}

export const recentQueries = () => stored(HISTORY_KEY, []);

/** Add `key:value` (or its negation) to the current query and apply it. */
export function refine(key, value, neg = false) {
  const s = app.get();
  return applyQuery(addTerm(s.route.q, key, value, neg, s.keys));
}

export function select(n) {
  const r = app.get().route;
  if (r.n !== n) navigate({ n });
}

export function setTheme(theme) {
  store(THEME_KEY, theme);
  app.set({ theme });
}

export async function loadHelp() {
  const help = await getJson("/v1/filter-help");
  app.set({ help, keys: new Set(help.keys.map((k) => k.key)), byKey: Object.fromEntries(help.keys.map((k) => [k.key, k])) });
}

export async function refreshSide() {
  const [scan, sessions, eventCounts] = await Promise.all([getJson("/v1/scan").catch(() => null), getJson("/v1/sessions").catch(() => null),
    getJson(`/v1/events/counts${qs({ since: eventsSeen() })}`).catch(() => null)]);
  app.set({ ...(scan ? { scan } : {}), ...(sessions ? { sessions } : {}), ...(eventCounts ? { eventCounts } : {}) });
}

const EVENTS_SEEN_KEY = "m2c-events-seen";
export function eventsSeen() {
  let seen = stored(EVENTS_SEEN_KEY, 0);
  if (!seen) store(EVENTS_SEEN_KEY, (seen = Date.now())); // a first visit: count from now, not from the scan's start
  return seen;
}

/** The Events view was looked at: the badge counts what comes after this. */
export function markEventsSeen() {
  store(EVENTS_SEEN_KEY, Date.now());
  app.set({ eventCounts: app.get().eventCounts.map((c) => ({ ...c, recent: 0 })) });
}

/** Open the comparison of flows a and b. */
export function compare(a, b) {
  navigate({ view: "diff", a, b }, true);
}

export function showView(view) {
  navigate({ view }, true);
}

let sideSeen = -1, sideAt = 0;
/** Refresh the side panels when the tab is visible and flows finished since the last time (or 30 s passed: proxy
 * events such as rejected logins don't finish flows), at most every SIDE_EVERY. */
export function startSideTimer() {
  return setInterval(() => {
    const v = app.get().sideVersion;
    if (document.hidden || (v === sideSeen && Date.now() - sideAt < 30000)) return;
    sideSeen = v;
    sideAt = Date.now();
    refreshSide();
  }, SIDE_EVERY);
}
