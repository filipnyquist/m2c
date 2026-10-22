// m2c web UI. Preact + htm modules served as files (no inline script: the CSP is script-src 'self').

import { getJson, hasToken, loadToken, onUnauthorized } from "./lib/api.js";
import { html, render, useEffect } from "./lib/html.js";
import { app, feed, loadHelp, navigate, refreshSide, select, setTheme, startSideTimer, syncRoute } from "./lib/state.js";
import { useStore } from "./lib/store.js";
import { Detail } from "./views/detail.js";
import { DiffView } from "./views/diff.js";
import { EventsView } from "./views/events.js";
import { FlowTable } from "./views/flowtable.js";
import { Help } from "./views/help.js";
import { Login } from "./views/login.js";
import { Menu } from "./views/menu.js";
import { Sessions } from "./views/sessions.js";
import { SessionsView } from "./views/sessionsview.js";
import { TimelineView } from "./views/timeline.js";
import { TopBar } from "./views/topbar.js";

const THEMES = ["auto", "light", "dark"];

async function boot() {
  if (!hasToken()) return app.set({ authed: false });
  try {
    app.set({ scan: await getJson("/v1/scan") });
    await loadHelp();
    app.set({ authed: true, loginMessage: "" });
    refreshSide();
  } catch (e) {
    app.set({ authed: false, loginMessage: e.status === 401
      ? "That token was not accepted. The admin token is in <data>/api.json; a session token is <session>:<proxy token>."
      : `Cannot reach the API: ${e.message}` });
  }
}

onUnauthorized((msg) => {
  feed.stopTail();
  app.set({ authed: false, loginMessage: `The token is no longer accepted (${msg}).` });
});

function onKey(e) {
  if (e.defaultPrevented) return;
  const s = app.get();
  const inInput = !!e.target.closest?.("input, textarea, select");
  if (e.key === "Escape") {
    if (s.menu) app.set({ menu: null });
    else if (s.showHelp) app.set({ showHelp: false });
    else if (!inInput && s.route.n != null) navigate({ n: null });
    return;
  }
  if (inInput || e.ctrlKey || e.metaKey || e.altKey || !s.authed) return;
  if (s.route.view !== "flows" && !["/", "?", "t", "l"].includes(e.key)) return; // list keys belong to the flows view
  const order = feed.list.order;
  const cur = s.route.n != null ? feed.list.indexOf(s.route.n) : -1;
  const move = (i) => order.length && select(order[Math.max(0, Math.min(order.length - 1, i))]);
  const inDetail = !!e.target.closest?.(".detail");
  switch (e.key) {
    case "/": if (document.getElementById("q")) { e.preventDefault(); document.getElementById("q").focus(); } break;
    case "j": move(cur + 1); break;
    case "k": move(cur < 0 ? 0 : cur - 1); break;
    case "ArrowDown": if (!inDetail) { e.preventDefault(); move(cur + 1); } break;
    case "ArrowUp": if (!inDetail) { e.preventDefault(); move(cur < 0 ? 0 : cur - 1); } break;
    case "g": move(0); break;
    case "G": move(order.length - 1); break;
    case "?": app.set({ showHelp: !s.showHelp }); break;
    case "t": setTheme(THEMES[(THEMES.indexOf(s.theme) + 1) % THEMES.length]); break;
    case "l": app.set({ live: !s.live }); feed.setLive(!s.live); break;
    case "a": if (s.route.n != null) navigate({ tab: "notes" }); break; // annotate the selected flow
  }
}

function FlowsView() {
  const q = useStore(app, (s) => s.route.q);
  useEffect(() => { feed.start(q, app.get().live); }, [q]);
  return html`<div class="main"><${Sessions} /><${FlowTable} /><${Detail} /></div>`;
}

function App() {
  const authed = useStore(app, (s) => s.authed);
  const message = useStore(app, (s) => s.loginMessage);
  const theme = useStore(app, (s) => s.theme);
  const showHelp = useStore(app, (s) => s.showHelp);
  const announce = useStore(app, (s) => s.announce);
  const view = useStore(app, (s) => s.route.view);
  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => {
    if (!authed) return;
    const timer = startSideTimer();
    return () => clearInterval(timer);
  }, [authed]);
  if (authed === null) return html`<div class="boot">Loading…</div>`;
  if (!authed) return html`<${Login} message=${message} onToken=${boot} />`;
  return html`
    <${TopBar} />
    ${view === "sessions" ? html`<${SessionsView} />` : view === "events" ? html`<${EventsView} />` : view === "timeline" ? html`<${TimelineView} />` : view === "diff" ? html`<${DiffView} />` : html`<${FlowsView} />`}
    <${Menu} />
    ${showHelp ? html`<${Help} />` : null}
    <div class="sr-only" aria-live="polite">${announce}</div>`;
}

loadToken();
syncRoute();
window.addEventListener("popstate", syncRoute);
window.addEventListener("hashchange", () => {
  if (/[#&]token=/.test(location.hash)) { loadToken(); boot(); } else syncRoute();
});
window.addEventListener("keydown", onKey);
render(html`<${App} />`, document.getElementById("root"));
boot();
