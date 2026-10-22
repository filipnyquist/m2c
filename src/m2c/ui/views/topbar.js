// The header: filter box, live toggle, HAR export, totals, theme, who you are; and the feed's problems, if any.

import { download, qs, setToken } from "../lib/api.js";
import { html } from "../lib/html.js";
import { FILTERED } from "../lib/router.js";
import { app, feed, setTheme, showView } from "../lib/state.js";
import { useStore } from "../lib/store.js";
import { FilterBox, Hints } from "./filterbox.js";

const THEMES = ["auto", "light", "dark"];
const STATUS = { live: "live", connecting: "connecting…", reconnecting: "reconnecting…", paused: "paused", loading: "loading…", error: "stopped", idle: "" };

export function TopBar() {
  // Field by field: the store changes on every batch of live flows, and this bar should not re-render for those.
  const s = {
    scan: useStore(app, (x) => x.scan), liveStats: useStore(app, (x) => x.liveStats), live: useStore(app, (x) => x.live),
    feedStatus: useStore(app, (x) => x.feedStatus), feedMessage: useStore(app, (x) => x.feedMessage), theme: useStore(app, (x) => x.theme),
    route: { q: useStore(app, (x) => x.route.q) }, view: useStore(app, (x) => x.route.view), eventCounts: useStore(app, (x) => x.eventCounts),
  };
  // new warnings since the Events view was last open
  const warnings = s.view === "events" ? 0 : s.eventCounts.filter((e) => e.severity === "warn" || e.severity === "error").reduce((a, e) => a + (e.recent || 0), 0);
  const tabs = [["flows", "Flows"], ["sessions", "Sessions"], ["timeline", "Timeline"], ["events", "Events"]];
  const scan = s.scan || {}, live = s.liveStats || {};
  const parts = [`${scan.flows ?? "-"} flows`, `${scan.sessions ?? "-"} sessions`, `${scan.failures ?? "-"} failed`];
  if (live.open) parts.push(`${live.open} open`);
  if (live.queued) parts.push(`${live.queued} queued`);
  const toggleLive = () => { const on = !s.live; app.set({ live: on }); feed.setLive(on); };
  return html`
    <header class="top">
      <div class="top-row">
        <h1 class="brand">m2c</h1>
        <nav class="views" aria-label="Views">
          ${tabs.map(([v, label]) => html`<a href=${`#/${v}`} class="view-tab ${s.view === v ? "on" : ""}" aria-current=${s.view === v ? "page" : undefined}
            onClick=${(e) => { e.preventDefault(); showView(v); }}>${label}${v === "events" && warnings ? html`<span class="count-badge" title="new warnings since you last looked">${warnings}</span>` : null}</a>`)}
          ${s.view === "diff" ? html`<span class="view-tab on" aria-current="page">Compare</span>` : null}
        </nav>
        ${FILTERED.has(s.view) ? html`<${FilterBox} />` : html`<span class="grow"></span>`}
        <button class="btn ${s.live ? "on" : ""}" aria-pressed=${s.live} title="Follow new flows (l)" onClick=${toggleLive}>
          <span class="dot dot-${s.feedStatus}"></span>${s.live ? STATUS[s.feedStatus] || "live" : "paused"}</button>
        <button class="btn" title="Download the filtered flows as HAR" onClick=${() => download(`/v1/har${qs({ q: s.route.q, limit: 1000 })}`, "m2c.har").catch((e) => alert(e.message))}>HAR</button>
        <span class="stats" title=${`scan ${scan.scan_id || ""}`}>${parts.join(" · ")}${live.dropped ? html` · <b class="s-bad">${live.dropped} rows dropped</b>` : null}</span>
        <button class="btn" title="Theme (t)" onClick=${() => setTheme(THEMES[(THEMES.indexOf(s.theme) + 1) % THEMES.length])}>${s.theme}</button>
        <span class="badge" title=${scan.scope ? "a session token: this session's flows only" : "the admin token: every session"}>${scan.scope ? `session ${scan.scope}` : "admin"}</span>
        <button class="btn" title="Forget the token" onClick=${() => { setToken(""); feed.stopTail(); app.set({ authed: false, loginMessage: "" }); }}>log out</button>
      </div>
      ${s.view === "flows" ? html`<${Hints} />` : null}
      ${s.feedStatus === "error" ? html`<div class="banner" role="alert">${s.feedMessage} <button class="link" onClick=${() => feed.start(s.route.q, s.live)}>retry</button></div>` : null}
      ${s.feedStatus === "reconnecting" ? html`<div class="banner warn">The live feed dropped (${s.feedMessage}); reconnecting…</div>` : null}
    </header>`;
}
