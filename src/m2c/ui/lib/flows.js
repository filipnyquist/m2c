// The flow list and its live feed.
//
// FlowList holds summaries by n, ordered by n (newest first), capped so a long run cannot grow the page without
// bound. FlowFeed fills it: for a new query it starts the tail first and buffers what arrives, loads the first page,
// then applies the buffer, so no flow falls between the two and an open stream is never wiped by a reload. Each
// query gets a generation number; answers for an older one are dropped. Live updates are applied in batches, once
// per animation frame (once a second while the tab is hidden).

import { ApiError, getJson, qs, readSse } from "./api.js";
import { insertAtDesc } from "./format.js";

export const CAP = 20000;
export const PAGE = 200;

export class FlowList {
  constructor(cap = CAP) {
    this.cap = cap;
    this.reset();
  }

  reset() {
    this.map = new Map();
    this.order = []; // n, descending
    this.hasOlder = false;
    this.capped = false;
  }

  get(n) { return this.map.get(n); }
  get size() { return this.order.length; }
  oldest() { return this.order[this.order.length - 1]; }
  indexOf(n) {
    const i = insertAtDesc(this.order, n);
    return this.order[i] === n ? i : -1;
  }

  /** Add or update a summary; false when nothing changed. A finished flow never goes back to open. */
  upsert(f) {
    const old = this.map.get(f.n);
    if (old) {
      if (f.open && !old.open) return false;
      this.map.set(f.n, f);
      return true;
    }
    if (this.order.length >= this.cap && f.n < this.oldest()) {
      this.capped = true;
      return false;
    }
    this.order.splice(insertAtDesc(this.order, f.n), 0, f.n);
    this.map.set(f.n, f);
    while (this.order.length > this.cap) {
      this.map.delete(this.order.pop());
      this.capped = true;
    }
    return true;
  }
}

export class FlowFeed {
  /** handlers: onChange({added, finished}), onStats(stats), onStatus(status, message) */
  constructor(handlers) {
    this.h = handlers;
    this.list = new FlowList();
    this.gen = 0;
    this.q = "";
    this.live = true;
    this.ctl = null;
    this.cursor = null;
    this.retry = 0;
    this.queue = [];
    this.buffer = null;
    this.flushHandle = null;
    this.olderLoading = false;
    this.status = "idle";
  }

  setStatus(status, message = "") {
    this.status = status;
    this.h.onStatus(status, message);
  }

  /** Load `q` from scratch; resolves when the first page is in. */
  async start(q, live = this.live) {
    const gen = ++this.gen;
    this.stopTail();
    this.q = q;
    this.live = live;
    this.cursor = null;
    this.queue = [];
    this.list.reset();
    this.buffer = [];
    this.setStatus("loading");
    this.h.onChange({ added: [], finished: 0, reset: true });
    if (live) this.tail(gen);
    let page;
    try {
      page = await getJson(`/v1/flows${qs({ q, limit: PAGE })}`);
    } catch (e) {
      if (gen !== this.gen) return;
      this.buffer = null;
      this.stopTail();
      this.setStatus("error", e.message);
      return;
    }
    if (gen !== this.gen) return;
    for (const f of page.flows) this.list.upsert(f);
    this.list.hasOlder = !!page.next;
    const buffered = this.buffer;
    this.buffer = null;
    for (const f of buffered) this.list.upsert(f);
    if (this.status === "loading") this.setStatus(live ? "live" : "paused");
    this.h.onChange({ added: [], finished: 0, reset: true });
  }

  async loadOlder() {
    if (!this.list.hasOlder || this.olderLoading || this.buffer || this.list.size >= this.list.cap) return;
    const gen = this.gen;
    this.olderLoading = true;
    try {
      const page = await getJson(`/v1/flows${qs({ q: this.q, limit: PAGE, cursor: this.list.oldest() })}`);
      if (gen !== this.gen) return;
      for (const f of page.flows) this.list.upsert(f);
      this.list.hasOlder = !!page.next && this.list.size < this.list.cap;
      this.h.onChange({ added: [], finished: 0 });
    } catch (e) {
      if (gen === this.gen) this.setStatus("error", e.message);
    } finally {
      this.olderLoading = false;
    }
  }

  setLive(live) {
    this.live = live;
    if (!live) {
      this.stopTail();
      this.setStatus("paused");
    } else if (this.cursor) {
      this.tail(this.gen, this.cursor); // replays what finished meanwhile, or asks for a resync
    } else {
      this.start(this.q, true);
    }
  }

  tail(gen, since = null) {
    const ctl = new AbortController();
    this.ctl = ctl;
    if (this.status !== "loading") this.setStatus("connecting");
    readSse(`/v1/tail${qs({ q: this.q, since })}`, ctl.signal, (kind, item, id) => {
      if (gen !== this.gen || this.ctl !== ctl) return;
      this.retry = 0;
      if (id) this.cursor = id;
      if (kind === "flow" || kind === "open") this.event(kind === "open" ? { ...item, open: true } : item);
      else if (kind === "stats") {
        if (this.status === "connecting" || this.status === "reconnecting") this.setStatus("live");
        this.h.onStats(item);
      } else if (kind === "resync") this.start(this.q, true);
    }).then(
      () => this.reconnect(gen, ctl, false),
      (e) => {
        if (e.name === "AbortError" || gen !== this.gen || this.ctl !== ctl) return;
        if (e instanceof ApiError && e.status !== 429 && e.status < 500) {
          this.ctl = null;
          this.setStatus("error", e.message); // a bad filter, a revoked token: retrying won't help
          return;
        }
        this.reconnect(gen, ctl, e instanceof ApiError && e.status === 429, e.message);
      },
    );
  }

  reconnect(gen, ctl, slow, message = "") {
    if (gen !== this.gen || this.ctl !== ctl || !this.live) return;
    this.retry = Math.min(Math.max((this.retry || 500) * 2, slow ? 5000 : 0), 30000);
    this.setStatus("reconnecting", message || "the live feed ended");
    setTimeout(() => {
      if (gen === this.gen && this.ctl === ctl && this.live) this.tail(gen, this.cursor);
    }, this.retry);
  }

  stopTail() {
    if (this.ctl) this.ctl.abort();
    this.ctl = null;
  }

  event(f) {
    if (this.buffer) {
      this.buffer.push(f);
      return;
    }
    this.queue.push(f);
    if (this.flushHandle) return;
    const run = () => { this.flushHandle = null; this.flush(); };
    this.flushHandle = document.hidden ? setTimeout(run, 1000) : requestAnimationFrame(run);
  }

  flush() {
    const added = [];
    let finished = 0, changed = false;
    for (const f of this.queue) {
      const had = this.list.get(f.n);
      if (this.list.upsert(f)) {
        changed = true;
        if (!had) added.push(f.n);
        if (!f.open) finished++;
      }
    }
    this.queue = [];
    if (changed) this.h.onChange({ added, finished });
  }
}
