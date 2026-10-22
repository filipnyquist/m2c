// The filter language on the client: the same tokenizer as the server's (filters.parse), with term positions, so
// the filter box can highlight a query, find the term under the cursor and add or merge terms. The server stays the
// judge of what a query means; tests/fixtures/queries.json pins both tokenizers to the same answers.

export const SINGLE = new Set(["body", "after", "before", "url", "err", "note"]); // values that may contain `|`

export class QueryError extends Error {
  constructor(message, at) {
    super(message);
    this.at = at;
  }
}

const space = (c) => /\s/.test(c);

/** Tokens [kind, text, start, end]: kind "open" (text "-" when negated), "close" or "word". Quotes and backslashes
 * work as in a POSIX shell. With `lenient`, an unclosed quote ends the word instead of throwing. */
export function lex(q, lenient = false) {
  const out = [];
  let i = 0, depth = 0;
  const n = q.length;
  while (i < n) {
    if (space(q[i])) { i++; continue; }
    const start = i;
    const j = q[i] === "-" ? i + 1 : i;
    if (j < n && q[j] === "(") {
      out.push(["open", j > i ? "-" : "", start, j + 1]);
      depth++;
      i = j + 1;
      continue;
    }
    if (q[i] === ")" && depth) {
      out.push(["close", "", i, i + 1]);
      depth--;
      i++;
      continue;
    }
    let buf = "", quote = null;
    while (i < n) {
      const c = q[i];
      if (quote === "'") {
        if (c === "'") quote = null; else buf += c;
      } else if (quote === '"') {
        if (c === '"') quote = null;
        else if (c === "\\" && i + 1 < n && (q[i + 1] === '"' || q[i + 1] === "\\")) buf += q[++i];
        else buf += c;
      } else if (space(c) || (c === ")" && depth)) {
        break;
      } else if (c === "'" || c === '"') {
        quote = c;
      } else if (c === "\\" && i + 1 < n) {
        buf += q[++i];
      } else {
        buf += c;
      }
      i++;
    }
    if (quote && !lenient) throw new QueryError("bad quoting: No closing quotation", start);
    out.push(["word", buf, start, i, !!quote]);
  }
  return out;
}

function word(text, start, end, keys) {
  const neg = text.startsWith("-") && text.includes(":");
  const body = neg ? text.slice(1) : text;
  const c = body.indexOf(":");
  if (c >= 0 && keys.has(body.slice(0, c).toLowerCase())) {
    const key = body.slice(0, c).toLowerCase();
    const value = body.slice(c + 1);
    const values = SINGLE.has(key) ? [value] : value.split("|");
    if (!values.length || (values.length === 1 && values[0] === "" && key !== "err")) throw new QueryError(`${key}: needs a value`, start);
    return { neg, key, values, start, end };
  }
  return { neg, key: null, values: [body], start, end };
}

/** Term {neg, key, values, start, end} and group {neg, group, start, end} nodes, as filters.parse returns them. */
export function parse(q, keys) {
  const toks = lex(q || "");
  let pos = 0;
  const items = () => {
    const out = [];
    while (pos < toks.length) {
      const [kind, text, start, end] = toks[pos];
      if (kind === "close") return out;
      pos++;
      if (kind === "word") { out.push(word(text, start, end, keys)); continue; }
      const inner = items();
      if (pos >= toks.length) throw new QueryError("unclosed (", start);
      if (!inner.length) throw new QueryError("empty ( )", start);
      out.push({ neg: text === "-", group: inner, start, end: toks[pos][3] });
      pos++;
    }
    return out;
  };
  return items();
}

export function quoteValue(v) {
  v = String(v);
  return v !== "" && /^[^\s"'()\\|]+$/.test(v) ? v : '"' + v.replace(/["\\]/g, "\\$&") + '"';
}

export const termText = (key, values, neg = false) => (neg ? "-" : "") + key + ":" + values.map(quoteValue).join("|");

/** What the cursor is on: {mode: "key"|"value"|"none", key, neg, start, end, altStart, altEnd, prefix}.
 * "key": completing a key (replace start..end); "value": completing one alternative of key's value (replace
 * altStart..altEnd); "none": free text or an unknown key. */
export function tokenAt(q, cursor, keys) {
  const tok = lex(q, true).find(([kind, , start, end]) => kind === "word" && start <= cursor && cursor <= end);
  if (!tok) return { mode: "key", key: null, neg: false, start: cursor, end: cursor, prefix: "" };
  const [, , start, end] = tok;
  const raw = q.slice(start, end);
  const neg = raw.startsWith("-");
  const off = neg ? 1 : 0;
  const colon = raw.indexOf(":");
  if (colon < 0 || cursor - start <= colon) {
    return { mode: "key", key: null, neg, start, end, prefix: raw.slice(off, Math.max(off, cursor - start)) };
  }
  const key = raw.slice(off, colon).toLowerCase();
  if (!keys.has(key)) return { mode: "none", key: null, neg, start, end, prefix: raw };
  const valueStart = start + colon + 1;
  let altStart = valueStart, altEnd = end;
  if (!SINGLE.has(key)) {
    let quote = null;
    for (let i = valueStart; i < end; i++) {
      const c = q[i];
      if (quote) { if (c === quote) quote = null; continue; }
      if (c === '"' || c === "'") quote = c;
      else if (c === "|") {
        if (i < cursor) altStart = i + 1; else { altEnd = i; break; }
      }
    }
  }
  const typed = q.slice(altStart, cursor);
  return { mode: "value", key, neg, start, end, altStart, altEnd, prefix: typed.replace(/^["']/, "").replace(/\\(.)/g, "$1") };
}

/** q with start..end replaced; the cursor lands after the inserted text. */
export function replaceRange(q, start, end, text) {
  return { q: q.slice(0, start) + text + q.slice(end), cursor: start + text.length };
}

/** q without its token at start..end (and one adjacent space): the context for value suggestions. */
export function without(q, start, end) {
  const before = q.slice(0, start), after = q.slice(end);
  return (before.replace(/\s+$/, "") + (before.trim() && after.trim() ? " " : "") + after.replace(/^\s+/, "")).trim();
}

function topTerms(q, keys) {
  try { return parse(q, keys).filter((n) => !n.group); } catch (e) { return null; }
}

/** q with `key:value` added (or `-key:value` when neg). A second value for a key that has a term of the same sign
 * joins it with `|`; adding a value removes its own negation; a value already there changes nothing. */
export function addTerm(q, key, value, neg, keys) {
  q = (q || "").trim();
  let nodes = topTerms(q, keys);
  if (nodes === null) return (q + " " + termText(key, [value], neg)).trim();
  const opposite = nodes.find((t) => t.key === key && t.neg !== neg && t.values.includes(String(value)));
  if (opposite) {
    const rest = opposite.values.filter((v) => v !== String(value));
    q = rest.length ? replaceRange(q, opposite.start, opposite.end, termText(key, rest, opposite.neg)).q : without(q, opposite.start, opposite.end);
    nodes = topTerms(q, keys) || [];
  }
  const same = nodes.find((t) => t.key === key && t.neg === neg && !SINGLE.has(key));
  if (same) {
    if (same.values.includes(String(value))) return q;
    return replaceRange(q, same.start, same.end, termText(key, [...same.values, value], neg)).q;
  }
  return (q + " " + termText(key, [value], neg)).trim();
}

/** Segments {text, cls} covering q, for the highlight layer behind the filter box. */
export function highlight(q, keys) {
  const out = [];
  let at = 0;
  const push = (text, cls) => { if (text) out.push({ text, cls }); };
  for (const [kind, , start, end, open] of lex(q, true)) {
    push(q.slice(at, start), "");
    const raw = q.slice(start, end);
    if (kind !== "word") push(raw, "q-paren");
    else if (open) push(raw, "q-err");
    else {
      const neg = raw.startsWith("-") ? 1 : 0;
      const colon = raw.indexOf(":");
      const key = colon > 0 ? raw.slice(neg, colon).toLowerCase() : "";
      if (colon > 0 && keys.has(key)) {
        push(raw.slice(0, neg), "q-neg");
        push(raw.slice(neg, colon + 1), "q-key");
        push(raw.slice(colon + 1), "q-val");
      } else push(raw, "q-free");
    }
    at = end;
  }
  push(q.slice(at), "");
  return out;
}
