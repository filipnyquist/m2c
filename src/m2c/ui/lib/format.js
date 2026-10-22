// Small presentation helpers shared by the views.

export function size(n) {
  n = +n || 0;
  if (n < 1024) return n + "B";
  for (const u of ["K", "M", "G"]) {
    n /= 1024;
    if (n < 1024 || u === "G") return n.toFixed(1) + u;
  }
  return String(n);
}

export function time(ms) {
  if (!ms) return "-";
  const d = new Date(ms);
  return d.toLocaleTimeString([], { hour12: false }) + "." + String(d.getMilliseconds()).padStart(3, "0");
}

/** HH:MM:SS, with the date in front when it isn't today. */
export function clock(ms) {
  if (!ms) return "-";
  const d = new Date(ms), now = new Date();
  const t = d.toLocaleTimeString([], { hour12: false });
  return d.toDateString() === now.toDateString() ? t : d.toLocaleDateString([], { month: "short", day: "numeric" }) + " " + t.slice(0, 5);
}

export const GRPC_STATUS = ["OK", "CANCELLED", "UNKNOWN", "INVALID_ARGUMENT", "DEADLINE_EXCEEDED", "NOT_FOUND", "ALREADY_EXISTS",
  "PERMISSION_DENIED", "RESOURCE_EXHAUSTED", "FAILED_PRECONDITION", "ABORTED", "OUT_OF_RANGE", "UNIMPLEMENTED", "INTERNAL", "UNAVAILABLE",
  "DATA_LOSS", "UNAUTHENTICATED"];

const grpcFailed = (f) => f.grpc && f.grpc_status > 0;
// The same vocabulary as the server (schema.ERROR / FAILED): red for errors, amber for the other failures (4xx).
export const isError = (f) => !!f.error || f.status >= 500 || grpcFailed(f);
export const statusClass = (f) => f.open ? "s-open" : isError(f) ? "s-bad" : f.status >= 400 ? "s-warn" : f.status >= 300 ? "s-muted" : f.status ? "s-ok" : "";
export const statusText = (f) => f.open ? "…" : grpcFailed(f) ? `${f.status || "ERR"}·g${f.grpc_status}` : String(f.status || (f.error ? "ERR" : "-"));
export const statusTitle = (f) => f.open ? "still running" : grpcFailed(f) ? `gRPC ${GRPC_STATUS[f.grpc_status] || f.grpc_status}` + (f.error ? `; ${f.error}` : "") : (f.error || "");
export const who = (f) => `${f.session} / ${f.tool}${f.call_id ? " #" + f.call_id : ""}`;
export const pathOnly = (p) => (p || "").split("?")[0] || "/";

/** Binary search: the index to insert `n` at in an array sorted by `key` descending. */
export function insertAtDesc(arr, n, key = (x) => x) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (key(arr[mid]) > n) lo = mid + 1; else hi = mid;
  }
  return lo;
}

/** Binary search: the index to insert `n` at in an array sorted by `key` ascending. */
export function insertAtAsc(arr, n, key = (x) => x) {
  let lo = 0, hi = arr.length;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (key(arr[mid]) < n) lo = mid + 1; else hi = mid;
  }
  return lo;
}
