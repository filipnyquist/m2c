// A tiny external store: state outside the component tree, components re-render when what they select changes.
import { useEffect, useReducer, useRef } from "./html.js";

export function createStore(initial) {
  let state = initial;
  const subs = new Set();
  return {
    get: () => state,
    set(patch) {
      const next = typeof patch === "function" ? patch(state) : patch;
      state = { ...state, ...next };
      subs.forEach((fn) => fn());
    },
    subscribe(fn) { subs.add(fn); return () => subs.delete(fn); },
  };
}

export function useStore(store, select = (s) => s) {
  const [, force] = useReducer((x) => x + 1, 0);
  const sel = useRef(select);
  sel.current = select;
  const value = select(store.get());
  const last = useRef(value);
  last.current = value;
  useEffect(() => store.subscribe(() => {
    if (!Object.is(sel.current(store.get()), last.current)) force();
  }), [store]);
  return value;
}
