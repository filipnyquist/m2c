// Preact + htm, vendored (see vendor/CHECKSUMS.json): components written as tagged templates, no build step.
import { h, render, Fragment, createContext } from "../vendor/preact.mjs";
import htm from "../vendor/htm.mjs";

export const html = htm.bind(h);
export { h, render, Fragment, createContext };
export { useState, useEffect, useLayoutEffect, useRef, useMemo, useCallback, useReducer, useContext } from "../vendor/hooks.mjs";
