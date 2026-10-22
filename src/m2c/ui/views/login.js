// Asked for when there is no token, or the proxy did not accept it.

import { setToken } from "../lib/api.js";
import { html, useState } from "../lib/html.js";

export function Login({ message, onToken }) {
  const [value, setValue] = useState("");
  const go = () => { setToken(value.trim()); onToken(); };
  return html`
    <main class="login">
      <h1 class="brand">m2c</h1>
      <p class="note">${message || html`Paste the admin token (printed by <code>m2c proxy</code>, also in <code>&lt;data&gt;/api.json</code>) or a session token <code>&lt;session&gt;:&lt;proxy token&gt;</code>.`}</p>
      <input type="password" autocomplete="off" aria-label="API token" value=${value} onInput=${(e) => setValue(e.target.value)}
        onKeyDown=${(e) => e.key === "Enter" && go()} autofocus />
      <button class="btn on" onClick=${go}>Open</button>
    </main>`;
}
