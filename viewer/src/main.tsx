import { StrictMode } from "react";
import { createRoot } from "react-dom/client";

import { App } from "./App";
import { contribute, registry } from "./core/registry";
import "./styles.css";

/**
 * The seam, reachable from outside the bundle.
 *
 * Without this, "extensible" would mean "fork `viewer/` and rebuild", which is
 * not extensibility — it is a patch. The client ships as a compiled bundle inside
 * a Rust binary, so the only way a third party can add a command or rebind a key
 * *at runtime* is a handle on the registry. This is it.
 *
 * It is deliberately the same `contribute` the core uses for every one of its own
 * features. Nothing here is a special path for outsiders; there is one door and
 * everyone walks through it.
 *
 * Reaching it today means a userscript or the console — the page is same-origin
 * and served by the engine, so there is no third-party script tag to add and (by
 * design, given the `Origin` allowlist) no remote code loading. A first-class
 * extension host — user JS read from the config dir and served same-origin — is
 * the natural next step, and it would land on this same API.
 */
declare global {
  interface Window {
    lait: { contribute: typeof contribute; registry: typeof registry };
  }
}

window.lait = { contribute, registry };

const root = document.getElementById("root");
if (!root) throw new Error("#root missing from index.html");

createRoot(root).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
