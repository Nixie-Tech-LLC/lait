import { useEffect, useRef, useState } from "react";

import { isTypingTarget, SEQUENCE_TIMEOUT_MS } from "./keys";
import { registry, type Ctx } from "./registry";
import { resolve, shouldHandle } from "./resolve";

/**
 * The keyboard driver: one listener for the whole app.
 *
 * One listener, not one per component, because that is what makes the registry
 * the single seam — a component that added its own `keydown` handler would be a
 * binding nobody can see in the `?` overlay or rebind in config.
 *
 * Returns the half-typed sequence so the UI can show it (`g …`), which is the
 * difference between a sequence feeling like a feature and feeling like a bug.
 */
export function useKeys(ctx: Ctx): string[] {
  // Two representations on purpose: the ref holds the raw events (resolution
  // needs the modifiers), the state holds their labels (render needs a string).
  const [pending, setPending] = useState<string[]>([]);
  // The listener is installed once; it reads the live ctx through a ref rather
  // than re-subscribing on every state change (and losing the pending buffer).
  const ctxRef = useRef(ctx);
  ctxRef.current = ctx;
  const pendingRef = useRef<KeyboardEvent[]>([]);
  const timer = useRef<number | undefined>(undefined);

  useEffect(() => {
    const clear = () => {
      pendingRef.current = [];
      setPending([]);
      if (timer.current) window.clearTimeout(timer.current);
      timer.current = undefined;
    };

    const onKey = (ev: KeyboardEvent) => {
      if (!shouldHandle(ev, isTypingTarget(ev.target))) return;
      const active = registry.active(ctxRef.current);
      const outcome = resolve(active, pendingRef.current, ev);

      switch (outcome.kind) {
        case "none":
          // An unmatched key abandons a half-typed sequence: `g q` should not
          // leave `g` armed and turn the next unrelated keystroke into a jump.
          if (pendingRef.current.length) clear();
          return;
        case "pending":
          ev.preventDefault();
          pendingRef.current = outcome.prefix;
          setPending(outcome.prefix.map((e) => e.key));
          if (timer.current) window.clearTimeout(timer.current);
          timer.current = window.setTimeout(clear, SEQUENCE_TIMEOUT_MS);
          return;
        case "run":
          ev.preventDefault();
          clear();
          void outcome.command.run(ctxRef.current);
          return;
      }
    };

    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("keydown", onKey);
      if (timer.current) window.clearTimeout(timer.current);
    };
  }, []);

  return pending;
}
