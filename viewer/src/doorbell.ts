import { useEffect, useRef, useState } from "react";

import type { SpaceDoorbell } from "./types";

export type Liveness = "connecting" | "live" | "retrying";

/**
 * The doorbell stream — one `EventSource` over every attached space.
 *
 * A frame is a **dirty flag, never state**: the client re-reads the authoritative
 * projection for each dirty scope and never patches from the frame (UI.md §4.2).
 * That is what keeps the browser honest about a CRDT it does not hold.
 *
 * `lagged` means the server's broadcast dropped frames under load; its contract is
 * the same as `reset` or an `epoch` change — rebaseline rather than trust the view.
 * We surface both as a bare "something changed, re-read everything" signal, because
 * the recovery is identical and pretending otherwise invites a subtle bug.
 *
 * `EventSource` reconnects on its own, so there is no retry loop here — only the
 * liveness the user should see.
 */
export function useDoorbell(onRing: (d: SpaceDoorbell | null) => void): Liveness {
  const [liveness, setLiveness] = useState<Liveness>("connecting");
  // Keep the newest callback without re-opening the stream on every render.
  const cb = useRef(onRing);
  cb.current = onRing;

  useEffect(() => {
    const es = new EventSource("/api/events", { withCredentials: true });
    es.onopen = () => setLiveness("live");
    es.onerror = () => setLiveness("retrying");
    es.addEventListener("doorbell", (ev) => {
      try {
        cb.current(JSON.parse((ev as MessageEvent<string>).data) as SpaceDoorbell);
      } catch {
        // A frame we can't read is still news: rebaseline rather than ignore it.
        cb.current(null);
      }
    });
    // Frames were dropped — our view may be stale in ways we can't name.
    es.addEventListener("lagged", () => cb.current(null));
    return () => es.close();
  }, []);

  return liveness;
}
