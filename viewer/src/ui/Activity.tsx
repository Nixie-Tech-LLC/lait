import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";

import { rpc } from "../api";
import { describeChanges, describeEvent } from "../core/activity";
import type { ActivityEvent } from "../types";
import { when } from "./time";

/**
 * The workspace feed.
 *
 * Pulled, never pushed: the doorbell only sets `activity_advanced` — it carries no
 * rows — so this re-reads when it rings (S§7.5). That is the same discipline as
 * every other surface here and the reason a client can never render an event the
 * daemon didn't derive.
 *
 * One `Request` = one commit = one row (S§7.1), so a mutation that moved three
 * fields is *one* entry with three changes rather than three entries. The feed's
 * granularity is the command surface's, by design.
 *
 * **Who did it is `core/activity.ts`'s call, not this file's.** This used to render
 * `{actor_nick} {text}` straight from the struct, which was wrong twice: most kinds
 * carry no `text` at all (so the row was a bare name), and `actor` is stamped with
 * the *local* identity on every event — including `synced`, the one that fires when
 * a teammate's change arrives. The feed was crediting you with other people's edits.
 */
export function Activity({
  spaceId,
  revision,
  onError,
  onOpen,
}: {
  spaceId: string;
  revision: number;
  onError: (m: string) => void;
  onOpen: (reff: string) => void;
}) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const r = await rpc(spaceId, { cmd: "activity", since: 0 });
        if (alive && r.kind === "activity") setEvents(r.events);
      } catch (e) {
        if (alive) onError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
  }, [spaceId, revision, onError]);

  if (!events) return <p className="text-mute p-4 text-sm">Loading…</p>;
  if (events.length === 0) {
    return <p className="text-mute p-8 text-center">No activity yet.</p>;
  }

  return (
    <ul className="min-h-0 flex-1 overflow-y-auto">
      {/* Newest first: the feed answers "what just happened", not "what happened". */}
      {[...events].reverse().map((e) => (
        <li
          key={e.seq}
          onClick={() => onOpen(e.reff)}
          className="border-line/60 hover:bg-hover flex cursor-default items-baseline gap-3 border-b px-4 py-2"
        >
          <span className="text-mute w-20 shrink-0 truncate font-mono text-xs tabular-nums">
            {e.reff}
          </span>
          <Line event={e} />
          {/* A concurrent overwrite is worth flagging but never worth blocking on
              (A§9): last-writer-wins already resolved it; you just get told. */}
          {e.collision && (
            <AlertTriangle
              className="text-warn size-3.5 shrink-0"
              aria-label="Concurrent overwrite detected"
            />
          )}
          <time className="text-mute shrink-0 text-xs">{when(e.ts)}</time>
        </li>
      ))}
    </ul>
  );
}

function Line({ event }: { event: ActivityEvent }) {
  const { actor, phrase } = describeEvent(event);
  const changes = describeChanges(event);
  return (
    <span className="min-w-0 flex-1">
      {/* No name when we have no honest one — see core/activity.ts. */}
      {actor && <span className="font-medium">{actor} </span>}
      <span className="text-dim">{phrase}</span>
      {/* `created` and `commented` are the two kinds that carry words of their
          own; everything else is phrased above. */}
      {event.text && <span className="text-mute ml-2 text-xs">{event.text}</span>}
      {changes && <span className="text-mute ml-2 text-xs">{changes}</span>}
    </span>
  );
}
