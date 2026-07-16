import { useEffect, useState } from "react";
import { AlertTriangle } from "lucide-react";

import { rpc } from "../api";
import { describeChanges, describeEvent, type NameResolver } from "../core/activity";
import type { ActivityEvent, MemberDto } from "../types";
import { memberName } from "./Avatar";
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
 * **Who did it is `core/activity.ts`'s call, not this file's.** This feed is the
 * per-session ring: local ops stamp their own key, and a remote change arrives as one
 * synthetic `synced` event stamped with *this* node's key — so `synced` is rendered
 * without a name, or the feed would credit you with a teammate's edit. Names for the
 * rest are resolved from the member list, same rule as the durable per-issue history.
 */
export function Activity({
  spaceId,
  members,
  revision,
  onError,
  onOpen,
}: {
  spaceId: string;
  members: MemberDto[];
  revision: number;
  onError: (m: string) => void;
  onOpen: (reff: string) => void;
}) {
  const [events, setEvents] = useState<ActivityEvent[] | null>(null);
  const resolveName: NameResolver = (key) =>
    memberName(key, members.find((m) => m.key === key));

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
          <Line event={e} resolveName={resolveName} />
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

function Line({ event, resolveName }: { event: ActivityEvent; resolveName: NameResolver }) {
  const { actor, phrase } = describeEvent(event, resolveName);
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
