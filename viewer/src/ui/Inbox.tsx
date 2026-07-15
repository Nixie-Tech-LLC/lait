import { useCallback, useEffect, useState } from "react";
import { AtSign, CheckCheck, MessageSquare, SignalHigh } from "lucide-react";

import { rpc } from "../api";
import type { InboxEntry } from "../types";
import { short, when } from "./time";

/**
 * The inbox — changes addressed to *you*.
 *
 * Not a filtered feed. Activity answers "what happened in this space"; the inbox
 * answers "what happened *to me*", and they are two different questions with two
 * different structures on purpose (S§8.1). It is derived at sync-import time and
 * persisted, so unlike the activity ring it survives a daemon restart.
 *
 * Attribution is honest and it is why `actor` is nullable: comments carry a real
 * author, but an assignment or a status change does not — the doc says what
 * changed, not who changed it. Those render actor-unknown rather than guessing,
 * which is a deliberate non-goal of the schema, not a gap to fill in.
 */
export function Inbox({
  spaceId,
  revision,
  onError,
  onOpen,
  onCountChange,
}: {
  spaceId: string;
  revision: number;
  onError: (m: string) => void;
  onOpen: (reff: string) => void;
  onCountChange: (unread: number) => void;
}) {
  const [entries, setEntries] = useState<InboxEntry[] | null>(null);
  const [unread, setUnread] = useState(0);

  const load = useCallback(
    async (clear: boolean) => {
      try {
        const r = await rpc(spaceId, { cmd: "inbox", clear });
        if (r.kind !== "inbox") return;
        setEntries(r.entries);
        // `unread` in the reply is a snapshot from *before* the clear: the daemon
        // counts, then advances the watermark (`inbox::list` then
        // `inbox::mark_read`), so a `clear: true` reply says "this is what you
        // just marked read", not "this is what remains". Taking it literally
        // leaves the badge lit over an inbox the daemon already considers read.
        // Marking read has no doc to change, so no doorbell corrects it either.
        const now = clear ? 0 : r.unread;
        setUnread(now);
        onCountChange(now);
      } catch (e) {
        onError(e instanceof Error ? e.message : String(e));
      }
    },
    [spaceId, onError, onCountChange],
  );

  // `clear: false` — reading the inbox must not silently mark it read. `clear`
  // advances the watermark (`inbox::mark_read`), which is a write wearing a
  // read's name; it happens when you *say* so, below.
  useEffect(() => {
    void load(false);
  }, [load, revision]);

  if (!entries) return <p className="text-mute p-4 text-sm">Loading…</p>;

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="border-line flex h-9 shrink-0 items-center gap-3 border-b px-4">
        <span className="text-mute text-sm">
          {entries.length} {entries.length === 1 ? "item" : "items"}
          {unread > 0 && <span className="text-accent"> · {unread} unread</span>}
        </span>
        {unread > 0 && (
          <button
            onClick={() => void load(true)}
            className="text-mute hover:text-fg ml-auto flex items-center gap-1.5 text-sm"
          >
            <CheckCheck className="size-3.5" />
            Mark all read
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <p className="text-mute p-8 text-center">
          Nothing addressed to you. This is the good outcome.
        </p>
      ) : (
        <ul className="min-h-0 flex-1 overflow-y-auto">
          {entries.map((e, i) => (
            <li
              key={`${e.doc_id}-${e.ts}-${i}`}
              onClick={() => onOpen(e.reff)}
              className={[
                "border-line/60 hover:bg-hover flex cursor-default items-start gap-3 border-b px-4 py-2",
                // `unread` counts entries past the watermark, and they are the
                // newest — so the first N are the unread ones.
                i < unread ? "bg-accent/5" : "",
              ].join(" ")}
            >
              <span className="mt-0.5 shrink-0">
                <KindIcon kind={e.kind} />
              </span>
              <span className="min-w-0 flex-1">
                <span className="flex items-baseline gap-2">
                  <span className="text-mute font-mono text-xs tabular-nums">{e.reff}</span>
                  <span className="truncate font-medium">{e.title}</span>
                </span>
                <span className="text-dim line-clamp-2 block">
                  {/* Only comments have an author to name. Anything else says so. */}
                  {e.actor_nick || (e.actor && short(e.actor)) || (
                    <span className="text-mute italic">someone</span>
                  )}{" "}
                  {e.detail}
                </span>
              </span>
              <time className="text-mute shrink-0 text-xs">{when(e.ts)}</time>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** `assigned` | `comment` | `status` — the three ways something reaches you. */
function KindIcon({ kind }: { kind: string }) {
  const cls = "size-3.5 text-mute";
  if (kind === "comment") return <MessageSquare className={cls} aria-label="Comment" />;
  if (kind === "assigned") return <AtSign className={cls} aria-label="Assigned to you" />;
  return <SignalHigh className={cls} aria-label="Status change" />;
}
