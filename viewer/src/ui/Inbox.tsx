import { useCallback, useEffect, useState } from "react";
import { AtSign, CheckCheck, Inbox as InboxIcon, MessageSquare, RotateCcw, SignalHigh } from "lucide-react";

import { rpc } from "../api";
import type { InboxEntry } from "../types";
import { ApplicationState, EmptyState, LoadingState } from "./AppState";
import { Button } from "./primitives";
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
  onOpen,
  onCountChange,
}: {
  spaceId: string;
  revision: number;
  onOpen: (reff: string) => void;
  onCountChange: (unread: number) => void;
}) {
  const [entries, setEntries] = useState<InboxEntry[] | null>(null);
  const [unread, setUnread] = useState(0);
  const [error, setError] = useState("");
  const [overrides, setOverrides] = useState(() => loadOverrides(spaceId));

  const load = useCallback(
    async (clear: boolean) => {
      try {
        const r = await rpc(spaceId, { cmd: "inbox", clear });
        if (r.kind !== "inbox") return;
        setEntries(r.entries);
        setError("");
        // `unread` in the reply is a snapshot from *before* the clear: the daemon
        // counts, then advances the watermark (`inbox::list` then
        // `inbox::mark_read`), so a `clear: true` reply says "this is what you
        // just marked read", not "this is what remains". Taking it literally
        // leaves the badge lit over an inbox the daemon already considers read.
        // Marking read has no doc to change, so no doorbell corrects it either.
        const now = clear ? 0 : r.unread;
        setUnread(now);
        onCountChange(now);
        if (clear) {
          setOverrides({ read: [], unread: [] });
          saveOverrides(spaceId, { read: [], unread: [] });
        }
      } catch (e) {
        const message = e instanceof Error ? e.message : String(e);
        setError(message);
      }
    },
    [spaceId, onCountChange],
  );

  // `clear: false` — reading the inbox must not silently mark it read. `clear`
  // advances the watermark (`inbox::mark_read`), which is a write wearing a
  // read's name; it happens when you *say* so, below.
  useEffect(() => {
    void load(false);
  }, [load, revision]);

  if (!entries) {
    if (error) {
      return (
        <ApplicationState
          kind="retry"
          title="Inbox unavailable"
          body={error}
          action={<Button onClick={() => void load(false)}><RotateCcw className="size-3.5" />Retry</Button>}
        />
      );
    }
    return (
      <LoadingState
        title="Loading inbox"
        body="Reading notifications from this local replica."
      />
    );
  }
  const read = new Set(overrides.read);
  const forcedUnread = new Set(overrides.unread);
  const keyOf = (entry: InboxEntry) => `${entry.doc_id}:${entry.ts}:${entry.kind}`;
  const isUnread = (entry: InboxEntry, index: number) =>
    forcedUnread.has(keyOf(entry)) || (index < unread && !read.has(keyOf(entry)));
  const unreadCount = entries.filter(isUnread).length;
  const groups = (["assigned", "comment", "status"] as const)
    .map((kind) => ({ kind, entries: entries.map((entry, index) => ({ entry, index })).filter(({ entry }) => entry.kind === kind) }))
    .filter((group) => group.entries.length > 0);
  const setReadState = (entry: InboxEntry, nextUnread: boolean) => {
    const key = keyOf(entry);
    const next = {
      read: nextUnread ? overrides.read.filter((item) => item !== key) : [...new Set([...overrides.read, key])],
      unread: nextUnread ? [...new Set([...overrides.unread, key])] : overrides.unread.filter((item) => item !== key),
    };
    setOverrides(next);
    saveOverrides(spaceId, next);
    const count = entries.filter((candidate, index) => {
      const candidateKey = keyOf(candidate);
      return next.unread.includes(candidateKey) || (index < unread && !next.read.includes(candidateKey));
    }).length;
    onCountChange(count);
  };

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="border-line flex h-9 shrink-0 items-center gap-3 border-b px-4">
        <span className="text-mute text-sm">
          {entries.length} {entries.length === 1 ? "item" : "items"}
          {unreadCount > 0 && <span className="text-accent"> · {unreadCount} unread</span>}
        </span>
        {unreadCount > 0 && (
          <button
            onClick={() => void load(true)}
            className="text-mute hover:text-fg ml-auto flex items-center gap-1.5 text-sm"
          >
            <CheckCheck className="size-3.5" />
            Mark {unreadCount === 1 ? "notification" : `all ${unreadCount} notifications`} read
          </button>
        )}
      </div>

      {entries.length === 0 ? (
        <EmptyState
          icon={<InboxIcon className="size-5" />}
          title="You’re all caught up"
          body="Nothing in this local space is currently addressed to you."
        />
      ) : (
        <div className="min-h-0 flex-1 overflow-y-auto">
          {groups.map((group) => (
            <section key={group.kind} aria-labelledby={`inbox-${group.kind}`}>
              <h2 id={`inbox-${group.kind}`} className="bg-raised/95 border-line text-mute sticky top-0 z-10 border-b px-4 py-1.5 text-2xs font-semibold uppercase">
                {causeLabel(group.kind)} · {group.entries.length}
              </h2>
              <ul>
              {group.entries.map(({ entry: e, index: i }) => (
            <li
              key={`${e.doc_id}-${e.ts}-${i}`}
              onClick={() => onOpen(e.reff)}
              className={[
                "border-line/60 hover:bg-hover flex cursor-default items-start gap-3 border-b px-4 py-2",
                // `unread` counts entries past the watermark, and they are the
                // newest — so the first N are the unread ones.
                isUnread(e, i) ? "bg-accent/5" : "",
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
              <button
                onClick={(event) => {
                  event.stopPropagation();
                  setReadState(e, !isUnread(e, i));
                }}
                className="text-mute hover:text-fg shrink-0 rounded px-1 text-xs"
                aria-label={`${isUnread(e, i) ? "Mark read" : "Mark unread on this device"}: ${e.title}`}
              >
                {isUnread(e, i) ? "Mark read" : "Mark unread"}
              </button>
            </li>
              ))}
              </ul>
            </section>
          ))}
        </div>
      )}
    </div>
  );
}

function causeLabel(kind: string): string {
  return { assigned: "Assignments", comment: "Comments and mentions", status: "Status changes" }[kind] ?? "Other";
}

interface ReadOverrides { read: string[]; unread: string[] }
const overrideKey = (spaceId: string) => `lait.inbox-read:${spaceId}`;
function loadOverrides(spaceId: string): ReadOverrides {
  try {
    return JSON.parse(localStorage.getItem(overrideKey(spaceId)) ?? '{"read":[],"unread":[]}');
  } catch {
    return { read: [], unread: [] };
  }
}
function saveOverrides(spaceId: string, value: ReadOverrides): void {
  try {
    localStorage.setItem(overrideKey(spaceId), JSON.stringify(value));
  } catch {
    // A storage-restricted browser still keeps the current in-memory choice.
  }
}

/** `assigned` | `comment` | `status` — the three ways something reaches you. */
function KindIcon({ kind }: { kind: string }) {
  const cls = "size-3.5 text-mute";
  if (kind === "comment") return <MessageSquare className={cls} aria-label="Comment" />;
  if (kind === "assigned") return <AtSign className={cls} aria-label="Assigned to you" />;
  return <SignalHigh className={cls} aria-label="Status change" />;
}
