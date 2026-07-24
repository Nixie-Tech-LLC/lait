import * as Popover from "@radix-ui/react-popover";
import { useCallback, useEffect, useRef, useState } from "react";
import { AtSign, CheckCheck, Inbox as InboxIcon, MessageSquare, RotateCcw, Settings2, SignalHigh, Timer } from "lucide-react";

import { rpc } from "../api";
import {
  defaultInboxPreferences,
  inboxEntryKey,
  type InboxKind,
  type InboxPreferences,
  visibleInboxEntries,
} from "../core/inbox";
import type { InboxEntry } from "../types";
import { ApplicationState, EmptyState, LoadingState } from "./AppState";
import { Combobox } from "./Picker";
import { Button, Checkbox, IconButton, InlineAction, interactiveRow, PopoverContent } from "./primitives";
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
  const [preferences, setPreferences] = useState(() => loadPreferences(spaceId));
  const [activeKey, setActiveKey] = useState(() => loadContext(spaceId).active);
  const scrollRef = useRef<HTMLDivElement>(null);

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

  useEffect(() => {
    const scroll = scrollRef.current;
    if (!scroll) return;
    const context = loadContext(spaceId);
    scroll.scrollTop = context.scroll;
    if (context.active) {
      requestAnimationFrame(() =>
        scroll.querySelector<HTMLElement>(`[data-inbox-key="${CSS.escape(context.active)}"]`)?.focus(),
      );
    }
  }, [spaceId, entries]);

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
  const keyOf = inboxEntryKey;
  const isUnread = (entry: InboxEntry, index: number) =>
    forcedUnread.has(keyOf(entry)) || (index < unread && !read.has(keyOf(entry)));
  const unreadCount = entries.filter(isUnread).length;
  const now = Date.now();
  const visible = visibleInboxEntries(entries, preferences, now);
  const indexed = visible.map((entry) => ({ entry, index: entries.indexOf(entry) }));
  const groups = preferences.grouping === "cause"
    ? (["assigned", "comment", "status"] as const)
      .map((kind) => ({ kind, entries: indexed.filter(({ entry }) => entry.kind === kind) }))
      .filter((group) => group.entries.length > 0)
    : [{ kind: "chronological" as const, entries: indexed }];
  const snoozedCount = entries.filter((entry) => (preferences.snoozed[keyOf(entry)] ?? 0) > now).length;
  const savePreferences = (next: InboxPreferences) => {
    setPreferences(next);
    persistPreferences(spaceId, next);
  };
  const snooze = (entry: InboxEntry) => {
    savePreferences({
      ...preferences,
      snoozed: { ...preferences.snoozed, [keyOf(entry)]: Date.now() + 60 * 60 * 1000 },
    });
  };
  const openEntry = (entry: InboxEntry) => {
    const key = keyOf(entry);
    setActiveKey(key);
    saveContext(spaceId, { active: key, scroll: scrollRef.current?.scrollTop ?? 0 });
    onOpen(entry.reff);
  };
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
          <Button
            onClick={() => void load(true)}
            className="ml-auto"
          >
            <CheckCheck className="size-3.5" />
            Mark {unreadCount === 1 ? "notification" : `all ${unreadCount} notifications`} read
          </Button>
        )}
        <Popover.Root>
          <Popover.Trigger asChild>
            <Button className="ml-auto" aria-label="Inbox preferences">
              <Settings2 className="size-3.5" /> Preferences
            </Button>
          </Popover.Trigger>
          <PopoverContent align="end" sideOffset={6} className="w-64 p-3">
              <h2 className="mb-1 text-sm font-medium">Inbox preferences</h2>
              <p className="text-mute mb-3 text-xs">Local controls for what is shown on this device. The daemon still delivers the complete feed.</p>
              {(["assigned", "comment", "status"] as InboxKind[]).map((kind) => (
                <label key={kind} className="hover:bg-hover flex min-h-8 items-center gap-2 rounded px-1.5 text-sm">
                  <Checkbox
                    checked={preferences.kinds[kind]}
                    onCheckedChange={(checked) => savePreferences({
                      ...preferences,
                      kinds: { ...preferences.kinds, [kind]: checked === true },
                    })}
                  />
                  {causeLabel(kind)}
                </label>
              ))}
              <div className="bg-line my-2 h-px" />
              <span className="text-mute block text-xs">Group notifications</span>
              <div className="mt-1">
                <Combobox
                  label="Group notifications"
                  value={{
                    id: preferences.grouping,
                    label: preferences.grouping === "cause" ? "By cause" : "Chronologically",
                  }}
                  options={[
                    { id: "cause", label: "By cause" },
                    { id: "chronological", label: "Chronologically" },
                  ]}
                  onPick={(id) =>
                    savePreferences({ ...preferences, grouping: id as InboxPreferences["grouping"] })
                  }
                />
              </div>
              {snoozedCount > 0 && <InlineAction onClick={() => savePreferences({ ...preferences, snoozed: {} })} className="mt-3">Restore {snoozedCount} snoozed</InlineAction>}
          </PopoverContent>
        </Popover.Root>
      </div>

      {entries.length === 0 ? (
        <EmptyState
          icon={<InboxIcon className="size-5" />}
          title="You’re all caught up"
          body="Nothing in this local space is currently addressed to you."
        />
      ) : visible.length === 0 ? (
        <EmptyState icon={<InboxIcon className="size-5" />} title="No notifications match" body="Adjust local preferences or restore snoozed notifications." />
      ) : (
        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
          {groups.map((group) => (
            <section key={group.kind} aria-labelledby={`inbox-${group.kind}`}>
              <h2 id={`inbox-${group.kind}`} className="bg-raised/95 border-line text-mute sticky top-0 z-10 border-b px-4 py-1.5 text-2xs font-semibold uppercase">
                {causeLabel(group.kind)} · {group.entries.length}
              </h2>
              <ul>
              {group.entries.map(({ entry: e, index: i }) => (
            <li
              key={`${e.doc_id}-${e.ts}-${i}`}
              data-inbox-key={keyOf(e)}
              tabIndex={activeKey === keyOf(e) || (!activeKey && i === indexed[0]?.index) ? 0 : -1}
              aria-current={activeKey === keyOf(e) ? "true" : undefined}
              onFocus={() => setActiveKey(keyOf(e))}
              onClick={() => openEntry(e)}
              onKeyDown={(event) => {
                const rows = [...(scrollRef.current?.querySelectorAll<HTMLElement>("[data-inbox-key]") ?? [])];
                const position = rows.indexOf(event.currentTarget);
                if (event.key === "ArrowDown" || event.key.toLowerCase() === "j") {
                  event.preventDefault(); event.stopPropagation(); rows[Math.min(rows.length - 1, position + 1)]?.focus();
                } else if (event.key === "ArrowUp" || event.key.toLowerCase() === "k") {
                  event.preventDefault(); event.stopPropagation(); rows[Math.max(0, position - 1)]?.focus();
                } else if (event.key === "Enter") {
                  event.preventDefault(); event.stopPropagation(); openEntry(e);
                } else if (event.key.toLowerCase() === "m") {
                  event.preventDefault(); event.stopPropagation(); setReadState(e, !isUnread(e, i));
                } else if (event.key.toLowerCase() === "s") {
                  event.preventDefault(); event.stopPropagation(); snooze(e);
                }
              }}
              className={[
                interactiveRow({ density: "normal" }),
                "group flex items-start gap-3 px-4 py-2",
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
              <Button
                onClick={(event) => {
                  event.stopPropagation();
                  setReadState(e, !isUnread(e, i));
                }}
                aria-label={`${isUnread(e, i) ? "Mark read" : "Mark unread on this device"}: ${e.title}`}
              >
                {isUnread(e, i) ? "Mark read" : "Mark unread"}
              </Button>
              <IconButton label={`Snooze for one hour: ${e.title}`} onClick={(event) => { event.stopPropagation(); snooze(e); }} className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100">
                <Timer className="size-3.5" />
              </IconButton>
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
  return { assigned: "Assignments", comment: "Comments and mentions", status: "Status changes", chronological: "Latest" }[kind] ?? "Other";
}

const preferencesKey = (spaceId: string) => `lait.inbox-preferences:${spaceId}`;
function loadPreferences(spaceId: string): InboxPreferences {
  try {
    const saved = JSON.parse(localStorage.getItem(preferencesKey(spaceId)) ?? "null") as Partial<InboxPreferences> | null;
    const defaults = defaultInboxPreferences();
    return saved ? { ...defaults, ...saved, kinds: { ...defaults.kinds, ...saved.kinds }, snoozed: saved.snoozed ?? {} } : defaults;
  } catch {
    return defaultInboxPreferences();
  }
}
function persistPreferences(spaceId: string, value: InboxPreferences): void {
  try { localStorage.setItem(preferencesKey(spaceId), JSON.stringify(value)); } catch { /* memory remains authoritative */ }
}

interface InboxContext { active: string; scroll: number }
const contextKey = (spaceId: string) => `lait.inbox-context:${spaceId}`;
function loadContext(spaceId: string): InboxContext {
  try { return JSON.parse(sessionStorage.getItem(contextKey(spaceId)) ?? '{"active":"","scroll":0}'); }
  catch { return { active: "", scroll: 0 }; }
}
function saveContext(spaceId: string, value: InboxContext): void {
  try { sessionStorage.setItem(contextKey(spaceId), JSON.stringify(value)); } catch { /* restoration is best effort */ }
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
