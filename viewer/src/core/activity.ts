import type { ActivityEvent } from "../types";

/**
 * What an activity event *says*, and who it may name.
 *
 * There are now **two** feeds behind `ActivityEvent`, and they attribute
 * differently — conflating them is what rots this file:
 *
 * - **Per-issue history** (`Request::History`) reads the issue's oplog **on disk**
 *   (`engine::history`). Each change carries the real committer in `actor` (an
 *   ed25519 key) and a real `ts`; it survives daemon restarts and attributes a
 *   *teammate's* change to the teammate. `actor_nick` is **empty** here — the daemon
 *   no longer resolves it, so the client must resolve `actor` itself. There is no
 *   `synced` event in this feed; you see the actual ops.
 * - **Space activity** (`Request::Activity`) is still the per-session ring. A
 *   remote change arrives as one synthetic `synced` event stamped with the *local*
 *   node's key. That key is not the author, so `synced` must be rendered **without a
 *   name** — the exact non-goal-6 trap (in-doc attribution is advisory), which the
 *   inbox already avoids by never guessing an actor for non-comments.
 *
 * So attribution is one rule that covers both: resolve `actor` (a key) through the
 * caller's resolver — except `synced`, which has no honest name. The resolver lives
 * in the UI because that is where the member list is; this module stays dumb about
 * *how* a key becomes a name and only decides *whether* there is one to show.
 *
 * Most kinds also carry no words of their own (`text: ""`, `changes: []` for
 * `assigned`/`labeled`/`moved`/…), so the phrasing comes from here — the daemon
 * never wrote any.
 */

/** Resolve an actor key to a display name (member alias, "you", or a short key). */
export type NameResolver = (key: string) => string;

/** Present tense, third person, no trailing punctuation. */
const PHRASE: Readonly<Record<string, string>> = {
  created: "created the issue",
  edited: "edited",
  started: "started it",
  finished: "finished it",
  stopped: "stopped it",
  moved: "moved it",
  assigned: "added an assignee",
  unassigned: "removed an assignee",
  labeled: "changed labels",
  commented: "commented",
  deleted: "deleted the issue",
  member_added: "added a member",
  member_removed: "removed a member",
  // No name is attached to this one — see the module note.
  synced: "changed by a peer",
};

/**
 * The one kind whose actor is a real, in-document claim.
 *
 * A comment's author is written into the CRDT by whoever wrote it, so it survives
 * sync and means something on every node. History's per-op `actor` is now also a
 * genuine claim (it travels in the commit message), but it is still advisory
 * (non-goal 6) — which is fine, because attribution here is a display nicety, not an
 * authorization decision.
 */
const ATTRIBUTABLE = new Set(["commented"]);

/**
 * Who and what an event says.
 *
 * `actor` is `null` whenever there is no honest name — a `synced` event, or an event
 * with no actor at all. Callers render the phrase alone in that case rather than
 * substituting "someone", which would imply we know there was a someone and merely
 * lost the name.
 */
export function describeEvent(
  e: ActivityEvent,
  resolveName?: NameResolver,
): { actor: string | null; phrase: string } {
  const phrase = PHRASE[e.kind] ?? e.kind;

  // A remote change in the *activity* feed is stamped with the local node's key, so
  // there is no honest author to name — the whole reason this special case exists.
  if (e.kind === "synced") return { actor: null, phrase };

  // Otherwise `actor` is the real committer (history) or this node (its own ops).
  // Resolve the key to a name; the caller owns the fallback chain (alias → you →
  // short key), because it is the caller that holds the member list.
  if (e.actor && resolveName) return { actor: resolveName(e.actor), phrase };

  // No resolver available: the daemon-resolved nick is the only remaining signal,
  // and it is empty in the history feed — so this yields `null` there, which is
  // honest (a name we cannot supply) rather than wrong.
  const nick = e.actor_nick?.trim();
  return { actor: nick || null, phrase };
}

/** Whether this event's author is a claim the document itself carries. */
export const isAttributable = (e: ActivityEvent): boolean => ATTRIBUTABLE.has(e.kind);

/**
 * `status: backlog → done`, for the events that populate `changes`.
 *
 * No-op changes are dropped. The durable-history projection of a `created` event
 * lists *every* field, including ones that went `— → —` (a container that was
 * created empty: `comments`, an empty `description`). Rendering those is noise that
 * makes the one real change ("→ backlog") hard to find, so a change whose before and
 * after read the same is omitted.
 */
export function describeChanges(e: ActivityEvent): string {
  return e.changes
    .filter((c) => (c.from ?? "—") !== (c.to ?? "—"))
    .map((c) => `${c.field}: ${c.from ?? "—"} → ${c.to ?? "—"}`)
    .join(", ");
}
