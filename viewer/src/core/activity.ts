import type { ActivityEvent } from "../types";

/**
 * What an activity event *says* — and, more importantly, who it may name.
 *
 * Two facts about `ActivityEvent` drive everything here, and both are easy to get
 * wrong by rendering the struct literally:
 *
 * **1. Most kinds carry no words.** `push_activity` is called with `text: ""` and
 * `changes: vec![]` for `assigned`, `unassigned`, `labeled`, `moved`, `deleted` and
 * `synced` — only `kind` is populated. A UI that renders `{actor} {text}` prints a
 * bare name and nothing else, which reads as a glitch. The phrasing has to come from
 * the client, because the daemon never wrote any.
 *
 * **2. `actor` is the node, not the author.** `push_activity` stamps
 * `actor: Some(self.me)` unconditionally — *including on `synced`*, which is the
 * event that fires when a **teammate's** change arrives over the wire
 * (`tracker.rs:2033`). Rendering `actor_nick` for a `synced` event credits you with
 * an edit alice made. That is not a rounding error; it is the exact failure the
 * schema's non-goal 6 warns about (in-doc attribution is advisory) and that the
 * inbox already avoids by setting `actor: None` for everything but comments
 * (`dto.rs:276-293`).
 *
 * So: `synced` is rendered **without a name**, because there is no honest one to
 * give. The activity ring is this node's log of its own operations; a remote change
 * appears in it only as the fact that one arrived.
 */

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
 * sync and means something on every node. Nothing else does.
 */
const ATTRIBUTABLE = new Set(["commented"]);

/**
 * `actor` is `null` whenever we cannot honestly name someone. Callers render the
 * phrase alone in that case rather than substituting "someone", which would imply we
 * know there was a someone and merely lost the name.
 */
export function describeEvent(e: ActivityEvent): { actor: string | null; phrase: string } {
  const phrase = PHRASE[e.kind] ?? e.kind;

  // `synced` means "a change arrived from a peer" — the local node performed the
  // import, so `actor` is us, but the *change* is someone else's and we have no way
  // to know whose.
  if (e.kind === "synced") return { actor: null, phrase };

  // Everything else in the ring was performed by this node, so its actor is real —
  // it is literally the identity that signed the operation. Comments additionally
  // carry an in-doc author, which is the only claim that survives a sync.
  const nick = e.actor_nick?.trim();
  return { actor: nick ? nick : null, phrase };
}

/** Whether this event's author is a claim the document itself carries. */
export const isAttributable = (e: ActivityEvent): boolean => ATTRIBUTABLE.has(e.kind);

/** `status: backlog → done`, for the events that populate `changes`. */
export function describeChanges(e: ActivityEvent): string {
  return e.changes.map((c) => `${c.field}: ${c.from ?? "—"} → ${c.to ?? "—"}`).join(", ");
}
