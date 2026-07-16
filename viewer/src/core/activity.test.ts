/**
 * Attribution.
 *
 * Two invariants, both load-bearing, both burned by a real bug:
 *
 * 1. **`synced` never carries a name — even with a resolver.** In the workspace
 *    Activity feed a remote change is one synthetic event stamped with the *local*
 *    node's key, so resolving that key would credit you with a teammate's edit.
 * 2. **History attribution reads `actor`, not `actor_nick`.** The durable history
 *    feed leaves `actor_nick` empty and puts the real committer's key in `actor`;
 *    a client that reads `actor_nick` for the name shows nothing. (This is exactly
 *    what regressed when the engine moved history onto the oplog — the guard in
 *    `tests/viewer_read_contract` catches it engine-side; these tests pin the
 *    client half.)
 */

import { describe, expect, it } from "vitest";

import type { ActivityEvent } from "../types";
import { describeChanges, describeEvent, isAttributable } from "./activity";

const ALICE = "a".repeat(64);
const BOB = "b".repeat(64);

const ev = (over: Partial<ActivityEvent> = {}): ActivityEvent => ({
  seq: 1,
  doc_id: "doc1",
  reff: "ENG-1",
  kind: "edited",
  changes: [],
  actor: ALICE,
  // Empty, mirroring the durable-history feed. Local Activity-feed ops still
  // populate it, which the fallback below covers.
  actor_nick: "",
  text: "",
  ts: 1000,
  collision: false,
  ...over,
});

/** A stand-in for the UI's member resolver: known keys get names, others a stub. */
const resolve = (key: string) => (key === ALICE ? "alice" : key === BOB ? "bob" : "someone");

describe("attribution", () => {
  it("never names a synced event, even with a resolver that would name its key", () => {
    // The load-bearing invariant. `actor` is the local node's key, which the
    // resolver *could* name — that is precisely the trap.
    const e = ev({ kind: "synced", actor: ALICE });
    expect(describeEvent(e, resolve).actor).toBeNull();
    expect(describeEvent(e, resolve).phrase).toBe("changed by a peer");
  });

  it("resolves the real committer from `actor`, not `actor_nick`", () => {
    // The durable-history shape: actor_nick empty, actor is the key. Reading
    // actor_nick (as the client used to) would show no name; resolving actor works.
    const e = ev({ kind: "edited", actor: BOB, actor_nick: "" });
    expect(describeEvent(e, resolve).actor).toBe("bob");
  });

  it("attributes a teammate's change to the teammate, not the viewer", () => {
    // The whole point of durable, attributed history: a change alice made shows as
    // alice on bob's machine, because her key travels with the op.
    const e = ev({ kind: "started", actor: ALICE });
    expect(describeEvent(e, resolve).actor).toBe("alice");
  });

  it("falls back to actor_nick when no resolver is supplied", () => {
    // The Activity feed's local ops still populate actor_nick; a caller without a
    // member list (or a defensive one) should still get a name.
    expect(describeEvent(ev({ actor_nick: "alice" })).actor).toBe("alice");
  });

  it("yields no name when neither a resolver nor a nick is available", () => {
    expect(describeEvent(ev({ actor_nick: "" })).actor).toBeNull();
    expect(describeEvent(ev({ actor_nick: "   " })).actor).toBeNull();
  });

  it("counts only comments as document-carried attribution", () => {
    expect(isAttributable(ev({ kind: "commented" }))).toBe(true);
    expect(isAttributable(ev({ kind: "assigned" }))).toBe(false);
    expect(isAttributable(ev({ kind: "synced" }))).toBe(false);
  });
});

describe("phrasing", () => {
  it("supplies words for the kinds the daemon sends bare", () => {
    for (const kind of ["assigned", "unassigned", "labeled", "moved", "deleted"]) {
      const { phrase } = describeEvent(ev({ kind }));
      expect(phrase).not.toBe("");
      expect(phrase).not.toBe(kind);
    }
  });

  it("distinguishes adding from removing an assignee, since changes[] is empty", () => {
    expect(describeEvent(ev({ kind: "assigned" })).phrase).toBe("added an assignee");
    expect(describeEvent(ev({ kind: "unassigned" })).phrase).toBe("removed an assignee");
  });

  it("falls back to the raw kind rather than dropping an event it doesn't know", () => {
    expect(describeEvent(ev({ kind: "frobnicated" })).phrase).toBe("frobnicated");
  });
});

describe("changes", () => {
  it("renders changes as from → to", () => {
    const e = ev({ changes: [{ field: "status", from: "backlog", to: "done" }] });
    expect(describeChanges(e)).toBe("status: backlog → done");
  });

  it("shows an em dash for a field that had no previous value", () => {
    const e = ev({ changes: [{ field: "priority", from: null, to: "high" }] });
    expect(describeChanges(e)).toBe("priority: — → high");
  });

  it("drops no-op changes — the durable `created` event lists empty containers", () => {
    // A `created` event projects every field; ones created empty read `— → —`
    // (comments, an empty description) and are noise that hides the real change.
    const e = ev({
      kind: "created",
      changes: [
        { field: "status", from: null, to: "backlog" },
        { field: "comments", from: null, to: null },
        { field: "description", from: null, to: null },
      ],
    });
    expect(describeChanges(e)).toBe("status: — → backlog");
  });

  it("keeps a change whose value genuinely changed to empty", () => {
    // `x → —` is a real transition (a field cleared); only `— → —` is a no-op.
    const e = ev({ changes: [{ field: "title", from: "old", to: null }] });
    expect(describeChanges(e)).toBe("title: old → —");
  });
});
