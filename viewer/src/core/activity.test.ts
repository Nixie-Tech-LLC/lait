/**
 * Attribution.
 *
 * The one invariant here is worth more than the phrasing: **`synced` must never
 * carry a name.** `push_activity` stamps `actor: Some(self.me)` on every event it
 * records, including the one that fires when a *teammate's* change arrives over the
 * wire — so rendering `actor_nick` literally credits you with alice's edit. The
 * schema calls in-doc attribution advisory (S non-goal 6) and the inbox already
 * refuses to guess (`actor: None` for everything but comments). This is the same
 * refusal, on the other surface.
 */

import { describe, expect, it } from "vitest";

import type { ActivityEvent } from "../types";
import { describeChanges, describeEvent, isAttributable } from "./activity";

const ev = (over: Partial<ActivityEvent> = {}): ActivityEvent => ({
  seq: 1,
  doc_id: "doc1",
  reff: "ENG-1",
  kind: "edited",
  changes: [],
  actor: "a".repeat(64),
  actor_nick: "alice",
  text: "",
  ts: 1000,
  collision: false,
  ...over,
});

describe("attribution", () => {
  it("never names an actor for a synced event, even though the DTO carries one", () => {
    // The trap: `actor_nick` is populated and looks perfectly usable. It is the
    // *local* node's nick, and the change was someone else's.
    const e = ev({ kind: "synced", actor_nick: "alice" });
    expect(e.actor_nick).toBe("alice"); // the DTO says so…
    expect(describeEvent(e).actor).toBeNull(); // …and we decline to repeat it
    expect(describeEvent(e).phrase).toBe("changed by a peer");
  });

  it("names the actor for an operation this node really performed", () => {
    expect(describeEvent(ev({ kind: "started" })).actor).toBe("alice");
  });

  it("treats an empty nick as no name rather than printing a blank", () => {
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
    // These arrive with `text: ""` and `changes: []` — only `kind` is populated,
    // so a UI that renders the struct literally prints a name and nothing else.
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
    // `Request` is add-only (S§9 rule 1): a future verb will show up here before
    // this table learns about it. Showing "frobnicated" beats showing nothing.
    expect(describeEvent(ev({ kind: "frobnicated" })).phrase).toBe("frobnicated");
  });

  it("renders changes as from → to", () => {
    const e = ev({ changes: [{ field: "status", from: "backlog", to: "done" }] });
    expect(describeChanges(e)).toBe("status: backlog → done");
  });

  it("shows an em dash for a field that had no previous value", () => {
    const e = ev({ changes: [{ field: "priority", from: null, to: "high" }] });
    expect(describeChanges(e)).toBe("priority: — → high");
  });
});
