import { describe, expect, it } from "vitest";

import type { ActivityEvent, InboxEntry } from "../types";
import {
  defaultInboxPreferences,
  groupActivity,
  inboxEntryKey,
  visibleInboxEntries,
} from "./inbox";

const entry = (kind: string, ts: number): InboxEntry => ({
  kind,
  ts,
  reff: `VIEW-${ts}`,
  doc_id: String(ts),
  title: "Title",
  detail: "changed",
});

const event = (reff: string, ts: number, seq: number): ActivityEvent => ({
  reff,
  ts,
  seq,
  doc_id: String(seq),
  kind: "edited",
  changes: [],
  actor: null,
  actor_nick: "",
  text: "",
  collision: false,
});

describe("inbox presentation", () => {
  it("filters disabled causes and active snoozes without discarding entries", () => {
    const assigned = entry("assigned", 1);
    const comment = entry("comment", 2);
    const preferences = defaultInboxPreferences();
    preferences.kinds.comment = false;
    preferences.snoozed[inboxEntryKey(assigned)] = 100;
    expect(visibleInboxEntries([assigned, comment], preferences, 50)).toEqual([]);
    expect(visibleInboxEntries([assigned, comment], preferences, 101)).toEqual([assigned]);
  });

  it("groups adjacent changes to one issue within a short activity burst", () => {
    const groups = groupActivity([
      event("VIEW-1", 100, 1),
      event("VIEW-1", 250, 2),
      event("VIEW-2", 260, 3),
      event("VIEW-1", 700, 4),
    ]);
    expect(groups.map((group) => group.events.length)).toEqual([2, 1, 1]);
  });
});
