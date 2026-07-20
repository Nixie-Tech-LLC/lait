/**
 * The work verbs' target resolution.
 *
 * This is a deliberate second copy of a daemon rule (`replica.rs::first_state_in`),
 * kept only to feed the optimistic overlay — so the tests that matter are the ones
 * pinning *which* rule it copies. "First in list order matching the category" is not
 * "the state whose id is `in_progress`", and a workflow that renames or reorders its
 * states is exactly where the difference shows up.
 */

import { describe, expect, it } from "vitest";

import type { WorkflowState } from "../types";
import { firstStateIn, neighbourState, workTarget } from "./workflow";

const s = (id: string, category: WorkflowState["category"]): WorkflowState => ({
  id,
  name: id,
  category,
  color: "gray",
});

/** The seeded default (`dto.rs::default_workflow`). */
const DEFAULT: WorkflowState[] = [
  s("backlog", "backlog"),
  s("in_progress", "active"),
  s("in_review", "active"),
  s("done", "done"),
];

describe("work verb targets", () => {
  it("resolves the default workflow the way the daemon does", () => {
    expect(workTarget(DEFAULT, "start")?.id).toBe("in_progress");
    expect(workTarget(DEFAULT, "done")?.id).toBe("done");
    expect(workTarget(DEFAULT, "stop")?.id).toBe("backlog");
  });

  it("picks the FIRST state in a category, not a state named after the verb", () => {
    // The whole point: `start` means "first active", so a workflow that opens with
    // Triage starts there — even though a state literally called `in_progress`
    // exists further down. Hard-coding the id would silently do the wrong thing.
    const custom = [s("backlog", "backlog"), s("triage", "active"), s("in_progress", "active")];
    expect(workTarget(custom, "start")?.id).toBe("triage");
  });

  it("follows list order, because list order is what the daemon walks", () => {
    const reordered = [s("in_review", "active"), s("in_progress", "active")];
    expect(firstStateIn(reordered, "active")?.id).toBe("in_review");
  });

  it("returns null when the workflow has no state in that category", () => {
    // The daemon refuses with "this space's workflow has no done-category status".
    // There is nothing honest to predict, so the caller sends and shows its words.
    const noDone = [s("backlog", "backlog"), s("in_progress", "active")];
    expect(workTarget(noDone, "done")).toBeNull();
  });
});

describe("neighbouring status", () => {
  it("steps to the adjacent column", () => {
    expect(neighbourState(DEFAULT, "in_progress", 1)?.id).toBe("in_review");
    expect(neighbourState(DEFAULT, "in_progress", -1)?.id).toBe("backlog");
  });

  it("clamps rather than wraps — a wrap is indistinguishable from a mis-key", () => {
    expect(neighbourState(DEFAULT, "done", 1)).toBeNull();
    expect(neighbourState(DEFAULT, "backlog", -1)).toBeNull();
  });

  it("returns null for a status that isn't in the workflow at all", () => {
    // A row can carry a status the board has no column for — the daemon validates
    // on write, but a synced doc from a peer with a different workflow need not.
    expect(neighbourState(DEFAULT, "cancelled", 1)).toBeNull();
  });
});
