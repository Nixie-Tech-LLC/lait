import { describe, expect, it } from "vitest";

import { applyOverlay, Overlay, PREDICTION_TTL_MS } from "./overlay";
import type { BoardView, Row } from "../types";

const row = (over: Partial<Row> & { reff: string }): Row => ({
  doc_id: `doc_${over.reff}`,
  project_id: "prj_1",
  key_alias: null,
  title: "",
  status: "backlog",
  priority: "none",
  assignee_summary: "",
  tombstone: false,
  provisional: false,
  ...over,
});

const board = (rows: Row[]): BoardView => ({
  schema_version: 1,
  project: { id: "prj_1", name: "P", key: "P", color: "blue" },
  columns: [
    {
      state: { id: "backlog", name: "Backlog", category: "backlog", color: "gray" },
      rows: rows.filter((r) => r.status === "backlog"),
    },
    {
      state: { id: "done", name: "Done", category: "done", color: "green" },
      rows: rows.filter((r) => r.status === "done"),
    },
  ],
});

describe("the overlay", () => {
  it("holds and returns a prediction per (doc, field)", () => {
    const o = new Overlay();
    o.set("doc_1", "title", "predicted");
    expect(o.get("doc_1", "title")).toBe("predicted");
    expect(o.get("doc_1", "status")).toBeUndefined();
    expect(o.has("doc_1")).toBe(true);
    expect(o.has("doc_2")).toBe(false);
  });

  it("clears a whole doc, which is all the doorbell knows how to say", () => {
    // The doorbell names docs, not fields — `dirty_by_project` is doc-ids. So
    // clearing has to be doc-granular or it couldn't be driven by it.
    const o = new Overlay();
    o.set("doc_1", "title", "a");
    o.set("doc_1", "status", "done");
    o.set("doc_2", "title", "b");
    o.clearDoc("doc_1");
    expect(o.has("doc_1")).toBe(false);
    expect(o.has("doc_2")).toBe(true);
  });

  it("expires a prediction whose request never came back", () => {
    // The TUI could do without this: against a local socket, a request that
    // neither errors nor rings is near-impossible. A browser is not that — a
    // dropped fetch would otherwise show a value that exists nowhere, forever.
    const o = new Overlay();
    const t0 = 1_000_000;
    o.set("doc_1", "title", "stuck", t0);

    expect(o.sweep(t0 + PREDICTION_TTL_MS - 1)).toBe(false);
    expect(o.has("doc_1")).toBe(true);

    expect(o.sweep(t0 + PREDICTION_TTL_MS)).toBe(true);
    expect(o.has("doc_1")).toBe(false);
    expect(o.size).toBe(0);
  });

  it("sweeps only what is stale", () => {
    const o = new Overlay();
    const t0 = 1_000_000;
    o.set("doc_1", "title", "old", t0);
    o.set("doc_2", "title", "fresh", t0 + PREDICTION_TTL_MS);
    o.sweep(t0 + PREDICTION_TTL_MS);
    expect(o.has("doc_1")).toBe(false);
    expect(o.has("doc_2")).toBe(true);
  });
});

describe("applyOverlay", () => {
  const b = board([
    row({ reff: "iss_1", status: "backlog", title: "One" }),
    row({ reff: "iss_2", status: "backlog", title: "Two" }),
    row({ reff: "iss_3", status: "done", title: "Three" }),
  ]);

  it("is a no-op with nothing predicted — same object, no re-render churn", () => {
    const out = applyOverlay(b, new Overlay());
    expect(out.board).toBe(b);
    expect(out.optimistic.size).toBe(0);
  });

  it("makes the prediction the displayed value, not a hint", () => {
    const o = new Overlay();
    o.set("doc_iss_1", "title", "Predicted title");
    const { board: out, optimistic } = applyOverlay(b, o);
    expect(out.columns[0]!.rows[0]!.title).toBe("Predicted title");
    // …and says so. A prediction that isn't marked is a lie.
    expect(optimistic.has("doc_iss_1")).toBe(true);
  });

  it("re-buckets a predicted status into its new column", () => {
    // The whole point: a card that claims to have moved must actually move, or
    // the optimism is worse than none.
    const o = new Overlay();
    o.set("doc_iss_1", "status", "done");
    const { board: out } = applyOverlay(b, o);
    expect(out.columns[0]!.rows.map((r) => r.reff)).toEqual(["iss_2"]);
    expect(out.columns[1]!.rows.map((r) => r.reff)).toEqual(["iss_3", "iss_1"]);
  });

  it("never disappears a row whose predicted status has no column", () => {
    // A wrong guess must be corrected by the doorbell, not vanish the issue.
    const o = new Overlay();
    o.set("doc_iss_1", "status", "nonexistent_status");
    const { board: out } = applyOverlay(b, o);
    const all = out.columns.flatMap((c) => c.rows.map((r) => r.reff));
    expect(all).toContain("iss_1");
    expect(all).toHaveLength(3);
  });

  it("leaves unpredicted rows untouched, in their column and order", () => {
    const o = new Overlay();
    o.set("doc_iss_1", "title", "changed");
    const { board: out } = applyOverlay(b, o);
    expect(out.columns[1]!.rows.map((r) => r.title)).toEqual(["Three"]);
    expect(out.columns[0]!.rows.map((r) => r.reff)).toEqual(["iss_1", "iss_2"]);
  });

  it("predicts priority", () => {
    const o = new Overlay();
    o.set("doc_iss_1", "priority", "urgent");
    const { board: out } = applyOverlay(b, o);
    expect(out.columns[0]!.rows[0]!.priority).toBe("urgent");
  });
});
