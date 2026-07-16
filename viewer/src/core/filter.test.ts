import { describe, expect, it } from "vitest";

import { applyFilter, countRows, EMPTY_FILTER, isActive, matchesText, needsServer } from "./filter";
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

describe("text filter", () => {
  const r = row({ reff: "iss_abc", key_alias: "ENG-12", title: "Fix the login race" });

  it("matches title, ref, and alias, case-insensitively", () => {
    expect(matchesText(r, "login")).toBe(true);
    expect(matchesText(r, "LOGIN")).toBe(true);
    expect(matchesText(r, "iss_ab")).toBe(true);
    expect(matchesText(r, "eng-12")).toBe(true);
    expect(matchesText(r, "nope")).toBe(false);
  });

  it("treats an empty or whitespace query as no filter", () => {
    expect(matchesText(r, "")).toBe(true);
    expect(matchesText(r, "   ")).toBe(true);
  });

  it("survives a row with no alias", () => {
    expect(matchesText(row({ reff: "iss_x", title: "hi" }), "hi")).toBe(true);
    expect(matchesText(row({ reff: "iss_x", title: "hi" }), "ENG")).toBe(false);
  });
});

describe("what the daemon must answer", () => {
  it("asks the server only for semantics we refuse to guess at", () => {
    expect(needsServer(EMPTY_FILTER)).toBe(false);
    // Text is ours — it must never cost a round trip.
    expect(needsServer({ ...EMPTY_FILTER, text: "login" })).toBe(false);
    // "Mine" is an authorization question; a label is a resolved LabelId.
    expect(needsServer({ ...EMPTY_FILTER, mine: true })).toBe(true);
    expect(needsServer({ ...EMPTY_FILTER, label: "bug" })).toBe(true);
  });

  it("knows when anything is narrowing the view", () => {
    expect(isActive(EMPTY_FILTER)).toBe(false);
    expect(isActive({ ...EMPTY_FILTER, text: "  " })).toBe(false);
    expect(isActive({ ...EMPTY_FILTER, text: "x" })).toBe(true);
    expect(isActive({ ...EMPTY_FILTER, mine: true })).toBe(true);
  });
});

describe("applyFilter", () => {
  const b = board([
    row({ reff: "iss_1", status: "backlog", title: "Fix login" }),
    row({ reff: "iss_2", status: "backlog", title: "Add logout" }),
    row({ reff: "iss_3", status: "done", title: "Ship it" }),
  ]);

  it("narrows by text without touching column structure", () => {
    const out = applyFilter(b, { ...EMPTY_FILTER, text: "log" }, null);
    expect(countRows(out)).toBe(2);
    // A status that exists is a column that exists: making it vanish would say
    // the workflow changed when only the view did.
    expect(out.columns).toHaveLength(2);
    expect(out.columns[1]!.rows).toHaveLength(0);
  });

  it("intersects by doc-id, never re-deriving what the daemon decided", () => {
    const allowed = new Set(["doc_iss_3"]);
    const out = applyFilter(b, { ...EMPTY_FILTER, mine: true }, allowed);
    expect(countRows(out)).toBe(1);
    expect(out.columns[1]!.rows[0]!.reff).toBe("iss_3");
  });

  it("combines text and server filter", () => {
    const allowed = new Set(["doc_iss_1", "doc_iss_2"]);
    const out = applyFilter(b, { ...EMPTY_FILTER, text: "logout", mine: true }, allowed);
    expect(countRows(out)).toBe(1);
  });

  it("distinguishes 'the daemon wasn't asked' from 'the daemon said none'", () => {
    // The bug this prevents: treating a missing set as an empty one renders an
    // unfiltered board as empty — and it looks exactly like "you have no issues".
    expect(countRows(applyFilter(b, EMPTY_FILTER, null))).toBe(3);
    expect(countRows(applyFilter(b, { ...EMPTY_FILTER, mine: true }, new Set()))).toBe(0);
  });

  it("returns the board untouched when nothing is filtering", () => {
    expect(applyFilter(b, EMPTY_FILTER, null)).toBe(b);
  });
});
