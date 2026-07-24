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
  assignees: [],
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

  it("supports AND, OR, and negation without a server round trip", () => {
    expect(matchesText(r, "login race")).toBe(true);
    expect(matchesText(r, "login -race")).toBe(false);
    expect(matchesText(r, "logout | ENG-12")).toBe(true);
    expect(matchesText(r, "logout | settings")).toBe(false);
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

  it("does not ask the server about status", () => {
    // Status is an id-to-id comparison over data the daemon already handed us —
    // there is no semantic to preserve, and `Filter.status` is single-valued so it
    // could not express a multi-select anyway. See the note in filter.ts.
    expect(needsServer({ ...EMPTY_FILTER, status: ["backlog", "done"] })).toBe(false);
  });

  it("knows when anything is narrowing the view", () => {
    expect(isActive(EMPTY_FILTER)).toBe(false);
    expect(isActive({ ...EMPTY_FILTER, text: "  " })).toBe(false);
    expect(isActive({ ...EMPTY_FILTER, text: "x" })).toBe(true);
    expect(isActive({ ...EMPTY_FILTER, mine: true })).toBe(true);
    expect(isActive({ ...EMPTY_FILTER, status: ["done"] })).toBe(true);
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

describe("the status filter selects columns", () => {
  const b = board([
    row({ reff: "iss_1", status: "backlog", title: "Fix login" }),
    row({ reff: "iss_2", status: "backlog", title: "Add logout" }),
    row({ reff: "iss_3", status: "done", title: "Ship it" }),
  ]);

  it("drops the columns you didn't ask for", () => {
    // The one filter allowed to change the board's structure: you named the
    // statuses, so the others are not "empty" — they are not part of the question.
    const out = applyFilter(b, { ...EMPTY_FILTER, status: ["done"] }, null);
    expect(out.columns).toHaveLength(1);
    expect(out.columns[0]!.state.id).toBe("done");
    expect(countRows(out)).toBe(1);
  });

  it("keeps every column when no status is selected", () => {
    expect(applyFilter(b, { ...EMPTY_FILTER, status: [] }, null).columns).toHaveLength(2);
  });

  it("is multi-select — the thing the daemon's Option<String> cannot express", () => {
    const out = applyFilter(b, { ...EMPTY_FILTER, status: ["backlog", "done"] }, null);
    expect(out.columns).toHaveLength(2);
    expect(countRows(out)).toBe(3);
  });

  it("keeps a selected column that a text filter emptied", () => {
    // The distinction the module note draws: `status` chose the column, `text`
    // emptied it. The column stays, because the workflow did not change.
    const out = applyFilter(b, { ...EMPTY_FILTER, status: ["done"], text: "zzz" }, null);
    expect(out.columns).toHaveLength(1);
    expect(countRows(out)).toBe(0);
  });

  it("composes with a server filter without re-deriving it", () => {
    const allowed = new Set(["doc_iss_1"]);
    const out = applyFilter(b, { ...EMPTY_FILTER, status: ["backlog"], mine: true }, allowed);
    expect(countRows(out)).toBe(1);
    expect(out.columns[0]!.rows[0]!.reff).toBe("iss_1");
  });
});
