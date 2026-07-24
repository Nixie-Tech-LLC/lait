import { describe, expect, it } from "vitest";

import type { BoardColumn } from "../types";
import { boardMovePosition } from "./Board";

describe("accessible board movement", () => {
  it("uses an ordered tail for live columns and append semantics for done", () => {
    expect(boardMovePosition(column("active"))).toEqual({ at: "bottom" });
    expect(boardMovePosition(column("done"))).toBeNull();
  });
});

function column(category: BoardColumn["state"]["category"]): BoardColumn {
  return {
    state: { id: category, name: category, category, color: "slate" },
    rows: [],
  };
}
