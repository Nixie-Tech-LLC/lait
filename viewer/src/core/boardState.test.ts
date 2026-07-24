import { beforeEach, describe, expect, it } from "vitest";
import { loadBoardScroll, saveBoardScroll } from "./boardState";

describe("board window state", () => {
  beforeEach(() => localStorage.clear());

  it("persists horizontal position per project and recovers from bad storage", () => {
    saveBoardScroll("a", 241.7);
    saveBoardScroll("b", 19);
    expect(loadBoardScroll("a")).toBe(242);
    expect(loadBoardScroll("b")).toBe(19);
    localStorage.setItem("lait.board-scroll.bad", "not-a-number");
    expect(loadBoardScroll("bad")).toBe(0);
  });
});
