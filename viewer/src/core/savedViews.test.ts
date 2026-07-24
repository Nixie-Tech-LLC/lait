import { beforeEach, describe, expect, it } from "vitest";

import { DEFAULT_DISPLAY } from "./display";
import { EMPTY_FILTER } from "./filter";
import { loadSavedViews, removeView, saveView } from "./savedViews";

describe("private local saved views", () => {
  beforeEach(() => localStorage.clear());

  it("scopes views by canonical space and project", () => {
    saveView("ws_a", "WEB", { id: "mine", name: "Mine", filter: { ...EMPTY_FILTER, mine: true }, display: DEFAULT_DISPLAY });
    expect(loadSavedViews("ws_a", "WEB")).toHaveLength(1);
    expect(loadSavedViews("ws_a", "API")).toEqual([]);
    expect(loadSavedViews("ws_b", "WEB")).toEqual([]);
  });

  it("replaces by id and removes without affecting other scopes", () => {
    saveView("ws_a", "WEB", { id: "mine", name: "Mine", filter: EMPTY_FILTER, display: DEFAULT_DISPLAY });
    saveView("ws_a", "WEB", { id: "mine", name: "Assigned", filter: EMPTY_FILTER, display: DEFAULT_DISPLAY });
    expect(loadSavedViews("ws_a", "WEB")[0]?.name).toBe("Assigned");
    removeView("ws_a", "WEB", "mine");
    expect(loadSavedViews("ws_a", "WEB")).toEqual([]);
  });
});
