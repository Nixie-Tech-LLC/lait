import { beforeEach, describe, expect, it } from "vitest";

import {
  loadFavoriteProjects,
  loadRecentIssues,
  loadRecentSearches,
  rememberRecentIssue,
  rememberRecentSearch,
  toggleFavoriteProject,
} from "./personalNav";

describe("private personal navigation", () => {
  beforeEach(() => localStorage.clear());

  it("scopes project favorites to a canonical space", () => {
    expect(toggleFavoriteProject("ws_a", "NAV")).toEqual(["NAV"]);
    expect(loadFavoriteProjects("ws_a")).toEqual(["NAV"]);
    expect(loadFavoriteProjects("ws_b")).toEqual([]);
    expect(toggleFavoriteProject("ws_a", "NAV")).toEqual([]);
  });

  it("keeps recent issues unique and most-recent first", () => {
    rememberRecentIssue("ws_a", "NAV-1");
    rememberRecentIssue("ws_a", "VIEW-2");
    rememberRecentIssue("ws_a", "NAV-1");
    expect(loadRecentIssues("ws_a")).toEqual(["NAV-1", "VIEW-2"]);
  });

  it("normalizes, deduplicates, and bounds recent searches per space", () => {
    for (const query of [" alpha ", "beta", "ALPHA", "gamma", "delta", "epsilon", "zeta", "eta"]) {
      rememberRecentSearch("ws_1", query);
    }
    expect(loadRecentSearches("ws_1")).toEqual(["eta", "zeta", "epsilon", "delta", "gamma", "ALPHA"]);
    expect(loadRecentSearches("ws_2")).toEqual([]);
  });

  it("recovers safely from damaged local preferences", () => {
    localStorage.setItem("lait.favorite-projects", "not json");
    expect(loadFavoriteProjects("ws_a")).toEqual([]);
  });
});
