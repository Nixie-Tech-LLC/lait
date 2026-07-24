import { describe, expect, it } from "vitest";

import { DEFAULT_ROUTE, formatRoute, loadLastRoute, parseRoute, resolveLocalSpace, sameRoute, saveLastRoute } from "./route";
import type { SpaceRow } from "../types";

describe("viewer routes", () => {
  it("uses the neutral list route for non-viewer paths", () => {
    expect(parseRoute({ pathname: "/", search: "" })).toEqual(DEFAULT_ROUTE);
    expect(parseRoute({ pathname: "/assets/app.js", search: "" })).toEqual(DEFAULT_ROUTE);
  });

  it("round-trips canonical product identity without local machine state", () => {
    const route = {
      spaceId: "ws_alpha/beta",
      project: "LAIT WEB",
      view: "board" as const,
      issue: "iss_42/7",
    };
    const href = formatRoute(route);

    expect(href).toBe(
      "/spaces/ws_alpha%2Fbeta/board?project=LAIT+WEB&issue=iss_42%2F7",
    );
    expect(parseRoute(new URL(href, "http://lait.local"))).toEqual(route);
    expect(href).not.toMatch(/token|seed|path|daemon/i);
  });

  it("falls back to list for unknown views and ignores empty selections", () => {
    expect(
      parseRoute({ pathname: "/spaces/ws_1/not-a-view", search: "?project=&issue=%20" }),
    ).toEqual({ spaceId: "ws_1", project: null, view: "list", issue: null });
  });

  it("round-trips a legible applied filter", () => {
    const href = formatRoute({
      spaceId: "ws_1",
      project: "WEB",
      view: "list",
      issue: null,
      filter: { text: "login bug", mine: true, label: "customer", status: ["todo", "doing"], priority: [], assignees: [] },
    });
    expect(parseRoute(new URL(href, "http://lait.local")).filter).toEqual({
      text: "login bug",
      mine: true,
      label: "customer",
      status: ["todo", "doing"],
      priority: [],
      assignees: [],
    });
  });

  it("does not carry an issue selection onto surfaces that cannot display it", () => {
    expect(
      parseRoute({ pathname: "/spaces/ws_1/inbox", search: "?issue=iss_1" }),
    ).toEqual({ spaceId: "ws_1", project: null, view: "inbox", issue: null });
    expect(
      formatRoute({ spaceId: "ws_1", project: null, view: "inbox", issue: "iss_1" }),
    ).toBe("/spaces/ws_1/inbox");
  });

  it("does not carry project scope onto workspace destinations", () => {
    expect(
      parseRoute({ pathname: "/spaces/ws_1/settings", search: "?project=WEB&q=stale&mine=1" }),
    ).toEqual({ spaceId: "ws_1", project: null, view: "settings", issue: null });
    expect(
      formatRoute({
        spaceId: "ws_1",
        project: "WEB",
        view: "settings",
        issue: null,
        filter: {
          text: "stale",
          mine: true,
          label: null,
          status: [],
          priority: [],
          assignees: [],
        },
      }),
    ).toBe("/spaces/ws_1/settings");
  });

  it("redirects legacy members routes into the settings shell", () => {
    expect(
      parseRoute({ pathname: "/spaces/ws_1/members", search: "?project=WEB" }),
    ).toEqual({ spaceId: "ws_1", project: null, view: "settings", issue: null });
  });

  it("round-trips the durable project portfolio destination", () => {
    const href = formatRoute({
      spaceId: "ws_1",
      project: null,
      view: "projects",
      issue: null,
    });
    expect(href).toBe("/spaces/ws_1/projects");
    expect(parseRoute(new URL(href, "http://lait.local"))).toMatchObject({
      spaceId: "ws_1",
      view: "projects",
      issue: null,
    });
  });

  it("round-trips focused detail only when an issue can be displayed", () => {
    const focused = formatRoute({
      spaceId: "ws_1", project: "WEB", view: "list", issue: "iss_1", focused: true,
    });
    expect(focused).toBe("/spaces/ws_1/list?project=WEB&issue=iss_1&focus=1");
    expect(parseRoute(new URL(focused, "http://lait.local")).focused).toBe(true);
    expect(formatRoute({ spaceId: "ws_1", project: null, view: "activity", issue: null, focused: true }))
      .toBe("/spaces/ws_1/activity");
  });

  it("compares every shareable route dimension", () => {
    const route = { spaceId: "ws_1", project: "WEB", view: "list" as const, issue: "iss_1" };
    expect(sameRoute(route, { ...route })).toBe(true);
    expect(sameRoute(route, { ...route, issue: "iss_2" })).toBe(false);
    expect(sameRoute(route, { ...route, focused: true })).toBe(false);
  });

  it("resolves canonical identity to a local target and prefers our actor", () => {
    const own = space("local-path-hash-own", "ws_shared", { kind: "own" });
    const agent = space("local-path-hash-agent", "ws_shared", { kind: "agent", name: "bot" });
    expect(resolveLocalSpace("ws_shared", [agent, own])).toBe(own);
    expect(resolveLocalSpace("ws_missing", [own])).toBeNull();
  });

  it("chooses the most recently opened replica deterministically", () => {
    const older = { ...space("own-a", "ws_shared", { kind: "own" }), last_opened: 10 };
    const newer = { ...space("own-b", "ws_shared", { kind: "own" }), last_opened: 20 };
    const agent = { ...space("agent", "ws_shared", { kind: "agent", name: "bot" }), last_opened: 30 };

    expect(resolveLocalSpace("ws_shared", [older, agent, newer])).toBe(newer);
    expect(resolveLocalSpace("ws_shared", [older, agent])).toBe(older);
  });

  it("restores the last canonical workspace without storing a local handle", () => {
    localStorage.clear();
    const route = { spaceId: "ws_shared", project: "WEB", view: "board" as const, issue: "iss_1" };
    saveLastRoute(route);
    expect(loadLastRoute()).toEqual(route);
    expect(localStorage.getItem("lait.last-route")).not.toContain("local-path-hash");
  });
});

function space(id: string, canonical: string, identity: SpaceRow["identity"]): SpaceRow {
  return {
    id,
    space: canonical,
    name: canonical,
    path: `C:/${id}`,
    origin: "test",
    last_opened: 0,
    status: "up",
    identity,
    projects: [],
  };
}
