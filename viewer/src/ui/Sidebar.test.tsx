import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { ProjectDto, SpaceRow } from "../types";
import { Sidebar } from "./Sidebar";
import { TooltipProvider } from "./primitives";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("Sidebar navigation", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  it("keeps workspace destinations global and enters project work through a project", () => {
    const onGo = vi.fn();
    const onMyIssues = vi.fn();
    const onPickProject = vi.fn();
    const onSearch = vi.fn();
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);

    act(() => {
      root?.render(
        <TooltipProvider><Sidebar
          spaces={[space]}
          current={space.id}
          projects={[project]}
          currentProject={project.key}
          view="list"
          unread={3}
          favoriteProjects={[]}
          savedViews={[]}
          onPickSpace={vi.fn()}
          onSearch={onSearch}
          onPickProject={onPickProject}
          onGo={onGo}
          onMyIssues={onMyIssues}
          onApplySavedView={vi.fn()}
          onToggleFavorite={vi.fn()}
          onCreateProject={vi.fn()}
        /></TooltipProvider>,
      );
    });

    click("Projects");
    expect(onGo).toHaveBeenCalledWith("projects");
    click("Roadmap");
    expect(onGo).toHaveBeenCalledWith("timeline");
    click("My issues");
    expect(onMyIssues).toHaveBeenCalledOnce();
    click("Search issues");
    expect(onSearch).toHaveBeenCalledOnce();
    click("Web");
    expect(onPickProject).toHaveBeenCalledWith("WEB");
    click("Workspace settings");
    expect(onGo).toHaveBeenCalledWith("settings");
    expect(host.textContent).toContain("3");
    expect([...host.querySelectorAll("button")].some((item) => item.textContent?.includes("Board"))).toBe(false);
    expect([...host.querySelectorAll("button")].some((item) => item.textContent?.includes("Activity"))).toBe(false);
    expect(host.querySelector("summary button")).toBeNull();
  });

  function click(label: string) {
    const button = [...host!.querySelectorAll("button")].find(
      (item) => item.textContent?.includes(label) || item.getAttribute("aria-label") === label,
    );
    expect(button).toBeTruthy();
    act(() => button?.click());
  }
});

const space: SpaceRow = {
  id: "local-hash",
  space: "ws_test",
  name: "Test space",
  path: "C:/test",
  origin: "test",
  last_opened: 0,
  status: "up",
  identity: { kind: "own" },
  projects: [],
};

const project: ProjectDto = {
  id: "prj_test",
  key: "WEB",
  name: "Web",
  color: "blue",
};
