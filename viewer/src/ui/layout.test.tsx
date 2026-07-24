import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { Breadcrumbs, IssueCrumb, ProjectCrumb, WorkspaceCrumb } from "./layout";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;

describe("Breadcrumbs", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  it("climbs from ancestors only, and drops a chevron with the crumb it belongs to", () => {
    const openWorkspace = vi.fn();
    const openProject = vi.fn();
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);

    act(() => {
      root?.render(
        <Breadcrumbs
          items={[
            {
              key: "workspace",
              label: "Nova",
              optional: true,
              content: <WorkspaceCrumb name="Nova" />,
              onNavigate: openWorkspace,
            },
            {
              key: "project",
              optional: true,
              content: <ProjectCrumb name="Engine" color="#f00" />,
              onNavigate: openProject,
            },
            { key: "issue", content: <IssueCrumb id="ENG-12" title="Ship it" /> },
          ]}
        />,
      );
    });

    const crumbs = [...host.querySelectorAll("li")];
    expect(crumbs).toHaveLength(3);

    // Every ancestor climbs; the leaf is where you already are.
    const links = [...host.querySelectorAll("button")];
    expect(links).toHaveLength(2);
    act(() => links[0]!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    act(() => links[1]!.dispatchEvent(new MouseEvent("click", { bubbles: true })));
    expect(openWorkspace).toHaveBeenCalledOnce();
    expect(openProject).toHaveBeenCalledOnce();

    // Exactly one "you are here", and it is the last crumb.
    const current = host.querySelectorAll('[aria-current="page"]');
    expect(current).toHaveLength(1);
    expect(current[0]?.textContent).toBe("ENG-12Ship it");

    // The separator lives inside the crumb *before* it, so an ancestor that
    // collapses on a narrow surface takes its chevron with it and the trail
    // never opens with a stray ›.
    expect(crumbs.map((li) => li.querySelectorAll("svg.lucide-chevron-right").length))
      .toEqual([1, 1, 0]);
    // Only ancestors may collapse.
    expect(crumbs.filter((li) => li.className.includes("hidden"))).toHaveLength(2);
  });
});
