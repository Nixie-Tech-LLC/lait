import { act } from "react";
import { useState } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import type { RowGroup } from "../core/display";
import type { Row, WorkflowState } from "../types";
import { IssueList } from "./IssueList";
import { TooltipProvider } from "./primitives";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = vi.fn();

describe("IssueList semantics", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  it("separates current issue semantics from bulk checkboxes and opens with Enter", () => {
    const onOpen = vi.fn();
    const current = row("LIST-1");
    render(current, onOpen);

    const item = host!.querySelector("li[aria-current=true]") as HTMLLIElement;
    expect(item.tabIndex).toBe(0);
    expect(host!.querySelector('[role="listbox"], [role="option"]')).toBeNull();
    expect(host!.querySelector('[role="checkbox"][aria-label="Select LIST-1"]')).toBeTruthy();
    act(() => item.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true })));
    expect(onOpen).toHaveBeenCalledWith(current.reff);
  });

  it("extends bulk selection across a shift-clicked range", () => {
    const toggled = vi.fn();
    const rows = [row("LIST-1"), row("LIST-2"), row("LIST-3")];
    const state: WorkflowState = { id: "backlog", name: "Backlog", category: "backlog", color: "gray" };
    function Harness() {
      const [checked, setChecked] = useState<ReadonlySet<string>>(new Set());
      return (
        <IssueList
          groups={[{ key: "backlog", kind: "status", label: "Backlog", rows, state }]}
          deleted={[]}
          deletedMode={false}
          states={[state]}
          members={[]}
          selection={rows[0]!.reff}
          checked={checked}
          optimistic={new Set()}
          onSelect={() => undefined}
          onToggleCheck={(reff) => {
            toggled(reff);
            setChecked((current) => {
              const next = new Set(current);
              if (!next.delete(reff)) next.add(reff);
              return next;
            });
          }}
          onOpen={() => undefined}
          onCreate={() => undefined}
          readOnly={false}
          filtered={false}
        />
      );
    }
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    act(() => root?.render(
      <TooltipProvider>
        <Harness />
      </TooltipProvider>,
    ));

    const checks = [...host.querySelectorAll<HTMLButtonElement>('[role="checkbox"]')];
    act(() => checks[0]!.click());
    act(() => checks[2]!.dispatchEvent(new MouseEvent("click", { bubbles: true, shiftKey: true })));
    expect(toggled.mock.calls.map(([reff]) => reff)).toEqual(rows.map((item) => item.reff));
  });

  function render(current: Row, onOpen: (reff: string) => void) {
    const state: WorkflowState = { id: "backlog", name: "Backlog", category: "backlog", color: "gray" };
    const groups: RowGroup[] = [{ key: "backlog", kind: "status", label: "Backlog", rows: [current], state }];
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    act(() => root?.render(
      <TooltipProvider>
        <IssueList
          groups={groups}
          deleted={[]}
          deletedMode={false}
          states={[state]}
          members={[]}
          selection={current.reff}
          checked={new Set()}
          optimistic={new Set()}
          onSelect={() => undefined}
          onToggleCheck={() => undefined}
          onOpen={onOpen}
          onCreate={() => undefined}
          readOnly={false}
          filtered={false}
        />
      </TooltipProvider>,
    ));
  }
});

function row(key: string): Row {
  return {
    reff: `iss_${key.toLowerCase()}`,
    doc_id: `iss_${key.toLowerCase()}`,
    project_id: "prj_list",
    key_alias: key,
    title: "Tune list density",
    status: "backlog",
    priority: "high",
    assignee_summary: "",
    assignees: [],
    tombstone: false,
    provisional: false,
  };
}
