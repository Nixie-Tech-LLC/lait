import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";

import { DEFAULT_DISPLAY } from "../core/display";
import type { BoardView } from "../types";
import { Board } from "./Board";
import { TooltipProvider } from "./primitives";

(globalThis as typeof globalThis & { IS_REACT_ACT_ENVIRONMENT: boolean })
  .IS_REACT_ACT_ENVIRONMENT = true;
Element.prototype.scrollIntoView = vi.fn();

// The board must never render as a silent grid of empty columns when a filter
// (classically a leftover `mine` from "My issues") is what emptied it — that was
// the "boards empty despite containing issues" bug.
describe("Board filtered-empty state", () => {
  let host: HTMLDivElement | null = null;
  let root: ReturnType<typeof createRoot> | null = null;

  afterEach(() => {
    if (root) act(() => root?.unmount());
    host?.remove();
    root = null;
    host = null;
  });

  const board: BoardView = {
    schema_version: 1,
    project: { id: "prj_x", name: "X", key: "X", color: "blue", description: "", lead: "", start_date: null, target_date: null, archived: false },
    columns: [
      { state: { id: "backlog", name: "Backlog", category: "backlog", color: "gray" }, rows: [] },
      { state: { id: "done", name: "Done", category: "done", color: "green" }, rows: [] },
    ],
  };

  function mount(props: Partial<Parameters<typeof Board>[0]>) {
    host = document.createElement("div");
    document.body.append(host);
    root = createRoot(host);
    act(() =>
      root?.render(
        <TooltipProvider>
          <Board
            board={board}
            display={DEFAULT_DISPLAY}
            members={[]}
            labels={[]}
            selection={null}
            optimistic={new Set()}
            onSelect={() => undefined}
            onCreate={() => undefined}
            onDrop={() => undefined}
            onReassign={() => undefined}
            onEdit={() => undefined}
            readOnly={false}
            filtered={false}
            onClearFilter={() => undefined}
            {...props}
          />
        </TooltipProvider>,
      ),
    );
  }

  it("offers a Clear filter action when a filter has hidden every issue", () => {
    const onClearFilter = vi.fn();
    mount({ filtered: true, onClearFilter });

    const state = host!.querySelector('[data-application-state="filtered-empty"]');
    expect(state).toBeTruthy();
    const clear = [...host!.querySelectorAll("button")].find((b) => /clear filter/i.test(b.textContent ?? ""));
    expect(clear).toBeTruthy();
    act(() => clear!.click());
    expect(onClearFilter).toHaveBeenCalledOnce();
  });

  it("shows the columns (not the filtered state) when no filter is active", () => {
    mount({ filtered: false });
    expect(host!.querySelector('[data-application-state="filtered-empty"]')).toBeNull();
    expect(host!.querySelector('[aria-label="Issue board"]')).toBeTruthy();
  });
});
