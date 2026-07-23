import type { BoardView, Priority, Row, WorkflowState } from "../types";
import { PRIORITY_ORDER } from "../types";

/**
 * Display options — how the list is *arranged*, as opposed to what is *in* it
 * (that is `core/filter.ts`'s job, and the line between them is the same one
 * Linear draws: filters change membership, display options change shape).
 *
 * Everything here is client-side rearrangement of rows the daemon already
 * ordered. That is safe for the same reason status filtering is (see filter.ts):
 * `Row.status`/`priority`/`assignees` are values the daemon put on the row, and
 * regrouping them re-derives nothing. Board *position* stays the daemon's — the
 * `board` order is `Catalog.boards[P]`'s answer and is never re-sorted, only
 * left alone (`order: "board"`) or deliberately replaced by a different axis the
 * user named.
 */

export type GroupBy = "status" | "assignee" | "priority" | "none";
export type OrderBy = "board" | "priority" | "title";

export interface DisplayState {
  group: GroupBy;
  order: OrderBy;
  /** Show tombstoned rows (the trash, inline) — off is the normal reading. */
  deleted: boolean;
}

export const DEFAULT_DISPLAY: DisplayState = { group: "status", order: "board", deleted: false };

const STORAGE_KEY = "lait.display";
const SCOPED_STORAGE_KEY = "lait.display.scoped";

/** Persisted per browser, like the sidebar width: an arrangement you chose once
 *  should survive a reload. Unknown values fall back rather than throw. */
export function loadDisplay(scope?: string): DisplayState {
  try {
    const scoped = scope
      ? (JSON.parse(localStorage.getItem(SCOPED_STORAGE_KEY) ?? "{}") as Record<string, DisplayState>)[scope]
      : undefined;
    const raw = scoped ? JSON.stringify(scoped) : localStorage.getItem(STORAGE_KEY);
    if (!raw) return DEFAULT_DISPLAY;
    const parsed = JSON.parse(raw) as Partial<DisplayState>;
    return {
      group: (["status", "assignee", "priority", "none"] as const).includes(
        parsed.group as GroupBy,
      )
        ? (parsed.group as GroupBy)
        : DEFAULT_DISPLAY.group,
      order: (["board", "priority", "title"] as const).includes(parsed.order as OrderBy)
        ? (parsed.order as OrderBy)
        : DEFAULT_DISPLAY.order,
      deleted: parsed.deleted === true,
    };
  } catch {
    return DEFAULT_DISPLAY;
  }
}

export function saveDisplay(d: DisplayState, scope?: string): void {
  try {
    if (!scope) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(d));
      return;
    }
    const all = JSON.parse(localStorage.getItem(SCOPED_STORAGE_KEY) ?? "{}") as Record<string, DisplayState>;
    all[scope] = d;
    localStorage.setItem(SCOPED_STORAGE_KEY, JSON.stringify(all));
  } catch {
    // Storage may be full or blocked; the arrangement still applies this session.
  }
}

/** One rendered group. `state` is set when the group *is* a workflow column. */
export interface RowGroup {
  key: string;
  kind: GroupBy;
  /** Group label — a status name, a priority, or an assignee KEY (the caller
   *  resolves keys to names; this module has no member list on purpose). */
  label: string;
  rows: Row[];
  state?: WorkflowState;
}

const UNASSIGNED = "";

/**
 * Arrange a board's rows into display groups.
 *
 * Rows arrive in board order (column by column, positions inside each), and that
 * order is preserved within every group unless a different `order` was named.
 * Grouping by assignee uses the *first* assignee — a multi-assignee issue lives
 * in one group, not several, because a row that appears twice breaks j/k motion
 * and selection identity.
 */
export function groupRows(board: BoardView, display: DisplayState): RowGroup[] {
  if (display.group === "status") {
    return board.columns.map((c) => ({
      key: c.state.id,
      kind: "status" as const,
      label: c.state.name,
      rows: order(c.rows, display.order),
      state: c.state,
    }));
  }

  const all = board.columns.flatMap((c) => c.rows);
  if (display.group === "none") {
    return [{ key: "all", kind: "none", label: "All issues", rows: order(all, display.order) }];
  }

  const buckets = new Map<string, Row[]>();
  const keyOf = (r: Row): string =>
    display.group === "priority" ? r.priority : (r.assignees[0] ?? UNASSIGNED);
  for (const r of all) {
    const k = keyOf(r);
    buckets.set(k, [...(buckets.get(k) ?? []), r]);
  }

  const keys =
    display.group === "priority"
      ? // Highest first — the scan starts where the urgency does.
        [...PRIORITY_ORDER].reverse().filter((p) => buckets.has(p))
      : // Assignees in first-appearance order; the unassigned bucket last.
        [...buckets.keys()].sort((a, b) =>
          a === UNASSIGNED ? 1 : b === UNASSIGNED ? -1 : 0,
        );

  return keys.map((k) => ({
    key: k || "unassigned",
    kind: display.group,
    label: display.group === "priority" ? k : k === UNASSIGNED ? "Unassigned" : k,
    rows: order(buckets.get(k) ?? [], display.order),
  }));
}

function order(rows: Row[], by: OrderBy): Row[] {
  switch (by) {
    case "board":
      return rows;
    case "priority": {
      const rank = (p: Priority) => PRIORITY_ORDER.indexOf(p);
      // Stable, so equal priorities keep their board order.
      return [...rows].sort((a, b) => rank(b.priority) - rank(a.priority));
    }
    case "title":
      return [...rows].sort((a, b) => a.title.localeCompare(b.title));
  }
}
