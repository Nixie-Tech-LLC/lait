import type { BoardView, Row } from "../types";

/**
 * Filtering — two kinds, deliberately not one.
 *
 * **Text** is ours: a live match over what is already on screen (title, ref,
 * alias). It is cosmetic, instant, and costs no round trip.
 *
 * **`mine` / `label` / `status` are the daemon's**, and this is the rule worth
 * stating because it is so tempting to break: those semantics are *server truth*
 * and are never re-implemented here. "Mine" means what the ACL says it means;
 * a label is a `LabelId` the daemon resolved, not a string we matched. So the
 * client asks `list` with a `Filter`, gets back the rows that qualify, and
 * **intersects the board by doc-id** (UI.md §5.2). The board keeps its own
 * ordering — `Catalog.boards[P]` is the authority (A§9) — and the filter only ever
 * removes.
 *
 * Guessing at "mine" client-side would be a second implementation of an
 * authorization question, and it would be wrong in exactly the cases that matter.
 */

export interface FilterState {
  /** Live text over title/ref/alias. Client-side. */
  text: string;
  /** Only issues assigned to me. Daemon-resolved. */
  mine: boolean;
  /** A label name. Daemon-resolved to a LabelId. */
  label: string | null;
}

export const EMPTY_FILTER: FilterState = { text: "", mine: false, label: null };

/** Whether anything is narrowing the view. */
export const isActive = (f: FilterState): boolean =>
  f.text.trim() !== "" || f.mine || f.label !== null;

/** Whether the daemon has to be asked — i.e. the parts we refuse to guess at. */
export const needsServer = (f: FilterState): boolean => f.mine || f.label !== null;

/** Case-insensitive match over the fields a human would type. */
export function matchesText(row: Row, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return (
    row.title.toLowerCase().includes(q) ||
    row.reff.toLowerCase().includes(q) ||
    (row.key_alias?.toLowerCase().includes(q) ?? false)
  );
}

/**
 * Narrow a board.
 *
 * `allowed` is the doc-id set from a daemon-side `list`; `null` means "the daemon
 * wasn't asked", which is not the same as "the daemon said nothing qualifies" —
 * conflating those two is how an unfiltered board renders empty.
 *
 * Columns are kept even when they empty out: a status that exists is a column
 * that exists, and making it vanish under a filter would tell you the workflow
 * changed when only the view did.
 */
export function applyFilter(
  board: BoardView,
  f: FilterState,
  allowed: ReadonlySet<string> | null,
): BoardView {
  if (!isActive(f) && allowed === null) return board;
  return {
    ...board,
    columns: board.columns.map((c) => ({
      ...c,
      rows: c.rows.filter(
        (r) => matchesText(r, f.text) && (allowed === null || allowed.has(r.doc_id)),
      ),
    })),
  };
}

/** Total visible rows, tombstones excluded. */
export const countRows = (board: BoardView): number =>
  board.columns.reduce((n, c) => n + c.rows.filter((r) => !r.tombstone).length, 0);
