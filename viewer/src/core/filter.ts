import type { BoardView, Row } from "../types";

/**
 * Filtering — two kinds, deliberately not one.
 *
 * **Text** is ours: a live match over what is already on screen (title, ref,
 * alias). It is cosmetic, instant, and costs no round trip.
 *
 * **`mine` / `label` are the daemon's**, and this is the rule worth stating because
 * it is so tempting to break: those semantics are *server truth* and are never
 * re-implemented here. "Mine" means what the ACL says it means; a label is a
 * `LabelId` the daemon resolved, not a string we matched. So the client asks `list`
 * with a `Filter`, gets back the rows that qualify, and **intersects the board by
 * doc-id** (UI.md §5.2). The board keeps its own ordering — `Catalog.boards[P]` is
 * the authority (A§9) — and the filter only ever removes.
 *
 * Guessing at "mine" client-side would be a second implementation of an
 * authorization question, and it would be wrong in exactly the cases that matter.
 *
 * ## Why `status` is client-side, when this file used to say it wasn't
 *
 * The rule above named `status` alongside `mine` and `label`, from before either was
 * built. It does not belong there, for two reasons — and the second is decisive:
 *
 * 1. **There is no semantic to preserve.** `Row.status` is a status id the daemon
 *    put there, and `WorkflowState.id` is a status id the daemon put there.
 *    Comparing them re-derives nothing — it is the identical operation the daemon
 *    performs (`replica.rs:1333-1339` is `r.status == s`, exact string equality on
 *    the same cached row). Contrast `mine`, which is an authorization question, and
 *    `label`, which is a resolution step. Neither has an analogue here.
 * 2. **`Filter.status` is `Option<String>` — one status, or none.** A status filter
 *    worth having is multi-select ("Backlog *and* In Progress"), and the daemon's
 *    type cannot express it. Routing through `list` would mean either one status at
 *    a time or N requests intersected client-side, which is a client-side filter
 *    wearing a round trip.
 *
 * So status selects **columns**, not rows, and it is the one filter that may empty
 * the board's structure — because unlike the others, the user named the statuses
 * they wanted. The "a status that exists is a column that exists" rule below is
 * about *incidental* emptiness (a text filter matching nothing in Done); it was
 * never about a column the user explicitly deselected.
 */

export interface FilterState {
  /** Live text over title/ref/alias. Client-side. */
  text: string;
  /** Only issues assigned to me. Daemon-resolved. */
  mine: boolean;
  /** A label name. Daemon-resolved to a LabelId. */
  label: string | null;
  /** Status ids to show. Empty means all — see the module note. Client-side. */
  status: readonly string[];
  /** Priorities to show. Empty means all. Client-side, like `status`: the row
   *  already carries the priority the daemon put there, so matching re-derives
   *  nothing. */
  priority: readonly string[];
  /** Assignee keys to show (rows assigned to ANY selected key). Empty means all.
   *  Client-side: the row carries its assignee keys, so this is a set membership
   *  test, not the ACL question `mine` answers. */
  assignees: readonly string[];
}

export const EMPTY_FILTER: FilterState = {
  text: "",
  mine: false,
  label: null,
  status: [],
  priority: [],
  assignees: [],
};

/** Whether anything is narrowing the view. */
export const isActive = (f: FilterState): boolean =>
  f.text.trim() !== "" ||
  f.mine ||
  f.label !== null ||
  f.status.length > 0 ||
  f.priority.length > 0 ||
  f.assignees.length > 0;

/** Whether the daemon has to be asked — i.e. the parts we refuse to guess at. */
export const needsServer = (f: FilterState): boolean => f.mine || f.label !== null;

/**
 * Case-insensitive expression over title/ref/alias.
 * Whitespace is AND, `|` separates OR branches, and `-term` excludes a term.
 */
export function matchesText(row: Row, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  const haystack = [row.title, row.reff, row.key_alias ?? ""].join(" ").toLowerCase();
  return q.split("|").some((branch) => {
    const terms = branch.trim().split(/\s+/).filter(Boolean);
    return terms.length > 0 && terms.every((term) =>
      term.startsWith("-") && term.length > 1
        ? !haystack.includes(term.slice(1))
        : haystack.includes(term),
    );
  });
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
 *
 * `f.status` is the one exception, and it is not a contradiction: there the user
 * *named* the columns they wanted, so dropping the rest is the request rather than
 * a side effect. The rule above is about columns emptied by accident.
 */
export function applyFilter(
  board: BoardView,
  f: FilterState,
  allowed: ReadonlySet<string> | null,
): BoardView {
  if (!isActive(f) && allowed === null) return board;
  const wanted = f.status.length > 0 ? new Set(f.status) : null;
  return {
    ...board,
    columns: board.columns
      .filter((c) => wanted === null || wanted.has(c.state.id))
      .map((c) => ({
        ...c,
        rows: c.rows.filter(
          (r) =>
            matchesText(r, f.text) &&
            (allowed === null || allowed.has(r.doc_id)) &&
            (f.priority.length === 0 || f.priority.includes(r.priority)) &&
            (f.assignees.length === 0 || r.assignees.some((a) => f.assignees.includes(a))),
        ),
      })),
  };
}

/** Total visible rows, tombstones excluded. */
export const countRows = (board: BoardView): number =>
  board.columns.reduce((n, c) => n + c.rows.filter((r) => !r.tombstone).length, 0);
