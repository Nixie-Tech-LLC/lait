import { useEffect, useRef } from "react";
import { Plus } from "lucide-react";

import type { BoardColumn, BoardView, Row } from "../types";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { IconButton, Kbd } from "./primitives";

/**
 * The default view: one flat, grouped list.
 *
 * Grouped **by status**, which costs nothing — `BoardView.columns` are already
 * status buckets with their rows in board order, so the list and the board are two
 * renderings of one fetch rather than two round trips.
 *
 * The density is the feature. Rows are a fixed 32px with a fixed column rhythm, so
 * the eye tracks straight down the ids and the titles without re-finding them on
 * each line — which is exactly what stops being true the moment a row grows to fit
 * its content.
 */
export function IssueList({
  board,
  selection,
  optimistic,
  onSelect,
  onOpen,
  onCreate,
  readOnly,
}: {
  board: BoardView;
  selection: string | null;
  /** Docs carrying an unconfirmed local prediction. */
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onOpen: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
}) {
  const total = board.columns.reduce((n, c) => n + visible(c).length, 0);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="text-mute border-line border-b px-4 py-2 text-sm">
        {total} {total === 1 ? "issue" : "issues"}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {board.columns.map((col) => (
          <Group
            key={col.state.id}
            col={col}
            selection={selection}
            optimistic={optimistic}
            onSelect={onSelect}
            onOpen={onOpen}
            onCreate={onCreate}
            readOnly={readOnly}
          />
        ))}
        {total === 0 && (
          <p className="text-mute p-8 text-center">
            Nothing here yet. Press <Kbd>c</Kbd> to file the first issue.
          </p>
        )}
      </div>
    </div>
  );
}

const visible = (c: BoardColumn) => c.rows.filter((r) => !r.tombstone);

function Group({
  col,
  selection,
  optimistic,
  onSelect,
  onOpen,
  onCreate,
  readOnly,
}: {
  col: BoardColumn;
  selection: string | null;
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onOpen: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
}) {
  const rows = visible(col);
  return (
    <section>
      {/* Sticky so you never lose which bucket you are reading — the one piece of
          context a long list silently takes away. */}
      <header className="bg-raised/95 border-line sticky top-0 z-10 flex h-9 items-center gap-2 border-b px-4 backdrop-blur-sm">
        <StatusIcon category={col.state.category} color={catalogColor(col.state.color)} />
        <h2 className="text-base font-semibold">{col.state.name}</h2>
        <span className="text-mute text-sm tabular-nums">{rows.length}</span>
        {!readOnly && (
          <IconButton
            label={`New issue in ${col.state.name}`}
            onClick={() => onCreate(col.state.id)}
            // Revealed on hover/focus: present when wanted, silent otherwise.
            className="ml-auto opacity-0 transition group-hover/list:opacity-100 focus-visible:opacity-100"
          >
            <Plus className="size-3.5" />
          </IconButton>
        )}
      </header>
      <ul>
        {rows.map((row) => (
          <IssueRow
            key={row.reff}
            row={row}
            state={col}
            selected={row.reff === selection}
            pending={optimistic.has(row.doc_id)}
            onSelect={onSelect}
            onOpen={onOpen}
          />
        ))}
      </ul>
    </section>
  );
}

function IssueRow({
  row,
  state,
  selected,
  pending,
  onSelect,
  onOpen,
}: {
  row: Row;
  state: BoardColumn;
  selected: boolean;
  pending: boolean;
  onSelect: (reff: string) => void;
  onOpen: (reff: string) => void;
}) {
  const el = useRef<HTMLLIElement>(null);

  // Selection moves by keyboard, so it must drag the viewport with it — a
  // selected row below the fold is indistinguishable from a dropped keypress.
  useEffect(() => {
    if (selected) el.current?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  return (
    <li
      ref={el}
      className={clsxish([
        "border-line/60 group flex h-8 cursor-default items-center gap-3 border-b px-4",
        selected ? "bg-active" : "hover:bg-hover",
        // A row whose body hasn't synced yet is real but not yet trustworthy;
        // say so quietly rather than rendering it as settled (UI.md §3.3).
        row.provisional && "opacity-60",
      ])}
      onClick={() => onSelect(row.reff)}
      onDoubleClick={() => onOpen(row.reff)}
      aria-selected={selected}
      role="option"
    >
      <PriorityIcon priority={row.priority} />
      {/* Fixed width + tabular numerals: the ids form a straight edge to scan. */}
      <span className="text-mute w-20 shrink-0 truncate font-mono text-xs tabular-nums">
        {row.key_alias ?? row.reff}
      </span>
      <StatusIcon category={state.state.category} color={catalogColor(state.state.color)} />
      <span className="min-w-0 flex-1 truncate">{row.title}</span>
      {/* Unconfirmed: shown as truth because that is what makes a write feel
          instant, but never *claimed* as truth. */}
      {pending && (
        <span
          className="bg-accent size-1.5 shrink-0 animate-pulse rounded-full"
          title="Not confirmed by the daemon yet"
          aria-label="Pending"
        />
      )}
      {row.assignee_summary && (
        <span className="text-mute shrink-0 text-xs">{row.assignee_summary}</span>
      )}
    </li>
  );
}

/** Tiny local join — `clsx` is a dependency, but a 3-line filter beats an import
 *  for the two call sites that need it. */
function clsxish(parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(" ");
}


