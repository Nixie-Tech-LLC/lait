import { useEffect, useRef } from "react";
import { Plus } from "lucide-react";

import type { BoardColumn, BoardView, Row } from "../types";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { IconButton } from "./primitives";

/**
 * The board — the same fetch as the list, laid out sideways.
 *
 * `BoardView.columns` are status buckets in board order, so this and `IssueList`
 * are two renderings of one `Request`. Switching views costs nothing and cannot
 * show you two different truths.
 *
 * Ordering is the daemon's: `Catalog.boards[P]` is a movable list and the
 * authority for position (A§9, S§5.5). This never sorts.
 */
export function Board({
  board,
  selection,
  optimistic,
  onSelect,
  onCreate,
  readOnly,
}: {
  board: BoardView;
  selection: string | null;
  /** Docs carrying an unconfirmed local prediction. */
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
}) {
  return (
    <div className="flex min-h-0 flex-1 gap-3 overflow-x-auto p-3">
      {board.columns.map((col) => (
        <Column
          key={col.state.id}
          col={col}
          selection={selection}
          optimistic={optimistic}
          onSelect={onSelect}
          onCreate={onCreate}
          readOnly={readOnly}
        />
      ))}
    </div>
  );
}

function Column({
  col,
  selection,
  optimistic,
  onSelect,
  onCreate,
  readOnly,
}: {
  col: BoardColumn;
  selection: string | null;
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
}) {
  const rows = col.rows.filter((r) => !r.tombstone);
  return (
    <section className="group/col flex w-72 shrink-0 flex-col">
      <header className="flex h-8 shrink-0 items-center gap-2 px-1">
        <StatusIcon category={col.state.category} color={catalogColor(col.state.color)} />
        <h2 className="text-base font-semibold">{col.state.name}</h2>
        <span className="text-mute text-sm tabular-nums">{rows.length}</span>
        {!readOnly && (
          <IconButton
            label={`New issue in ${col.state.name}`}
            onClick={() => onCreate(col.state.id)}
            className="ml-auto opacity-0 transition group-hover/col:opacity-100 focus-visible:opacity-100"
          >
            <Plus className="size-3.5" />
          </IconButton>
        )}
      </header>
      <ul className="flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto p-1">
        {rows.map((row) => (
          <Card
            key={row.reff}
            row={row}
            selected={row.reff === selection}
            pending={optimistic.has(row.doc_id)}
            onSelect={onSelect}
          />
        ))}
        {rows.length === 0 && (
          <li className="border-line text-mute rounded border border-dashed p-4 text-center text-sm">
            —
          </li>
        )}
      </ul>
    </section>
  );
}

function Card({
  row,
  selected,
  pending,
  onSelect,
}: {
  row: Row;
  selected: boolean;
  pending: boolean;
  onSelect: (reff: string) => void;
}) {
  const el = useRef<HTMLLIElement>(null);
  // Selection moves by keyboard, so it has to drag the viewport with it.
  useEffect(() => {
    if (selected) el.current?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  return (
    <li
      ref={el}
      onClick={() => onSelect(row.reff)}
      aria-selected={selected}
      role="option"
      className={[
        "bg-raised cursor-default rounded border p-2 transition-colors",
        selected ? "border-accent ring-accent ring-1" : "border-line hover:border-line-strong",
        row.provisional ? "opacity-60" : "",
      ].join(" ")}
    >
      <p className="mb-1.5 line-clamp-2">{row.title}</p>
      <div className="flex items-center gap-2">
        <PriorityIcon priority={row.priority} />
        <span className="text-mute font-mono text-2xs tabular-nums">
          {row.key_alias ?? row.reff}
        </span>
        {row.assignee_summary && (
          <span className="text-mute ml-auto text-2xs">{row.assignee_summary}</span>
        )}
        {pending && (
          <span
            className="bg-accent ml-auto size-1.5 animate-pulse rounded-full"
            title="Not confirmed by the daemon yet"
            aria-label="Pending"
          />
        )}
      </div>
    </li>
  );
}
