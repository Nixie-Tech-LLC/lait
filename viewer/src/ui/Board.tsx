import { useEffect, useRef, useState } from "react";
import { Plus } from "lucide-react";

import type { BoardColumn, BoardPos, BoardView, MemberDto, Row } from "../types";
import { AvatarStack, stackFor } from "./Avatar";
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
 *
 * ## Dragging
 *
 * Native HTML5 drag-and-drop, not a library. The board is four columns of one card
 * shape, the platform already owns the drag image, the cursor, and the escape key —
 * and this bundle is committed into the binary (`src/serve/assets`), so a 40KB drag
 * engine is 40KB every `lait` install carries forever. The keyboard path (`J`/`K`,
 * `H`/`L`) is separate and primary; this is the mouse affordance for the same verbs.
 */
export function Board({
  board,
  members,
  selection,
  optimistic,
  onSelect,
  onCreate,
  onDrop,
  readOnly,
}: {
  board: BoardView;
  /** The ACL, for resolving assignee keys to faces. */
  members: MemberDto[];
  selection: string | null;
  /** Docs carrying an unconfirmed local prediction. */
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onCreate: (status: string) => void;
  /** A card landed. `pos` is null when the target column can't be ordered. */
  onDrop: (reff: string, status: string, pos: BoardPos | null) => void;
  readOnly: boolean;
}) {
  /** The card in flight, and the column it left. */
  const [drag, setDrag] = useState<{ reff: string; from: string } | null>(null);
  /** Where it would land. Rendered as the gap. */
  const [over, setOver] = useState<{ col: string; pos: BoardPos } | null>(null);

  const finish = (col: BoardColumn) => {
    if (!drag || !over) return reset();
    const isDone = col.state.category === "done";
    // A done column is not drawn from `boards[P]` — entering a done status removes
    // the doc from the movable list and the column is rendered by the append rule
    // instead (`replica.rs:858-869`). So there is no position to ask for, and
    // asking anyway would write to a list this column ignores.
    onDrop(drag.reff, col.state.id, isDone ? null : over.pos);
    reset();
  };

  const reset = () => {
    setDrag(null);
    setOver(null);
  };

  return (
    <div className="flex min-h-0 flex-1 gap-3 overflow-x-auto p-3">
      {board.columns.map((col) => (
        <Column
          key={col.state.id}
          col={col}
          members={members}
          selection={selection}
          optimistic={optimistic}
          drag={drag}
          over={over?.col === col.state.id ? over.pos : null}
          onSelect={onSelect}
          onCreate={onCreate}
          onDragStart={(reff) => setDrag({ reff, from: col.state.id })}
          onDragEnd={reset}
          onOver={(pos) => setOver({ col: col.state.id, pos })}
          onDrop={() => finish(col)}
          readOnly={readOnly}
        />
      ))}
    </div>
  );
}

function Column({
  col,
  members,
  selection,
  optimistic,
  drag,
  over,
  onSelect,
  onCreate,
  onDragStart,
  onDragEnd,
  onOver,
  onDrop,
  readOnly,
}: {
  col: BoardColumn;
  members: MemberDto[];
  selection: string | null;
  optimistic: ReadonlySet<string>;
  drag: { reff: string; from: string } | null;
  over: BoardPos | null;
  onSelect: (reff: string) => void;
  onCreate: (status: string) => void;
  onDragStart: (reff: string) => void;
  onDragEnd: () => void;
  onOver: (pos: BoardPos) => void;
  onDrop: () => void;
  readOnly: boolean;
}) {
  const rows = col.rows.filter((r) => !r.tombstone);
  const active = drag !== null && !readOnly;

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
      <ul
        className={[
          "flex min-h-0 flex-1 flex-col gap-2 overflow-y-auto rounded p-1 transition-colors",
          // The whole column lights up as a target, because the drop is a *status*
          // change first and a position second — the column is the thing you are
          // choosing.
          active && over !== null ? "bg-hover" : "",
        ].join(" ")}
        onDragOver={(e) => {
          if (!active) return;
          // Without this the browser refuses the drop and snaps the card back.
          e.preventDefault();
          e.dataTransfer.dropEffect = "move";
          // Past the last card — or over an empty column — means the end.
          if (rows.length === 0) onOver({ at: "top" });
        }}
        onDrop={(e) => {
          if (!active) return;
          e.preventDefault();
          onDrop();
        }}
      >
        {rows.map((row) => (
          <Card
            key={row.reff}
            row={row}
            members={members}
            selected={row.reff === selection}
            pending={optimistic.has(row.doc_id)}
            dragging={drag?.reff === row.reff}
            gap={gapFor(over, row.reff)}
            draggable={!readOnly}
            onSelect={onSelect}
            onDragStart={onDragStart}
            onDragEnd={onDragEnd}
            onOver={onOver}
          />
        ))}
        {rows.length === 0 && (
          <li
            className={[
              "text-mute rounded border border-dashed p-4 text-center text-sm transition-colors",
              active && over !== null ? "border-accent text-accent" : "border-line",
            ].join(" ")}
          >
            {active && over !== null ? "Drop here" : "—"}
          </li>
        )}
        {/* The tail target. A card dropped below the last one has to land
            *somewhere*, and the list's own padding is not a drop zone the eye can
            find — this is, and it only exists while something is in flight. */}
        {active && rows.length > 0 && (
          <li
            className="min-h-8 flex-1"
            onDragOver={(e) => {
              e.preventDefault();
              onOver({ at: "bottom" });
            }}
          >
            {over?.at === "bottom" && <DropLine />}
          </li>
        )}
      </ul>
    </section>
  );
}

/** Whether the insertion line sits above or below this card, if at all. */
function gapFor(over: BoardPos | null, reff: string): "before" | "after" | null {
  if (!over) return null;
  if (over.at === "before" && over.reff === reff) return "before";
  if (over.at === "after" && over.reff === reff) return "after";
  if (over.at === "top") return null;
  return null;
}

/** The insertion point, drawn where the card will land. */
function DropLine() {
  return <div className="bg-accent my-0.5 h-0.5 rounded-full" aria-hidden="true" />;
}

function Card({
  row,
  members,
  selected,
  pending,
  dragging,
  gap,
  draggable,
  onSelect,
  onDragStart,
  onDragEnd,
  onOver,
}: {
  row: Row;
  members: MemberDto[];
  selected: boolean;
  pending: boolean;
  dragging: boolean;
  gap: "before" | "after" | null;
  draggable: boolean;
  onSelect: (reff: string) => void;
  onDragStart: (reff: string) => void;
  onDragEnd: () => void;
  onOver: (pos: BoardPos) => void;
}) {
  const el = useRef<HTMLLIElement>(null);
  // Selection moves by keyboard, so it has to drag the viewport with it.
  useEffect(() => {
    if (selected) el.current?.scrollIntoView({ block: "nearest" });
  }, [selected]);

  return (
    <>
      {gap === "before" && <DropLine />}
      <li
        ref={el}
        draggable={draggable}
        onClick={() => onSelect(row.reff)}
        onDragStart={(e) => {
          // Firefox ignores a drag whose dataTransfer carries nothing.
          e.dataTransfer.setData("text/plain", row.reff);
          e.dataTransfer.effectAllowed = "move";
          onDragStart(row.reff);
        }}
        onDragEnd={onDragEnd}
        onDragOver={(e) => {
          e.preventDefault();
          // Which half of the card the pointer is in decides the side. Measuring
          // per-event rather than on drag start, because the card under the cursor
          // moves as the placeholder opens gaps above it.
          const box = e.currentTarget.getBoundingClientRect();
          const below = e.clientY > box.top + box.height / 2;
          onOver({ at: below ? "after" : "before", reff: row.reff });
        }}
        aria-selected={selected}
        role="option"
        className={[
          "bg-raised cursor-default rounded border p-2 transition-colors",
          selected ? "border-accent ring-accent ring-1" : "border-line hover:border-line-strong",
          row.provisional ? "opacity-60" : "",
          // The card left the deck: dim the hole it came from rather than removing
          // it, so the column doesn't reflow under the cursor mid-drag.
          dragging ? "opacity-40" : "",
        ].join(" ")}
      >
        <p className="mb-1.5 line-clamp-2">{row.title}</p>
        <div className="flex items-center gap-2">
          <PriorityIcon priority={row.priority} />
          <span className="text-mute font-mono text-2xs tabular-nums">
            {row.key_alias ?? row.reff}
          </span>
          <span className="ml-auto flex items-center gap-2">
            {pending && (
              <span
                className="bg-accent size-1.5 animate-pulse rounded-full"
                title="Not confirmed by the daemon yet"
                aria-label="Pending"
              />
            )}
            {/* Faces, not `assignee_summary`. The summary is the *terminal's*
                projection — "you +1" is a sentence, and a card wants a glance. */}
            <AvatarStack members={stackFor(row.assignees, members)} />
          </span>
        </div>
      </li>
      {gap === "after" && <DropLine />}
    </>
  );
}
