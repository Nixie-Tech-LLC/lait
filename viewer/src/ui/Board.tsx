import { useEffect, useLayoutEffect, useRef, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronRight, ExternalLink, Flag, Info, MoreHorizontal, Plus, Tags, UserPlus } from "lucide-react";

import { loadBoardScroll, saveBoardScroll } from "../core/boardState";
import type { IssueField } from "../core/registry";
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
  onEdit,
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
  onEdit: (reff: string, field: Extract<IssueField, "priority" | "assignee" | "label">) => void;
  readOnly: boolean;
}) {
  /** The card in flight, and the column it left. */
  const [drag, setDrag] = useState<{ reff: string; from: string } | null>(null);
  /** Where it would land. Rendered as the gap. */
  const [over, setOver] = useState<{ col: string; pos: BoardPos } | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  useLayoutEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollLeft = loadBoardScroll(board.project.id);
  }, [board.project.id]);

  const finish = (col: BoardColumn) => {
    if (!drag || !over) return reset();
    const isDone = col.state.category === "done";
    // A done column is not drawn from `boards[P]` — entering a done status removes
    // the doc from the movable list and the column is rendered by the append rule
    // instead (`replica.rs:858-869`). So there is no position to ask for, and
    // asking anyway would write to a list this column ignores.
    onDrop(drag.reff, col.state.id, isDone ? null : over.pos);
    setAnnouncement(`Moved ${drag.reff} to ${col.state.name}`);
    reset();
  };

  const move = (row: Row, col: BoardColumn) => {
    if (row.status === col.state.id) return;
    onDrop(
      row.reff,
      col.state.id,
      boardMovePosition(col),
    );
    setAnnouncement(`Moved ${row.key_alias ?? row.reff} to ${col.state.name}`);
  };

  const reset = () => {
    setDrag(null);
    setOver(null);
  };

  return (
    <div
      ref={scrollRef}
      className="flex min-h-0 flex-1 gap-3 overflow-x-auto p-3"
      aria-label="Issue board"
      tabIndex={0}
      onScroll={(event) => saveBoardScroll(board.project.id, event.currentTarget.scrollLeft)}
    >
      <p className="sr-only" aria-live="polite">{announcement}</p>
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
          onMove={move}
          onEdit={onEdit}
          columns={board.columns}
          readOnly={readOnly}
        />
      ))}
    </div>
  );
}

/** Done is append-only in the daemon; live columns accept an explicit tail. */
export function boardMovePosition(col: BoardColumn): BoardPos | null {
  return col.state.category === "done" ? null : { at: "bottom" };
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
  onMove,
  onEdit,
  columns,
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
  onMove: (row: Row, col: BoardColumn) => void;
  onEdit: (reff: string, field: Extract<IssueField, "priority" | "assignee" | "label">) => void;
  columns: BoardColumn[];
  readOnly: boolean;
}) {
  const rows = col.rows.filter((r) => !r.tombstone);
  const active = drag !== null && !readOnly;
  const [collapsed, setCollapsed] = useState(false);

  return (
    <section className={`group/col flex shrink-0 flex-col transition-[width] ${collapsed ? "w-10" : rows.length ? "w-72" : "w-60"}`}>
      <header className="flex h-8 shrink-0 items-center gap-2 px-1">
        <button
          className="text-mute hover:text-fg flex size-6 items-center justify-center rounded"
          onClick={() => setCollapsed((value) => !value)}
          aria-label={`${collapsed ? "Expand" : "Collapse"} ${col.state.name}`}
          aria-expanded={!collapsed}
        >
          <ChevronRight className={`size-3 transition-transform ${collapsed ? "" : "rotate-90"}`} />
        </button>
        {!collapsed && <>
        <StatusIcon category={col.state.category} color={catalogColor(col.state.color)} />
        <h2 className="text-base font-semibold">{col.state.name}</h2>
        <span className="text-mute text-sm tabular-nums">{rows.length}</span>
        {col.state.category === "done" && (
          <Info
            className="text-mute size-3.5"
            role="img"
            aria-label="Completed issues follow completion order. Move an issue here; its completion time determines its position."
          />
        )}
        {!readOnly && (
          <IconButton
            label={`New issue in ${col.state.name}`}
            onClick={() => onCreate(col.state.id)}
            className="ml-auto"
          >
            <Plus className="size-3.5" />
          </IconButton>
        )}
        <DropdownMenu.Root>
          <DropdownMenu.Trigger asChild>
            <IconButton label={`${col.state.name} column actions`} className={readOnly ? "ml-auto" : ""}>
              <MoreHorizontal className="size-3.5" />
            </IconButton>
          </DropdownMenu.Trigger>
          <DropdownMenu.Portal>
            <DropdownMenu.Content
              align="end"
              sideOffset={4}
              className="border-line-strong bg-raised shadow-overlay z-50 min-w-44 rounded-lg border p-1"
            >
              {!readOnly && (
                <DropdownMenu.Item
                  onSelect={() => onCreate(col.state.id)}
                  className="data-[highlighted]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none"
                >
                  <Plus className="size-3.5" />
                  New issue
                </DropdownMenu.Item>
              )}
              <DropdownMenu.Item
                disabled={!rows[0]}
                onSelect={() => rows[0] && onSelect(rows[0].reff)}
                className="data-[highlighted]:bg-hover data-[disabled]:text-mute flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none"
              >
                Open first issue
                <span className="text-mute ml-auto tabular-nums">{rows.length}</span>
              </DropdownMenu.Item>
            </DropdownMenu.Content>
          </DropdownMenu.Portal>
        </DropdownMenu.Root>
        </>}
      </header>
      {collapsed ? (
        <button
          className="text-mute hover:text-fg flex min-h-0 flex-1 items-start justify-center py-2 text-xs [writing-mode:vertical-rl]"
          onClick={() => setCollapsed(false)}
        >
          {col.state.name} · {rows.length}
        </button>
      ) : (
      <ul
        aria-label={`${col.state.name} issues`}
        data-board-collection
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
            draggable={!readOnly && !row.tombstone}
            onSelect={onSelect}
            onDragStart={onDragStart}
            onDragEnd={onDragEnd}
            onOver={onOver}
            columns={columns}
            onMove={onMove}
            onEdit={onEdit}
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
      )}
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
  columns,
  onMove,
  onEdit,
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
  columns: BoardColumn[];
  onMove: (row: Row, col: BoardColumn) => void;
  onEdit: (reff: string, field: Extract<IssueField, "priority" | "assignee" | "label">) => void;
}) {
  const el = useRef<HTMLLIElement>(null);
  // Selection moves by keyboard, so it has to drag the viewport with it.
  useEffect(() => {
    if (selected) {
      el.current?.scrollIntoView({ block: "nearest" });
      if (document.activeElement?.closest("[data-board-collection]")) {
        el.current?.focus({ preventScroll: true });
      }
    }
  }, [selected]);

  return (
    <>
      {gap === "before" && <DropLine />}
      <li
        ref={el}
        draggable={draggable}
        onClick={(event) => {
          event.currentTarget.focus({ preventScroll: true });
          onSelect(row.reff);
        }}
        onKeyDown={(event) => {
          if (event.target === event.currentTarget && event.key === "Enter") {
            event.preventDefault();
            onSelect(row.reff);
          }
        }}
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
        aria-current={selected ? "true" : undefined}
        tabIndex={selected ? 0 : -1}
        className={[
          "bg-raised group/card cursor-default rounded border p-2 transition-[border-color,box-shadow,opacity] duration-150",
          selected
            ? "border-accent ring-accent shadow-sm ring-1"
            : "border-line hover:border-line-strong hover:shadow-sm",
          row.provisional ? "opacity-60" : "",
          row.tombstone ? "opacity-60" : "",
          // The card left the deck: dim the hole it came from rather than removing
          // it, so the column doesn't reflow under the cursor mid-drag.
          dragging ? "opacity-40" : "",
        ].join(" ")}
      >
        <div className="mb-1.5 flex items-start gap-1">
          <p className={`min-w-0 flex-1 line-clamp-2 ${row.tombstone ? "text-mute line-through" : ""}`}>
            {row.title}
          </p>
          {!row.tombstone && (
            <DropdownMenu.Root>
              <DropdownMenu.Trigger asChild>
                <IconButton
                  label={`Move ${row.key_alias ?? row.reff}`}
                  onClick={(event) => event.stopPropagation()}
                  className="-mr-1 -mt-1 opacity-0 group-hover/card:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
                >
                  <MoreHorizontal className="size-3.5" />
                </IconButton>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <DropdownMenu.Content
                  align="end"
                  sideOffset={4}
                  className="border-line-strong bg-raised shadow-overlay z-50 min-w-44 rounded-lg border p-1"
                >
                  <DropdownMenu.Label className="text-mute px-2 py-1 text-2xs font-semibold uppercase">
                    Move to
                  </DropdownMenu.Label>
                  {columns.map((column) => (
                    <DropdownMenu.Item
                      key={column.state.id}
                      disabled={column.state.id === row.status}
                      onSelect={() => onMove(row, column)}
                      className="data-[highlighted]:bg-hover data-[disabled]:text-mute flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none"
                    >
                      <StatusIcon
                        category={column.state.category}
                        color={catalogColor(column.state.color)}
                      />
                      <span className="flex-1">{column.state.name}</span>
                      <span className="text-mute tabular-nums">{column.rows.length}</span>
                      {column.state.category === "done" && <span className="sr-only">Completion time determines order</span>}
                    </DropdownMenu.Item>
                  ))}
                  <DropdownMenu.Separator className="bg-line my-1 h-px" />
                  <DropdownMenu.Item onSelect={() => onSelect(row.reff)} className="data-[highlighted]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none">
                    <ExternalLink className="size-3.5" /> Open issue
                  </DropdownMenu.Item>
                  <DropdownMenu.Item onSelect={() => onEdit(row.reff, "priority")} className="data-[highlighted]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none">
                    <Flag className="size-3.5" /> Set priority
                  </DropdownMenu.Item>
                  <DropdownMenu.Item onSelect={() => onEdit(row.reff, "assignee")} className="data-[highlighted]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none">
                    <UserPlus className="size-3.5" /> Assign
                  </DropdownMenu.Item>
                  <DropdownMenu.Item onSelect={() => onEdit(row.reff, "label")} className="data-[highlighted]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1.5 text-sm outline-none">
                    <Tags className="size-3.5" /> Add label
                  </DropdownMenu.Item>
                </DropdownMenu.Content>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
          )}
        </div>
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
