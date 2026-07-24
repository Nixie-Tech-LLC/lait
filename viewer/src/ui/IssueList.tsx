import { useEffect, useMemo, useRef, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { CheckSquare, ChevronRight, Copy, ExternalLink, MoreHorizontal, Plus, Trash2 } from "lucide-react";

import type { RowGroup } from "../core/display";
import { indexBy } from "../core/performance";
import type { MemberDto, Row, WorkflowState } from "../types";
import { Avatar, AvatarStack, memberName, stackFor } from "./Avatar";
import { ApplicationState } from "./AppState";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { MenuContent, MenuItem } from "./layout";
import { Button, Checkbox, IconButton, interactiveRow } from "./primitives";
import { dueLabel, dueTone } from "./time";

/**
 * The default view: one flat, grouped list.
 *
 * The groups arrive from `core/display.ts` — by status they are the board's own
 * columns (one fetch, two renderings), and the other axes are client-side
 * rearrangements of the same rows. Group *shape* changes; row identity, motion,
 * and selection never do.
 *
 * The density is the feature. Rows are a fixed 32px with a fixed column rhythm,
 * so the eye tracks straight down the ids and the titles without re-finding them
 * on each line — which is exactly what stops being true the moment a row grows to
 * fit its content.
 */
export function IssueList({
  groups,
  deleted,
  deletedMode,
  states,
  members,
  selection,
  checked,
  optimistic,
  onSelect,
  onToggleCheck,
  onOpen,
  onCreate,
  readOnly,
  filtered,
}: {
  groups: RowGroup[];
  /** The trash — tombstoned rows from `list all:true`, rendered as their own
   *  group. Separate from `groups` because a deleted issue is *not on the
   *  board* (deletion removes it from `boards[P]`); empty = trash hidden. */
  deleted: Row[];
  /** Deleted rows are a recovery destination, never an appendix to live work. */
  deletedMode: boolean;
  /** Board-ordered workflow, for a row's status glyph under non-status grouping. */
  states: WorkflowState[];
  /** The ACL, for resolving assignee keys to faces. */
  members: MemberDto[];
  selection: string | null;
  /** Bulk-selection checks, by canonical ref. */
  checked: ReadonlySet<string>;
  /** Docs carrying an unconfirmed local prediction. */
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onToggleCheck: (reff: string) => void;
  onOpen: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
  filtered: boolean;
}) {
  const visible = (g: RowGroup) => g.rows.filter((r) => !r.tombstone);
  const stateById = useMemo(
    () => indexBy(states, (state) => state.id),
    [states],
  );
  const checkAnchor = useRef<string | null>(null);
  const orderedRows = useMemo(
    () => deletedMode ? deleted : groups.flatMap((group) => visible(group)),
    [deletedMode, deleted, groups],
  );
  const checkRow = (reff: string, range: boolean) => {
    const anchor = checkAnchor.current;
    if (range && anchor) {
      const from = orderedRows.findIndex((row) => row.reff === anchor);
      const to = orderedRows.findIndex((row) => row.reff === reff);
      if (from >= 0 && to >= 0) {
        const desired = !checked.has(reff);
        for (const row of orderedRows.slice(Math.min(from, to), Math.max(from, to) + 1)) {
          if (checked.has(row.reff) !== desired) onToggleCheck(row.reff);
        }
        return;
      }
    }
    checkAnchor.current = reff;
    onToggleCheck(reff);
  };
  const total = deletedMode
    ? deleted.length
    : groups.reduce((n, g) => n + visible(g).length, 0);

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <div className="text-mute border-line border-b px-4 py-2 text-sm">
        {total} {deletedMode ? "deleted " : ""}{total === 1 ? "issue" : "issues"}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {!deletedMode && groups.map((group) => (
          <Group
            key={group.key}
            group={group}
            rows={visible(group)}
            stateById={stateById}
            members={members}
            selection={selection}
            checked={checked}
            optimistic={optimistic}
            onSelect={onSelect}
            onToggleCheck={checkRow}
            onOpen={onOpen}
            onCreate={onCreate}
            readOnly={readOnly}
          />
        ))}
        {deleted.length > 0 && (
          <section>
            <header className="bg-raised/95 border-line sticky top-0 z-10 flex h-9 items-center gap-2 border-b px-4 backdrop-blur-sm">
              <Trash2 className="text-mute size-3.5" />
              <h2 className="text-base font-semibold">Deleted</h2>
              <span className="text-mute text-sm tabular-nums">{deleted.length}</span>
            </header>
            <ul>
              {deleted.map((row) => (
                <IssueRow
                  key={row.reff}
                  row={row}
                  state={stateById.get(row.status)}
                  members={members}
                  selected={row.reff === selection}
                  checked={checked.has(row.reff)}
                  anyChecked={checked.size > 0}
                  pending={optimistic.has(row.doc_id)}
                  onSelect={onSelect}
                  onToggleCheck={checkRow}
                  onOpen={onOpen}
                  readOnly={readOnly}
                />
              ))}
            </ul>
          </section>
        )}
        {total === 0 && (
          <ApplicationState
            kind={deletedMode ? "empty" : filtered ? "filtered-empty" : "empty"}
            title={deletedMode ? "No deleted issues" : filtered ? "No matching issues" : "No issues yet"}
            body={deletedMode ? "Deleted issues will appear here so they can be inspected or restored." : filtered ? "Clear or adjust the current filters to see more." : "Create the first issue in this project."}
            action={!deletedMode && !filtered && !readOnly && states[0] ? <Button variant="primary" onClick={() => onCreate(states[0]!.id)}><Plus className="size-3.5" /> New issue</Button> : undefined}
            className="min-h-60"
          />
        )}
      </div>
    </div>
  );
}

/** The group header's leading glyph: whatever the group *is*. */
function GroupIcon({ group, members }: { group: RowGroup; members: MemberDto[] }) {
  if (group.state) {
    return (
      <StatusIcon category={group.state.category} color={catalogColor(group.state.color)} />
    );
  }
  if (group.kind === "priority") {
    return <PriorityIcon priority={group.label as Row["priority"]} />;
  }
  if (group.kind === "assignee" && group.key !== "unassigned") {
    const m = members.find((x) => x.key === group.label);
    return <Avatar deviceKey={group.label} alias={m?.alias ?? ""} me={m?.me ?? false} size="sm" />;
  }
  return null;
}

function Group({
  group,
  rows,
  stateById,
  members,
  selection,
  checked,
  optimistic,
  onSelect,
  onToggleCheck,
  onOpen,
  onCreate,
  readOnly,
}: {
  group: RowGroup;
  rows: Row[];
  stateById: ReadonlyMap<string, WorkflowState>;
  members: MemberDto[];
  selection: string | null;
  checked: ReadonlySet<string>;
  optimistic: ReadonlySet<string>;
  onSelect: (reff: string) => void;
  onToggleCheck: (reff: string, range: boolean) => void;
  onOpen: (reff: string) => void;
  onCreate: (status: string) => void;
  readOnly: boolean;
}) {
  const [collapsed, setCollapsed] = useState(false);
  // An emptied group stays visible under status grouping (a status that exists
  // is a column that exists — filter.ts's rule); a derived group with no rows
  // is nothing at all, so it goes.
  if (rows.length === 0 && group.kind !== "status") return null;

  // An assignee group is labeled by a KEY; the human name is resolved here,
  // where the member list is (same rule as every other naming site).
  const title =
    group.kind === "assignee" && group.key !== "unassigned"
      ? memberName(group.label, members.find((m) => m.key === group.label))
      : group.label;

  return (
    <section>
      {/* Sticky so you never lose which bucket you are reading — the one piece of
          context a long list silently takes away. */}
      <header className="bg-raised/95 border-line sticky top-0 z-10 flex h-9 items-center gap-2 border-b px-4 backdrop-blur-sm">
        <IconButton
          label={`${collapsed ? "Expand" : "Collapse"} ${title}`}
          onClick={() => setCollapsed((value) => !value)}
          aria-expanded={!collapsed}
          className="-ml-2"
        >
          <ChevronRight className={`size-3 transition-transform ${collapsed ? "" : "rotate-90"}`} />
        </IconButton>
        <GroupIcon group={group} members={members} />
        <h2 className="text-base font-semibold capitalize">{title}</h2>
        <span className="text-mute text-sm tabular-nums">{rows.length}</span>
        {!readOnly && group.state && (
          <IconButton
            label={`New issue in ${group.state.name}`}
            onClick={() => onCreate(group.state!.id)}
            // Revealed on hover/focus: present when wanted, silent otherwise.
            className="ml-auto opacity-0 transition group-hover/list:opacity-100 focus-visible:opacity-100"
          >
            <Plus className="size-3.5" />
          </IconButton>
        )}
      </header>
      {!collapsed && <ul aria-label={`${title} issues`} data-issue-collection>
        {rows.map((row) => (
          <IssueRow
            key={row.reff}
            row={row}
            state={stateById.get(row.status)}
            members={members}
            selected={row.reff === selection}
            checked={checked.has(row.reff)}
            anyChecked={checked.size > 0}
            pending={optimistic.has(row.doc_id)}
            onSelect={onSelect}
            onToggleCheck={onToggleCheck}
            onOpen={onOpen}
            readOnly={readOnly}
          />
        ))}
      </ul>}
    </section>
  );
}

function IssueRow({
  row,
  state,
  members,
  selected,
  checked,
  anyChecked,
  pending,
  onSelect,
  onToggleCheck,
  onOpen,
  readOnly,
}: {
  row: Row;
  state: WorkflowState | undefined;
  members: MemberDto[];
  selected: boolean;
  checked: boolean;
  /** While any check exists the whole column shows, so targets stay aligned. */
  anyChecked: boolean;
  pending: boolean;
  onSelect: (reff: string) => void;
  onToggleCheck: (reff: string, range: boolean) => void;
  onOpen: (reff: string) => void;
  readOnly: boolean;
}) {
  const el = useRef<HTMLLIElement>(null);

  // Selection moves by keyboard, so it must drag the viewport with it — a
  // selected row below the fold is indistinguishable from a dropped keypress.
  useEffect(() => {
    if (selected) {
      el.current?.scrollIntoView({ block: "nearest" });
      if (document.activeElement?.closest("[data-issue-collection]")) {
        el.current?.focus({ preventScroll: true });
      }
    }
  }, [selected]);

  return (
    <li
      ref={el}
      className={clsxish([
        interactiveRow({ selected }),
        "group/row flex h-8 items-center gap-2 px-4",
        checked && !selected && "bg-accent/5 shadow-[inset_2px_0_var(--color-accent)]",
        // A row whose body hasn't synced yet is real but not yet trustworthy;
        // say so quietly rather than rendering it as settled (UI.md §3.3).
        row.provisional && "opacity-60",
        row.tombstone && "opacity-60",
      ])}
      onClick={(event) => {
        event.currentTarget.focus({ preventScroll: true });
        onSelect(row.reff);
      }}
      onDoubleClick={() => onOpen(row.reff)}
      onKeyDown={(event) => {
        if (event.target === event.currentTarget && event.key === "Enter") {
          event.preventDefault();
          onOpen(row.reff);
        }
      }}
      aria-current={selected ? "true" : undefined}
      data-bulk-selected={checked || undefined}
      tabIndex={selected ? 0 : -1}
    >
      {/* This 16px column is shared with the group chevron above it. Keeping the
          selection affordance in that column lets priority/status/title retain
          exactly the same geometry when the checkbox appears. */}
      <span className="flex size-4 shrink-0 items-center justify-center">
        {!readOnly && (
          <Checkbox
            checked={checked}
            onCheckedChange={() => onToggleCheck(row.reff, false)}
            onClick={(event) => {
              event.stopPropagation();
              if ((event.nativeEvent as MouseEvent).shiftKey) {
                event.preventDefault();
                onToggleCheck(row.reff, true);
              }
            }}
            aria-label={`Select ${row.key_alias ?? row.reff}`}
            className={clsxish([
              !anyChecked && !checked &&
                "opacity-0 transition-opacity group-hover/row:opacity-100 focus-visible:opacity-100",
            ])}
          />
        )}
      </span>
      <PriorityIcon priority={row.priority} />
      {/* Fixed width + tabular numerals: the ids form a straight edge to scan. */}
      <span className="text-mute w-20 shrink-0 truncate font-mono text-xs tabular-nums">
        {row.key_alias ?? row.reff}
      </span>
      {state && <StatusIcon category={state.category} color={catalogColor(state.color)} />}
      <span
        className={clsxish(["min-w-0 flex-1 truncate", row.tombstone && "text-mute line-through"])}
      >
        {row.title}
      </span>
      {row.tombstone && (
        <Trash2 className="text-mute size-3 shrink-0" aria-label="Deleted" />
      )}
      {row.estimate != null && (
        <span className="text-mute shrink-0 text-2xs tabular-nums" title="Estimate">
          {row.estimate}pt
        </span>
      )}
      {row.due_date != null && (
        <span
          className={clsxish([
            "shrink-0 text-2xs tabular-nums",
            { overdue: "text-danger", soon: "text-warn", later: "text-mute" }[
              dueTone(row.due_date)
            ],
          ])}
          title="Due date"
        >
          {dueLabel(row.due_date)}
        </span>
      )}
      {/* Unconfirmed: shown as truth because that is what makes a write feel
          instant, but never *claimed* as truth. */}
      {pending && (
        <span
          className="bg-accent size-1.5 shrink-0 animate-pulse rounded-full"
          title="Not confirmed by the daemon yet"
          aria-label="Pending"
        />
      )}
      {/* Faces, not `assignee_summary` — that string is the terminal's projection
          ("you +1"), and this row has a fixed 32px rhythm to keep. */}
      <AvatarStack members={stackFor(row.assignees, members)} className="w-14 justify-end" />
      <DropdownMenu.Root>
        <DropdownMenu.Trigger asChild>
          <IconButton
            label={`Actions for ${row.key_alias ?? row.reff}`}
            onClick={(event) => event.stopPropagation()}
            className="opacity-0 transition-opacity group-hover/row:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
          >
            <MoreHorizontal className="size-3.5" />
          </IconButton>
        </DropdownMenu.Trigger>
        <DropdownMenu.Portal>
          <MenuContent align="end">
            <MenuItem onSelect={() => onOpen(row.reff)}>
              <ExternalLink className="size-3.5" />
              Open focused
            </MenuItem>
            <MenuItem
              onSelect={() => {
                const url = new URL(window.location.href);
                url.searchParams.set("issue", row.reff);
                url.searchParams.set("focus", "1");
                void navigator.clipboard.writeText(url.toString());
              }}
            >
              <Copy className="size-3.5" />
              Copy link
            </MenuItem>
            {!readOnly && (
              <MenuItem onSelect={() => onToggleCheck(row.reff, false)}>
                <CheckSquare className="size-3.5" />
                {checked ? "Remove from selection" : "Add to selection"}
              </MenuItem>
            )}
          </MenuContent>
        </DropdownMenu.Portal>
      </DropdownMenu.Root>
    </li>
  );
}


/** Tiny local join — `clsx` is a dependency, but a 3-line filter beats an import
 *  for the two call sites that need it. */
function clsxish(parts: Array<string | false | undefined>): string {
  return parts.filter(Boolean).join(" ");
}
