import { useEffect, useRef } from "react";
import { ListFilter, X } from "lucide-react";

import { EMPTY_FILTER, isActive, type FilterState } from "../core/filter";
import { PRIORITY_ORDER, type LabelDto, type MemberDto, type WorkflowState } from "../types";
import { Avatar, memberName } from "./Avatar";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Combobox } from "./Picker";
import { Button, IconButton } from "./primitives";

/** Toggle one id in a multi-select filter axis. */
const toggle = (list: readonly string[], id: string): string[] =>
  list.includes(id) ? list.filter((x) => x !== id) : [...list, id];

/**
 * The filter bar.
 *
 * **One control per dimension**, not one menu holding several. `mine`, `status`, and
 * `label` answer different questions, and a single "Any ▾" menu that mixed them
 * could only ever show one of them in its trigger — so a board narrowed by both a
 * label and `mine` looked, from the outside, like it was narrowed by one. Linear
 * splits filters into a chip each for the same reason: the bar has to *say* what is
 * hiding your issues, or you stop trusting it.
 *
 * The kinds are still marked by where they live: text is the box you type into and
 * is client-side; everything else is a control. Which of those cost a round trip and
 * which do not is `core/filter.ts`'s call, not this file's — see the note there on
 * why `status` is the one that looks server-shaped and isn't.
 *
 * Escape restores what the filter was on open rather than just clearing it, which
 * is the TUI's rule: a filter you can't back out of is one you stop using.
 */
export function FilterBar({
  filter,
  labels,
  states,
  members,
  focusToken,
  resultCount,
  totalCount,
  onChange,
  onClose,
}: {
  filter: FilterState;
  labels: LabelDto[];
  states: WorkflowState[];
  members: MemberDto[];
  /** Bumped by the `/` command; refocuses without the bar owning the binding. */
  focusToken: number;
  resultCount: number;
  totalCount: number;
  onChange: (f: FilterState) => void;
  onClose: () => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const restore = useRef(filter);

  useEffect(() => {
    restore.current = filter;
    input.current?.focus();
    input.current?.select();
    // Only when `/` fires — not on every keystroke, or it would re-select as you type.
  }, [focusToken]); // eslint-disable-line react-hooks/exhaustive-deps

  const label = labels.find((l) => l.name === filter.label);

  return (
    <div className="border-line flex h-9 shrink-0 items-center gap-2 border-b px-3">
      <ListFilter className="text-mute size-3.5 shrink-0" />
      <input
        ref={input}
        value={filter.text}
        placeholder="Filter issues… use spaces for AND, | for OR, - to exclude"
        onChange={(e) => onChange({ ...filter, text: e.target.value })}
        onKeyDown={(e) => {
          if (e.key === "Escape") {
            e.stopPropagation();
            // Restore, don't just clear: Esc undoes the filtering session.
            onChange(restore.current);
            onClose();
          }
          if (e.key === "Enter") {
            e.stopPropagation();
            input.current?.blur();
          }
        }}
        className="placeholder:text-mute min-w-0 flex-1 bg-transparent outline-none"
        aria-label="Filter issues"
      />

      {/* A boolean is a toggle, not a menu with two entries in it. */}
      <Button
        variant={filter.mine ? "active" : "ghost"}
        aria-pressed={filter.mine}
        onClick={() => onChange({ ...filter, mine: !filter.mine })}
        className="shrink-0"
      >
        Mine
      </Button>

      <Combobox
        multi
        label="Status"
        selected={filter.status}
        className="shrink-0"
        face={
          <span className={filter.status.length ? "text-accent" : "text-mute"}>
            {filter.status.length === 0
              ? "Status"
              : filter.status.length === 1
                ? (states.find((s) => s.id === filter.status[0])?.name ?? "Status")
                : `${filter.status.length} statuses`}
          </span>
        }
        options={states.map((s) => ({
          id: s.id,
          label: s.name,
          icon: <StatusIcon category={s.category} color={catalogColor(s.color)} />,
        }))}
        onToggle={(id) => onChange({ ...filter, status: toggle(filter.status, id) })}
      />

      <Combobox
        multi
        label="Priority"
        selected={filter.priority}
        className="shrink-0 capitalize"
        face={
          <span className={filter.priority.length ? "text-accent" : "text-mute"}>
            {filter.priority.length === 0
              ? "Priority"
              : filter.priority.length === 1
                ? filter.priority[0]
                : `${filter.priority.length} priorities`}
          </span>
        }
        // Highest first, matching the detail picker.
        options={[...PRIORITY_ORDER].reverse().map((p) => ({
          id: p,
          label: p,
          icon: <PriorityIcon priority={p} />,
        }))}
        onToggle={(id) => onChange({ ...filter, priority: toggle(filter.priority, id) })}
      />

      {members.length > 0 && (
        <Combobox
          multi
          label="Assignee"
          selected={filter.assignees}
          className="shrink-0"
          face={
            <span className={filter.assignees.length ? "text-accent" : "text-mute"}>
              {filter.assignees.length === 0
                ? "Assignee"
                : filter.assignees.length === 1
                  ? memberName(
                      filter.assignees[0]!,
                      members.find((m) => m.key === filter.assignees[0]),
                    )
                  : `${filter.assignees.length} assignees`}
            </span>
          }
          options={members.map((m) => ({
            id: m.key,
            label: memberName(m.key, m),
            icon: <Avatar deviceKey={m.key} alias={m.alias} me={m.me} size="sm" />,
            hint: m.key.slice(0, 6),
            keywords: [m.key, m.alias],
          }))}
          onToggle={(key) => onChange({ ...filter, assignees: toggle(filter.assignees, key) })}
        />
      )}

      {labels.length > 0 && (
        <Combobox
          label="Label"
          className="shrink-0"
          // Single-valued because `Filter.label` is: the daemon resolves one name to
          // one `LabelId`. Offering multi-select here would be promising an
          // intersection the `Request` cannot carry.
          value={
            label ? { id: label.name, label: label.name, swatch: catalogColor(label.color) } : null
          }
          face={
            <span className={filter.label ? "text-accent" : "text-mute"}>
              {filter.label ?? "Label"}
            </span>
          }
          options={labels.map((l) => ({
            id: l.name,
            label: l.name,
            swatch: catalogColor(l.color),
          }))}
          onPick={(name) =>
            onChange({ ...filter, label: filter.label === name ? null : name })
          }
        />
      )}

      {isActive(filter) && (
        <>
          <span
            className="text-mute hidden shrink-0 text-2xs tabular-nums sm:inline"
            aria-live="polite"
          >
            {resultCount} of {totalCount} · AND across chips
          </span>
          <IconButton label="Clear all filters" onClick={() => onChange(EMPTY_FILTER)}>
            <X className="size-3.5" />
          </IconButton>
        </>
      )}
    </div>
  );
}
