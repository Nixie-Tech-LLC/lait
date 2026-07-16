import { useEffect, useRef } from "react";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Check, ListFilter, X } from "lucide-react";

import { isActive, type FilterState } from "../core/filter";
import type { LabelDto } from "../types";
import { catalogColor } from "./colors";
import { IconButton } from "./primitives";

/**
 * The filter bar.
 *
 * Text is live and client-side (keystroke-by-keystroke, no round trip); `mine` and
 * `label` are the daemon's and are marked as such by being in a menu rather than in
 * the box you type into. That split is not cosmetic — see `core/filter.ts`.
 *
 * Escape restores what the filter was on open rather than just clearing it, which
 * is the TUI's rule: a filter you can't back out of is one you stop using.
 */
export function FilterBar({
  filter,
  labels,
  focusToken,
  onChange,
  onClose,
}: {
  filter: FilterState;
  labels: LabelDto[];
  /** Bumped by the `/` command; refocuses without the bar owning the binding. */
  focusToken: number;
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

  return (
    <div className="border-line flex h-9 shrink-0 items-center gap-2 border-b px-3">
      <ListFilter className="text-mute size-3.5 shrink-0" />
      <input
        ref={input}
        value={filter.text}
        placeholder="Filter by title, ref, or alias…"
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

      <Dropdown.Root>
        <Dropdown.Trigger
          className={`hover:bg-hover flex shrink-0 items-center gap-1 rounded px-2 py-0.5 text-sm ${
            filter.mine || filter.label ? "text-accent" : "text-mute"
          }`}
        >
          {filter.mine ? "Mine" : filter.label ? `Label: ${filter.label}` : "Any"}
        </Dropdown.Trigger>
        <Dropdown.Portal>
          <Dropdown.Content
            sideOffset={4}
            align="end"
            className="border-line-strong bg-raised shadow-overlay z-50 min-w-44 rounded-lg border p-1"
          >
            <Dropdown.Item
              onSelect={() => onChange({ ...filter, mine: !filter.mine })}
              className="data-[highlighted=true]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
            >
              <span className="flex-1">Assigned to me</span>
              {filter.mine && <Check className="size-3" />}
            </Dropdown.Item>
            {labels.length > 0 && <Dropdown.Separator className="bg-line my-1 h-px" />}
            {labels.map((l) => (
              <Dropdown.Item
                key={l.id}
                onSelect={() => onChange({ ...filter, label: filter.label === l.name ? null : l.name })}
                className="data-[highlighted=true]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
              >
                <span
                  className="size-2 shrink-0 rounded-full"
                  style={{ background: catalogColor(l.color) }}
                />
                <span className="flex-1">{l.name}</span>
                {filter.label === l.name && <Check className="size-3" />}
              </Dropdown.Item>
            ))}
          </Dropdown.Content>
        </Dropdown.Portal>
      </Dropdown.Root>

      {isActive(filter) && (
        <IconButton label="Clear filter" onClick={() => onChange({ text: "", mine: false, label: null })}>
          <X className="size-3.5" />
        </IconButton>
      )}

    </div>
  );
}
