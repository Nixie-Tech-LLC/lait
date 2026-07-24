import * as Popover from "@radix-ui/react-popover";
import { SlidersHorizontal } from "lucide-react";

import type { DisplayState, GroupBy, OrderBy } from "../core/display";
import { Button, IconButton, PopoverContent } from "./primitives";

/**
 * The display-options popover — Linear's `Shift+V` surface, reduced to the axes
 * this client actually has: grouping, ordering, and whether deleted issues show.
 *
 * Controlled from the App so the keybinding can open it: an uncontrolled
 * popover would be the one overlay the registry couldn't reach.
 *
 * Grouping applies to the list (the board's columns *are* the status grouping);
 * ordering applies to both. Deleted issues are a dedicated list recovery mode;
 * choosing it from the board moves to that destination.
 */
export function DisplayOptions({
  display,
  view,
  open,
  onOpenChange,
  onChange,
  density,
  onDensityChange,
}: {
  display: DisplayState;
  /** Which root surface is showing — grouping is disabled on the board. */
  view: "list" | "board";
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onChange: (d: DisplayState) => void;
  density: "compact" | "comfortable";
  onDensityChange: (density: "compact" | "comfortable") => void;
}) {
  const changed =
    display.group !== "status" || display.order !== "board" || display.deleted;

  return (
    <Popover.Root open={open} onOpenChange={onOpenChange}>
      <Popover.Trigger asChild>
        <IconButton label="Display options" chord="⇧V" variant={changed ? "active" : "ghost"}>
          <SlidersHorizontal className="size-4" />
        </IconButton>
      </Popover.Trigger>
      <PopoverContent align="end" className="flex w-64 flex-col gap-3 p-3">
          <Axis label="Group by">
            {(
              [
                ["status", "Status"],
                ["assignee", "Assignee"],
                ["priority", "Priority"],
                ["none", "None"],
              ] as const
            )
              // "None" is a list-only shape — a single-column board is just the
              // list; the board's other axes (status/assignee/priority) become
              // its columns.
              .filter(([id]) => !(view === "board" && id === "none"))
              .map(([id, label]) => (
                <Choice
                  key={id}
                  label={label}
                  active={display.group === id}
                  onClick={() => onChange({ ...display, group: id as GroupBy })}
                />
              ))}
          </Axis>

          <Axis label="Order by">
            {(
              [
                ["board", "Board order"],
                ["priority", "Priority"],
                ["title", "Title"],
              ] as const
            ).map(([id, label]) => (
              <Choice
                key={id}
                label={label}
                active={display.order === id}
                onClick={() => onChange({ ...display, order: id as OrderBy })}
              />
            ))}
          </Axis>

          <Axis label="Issue mode">
            <Choice
              label="Active"
              active={!display.deleted}
              onClick={() => onChange({ ...display, deleted: false })}
            />
            <Choice
              label="Deleted"
              active={display.deleted}
              onClick={() => onChange({ ...display, deleted: true })}
            />
          </Axis>

          <Axis label="Density">
            <Choice label="Compact" active={density === "compact"} onClick={() => onDensityChange("compact")} />
            <Choice label="Comfortable" active={density === "comfortable"} onClick={() => onDensityChange("comfortable")} />
          </Axis>
      </PopoverContent>
    </Popover.Root>
  );
}

function Axis({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <span className="text-mute text-2xs font-semibold tracking-wider uppercase">{label}</span>
      <div className="flex flex-wrap gap-1">{children}</div>
    </div>
  );
}

function Choice({
  label,
  active,
  disabled,
  onClick,
}: {
  label: string;
  active: boolean;
  disabled?: boolean;
  onClick: () => void;
}) {
  return (
    <Button
      variant={active ? "active" : "outline"}
      aria-pressed={active}
      disabled={disabled ?? false}
      onClick={onClick}
    >
      {label}
    </Button>
  );
}
