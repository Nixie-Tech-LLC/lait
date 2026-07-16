import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown } from "lucide-react";

import { cn } from "./primitives";

/**
 * A pill that opens a menu — the tracker's workhorse control.
 *
 * Shared rather than re-declared per surface: the detail pane and the composer are
 * setting the *same* fields, and a status pill that behaves differently depending
 * on which panel you opened it from is the kind of drift nobody notices until it's
 * everywhere.
 *
 * Radix owns focus trapping, escape, outside-click, typeahead, and collision
 * flipping — all invisible until they're missing.
 */

export interface Option {
  id: string;
  label: string;
  icon?: React.ReactNode;
  swatch?: string;
}

export function Picker({
  label,
  value,
  options,
  onPick,
  disabled,
  placeholder,
  className,
}: {
  label: string;
  /** The selected option, or null for "nothing chosen yet". */
  value: Option | null;
  options: Option[];
  onPick: (id: string) => void;
  disabled?: boolean;
  placeholder?: string;
  className?: string;
}) {
  const face = (
    <>
      {value?.icon}
      {value?.swatch && (
        <span className="size-2 shrink-0 rounded-full" style={{ background: value.swatch }} />
      )}
      <span className={cn(!value && "text-mute")}>{value?.label ?? placeholder ?? label}</span>
    </>
  );

  if (disabled) {
    return (
      <span className={cn("border-line text-dim flex items-center gap-1.5 rounded-full border px-2 py-1 text-sm", className)}>
        {face}
      </span>
    );
  }

  return (
    <Dropdown.Root>
      <Dropdown.Trigger
        aria-label={label}
        className={cn(
          "border-line hover:bg-hover data-[state=open]:bg-hover flex items-center gap-1.5 rounded-full border px-2 py-1 text-sm",
          className,
        )}
      >
        {face}
        <ChevronDown className="text-mute size-3" />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content
          sideOffset={4}
          className="border-line-strong bg-raised shadow-overlay z-50 min-w-44 rounded-lg border p-1"
        >
          {options.map((o) => (
            <Dropdown.Item
              key={o.id}
              onSelect={() => onPick(o.id)}
              className="data-[highlighted=true]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
            >
              {o.icon}
              {o.swatch && (
                <span className="size-2 shrink-0 rounded-full" style={{ background: o.swatch }} />
              )}
              <span className="flex-1">{o.label}</span>
              {value?.id === o.id && <Check className="size-3" />}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

/** The same pill, multi-select. Stays open between picks — choosing three labels
 *  should cost one trip to the menu, not three. */
export function MultiPicker({
  label,
  selected,
  options,
  onToggle,
  disabled,
}: {
  label: string;
  selected: string[];
  options: Option[];
  onToggle: (id: string) => void;
  disabled?: boolean;
}) {
  if (disabled || options.length === 0) return null;
  return (
    <Dropdown.Root>
      <Dropdown.Trigger
        aria-label={label}
        className="border-line hover:bg-hover data-[state=open]:bg-hover flex items-center gap-1.5 rounded-full border px-2 py-1 text-sm"
      >
        <span className={cn(selected.length === 0 && "text-mute")}>
          {selected.length === 0 ? label : selected.join(", ")}
        </span>
        <ChevronDown className="text-mute size-3" />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        <Dropdown.Content
          sideOffset={4}
          className="border-line-strong bg-raised shadow-overlay z-50 min-w-44 rounded-lg border p-1"
        >
          {options.map((o) => (
            <Dropdown.CheckboxItem
              key={o.id}
              checked={selected.includes(o.label)}
              onCheckedChange={() => onToggle(o.label)}
              // Without this the menu closes on every pick.
              onSelect={(e) => e.preventDefault()}
              className="data-[highlighted=true]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
            >
              {o.swatch && (
                <span className="size-2 shrink-0 rounded-full" style={{ background: o.swatch }} />
              )}
              <span className="flex-1">{o.label}</span>
              {selected.includes(o.label) && <Check className="size-3" />}
            </Dropdown.CheckboxItem>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}
