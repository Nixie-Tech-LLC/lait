import { useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import { Command } from "cmdk";
import { Check, ChevronDown, Plus } from "lucide-react";

import { cmdkFilter } from "../core/fuzzy";
import {
  cn,
  controlTrigger,
  type ControlTriggerVariant,
  PopoverContent,
} from "./primitives";

/**
 * A pill that opens a searchable menu — the tracker's workhorse control.
 *
 * **One control, not one per field.** Status, priority, assignees, labels, and
 * project are all "pick from a set", and the moment they stop being the same
 * component they start disagreeing: about where the check mark goes, whether the
 * menu closes on pick, whether search exists. That drift is invisible in review and
 * obvious in use, so there is exactly one of these.
 *
 * **The search field is always there**, including over four statuses where it looks
 * like overkill. Two reasons, and the second is the real one:
 *
 * 1. It makes every picker keyboard-complete — `s` `d` `o` `n` `↵` sets Done without
 *    the hand leaving the keys, which is the whole point of this client.
 * 2. `cmdk` drives its list from the input's focus. Hiding the input below some
 *    threshold means Radix focuses the popover content instead, and the keydown
 *    never reaches `Command`'s handler — arrow keys silently stop working on
 *    exactly the small menus that looked too simple to break.
 *
 * Radix's Popover owns focus trapping, escape, outside-click, and collision
 * flipping; `cmdk` owns roving focus, `aria-activedescendant`, and scroll-into-view.
 * The *ranking* stays ours (`cmdkFilter`), so the palette and every picker agree on
 * what "matches" means.
 *
 * `open`/`onOpenChange` are exposed so a keybinding can open a picker — `a` has to
 * reach the assignee menu without a mouse, and a component with private open state
 * could not be driven from the registry.
 */

export interface Option {
  id: string;
  label: string;
  icon?: React.ReactNode;
  swatch?: string;
  /** Secondary text, muted and right-aligned — a key prefix under a petname. */
  hint?: string;
  /** Matched by search but not shown. A member's full key, a label's id. */
  keywords?: string[];
}

type Mode =
  | { multi?: false; value: Option | null; onPick: (id: string) => void }
  | { multi: true; selected: readonly string[]; onToggle: (id: string) => void };

type Props = {
  /** Accessible name, and the trigger's text when nothing is chosen. */
  label: string;
  options: Option[];
  /** Trigger content. Defaults to the single-select face. */
  face?: React.ReactNode;
  disabled?: boolean;
  placeholder?: string;
  className?: string;
  /** Controlled, so a keybinding can open this. Uncontrolled if omitted. */
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  emptyText?: string;
  /**
   * Make the picker *creatable*: typing a name no option carries offers a
   * "Create" row (Linear's on-the-fly labels). The daemon is the one that
   * actually mints — this only forwards the typed name — so the row appears
   * exactly when the query matches no existing label, not on every keystroke.
   */
  onCreate?: (text: string) => void;
} & Mode & {
  variant?: ControlTriggerVariant;
};

export function Combobox(props: Props) {
  const {
    label,
    options,
    face,
    disabled,
    placeholder,
    className,
    open,
    onOpenChange,
    emptyText,
    variant,
    onCreate,
  } = props;

  // Open state is internal *and* overridable. A keybinding needs to force it open;
  // a single-select pick needs to close it. Both have to work, so the component owns
  // a copy and mirrors any controlled value over the top.
  const [internal, setInternal] = useState(false);
  // The live query, held only so the create row can offer what was typed.
  const [query, setQuery] = useState("");
  const isOpen = open ?? internal;
  const setOpen = (o: boolean) => {
    setInternal(o);
    onOpenChange?.(o);
    if (!o) setQuery("");
  };

  const single = props.multi !== true ? props.value : null;
  const content = face ?? (
    <>
      {single?.icon}
      {single?.swatch && (
        <span className="size-2 shrink-0 rounded-full" style={{ background: single.swatch }} />
      )}
      <span className={cn("min-w-0 truncate", !single && "text-mute")}>{single?.label ?? placeholder ?? label}</span>
    </>
  );

  // A read-only space still shows its values — it just cannot open a menu over
  // them. Rendering nothing would hide the data; rendering a dead button would
  // promise something the engine refuses.
  if (disabled) {
    return (
      <span
        className={cn(
          controlTrigger({ variant }),
          "text-dim",
          className,
        )}
      >
        {content}
      </span>
    );
  }

  const isSelected = (id: string) =>
    props.multi === true ? props.selected.includes(id) : props.value?.id === id;

  return (
    <Popover.Root open={isOpen} onOpenChange={setOpen}>
      <Popover.Trigger aria-label={label} className={cn(controlTrigger({ variant }), className)}>
        {content}
        {/* A bare trigger keeps its chevron hidden until hover: in a property list
            the value is the content and five permanent chevrons are five arrows
            pointing at nothing. It still appears on keyboard focus. */}
        <ChevronDown
          className={cn(
            "text-mute size-3 shrink-0",
            variant === "property" &&
              "opacity-0 transition-opacity group-hover/prop:opacity-100 group-focus-within/prop:opacity-100",
          )}
        />
      </Popover.Trigger>
      <PopoverContent align="start" className="w-60 overflow-hidden p-0">
          <Command filter={cmdkFilter} loop>
            <Command.Input
              autoFocus
              value={query}
              onValueChange={setQuery}
              placeholder={`${label}…`}
              className="border-line placeholder:text-mute w-full border-b bg-transparent px-3 py-2 text-sm outline-none"
            />
            <Command.List className="max-h-64 overflow-y-auto p-1">
              {/* The create row replaces "no matches" when creating is possible:
                  an empty result with a dead end and an empty result with a way
                  forward are different answers. */}
              {!(onCreate && query.trim()) && (
                <Command.Empty className="text-mute px-2 py-3 text-center text-sm">
                  {emptyText ?? "No matches"}
                </Command.Empty>
              )}
              {options.map((o) => (
                <Command.Item
                  key={o.id}
                  // Identity is the **id**, not the label: cmdk keys items by
                  // `value`, so two members sharing a petname — or two labels named
                  // the same in different cases — would collapse into one row that
                  // highlights twice. Search still reaches the label through
                  // `keywords`, which `cmdkFilter` scores identically.
                  value={o.id}
                  keywords={[o.label, ...(o.keywords ?? [])]}
                  onSelect={() => {
                    if (props.multi === true) {
                      // Multi stays open: choosing three labels should cost one trip
                      // to the menu, not three.
                      props.onToggle(o.id);
                    } else {
                      props.onPick(o.id);
                      setOpen(false);
                    }
                  }}
                  className="data-[selected=true]:bg-active flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
                >
                  {o.icon}
                  {o.swatch && (
                    <span className="size-2 shrink-0 rounded-full" style={{ background: o.swatch }} />
                  )}
                  <span className="min-w-0 flex-1 truncate">{o.label}</span>
                  {o.hint && <span className="text-mute shrink-0 font-mono text-2xs">{o.hint}</span>}
                  {/* Reserve the check's width always, or every row shifts sideways
                      the moment one becomes selected. */}
                  <span className="size-3 shrink-0">
                    {isSelected(o.id) && <Check className="size-3" />}
                  </span>
                </Command.Item>
              ))}
              {onCreate &&
                query.trim() &&
                !options.some((o) => o.label.toLowerCase() === query.trim().toLowerCase()) && (
                  <Command.Item
                    // forceMount: this row must survive cmdk's filter — its whole
                    // point is to show when nothing else matches the query.
                    forceMount
                    value={`create:${query.trim()}`}
                    onSelect={() => {
                      onCreate(query.trim());
                      setQuery("");
                      if (props.multi !== true) setOpen(false);
                    }}
                    className="data-[selected=true]:bg-active flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
                  >
                    <Plus className="size-3 shrink-0" />
                    <span className="min-w-0 flex-1 truncate">
                      Create “{query.trim()}”
                    </span>
                  </Command.Item>
                )}
            </Command.List>
          </Command>
      </PopoverContent>
    </Popover.Root>
  );
}
