import { useState } from "react";
import * as Popover from "@radix-ui/react-popover";
import { Calendar, ChevronLeft, ChevronRight, X } from "lucide-react";

import {
  Button,
  cn,
  controlTrigger,
  type ControlTriggerVariant,
  IconButton,
  PopoverContent,
} from "./primitives";

/**
 * A date picker that belongs to the design system — the one control that used to
 * be the browser's native `<input type="date">`.
 *
 * The native input was defensible (its picker beats anything hand-rolled), and it
 * was also the single control that looked different on every OS and nothing like
 * the `Combobox` popover every other field opens. Worse, it made "tomorrow" a
 * calendar-driving chore: the deadlines people actually set are relative, and Linear
 * leads its date control with exactly those — Today, Tomorrow, Next week — before
 * the grid. So do we.
 *
 * **Everything is UTC.** The engine stores a due date as UTC midnight of the day you
 * named (see `time.ts::dueLabel`), and the wire format is `YYYY-MM-DD`. This whole
 * component computes in UTC so the day you tap is the day that gets stored, with no
 * timezone drift bending it a day either way. `value` and the argument to `onChange`
 * are that same `YYYY-MM-DD` string (or `null` for "no date") — the component never
 * touches unix seconds, so the caller's engine round-trip is a pure pass-through.
 */

// A day as its UTC calendar date, never a local one.
function utcDay(y: number, m: number, d: number): Date {
  return new Date(Date.UTC(y, m, d));
}
function todayUtc(): Date {
  const now = new Date();
  return utcDay(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
}
function parseInput(s: string): Date {
  const [y, m, d] = s.split("-").map(Number);
  return utcDay(y ?? 1970, (m ?? 1) - 1, d ?? 1);
}
function toInput(d: Date): string {
  return d.toISOString().slice(0, 10);
}
function addDays(d: Date, n: number): Date {
  return utcDay(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate() + n);
}
function startOfMonth(d: Date): Date {
  return utcDay(d.getUTCFullYear(), d.getUTCMonth(), 1);
}
function addMonths(d: Date, n: number): Date {
  return utcDay(d.getUTCFullYear(), d.getUTCMonth() + n, 1);
}
// Monday-indexed weekday (0 = Monday), the week most product calendars open on.
function mondayIndex(d: Date): number {
  return (d.getUTCDay() + 6) % 7;
}

const WEEKDAYS = ["Mo", "Tu", "We", "Th", "Fr", "Sa", "Su"];

function labelFor(value: string): string {
  const d = parseInput(value);
  const sameYear = d.getUTCFullYear() === new Date().getUTCFullYear();
  return d.toLocaleDateString(undefined, {
    timeZone: "UTC",
    month: "short",
    day: "numeric",
    ...(sameYear ? {} : { year: "numeric" }),
  });
}

export function DatePicker({
  value,
  onChange,
  disabled,
  variant,
  ariaLabel = "Due date",
  placeholder = "None",
  className,
}: {
  value: string | null;
  onChange: (next: string | null) => void;
  disabled?: boolean;
  ariaLabel?: string;
  /** Trigger text (and colour) when `value` is null. */
  placeholder?: string;
  /** Extra trigger classes — the caller's tone colour rides here. */
  className?: string;
  variant?: ControlTriggerVariant;
}) {
  const [open, setOpen] = useState(false);
  const [view, setView] = useState<Date>(() =>
    startOfMonth(value ? parseInput(value) : todayUtc()),
  );

  const today = todayUtc();
  const selected = value;

  const pick = (next: string | null) => {
    onChange(next);
    setOpen(false);
  };

  // A read-only field still shows its value — it just can't open a menu over it.
  if (disabled) {
    return (
      <span className={cn(controlTrigger({ variant }), "text-dim", !value && "text-mute", className)}>
        {value ? labelFor(value) : placeholder}
      </span>
    );
  }

  const monthStart = view;
  const gridStart = addDays(monthStart, -mondayIndex(monthStart));
  const cells = Array.from({ length: 42 }, (_, i) => addDays(gridStart, i));

  const quick: { label: string; value: string | null }[] = [
    { label: "Today", value: toInput(today) },
    { label: "Tomorrow", value: toInput(addDays(today, 1)) },
    { label: "Next week", value: toInput(addDays(today, 7)) },
    { label: "No due date", value: null },
  ];

  return (
    <Popover.Root
      open={open}
      onOpenChange={(o) => {
        setOpen(o);
        // Re-centre on the current value each time it opens — you almost always
        // want to start from the date that's set, not wherever you last browsed.
        if (o) setView(startOfMonth(value ? parseInput(value) : todayUtc()));
      }}
    >
      <Popover.Trigger
        aria-label={ariaLabel}
        className={cn(controlTrigger({ variant }), !value && "text-mute", className)}
      >
        <Calendar className="text-mute size-3.5 shrink-0" />
        <span>{value ? labelFor(value) : placeholder}</span>
      </Popover.Trigger>
      <PopoverContent align="start" className="w-64 p-2">
        <div className="mb-1 flex flex-col gap-0.5">
          {quick.map((q) => (
            <Button
              key={q.label}
              onClick={() => pick(q.value)}
              className="w-full justify-between"
            >
              {q.label}
              {q.value === null && selected && <X className="text-mute size-3" />}
            </Button>
          ))}
        </div>

        <div className="border-line border-t pt-2">
          <div className="mb-1 flex items-center justify-between px-1">
            <IconButton
              label="Previous month"
              onClick={() => setView(addMonths(view, -1))}
            >
              <ChevronLeft className="size-3.5" />
            </IconButton>
            <span className="text-sm font-medium">
              {view.toLocaleDateString(undefined, {
                timeZone: "UTC",
                month: "long",
                year: "numeric",
              })}
            </span>
            <IconButton
              label="Next month"
              onClick={() => setView(addMonths(view, 1))}
            >
              <ChevronRight className="size-3.5" />
            </IconButton>
          </div>

          <div className="grid grid-cols-7 gap-0.5">
            {WEEKDAYS.map((w) => (
              <span key={w} className="text-mute py-1 text-center text-2xs font-medium">
                {w}
              </span>
            ))}
            {cells.map((cell) => {
              const iso = toInput(cell);
              const inMonth = cell.getUTCMonth() === monthStart.getUTCMonth();
              const isSelected = iso === selected;
              const isToday = iso === toInput(today);
              return (
                <Button
                  key={iso}
                  onClick={() => pick(iso)}
                  size="icon"
                  aria-label={cell.toLocaleDateString(undefined, {
                    timeZone: "UTC",
                    weekday: "long",
                    month: "long",
                    day: "numeric",
                    year: "numeric",
                  })}
                  aria-pressed={isSelected}
                  className={cn(
                    "size-7 text-sm tabular-nums",
                    isSelected
                      ? "bg-accent text-accent-fg"
                      : inMonth
                        ? "text-fg hover:bg-active"
                        : "text-mute hover:bg-active",
                    isToday && !isSelected && "ring-line-strong ring-1 ring-inset",
                  )}
                >
                  {cell.getUTCDate()}
                </Button>
              );
            })}
          </div>
        </div>
      </PopoverContent>
    </Popover.Root>
  );
}
