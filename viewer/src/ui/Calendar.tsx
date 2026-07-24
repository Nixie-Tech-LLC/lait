import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight } from "lucide-react";

import type { BoardView, Row } from "../types";
import { tsToDate } from "../types";
import { PriorityIcon } from "./icons";
import { Button, IconButton } from "./primitives";

/**
 * The calendar view — the same filtered query as the list and board, placed on a
 * month grid by due date.
 *
 * No new data: `Row.due_date` already rides on every row (the list rows and board
 * cards render it too), so this is purely another arrangement of `board`'s rows —
 * exactly like `groupRows`, but two-dimensional. Dates are read in **UTC** because
 * the engine stores a due date as UTC midnight of the day the user named; a
 * local-time grid would file a deadline under the wrong square west of Greenwich.
 */
export function Calendar({
  board,
  onSelect,
}: {
  board: BoardView;
  onSelect: (reff: string) => void;
}) {
  const rows = useMemo(
    () => board.columns.flatMap((c) => c.rows).filter((r) => !r.tombstone),
    [board],
  );

  // Bucket dated rows by their UTC day key; keep the undated ones for the footer.
  const { byDay, undated } = useMemo(() => {
    const byDay = new Map<string, Row[]>();
    const undated: Row[] = [];
    for (const r of rows) {
      if (r.due_date == null) {
        undated.push(r);
        continue;
      }
      const key = dayKey(tsToDate(r.due_date));
      byDay.set(key, [...(byDay.get(key) ?? []), r]);
    }
    return { byDay, undated };
  }, [rows]);

  // The month on screen, as a UTC anchor at day 1. Starts on the current month.
  const [anchor, setAnchor] = useState(() => {
    const now = new Date();
    return Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1);
  });
  const anchorDate = new Date(anchor);
  const year = anchorDate.getUTCFullYear();
  const month = anchorDate.getUTCMonth();

  const step = (delta: number) => setAnchor(Date.UTC(year, month + delta, 1));
  const toThisMonth = () => {
    const now = new Date();
    setAnchor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
  };

  const weeks = useMemo(() => monthGrid(year, month), [year, month]);
  const todayKey = dayKey(new Date());
  const monthLabel = anchorDate.toLocaleDateString(undefined, {
    timeZone: "UTC",
    month: "long",
    year: "numeric",
  });

  return (
    <div className="flex min-h-0 flex-1 flex-col">
      <header className="border-line flex shrink-0 items-center gap-2 border-b px-3 py-2">
        <h2 className="text-sm font-semibold tabular-nums">{monthLabel}</h2>
        <div className="ml-2 flex items-center gap-0.5">
          <IconButton label="Previous month" onClick={() => step(-1)}>
            <ChevronLeft className="size-4" />
          </IconButton>
          <IconButton label="Next month" onClick={() => step(1)}>
            <ChevronRight className="size-4" />
          </IconButton>
        </div>
        <Button
          onClick={toThisMonth}
          variant="outline"
          className="ml-1"
        >
          Today
        </Button>
        <span className="text-mute ml-auto text-xs">
          {rows.length - undated.length} scheduled · {undated.length} undated
        </span>
      </header>

      <div className="grid shrink-0 grid-cols-7 border-b border-line">
        {WEEKDAYS.map((d) => (
          <div key={d} className="text-mute px-2 py-1 text-2xs font-semibold tracking-wider uppercase">
            {d}
          </div>
        ))}
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-7 grid-rows-6">
        {weeks.flat().map((day) => {
          const key = dayKey(day);
          const inMonth = day.getUTCMonth() === month;
          const dayRows = byDay.get(key) ?? [];
          return (
            <div
              key={key}
              className={`border-line flex min-h-0 flex-col gap-0.5 overflow-hidden border-r border-b p-1 ${
                inMonth ? "" : "bg-bg/40"
              }`}
            >
              <span
                className={`text-2xs tabular-nums ${
                  key === todayKey
                    ? "bg-accent text-accent-fg flex size-4 items-center justify-center rounded-full"
                    : inMonth
                      ? "text-dim"
                      : "text-mute"
                }`}
              >
                {day.getUTCDate()}
              </span>
              <div className="flex min-h-0 flex-col gap-0.5 overflow-y-auto">
                {dayRows.map((r) => (
                  <button
                    key={r.reff}
                    onClick={() => onSelect(r.reff)}
                    title={r.title}
                    className="bg-raised border-line hover:border-line-strong flex items-center gap-1 rounded border px-1 py-0.5 text-left text-2xs"
                  >
                    <PriorityIcon priority={r.priority} />
                    <span className="min-w-0 flex-1 truncate">{r.title}</span>
                  </button>
                ))}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

const WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"];

/** The `YYYY-MM-DD` UTC key a due date files under. */
function dayKey(d: Date): string {
  return d.toISOString().slice(0, 10);
}

/** Six weeks of UTC days covering `month`, Monday-first, spilling into the
 *  neighbouring months so the grid is always a full rectangle. */
function monthGrid(year: number, month: number): Date[][] {
  const first = new Date(Date.UTC(year, month, 1));
  // JS: 0=Sun … 6=Sat. Shift so Monday=0.
  const lead = (first.getUTCDay() + 6) % 7;
  const start = Date.UTC(year, month, 1 - lead);
  const weeks: Date[][] = [];
  for (let w = 0; w < 6; w++) {
    const week: Date[] = [];
    for (let d = 0; d < 7; d++) {
      week.push(new Date(start + (w * 7 + d) * 86_400_000));
    }
    weeks.push(week);
  }
  return weeks;
}
