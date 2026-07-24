import { useMemo } from "react";

import type { ProjectDto } from "../types";
import { tsToDate } from "../types";
import { catalogColor } from "./colors";
import { EmptyState } from "./AppState";
import { Button } from "./primitives";

/**
 * The timeline / roadmap view — projects as horizontal bars across months.
 *
 * Project spans (`start_date` → `target_date`) landed with the project-overview
 * layer (SCOPE-1), so this is a pure rendering of data that already exists: no
 * engine call of its own. Issue-level bars would need a per-issue start date the
 * schema does not carry yet; this draws the project granularity, which does.
 *
 * Dates are read in UTC to agree with the DatePicker that set them.
 */
export function Timeline({
  projects,
  onOpenProject,
}: {
  projects: ProjectDto[];
  onOpenProject: (key: string) => void;
}) {
  const scheduled = useMemo(
    () => projects.filter((p) => p.start_date != null || p.target_date != null),
    [projects],
  );
  const unscheduled = useMemo(
    () => projects.filter((p) => p.start_date == null && p.target_date == null),
    [projects],
  );

  // The window every bar is positioned within: the earliest start to the latest
  // target, snapped out to whole months and padded by one on each side.
  const range = useMemo(() => {
    const stamps: number[] = [];
    for (const p of scheduled) {
      if (p.start_date != null) stamps.push(p.start_date);
      if (p.target_date != null) stamps.push(p.target_date);
    }
    if (stamps.length === 0) return null;
    const lo = tsToDate(Math.min(...stamps));
    const hi = tsToDate(Math.max(...stamps));
    const start = Date.UTC(lo.getUTCFullYear(), lo.getUTCMonth() - 1, 1);
    const end = Date.UTC(hi.getUTCFullYear(), hi.getUTCMonth() + 2, 1);
    return { start, end, span: end - start };
  }, [scheduled]);

  const months = useMemo(() => (range ? monthTicks(range.start, range.end) : []), [range]);

  if (!range) {
    return (
      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <EmptyState
          title="No scheduled projects"
          body="Give a project a start or target date (on its overview page) and it appears here as a roadmap bar."
        />
      </div>
    );
  }

  const pct = (ms: number) => ((ms - range.start) / range.span) * 100;

  return (
    <div className="min-h-0 flex-1 overflow-auto">
      <div className="min-w-[720px] p-4">
        {/* Month scale. */}
        <div className="text-mute relative mb-2 ml-48 h-5 border-b border-line">
          {months.map((m) => (
            <span
              key={m.ms}
              className="absolute top-0 text-2xs"
              style={{ left: `${pct(m.ms)}%` }}
            >
              {m.label}
            </span>
          ))}
        </div>

        <div className="flex flex-col gap-1.5">
          {scheduled.map((p) => {
            const s = p.start_date ?? p.target_date!;
            const e = p.target_date ?? p.start_date!;
            const left = pct(s);
            const width = Math.max(1.5, pct(e) - left);
            return (
              <div key={p.id} className="flex items-center gap-2">
                <Button
                  onClick={() => onOpenProject(p.key)}
                  className="w-48 justify-start truncate px-1 text-left"
                >
                  <span
                    className="size-2.5 shrink-0 rounded-full"
                    style={{ background: catalogColor(p.color) }}
                  />
                  <span className="truncate">{p.name}</span>
                </Button>
                <div className="relative h-6 flex-1">
                  <Button
                    onClick={() => onOpenProject(p.key)}
                    title={`${p.name}${p.start_date == null ? " (no start)" : ""}${p.target_date == null ? " (no target)" : ""}`}
                    className="absolute top-0.5 h-5 p-0"
                    style={{
                      left: `${left}%`,
                      width: `${width}%`,
                      background: catalogColor(p.color),
                      opacity: p.start_date == null || p.target_date == null ? 0.5 : 0.85,
                    }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {unscheduled.length > 0 && (
          <div className="mt-6">
            <h3 className="text-mute mb-2 text-2xs font-semibold tracking-wider uppercase">
              Unscheduled · {unscheduled.length}
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {unscheduled.map((p) => (
                <Button
                  key={p.id}
                  onClick={() => onOpenProject(p.key)}
                  variant="outline"
                >
                  <span
                    className="size-2.5 rounded-full"
                    style={{ background: catalogColor(p.color) }}
                  />
                  {p.name}
                </Button>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

/** First-of-month UTC ticks from `start` to `end` (exclusive of the trailing
 *  edge), each with a short label. */
function monthTicks(start: number, end: number): { ms: number; label: string }[] {
  const out: { ms: number; label: string }[] = [];
  const d = new Date(start);
  let y = d.getUTCFullYear();
  let m = d.getUTCMonth();
  while (Date.UTC(y, m, 1) < end) {
    const ms = Date.UTC(y, m, 1);
    out.push({
      ms,
      label: new Date(ms).toLocaleDateString(undefined, {
        timeZone: "UTC",
        month: "short",
        ...(m === 0 ? { year: "2-digit" } : {}),
      }),
    });
    m += 1;
    if (m > 11) {
      m = 0;
      y += 1;
    }
  }
  return out;
}
