import type { Priority, StatusCategory } from "../types";

/**
 * The two glyphs a tracker row lives or dies by.
 *
 * Hand-drawn rather than pulled from an icon set, and this is the exception that
 * proves the "don't build what exists" rule: priority and status are *data*
 * encoded as shape, not decoration. lucide has no bar-chart-priority or
 * partial-progress-ring, and approximating them with the nearest generic icon is
 * how a dense list stops being scannable — which is the whole point of the row.
 */

/** Priority as ascending bars, dimmed when unset. Linear's grammar, and it reads
 *  at a glance in a way a word never does at this density. */
export function PriorityIcon({ priority, className = "" }: { priority: Priority; className?: string }) {
  if (priority === "urgent") {
    return (
      <span
        className={`inline-flex size-4 shrink-0 items-center justify-center rounded-sm bg-urgent ${className}`}
        role="img"
        aria-label="Urgent priority"
      >
        <svg viewBox="0 0 16 16" className="size-3 fill-white" aria-hidden="true">
          <rect x="7" y="3.5" width="2" height="6" rx="1" />
          <rect x="7" y="11" width="2" height="2" rx="1" />
        </svg>
      </span>
    );
  }
  // 3 bars; `lit` counts how many are filled.
  const lit = { none: 0, low: 1, medium: 2, high: 3, urgent: 3 }[priority];
  const label = priority === "none" ? "No priority" : `${priority} priority`;
  return (
    <svg
      viewBox="0 0 16 16"
      className={`size-4 shrink-0 ${className}`}
      role="img"
      aria-label={label}
    >
      {[0, 1, 2].map((i) => (
        <rect
          key={i}
          x={2 + i * 5}
          y={11 - i * 3}
          width="3"
          height={3 + i * 3}
          rx="1"
          // An unset priority still draws all three bars, faintly: the shape has
          // to stay constant or the column jitters between rows.
          className={i < lit ? "fill-dim" : "fill-line-strong"}
        />
      ))}
    </svg>
  );
}

/**
 * Status as a progress ring, shaped by category so it reads without colour —
 * which matters for the ~8% of users who would otherwise see three identical
 * circles.
 */
export function StatusIcon({
  category,
  color,
  className = "",
}: {
  category: StatusCategory;
  color: string;
  className?: string;
}) {
  const label = { backlog: "Backlog", active: "In progress", done: "Done" }[category];
  return (
    <svg
      viewBox="0 0 14 14"
      className={`size-3.5 shrink-0 ${className}`}
      role="img"
      aria-label={label}
      style={{ color }}
    >
      <circle
        cx="7"
        cy="7"
        r="6"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        // Backlog is not started, and a dashed ring says so before the colour does.
        strokeDasharray={category === "backlog" ? "2.5 2" : undefined}
        opacity={category === "backlog" ? 0.65 : 1}
      />
      {category === "active" && (
        // A half-filled pie: "started, not finished".
        <path d="M7 7 L7 2.5 A4.5 4.5 0 0 1 7 11.5 Z" fill="currentColor" />
      )}
      {category === "done" && (
        <>
          <circle cx="7" cy="7" r="6" fill="currentColor" />
          <path
            d="M4.4 7.2 L6.2 9 L9.6 5.2"
            fill="none"
            stroke="var(--color-bg)"
            strokeWidth="1.6"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        </>
      )}
    </svg>
  );
}
