import type { Priority, WorkflowState } from "./types";
import { DEFAULT_WORKFLOW } from "./types";

const COLOR_VAR: Record<string, string> = {
  gray: "var(--c-gray)",
  blue: "var(--c-blue)",
  yellow: "var(--c-yellow)",
  green: "var(--c-green)",
  red: "var(--c-red)",
  orange: "var(--c-orange)",
};

export function colorOf(name: string | undefined): string {
  if (!name) return "var(--c-gray)";
  return COLOR_VAR[name] ?? (name.startsWith("#") ? name : "var(--c-gray)");
}

export function statusMeta(id: string): WorkflowState {
  return (
    DEFAULT_WORKFLOW.find((s) => s.id === id) ?? {
      id,
      name: id,
      category: "backlog",
      color: "gray",
    }
  );
}

export function StatusDot({ status }: { status: string }) {
  const s = statusMeta(status);
  return (
    <span
      className={"status-dot" + (s.category === "done" ? " filled" : "")}
      style={{ color: colorOf(s.color) }}
      title={s.name}
    />
  );
}

const PRIO_LEVEL: Record<Priority, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  urgent: 4,
};

export function PriorityBars({ priority }: { priority: Priority }) {
  const level = PRIO_LEVEL[priority] ?? 0;
  if (priority === "urgent") {
    return (
      <span className="prio" title="Urgent" style={{ color: "var(--c-orange)" }}>
        <span style={{ fontSize: 12, lineHeight: 1 }}>⚠</span>
      </span>
    );
  }
  return (
    <span className="prio" title={priority}>
      {[6, 9, 12].map((h, i) => (
        <i key={i} className={i < level ? "on" : ""} style={{ height: h }} />
      ))}
    </span>
  );
}

export function fmtTime(ms: number): string {
  if (!ms) return "";
  const d = new Date(ms);
  const now = Date.now();
  const diff = now - ms;
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.round(hrs / 24);
  if (days < 7) return `${days}d ago`;
  return d.toLocaleDateString();
}
