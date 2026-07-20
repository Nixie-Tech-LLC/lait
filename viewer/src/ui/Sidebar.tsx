import { Bot, Folder } from "lucide-react";

import { isReadOnly, type SpaceRow } from "../types";

/**
 * The sidebar body. Resizing and collapsing are the *panel's* job (see App) —
 * this only renders what is in it, so the layout mechanics and the content stay
 * independently replaceable.
 *
 * Your spaces and your agents' spaces are separate sections on purpose. They are
 * not the same kind of thing: an agent's daemon signs with the agent's key, the
 * engine refuses writes there, and mixing them into one list would be the UI
 * quietly implying otherwise.
 */
export function Sidebar({
  spaces,
  current,
  onPick,
}: {
  spaces: SpaceRow[];
  current: string | null;
  onPick: (id: string) => void;
}) {
  const mine = spaces.filter((s) => !isReadOnly(s));
  const agents = spaces.filter(isReadOnly);

  return (
    <nav className="flex h-full min-h-0 flex-col overflow-y-auto p-2">
      <Section title="Spaces" />
      <SpaceList rows={mine} current={current} onPick={onPick} empty="No spaces yet." />
      {agents.length > 0 && (
        <>
          <Section title="Agents" hint="Read-only — writes would sign as the agent" />
          <SpaceList rows={agents} current={current} onPick={onPick} empty="" />
        </>
      )}
    </nav>
  );
}

function Section({ title, hint }: { title: string; hint?: string }) {
  return (
    <h2
      className="text-mute mt-4 mb-1 px-2 text-2xs font-semibold tracking-[0.08em] uppercase first:mt-1"
      title={hint}
    >
      {title}
    </h2>
  );
}

function SpaceList({
  rows,
  current,
  onPick,
  empty,
}: {
  rows: SpaceRow[];
  current: string | null;
  onPick: (id: string) => void;
  empty: string;
}) {
  if (rows.length === 0) {
    return empty ? <p className="text-mute px-2 py-1 text-sm">{empty}</p> : null;
  }
  return (
    <ul role="listbox" className="flex flex-col gap-px">
      {rows.map((s) => {
        // Narrow once and carry the name: the discriminant is what proves an
        // agent *has* a name, so reading it off the union would be a lie.
        const agent = s.identity.kind === "agent" ? s.identity.name : null;
        return (
          <li key={s.id}>
            <button
              role="option"
              aria-selected={s.id === current}
              onClick={() => onPick(s.id)}
              // `truncate` needs a min-w-0 flex child; without it a long space
              // name pushes the status dot out of the panel instead of eliding.
              className={[
                "flex w-full items-center gap-2 rounded px-2 py-1 text-left transition-colors",
                s.id === current ? "bg-active text-fg" : "text-dim hover:bg-hover hover:text-fg",
              ].join(" ")}
              title={agent ? `${agent}'s space (read-only) — ${s.path}` : s.path}
            >
              {agent ? (
                <Bot className="text-mute size-3.5 shrink-0" />
              ) : (
                <Folder className="text-mute size-3.5 shrink-0" />
              )}
              <span className="min-w-0 flex-1 truncate">{s.name || s.space}</span>
              <StatusDot status={s.status} />
            </button>
          </li>
        );
      })}
    </ul>
  );
}

/** `up` | `idle` | `missing`, exactly as `lait spaces` reports it. */
function StatusDot({ status }: { status: SpaceRow["status"] }) {
  const cls = { up: "bg-ok", idle: "bg-mute", missing: "bg-danger" }[status];
  return (
    <span
      className={`size-1.5 shrink-0 rounded-full ${cls}`}
      title={status}
      role="img"
      aria-label={status}
    />
  );
}
