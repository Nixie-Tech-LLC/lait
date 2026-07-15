import { useCallback, useEffect, useRef, useState } from "react";
import * as Dropdown from "@radix-ui/react-dropdown-menu";
import { Check, ChevronDown, Trash2 } from "lucide-react";

import { rpc } from "../api";
import { PRIORITY_ORDER, tsToDate, type IssueView, type Priority, type WorkflowState } from "../types";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";

/**
 * The issue detail — co-visible beside the list, not an overlay.
 *
 * The TUI called this "peek" and kept it deliberately *off* the overlay stack so a
 * picker could sit over it while the list still rendered behind. Same reasoning
 * here: it is a third panel, so it does not steal the keymap and the list keeps
 * moving under `j`/`k` while you read.
 *
 * Every edit is a `Request` on the way out and a doorbell on the way back. Nothing
 * here refetches after a write: the daemon rings, the doorbell reloads the row, and
 * the detail re-reads with it. That is what keeps this pane and the list from ever
 * disagreeing about what an issue says.
 */
export function IssueDetail({
  spaceId,
  reff,
  states,
  readOnly,
  onError,
  onDelete,
  revision,
}: {
  spaceId: string;
  reff: string;
  states: WorkflowState[];
  readOnly: boolean;
  onError: (m: string) => void;
  onDelete: (reff: string) => void;
  /** Bumped by the doorbell; re-reads without this pane knowing why. */
  revision: number;
}) {
  const [issue, setIssue] = useState<IssueView | null>(null);
  const [draft, setDraft] = useState("");
  const [comment, setComment] = useState("");
  const titleRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const r = await rpc(spaceId, { cmd: "issue_view", reff });
        if (!alive) return;
        if (r.kind === "issue") {
          setIssue(r);
          setDraft(r.title);
        }
      } catch (e) {
        if (alive) onError(e instanceof Error ? e.message : String(e));
      }
    })();
    return () => {
      alive = false;
    };
    // `revision` is the doorbell: a change anywhere in this space re-reads.
  }, [spaceId, reff, revision, onError]);

  const edit = useCallback(
    async (patch: { title?: string; status?: string; priority?: string; description?: string }) => {
      try {
        await rpc(spaceId, { cmd: "issue_edit", reff, ...patch });
      } catch (e) {
        onError(e instanceof Error ? e.message : String(e));
      }
    },
    [spaceId, reff, onError],
  );

  if (!issue) {
    return <aside className="border-line text-mute border-l p-4 text-sm">Loading…</aside>;
  }

  const state = states.find((s) => s.id === issue.status);

  const saveTitle = () => {
    const next = draft.trim();
    if (!next || next === issue.title) return setDraft(issue.title);
    void edit({ title: next });
  };

  return (
    <aside className="border-line flex h-full min-h-0 flex-col overflow-y-auto border-l">
      <header className="border-line flex h-11 shrink-0 items-center gap-2 border-b px-3">
        <span className="text-mute font-mono text-xs tabular-nums">
          {issue.key_alias ?? issue.reff}
        </span>
        {issue.provisional && (
          <span className="text-warn text-2xs" title="The issue body hasn't synced yet">
            provisional
          </span>
        )}
        {!readOnly && (
          <button
            onClick={() => onDelete(issue.reff)}
            className="text-mute hover:text-danger ml-auto grid size-6 place-items-center rounded"
            title="Delete issue"
            aria-label="Delete issue"
          >
            <Trash2 className="size-3.5" />
          </button>
        )}
      </header>

      <div className="flex flex-col gap-4 p-4">
        {/* A textarea, not an input: a long title should wrap rather than scroll
            sideways past the edge of the pane. */}
        <textarea
          ref={titleRef}
          value={draft}
          readOnly={readOnly}
          rows={Math.max(1, Math.ceil(draft.length / 40))}
          onChange={(e) => setDraft(e.target.value)}
          onBlur={saveTitle}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              titleRef.current?.blur();
            }
            if (e.key === "Escape") {
              setDraft(issue.title);
              titleRef.current?.blur();
            }
          }}
          className="resize-none bg-transparent text-lg font-semibold outline-none"
          aria-label="Title"
        />

        <div className="flex flex-wrap gap-2">
          <Picker
            label="Status"
            disabled={readOnly}
            trigger={
              <>
                {state && (
                  <StatusIcon category={state.category} color={catalogColor(state.color)} />
                )}
                {state?.name ?? issue.status}
              </>
            }
            items={states.map((s) => ({
              id: s.id,
              label: s.name,
              icon: <StatusIcon category={s.category} color={catalogColor(s.color)} />,
              active: s.id === issue.status,
            }))}
            onPick={(id) => void edit({ status: id })}
          />

          <Picker
            label="Priority"
            disabled={readOnly}
            trigger={
              <>
                <PriorityIcon priority={issue.priority} />
                <span className="capitalize">{issue.priority}</span>
              </>
            }
            // Highest first: the list you scan top-down should start where the
            // urgency does.
            items={[...PRIORITY_ORDER].reverse().map((p) => ({
              id: p,
              label: p,
              icon: <PriorityIcon priority={p} />,
              active: p === issue.priority,
            }))}
            onPick={(id) => void edit({ priority: id })}
          />
        </div>

        {(issue.assignees.length > 0 || issue.label_names.length > 0) && (
          <dl className="flex flex-col gap-2 text-sm">
            {issue.assignees.length > 0 && (
              <Field label="Assignees">{issue.assignees.map(short).join(", ")}</Field>
            )}
            {issue.label_names.length > 0 && (
              <Field label="Labels">
                <span className="flex flex-wrap gap-1">
                  {issue.label_names.map((l) => (
                    <span key={l} className="border-line-strong rounded-full border px-2 text-2xs">
                      {l}
                    </span>
                  ))}
                </span>
              </Field>
            )}
          </dl>
        )}

        <Description
          value={issue.description}
          readOnly={readOnly}
          onSave={(description) => void edit({ description })}
        />

        <section className="flex flex-col gap-3">
          <h3 className="text-mute text-2xs font-semibold tracking-wider uppercase">
            Comments {issue.comments.length > 0 && `· ${issue.comments.length}`}
          </h3>
          {issue.comments.map((c, i) => (
            <article key={i} className="flex flex-col gap-1">
              <div className="flex items-baseline gap-2">
                <span className="font-medium">{c.author_nick ?? short(c.author)}</span>
                {/* Unix SECONDS — `tsToDate` is the only place that's converted. */}
                <time className="text-mute text-xs" dateTime={tsToDate(c.ts).toISOString()}>
                  {when(c.ts)}
                </time>
              </div>
              <p className="whitespace-pre-wrap">{c.body}</p>
            </article>
          ))}
          {!readOnly && (
            <textarea
              value={comment}
              placeholder="Leave a comment…  (⌘/Ctrl + Enter)"
              onChange={(e) => setComment(e.target.value)}
              onKeyDown={(e) => {
                // The one chord that survives the typing guard, and the one people
                // expect: submit without reaching for the mouse.
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && comment.trim()) {
                  e.preventDefault();
                  const body = comment.trim();
                  setComment("");
                  void rpc(spaceId, { cmd: "comment", reff, body }).catch((err) =>
                    onError(err instanceof Error ? err.message : String(err)),
                  );
                }
              }}
              rows={2}
              className="border-line focus-within:border-line-strong placeholder:text-mute resize-y rounded border bg-transparent p-2 outline-none"
              aria-label="New comment"
            />
          )}
        </section>

        <footer className="text-mute border-line mt-2 border-t pt-3 text-xs">
          Opened by {short(issue.created_by)} · {when(issue.created_at)}
        </footer>
      </div>
    </aside>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <dt className="text-mute w-20 shrink-0">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}

/** Description: a draft you commit, not a field that saves per keystroke — a
 *  doorbell mid-typing would otherwise fight the cursor. */
function Description({
  value,
  readOnly,
  onSave,
}: {
  value: string;
  readOnly: boolean;
  onSave: (v: string) => void;
}) {
  const [draft, setDraft] = useState(value);
  const [editing, setEditing] = useState(false);

  // Adopt server truth whenever we're not the one holding the pen.
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  if (readOnly || (!editing && value)) {
    return (
      <p
        className={`min-h-8 whitespace-pre-wrap ${readOnly ? "" : "hover:bg-hover -mx-2 cursor-text rounded px-2"}`}
        onClick={() => !readOnly && setEditing(true)}
      >
        {value || <span className="text-mute">No description</span>}
      </p>
    );
  }
  if (!editing) {
    return (
      <button
        onClick={() => setEditing(true)}
        className="text-mute hover:text-fg -mx-2 rounded px-2 py-1 text-left"
      >
        Add description…
      </button>
    );
  }
  return (
    <textarea
      autoFocus
      value={draft}
      rows={5}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        setEditing(false);
        if (draft !== value) onSave(draft);
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          setDraft(value);
          setEditing(false);
        }
      }}
      className="border-line focus:border-line-strong resize-y rounded border bg-transparent p-2 outline-none"
      aria-label="Description"
    />
  );
}

function Picker({
  label,
  trigger,
  items,
  onPick,
  disabled,
}: {
  label: string;
  trigger: React.ReactNode;
  items: Array<{ id: string; label: string; icon: React.ReactNode; active: boolean }>;
  onPick: (id: string) => void;
  disabled: boolean;
}) {
  if (disabled) {
    return (
      <span className="border-line text-dim flex items-center gap-1.5 rounded border px-2 py-1 text-sm">
        {trigger}
      </span>
    );
  }
  return (
    <Dropdown.Root>
      <Dropdown.Trigger
        aria-label={label}
        className="border-line hover:bg-hover data-[state=open]:bg-hover flex items-center gap-1.5 rounded border px-2 py-1 text-sm"
      >
        {trigger}
        <ChevronDown className="text-mute size-3" />
      </Dropdown.Trigger>
      <Dropdown.Portal>
        {/* Radix owns focus trapping, escape, outside-click, and collision
            flipping — all of which are invisible until they're missing. */}
        <Dropdown.Content
          sideOffset={4}
          className="border-line-strong bg-raised shadow-overlay z-50 min-w-40 rounded-lg border p-1"
        >
          {items.map((i) => (
            <Dropdown.Item
              key={i.id}
              onSelect={() => onPick(i.id)}
              className="data-[highlighted=true]:bg-hover flex cursor-default items-center gap-2 rounded px-2 py-1 text-sm outline-none"
            >
              {i.icon}
              <span className="flex-1 capitalize">{i.label}</span>
              {i.active && <Check className="size-3" />}
            </Dropdown.Item>
          ))}
        </Dropdown.Content>
      </Dropdown.Portal>
    </Dropdown.Root>
  );
}

/** Keys are 64 hex chars; nobody reads more than the head of one. */
const short = (key: string) => key.slice(0, 8);

/** Relative time, unix seconds in. Coarse on purpose — "3d" is what you want on a
 *  row, and the exact stamp is one hover away via `<time dateTime>`. */
function when(ts: number): string {
  const secs = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (secs < 60) return "just now";
  const mins = Math.floor(secs / 60);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days < 30) return `${days}d ago`;
  return tsToDate(ts).toLocaleDateString(undefined, { month: "short", day: "numeric" });
}

export type { Priority };
