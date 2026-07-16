import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Ban, CircleDot, CornerDownRight, GitMerge, Info, Trash2 } from "lucide-react";

import { rpc } from "../api";
import { describeChanges, describeEvent, type NameResolver } from "../core/activity";
import type { Field as PredictField } from "../core/overlay";
import type { IssueField } from "../core/registry";
import {
  type GraphView,
  type LinkDto,
  type Row,
  PRIORITY_ORDER,
  tsToDate,
  type ActivityEvent,
  type CommentDto,
  type IssueView,
  type LabelDto,
  type MemberDto,
  type ProjectDto,
  type WorkflowState,
} from "../types";
import { Avatar, AvatarStack, memberName as nameOf } from "./Avatar";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Combobox } from "./Picker";
import { IconButton } from "./primitives";
import { short, when } from "./time";

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
  members,
  labels,
  projects,
  readOnly,
  openField,
  onOpenField,
  onError,
  onDelete,
  onPredict,
  onNavigate,
  revision,
}: {
  spaceId: string;
  reff: string;
  states: WorkflowState[];
  /** The signed ACL, for the assignee picker. Keys are the only real identity. */
  members: MemberDto[];
  labels: LabelDto[];
  projects: ProjectDto[];
  readOnly: boolean;
  /** Which picker a keybinding wants open, if any. */
  openField: IssueField | null;
  onOpenField: (f: IssueField | null) => void;
  onError: (m: string) => void;
  onDelete: (reff: string) => void;
  /** Predict `(doc, field)` locally, then send. The doorbell retires the guess. */
  onPredict: (doc: string, field: PredictField, value: string, send: () => Promise<unknown>) => void;
  /** Select another issue — following a graph edge (parent, sub-issue, blocker). */
  onNavigate: (reff: string) => void;
  /** Bumped by the doorbell; re-reads without this pane knowing why. */
  revision: number;
}) {
  const [issue, setIssue] = useState<IssueView | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [graph, setGraph] = useState<GraphView | null>(null);
  const [draft, setDraft] = useState("");
  const [comment, setComment] = useState("");
  const titleRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        // Both halves of the story, in one trip. `history` is a separate `Request`
        // because the activity ring is not part of the issue document — see the
        // Timeline note on what that costs.
        const [view, hist, gr] = await Promise.all([
          rpc(spaceId, { cmd: "issue_view", reff }),
          // A failed history/graph must not take the issue down with it: the pane is
          // still useful without them, and both are secondary to the issue itself.
          rpc(spaceId, { cmd: "history", reff }).catch(() => null),
          rpc(spaceId, { cmd: "issue_graph", reff }).catch(() => null),
        ]);
        if (!alive) return;
        if (view.kind === "issue") {
          setIssue(view);
          setDraft(view.title);
        }
        setEvents(hist?.kind === "activity" ? hist.events : []);
        setGraph(gr?.kind === "graph" ? gr : null);
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
    async (patch: { title?: string; description?: string }) => {
      try {
        await rpc(spaceId, { cmd: "issue_edit", reff, ...patch });
      } catch (e) {
        onError(e instanceof Error ? e.message : String(e));
      }
    },
    [spaceId, reff, onError],
  );

  /** Writes with no predictable row field — the doorbell is the only feedback. */
  const send = useCallback(
    async (fn: () => Promise<unknown>) => {
      try {
        await fn();
      } catch (e) {
        onError(e instanceof Error ? e.message : String(e));
      }
    },
    [onError],
  );

  const memberOf = useCallback(
    (key: string): MemberDto | undefined => members.find((m) => m.key === key),
    [members],
  );

  if (!issue) {
    return <aside className="border-line text-mute border-l p-4 text-sm">Loading…</aside>;
  }

  const state = states.find((s) => s.id === issue.status);
  const project = projects.find((p) => p.id === issue.project_id);

  const saveTitle = () => {
    const next = draft.trim();
    if (!next || next === issue.title) return setDraft(issue.title);
    void edit({ title: next });
  };

  const pickerOpen = (f: IssueField) => openField === f;
  const setPicker = (f: IssueField) => (o: boolean) => onOpenField(o ? f : null);

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
          <IconButton
            label="Delete issue"
            variant="danger"
            className="ml-auto"
            onClick={() => onDelete(issue.reff)}
          >
            <Trash2 className="size-3.5" />
          </IconButton>
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

        {/*
          No Start/Done/Stop buttons here, deliberately.

          `start`/`done`/`stop` are real verbs with their own `Request`s, and the
          temptation is to give them a button row. Linear does not work that way:
          its issue detail is a title, a properties list, and a timeline — the
          status picker *is* the action, and every verb lives on a key and in the
          palette. lait's verbs are reachable exactly there (`S`/`D`/`O`, and by
          name in ⌘K). A button row would be a second, louder way to do what the
          Status row above already does, and it would be the one piece of this pane
          that came from somewhere else.
        */}
        <dl className="flex flex-col gap-1 text-sm">
          <Prop label="Status">
            <Combobox
              variant="bare"
              label="Status"
              disabled={readOnly}
              open={pickerOpen("status")}
              onOpenChange={setPicker("status")}
              value={{
                id: issue.status,
                label: state?.name ?? issue.status,
                ...(state
                  ? {
                      icon: (
                        <StatusIcon category={state.category} color={catalogColor(state.color)} />
                      ),
                    }
                  : {}),
              }}
              options={states.map((s) => ({
                id: s.id,
                label: s.name,
                icon: <StatusIcon category={s.category} color={catalogColor(s.color)} />,
              }))}
              onPick={(id) =>
                onPredict(issue.doc_id, "status", id, () =>
                  rpc(spaceId, { cmd: "issue_edit", reff, status: id }),
                )
              }
            />
          </Prop>

          <Prop label="Priority">
            <Combobox
              variant="bare"
              label="Priority"
              className="capitalize"
              disabled={readOnly}
              open={pickerOpen("priority")}
              onOpenChange={setPicker("priority")}
              value={{
                id: issue.priority,
                label: issue.priority,
                icon: <PriorityIcon priority={issue.priority} />,
              }}
              // Highest first: the list you scan top-down should start where the
              // urgency does.
              options={[...PRIORITY_ORDER].reverse().map((p) => ({
                id: p,
                label: p,
                icon: <PriorityIcon priority={p} />,
              }))}
              onPick={(id) =>
                onPredict(issue.doc_id, "priority", id, () =>
                  rpc(spaceId, { cmd: "issue_edit", reff, priority: id }),
                )
              }
            />
          </Prop>

          <Prop label="Assignees">
            <Combobox
              variant="bare"
              multi
              label="Assignees"
              disabled={readOnly}
              open={pickerOpen("assignee")}
              onOpenChange={setPicker("assignee")}
              selected={issue.assignees}
              emptyText={members.length ? "No matches" : "No members yet"}
              face={
                issue.assignees.length === 0 ? (
                  <span className="text-mute">Unassigned</span>
                ) : (
                  <span className="flex min-w-0 items-center gap-1.5">
                    <AvatarStack
                      members={issue.assignees.map((k) => ({
                        key: k,
                        alias: memberOf(k)?.alias ?? "",
                        me: memberOf(k)?.me ?? false,
                      }))}
                    />
                    <span className="truncate">
                      {issue.assignees.map((k) => nameOf(k, memberOf(k))).join(", ")}
                    </span>
                  </span>
                )
              }
              options={members.map((m) => ({
                id: m.key,
                label: nameOf(m.key, m),
                icon: <Avatar userKey={m.key} alias={m.alias} me={m.me} size="sm" />,
                // The key prefix, because the petname is the *unverified* half of
                // the identity — Members.tsx makes the same point at full width.
                hint: m.key.slice(0, 6),
                keywords: [m.key, m.alias],
              }))}
              onToggle={(key) => {
                const add = !issue.assignees.includes(key);
                // `who` takes `me`/`@me` or a **full 64-hex key** — `index::resolve_user`
                // does not consult the member directory, so a petname would 404. The
                // key is what we hold and the key is what we send.
                void send(() => rpc(spaceId, { cmd: "assign", reff, who: [key], add }));
              }}
            />
          </Prop>

          <Prop label="Labels">
            <Combobox
              variant="bare"
              multi
              label="Labels"
              disabled={readOnly}
              open={pickerOpen("label")}
              onOpenChange={setPicker("label")}
              // The registry is keyed by id, but `Request::Label` resolves **names**
              // (`tracker.rs::label`), so the selection is tracked by name too —
              // matching what we send rather than translating at the boundary.
              selected={issue.label_names}
              emptyText={labels.length ? "No matches" : "No labels yet"}
              face={
                issue.label_names.length === 0 ? (
                  <span className="text-mute">None</span>
                ) : (
                  <span className="flex min-w-0 flex-wrap items-center gap-1">
                    {issue.label_names.map((name) => (
                      <LabelChip key={name} name={name} labels={labels} />
                    ))}
                  </span>
                )
              }
              options={labels.map((l) => ({
                id: l.name,
                label: l.name,
                swatch: catalogColor(l.color),
                keywords: [l.id],
              }))}
              onToggle={(name) => {
                const on = issue.label_names.includes(name);
                void send(() =>
                  rpc(spaceId, {
                    cmd: "label",
                    reff,
                    ...(on ? { remove: [name] } : { add: [name] }),
                  }),
                );
              }}
            />
          </Prop>

          <Prop label="Project">
            <Combobox
              variant="bare"
              label="Project"
              disabled={readOnly}
              open={pickerOpen("project")}
              onOpenChange={setPicker("project")}
              value={
                project
                  ? { id: project.id, label: project.name, swatch: catalogColor(project.color) }
                  : { id: issue.project_id, label: issue.project_key ?? "—" }
              }
              options={projects.map((p) => ({
                id: p.id,
                label: p.name,
                swatch: catalogColor(p.color),
                hint: p.key,
                keywords: [p.key],
              }))}
              onPick={(id) => {
                if (id === issue.project_id) return;
                // `issue_move` carries project *and* position; sending only the
                // project leaves `pos` null, which the daemon reads as "don't
                // reorder" rather than "move to top".
                void send(() => rpc(spaceId, { cmd: "issue_move", reff, project: id }));
              }}
            />
          </Prop>
        </dl>

        <Description
          value={issue.description}
          readOnly={readOnly}
          onSave={(description) => void edit({ description })}
        />

        {graph && <Relations graph={graph} onNavigate={onNavigate} />}

        <Timeline events={events} comments={issue.comments} memberOf={memberOf} />

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

        <footer className="text-mute border-line mt-2 border-t pt-3 text-xs">
          Opened by {nameOf(issue.created_by, memberOf(issue.created_by))} ·{" "}
          {when(issue.created_at)}
        </footer>
      </div>
    </aside>
  );
}

/** A property row. The `group/prop` is what reveals the trigger's chevron. */
function Prop({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="group/prop flex min-h-7 items-center gap-2">
      <dt className="text-mute w-20 shrink-0">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}

function LabelChip({ name, labels }: { name: string; labels: LabelDto[] }) {
  const def = labels.find((l) => l.name === name);
  return (
    <span className="border-line-strong flex items-center gap-1 rounded-full border px-1.5 text-2xs">
      <span
        className="size-1.5 shrink-0 rounded-full"
        style={{ background: catalogColor(def?.color ?? "gray") }}
      />
      {name}
    </span>
  );
}

/**
 * The issue graph — parent, sub-issues, blockers, links — read from `GraphView`.
 *
 * Read-only for now: every edge here is navigable (click to open that issue), which
 * is the thing that was impossible before — the structure existed in the engine and
 * the browser couldn't see it. *Creating* edges (`IssueLink`/`IssueParent`) wants an
 * issue-search picker that doesn't exist yet, so it's a deliberate follow-up rather
 * than a half-built control here.
 *
 * `blocked_by` is the daemon's transitive computation (issues that block this one and
 * are still open), not just direct `blocks` edges — so it's shown as its own line,
 * separate from the raw links, and only when non-empty because "not blocked" is the
 * normal case and deserves no row.
 */
function Relations({ graph, onNavigate }: { graph: GraphView; onNavigate: (reff: string) => void }) {
  const blocks = graph.links.filter((l) => l.kind === "blocks");
  const related = graph.links.filter((l) => l.kind === "relates");
  const dupes = graph.links.filter((l) => l.kind === "duplicates");

  const empty =
    !graph.parent &&
    graph.children.length === 0 &&
    graph.blocked_by.length === 0 &&
    graph.links.length === 0;
  if (empty) return null;

  return (
    <section className="border-line flex flex-col gap-3 border-t pt-3">
      {graph.parent && (
        <RelGroup label="Parent">
          <RelRow row={graph.parent} icon={<GitMerge className="size-3" />} onNavigate={onNavigate} />
        </RelGroup>
      )}

      {graph.children.length > 0 && (
        <RelGroup label={`Sub-issues · ${graph.children.length}`}>
          {graph.children.map((r) => (
            <RelRow
              key={r.reff}
              row={r}
              icon={<CornerDownRight className="size-3" />}
              onNavigate={onNavigate}
            />
          ))}
        </RelGroup>
      )}

      {graph.blocked_by.length > 0 && (
        <RelGroup label="Blocked by" tone="warn">
          {graph.blocked_by.map((r) => (
            <RelRow
              key={r.reff}
              row={r}
              icon={<Ban className="text-warn size-3" />}
              onNavigate={onNavigate}
            />
          ))}
        </RelGroup>
      )}

      {blocks.length > 0 && <LinkGroup label="Blocks" links={blocks} onNavigate={onNavigate} />}
      {related.length > 0 && (
        <LinkGroup label="Related" links={related} onNavigate={onNavigate} />
      )}
      {dupes.length > 0 && <LinkGroup label="Duplicates" links={dupes} onNavigate={onNavigate} />}
    </section>
  );
}

function RelGroup({
  label,
  tone,
  children,
}: {
  label: string;
  tone?: "warn";
  children: React.ReactNode;
}) {
  return (
    <div className="flex flex-col gap-1">
      <h3
        className={`text-2xs font-semibold tracking-wider uppercase ${tone === "warn" ? "text-warn" : "text-mute"}`}
      >
        {label}
      </h3>
      {children}
    </div>
  );
}

/** A `relates`/`duplicates` edge can point either way; `direction` is `in`/`out`. */
function LinkGroup({
  label,
  links,
  onNavigate,
}: {
  label: string;
  links: LinkDto[];
  onNavigate: (reff: string) => void;
}) {
  return (
    <RelGroup label={label}>
      {links.map((l) => (
        <RelRow
          key={`${l.direction}-${l.row.reff}`}
          row={l.row}
          icon={
            <span className="text-mute text-2xs" title={l.direction === "in" ? "incoming" : "outgoing"}>
              {l.direction === "in" ? "←" : "→"}
            </span>
          }
          onNavigate={onNavigate}
        />
      ))}
    </RelGroup>
  );
}

/** One navigable edge: click opens that issue in this same pane. */
function RelRow({
  row,
  icon,
  onNavigate,
}: {
  row: Row;
  icon: React.ReactNode;
  onNavigate: (reff: string) => void;
}) {
  return (
    <button
      onClick={() => onNavigate(row.reff)}
      className="hover:bg-hover -mx-1 flex items-center gap-2 rounded px-1 py-0.5 text-left text-sm"
    >
      <span className="flex size-3 shrink-0 items-center justify-center">{icon}</span>
      <span className="text-mute w-16 shrink-0 truncate font-mono text-2xs tabular-nums">
        {row.key_alias ?? row.reff}
      </span>
      <span className="min-w-0 flex-1 truncate">{row.title}</span>
    </button>
  );
}

type Entry =
  | { at: number; order: number; kind: "comment"; comment: CommentDto }
  | { at: number; order: number; kind: "event"; event: ActivityEvent };

/**
 * Comments and activity, in one chronological stream.
 *
 * The two halves come from different places, and the events one changed under this
 * pane: `Request::History` now reads the issue's oplog **on disk** (`engine::history`)
 * rather than a session ring. So the timeline is durable — it survives daemon
 * restarts — and every event carries the *real* committer in `actor`, a teammate
 * included. The daemon leaves `actor_nick` empty, so the name is resolved here
 * against the member list (see `describeEvent`); reading `actor_nick` — as this used
 * to — now shows nothing.
 *
 * - **Comments come from the issue document.** They sync and carry a real author.
 * - **Events come from the durable oplog.** Real actors, real timestamps, no
 *   synthetic `synced` marker (that belongs to the workspace Activity feed).
 *
 * `commented` events are dropped: a comment is already rendered from the document,
 * so keeping its event too would double-print it.
 *
 * The visual weight follows the split. A comment is a card with a face; an event is
 * one muted line. That is Better Stack's timeline and Linear's, for the same reason
 * in both: the events are context, the comments are the conversation, and drawing
 * them alike makes you read the furniture.
 */
function Timeline({
  events,
  comments,
  memberOf,
}: {
  events: ActivityEvent[];
  comments: CommentDto[];
  memberOf: (key: string) => MemberDto | undefined;
}) {
  // The naming policy lives here, where the member list is: a key becomes an alias,
  // "you", or a short prefix. `describeEvent` only decides *whether* there is a name.
  const resolveName: NameResolver = (key) => nameOf(key, memberOf(key));
  const entries = useMemo<Entry[]>(() => {
    const out: Entry[] = [
      ...comments.map((c, i) => ({ at: c.ts, order: i, kind: "comment" as const, comment: c })),
      ...events
        .filter((e) => e.kind !== "commented")
        .map((e) => ({ at: e.ts, order: e.seq, kind: "event" as const, event: e })),
    ];
    // Oldest first — a timeline you read downward, like the conversation it is.
    // `order` breaks ties: whole-second stamps mean a burst of edits all land on
    // the same `ts`, and without it they shuffle on every render.
    return out.sort((a, b) => a.at - b.at || a.order - b.order);
  }, [events, comments]);

  return (
    <section className="flex flex-col gap-3">
      <h3 className="text-mute flex items-center gap-1.5 text-2xs font-semibold tracking-wider uppercase">
        Activity
        {comments.length > 0 && <span className="normal-case">· {comments.length} comments</span>}
        {/* Said once, quietly. This feed is durable and attributed now — worth
            saying, because it wasn't before. */}
        <span
          title="This issue's full history, read from its change log on disk — it survives restarts and shows who made each change. (The workspace-wide Activity view is a lighter, per-session feed.)"
          className="cursor-help"
        >
          <Info className="size-3" />
        </span>
      </h3>

      {entries.length === 0 && <p className="text-mute text-sm">Nothing yet.</p>}

      {entries.map((entry) =>
        entry.kind === "comment" ? (
          <Comment
            key={`c${entry.order}`}
            comment={entry.comment}
            member={memberOf(entry.comment.author)}
          />
        ) : (
          <Event key={`e${entry.order}`} event={entry.event} resolveName={resolveName} />
        ),
      )}
    </section>
  );
}

function Comment({ comment: c, member }: { comment: CommentDto; member: MemberDto | undefined }) {
  return (
    <article className="flex gap-2">
      <Avatar
        userKey={c.author}
        // The in-doc `author_nick` is what the author *claimed*; the local alias is
        // what you decided they are. Prefer yours — it is the half that was verified.
        alias={member?.alias || c.author_nick || ""}
        me={member?.me ?? false}
        className="mt-0.5"
      />
      <div className="min-w-0 flex-1">
        <div className="flex items-baseline gap-2">
          <span className="font-medium">
            {member ? nameOf(c.author, member) : (c.author_nick ?? short(c.author))}
          </span>
          {/* Unix SECONDS — `tsToDate` is the only place that's converted. */}
          <time className="text-mute text-xs" dateTime={tsToDate(c.ts).toISOString()}>
            {when(c.ts)}
          </time>
        </div>
        <p className="whitespace-pre-wrap">{c.body}</p>
      </div>
    </article>
  );
}

function Event({ event: e, resolveName }: { event: ActivityEvent; resolveName: NameResolver }) {
  const { actor, phrase } = describeEvent(e, resolveName);
  const changes = describeChanges(e);

  return (
    <div className="text-mute flex items-baseline gap-2 text-xs">
      <CircleDot className="size-3 shrink-0 translate-y-0.5" />
      <span className="min-w-0 flex-1">
        {/* No actor means we genuinely don't know — see core/activity.ts. Printing
            "someone" would claim we know there was a someone and lost the name. */}
        {actor && <span className="text-dim font-medium">{actor} </span>}
        {phrase}
        {changes && <span className="text-mute"> · {changes}</span>}
      </span>
      {/* A concurrent overwrite is worth flagging but never worth blocking on
          (A§9): last-writer-wins already resolved it; you just get told. */}
      {e.collision && (
        <AlertTriangle className="text-warn size-3 shrink-0" aria-label="Concurrent overwrite" />
      )}
      <time className="shrink-0" dateTime={tsToDate(e.ts).toISOString()}>
        {when(e.ts)}
      </time>
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
