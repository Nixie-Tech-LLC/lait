import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import * as Popover from "@radix-ui/react-popover";
import {
  AlertTriangle,
  ArchiveRestore,
  Ban,
  Bell,
  BellOff,
  Check,
  ChevronLeft,
  ChevronRight,
  CircleDot,
  Copy,
  CopyPlus,
  CornerDownRight,
  Download,
  GitMerge,
  Info,
  Link2,
  Maximize2,
  MoreHorizontal,
  Minimize2,
  MoveRight,
  Paperclip,
  Play,
  RotateCcw,
  Plus,
  SmilePlus,
  Trash2,
  UserPlus,
  X,
} from "lucide-react";

import { rpc } from "../api";
import { clearDraft, loadDraft, saveDraft } from "../core/drafts";
import { describeChanges, describeEvent, type NameResolver } from "../core/activity";
import type { Field as PredictField } from "../core/overlay";
import type { IssueField } from "../core/registry";
import { inverseWorkAction, primaryWorkAction, workTarget } from "../core/workflow";
import { boundedTail } from "../core/performance";
import {
  type AttachmentMetaDto,
  type GraphView,
  type LinkDto,
  type MilestoneDto,
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
import { LoadingState } from "./AppState";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Markdown } from "./Markdown";
import { DatePicker } from "./DatePicker";
import { NewLabelDialog } from "./NewLabel";
import { Combobox, type Option } from "./Picker";
import { Button, ChipButton, EditableSurface, IconButton, InlineAction, PopoverContent, Textarea } from "./primitives";
import { MenuContent, MenuItem, PropertyRow, SectionHeader, SurfaceHeader, Toast } from "./layout";
import * as ask from "./dialogs";
import { dueToInput, dueTone, short, when } from "./time";

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
  canonicalSpaceId,
  reff,
  states,
  members,
  labels,
  projects,
  readOnly,
  tombstone,
  openField,
  onOpenField,
  onError,
  onDelete,
  onPredict,
  onNavigate,
  onClose,
  onPrevious,
  onNext,
  focused,
  onToggleFocus,
  revision,
}: {
  spaceId: string;
  canonicalSpaceId: string;
  reff: string;
  states: WorkflowState[];
  /** The signed ACL, for the assignee picker. Keys are the only real identity. */
  members: MemberDto[];
  labels: LabelDto[];
  projects: ProjectDto[];
  readOnly: boolean;
  /** Whether the board says this issue is deleted — `IssueView` doesn't carry
   *  the tombstone, but the row does, and it decides Delete vs Restore. */
  tombstone: boolean;
  /** Which picker a keybinding wants open, if any. */
  openField: IssueField | null;
  onOpenField: (f: IssueField | null) => void;
  onError: (m: string) => void;
  onDelete: (reff: string) => void;
  /** Predict `(doc, field)` locally, then send. The doorbell retires the guess. */
  onPredict: (doc: string, field: PredictField, value: string, send: () => Promise<unknown>) => Promise<boolean>;
  /** Select another issue — following a graph edge (parent, sub-issue, blocker). */
  onNavigate: (reff: string) => void;
  onClose: () => void;
  onPrevious?: () => void;
  onNext?: () => void;
  focused: boolean;
  onToggleFocus: () => void;
  /** Bumped by the doorbell; re-reads without this pane knowing why. */
  revision: number;
}) {
  const [issue, setIssue] = useState<IssueView | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [graph, setGraph] = useState<GraphView | null>(null);
  const [milestones, setMilestones] = useState<MilestoneDto[]>([]);
  const [draft, setDraft] = useState(() => loadDraft(canonicalSpaceId, reff, "title"));
  const [comment, setComment] = useState(() => loadDraft(canonicalSpaceId, reff, "comment"));
  const [commentPending, setCommentPending] = useState(false);
  const [commentError, setCommentError] = useState<string | null>(null);
  const [pendingAction, setPendingAction] = useState<string | null>(null);
  /** A label name the picker wants to mint — opens the colour step. */
  const [newLabel, setNewLabel] = useState<string | null>(null);
  const [undoWork, setUndoWork] = useState<{
    message: string;
    action: "start" | "done" | "stop";
  } | null>(null);
  const titleRef = useRef<HTMLTextAreaElement>(null);
  const commentRef = useRef<HTMLTextAreaElement>(null);

  useEffect(
    () => saveDraft(canonicalSpaceId, reff, "comment", comment),
    [canonicalSpaceId, reff, comment],
  );

  useEffect(() => {
    if (!issue) return;
    if (draft !== issue.title) saveDraft(canonicalSpaceId, reff, "title", draft);
    else clearDraft(canonicalSpaceId, reff, "title");
  }, [canonicalSpaceId, reff, draft, issue]);

  useEffect(() => {
    if (!undoWork) return;
    const timeout = window.setTimeout(() => setUndoWork(null), 6000);
    return () => window.clearTimeout(timeout);
  }, [undoWork]);

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
          setDraft((current) => current || view.title);
          // Milestones are project-scoped, so the project comes from the view.
          const ms = await rpc(spaceId, {
            cmd: "milestone_list",
            project: view.project_id,
          }).catch(() => null);
          if (alive) setMilestones(ms?.kind === "milestones" ? ms.milestones : []);
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
    return <aside className="border-line flex h-full border-l"><LoadingState title="Loading issue" body="Reading the local issue document." /></aside>;
  }

  const state = states.find((s) => s.id === issue.status);
  const project = projects.find((p) => p.id === issue.project_id);
  const locked = readOnly || issue.provisional;
  const lifecycle = primaryWorkAction(state?.category ?? "backlog");

  const runWorkAction = async (
    action: "start" | "done" | "stop",
    recordUndo = true,
  ) => {
    if (pendingAction) return;
    const target = workTarget(states, action);
    const previousCategory = state?.category ?? "backlog";
    setPendingAction(action);
    try {
      const accepted = target
        ? await onPredict(issue.doc_id, "status", target.id, () =>
          rpc(spaceId, { cmd: `issue_${action}`, reff }),
        )
        : await rpc(spaceId, { cmd: `issue_${action}`, reff }).then(() => true);
      if (!accepted) return;
      if (recordUndo) {
        setUndoWork({
          message:
            action === "done"
              ? "Issue completed"
              : action === "stop"
                ? "Work stopped"
                : "Work started",
          action: inverseWorkAction(action, previousCategory),
        });
      }
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setPendingAction(null);
    }
  };

  const saveTitle = () => {
    const next = draft.trim();
    if (!next || next === issue.title) {
      setDraft(issue.title);
      clearDraft(canonicalSpaceId, reff, "title");
      return;
    }
    void onPredict(issue.doc_id, "title", next, () =>
      rpc(spaceId, { cmd: "issue_edit", reff, title: next }),
    ).then((accepted) => {
      if (accepted) clearDraft(canonicalSpaceId, reff, "title");
    });
  };

  const submitComment = async () => {
    const body = comment.trim();
    if (!body || commentPending) return;
    setCommentPending(true);
    setCommentError(null);
    try {
      await rpc(spaceId, { cmd: "comment", reff, body });
      setComment("");
      clearDraft(canonicalSpaceId, reff, "comment");
      commentRef.current?.focus();
    } catch (error) {
      setCommentError(error instanceof Error ? error.message : String(error));
    } finally {
      setCommentPending(false);
    }
  };

  const duplicateIssue = async () => {
    if (pendingAction) return;
    setPendingAction("duplicate");
    try {
      const result = await rpc(spaceId, {
        cmd: "issue_new",
        title: `${issue.title} (copy)`,
        project: issue.project_id,
        body: issue.description || null,
        priority: issue.priority,
        labels: issue.label_names,
        assignees: issue.assignees,
        due: issue.due_date != null ? dueToInput(issue.due_date) : null,
        estimate: issue.estimate ?? null,
      });
      if (result.kind === "ref") onNavigate(result.reff);
    } catch (error) {
      onError(error instanceof Error ? error.message : String(error));
    } finally {
      setPendingAction(null);
    }
  };

  const pickerOpen = (f: IssueField) => openField === f;
  const setPicker = (f: IssueField) => (o: boolean) => onOpenField(o ? f : null);

  return (
    <aside className="issue-detail border-line flex h-full min-h-0 flex-col overflow-y-auto border-l">
      <SurfaceHeader className="gap-2 px-3">
        <span className="text-mute font-mono text-xs tabular-nums">
          {issue.key_alias ?? issue.reff}
        </span>
        {issue.provisional && (
          <span className="text-warn text-2xs" title="The issue body hasn't synced yet">
            provisional
          </span>
        )}
        {tombstone && (
          <span className="text-danger text-2xs" title="Deleted — restorable at any time">
            deleted
          </span>
        )}
        <span className="ml-auto flex items-center gap-0.5">
          <IconButton label="Previous issue" onClick={onPrevious} disabled={!onPrevious}>
            <ChevronLeft className="size-3.5" />
          </IconButton>
          <IconButton label="Next issue" onClick={onNext} disabled={!onNext}>
            <ChevronRight className="size-3.5" />
          </IconButton>
          <IconButton
            label="Copy issue link"
            onClick={() => void navigator.clipboard.writeText(window.location.href)}
          >
            <Copy className="size-3.5" />
          </IconButton>
          {!locked && !tombstone && (
            <Button
              variant="toolbar"
              disabled={pendingAction !== null}
              aria-busy={pendingAction === lifecycle.action}
              onClick={() => void runWorkAction(lifecycle.action)}
            >
              {lifecycle.action === "done" ? (
                <Check className="size-3" />
              ) : state?.category === "done" ? (
                <RotateCcw className="size-3" />
              ) : (
                <Play className="size-3" />
              )}
              {pendingAction === lifecycle.action ? lifecycle.pendingLabel : lifecycle.label}
            </Button>
          )}
          <IconButton label={focused ? "Return to split view" : "Focus issue"} onClick={onToggleFocus}>
            {focused ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
          </IconButton>
          <IssueOverflow
            issueRef={issue.key_alias ?? issue.reff}
            active={state?.category === "active"}
            locked={locked}
            tombstone={tombstone}
            pending={pendingAction !== null}
            onDuplicate={() => void duplicateIssue()}
            onRelate={() => document.getElementById("issue-add-relation")?.click()}
            onAssign={() => onOpenField("assignee")}
            onMove={() => onOpenField("project")}
            onStop={() => void runWorkAction("stop")}
            onRestore={() => void send(() => rpc(spaceId, { cmd: "issue_restore", reff: issue.reff }))}
            onDelete={() => onDelete(issue.reff)}
          />
          <IconButton label="Close issue" chord="Esc" onClick={onClose}>
            <X className="size-3.5" />
          </IconButton>
        </span>
      </SurfaceHeader>

      <div className="issue-detail-body flex flex-col gap-4 p-4">
        {undoWork && (
          <Toast action={<Button
              variant="ghost"
              onClick={() => {
                const action = undoWork.action;
                setUndoWork(null);
                void runWorkAction(action, false);
              }}
            >
              Undo
            </Button>}>
            {undoWork.message}
          </Toast>
        )}
        {events.some((event) => event.collision) && (
          <div className="border-warn/30 bg-warn/5 text-dim flex items-start gap-2 rounded border p-3 text-sm" role="status">
            <AlertTriangle className="text-warn mt-0.5 size-3.5 shrink-0" />
            <span className="min-w-0 flex-1">
              Concurrent edits converged to the current values. Review the marked history entry;
              if its outcome is not what you intended, reapply the field above as a new explicit change.
            </span>
            <Button
              variant="ghost"
              onClick={() => document.getElementById("issue-activity")?.scrollIntoView({ block: "start" })}
            >
              Review history
            </Button>
          </div>
        )}
        {issue.provisional && (
          <div className="border-warn/30 bg-warn/5 text-dim flex gap-2 rounded border p-3 text-sm">
            <Info className="text-warn mt-0.5 size-3.5 shrink-0" />
            <span>
              This issue is known to the local catalog, but its body is still arriving. Metadata may be incomplete; editing stays unavailable until the projection is ready.
            </span>
          </div>
        )}
        {!!issue.corrupt_records?.length && (
          <details className="border-danger/30 bg-danger/5 rounded border p-3 text-sm">
            <summary className="text-danger flex items-center gap-2 font-medium">
              <AlertTriangle className="size-3.5" />
              {issue.corrupt_records.length} stored {issue.corrupt_records.length === 1 ? "record needs" : "records need"} attention
            </summary>
            <ul className="text-dim mt-2 flex flex-col gap-1 pl-5 text-xs">
              {issue.corrupt_records.map((record, index) => (
                <li key={`${record.locus}-${index}`}>
                  <code>{record.locus}</code>: {record.reason}
                </li>
              ))}
            </ul>
          </details>
        )}
        {/* A textarea, not an input: a long title should wrap rather than scroll
            sideways past the edge of the pane. */}
        <textarea
          ref={titleRef}
          value={draft}
          readOnly={locked}
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
              clearDraft(canonicalSpaceId, reff, "title");
              titleRef.current?.blur();
            }
          }}
          className="issue-detail-title resize-none bg-transparent text-lg font-semibold outline-none"
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
        <dl className="issue-detail-properties flex flex-col gap-1 text-sm">
          <PropertyRow label="Status">
            <Combobox
              variant="property"
              label="Status"
              disabled={locked}
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
          </PropertyRow>

          <PropertyRow label="Priority">
            <Combobox
              variant="property"
              label="Priority"
              className="capitalize"
              disabled={locked}
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
          </PropertyRow>

          <PropertyRow label="Assignees">
            <Combobox
              variant="property"
              multi
              label="Assignees"
              disabled={locked}
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
                icon: <Avatar deviceKey={m.key} alias={m.alias} me={m.me} size="sm" />,
                // The key prefix, because the petname is the *unverified* half of
                // the identity — Members.tsx makes the same point at full width.
                hint: m.key.slice(0, 6),
                keywords: [m.key, m.alias],
              }))}
              onToggle={(key) => {
                const add = !issue.assignees.includes(key);
                // `who` takes `me`/`@me` or a **full 64-hex key** — `index::resolve_device`
                // does not consult the member directory, so a petname would 404. The
                // key is what we hold and the key is what we send.
                void send(() => rpc(spaceId, { cmd: "assign", reff, who: [key], add }));
              }}
            />
          </PropertyRow>

          <PropertyRow label="Labels">
            <Combobox
              variant="property"
              multi
              label="Labels"
              disabled={locked}
              open={pickerOpen("label")}
              onOpenChange={setPicker("label")}
              // The registry is keyed by id, but `Request::Label` resolves **names**
              // (`replica.rs::label`), so the selection is tracked by name too —
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
              // A brand-new label gets a colour before it exists: the picker hands
              // the name off to the colour step, which registers it via `label_new`
              // and then attaches it — rather than minting it gray on first use.
              onCreate={(name) => setNewLabel(name)}
            />
          </PropertyRow>

          <PropertyRow label="Due date">
            <DueDate
              value={issue.due_date ?? null}
              readOnly={locked}
              onChange={(due) =>
                void send(() => rpc(spaceId, { cmd: "issue_edit", reff, due }))
              }
            />
          </PropertyRow>

          <PropertyRow label="Estimate">
            <Combobox
              variant="property"
              label="Estimate"
              disabled={locked}
              value={
                issue.estimate != null
                  ? { id: String(issue.estimate), label: `${issue.estimate} pt` }
                  : null
              }
              placeholder="None"
              // Fibonacci-ish, Linear's default scale; "None" clears. The
              // engine stores a bare number — the scale is a team convention.
              options={[
                { id: "none", label: "None" },
                ...[1, 2, 3, 5, 8, 13].map((n) => ({ id: String(n), label: `${n} pt` })),
              ]}
              onPick={(id) =>
                void send(() => rpc(spaceId, { cmd: "issue_edit", reff, estimate: id }))
              }
            />
          </PropertyRow>

          {(milestones.length > 0 || issue.milestone) && (
            <PropertyRow label="Milestone">
              <Combobox
                variant="property"
                label="Milestone"
                disabled={locked}
                value={
                  issue.milestone
                    ? {
                        id: issue.milestone,
                        label:
                          milestones.find((m) => m.id === issue.milestone)?.name ??
                          issue.milestone,
                      }
                    : null
                }
                placeholder="None"
                options={[
                  { id: "none", label: "None" },
                  ...milestones.map((m) => ({
                    id: m.id,
                    label: m.name,
                    hint: `${m.done}/${m.total}`,
                  })),
                ]}
                onPick={(id) =>
                  void send(() =>
                    rpc(spaceId, {
                      cmd: "issue_milestone",
                      reff,
                      milestone: id === "none" ? null : id,
                    }),
                  )
                }
              />
            </PropertyRow>
          )}

          <PropertyRow label="Notifications">
            <FollowToggle
              issue={issue}
              meKey={members.find((m) => m.me)?.key ?? null}
              readOnly={locked}
              onToggle={(on) => void send(() => rpc(spaceId, { cmd: "follow", reff, on }))}
            />
          </PropertyRow>

          <PropertyRow label="Project">
            <Combobox
              variant="property"
              label="Project"
              disabled={locked}
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
          </PropertyRow>
        </dl>

        <Description
          draftKey={{ spaceId: canonicalSpaceId, reff }}
          value={issue.description}
          readOnly={locked}
          onSave={(description) => void edit({ description })}
        />

        <Attachments
          spaceId={spaceId}
          reff={issue.reff}
          attachments={issue.attachments ?? []}
          readOnly={locked}
          onError={onError}
        />

        {graph && (
          <Relations
            graph={graph}
            spaceId={spaceId}
            reff={issue.reff}
            projectId={issue.project_id}
            states={states}
            readOnly={locked}
            send={send}
            onNavigate={onNavigate}
          />
        )}

        <Timeline
          key={reff}
          events={events}
          comments={issue.comments}
          memberOf={memberOf}
          readOnly={locked}
          meKey={members.find((m) => m.me)?.key ?? null}
          onReact={(comment, emoji, on) =>
            void send(() => rpc(spaceId, { cmd: "react", reff, comment, emoji, on }))
          }
          onReply={(replyTo, body) =>
            void send(() => rpc(spaceId, { cmd: "comment", reff, body, reply_to: replyTo }))
          }
          onCopyLink={(commentId) => {
            const url = new URL(window.location.href);
            url.searchParams.set("issue", issue.reff);
            url.searchParams.set("comment", commentId);
            void navigator.clipboard.writeText(url.toString());
          }}
          onCreateFromComment={(body) =>
            void (async () => {
              const title = body.split("\n")[0]!.slice(0, 80).trim() || "Follow-up";
              const r = await rpc(spaceId, {
                cmd: "issue_new",
                title,
                project: issue.project_id,
                body,
              });
              if (r.kind === "ref") onNavigate(r.reff);
            })()
          }
        />

        {!locked && (
          <div className="border-line focus-within:border-line-strong rounded border bg-transparent">
            <textarea
              ref={commentRef}
              value={comment}
              placeholder="Leave a comment…"
              onChange={(e) => {
                setComment(e.target.value);
                setCommentError(null);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && comment.trim()) {
                  e.preventDefault();
                  void submitComment();
                }
              }}
              rows={3}
              className="placeholder:text-mute block w-full resize-y bg-transparent p-2 outline-none"
              aria-label="New comment"
              aria-describedby={commentError ? "comment-error" : undefined}
            />
            <div className="border-line flex items-center gap-2 border-t px-2 py-1.5">
              {commentError ? (
                <span
                  id="comment-error"
                  className="text-danger min-w-0 flex-1 truncate text-xs"
                  role="alert"
                >
                  Comment not sent. Your draft is safe.
                </span>
              ) : (
                <span className="text-mute min-w-0 flex-1 text-xs">
                  Ctrl/⌘ Enter to send
                </span>
              )}
              <Button
                variant="primary"
                disabled={!comment.trim()}
                loading={commentPending}
                onClick={() => void submitComment()}
              >
                {commentPending ? "Sending…" : commentError ? "Retry" : "Comment"}
              </Button>
            </div>
          </div>
        )}

        <footer className="text-mute border-line mt-2 border-t pt-3 text-xs">
          Opened by {nameOf(issue.created_by, memberOf(issue.created_by))} ·{" "}
          {when(issue.created_at)}
        </footer>
      </div>
      {newLabel !== null && (
        <NewLabelDialog
          name={newLabel}
          onCancel={() => setNewLabel(null)}
          onCreate={(labelName, color) => {
            setNewLabel(null);
            // Two requests, in order: register the label with its colour, then
            // attach it. `label add` on an existing name only attaches, so the
            // colour set here is the one that sticks.
            void send(async () => {
              await rpc(spaceId, { cmd: "label_new", name: labelName, color });
              await rpc(spaceId, { cmd: "label", reff, add: [labelName] });
            });
          }}
        />
      )}
    </aside>
  );
}

function IssueOverflow({
  issueRef,
  active,
  locked,
  tombstone,
  pending,
  onDuplicate,
  onRelate,
  onAssign,
  onMove,
  onStop,
  onRestore,
  onDelete,
}: {
  issueRef: string;
  active: boolean;
  locked: boolean;
  tombstone: boolean;
  pending: boolean;
  onDuplicate: () => void;
  onRelate: () => void;
  onAssign: () => void;
  onMove: () => void;
  onStop: () => void;
  onRestore: () => void;
  onDelete: () => void;
}) {
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger asChild>
        <IconButton label="More issue actions"><MoreHorizontal className="size-3.5" /></IconButton>
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <MenuContent align="end" className="min-w-52">
          <MenuItem onSelect={() => void navigator.clipboard.writeText(issueRef)}><Copy className="size-3.5" /> Copy reference</MenuItem>
          {!locked && !tombstone && (
            <>
              <MenuItem disabled={pending} onSelect={onDuplicate}><CopyPlus className="size-3.5" /> Duplicate issue</MenuItem>
              <MenuItem disabled={pending} onSelect={onRelate}><Link2 className="size-3.5" /> Add relation</MenuItem>
              <MenuItem disabled={pending} onSelect={onAssign}><UserPlus className="size-3.5" /> Assign issue</MenuItem>
              <MenuItem disabled={pending} onSelect={onMove}><MoveRight className="size-3.5" /> Move to project</MenuItem>
            </>
          )}
          {active && !locked && <MenuItem disabled={pending} onSelect={onStop}><CircleDot className="size-3.5" /> Stop work</MenuItem>}
          {!locked && <DropdownMenu.Separator className="bg-line my-1 h-px" />}
          {!locked && (tombstone
            ? <MenuItem onSelect={onRestore}><ArchiveRestore className="size-3.5" /> Restore issue</MenuItem>
            : <MenuItem danger onSelect={onDelete}><Trash2 className="size-3.5" /> Delete issue</MenuItem>)}
        </MenuContent>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

/** Follow/unfollow (INBOX-9): subscribe to activity without holding the assignment. */
function FollowToggle({
  issue,
  meKey,
  readOnly,
  onToggle,
}: {
  issue: IssueView;
  meKey: string | null;
  readOnly: boolean;
  onToggle: (on: boolean) => void;
}) {
  const followers = issue.followers ?? [];
  const following = meKey != null && followers.includes(meKey);
  const others = followers.length - (following ? 1 : 0);
  return (
    <Button
      type="button"
      variant={following ? "active" : "ghost"}
      disabled={readOnly || meKey == null}
      onClick={() => onToggle(!following)}
      title={following ? "Stop receiving this issue's activity" : "Receive this issue's activity in your inbox"}
    >
      {following ? <BellOff className="size-3.5" /> : <Bell className="size-3.5" />}
      {following ? "Following" : "Follow"}
      {others > 0 && <span className="text-mute">+{others}</span>}
    </Button>
  );
}

/** Base64 helpers for the attachment payloads (standard alphabet, padded). */
const bufToB64 = (buf: ArrayBuffer): string => {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin);
};
const b64ToBytes = (b64: string): Uint8Array =>
  Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));

/** The engine's cap (contract.rs MAX_ATTACHMENT_BYTES), mirrored for a
 *  friendly refusal before the bytes ever leave the browser. */
const MAX_ATTACHMENT_BYTES = 256 * 1024;

/**
 * Attachments (CREATE-5): bounded files riding the issue document's own
 * sync + encryption. Metadata comes with the view; payloads are fetched only
 * on download.
 */
function Attachments({
  spaceId,
  reff,
  attachments,
  readOnly,
  onError,
}: {
  spaceId: string;
  reff: string;
  attachments: AttachmentMetaDto[];
  readOnly: boolean;
  onError: (m: string) => void;
}) {
  const fileRef = useRef<HTMLInputElement>(null);
  const [busy, setBusy] = useState(false);
  if (attachments.length === 0 && readOnly) return null;

  const upload = async (file: File) => {
    if (file.size > MAX_ATTACHMENT_BYTES) {
      onError(
        `${file.name} is ${Math.ceil(file.size / 1024)} KiB — attachments are capped at ${MAX_ATTACHMENT_BYTES / 1024} KiB`,
      );
      return;
    }
    setBusy(true);
    try {
      const data_b64 = bufToB64(await file.arrayBuffer());
      await rpc(spaceId, {
        cmd: "attach",
        reff,
        name: file.name,
        mime: file.type || null,
        data_b64,
      });
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const download = async (att: AttachmentMetaDto) => {
    try {
      const r = await rpc(spaceId, { cmd: "attachment_get", reff, id: att.id });
      if (r.kind !== "attachment") return;
      const bytes = b64ToBytes(r.data_b64);
      const blob = new Blob([bytes.buffer as ArrayBuffer], {
        type: r.mime || "application/octet-stream",
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = r.name || att.name;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <section>
      <SectionHeader
        title={`Attachments${attachments.length ? ` (${attachments.length})` : ""}`}
        action={
          !readOnly && (
            <IconButton
              label="Attach a file"
              disabled={busy}
              onClick={() => fileRef.current?.click()}
            >
              <Paperclip className="size-3.5" />
            </IconButton>
          )
        }
      />
      <input
        ref={fileRef}
        type="file"
        className="hidden"
        onChange={(e) => {
          const file = e.target.files?.[0];
          e.target.value = "";
          if (file) void upload(file);
        }}
      />
      {attachments.length === 0 ? (
        <p className="text-mute text-sm">No files yet — attach up to 256 KiB each.</p>
      ) : (
        <ul className="flex flex-col gap-1">
          {attachments.map((att) => (
            <li
              key={att.id}
              className="border-line hover:bg-surface-2 group flex items-center gap-2 rounded border px-2 py-1 text-sm"
            >
              <Paperclip className="text-mute size-3.5 shrink-0" />
              <span className="text-ink min-w-0 flex-1 truncate">{att.name}</span>
              <span className="text-mute shrink-0 text-xs">
                {Math.max(1, Math.round(att.size / 1024))} KiB
              </span>
              <IconButton label={`Download ${att.name}`} onClick={() => void download(att)}>
                <Download className="size-3.5" />
              </IconButton>
              {!readOnly && (
                <IconButton
                  label={`Remove ${att.name}`}
                  onClick={() =>
                    void rpc(spaceId, { cmd: "detach", reff, id: att.id }).catch((e) =>
                      onError(e instanceof Error ? e.message : String(e)),
                    )
                  }
                >
                  <Trash2 className="size-3.5" />
                </IconButton>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

/**
 * The due-date control — the shared `DatePicker` wearing the property row's tone.
 *
 * The engine speaks unix seconds here but the picker speaks `YYYY-MM-DD` (UTC — the
 * engine stores UTC midnight), so this thin wrapper is the one conversion: seconds
 * in via `dueToInput`, and `null` back out becomes the request's `"none"`. The
 * traffic-light tone (overdue/soon/later) rides in as the trigger's colour.
 */
function DueDate({
  value,
  readOnly,
  onChange,
}: {
  value: number | null;
  readOnly: boolean;
  onChange: (due: string) => void;
}) {
  const tone =
    value !== null ? { overdue: "text-danger", soon: "text-warn", later: "" }[dueTone(value)] : "";
  return (
    <DatePicker
      variant="property"
      value={value !== null ? dueToInput(value) : null}
      disabled={readOnly}
      placeholder="None"
      className={tone}
      onChange={(next) => onChange(next ?? "none")}
    />
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
 * The kinds of edge a human adds. The engine has three link kinds plus the
 * parent tree; "blocked by" and "sub-issue" are the same verbs with the ends
 * swapped, spelled out because that is how people think about them (and how
 * Linear's relation menu names them).
 */
const RELATION_KINDS = [
  { id: "blocks", label: "Blocks" },
  { id: "blocked-by", label: "Blocked by" },
  { id: "relates", label: "Related to" },
  { id: "duplicates", label: "Duplicate of" },
  { id: "parent", label: "Parent" },
  { id: "sub-issue", label: "Sub-issue (existing)" },
] as const;
type RelationKind = (typeof RELATION_KINDS)[number]["id"];

/**
 * The issue graph — parent, sub-issues, blockers, links — read from `GraphView`,
 * and now written back through it: every edge can be added and removed here
 * (`IssueLink`/`IssueUnlink`/`IssueParent`), and a sub-issue can be created
 * in place (an `issue_new` and then an `issue_parent` — two commits, two
 * activity rows, which is the honest record of what happened).
 *
 * `blocked_by` is the daemon's transitive computation (issues that block this one
 * and are still open), not just direct `blocks` edges — so it's shown as its own
 * warning line and offers no remove: cutting an edge two hops away from here
 * would be action at a distance. The direct edge is removable in its own group.
 */
function Relations({
  graph,
  spaceId,
  reff,
  projectId,
  states,
  readOnly,
  send,
  onNavigate,
}: {
  graph: GraphView;
  spaceId: string;
  reff: string;
  /** The issue's project — where a quick-created sub-issue is filed. */
  projectId: string;
  states: WorkflowState[];
  readOnly: boolean;
  send: (fn: () => Promise<unknown>) => Promise<void>;
  onNavigate: (reff: string) => void;
}) {
  const [adding, setAdding] = useState(false);
  const [kind, setKind] = useState<RelationKind>("blocks");
  /** Every live issue in the space, fetched when the picker first opens. */
  const [candidates, setCandidates] = useState<Row[] | null>(null);
  /** The inline sub-issue composer. `null` = closed. */
  const [subDraft, setSubDraft] = useState<string | null>(null);

  useEffect(() => {
    if (!adding || candidates !== null) return;
    let alive = true;
    // `all: true` on purpose: a duplicate's canonical is often already Done.
    // Tombstoned rows stay out — linking to a deleted issue is a dead edge.
    void rpc(spaceId, { cmd: "list", project: null, filter: { all: true } })
      .then((r) => {
        if (alive && r.kind === "list") {
          setCandidates(r.rows.filter((x) => !x.tombstone && x.reff !== reff));
        }
      })
      .catch(() => {
        if (alive) setCandidates([]);
      });
    return () => {
      alive = false;
    };
  }, [adding, candidates, spaceId, reff]);

  const relate = (target: string) => {
    setAdding(false);
    void send(() => {
      switch (kind) {
        case "blocked-by":
          // Same edge, other end: `target` blocks this issue.
          return rpc(spaceId, { cmd: "issue_link", reff: target, kind: "blocks", target: reff });
        case "parent":
          return rpc(spaceId, { cmd: "issue_parent", reff, parent: target });
        case "sub-issue":
          return rpc(spaceId, { cmd: "issue_parent", reff: target, parent: reff });
        default:
          return rpc(spaceId, { cmd: "issue_link", reff, kind, target });
      }
    });
  };

  const confirmRemove = (body: string, remove: () => Promise<unknown>) =>
    void ask
      .confirm({
        title: "Remove relationship?",
        body,
        confirmText: "Remove",
        danger: true,
      })
      .then((confirmed) => {
        if (confirmed) return send(remove);
      });

  const unlink = (l: LinkDto) =>
    confirmRemove(`Remove the ${l.kind} relationship with ${l.row.key_alias ?? l.row.reff}?`, () =>
      // `direction` says which end this issue is; the unlink must name the same
      // ordered pair the link did or `blocks`/`duplicates` would miss the edge.
      l.direction === "out"
        ? rpc(spaceId, { cmd: "issue_unlink", reff, kind: l.kind, target: l.row.reff })
        : rpc(spaceId, { cmd: "issue_unlink", reff: l.row.reff, kind: l.kind, target: reff }),
    );

  const createSub = (title: string) => {
    setSubDraft("");
    void send(async () => {
      const r = await rpc(spaceId, { cmd: "issue_new", title, project: projectId });
      if (r.kind === "ref") {
        await rpc(spaceId, { cmd: "issue_parent", reff: r.reff, parent: reff });
      }
    });
  };

  const blocks = graph.links.filter((l) => l.kind === "blocks");
  const related = graph.links.filter((l) => l.kind === "relates");
  const dupes = graph.links.filter((l) => l.kind === "duplicates");
  const doneChildren = graph.children.filter(
    (c) => states.find((s) => s.id === c.status)?.category === "done",
  ).length;

  const empty =
    !graph.parent &&
    graph.children.length === 0 &&
    graph.blocked_by.length === 0 &&
    graph.links.length === 0;
  if (empty && readOnly) return null;

  const removable = !readOnly;

  return (
    <section className="border-line flex flex-col gap-3 border-t pt-3">
      {graph.parent && (
        <RelGroup label="Parent">
          <RelRow
            row={graph.parent}
            icon={<GitMerge className="size-3" />}
            onNavigate={onNavigate}
            {...(removable
              ? {
                  onRemove: () =>
                    confirmRemove("Detach this issue from its parent?", () =>
                      rpc(spaceId, { cmd: "issue_parent", reff, parent: null }),
                    ),
                }
              : {})}
          />
        </RelGroup>
      )}

      {(graph.children.length > 0 || subDraft !== null) && (
        // `done/total`, Linear's sub-issue progress at a glance.
        <RelGroup label={`Sub-issues · ${doneChildren}/${graph.children.length}`}>
          {graph.children.length > 0 && (
            <div
              className="bg-line h-1.5 overflow-hidden rounded-full"
              role="progressbar"
              aria-label="Sub-issue completion"
              aria-valuemin={0}
              aria-valuemax={graph.children.length}
              aria-valuenow={doneChildren}
            >
              <span
                className="bg-ok block h-full rounded-full transition-[width]"
                style={{ width: `${(doneChildren / graph.children.length) * 100}%` }}
              />
            </div>
          )}
          {graph.children.map((r) => (
            <RelRow
              key={r.reff}
              row={r}
              icon={<CornerDownRight className="size-3" />}
              onNavigate={onNavigate}
              {...(removable
                ? {
                    onRemove: () =>
                      confirmRemove(`Detach ${r.key_alias ?? r.reff} from this issue?`, () =>
                        rpc(spaceId, { cmd: "issue_parent", reff: r.reff, parent: null }),
                      ),
                  }
                : {})}
            />
          ))}
          {subDraft !== null && (
            <input
              autoFocus
              value={subDraft}
              placeholder="Sub-issue title…  (Enter creates, Esc closes)"
              onChange={(e) => setSubDraft(e.target.value)}
              onKeyDown={(e) => {
                e.stopPropagation();
                if (e.key === "Enter" && subDraft.trim()) createSub(subDraft.trim());
                if (e.key === "Escape") setSubDraft(null);
              }}
              onBlur={() => {
                if (!subDraft.trim()) setSubDraft(null);
              }}
              aria-label="New sub-issue title"
              className="border-line focus:border-line-strong placeholder:text-mute rounded border bg-transparent px-2 py-1 text-sm outline-none"
            />
          )}
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

      {blocks.length > 0 && (
        <LinkGroup
          label="Blocks"
          links={blocks}
          onNavigate={onNavigate}
          {...(removable ? { onRemove: unlink } : {})}
        />
      )}
      {related.length > 0 && (
        <LinkGroup
          label="Related"
          links={related}
          onNavigate={onNavigate}
          {...(removable ? { onRemove: unlink } : {})}
        />
      )}
      {dupes.length > 0 && (
        <LinkGroup
          label="Duplicates"
          links={dupes}
          onNavigate={onNavigate}
          {...(removable ? { onRemove: unlink } : {})}
        />
      )}

      {!readOnly &&
        (adding ? (
          <div className="flex items-center gap-2">
            <Combobox
              label="Relation"
              value={{
                id: kind,
                label: RELATION_KINDS.find((k) => k.id === kind)?.label ?? kind,
              }}
              options={RELATION_KINDS.map((k) => ({ id: k.id, label: k.label }))}
              onPick={(id) => setKind(id as RelationKind)}
            />
            <Combobox
              label="Issue"
              value={null}
              placeholder="Issue…"
              emptyText={candidates === null ? "Loading…" : "No issues"}
              options={(candidates ?? []).map(issueOption)}
              onPick={relate}
            />
            <IconButton label="Cancel" onClick={() => setAdding(false)}>
              <X className="size-3.5" />
            </IconButton>
          </div>
        ) : (
          <div className="flex items-center gap-1">
            <Button id="issue-add-relation" onClick={() => setAdding(true)} className="w-fit">
              <Plus className="size-3" />
              Add relation
            </Button>
            <Button onClick={() => setSubDraft("")} className="w-fit">
              <Plus className="size-3" />
              Add sub-issue
            </Button>
          </div>
        ))}
    </section>
  );
}

/** How an issue reads inside a picker: its handle, then its title; searchable by both. */
function issueOption(r: Row): Option {
  return {
    id: r.reff,
    label: r.title,
    hint: r.key_alias ?? r.reff,
    keywords: [r.reff, ...(r.key_alias ? [r.key_alias] : [])],
  };
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
  onRemove,
}: {
  label: string;
  links: LinkDto[];
  onNavigate: (reff: string) => void;
  onRemove?: (l: LinkDto) => void;
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
          {...(onRemove ? { onRemove: () => onRemove(l) } : {})}
        />
      ))}
    </RelGroup>
  );
}

/**
 * One navigable edge: click opens that issue in this same pane. A `div` holding
 * two buttons rather than one button, because "open" and "remove" are separate
 * gestures and nested buttons are invalid HTML the keyboard can't reach.
 */
function RelRow({
  row,
  icon,
  onNavigate,
  onRemove,
}: {
  row: Row;
  icon: React.ReactNode;
  onNavigate: (reff: string) => void;
  onRemove?: () => void;
}) {
  return (
    <div className="group/rel -mx-1 flex items-center gap-2 rounded px-1 py-0.5 text-sm">
      <Button
        onClick={() => onNavigate(row.reff)}
        className="min-w-0 flex-1 shrink justify-start px-1 text-left"
      >
        <span className="flex size-3 shrink-0 items-center justify-center">{icon}</span>
        <span className="text-mute w-16 shrink-0 truncate font-mono text-2xs tabular-nums">
          {row.key_alias ?? row.reff}
        </span>
        <span className="min-w-0 flex-1 truncate">{row.title}</span>
      </Button>
      {onRemove && (
        <IconButton
          label="Remove relation"
          onClick={onRemove}
          // Revealed on row hover/focus: the affordance is there when wanted and
          // the list stays quiet the rest of the time.
          className="opacity-0 group-hover/rel:opacity-100 focus-visible:opacity-100"
        >
          <X className="size-3" />
        </IconButton>
      )}
    </div>
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
 *   synthetic `synced` marker (that belongs to the space Activity feed).
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
  readOnly,
  meKey,
  onReact,
  onReply,
  onCopyLink,
  onCreateFromComment,
}: {
  events: ActivityEvent[];
  comments: CommentDto[];
  memberOf: (key: string) => MemberDto | undefined;
  readOnly: boolean;
  /** My member key — how "did I already react" is answered. */
  meKey: string | null;
  onReact: (comment: string, emoji: string, on: boolean) => void;
  onReply: (replyTo: string, body: string) => void;
  onCopyLink: (commentId: string) => void;
  onCreateFromComment: (body: string) => void;
}) {
  const [visibleCount, setVisibleCount] = useState(40);
  // The naming policy lives here, where the member list is: a key becomes an alias,
  // "you", or a short prefix. `describeEvent` only decides *whether* there is a name.
  const resolveName: NameResolver = (key) => nameOf(key, memberOf(key));
  const entries = useMemo<Entry[]>(() => {
    const out: Entry[] = [
      // Roots only: a reply renders nested under its parent, not as its own
      // timeline entry — the thread reads as one exchange.
      ...comments
        .filter((c) => !c.parent)
        .map((c, i) => ({ at: c.ts, order: i, kind: "comment" as const, comment: c })),
      ...events
        .filter((e) => e.kind !== "commented")
        .map((e) => ({ at: e.ts, order: e.seq, kind: "event" as const, event: e })),
    ];
    // Oldest first — a timeline you read downward, like the conversation it is.
    // `order` breaks ties: whole-second stamps mean a burst of edits all land on
    // the same `ts`, and without it they shuffle on every render.
    return out.sort((a, b) => a.at - b.at || a.order - b.order);
  }, [events, comments]);

  const repliesByParent = useMemo(() => {
    const indexed = new Map<string, CommentDto[]>();
    for (const comment of comments) {
      if (!comment.parent) continue;
      indexed.set(comment.parent, [...(indexed.get(comment.parent) ?? []), comment]);
    }
    return indexed;
  }, [comments]);
  const visibleEntries = boundedTail(entries, visibleCount);

  return (
    <section id="issue-activity" className="flex flex-col gap-3 scroll-mt-3">
      <SectionHeader
        title="Activity"
        meta={comments.length > 0 ? `${comments.length} comments` : undefined}
        action={
          <span
            title="This issue's full history, read from its change log on disk — it survives restarts and shows who made each change. (The space-wide Activity view is a lighter, per-session feed.)"
            className="cursor-help"
          >
            <Info className="size-3" />
          </span>
        }
      />

      {entries.length === 0 && <p className="text-mute text-sm">Nothing yet.</p>}
      {entries.length > visibleCount && (
        <Button
          variant="ghost"
          onClick={() => setVisibleCount((count) => count + 40)}
          className="self-start"
        >
          Show {Math.min(40, entries.length - visibleCount)} earlier changes
        </Button>
      )}

      {visibleEntries.map((entry) =>
        entry.kind === "comment" ? (
          <Comment
            key={`c${entry.order}`}
            comment={entry.comment}
            replies={entry.comment.id ? (repliesByParent.get(entry.comment.id) ?? []) : []}
            memberOf={memberOf}
            readOnly={readOnly}
            meKey={meKey}
            onReact={onReact}
            onReply={onReply}
            onCopyLink={onCopyLink}
            onCreateFromComment={onCreateFromComment}
          />
        ) : (
          <Event key={`e${entry.order}`} event={entry.event} resolveName={resolveName} />
        ),
      )}
    </section>
  );
}

/** The fixed reaction palette — Linear's set, no free-typing an emoji here
 *  (the engine accepts any single emoji; the CLI can send exotic ones). */
const REACTION_EMOJIS = ["👍", "❤️", "🎉", "😄", "🚀", "👀"] as const;

function Comment({
  comment: c,
  replies,
  memberOf,
  readOnly,
  meKey,
  onReact,
  onReply,
  onCopyLink,
  onCreateFromComment,
}: {
  comment: CommentDto;
  replies: CommentDto[];
  memberOf: (key: string) => MemberDto | undefined;
  readOnly: boolean;
  meKey: string | null;
  onReact: (comment: string, emoji: string, on: boolean) => void;
  onReply: (replyTo: string, body: string) => void;
  onCopyLink: (commentId: string) => void;
  onCreateFromComment: (body: string) => void;
}) {
  const member = memberOf(c.author);
  const [picking, setPicking] = useState(false);
  const [replying, setReplying] = useState<string | null>(null);
  // Pre-identity comments (no id) cannot anchor reactions or replies — the
  // affordances simply don't exist for them, rather than existing and failing.
  const canAct = !readOnly && !!c.id;

  return (
    <article className="flex gap-2">
      <Avatar
        deviceKey={c.author}
        // The in-doc `author_nick` is what the author *claimed*; the local alias is
        // what you decided they are. Prefer yours — it is the half that was verified.
        alias={member?.alias || c.author_nick || ""}
        me={member?.me ?? false}
        className="mt-0.5"
      />
      <div className="min-w-0 flex-1">
        <div className="group/comment">
          <div className="flex items-baseline gap-2">
            <span className="font-medium">
              {member ? nameOf(c.author, member) : (c.author_nick ?? short(c.author))}
            </span>
            {/* Unix SECONDS — `tsToDate` is the only place that's converted. */}
            <time className="text-mute text-xs" dateTime={tsToDate(c.ts).toISOString()}>
              {when(c.ts)}
            </time>
          </div>
          <Markdown text={c.body} />

          {(canAct || (c.reactions?.length ?? 0) > 0) && (
            <div className="mt-1 flex flex-wrap items-center gap-1">
              {(c.reactions ?? []).map((r) => {
                const mine = meKey !== null && r.actors.includes(meKey);
                return (
                  <ChipButton
                    key={r.emoji}
                    disabled={!canAct}
                    onClick={() => c.id && onReact(c.id, r.emoji, !mine)}
                    title={r.actors.map((a) => nameOf(a, memberOf(a))).join(", ")}
                    aria-pressed={mine}
                  >
                    {r.emoji}
                    <span className="tabular-nums">{r.actors.length}</span>
                  </ChipButton>
                );
              })}
              {canAct && (
                <>
                  {/* A floating palette, like every other pick-from-a-set surface —
                      it used to swap itself inline for six buttons and shove the
                      footer sideways. */}
                  <Popover.Root open={picking} onOpenChange={setPicking}>
                    <Popover.Trigger asChild>
                      <IconButton
                        aria-label="Add reaction"
                        label="Add reaction"
                        className="opacity-0 transition-opacity group-hover/comment:opacity-100 focus-visible:opacity-100 data-[state=open]:opacity-100"
                      >
                        <SmilePlus className="size-3.5" />
                      </IconButton>
                    </Popover.Trigger>
                    <PopoverContent align="start" className="flex gap-0.5 p-1">
                      {REACTION_EMOJIS.map((emoji) => (
                        <Button
                          key={emoji}
                          onClick={() => {
                            setPicking(false);
                            if (c.id) onReact(c.id, emoji, true);
                          }}
                          aria-label={`React ${emoji}`}
                          size="icon"
                          className="text-base"
                        >
                          {emoji}
                        </Button>
                      ))}
                    </PopoverContent>
                  </Popover.Root>
                  {/* Replies to a reply re-anchor to the root: one level. */}
                  {!c.parent && (
                    <InlineAction
                      onClick={() => setReplying("")}
                      className="opacity-0 transition-opacity group-hover/comment:opacity-100 focus-visible:opacity-100"
                    >
                      Reply
                    </InlineAction>
                  )}
                  {c.id && (
                    <>
                      <InlineAction
                        onClick={() => onCopyLink(c.id!)}
                        className="opacity-0 transition-opacity group-hover/comment:opacity-100 focus-visible:opacity-100"
                      >
                        Copy link
                      </InlineAction>
                      <InlineAction
                        onClick={() => onCreateFromComment(c.body)}
                        title="Create a new issue from this comment"
                        className="opacity-0 transition-opacity group-hover/comment:opacity-100 focus-visible:opacity-100"
                      >
                        New issue
                      </InlineAction>
                    </>
                  )}
                </>
              )}
            </div>
          )}
        </div>

        {(replies.length > 0 || replying !== null) && (
          <div className="border-line mt-2 flex flex-col gap-2 border-l pl-3">
            {replies.map((r, i) => (
              <Comment
                key={r.id ?? `r${i}`}
                comment={r}
                replies={[]}
                memberOf={memberOf}
                readOnly={readOnly}
                meKey={meKey}
                onReact={onReact}
                onReply={onReply}
                onCopyLink={onCopyLink}
                onCreateFromComment={onCreateFromComment}
              />
            ))}
            {replying !== null && (
              <textarea
                autoFocus
                value={replying}
                placeholder="Reply…  (⌘/Ctrl + Enter)"
                onChange={(e) => setReplying(e.target.value)}
                onKeyDown={(e) => {
                  e.stopPropagation();
                  if (e.key === "Escape") setReplying(null);
                  if (e.key === "Enter" && (e.metaKey || e.ctrlKey) && replying.trim() && c.id) {
                    e.preventDefault();
                    onReply(c.id, replying.trim());
                    setReplying(null);
                  }
                }}
                rows={2}
                aria-label="Reply"
                className="border-line focus-within:border-line-strong placeholder:text-mute resize-y rounded border bg-transparent p-2 text-sm outline-none"
              />
            )}
          </div>
        )}
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
  draftKey,
  value,
  readOnly,
  onSave,
}: {
  draftKey: { spaceId: string; reff: string };
  value: string;
  readOnly: boolean;
  onSave: (v: string) => void;
}) {
  const [draft, setDraft] = useState(
    () => loadDraft(draftKey.spaceId, draftKey.reff, "description") || value,
  );
  const [editing, setEditing] = useState(
    () => loadDraft(draftKey.spaceId, draftKey.reff, "description") !== "",
  );

  // Adopt server truth whenever we're not the one holding the pen.
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  useEffect(() => {
    if (editing && draft !== value) {
      saveDraft(draftKey.spaceId, draftKey.reff, "description", draft);
    }
  }, [draftKey.spaceId, draftKey.reff, draft, editing, value]);

  if (readOnly || (!editing && value)) {
    const content = value ? <Markdown text={value} /> : <span className="text-mute">No description</span>;
    return readOnly ? (
      <div className="min-h-10 py-2">{content}</div>
    ) : (
      <EditableSurface label="Edit description" onEdit={() => setEditing(true)}>
        {content}
      </EditableSurface>
    );
  }
  if (!editing) {
    return (
      <EditableSurface label="Add description" onEdit={() => setEditing(true)}>
        <span className="text-mute">Add description…</span>
      </EditableSurface>
    );
  }
  return (
    <Textarea
      autoFocus
      value={draft}
      rows={5}
      onChange={(e) => setDraft(e.target.value)}
      onBlur={() => {
        setEditing(false);
        if (draft !== value) {
          clearDraft(draftKey.spaceId, draftKey.reff, "description");
          onSave(draft);
        }
      }}
      onKeyDown={(e) => {
        if (e.key === "Escape") {
          setDraft(value);
          clearDraft(draftKey.spaceId, draftKey.reff, "description");
          setEditing(false);
        }
      }}
      aria-label="Description"
    />
  );
}
