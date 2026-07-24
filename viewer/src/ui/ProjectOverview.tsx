import { useCallback, useEffect, useState } from "react";
import { Archive, ArchiveRestore, ArrowLeft, ArrowRight, X } from "lucide-react";

import { rpc } from "../api";
import type { MemberDto, MilestoneDto, ProjectDto, ProjectUpdateDto } from "../types";
import { Avatar, memberName } from "./Avatar";
import { catalogColor } from "./colors";
import { ColorPicker } from "./ColorPicker";
import { DatePicker } from "./DatePicker";
import { Markdown } from "./Markdown";
import { Combobox } from "./Picker";
import { PropertyRow, SurfaceHeader } from "./layout";
import { Button, EditableSurface, IconButton, PopoverContent, Textarea } from "./primitives";
import { when } from "./time";
import * as Popover from "@radix-ui/react-popover";

/** The health signals a project update can carry — Linear's on-track palette. */
const HEALTH: Record<string, { label: string; tone: string }> = {
  on_track: { label: "On track", tone: "text-ok" },
  at_risk: { label: "At risk", tone: "text-warn" },
  off_track: { label: "Off track", tone: "text-danger" },
};

/** unix seconds -> YYYY-MM-DD (UTC), the wire format the engine + DatePicker share. */
function toInput(secs: number | null | undefined): string | null {
  if (secs == null) return null;
  return new Date(secs * 1000).toISOString().slice(0, 10);
}

/**
 * A project's overview — the document a project became.
 *
 * A lait project used to be `{name, key, color}`; the catalog now carries a
 * description, a lead, and a planned window, so this is the page that edits them.
 * Every field is a `project_edit` on the way out (the same LWW catalog write the
 * settings labels page uses); there is no project doc/body yet, so the description
 * is a catalog register — good for an overview paragraph, not a wiki.
 */
export function ProjectOverview({
  spaceId,
  project,
  members,
  counts,
  readOnly,
  onOpenIssues,
  onBack,
  onError,
}: {
  spaceId: string;
  project: ProjectDto;
  members: MemberDto[];
  counts: { backlog: number; active: number; done: number; total: number };
  readOnly: boolean;
  onOpenIssues: () => void;
  onBack: () => void;
  onError: (message: string) => void;
}) {
  const edit = async (patch: Record<string, string | boolean | null>) => {
    try {
      await rpc(spaceId, { cmd: "project_edit", project: project.key, ...patch });
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  const lead = members.find((m) => m.key === project.lead);
  const { backlog, active, done, total } = counts;

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SurfaceHeader className="gap-2 px-3">
        <IconButton label="Back to projects" onClick={onBack}>
          <ArrowLeft className="size-4" />
        </IconButton>
        <span className="text-mute font-mono text-xs">{project.key}</span>
        {project.archived && (
          <span className="border-line text-mute rounded-full border px-2 py-px text-2xs">
            Archived
          </span>
        )}
        {!readOnly && (
          <Button
            variant="outline"
            className="ml-auto"
            onClick={() => void edit({ archived: !project.archived })}
          >
            {project.archived ? (
              <>
                <ArchiveRestore className="size-3.5" /> Restore
              </>
            ) : (
              <>
                <Archive className="size-3.5" /> Archive
              </>
            )}
          </Button>
        )}
        <Button className={readOnly ? "ml-auto" : ""} onClick={onOpenIssues}>
          Open issues
          <ArrowRight className="size-3" />
        </Button>
      </SurfaceHeader>

      <div className="min-h-0 flex-1 overflow-y-auto p-6">
        <div className="mx-auto grid max-w-4xl gap-8 md:grid-cols-[minmax(0,1fr)_260px]">
          {/* Title + description */}
          <div className="min-w-0">
            <div className="mb-4 flex items-center gap-2">
              {!readOnly ? (
                <Popover.Root>
                  <Popover.Trigger asChild>
                    <button
                      aria-label="Project colour"
                      className="hover:ring-line-strong rounded p-0.5 hover:ring-1"
                    >
                      <span
                        className="block size-4 rounded"
                        style={{ background: catalogColor(project.color) }}
                      />
                    </button>
                  </Popover.Trigger>
                  <PopoverContent align="start" className="p-2">
                    <ColorPicker
                      value={project.color}
                      onChange={(color) => void edit({ color })}
                    />
                  </PopoverContent>
                </Popover.Root>
              ) : (
                <span
                  className="block size-4 rounded"
                  style={{ background: catalogColor(project.color) }}
                />
              )}
              <input
                defaultValue={project.name}
                readOnly={readOnly}
                onBlur={(e) => {
                  const next = e.target.value.trim();
                  if (next && next !== project.name) void edit({ name: next });
                }}
                className="min-w-0 flex-1 bg-transparent text-xl font-semibold outline-none"
                aria-label="Project name"
              />
            </div>
            <Description
              value={project.description ?? ""}
              readOnly={readOnly}
              onSave={(description) => void edit({ description })}
            />
            <Milestones
              spaceId={spaceId}
              projectKey={project.key}
              readOnly={readOnly}
              onError={onError}
            />
            <Updates
              spaceId={spaceId}
              projectKey={project.key}
              members={members}
              readOnly={readOnly}
              onError={onError}
            />
          </div>

          {/* Properties rail */}
          <dl className="flex flex-col gap-1 text-sm md:border-l md:border-line md:pl-6">
            <PropertyRow label="Lead">
              <Combobox
                variant="property"
                label="Lead"
                disabled={readOnly}
                value={
                  lead
                    ? {
                        id: lead.key,
                        label: memberName(lead.key, lead),
                        icon: <Avatar deviceKey={lead.key} alias={lead.alias} me={lead.me} size="sm" />,
                      }
                    : null
                }
                placeholder="No lead"
                options={[
                  { id: "none", label: "No lead" },
                  ...members.map((m) => ({
                    id: m.key,
                    label: memberName(m.key, m),
                    icon: <Avatar deviceKey={m.key} alias={m.alias} me={m.me} size="sm" />,
                    hint: m.key.slice(0, 6),
                    keywords: [m.key, m.alias],
                  })),
                ]}
                onPick={(id) => void edit({ lead: id === "none" ? "none" : id })}
              />
            </PropertyRow>
            <PropertyRow label="Start">
              <DatePicker
                variant="property"
                value={toInput(project.start_date)}
                disabled={readOnly}
                placeholder="—"
                ariaLabel="Start date"
                onChange={(next) => void edit({ start: next ?? "none" })}
              />
            </PropertyRow>
            <PropertyRow label="Target">
              <DatePicker
                variant="property"
                value={toInput(project.target_date)}
                disabled={readOnly}
                placeholder="—"
                ariaLabel="Target date"
                onChange={(next) => void edit({ target: next ?? "none" })}
              />
            </PropertyRow>
            <PropertyRow label="Progress">
              <div className="flex w-full flex-col gap-1">
                <span className="bg-line flex h-1.5 w-full gap-0.5 overflow-hidden rounded-full">
                  {total === 0 ? null : (
                    <>
                      {backlog > 0 && <span className="bg-mute" style={{ flex: backlog }} />}
                      {active > 0 && <span className="bg-accent" style={{ flex: active }} />}
                      {done > 0 && <span className="bg-ok" style={{ flex: done }} />}
                    </>
                  )}
                </span>
                <span className="text-mute text-2xs">
                  {done}/{total} done · {active} active
                </span>
              </div>
            </PropertyRow>
          </dl>
        </div>
      </div>
    </div>
  );
}

/** The overview paragraph — a draft you commit, mirroring the issue description. */
function Description({
  value,
  readOnly,
  onSave,
}: {
  value: string;
  readOnly: boolean;
  onSave: (v: string) => void;
}) {
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState(value);
  useEffect(() => {
    if (!editing) setDraft(value);
  }, [value, editing]);

  if (readOnly || !editing) {
    const content = value ? (
      <Markdown text={value} />
    ) : (
      <span className="text-mute">
        {readOnly ? "No description" : "Add a project overview…"}
      </span>
    );
    return readOnly ? (
      <div className="min-h-16 py-2">{content}</div>
    ) : (
      <EditableSurface
        label="Edit project overview"
        className="min-h-16"
        onEdit={() => setEditing(true)}
      >
        {content}
      </EditableSurface>
    );
  }
  return (
    <Textarea
      autoFocus
      value={draft}
      rows={8}
      placeholder="Describe this project — goals, scope, links. Markdown supported."
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
      aria-label="Project description"
    />
  );
}

/**
 * The project's milestones (SCOPE-1): named targets with derived progress.
 * Records live in the catalog's `project_milestones` map; the counts are
 * derived by the engine from issues' milestone pointers, never stored.
 */
function Milestones({
  spaceId,
  projectKey,
  readOnly,
  onError,
}: {
  spaceId: string;
  projectKey: string;
  readOnly: boolean;
  onError: (message: string) => void;
}) {
  const [milestones, setMilestones] = useState<MilestoneDto[] | null>(null);
  const [draft, setDraft] = useState("");
  const [target, setTarget] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await rpc(spaceId, { cmd: "milestone_list", project: projectKey });
      if (r.kind === "milestones") setMilestones(r.milestones);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }, [spaceId, projectKey, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  const add = async () => {
    const name = draft.trim();
    if (!name) return;
    setAdding(true);
    try {
      await rpc(spaceId, {
        cmd: "milestone_set",
        project: projectKey,
        name,
        target,
      });
      setDraft("");
      setTarget(null);
      await load();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setAdding(false);
    }
  };

  const remove = async (id: string) => {
    try {
      await rpc(spaceId, { cmd: "milestone_set", project: projectKey, milestone: id, remove: true });
      await load();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  if (milestones !== null && milestones.length === 0 && readOnly) return null;
  return (
    <section className="mt-8">
      <h2 className="text-mute mb-3 text-2xs font-semibold tracking-wider uppercase">
        Milestones
      </h2>
      {milestones === null && <p className="text-mute text-sm">Loading…</p>}
      {milestones !== null && milestones.length === 0 && (
        <p className="text-mute mb-2 text-sm">No milestones yet.</p>
      )}
      <ol className="flex flex-col gap-2">
        {milestones?.map((m) => {
          const pct = m.total === 0 ? 0 : Math.round((m.done / m.total) * 100);
          return (
            <li
              key={m.id}
              className="border-line group flex items-center gap-3 rounded border px-3 py-2"
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-baseline gap-2 text-sm">
                  <span className="text-ink truncate font-medium">{m.name}</span>
                  {m.target_date != null && (
                    <span className="text-mute text-xs">→ {toInput(m.target_date)}</span>
                  )}
                  <span className="text-mute ml-auto shrink-0 text-xs">
                    {m.done}/{m.total} · {pct}%
                  </span>
                </div>
                <span className="bg-line mt-1.5 block h-1 w-full overflow-hidden rounded-full">
                  <span className="bg-ok block h-full" style={{ width: `${pct}%` }} />
                </span>
              </div>
              {!readOnly && (
                <IconButton
                  label={`Remove milestone ${m.name}`}
                  className="opacity-0 group-hover:opacity-100"
                  onClick={() => void remove(m.id)}
                >
                  <X className="size-3.5" />
                </IconButton>
              )}
            </li>
          );
        })}
      </ol>
      {!readOnly && (
        <div className="mt-2 flex items-center gap-2">
          <input
            value={draft}
            placeholder="New milestone…"
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && draft.trim()) void add();
            }}
            className="border-line focus:border-line-strong placeholder:text-mute min-w-0 flex-1 rounded border bg-transparent px-2 py-1 text-sm outline-none"
            aria-label="New milestone name"
          />
          <DatePicker
            variant="property"
            value={target}
            placeholder="Target"
            ariaLabel="Milestone target date"
            onChange={setTarget}
          />
          <Button variant="outline" disabled={!draft.trim() || adding} onClick={() => void add()}>
            Add
          </Button>
        </div>
      )}
    </section>
  );
}

/**
 * The project updates feed (SCOPE-1) — an append-only stream of status posts.
 *
 * Each update is an immutable record in the engine's grow-only `project_updates`
 * log (a catalog map, not a per-project doc: an update is authored once, so a
 * record is the honest shape and it needs no collaborative-text merge). This
 * posts via `project_update_post` and reads via `project_updates`; the doorbell
 * is not wired here, so it reloads after its own post.
 */
function Updates({
  spaceId,
  projectKey,
  members,
  readOnly,
  onError,
}: {
  spaceId: string;
  projectKey: string;
  members: MemberDto[];
  readOnly: boolean;
  onError: (message: string) => void;
}) {
  const [updates, setUpdates] = useState<ProjectUpdateDto[] | null>(null);
  const [draft, setDraft] = useState("");
  const [health, setHealth] = useState("");
  const [posting, setPosting] = useState(false);

  const load = useCallback(async () => {
    try {
      const r = await rpc(spaceId, { cmd: "project_updates", project: projectKey });
      if (r.kind === "updates") setUpdates(r.updates);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }, [spaceId, projectKey, onError]);

  useEffect(() => {
    void load();
  }, [load]);

  const post = async () => {
    const body = draft.trim();
    if (!body) return;
    setPosting(true);
    try {
      await rpc(spaceId, { cmd: "project_update_post", project: projectKey, body, health });
      setDraft("");
      setHealth("");
      await load();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setPosting(false);
    }
  };

  return (
    <section className="mt-8">
      <h2 className="text-mute mb-3 text-2xs font-semibold tracking-wider uppercase">Updates</h2>

      {!readOnly && (
        <div className="border-line mb-4 rounded border p-3">
          <textarea
            value={draft}
            rows={2}
            placeholder="Post a status update — what changed, what's next…"
            onChange={(e) => setDraft(e.target.value)}
            className="placeholder:text-mute w-full resize-y bg-transparent text-sm outline-none"
            aria-label="New project update"
          />
          <div className="mt-2 flex items-center gap-2">
            <Combobox
              label="Health"
              value={{ id: health, label: health ? (HEALTH[health]?.label ?? health) : "No health" }}
              placeholder="Health"
              options={[
                { id: "", label: "No health" },
                { id: "on_track", label: "On track" },
                { id: "at_risk", label: "At risk" },
                { id: "off_track", label: "Off track" },
              ]}
              onPick={setHealth}
            />
            <Button
              variant="primary"
              size="md"
              className="ml-auto"
              disabled={!draft.trim() || posting}
              loading={posting}
              onClick={() => void post()}
            >
              Post update
            </Button>
          </div>
        </div>
      )}

      {!updates && <p className="text-mute text-sm">Loading…</p>}
      {updates && updates.length === 0 && (
        <p className="text-mute text-sm">No updates yet.</p>
      )}
      <ol className="flex flex-col gap-4">
        {updates?.map((u) => {
          const author = members.find((m) => m.key === u.author);
          const h = u.health ? HEALTH[u.health] : undefined;
          return (
            <li key={u.id} className="border-line border-l-2 pl-3">
              <div className="mb-1 flex items-center gap-2 text-sm">
                {author && <Avatar deviceKey={u.author} alias={author.alias} me={author.me} size="sm" />}
                <span className="font-medium">{memberName(u.author, author)}</span>
                {h && <span className={`text-2xs ${h.tone}`}>· {h.label}</span>}
                <span className="text-mute ml-auto text-xs">{when(u.ts)}</span>
              </div>
              <div className="text-sm">
                <Markdown text={u.body} />
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
