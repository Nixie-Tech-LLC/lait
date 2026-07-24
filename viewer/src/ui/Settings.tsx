import { useCallback, useEffect, useMemo, useState } from "react";
import {
  ArrowLeft,
  Hash,
  Palette,
  ShieldCheck,
  ShieldPlus,
  SlidersHorizontal,
  Tag,
  Trash2,
  Users,
  X,
} from "lucide-react";

import { rpc } from "../api";
import type { AssignmentDto, LabelDto, MemberDto, ProjectDto } from "../types";
import { memberName } from "./Avatar";
import { catalogColor } from "./colors";
import { ColorPicker } from "./ColorPicker";
import * as ask from "./dialogs";
import { StatusIcon } from "./icons";
import { SurfaceHeader } from "./layout";
import { Members } from "./Members";
import { Combobox } from "./Picker";
import { Button, cn, IconButton, Input, navigationItem, Textarea } from "./primitives";

type Tab = "general" | "members" | "labels" | "workflow" | "access";

/**
 * The settings surface — the place a space is administered like an application.
 *
 * It is a real destination (a `settings` view/route), not a modal, because it hosts
 * several editors that each own state; a popover would throw that away on the first
 * outside click. The left rail is the taxonomy Linear uses — General, Labels,
 * Workflow — over the engine's now-mutable catalog (space rename, label lifecycle,
 * workflow states), which until recently was create-only.
 */
export function Settings({
  spaceId,
  spaceName,
  spaceDescription,
  labels,
  projects,
  readOnly,
  revision,
  onError,
  onExit,
}: {
  spaceId: string;
  spaceName: string;
  spaceDescription: string;
  labels: LabelDto[];
  projects: ProjectDto[];
  readOnly: boolean;
  /** Bumped by the doorbell; re-reads the panels that fetch. */
  revision: number;
  onError: (message: string) => void;
  /** Leave settings and return to the app — the workspace sidebar is collapsed
   *  while this page is open, so this is the way back. */
  onExit: () => void;
}) {
  // Read the initial tab from `?tab=` so a settings sub-page is deep-linkable
  // (and reliably reachable by a headless driver via `open`, no click needed).
  const [tab, setTabState] = useState<Tab>(() => {
    if (window.location.pathname.split("/").filter(Boolean).at(-1) === "members") return "members";
    const t = new URLSearchParams(window.location.search).get("tab");
    return t === "members" || t === "labels" || t === "workflow" || t === "access" ? t : "general";
  });
  const setTab = (next: Tab) => {
    setTabState(next);
    const url = new URL(window.location.href);
    if (next === "general") url.searchParams.delete("tab");
    else url.searchParams.set("tab", next);
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  };
  // Reliable driver hook: `lait:nav { tab }` selects a sub-page without a click.
  useEffect(() => {
    const onNav = (event: Event) => {
      const t = (event as CustomEvent).detail?.tab;
      if (t === "general" || t === "members" || t === "labels" || t === "workflow" || t === "access") setTab(t);
    };
    window.addEventListener("lait:nav", onNav as EventListener);
    return () => window.removeEventListener("lait:nav", onNav as EventListener);
  }, []);
  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: "general", label: "General", icon: <SlidersHorizontal className="size-3.5" /> },
    { id: "members", label: "Members", icon: <Users className="size-3.5" /> },
    { id: "labels", label: "Labels", icon: <Tag className="size-3.5" /> },
    { id: "workflow", label: "Workflow", icon: <Palette className="size-3.5" /> },
    { id: "access", label: "Roles & access", icon: <ShieldCheck className="size-3.5" /> },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SurfaceHeader className="gap-2 px-3">
        <IconButton label="Back to app" onClick={onExit}>
          <ArrowLeft className="size-4" />
        </IconButton>
        <h1 className="text-sm font-semibold">Settings</h1>
      </SurfaceHeader>
      <div className="flex min-h-0 flex-1">
        <nav className="border-line flex w-48 shrink-0 flex-col gap-0.5 border-r p-2">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cn(navigationItem({ selected: tab === t.id, density: "roomy" }))}
            >
              {t.icon}
              {t.label}
            </button>
          ))}
        </nav>
        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-2xl">
            {tab === "general" && (
              <GeneralPanel
                spaceId={spaceId}
                spaceName={spaceName}
                spaceDescription={spaceDescription}
                readOnly={readOnly}
                onError={onError}
              />
            )}
            {tab === "members" && (
              <Members
                spaceId={spaceId}
                revision={revision}
                readOnly={readOnly}
                onError={onError}
                embedded
              />
            )}
            {tab === "labels" && (
              <LabelsPanel spaceId={spaceId} labels={labels} readOnly={readOnly} onError={onError} />
            )}
            {tab === "workflow" && (
              <WorkflowPanel
                spaceId={spaceId}
                projects={projects}
                readOnly={readOnly}
                revision={revision}
                onError={onError}
              />
            )}
            {tab === "access" && (
              <AccessPanel
                spaceId={spaceId}
                projects={projects}
                readOnly={readOnly}
                revision={revision}
                onError={onError}
              />
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function Section({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <section className="mb-8">
      <h2 className="text-base font-semibold">{title}</h2>
      {hint && <p className="text-mute mt-0.5 text-sm">{hint}</p>}
      <div className="mt-3">{children}</div>
    </section>
  );
}

/** General — the space's mutable display label, description, and immutable identity. */
function GeneralPanel({
  spaceId,
  spaceName,
  spaceDescription,
  readOnly,
  onError,
}: {
  spaceId: string;
  spaceName: string;
  spaceDescription: string;
  readOnly: boolean;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState(spaceName);
  const [description, setDescription] = useState(spaceDescription);
  const [saving, setSaving] = useState(false);
  const [savingDesc, setSavingDesc] = useState(false);
  useEffect(() => setName(spaceName), [spaceName]);
  useEffect(() => setDescription(spaceDescription), [spaceDescription]);
  const dirty = name.trim() !== spaceName && name.trim() !== "";
  const descDirty = description !== spaceDescription;

  const save = async () => {
    setSaving(true);
    try {
      await rpc(spaceId, { cmd: "space_rename", name: name.trim() });
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const saveDescription = async () => {
    setSavingDesc(true);
    try {
      await rpc(spaceId, { cmd: "space_describe", description: description.trim() });
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSavingDesc(false);
    }
  };

  return (
    <>
      <Section title="Space name" hint="A mutable display label. The space's identity (below) never changes.">
        <div className="flex items-center gap-2">
          <Input
            value={name}
            disabled={readOnly}
            onChange={(e) => setName(e.target.value)}
            className="max-w-sm"
            aria-label="Space name"
          />
          <Button variant="primary" size="md" disabled={!dirty || readOnly} loading={saving} onClick={() => void save()}>
            Update
          </Button>
        </div>
      </Section>
      <Section title="Description" hint="A short overview of what this space is for. Shared with everyone in the space.">
        <div className="flex max-w-lg flex-col items-start gap-2">
          <Textarea
            value={description}
            disabled={readOnly}
            rows={3}
            placeholder="What is this space for? Goals, scope, links…"
            onChange={(e) => setDescription(e.target.value)}
            aria-label="Space description"
          />
          {!readOnly && (
            <Button variant="primary" size="md" disabled={!descDirty} loading={savingDesc} onClick={() => void saveDescription()}>
              Save description
            </Button>
          )}
        </div>
      </Section>
      <Section title="Identity" hint="The seed id — derived at founding from keys, not the name. It cannot be changed.">
        <div className="border-line bg-raised text-dim flex items-center gap-2 rounded border px-2 py-1.5 font-mono text-xs">
          <Hash className="text-mute size-3.5 shrink-0" />
          {spaceId}
        </div>
      </Section>
    </>
  );
}

/** Labels — the registry lifecycle the engine gained: create, rename, recolor, delete. */
function LabelsPanel({
  spaceId,
  labels,
  readOnly,
  onError,
}: {
  spaceId: string;
  labels: LabelDto[];
  readOnly: boolean;
  onError: (message: string) => void;
}) {
  const [creating, setCreating] = useState(false);
  const [newName, setNewName] = useState("");
  const [newColor, setNewColor] = useState("blue");
  const [editing, setEditing] = useState<string | null>(null);

  const send = async (fn: () => Promise<unknown>) => {
    try {
      await fn();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  };

  const create = () => {
    const name = newName.trim();
    if (!name) return;
    setNewName("");
    setCreating(false);
    void send(() => rpc(spaceId, { cmd: "label_new", name, color: newColor }));
  };

  return (
    <Section title="Labels" hint="Shared across every project. Renaming re-points every issue that uses one.">
      <ul className="flex flex-col gap-0.5">
        {labels.length === 0 && <li className="text-mute text-sm">No labels yet.</li>}
        {labels.map((l) =>
          editing === l.id ? (
            <LabelEditor
              key={l.id}
              label={l}
              onCancel={() => setEditing(null)}
              onSave={(name, color) => {
                setEditing(null);
                void send(() => rpc(spaceId, { cmd: "label_edit", label: l.id, name, color }));
              }}
            />
          ) : (
            <li
              key={l.id}
              className="group/label hover:bg-hover -mx-2 flex items-center gap-2 rounded px-2 py-1.5"
            >
              <span
                className="size-3 shrink-0 rounded-full"
                style={{ background: catalogColor(l.color) }}
              />
              <span className="min-w-0 flex-1 truncate text-sm">{l.name}</span>
              {!readOnly && (
                <span className="flex items-center gap-0.5 opacity-0 group-hover/label:opacity-100 focus-within:opacity-100">
                  <Button variant="ghost" onClick={() => setEditing(l.id)}>
                    Edit
                  </Button>
                  <IconButton
                    label={`Delete ${l.name}`}
                    onClick={() =>
                      void ask
                        .confirm({
                          title: `Delete label “${l.name}”?`,
                          body: "Issues keep the reference until it's re-created; it just leaves the registry.",
                          confirmText: "Delete",
                          danger: true,
                        })
                        .then((ok) => {
                          if (ok) void send(() => rpc(spaceId, { cmd: "label_delete", label: l.id }));
                        })
                    }
                  >
                    <Trash2 className="size-3.5" />
                  </IconButton>
                </span>
              )}
            </li>
          ),
        )}
      </ul>

      {!readOnly &&
        (creating ? (
          <div className="border-line mt-3 flex flex-col gap-3 rounded border p-3">
            <input
              autoFocus
              value={newName}
              placeholder="Label name"
              onChange={(e) => setNewName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newName.trim()) create();
                if (e.key === "Escape") setCreating(false);
              }}
              className="border-line focus:border-line-strong rounded border bg-transparent px-2 py-1.5 text-sm outline-none"
              aria-label="New label name"
            />
            <ColorPicker value={newColor} onChange={setNewColor} />
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setCreating(false)}>
                Cancel
              </Button>
              <Button variant="primary" disabled={!newName.trim()} onClick={create}>
                Create label
              </Button>
            </div>
          </div>
        ) : (
          <Button variant="outline" className="mt-3" onClick={() => setCreating(true)}>
            New label
          </Button>
        ))}
    </Section>
  );
}

function LabelEditor({
  label,
  onCancel,
  onSave,
}: {
  label: LabelDto;
  onCancel: () => void;
  onSave: (name: string, color: string) => void;
}) {
  const [name, setName] = useState(label.name);
  const [color, setColor] = useState(label.color);
  return (
    <li className="border-line -mx-2 my-1 flex flex-col gap-3 rounded border p-3">
      <input
        autoFocus
        value={name}
        onChange={(e) => setName(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" && name.trim()) onSave(name.trim(), color);
          if (e.key === "Escape") onCancel();
        }}
        className="border-line focus:border-line-strong rounded border bg-transparent px-2 py-1.5 text-sm outline-none"
        aria-label="Label name"
      />
      <ColorPicker value={color} onChange={setColor} />
      <div className="flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button variant="primary" disabled={!name.trim()} onClick={() => onSave(name.trim(), color)}>
          Save
        </Button>
      </div>
    </li>
  );
}

interface StateWire {
  state_id: string;
  name: string;
  category: string;
  color: string;
}
interface WorkflowWire {
  project_id: string;
  revision: {
    revision_id: string;
    body: { name: string; states: StateWire[]; transitions: unknown[] };
  } | null;
  conflict_heads: string[];
}

/**
 * Workflow — rename and recolor the status columns of a project.
 *
 * The engine already speaks this (`WorkflowSet` is a whole-body CAS replace at the
 * current heads); the viewer only ever read it. This edits the *display* of each
 * state — name and colour — and re-submits the same `state_id`s and transitions, so
 * referential integrity is preserved for free. Adding/removing states (which would
 * rewrite transitions) is deliberately out of scope here.
 */
function WorkflowPanel({
  spaceId,
  projects,
  readOnly,
  revision,
  onError,
}: {
  spaceId: string;
  projects: ProjectDto[];
  readOnly: boolean;
  revision: number;
  onError: (message: string) => void;
}) {
  const [projectKey, setProjectKey] = useState<string | null>(projects[0]?.key ?? null);
  const [wf, setWf] = useState<WorkflowWire | null>(null);
  const [draft, setDraft] = useState<StateWire[]>([]);
  const [saving, setSaving] = useState(false);
  const [editingColor, setEditingColor] = useState<string | null>(null);

  useEffect(() => {
    if (!projectKey) return;
    let alive = true;
    setWf(null);
    void rpc(spaceId, { cmd: "workflow_show", project: projectKey })
      .then((r) => {
        if (!alive) return;
        if (r.kind === "text") {
          const parsed = JSON.parse(r.text) as WorkflowWire;
          setWf(parsed);
          setDraft(parsed.revision?.body.states.map((s) => ({ ...s })) ?? []);
        }
      })
      .catch((e) => {
        if (alive) onError(e instanceof Error ? e.message : String(e));
      });
    return () => {
      alive = false;
    };
  }, [spaceId, projectKey, revision, onError]);

  const dirty = useMemo(() => {
    const original = wf?.revision?.body.states ?? [];
    return draft.some((s, i) => s.name !== original[i]?.name || s.color !== original[i]?.color);
  }, [draft, wf]);

  const save = async () => {
    if (!wf?.revision || !projectKey) return;
    setSaving(true);
    try {
      const body = { ...wf.revision.body, states: draft };
      const heads = [wf.revision.revision_id, ...wf.conflict_heads];
      await rpc(spaceId, {
        cmd: "workflow_set",
        project: projectKey,
        expect_heads: heads,
        body_json: JSON.stringify(body),
      });
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  const patch = (id: string, change: Partial<StateWire>) =>
    setDraft((d) => d.map((s) => (s.state_id === id ? { ...s, ...change } : s)));

  return (
    <Section
      title="Workflow states"
      hint="Rename and recolor the statuses issues move through. Applies to the selected project."
    >
      <div className="mb-4 flex items-center gap-2">
        <span className="text-mute text-sm">Project</span>
        <Combobox
          label="Project"
          value={
            projectKey
              ? {
                  id: projectKey,
                  label: projects.find((p) => p.key === projectKey)?.name ?? projectKey,
                }
              : null
          }
          placeholder="Select…"
          options={projects.map((p) => ({
            id: p.key,
            label: p.name,
            swatch: catalogColor(p.color),
            hint: p.key,
          }))}
          onPick={setProjectKey}
        />
      </div>

      {!wf && projectKey && <p className="text-mute text-sm">Loading…</p>}
      {wf && !wf.revision && (
        <p className="text-warn text-sm">This project has unresolved concurrent workflow revisions.</p>
      )}
      {wf?.revision && (
        <>
          <ul className="flex flex-col gap-1">
            {draft.map((s) => (
              <li
                key={s.state_id}
                className="border-line -mx-1 flex items-center gap-2 rounded px-1 py-1"
              >
                <div className="relative">
                  <button
                    disabled={readOnly}
                    onClick={() => setEditingColor(editingColor === s.state_id ? null : s.state_id)}
                    aria-label={`Colour of ${s.name}`}
                    className="hover:ring-line-strong rounded p-0.5 hover:ring-1 disabled:opacity-50"
                  >
                    <StatusIcon
                      category={s.category as "backlog"}
                      color={catalogColor(s.color)}
                    />
                  </button>
                  {editingColor === s.state_id && (
                    <div className="border-line-strong bg-raised shadow-overlay absolute left-0 top-7 z-10 rounded-lg border p-2">
                      <ColorPicker
                        value={s.color}
                        onChange={(color) => {
                          patch(s.state_id, { color });
                          setEditingColor(null);
                        }}
                      />
                    </div>
                  )}
                </div>
                <input
                  value={s.name}
                  disabled={readOnly}
                  onChange={(e) => patch(s.state_id, { name: e.target.value })}
                  className="focus:border-line-strong min-w-0 flex-1 rounded border border-transparent bg-transparent px-1.5 py-1 text-sm outline-none disabled:opacity-50"
                  aria-label={`Name of ${s.name}`}
                />
                <span className="text-mute text-2xs capitalize">
                  {s.category.replaceAll("_", " ")}
                </span>
              </li>
            ))}
          </ul>
          {!readOnly && (
            <div className="mt-4 flex items-center justify-between">
              <p className="text-mute text-xs">
                Adding or removing states (which rewrites transitions) is CLI-only for now.
              </p>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  disabled={!dirty}
                  onClick={() => setDraft(wf.revision!.body.states.map((s) => ({ ...s })))}
                >
                  Reset
                </Button>
                <Button variant="primary" disabled={!dirty} loading={saving} onClick={() => void save()}>
                  Save workflow
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </Section>
  );
}

// ---- Roles & access ---------------------------------------------------------

interface RoleWire {
  role_id: string;
  built_in: boolean;
  revision: {
    revision_id: string;
    body: { name: string; description: string; scope_kind: string; capabilities: string[] };
  } | null;
  conflict_heads: string[];
}

/** The name a role grant carries, falling back to its id. */
function roleName(r: RoleWire): string {
  return r.revision?.body.name ?? r.role_id;
}

/**
 * Roles & access — the plan-04 authority layer, made browser-operable.
 *
 * The engine has always spoken this (`role_list` / `access_list` / `access_grant`
 * / `access_revoke`); until now it was terminal-only, so a browser-first admin
 * could see a *membership* role on the Members page but never grant a scoped
 * capability. This surfaces the role catalogue read-only (authoring a role is a
 * CAS ceremony best left to the CLI) and makes the *assignment* verbs — grant a
 * role's capabilities to an actor, revoke one — first-class here.
 *
 * A grant expands a role into one assignment per capability, each with its own
 * `grant_id`; revoke is per capability, so the list is grouped by actor and every
 * held capability carries its own revoke handle.
 */
function AccessPanel({
  spaceId,
  projects,
  readOnly,
  revision,
  onError,
}: {
  spaceId: string;
  projects: ProjectDto[];
  readOnly: boolean;
  revision: number;
  onError: (message: string) => void;
}) {
  const [roles, setRoles] = useState<RoleWire[] | null>(null);
  const [members, setMembers] = useState<MemberDto[] | null>(null);
  const [rows, setRows] = useState<AssignmentDto[] | null>(null);
  const [busy, setBusy] = useState(false);
  const [grantActor, setGrantActor] = useState<string | null>(null);
  const [grantRole, setGrantRole] = useState<string | null>(null);
  const [grantProject, setGrantProject] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [r, m, a] = await Promise.all([
        rpc(spaceId, { cmd: "role_list" }),
        rpc(spaceId, { cmd: "members" }),
        rpc(spaceId, { cmd: "access_list" }),
      ]);
      if (r.kind === "text") setRoles(JSON.parse(r.text) as RoleWire[]);
      if (m.kind === "members") setMembers(m.members);
      if (a.kind === "assignments") setRows(a.rows);
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    }
  }, [spaceId, onError]);

  useEffect(() => {
    void load();
  }, [load, revision]);

  const nameOf = useCallback(
    (actor: string) => memberName(actor, members?.find((m) => m.key === actor)),
    [members],
  );
  const projectLabel = useCallback(
    (id: string) => projects.find((p) => p.id === id || p.key === id)?.key ?? id,
    [projects],
  );

  /** Assignments folded by actor, so each person reads as one block. */
  const byActor = useMemo(() => {
    const groups = new Map<string, AssignmentDto[]>();
    for (const row of rows ?? []) {
      const list = groups.get(row.actor) ?? [];
      list.push(row);
      groups.set(row.actor, list);
    }
    return [...groups.entries()].sort((a, b) => nameOf(a[0]).localeCompare(nameOf(b[0])));
  }, [rows, nameOf]);

  const grant = async () => {
    if (!grantActor || !grantRole) return;
    setBusy(true);
    try {
      await rpc(spaceId, {
        cmd: "access_grant",
        actor: grantActor,
        role: grantRole,
        project: grantProject,
      });
      setGrantActor(null);
      setGrantRole(null);
      setGrantProject(null);
      await load();
    } catch (e) {
      onError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  };

  const revoke = (row: AssignmentDto) =>
    void ask
      .confirm({
        title: `Revoke ${row.capability}?`,
        body: `Removes this one capability from ${nameOf(row.actor)}. Their base membership role is unaffected.`,
        confirmText: "Revoke",
        danger: true,
      })
      .then(async (ok) => {
        if (!ok) return;
        setBusy(true);
        try {
          await rpc(spaceId, { cmd: "access_revoke", grant_id: row.grant_id });
          await load();
        } catch (e) {
          onError(e instanceof Error ? e.message : String(e));
        } finally {
          setBusy(false);
        }
      });

  const grantableRoles = (roles ?? []).filter((r) => r.revision && !r.conflict_heads.length);

  return (
    <>
      <Section
        title="Roles"
        hint="Named capability sets from the signed policy. Authoring a role is a CAS ceremony — create and edit them with lait role create/edit."
      >
        {!roles && <p className="text-mute text-sm">Loading…</p>}
        <ul className="flex flex-col gap-2">
          {roles?.map((role) => (
            <li key={role.role_id} className="border-line rounded border p-3">
              <div className="flex items-center gap-2">
                <span className="font-medium">{roleName(role)}</span>
                {role.built_in && (
                  <span className="text-accent flex items-center gap-1 text-2xs" title="Immutable">
                    <ShieldCheck className="size-3" />
                    built-in
                  </span>
                )}
                <span className="text-mute text-2xs capitalize">
                  {role.revision?.body.scope_kind ?? ""}
                </span>
              </div>
              {role.revision?.body.description && (
                <p className="text-dim mt-1 text-sm">{role.revision.body.description}</p>
              )}
              <ul className="mt-2 flex flex-wrap gap-1">
                {(role.revision?.body.capabilities ?? []).map((c) => (
                  <li
                    key={c}
                    className="border-line-strong text-dim rounded-full border px-2 py-px font-mono text-2xs"
                  >
                    {c}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </Section>

      <Section
        title="Access grants"
        hint="Capabilities granted to an actor beyond their base membership role, at the Space or a single project."
      >
        {!readOnly && (
          <div className="border-line mb-4 flex flex-wrap items-end gap-2 rounded border p-3">
            <Combobox
              label="Member"
              value={
                grantActor
                  ? { id: grantActor, label: nameOf(grantActor) }
                  : null
              }
              placeholder="Member…"
              options={(members ?? []).map((m) => ({
                id: m.key,
                label: memberName(m.key, m),
                hint: m.role,
              }))}
              onPick={setGrantActor}
            />
            <Combobox
              label="Role"
              value={
                grantRole
                  ? {
                      id: grantRole,
                      label: roleName(
                        grantableRoles.find((r) => r.role_id === grantRole) ?? {
                          role_id: grantRole,
                          built_in: false,
                          revision: null,
                          conflict_heads: [],
                        },
                      ),
                    }
                  : null
              }
              placeholder="Role…"
              options={grantableRoles.map((r) => ({
                id: r.role_id,
                label: roleName(r),
                hint: r.revision?.body.scope_kind ?? "",
              }))}
              onPick={setGrantRole}
            />
            <Combobox
              label="Scope"
              value={{
                id: grantProject ?? "",
                label: grantProject ? projectLabel(grantProject) : "Whole space",
              }}
              placeholder="Whole space"
              options={[
                { id: "", label: "Whole space" },
                ...projects.map((p) => ({
                  id: p.key,
                  label: p.name,
                  swatch: catalogColor(p.color),
                  hint: p.key,
                })),
              ]}
              onPick={(id) => setGrantProject(id === "" ? null : id)}
            />
            <Button
              variant="primary"
              size="md"
              disabled={!grantActor || !grantRole || busy}
              loading={busy}
              onClick={() => void grant()}
            >
              <ShieldPlus className="size-3.5" />
              Grant
            </Button>
          </div>
        )}

        {!rows && <p className="text-mute text-sm">Loading…</p>}
        {rows && byActor.length === 0 && (
          <p className="text-mute text-sm">
            No scoped grants. Members act with their base role until granted extra capabilities here.
          </p>
        )}
        <ul className="flex flex-col gap-3">
          {byActor.map(([actor, items]) => (
            <li key={actor} className="border-line rounded border p-3">
              <div className="mb-2 font-medium">{nameOf(actor)}</div>
              <ul className="flex flex-col gap-1">
                {items.map((row) => (
                  <li key={row.grant_id} className="flex items-center gap-2 text-sm">
                    <code className="font-mono text-xs">{row.capability}</code>
                    <span className="text-mute text-2xs">
                      {row.resource.length === 0 ? "space" : projectLabel(row.resource[0] ?? "")}
                    </span>
                    {!readOnly && (
                      <IconButton
                        label={`Revoke ${row.capability}`}
                        variant="danger"
                        disabled={busy}
                        className="ml-auto"
                        onClick={() => revoke(row)}
                      >
                        <X className="size-3.5" />
                      </IconButton>
                    )}
                  </li>
                ))}
              </ul>
            </li>
          ))}
        </ul>
      </Section>
    </>
  );
}
