import { useEffect, useMemo, useState } from "react";
import { Hash, Palette, SlidersHorizontal, Tag, Trash2 } from "lucide-react";

import { rpc } from "../api";
import type { LabelDto, ProjectDto } from "../types";
import { catalogColor } from "./colors";
import { ColorPicker } from "./ColorPicker";
import * as ask from "./dialogs";
import { StatusIcon } from "./icons";
import { SurfaceHeader } from "./layout";
import { Combobox } from "./Picker";
import { Button, IconButton } from "./primitives";

type Tab = "general" | "labels" | "workflow";

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
  labels,
  projects,
  readOnly,
  revision,
  onError,
}: {
  spaceId: string;
  spaceName: string;
  labels: LabelDto[];
  projects: ProjectDto[];
  readOnly: boolean;
  /** Bumped by the doorbell; re-reads the panels that fetch. */
  revision: number;
  onError: (message: string) => void;
}) {
  const [tab, setTab] = useState<Tab>("general");
  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: "general", label: "General", icon: <SlidersHorizontal className="size-3.5" /> },
    { id: "labels", label: "Labels", icon: <Tag className="size-3.5" /> },
    { id: "workflow", label: "Workflow", icon: <Palette className="size-3.5" /> },
  ];

  return (
    <div className="flex h-full min-h-0 flex-col">
      <SurfaceHeader className="px-3">
        <h1 className="text-sm font-semibold">Settings</h1>
      </SurfaceHeader>
      <div className="flex min-h-0 flex-1">
        <nav className="border-line flex w-48 shrink-0 flex-col gap-0.5 border-r p-2">
          {tabs.map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`flex h-8 items-center gap-2 rounded px-2 text-left text-sm ${
                tab === t.id ? "bg-active text-fg" : "text-dim hover:bg-hover hover:text-fg"
              }`}
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
                readOnly={readOnly}
                onError={onError}
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

/** General — the space's mutable display label, and its immutable identity. */
function GeneralPanel({
  spaceId,
  spaceName,
  readOnly,
  onError,
}: {
  spaceId: string;
  spaceName: string;
  readOnly: boolean;
  onError: (message: string) => void;
}) {
  const [name, setName] = useState(spaceName);
  const [saving, setSaving] = useState(false);
  useEffect(() => setName(spaceName), [spaceName]);
  const dirty = name.trim() !== spaceName && name.trim() !== "";

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

  return (
    <>
      <Section title="Space name" hint="A mutable display label. The space's identity (below) never changes.">
        <div className="flex items-center gap-2">
          <input
            value={name}
            disabled={readOnly}
            onChange={(e) => setName(e.target.value)}
            className="border-line focus:border-line-strong w-full max-w-sm rounded border bg-transparent px-2 py-1.5 text-sm outline-none disabled:opacity-50"
            aria-label="Space name"
          />
          <Button variant="primary" size="md" disabled={!dirty || readOnly} loading={saving} onClick={() => void save()}>
            Update
          </Button>
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
