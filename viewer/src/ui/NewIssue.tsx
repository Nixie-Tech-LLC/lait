import { useEffect, useState } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { LayoutTemplate, Trash2, X } from "lucide-react";

import { rpc } from "../api";
import { clearDraft, loadDraft, saveDraft } from "../core/drafts";
import { loadTemplates, removeTemplate, saveTemplate, type IssueTemplate } from "../core/templates";
import * as ask from "./dialogs";
import { MenuContent, MenuItem } from "./layout";
import {
  PRIORITY_ORDER,
  type LabelDto,
  type MemberDto,
  type Priority,
  type ProjectDto,
  type WorkflowState,
} from "../types";
import { Avatar, AvatarStack } from "./Avatar";
import { catalogColor } from "./colors";
import { PriorityIcon, StatusIcon } from "./icons";
import { Combobox } from "./Picker";
import { DatePicker } from "./DatePicker";
import { NewLabelDialog } from "./NewLabel";
import { Button, IconButton, Kbd, Switch } from "./primitives";
import { short } from "./time";

/**
 * The composer.
 *
 * A tracker's most-used surface, so it is a real dialog rather than the labelled
 * text box it replaced: title and description read as *the document*, borderless
 * and unlabelled — the placeholder is the label — and the fields you might set sit
 * underneath as pills you can ignore. Filing an issue should cost a title and
 * Enter; everything else is optional and stays out of the way until wanted.
 *
 * One wrinkle worth naming: `issue_new` takes title/body/priority/labels/assignees
 * but **not status** — a new issue lands in `DEFAULT_STATUS` by construction. So
 * when you open the composer from a column's `+`, honouring that column costs a
 * second request (`issue_edit`), and therefore a second commit and a second
 * activity row (S§7.1). That is an honest record of what happened — filed, then
 * moved — and it only happens when you asked for a non-default column.
 */
export function NewIssue({
  spaceId,
  canonicalSpaceId,
  projectKey,
  projects,
  states,
  labels,
  members,
  defaultStatus,
  onClose,
  onError,
  onCreated,
}: {
  spaceId: string;
  canonicalSpaceId: string;
  projectKey: string;
  projects: ProjectDto[];
  states: WorkflowState[];
  labels: LabelDto[];
  members: MemberDto[];
  /** The column you opened this from, if any. */
  defaultStatus?: string | undefined;
  onClose: () => void;
  onError: (m: string) => void;
  onCreated: (message: string) => void;
}) {
  const draftSubject = `new:${projectKey}`;
  const [title, setTitle] = useState(() => loadDraft(canonicalSpaceId, draftSubject, "new-title"));
  const [body, setBody] = useState(() => loadDraft(canonicalSpaceId, draftSubject, "new-body"));
  const [priority, setPriority] = useState<Priority>("none");
  const [project, setProject] = useState(projectKey);
  const [due, setDue] = useState("");
  const [status, setStatus] = useState(defaultStatus ?? states[0]?.id ?? "backlog");
  /** Label **names** — `issue_new` resolves names, not ids, and creates on first use. */
  const [picked, setPicked] = useState<string[]>([]);
  /** Assignee **keys** — `index::resolve_device` takes `me` or a full 64-hex key. */
  const [assignees, setAssignees] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [again, setAgain] = useState(false);
  const [newLabel, setNewLabel] = useState<string | null>(null);
  const [templates, setTemplates] = useState(() => loadTemplates(canonicalSpaceId));
  const [templateMenu, setTemplateMenu] = useState(false);
  const [failure, setFailure] = useState("");
  const [recovered] = useState(() =>
    Boolean(
      loadDraft(canonicalSpaceId, draftSubject, "new-title") ||
      loadDraft(canonicalSpaceId, draftSubject, "new-body"),
    ),
  );

  const state = states.find((s) => s.id === status) ?? null;
  const landsIn = states[0]?.id ?? "backlog";

  const applyTemplate = (t: IssueTemplate) => {
    if (t.title) setTitle(t.title);
    if (t.body) setBody(t.body);
    setPriority(t.priority);
    if (t.status) setStatus(t.status);
    setPicked(t.labels);
    setAssignees(t.assignees);
    setTemplateMenu(false);
  };
  const saveAsTemplate = async () => {
    setTemplateMenu(false);
    const name = await ask.prompt({
      title: "Save as template",
      body: "Stored on this device, for this space. Applies the current fields to a new issue.",
      label: "Template name",
      defaultValue: title.trim(),
    });
    if (!name?.trim()) return;
    const id = `${Date.now().toString(36)}-${name.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`;
    setTemplates(
      saveTemplate(canonicalSpaceId, {
        id,
        name: name.trim(),
        title: title.trim(),
        body: body.trim(),
        priority,
        status,
        labels: picked,
        assignees,
      }),
    );
    onCreated(`Saved template “${name.trim()}”`);
  };

  useEffect(
    () => saveDraft(canonicalSpaceId, draftSubject, "new-title", title),
    [canonicalSpaceId, draftSubject, title],
  );
  useEffect(
    () => saveDraft(canonicalSpaceId, draftSubject, "new-body", body),
    [canonicalSpaceId, draftSubject, body],
  );

  const create = async () => {
    const t = title.trim();
    if (!t || busy) return;
    setBusy(true);
    setFailure("");
    let created: string | null = null;
    try {
      const r = await rpc(spaceId, {
        cmd: "issue_new",
        title: t,
        ...(body.trim() ? { body: body.trim() } : {}),
        ...(priority !== "none" ? { priority } : {}),
        ...(picked.length ? { labels: picked } : {}),
        ...(assignees.length ? { assignees } : {}),
        ...(project !== projectKey ? { project } : {}),
        ...(due ? { due } : {}),
      });
      if (r.kind === "ref") created = r.reff;
      // `issue_new` can't set status, so honour a non-default column with a
      // follow-up rather than pretending the field exists.
      if (r.kind === "ref" && status !== landsIn) {
        await rpc(spaceId, { cmd: "issue_edit", reff: r.reff, status });
      }
      clearDraft(canonicalSpaceId, draftSubject, "new-title");
      clearDraft(canonicalSpaceId, draftSubject, "new-body");
      if (again) {
        // "Create more": keep the scaffolding, clear the prose. Filing five
        // related issues shouldn't mean re-picking the same labels five times.
        setTitle("");
        setBody("");
        onCreated(`Created ${created ?? "issue"} · ready for another`);
      } else {
        onCreated(`Created ${created ?? "issue"}`);
        onClose();
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (created) {
        clearDraft(canonicalSpaceId, draftSubject, "new-title");
        clearDraft(canonicalSpaceId, draftSubject, "new-body");
        onError(`Created ${created}, but an optional field was not applied: ${message}`);
        onClose();
      } else {
        setFailure(message);
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay className="ui-overlay fixed inset-0 z-50 bg-black/45 backdrop-blur-[2px]" />
        <Dialog.Content
          className="ui-surface border-line-strong bg-raised shadow-overlay fixed top-[12vh] left-1/2 z-50 flex w-[min(640px,94vw)] -translate-x-1/2 flex-col rounded-lg border"
          // The title lives in the body as the composer's own input, so the
          // accessible name is given here rather than rendered twice.
          aria-describedby={undefined}
        >
          <header className="flex items-center gap-2 px-4 pt-3">
            <span className="border-line text-dim rounded border px-1.5 py-px font-mono text-2xs">
              {projectKey}
            </span>
            <span className="text-mute">›</span>
            <Dialog.Title className="text-dim text-sm">New issue</Dialog.Title>
            <DropdownMenu.Root open={templateMenu} onOpenChange={setTemplateMenu}>
              <DropdownMenu.Trigger asChild>
                <IconButton label="Templates" className="ml-auto">
                  <LayoutTemplate className="size-4" />
                </IconButton>
              </DropdownMenu.Trigger>
              <DropdownMenu.Portal>
                <MenuContent align="end" className="w-56">
                  <DropdownMenu.Label className="text-mute px-2 py-1 text-2xs font-semibold uppercase">
                    Templates
                  </DropdownMenu.Label>
                  {templates.length === 0 && (
                    <p className="text-mute px-2 py-1 text-xs">None yet — fill the fields, then save.</p>
                  )}
                  {templates.map((t) => (
                    <div key={t.id} className="hover:bg-hover flex items-center rounded">
                      <button
                        onClick={() => applyTemplate(t)}
                        className="min-w-0 flex-1 truncate px-2 py-1.5 text-left text-sm"
                      >
                        {t.name}
                      </button>
                      <IconButton
                        label={`Delete template ${t.name}`}
                        className="mr-0.5"
                        onClick={() => setTemplates(removeTemplate(canonicalSpaceId, t.id))}
                      >
                        <Trash2 className="size-3.5" />
                      </IconButton>
                    </div>
                  ))}
                  <DropdownMenu.Separator className="bg-line my-1 h-px" />
                  <MenuItem onSelect={() => void saveAsTemplate()} disabled={!title.trim()}>
                    <LayoutTemplate className="size-3.5" />
                    Save current as template…
                  </MenuItem>
                </MenuContent>
              </DropdownMenu.Portal>
            </DropdownMenu.Root>
            <Dialog.Close asChild>
              <IconButton label="Close" chord="Esc">
                <X className="size-4" />
              </IconButton>
            </Dialog.Close>
          </header>

          <div className="flex flex-col gap-1 px-4 pt-2">
            {/* Borderless: this reads as the document, not a form. */}
            <input
              autoFocus
              value={title}
              placeholder="Issue title"
              onChange={(e) => setTitle(e.target.value)}
              onKeyDown={(e) => {
                e.stopPropagation();
                if (e.key === "Enter") {
                  e.preventDefault();
                  void create();
                }
              }}
              aria-label="Issue title"
              className="placeholder:text-mute bg-transparent text-lg font-semibold outline-none"
            />
            <textarea
              value={body}
              rows={3}
              placeholder="Add description…"
              onChange={(e) => setBody(e.target.value)}
              onKeyDown={(e) => {
                e.stopPropagation();
                // Enter is a newline here; the chord submits.
                if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
                  e.preventDefault();
                  void create();
                }
              }}
              aria-label="Description"
              className="placeholder:text-mute resize-none bg-transparent outline-none"
            />
          </div>

          <div className="flex flex-wrap items-center gap-2 px-4 py-3">
            <Combobox
              label="Project"
              value={{
                id: project,
                label: projects.find((candidate) => candidate.key === project)?.name ?? project,
              }}
              options={projects.map((candidate) => ({
                id: candidate.key,
                label: candidate.name,
                hint: candidate.key,
                swatch: catalogColor(candidate.color),
              }))}
              onPick={setProject}
            />
            <Combobox
              label="Status"
              value={
                state
                  ? {
                      id: state.id,
                      label: state.name,
                      icon: <StatusIcon category={state.category} color={catalogColor(state.color)} />,
                    }
                  : null
              }
              options={states.map((s) => ({
                id: s.id,
                label: s.name,
                icon: <StatusIcon category={s.category} color={catalogColor(s.color)} />,
              }))}
              onPick={setStatus}
            />
            <Combobox
              label="Priority"
              value={{ id: priority, label: priority === "none" ? "Priority" : priority }}
              options={[...PRIORITY_ORDER].reverse().map((p) => ({
                id: p,
                label: p,
                icon: <PriorityIcon priority={p} />,
              }))}
              onPick={(id) => setPriority(id as Priority)}
              className="capitalize"
            />
            <Combobox
              multi
              label="Assignees"
              selected={assignees}
              emptyText="No members yet"
              face={
                assignees.length === 0 ? (
                  <span className="text-mute">Assignees</span>
                ) : (
                  <span className="flex items-center gap-1.5">
                    <AvatarStack
                      members={assignees.map((k) => {
                        const m = members.find((x) => x.key === k);
                        return { key: k, alias: m?.alias ?? "", me: m?.me ?? false };
                      })}
                    />
                    <span>{assignees.length === 1 ? nameFor(assignees[0]!, members) : assignees.length}</span>
                  </span>
                )
              }
              options={members.map((m) => ({
                id: m.key,
                label: nameFor(m.key, members),
                icon: <Avatar deviceKey={m.key} alias={m.alias} me={m.me} size="sm" />,
                hint: m.key.slice(0, 6),
                keywords: [m.key, m.alias],
              }))}
              onToggle={(key) =>
                setAssignees((a) => (a.includes(key) ? a.filter((x) => x !== key) : [...a, key]))
              }
            />
            <Combobox
              multi
              label="Labels"
              selected={picked}
              emptyText="No labels yet"
              face={
                picked.length === 0 ? (
                  <span className="text-mute">Labels</span>
                ) : (
                  <span>{picked.join(", ")}</span>
                )
              }
              // `id` is the **name**: `issue_new` resolves label names and creates
              // unknown ones on first use, so the name is the identity here.
              options={labels.map((l) => ({
                id: l.name,
                label: l.name,
                swatch: catalogColor(l.color),
                keywords: [l.id],
              }))}
              onToggle={(name) =>
                setPicked((p) => (p.includes(name) ? p.filter((x) => x !== name) : [...p, name]))
              }
              // A typed-but-unknown name gets a colour first: the colour step
              // registers it via `label_new`, then it joins the picked set and
              // `issue_new` attaches the now-coloured label by name.
              onCreate={(name) => setNewLabel(name)}
            />
            <DatePicker
              variant="chip"
              value={due || null}
              placeholder="Due date"
              onChange={(next) => setDue(next ?? "")}
            />
          </div>

          <footer className="border-line flex flex-wrap items-center gap-3 border-t px-4 py-3">
            <span className={failure ? "text-danger w-full text-xs" : "text-mute w-full text-xs"} role={failure ? "alert" : "status"}>
              {failure
                ? `Not created. Draft remains on this device: ${failure}`
                : recovered
                  ? "Recovered local draft · saved as you type"
                  : title || body
                    ? "Draft saved on this device"
                    : "Draft saves on this device"}
            </span>
            <div className="text-mute flex items-center gap-2 text-sm">
              <Switch id="create-more" checked={again} onCheckedChange={setAgain} />
              <label htmlFor="create-more">Create more</label>
            </div>
            {(title || body) && !busy && (
              <Button
                variant="ghost"
                onClick={() => {
                  clearDraft(canonicalSpaceId, draftSubject, "new-title");
                  clearDraft(canonicalSpaceId, draftSubject, "new-body");
                  setTitle("");
                  setBody("");
                  onClose();
                }}
              >
                Discard draft
              </Button>
            )}
            <span className="ml-auto flex items-center gap-2">
              <Kbd>↵</Kbd>
              <Button variant="primary" size="md" disabled={!title.trim()} loading={busy} onClick={() => void create()}>
                {busy ? "Creating…" : "Create issue"}
              </Button>
            </span>
          </footer>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
    {newLabel !== null && (
      <NewLabelDialog
        name={newLabel}
        onCancel={() => setNewLabel(null)}
        onCreate={(labelName, color) => {
          setNewLabel(null);
          // Register the label with its colour, then add it to the picked set —
          // `issue_new` attaches by name, so the label already carries its colour
          // by the time the issue is created.
          void rpc(spaceId, { cmd: "label_new", name: labelName, color })
            .then(() => setPicked((p) => (p.includes(labelName) ? p : [...p, labelName])))
            .catch((e) => onError(e instanceof Error ? e.message : String(e)));
        }}
      />
    )}
    </>
  );
}

/** `you` for yourself, the local petname if set, the key's head otherwise. */
function nameFor(key: string, members: MemberDto[]): string {
  const m = members.find((x) => x.key === key);
  if (m?.me) return "you";
  return m?.alias.trim() || short(key);
}
