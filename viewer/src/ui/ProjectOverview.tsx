import { useEffect, useState } from "react";
import { ArrowLeft, ArrowRight } from "lucide-react";

import { rpc } from "../api";
import type { MemberDto, ProjectDto } from "../types";
import { Avatar, memberName } from "./Avatar";
import { catalogColor } from "./colors";
import { ColorPicker } from "./ColorPicker";
import { DatePicker } from "./DatePicker";
import { Markdown } from "./Markdown";
import { Combobox } from "./Picker";
import { PropertyRow, SurfaceHeader } from "./layout";
import { Button, IconButton, PopoverContent } from "./primitives";
import * as Popover from "@radix-ui/react-popover";

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
  const edit = async (patch: Record<string, string | null>) => {
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
        <Button className="ml-auto" onClick={onOpenIssues}>
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
          </div>

          {/* Properties rail */}
          <dl className="flex flex-col gap-1 text-sm md:border-l md:border-line md:pl-6">
            <PropertyRow label="Lead">
              <Combobox
                variant="bare"
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
                variant="bare"
                value={toInput(project.start_date)}
                disabled={readOnly}
                placeholder="—"
                ariaLabel="Start date"
                onChange={(next) => void edit({ start: next ?? "none" })}
              />
            </PropertyRow>
            <PropertyRow label="Target">
              <DatePicker
                variant="bare"
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
    return (
      <div
        className={`min-h-16 ${readOnly ? "" : "hover:bg-hover -mx-2 cursor-text rounded px-2 py-1"}`}
        onClick={(e) => {
          if ((e.target as HTMLElement).closest("a")) return;
          if (!readOnly) setEditing(true);
        }}
      >
        {value ? (
          <Markdown text={value} />
        ) : (
          <span className="text-mute">
            {readOnly ? "No description" : "Add a project overview…"}
          </span>
        )}
      </div>
    );
  }
  return (
    <textarea
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
      className="border-line focus:border-line-strong placeholder:text-mute w-full resize-y rounded border bg-transparent p-2 outline-none"
      aria-label="Project description"
    />
  );
}
