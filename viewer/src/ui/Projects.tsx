import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, ArrowRight, FolderKanban } from "lucide-react";

import { rpc } from "../api";
import type { BoardView, MemberDto, ProjectDto } from "../types";
import { ApplicationState, LoadingState } from "./AppState";
import { catalogColor } from "./colors";
import { ProjectOverview } from "./ProjectOverview";

type ProjectHealth = {
  project: ProjectDto;
  total: number;
  backlog: number;
  active: number;
  done: number;
  unavailable: boolean;
};

/** A durable portfolio destination, not another display toggle. Its health is
 * derived from the same board projections used by list/board, so there is no
 * second project-status model to drift. */
export function Projects({
  spaceId,
  projects,
  members,
  revision,
  readOnly,
  spaceDescription,
  onOpen,
  onError,
}: {
  spaceId: string;
  projects: ProjectDto[];
  members: MemberDto[];
  revision: number;
  readOnly: boolean;
  spaceDescription?: string;
  onOpen: (key: string) => void;
  onError: (message: string) => void;
}) {
  const [boards, setBoards] = useState<Map<string, BoardView> | null>(null);
  // `?overview=<key>` deep-links a project's overview (and lets a headless driver
  // reach it by `open`-ing the URL — no card click needed).
  const [selected, setSelectedState] = useState<string | null>(
    () => new URLSearchParams(window.location.search).get("overview"),
  );
  const setSelected = (key: string | null) => {
    setSelectedState(key);
    const url = new URL(window.location.href);
    if (key) url.searchParams.set("overview", key);
    else url.searchParams.delete("overview");
    window.history.replaceState(null, "", `${url.pathname}${url.search}`);
  };
  // Reliable driver hook: `lait:nav { overview }` opens a project's overview.
  useEffect(() => {
    const onNav = (event: Event) => {
      const detail = (event as CustomEvent).detail ?? {};
      if ("overview" in detail) setSelected(detail.overview ?? null);
    };
    window.addEventListener("lait:nav", onNav as EventListener);
    return () => window.removeEventListener("lait:nav", onNav as EventListener);
  }, []);

  useEffect(() => {
    let alive = true;
    setBoards(null);
    void Promise.allSettled(projects.map((project) => rpc(spaceId, { cmd: "board", project: project.key })))
      .then((results) => {
        if (!alive) return;
        const next = new Map<string, BoardView>();
        for (const result of results) {
          if (result.status === "fulfilled" && result.value.kind === "board") {
            next.set(result.value.project.id, result.value);
          }
        }
        setBoards(next);
      });
    return () => {
      alive = false;
    };
  }, [spaceId, projects, revision]);

  const health = useMemo<ProjectHealth[]>(() => {
    if (!boards) return [];
    return projects.map((project) => {
      const board = boards.get(project.id);
      const counts = { backlog: 0, active: 0, done: 0 };
      for (const column of board?.columns ?? []) {
        counts[column.state.category] += column.rows.filter((row) => !row.tombstone).length;
      }
      return {
        project,
        ...counts,
        total: counts.backlog + counts.active + counts.done,
        unavailable: !board,
      };
    });
  }, [boards, projects]);

  if (!boards) return <LoadingState title="Loading projects" body="Reading local project projections." />;

  const openProject = selected ? health.find((h) => h.project.key === selected) : null;
  if (openProject) {
    return (
      <ProjectOverview
        spaceId={spaceId}
        project={openProject.project}
        members={members}
        counts={{
          backlog: openProject.backlog,
          active: openProject.active,
          done: openProject.done,
          total: openProject.total,
        }}
        readOnly={readOnly}
        onOpenIssues={() => onOpen(openProject.project.key)}
        onBack={() => setSelected(null)}
        onError={onError}
      />
    );
  }

  if (projects.length === 0) {
    return (
      <ApplicationState
        kind="empty"
        icon={<FolderKanban className="size-5" />}
        title="No projects yet"
        body="Projects give issues a workflow, identity, and stable place in the space."
      />
    );
  }

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-4 sm:p-6">
      <div className="mx-auto max-w-5xl">
        <div className="mb-5">
          <h2 className="text-lg font-semibold">Projects</h2>
          {spaceDescription ? (
            <p className="text-dim mt-1 max-w-2xl text-sm whitespace-pre-line">{spaceDescription}</p>
          ) : (
            <p className="text-dim mt-1 text-sm">
              {projects.length} {projects.length === 1 ? "project" : "projects"} in this local space
            </p>
          )}
        </div>
        <ul className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          {[...health]
            .sort((a, b) => Number(a.project.archived ?? false) - Number(b.project.archived ?? false))
            .map(({ project, total, backlog, active, done, unavailable }) => (
            <li key={project.id}>
              <button
                onClick={() => setSelected(project.key)}
                className={`border-line bg-raised hover:border-line-strong hover:bg-hover group flex min-h-32 w-full flex-col rounded-lg border p-4 text-left transition-colors ${
                  project.archived ? "opacity-60" : ""
                }`}
              >
                <span className="flex w-full items-center gap-2">
                  <span className="size-3 rounded-sm" style={{ background: catalogColor(project.color) }} />
                  <strong className="min-w-0 flex-1 truncate">{project.name}</strong>
                  {project.archived && (
                    <span className="border-line text-mute rounded-full border px-1.5 text-2xs">
                      Archived
                    </span>
                  )}
                  <span className="text-mute font-mono text-xs">{project.key}</span>
                  <ArrowRight className="text-mute size-3.5 transition-transform group-hover:translate-x-0.5" />
                </span>
                {unavailable ? (
                  <span className="text-warn mt-auto flex items-center gap-1.5 text-xs">
                    <AlertTriangle className="size-3.5" /> Projection unavailable
                  </span>
                ) : (
                  <>
                    <span className="text-dim mt-3 text-sm">{total} {total === 1 ? "issue" : "issues"}</span>
                    <span className="mt-auto flex w-full gap-1" aria-label={`${backlog} backlog, ${active} active, ${done} done`}>
                      {total === 0 ? (
                        <span className="bg-line h-1.5 w-full rounded-full" />
                      ) : (
                        <>
                          {backlog > 0 && <span className="bg-mute h-1.5 rounded-full" style={{ flex: backlog }} />}
                          {active > 0 && <span className="bg-accent h-1.5 rounded-full" style={{ flex: active }} />}
                          {done > 0 && <span className="bg-ok h-1.5 rounded-full" style={{ flex: done }} />}
                        </>
                      )}
                    </span>
                    <span className="text-mute mt-2 flex gap-3 text-xs">
                      <span>{backlog} backlog</span><span>{active} active</span><span>{done} done</span>
                    </span>
                  </>
                )}
              </button>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
