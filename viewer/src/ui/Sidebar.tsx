import { useState } from "react";
import {
  Activity,
  Bookmark,
  Bot,
  ChevronDown,
  ChevronRight,
  CircleDot,
  Clock3,
  Cog,
  Folder,
  Inbox,
  LayoutGrid,
  FolderKanban,
  Plus,
  Star,
  StarOff,
  UserRound,
} from "lucide-react";

import type { View } from "../core/registry";
import type { SavedView } from "../core/savedViews";
import type { ProjectDto, SpaceRow } from "../types";
import { catalogColor } from "./colors";
import { Badge, cn, IconButton, navigationItem } from "./primitives";

/** Linear-shaped navigation over lait's local identities and projects. */
export function Sidebar({
  spaces,
  current,
  projects,
  currentProject,
  view,
  unread,
  memberCount,
  membership,
  currentName,
  favoriteProjects,
  recentIssues,
  savedViews,
  onPickSpace,
  onPickProject,
  onGo,
  onMyIssues,
  onOpenRecent,
  onApplySavedView,
  onToggleFavorite,
  onCreateProject,
}: {
  spaces: SpaceRow[];
  current: string | null;
  projects: ProjectDto[];
  currentProject: string | null;
  view: View;
  unread: number;
  memberCount?: number | undefined;
  membership?: string | null | undefined;
  /** The current space's authoritative catalog name (from `status`), which
   *  refreshes on every doorbell — so a rename shows without reloading, unlike the
   *  spaces-list `name` that only refetches on a catalog-dirty doorbell. */
  currentName?: string | undefined;
  favoriteProjects: readonly string[];
  recentIssues: readonly string[];
  savedViews: readonly SavedView[];
  onPickSpace: (id: string) => void;
  onPickProject: (key: string) => void;
  onGo: (view: View) => void;
  onMyIssues: () => void;
  onOpenRecent: (reff: string) => void;
  onApplySavedView: (view: SavedView) => void;
  onToggleFavorite: (key: string) => void;
  onCreateProject: () => void;
}) {
  const space = spaces.find((s) => s.id === current) ?? null;
  const agent = space?.identity.kind === "agent" ? space.identity.name : null;
  // Linear's density model: favorites are the always-visible projects; the full
  // list folds behind its section header. Default-collapsed once you have
  // favorites (curation replaces enumeration), open until then so a fresh space
  // never hides its projects. The choice sticks per device.
  const [projectsOpen, setProjectsOpen] = useState<boolean>(() => {
    const stored = localStorage.getItem("lait.sidebar.allProjects");
    return stored !== null ? stored === "1" : favoriteProjects.length === 0;
  });
  const toggleProjects = () => {
    setProjectsOpen((open) => {
      localStorage.setItem("lait.sidebar.allProjects", open ? "0" : "1");
      return !open;
    });
  };

  return (
    <nav aria-label="Workspace" className="flex h-full min-h-0 flex-col p-2">
      <SpaceSwitcher
        spaces={spaces}
        current={current}
        currentName={currentName}
        memberCount={memberCount}
        membership={membership}
        onPick={onPickSpace}
        onOpenSettings={() => onGo("settings")}
      />

      {agent && (
        <div className="border-line bg-bg text-dim mx-1 mt-2 flex items-start gap-2 rounded border p-2 text-xs">
          <Bot className="mt-0.5 size-3.5 shrink-0" />
          <span>
            Observing as <strong className="text-fg">{agent}</strong>. Writes are disabled.
          </span>
        </div>
      )}

      <div className="mt-3 flex flex-col gap-px">
        <NavItem icon={<Inbox />} label="Inbox" active={view === "inbox"} badge={unread} onClick={() => onGo("inbox")} />
        <NavItem icon={<CircleDot />} label="Issues" active={view === "list"} onClick={() => onGo("list")} />
        <NavItem icon={<LayoutGrid />} label="Board" active={view === "board"} onClick={() => onGo("board")} />
        <NavItem icon={<FolderKanban />} label="Projects" active={view === "projects"} onClick={() => onGo("projects")} />
        <NavItem icon={<Activity />} label="Activity" active={view === "activity"} onClick={() => onGo("activity")} />
      </div>

      <Section title="Your workspace" />
      <div className="flex flex-col gap-px">
        <NavItem icon={<UserRound />} label="My issues" onClick={onMyIssues} />
        {favoriteProjects.length > 0 && <MiniSection title="Favorites" />}
        {favoriteProjects.map((key) => {
          const favorite = projects.find((candidate) => candidate.key === key);
          return favorite ? (
            <ProjectRow
              key={key}
              project={favorite}
              active={favorite.key === currentProject}
              favorited
              onPick={onPickProject}
              onToggleFavorite={onToggleFavorite}
            />
          ) : null;
        })}
        {savedViews.length > 0 && <MiniSection title="Saved views" />}
        {savedViews.map((saved) => (
          <NavItem key={saved.id} icon={<Bookmark />} label={saved.name} onClick={() => onApplySavedView(saved)} compact />
        ))}
        {recentIssues.length > 0 && <MiniSection title="Recent" />}
        {recentIssues.slice(0, 3).map((reff) => (
          <NavItem key={reff} icon={<Clock3 />} label={reff} onClick={() => onOpenRecent(reff)} compact />
        ))}
      </div>

      <div className="mt-3 mb-1 flex h-6 items-center justify-between px-2">
        <button
          className="text-mute hover:text-fg flex min-w-0 items-center gap-1 text-xs font-semibold uppercase"
          onClick={toggleProjects}
          aria-expanded={projectsOpen}
        >
          <ChevronRight className={cn("size-3 shrink-0 transition-transform", projectsOpen && "rotate-90")} />
          <span className="truncate">All projects</span>
          <span className="font-normal tabular-nums">{projects.length}</span>
        </button>
        {!agent && (
          <IconButton label="New project" onClick={onCreateProject}>
            <Plus className="size-3" />
          </IconButton>
        )}
      </div>
      <div className="min-h-0 flex-1 overflow-y-auto">
        {projectsOpen ? (
          projects.length === 0 ? (
            <p className="text-mute px-2 py-1 text-sm">No projects yet.</p>
          ) : (
            projects.map((project) => (
              <ProjectRow
                key={project.id}
                project={project}
                active={project.key === currentProject}
                favorited={favoriteProjects.includes(project.key)}
                onPick={onPickProject}
                onToggleFavorite={onToggleFavorite}
              />
            ))
          )
        ) : (
          // Collapsed still anchors you: the project you're in stays visible
          // unless it's already pinned under Favorites.
          (() => {
            const active = projects.find(
              (project) => project.key === currentProject && !favoriteProjects.includes(project.key),
            );
            return active ? (
              <ProjectRow
                project={active}
                active
                favorited={false}
                onPick={onPickProject}
                onToggleFavorite={onToggleFavorite}
              />
            ) : null;
          })()
        )}
      </div>

    </nav>
  );
}

function SpaceSwitcher({
  spaces,
  current,
  currentName,
  memberCount,
  membership,
  onPick,
  onOpenSettings,
}: {
  spaces: SpaceRow[];
  current: string | null;
  currentName?: string | undefined;
  memberCount?: number | undefined;
  membership?: string | null | undefined;
  onPick: (id: string) => void;
  onOpenSettings: () => void;
}) {
  const selected = spaces.find((s) => s.id === current) ?? null;
  return (
    <details className="group relative">
      <summary className="hover:bg-hover flex min-h-10 list-none items-center gap-2 rounded px-2 py-1 [&::-webkit-details-marker]:hidden">
        <span className="bg-active flex size-7 shrink-0 items-center justify-center rounded-md">
          {selected?.identity.kind === "agent" ? <Bot className="text-mute size-4" /> : <Folder className="text-mute size-4" />}
        </span>
        <span className="min-w-0 flex-1">
          <strong className="block truncate text-sm">{(currentName?.trim() || selected?.name) || selected?.space || "Choose a space"}</strong>
          {selected && (
            <span className="text-mute block truncate text-[10px] font-normal">
              {selected.identity.kind === "agent"
                ? `Agent-owned · read only`
                : `${membership === "admin" ? "Admin" : membership === "pending" ? "Joining" : "Member"}${memberCount !== undefined ? ` · ${memberCount} ${memberCount === 1 ? "person" : "people"}` : ""}`}
            </span>
          )}
        </span>
        {selected && <StatusDot status={selected.status} />}
        <ChevronDown className="text-mute size-3 transition-transform group-open:rotate-180" />
      </summary>
      <div className="border-line-strong bg-raised shadow-overlay absolute inset-x-0 top-9 z-40 max-h-72 overflow-y-auto rounded-lg border p-1">
        {spaces.length === 0 ? (
          <p className="text-mute px-2 py-3 text-center text-sm">No local spaces</p>
        ) : (
          spaces.map((space) => (
            <button
              key={`${space.id}-${space.identity.kind === "agent" ? space.identity.name : "own"}`}
              onClick={(event) => {
                onPick(space.id);
                event.currentTarget.closest("details")?.removeAttribute("open");
              }}
              className={cn(
                "flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm",
                space.id === current ? "bg-active" : "hover:bg-hover",
              )}
            >
              {space.identity.kind === "agent" ? <Bot className="text-mute size-3.5" /> : <Folder className="text-mute size-3.5" />}
              <span className="min-w-0 flex-1">
                <span className="block truncate">{space.name || space.space}</span>
                <span className="text-mute block truncate text-xs">
                  {space.identity.kind === "agent" ? `Agent · ${space.identity.name}` : "Your local actor"}
                </span>
              </span>
              <StatusDot status={space.status} />
            </button>
          ))
        )}
        {selected && (
          <>
            <div className="bg-line my-1 h-px" />
            <button
              onClick={(event) => {
                onOpenSettings();
                event.currentTarget.closest("details")?.removeAttribute("open");
              }}
              className="text-dim hover:bg-hover hover:text-fg flex w-full items-center gap-2 rounded px-2 py-1.5 text-left text-sm"
            >
              <Cog className="text-mute size-3.5" />
              Workspace settings
            </button>
          </>
        )}
      </div>
    </details>
  );
}

/** One project in the nav — color dot, name, key, and a hover star to (un)pin.
 *  Shared by Favorites and the collapsible all-projects list so the two render
 *  identically and a pin just moves the row up. */
function ProjectRow({
  project,
  active,
  favorited,
  onPick,
  onToggleFavorite,
}: {
  project: ProjectDto;
  active: boolean;
  favorited: boolean;
  onPick: (key: string) => void;
  onToggleFavorite: (key: string) => void;
}) {
  return (
    <div className="group/project relative mb-0.5">
      <button
        onClick={() => onPick(project.key)}
        className={cn(
          navigationItem({ selected: active }),
        )}
      >
        <span className="size-2 shrink-0 rounded-sm" style={{ background: catalogColor(project.color) }} />
        <span className="min-w-0 flex-1 truncate">{project.name}</span>
        <span className="text-mute font-mono text-2xs">{project.key}</span>
      </button>
      <IconButton
        label={favorited ? `Remove ${project.name} from favorites` : `Add ${project.name} to favorites`}
        className={cn(
          "absolute top-0.5 right-0.5 size-6 opacity-0 group-hover/project:opacity-100 focus-visible:opacity-100",
          active ? "bg-active hover:bg-hover" : "bg-hover",
        )}
        onClick={() => onToggleFavorite(project.key)}
      >
        {favorited ? <StarOff className="size-3" /> : <Star className="size-3" />}
      </IconButton>
    </div>
  );
}

function Section({ title, action }: { title: string; action?: React.ReactNode }) {
  return (
    <div className="mt-4 mb-1 flex h-5 items-center px-2">
      <h2 className="text-mute text-2xs font-semibold tracking-[0.08em] uppercase">{title}</h2>
      {action && <span className="ml-auto">{action}</span>}
    </div>
  );
}

function MiniSection({ title }: { title: string }) {
  return <p className="text-mute mt-1 px-2 text-[9px] font-semibold tracking-[0.08em] uppercase">{title}</p>;
}

function NavItem({ icon, label, active, badge, compact, onClick }: { icon: React.ReactElement; label: string; active?: boolean; badge?: number; compact?: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={cn(
        navigationItem({
          selected: active,
          density: compact ? "compact" : "normal",
        }),
      )}
    >
      <span className="text-mute [&>svg]:size-3.5">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {!!badge && <Badge tone="accent" className="justify-center tabular-nums">{badge}</Badge>}
    </button>
  );
}

function StatusDot({ status }: { status: SpaceRow["status"] }) {
  const cls = { up: "bg-ok", idle: "bg-mute", missing: "bg-danger" }[status];
  const label = { up: "Local daemon running", idle: "Local daemon idle", missing: "Local replica unavailable" }[status];
  return <span className={cn("size-1.5 shrink-0 rounded-full", cls)} title={label} role="img" aria-label={label} />;
}
