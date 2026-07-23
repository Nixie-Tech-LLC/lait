import {
  Activity,
  Bookmark,
  Bot,
  ChevronDown,
  CircleDot,
  Clock3,
  Folder,
  Inbox,
  LayoutGrid,
  Plus,
  Settings2,
  Star,
  StarOff,
  UserRound,
  Users,
} from "lucide-react";

import type { View } from "../core/registry";
import type { SavedView } from "../core/savedViews";
import type { ProjectDto, SpaceRow } from "../types";
import { catalogColor } from "./colors";
import { cn, IconButton } from "./primitives";

/** Linear-shaped navigation over lait's local identities and projects. */
export function Sidebar({
  spaces,
  current,
  projects,
  currentProject,
  view,
  unread,
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
  onOpenGovernance,
}: {
  spaces: SpaceRow[];
  current: string | null;
  projects: ProjectDto[];
  currentProject: string | null;
  view: View;
  unread: number;
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
  onOpenGovernance: () => void;
}) {
  const space = spaces.find((s) => s.id === current) ?? null;
  const agent = space?.identity.kind === "agent" ? space.identity.name : null;

  return (
    <nav aria-label="Workspace" className="flex h-full min-h-0 flex-col p-2">
      <SpaceSwitcher spaces={spaces} current={current} onPick={onPickSpace} />

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
        <NavItem icon={<Activity />} label="Activity" active={view === "activity"} onClick={() => onGo("activity")} />
      </div>

      <Section title="Your workspace" />
      <div className="flex flex-col gap-px">
        <NavItem icon={<UserRound />} label="My issues" onClick={onMyIssues} />
        {favoriteProjects.map((key) => {
          const favorite = projects.find((candidate) => candidate.key === key);
          return favorite ? <NavItem key={key} icon={<Star />} label={favorite.name} onClick={() => onPickProject(key)} compact /> : null;
        })}
        {savedViews.map((saved) => (
          <NavItem key={saved.id} icon={<Bookmark />} label={saved.name} onClick={() => onApplySavedView(saved)} compact />
        ))}
        {recentIssues.slice(0, 3).map((reff) => (
          <NavItem key={reff} icon={<Clock3 />} label={reff} onClick={() => onOpenRecent(reff)} compact />
        ))}
      </div>

      <Section
        title="Projects"
        action={
          !agent ? (
            <IconButton label="New project" onClick={onCreateProject}>
              <Plus className="size-3" />
            </IconButton>
          ) : null
        }
      />
      <div className="min-h-0 flex-1 overflow-y-auto">
        {projects.length === 0 ? (
          <p className="text-mute px-2 py-1 text-sm">No projects yet.</p>
        ) : (
          projects.map((project) => {
            const active = project.key === currentProject;
            return (
              <div key={project.id} className="group/project mb-0.5 flex items-center">
                <button
                  onClick={() => onPickProject(project.key)}
                  className={cn(
                    "flex h-7 min-w-0 flex-1 items-center gap-2 rounded px-2 text-left text-sm",
                    active ? "bg-active text-fg" : "text-dim hover:bg-hover hover:text-fg",
                  )}
                >
                  <span className="size-2 shrink-0 rounded-sm" style={{ background: catalogColor(project.color) }} />
                  <span className="min-w-0 flex-1 truncate">{project.name}</span>
                  <span className="text-mute font-mono text-2xs">{project.key}</span>
                </button>
                <IconButton
                  label={favoriteProjects.includes(project.key) ? `Remove ${project.name} from favorites` : `Add ${project.name} to favorites`}
                  className="size-6 opacity-0 group-hover/project:opacity-100 focus-visible:opacity-100"
                  onClick={() => onToggleFavorite(project.key)}
                >
                  {favoriteProjects.includes(project.key) ? <StarOff className="size-3" /> : <Star className="size-3" />}
                </IconButton>
              </div>
            );
          })
        )}
      </div>

      <div className="border-line mt-2 flex flex-col gap-px border-t pt-2">
        <NavItem icon={<Users />} label="Members" active={view === "members"} onClick={() => onGo("members")} />
        <NavItem icon={<Settings2 />} label="Governance" onClick={onOpenGovernance} />
      </div>
    </nav>
  );
}

function SpaceSwitcher({ spaces, current, onPick }: { spaces: SpaceRow[]; current: string | null; onPick: (id: string) => void }) {
  const selected = spaces.find((s) => s.id === current) ?? null;
  return (
    <details className="group relative">
      <summary className="hover:bg-hover flex h-8 list-none items-center gap-2 rounded px-2 font-semibold [&::-webkit-details-marker]:hidden">
        {selected?.identity.kind === "agent" ? <Bot className="text-mute size-4" /> : <Folder className="text-mute size-4" />}
        <span className="min-w-0 flex-1 truncate">{selected?.name || selected?.space || "Choose a space"}</span>
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
      </div>
    </details>
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

function NavItem({ icon, label, active, badge, compact, onClick }: { icon: React.ReactElement; label: string; active?: boolean; badge?: number; compact?: boolean; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      aria-current={active ? "page" : undefined}
      className={cn(
        "flex w-full items-center gap-2 rounded px-2 text-left text-sm",
        compact ? "h-6" : "h-7",
        active ? "bg-active text-fg" : "text-dim hover:bg-hover hover:text-fg",
      )}
    >
      <span className="text-mute [&>svg]:size-3.5">{icon}</span>
      <span className="min-w-0 flex-1 truncate">{label}</span>
      {!!badge && <span className="bg-accent text-accent-fg min-w-4 rounded-full px-1 text-center text-2xs tabular-nums">{badge}</span>}
    </button>
  );
}

function StatusDot({ status }: { status: SpaceRow["status"] }) {
  const cls = { up: "bg-ok", idle: "bg-mute", missing: "bg-danger" }[status];
  const label = { up: "Local daemon running", idle: "Local daemon idle", missing: "Local replica unavailable" }[status];
  return <span className={cn("size-1.5 shrink-0 rounded-full", cls)} title={label} role="img" aria-label={label} />;
}
