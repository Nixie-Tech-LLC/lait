import { cn } from "./primitives";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Bot, ChevronRight, Folder, FolderKanban, GanttChart, Inbox, UserRound } from "lucide-react";

export function SurfaceHeader({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <header
      className={cn("border-line/70 flex h-8 shrink-0 items-center gap-1 border-b px-2", className)}
      {...props}
    />
  );
}

/**
 * One hop of the trail.
 *
 * The trail is an *object* path — workspace, project, issue — never the route you
 * took to get here. A surface with a tab strip (a project's views, Settings' rail)
 * therefore ends its trail at the object the tabs belong to: the strip already says
 * which face of it you are looking at, and naming it twice was the old duplication.
 */
export type BreadcrumbItem = {
  key: string;
  content: React.ReactNode;
  /** Ancestors climb; the leaf is where you already are and never navigates. */
  onNavigate?: (() => void) | undefined;
  /** Accessible name, for crumbs whose content mixes a glyph with text. */
  label?: string | undefined;
  /** Content that brings its own trigger geometry (a picker) — don't pad it twice. */
  control?: boolean | undefined;
  /** Ancestors may drop out on a narrow surface. The leaf never does. */
  optional?: boolean | undefined;
};

/** Shared crumb geometry: a link, a static crumb and a picker crumb must land on
 *  the same baseline and the same padding, or the trail visibly steps. */
const crumbFace = "flex min-h-6 min-w-0 items-center gap-1.5 rounded-md transition-colors";

export function Breadcrumbs({
  items,
  className,
}: {
  items: BreadcrumbItem[];
  className?: string;
}) {
  return (
    <nav aria-label="Breadcrumb" className={cn("min-w-0 flex-1 overflow-hidden", className)}>
      <ol className="flex min-w-0 items-center text-sm">
        {items.map((item, index) => {
          const leaf = index === items.length - 1;
          return (
            <li
              key={item.key}
              className={cn(
                "flex min-w-0 items-center",
                // The leaf takes the slack and truncates last; ancestors hold their
                // width up to a ceiling so a long project name can't erase them.
                leaf ? "flex-1" : "max-w-[min(32cqw,240px)] shrink-0",
                !leaf && item.optional && "@max-[560px]:hidden",
              )}
            >
              {item.onNavigate ? (
                <button
                  type="button"
                  aria-label={item.label}
                  onClick={item.onNavigate}
                  className={cn(
                    crumbFace,
                    "text-dim hover:bg-hover hover:text-fg focus-visible:ring-accent/50 -mx-1 px-1.5 outline-none focus-visible:ring-1",
                  )}
                >
                  {item.content}
                </button>
              ) : (
                <span
                  aria-current={leaf ? "page" : undefined}
                  aria-label={item.label}
                  className={cn(
                    crumbFace,
                    leaf ? "text-fg font-medium" : "text-dim",
                    !item.control && "-mx-1 px-1.5",
                  )}
                >
                  {item.content}
                </span>
              )}
              {/* The separator belongs to the crumb before it: a dropped ancestor
                  takes its chevron with it, so the trail never opens with a stray ›. */}
              {!leaf && <ChevronRight className="text-mute mx-0.5 size-3 shrink-0" aria-hidden />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** The space, drawn the way the sidebar's space switcher draws it. */
export function WorkspaceCrumb({ name, agent }: { name: string; agent?: boolean | undefined }) {
  const Glyph = agent ? Bot : Folder;
  return (
    <>
      <span className="bg-active flex size-4 shrink-0 items-center justify-center rounded">
        <Glyph className="text-mute size-2.5" aria-hidden />
      </span>
      <span className="truncate">{name}</span>
    </>
  );
}

/** A project, drawn the way the sidebar, the project cards and the project picker
 *  draw it — so the crumb doesn't change shape when a second project turns it
 *  into a picker. */
export function ProjectCrumb({ name, color }: { name: string; color?: string | undefined }) {
  return (
    <>
      <span
        className="size-2 shrink-0 rounded-[3px]"
        style={{ background: color ?? "var(--color-mute)" }}
        aria-hidden
      />
      <span className="truncate">{name}</span>
    </>
  );
}

/** An issue: the key is the identity, the title is context. */
export function IssueCrumb({ id, title }: { id: string; title?: string | undefined }) {
  return (
    <>
      <span className="text-mute shrink-0 font-mono text-xs tabular-nums">{id}</span>
      {title && <span className="truncate">{title}</span>}
    </>
  );
}

/** A workspace destination — its own root, carrying the sidebar's icon for it. */
export function DestinationCrumb({ icon, label }: { icon?: React.ReactNode; label: string }) {
  return (
    <>
      {icon && <span className="text-mute shrink-0 [&>svg]:size-3.5">{icon}</span>}
      <span className="truncate">{label}</span>
    </>
  );
}

/** One icon per destination, shared by the sidebar and the header crumb so the two
 *  can't drift apart. */
export const DESTINATION_ICON = {
  inbox: <Inbox />,
  "my-issues": <UserRound />,
  projects: <FolderKanban />,
  timeline: <GanttChart />,
  workspace: <Folder />,
} as const;

export function SectionHeader({
  title,
  meta,
  action,
  className,
}: {
  title: React.ReactNode;
  meta?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div className={cn("flex min-h-6 items-center gap-2", className)}>
      <h3 className="text-mute text-2xs font-semibold tracking-wider uppercase">{title}</h3>
      {meta && <span className="text-mute text-xs">{meta}</span>}
      {action && <span className="ml-auto">{action}</span>}
    </div>
  );
}

export function PropertyRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="issue-property group/prop flex min-h-7 items-center gap-2">
      <dt className="text-mute w-20 shrink-0">{label}</dt>
      <dd className="min-w-0 flex-1">{children}</dd>
    </div>
  );
}

export function Toast({
  children,
  action,
  className,
}: {
  children: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn("border-line bg-raised text-dim flex items-center gap-3 rounded-md border px-3 py-2 text-sm shadow-raised", className)}
      role="status"
      aria-live="polite"
    >
      <span className="min-w-0 flex-1">{children}</span>
      {action}
    </div>
  );
}

export function MenuContent({
  className,
  ...props
}: React.ComponentProps<typeof DropdownMenu.Content>) {
  return (
    <DropdownMenu.Content
      sideOffset={4}
      className={cn("ui-surface border-line-strong bg-raised shadow-overlay z-50 min-w-48 rounded-lg border p-1 text-sm", className)}
      {...props}
    />
  );
}

export function MenuItem({
  danger,
  className,
  ...props
}: React.ComponentProps<typeof DropdownMenu.Item> & { danger?: boolean }) {
  return (
    <DropdownMenu.Item
      className={cn(
        "flex h-7 cursor-default select-none items-center gap-2 rounded-md px-2 outline-none data-[highlighted]:bg-active data-[disabled]:opacity-50",
        danger ? "text-danger" : "text-dim",
        className,
      )}
      {...props}
    />
  );
}
