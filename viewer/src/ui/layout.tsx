import { cn } from "./primitives";
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";

export function SurfaceHeader({ className, ...props }: React.HTMLAttributes<HTMLElement>) {
  return (
    <header
      className={cn("border-line flex h-11 shrink-0 items-center gap-1 border-b px-2", className)}
      {...props}
    />
  );
}

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
    <div className="group/prop flex min-h-7 items-center gap-2">
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
