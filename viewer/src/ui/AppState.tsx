import * as Popover from "@radix-ui/react-popover";
import {
  AlertTriangle,
  CheckCircle2,
  CloudOff,
  Copy,
  Database,
  HardDrive,
  LoaderCircle,
  RefreshCw,
  SearchX,
  ShieldCheck,
  Users,
  X,
} from "lucide-react";

import type { SpaceRow, StatusInfo } from "../types";
import { Button, cn } from "./primitives";

export type ApplicationStateKind =
  | "loading"
  | "empty"
  | "filtered-empty"
  | "unavailable"
  | "error"
  | "retry"
  | "progress"
  | "success";

export function ApplicationState({
  kind,
  icon,
  title,
  body,
  action,
  className,
}: {
  kind: ApplicationStateKind;
  icon?: React.ReactNode;
  title: string;
  body?: React.ReactNode;
  action?: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn("flex flex-1 items-center justify-center p-8", className)}
      data-application-state={kind}
      role={kind === "error" || kind === "retry" ? "alert" : "status"}
      aria-live={kind === "loading" || kind === "progress" ? "polite" : undefined}
      aria-busy={kind === "loading" || kind === "progress" ? true : undefined}
    >
      <div className="flex max-w-sm flex-col items-center text-center">
        <span className={cn("text-mute mb-3", (kind === "error" || kind === "retry") && "text-danger")}>
          {icon ?? <StateIcon kind={kind} />}
        </span>
        <h2 className="text-base font-semibold">{title}</h2>
        {body && <p className="text-dim mt-1 text-sm leading-5">{body}</p>}
        {action && <div className="mt-4">{action}</div>}
      </div>
    </div>
  );
}

export function EmptyState(props: Omit<React.ComponentProps<typeof ApplicationState>, "kind"> & { kind?: Extract<ApplicationStateKind, "empty" | "filtered-empty" | "unavailable"> }) {
  const { kind = "empty", ...rest } = props;
  return <ApplicationState kind={kind} {...rest} />;
}

export function LoadingState(props: Omit<React.ComponentProps<typeof ApplicationState>, "kind">) {
  return <ApplicationState kind="loading" {...props} />;
}

function StateIcon({ kind }: { kind: ApplicationStateKind }) {
  if (kind === "loading" || kind === "progress") return <LoaderCircle className="size-5 animate-spin" />;
  if (kind === "filtered-empty") return <SearchX className="size-5" />;
  if (kind === "error" || kind === "retry" || kind === "unavailable") return <AlertTriangle className="size-5" />;
  if (kind === "success") return <CheckCircle2 className="text-ok size-5" />;
  return <Database className="size-5" />;
}

export function InlineError({
  title,
  message,
  retryLabel = "Retry",
  onRetry,
  onCopy,
  onDismiss,
}: {
  title?: string;
  message: string;
  retryLabel?: string;
  onRetry?: () => void;
  onCopy?: () => void;
  onDismiss?: () => void;
}) {
  return (
    <div className="border-danger/25 bg-danger/5 text-danger flex items-center gap-2 border-b px-3 py-2 text-sm" role="alert">
      <AlertTriangle className="size-3.5 shrink-0" />
      <span className="min-w-0 flex-1">
        {title && <strong className="mr-1">{title}.</strong>}
        {message}
      </span>
      {onRetry && (
        <Button variant="ghost" onClick={onRetry} className="text-danger">
          <RefreshCw className="size-3" />
          {retryLabel}
        </Button>
      )}
      {onCopy && (
        <Button variant="ghost" onClick={onCopy} className="text-danger">
          <Copy className="size-3" />
          Copy details
        </Button>
      )}
      {onDismiss && (
        <Button variant="ghost" onClick={onDismiss} className="text-danger" aria-label="Dismiss error">
          <X className="size-3" />
        </Button>
      )}
    </div>
  );
}

export function recoveryForError(message: string): {
  title: string;
  retryLabel: string;
} {
  if (/connect|daemon|network|fetch|offline/i.test(message)) {
    return { title: "Local service unavailable", retryLabel: "Reconnect" };
  }
  if (/permission|unauthori|read.?only|refused/i.test(message)) {
    return { title: "Change not allowed", retryLabel: "Refresh" };
  }
  return { title: "Something didn’t finish", retryLabel: "Retry" };
}

/**
 * Four facts, never one "sync" lamp:
 * browser↔daemon health, local projection readiness, peer reachability, and
 * recovery custody. The current contract does not prove per-change convergence,
 * so this component deliberately makes no "synced everywhere" claim.
 */
export function TrustPopover({
  liveness,
  status,
  space,
  localReady,
  latestChange,
}: {
  liveness: "connecting" | "live" | "retrying";
  status: StatusInfo | null;
  space: SpaceRow | null;
  localReady: boolean;
  latestChange?: string;
}) {
  const peers = status?.online_peers ?? 0;
  const degraded = (status?.degraded_recovery?.length ?? 0) > 0;
  const healthy = liveness === "live" && localReady && !degraded && status?.membership !== "pending";
  const agent = space?.identity.kind === "agent" ? space.identity.name : null;

  return (
    <Popover.Root>
      <Popover.Trigger
        className={cn(
          "hover:bg-hover flex h-6 shrink-0 items-center gap-1.5 whitespace-nowrap rounded px-2 text-xs",
          healthy ? "text-dim" : "text-warn",
        )}
        aria-label="Local and peer status"
      >
        <span className={cn("size-1.5 rounded-full", healthy ? "bg-ok" : "bg-warn animate-pulse")} />
        <span className="max-[1200px]:hidden">
          {trustSummary(liveness, localReady, peers, degraded)}
        </span>
      </Popover.Trigger>
      <Popover.Portal>
        <Popover.Content
          align="end"
          sideOffset={6}
          className="border-line-strong bg-raised shadow-overlay z-50 w-80 rounded-lg border p-3"
        >
          <div className="mb-3 flex items-center gap-2">
            <ShieldCheck className="text-accent size-4" />
            <div>
              <p className="font-semibold">Local trust and availability</p>
              <p className="text-mute text-xs">Facts from this device, not cloud-style guesses.</p>
            </div>
          </div>
          <dl className="flex flex-col gap-2 text-sm">
            <Fact icon={<HardDrive />} label="Local service" value={livenessLabel(liveness)} ok={liveness === "live"} />
            <Fact icon={<Database />} label="Local data" value={localReady ? "Ready" : "Loading or unavailable"} ok={localReady} />
            <Fact
              icon={peers ? <Users /> : <CloudOff />}
              label="Peer reachability"
              value={peers ? `${peers} connected` : "No peers connected"}
              ok={peers > 0}
              neutral={peers === 0}
            />
            <Fact
              icon={<Database />}
              label="Latest change"
              value={latestChange || "No change pending"}
              ok={!latestChange || latestChange.includes("saved on this device")}
              neutral={!latestChange || latestChange.startsWith("Saving")}
            />
            <Fact
              icon={<ShieldCheck />}
              label="Recovery custody"
              value={degraded ? "Needs attention" : recoveryLabel(status)}
              ok={!degraded}
            />
          </dl>
          {peers === 0 && localReady && (
            <p className="bg-bg border-line text-dim mt-3 rounded border p-2 text-xs">
              Ready locally. Changes will share when a peer connects.
            </p>
          )}
          <p className="text-mute mt-3 text-xs leading-4">
            “Saved on this device” means the local daemon accepted the change. Peer count shows reachability only; this build does not report per-change peer acknowledgement or convergence.
          </p>
          <div className="border-line text-mute mt-3 border-t pt-2 text-xs">
            Acting as {agent ? <strong className="text-fg">agent {agent}</strong> : <strong className="text-fg">your local actor</strong>}
            {status?.membership ? ` · ${status.membership}` : ""}
          </div>
          <Popover.Arrow className="fill-line-strong" />
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}

export function trustSummary(
  liveness: "connecting" | "live" | "retrying",
  localReady: boolean,
  peers: number,
  degraded: boolean,
): string {
  if (degraded) return "Recovery needs attention";
  if (liveness !== "live") return localReady ? "Offline · local data safe" : livenessLabel(liveness);
  if (!localReady) return "Loading local data";
  return peers > 0 ? `${peers} ${peers === 1 ? "peer" : "peers"}` : "Ready locally";
}

function livenessLabel(liveness: "connecting" | "live" | "retrying"): string {
  return { connecting: "Connecting", live: "Connected", retrying: "Reconnecting" }[liveness];
}

function Fact({
  icon,
  label,
  value,
  ok,
  neutral = false,
}: {
  icon: React.ReactElement;
  label: string;
  value: string;
  ok: boolean;
  neutral?: boolean;
}) {
  return (
    <div className="grid grid-cols-[16px_1fr_auto] items-center gap-2">
      <span className={cn("[&>svg]:size-3.5", ok || neutral ? "text-mute" : "text-warn")}>{icon}</span>
      <dt className="text-dim">{label}</dt>
      <dd className="flex items-center gap-1.5 text-right">
        {ok ? (
          <CheckCircle2 className="text-ok size-3" />
        ) : neutral ? null : (
          <AlertTriangle className="text-warn size-3" />
        )}
        {value}
      </dd>
    </div>
  );
}

function recoveryLabel(status: StatusInfo | null): string {
  const custody = status?.recovery?.local_custody.state;
  if (!custody) return "Not reported";
  return {
    not_a_holder: "Not a holder",
    ready: "Ready on this device",
    missing: "Share missing",
    backup_unverified: "Backup unverified",
    unreadable: "Share unreadable",
  }[custody];
}
