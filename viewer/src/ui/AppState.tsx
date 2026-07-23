import * as Popover from "@radix-ui/react-popover";
import { useState } from "react";
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
import { Button, cn, PopoverContent } from "./primitives";

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

export function ProgressState(props: Omit<React.ComponentProps<typeof ApplicationState>, "kind">) {
  return <ApplicationState kind="progress" {...props} />;
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
  failureKind,
}: {
  title?: string;
  message: string;
  retryLabel?: string;
  onRetry?: () => void;
  onCopy?: () => void;
  onDismiss?: () => void;
  failureKind?: FailureKind;
}) {
  return (
    <div className="border-danger/25 bg-danger/5 text-danger flex items-center gap-2 border-b px-3 py-2 text-sm" role="alert" data-failure-kind={failureKind}>
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

export type FailureKind =
  | "offline"
  | "incompatible"
  | "authorization"
  | "read-only"
  | "invalid-reference"
  | "stale"
  | "ambiguity"
  | "conflict"
  | "provisional"
  | "corrupt"
  | "rejected"
  | "pending-sync"
  | "unknown";

export function classifyFailure(message: string): FailureKind {
  if (/read.?only/i.test(message)) return "read-only";
  if (/permission|unauthori|forbidden/i.test(message)) return "authorization";
  if (/version|schema|implementation mismatch|incompatible|upgrade required/i.test(message)) return "incompatible";
  if (/connect|daemon|network|fetch|offline/i.test(message)) return "offline";
  if (/not found|unknown (issue|project|reference)|invalid ref/i.test(message)) return "invalid-reference";
  if (/stale|expected (revision|head)|head changed/i.test(message)) return "stale";
  if (/ambiguous|multiple matches/i.test(message)) return "ambiguity";
  if (/conflict|collision|concurrent/i.test(message)) return "conflict";
  if (/provisional|still arriving/i.test(message)) return "provisional";
  if (/corrupt|undecodable|malformed/i.test(message)) return "corrupt";
  if (/pending|queued|synchroniz/i.test(message)) return "pending-sync";
  if (/reject|refused|validation|invalid/i.test(message)) return "rejected";
  return "unknown";
}

export function recoveryForError(message: string): {
  title: string;
  retryLabel: string;
} {
  switch (classifyFailure(message)) {
    case "offline": return { title: "Local service unavailable", retryLabel: "Reconnect" };
    case "incompatible": return { title: "Viewer update required", retryLabel: "Refresh" };
    case "authorization": return { title: "Change not allowed", retryLabel: "Refresh" };
    case "read-only": return { title: "Read-only space", retryLabel: "Refresh" };
    case "invalid-reference": return { title: "Reference unavailable", retryLabel: "Refresh" };
    case "stale": return { title: "Data changed elsewhere", retryLabel: "Reload" };
    case "ambiguity": return { title: "Reference is ambiguous", retryLabel: "Refresh" };
    case "conflict": return { title: "Concurrent change detected", retryLabel: "Reload" };
    case "provisional": return { title: "Data is still arriving", retryLabel: "Refresh" };
    case "corrupt": return { title: "Stored data needs attention", retryLabel: "Refresh" };
    case "rejected": return { title: "Change rejected", retryLabel: "Retry" };
    case "pending-sync": return { title: "Change is pending", retryLabel: "Refresh" };
    default: return { title: "Something didn’t finish", retryLabel: "Retry" };
  }
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
  const [diagnosticsCopied, setDiagnosticsCopied] = useState(false);
  const peers = status?.online_peers ?? 0;
  const recoveryFailures = status?.degraded_recovery ?? [];
  const degraded = recoveryFailures.length > 0;
  const healthy = liveness === "live" && localReady && !degraded && status?.membership !== "pending";
  const agent = space?.identity.kind === "agent" ? space.identity.name : null;

  return (
    <Popover.Root>
      <Popover.Trigger
        className={cn(
          "hover:bg-hover flex h-6 min-w-6 shrink-0 items-center gap-1.5 whitespace-nowrap rounded px-2 text-xs",
          healthy ? "text-dim" : "text-warn",
        )}
        aria-label="Local and peer status"
      >
        <span className={cn("size-1.5 rounded-full", healthy ? "bg-ok" : "bg-warn animate-pulse")} />
        <span className="max-[1200px]:hidden">
          {trustSummary(liveness, localReady, peers, degraded)}
        </span>
      </Popover.Trigger>
      <PopoverContent align="end" sideOffset={6} className="w-80 p-3">
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
              icon={<Users />}
              label="Last peer contact"
              value="Not reported"
              ok={false}
              neutral
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
            <Fact
              icon={<ShieldCheck />}
              label="Peer convergence"
              value="Not reported"
              ok={false}
              neutral
            />
          </dl>
          {degraded && (
            <section className="border-warn/30 bg-warn/5 mt-3 rounded-md border p-2.5" aria-label="Recovery required">
              <div className="flex items-start gap-2">
                <AlertTriangle className="text-warn mt-0.5 size-3.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium">Recovery material needs attention</p>
                  <p className="text-dim mt-0.5 text-xs leading-4">
                    Local issue data remains readable. Do not remove or replace recovery files until you have inspected the diagnosis and verified a backup.
                  </p>
                </div>
              </div>
              <ul className="border-line mt-2 space-y-1 border-t pt-2 text-xs">
                {recoveryFailures.map((failure) => (
                  <li key={failure.transcript} className="grid grid-cols-[1fr_auto] gap-2">
                    <span className="min-w-0 truncate font-mono" title={failure.transcript}>
                      {failure.transcript}
                    </span>
                    <span className="text-warn">
                      {failure.reason.kind === "undecryptable" ? "Unreadable" : "I/O failure"}
                      {failure.is_current_authority ? " · current authority" : ""}
                    </span>
                    <span className="text-dim col-span-2 break-words">{failure.reason.detail}</span>
                  </li>
                ))}
              </ul>
              <div className="mt-2 flex items-center gap-2">
                <Button
                  variant="ghost"
                  onClick={() => {
                    void navigator.clipboard.writeText(recoveryDiagnostics(status));
                    setDiagnosticsCopied(true);
                    window.setTimeout(() => setDiagnosticsCopied(false), 1600);
                  }}
                >
                  <Copy className="size-3" />
                  {diagnosticsCopied ? "Copied" : "Copy diagnosis"}
                </Button>
                <span className="text-mute text-xs">Run `lait doctor` before repair.</span>
              </div>
            </section>
          )}
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
      </PopoverContent>
    </Popover.Root>
  );
}

export function recoveryDiagnostics(status: StatusInfo | null): string {
  if (!status) return "Lait recovery diagnosis\nStatus unavailable";
  const failures = status.degraded_recovery ?? [];
  return [
    "Lait recovery diagnosis",
    `Space: ${status.name} (${status.space ?? "unavailable"})`,
    `Membership: ${status.membership}`,
    `Recovery: ${recoveryLabel(status)}`,
    `Scheme: ${status.recovery?.scheme ?? "not reported"}`,
    ...failures.flatMap((failure) => [
      `Transcript: ${failure.transcript}`,
      `Failure: ${failure.reason.kind}: ${failure.reason.detail}`,
      `Current authority: ${failure.is_current_authority === true ? "yes" : "no"}`,
    ]),
  ].join("\n");
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
