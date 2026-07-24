/**
 * TypeScript mirrors of the engine's Layer-B contract — `src/dto.rs` (the DTOs)
 * and `src/control.rs` (the `Request`/`Response` envelopes).
 *
 * These are hand-maintained on purpose, mirroring a projection that is itself
 * hand-maintained: "not an automatic dump of the Loro layout — a storage refactor
 * must not break these" (dto.rs). Drift here is silent, so two rules:
 *
 * - **Timestamps are unix SECONDS**, not millis. The previous viewer passed
 *   `created_at` straight to `new Date(ms)` and rendered every issue as 1970.
 *   Use `tsToDate` and never construct a Date from these directly.
 * - **`SCHEMA_VERSION` does not move for renames.** It is still 1 across the
 *   `StatusInfo.room` → `name` rename that broke the old viewer's sidebar, so a
 *   version check would not have caught it. Only reading dto.rs catches it.
 */

/** dto.rs `SCHEMA_VERSION` — every top-level DTO carries it. */
export const SCHEMA_VERSION = 3;

/** Unix seconds → Date. The one place the units are converted. */
export const tsToDate = (ts: number): Date => new Date(ts * 1000);

// ---- plain domain enums -----------------------------------------------------

export type Priority = "none" | "low" | "medium" | "high" | "urgent";
export type StatusCategory = "backlog" | "active" | "done";

/** Priority order, low → high. Mirrors the Rust enum's `Ord`. */
export const PRIORITY_ORDER: readonly Priority[] = ["none", "low", "medium", "high", "urgent"];

/** UI.md §5.1 board badge: `·U/H/M/L·`. */
export const PRIORITY_BADGE: Record<Priority, string> = {
  none: "-",
  low: "L",
  medium: "M",
  high: "H",
  urgent: "U",
};

export interface WorkflowState {
  id: string;
  name: string;
  category: StatusCategory;
  color: string;
}

// ---- projections ------------------------------------------------------------

export interface ProjectDto {
  id: string;
  name: string;
  key: string;
  color: string;
  /** Overview markdown (absent/empty = none). */
  description?: string;
  /** Lead actor key (absent/empty = none). */
  lead?: string;
  /** Planned window, unix seconds. */
  start_date?: number | null;
  target_date?: number | null;
  /** Soft-hidden from pickers and all-project lists (still openable directly). */
  archived?: boolean;
}

export interface LabelDto {
  id: string;
  name: string;
  color: string;
}

/**
 * One board/list row — the `DocMeta` cache, never the issue doc.
 * `provisional` means the row is known but its body hasn't arrived (UI.md §3.3).
 */
export interface Row {
  reff: string;
  doc_id: string;
  project_id: string;
  key_alias: string | null;
  title: string;
  status: string;
  priority: Priority;
  /** Viewer-relative one-liner (`you +2`) — the shape a terminal row prints. */
  assignee_summary: string;
  /** The keys behind that summary, for clients that draw faces instead. */
  assignees: string[];
  tombstone: boolean;
  provisional: boolean;
  /** Due date, unix seconds. Absent = none. */
  due_date?: number | null;
  /** Estimate points (the scale is the team's convention). */
  estimate?: number | null;
  /** Resolved label names (absent/empty = none). */
  label_names?: string[];
  /** Sub-issue progress: done / total live children. Absent = no children.
   *  Populated by the board projection only. */
  child_done?: number | null;
  child_total?: number | null;
}

export interface BoardColumn {
  state: WorkflowState;
  rows: Row[];
}

export interface BoardView {
  schema_version: number;
  project: ProjectDto;
  columns: BoardColumn[];
}

export interface CommentDto {
  author: string;
  author_nick: string | null;
  /** Unix seconds. */
  ts: number;
  body: string;
  /** Canonical comment id (`cmt_…`). Absent on comments stored before comment
   *  identity existed — those cannot anchor reactions or replies. */
  id?: string | null;
  /** The comment this one replies to (one level of nesting). */
  parent?: string | null;
  /** Emoji reactions, grouped per emoji with the actors who reacted. */
  reactions?: ReactionDto[];
}

export interface ReactionDto {
  emoji: string;
  actors: string[];
}

export interface IssueView {
  schema_version: number;
  reff: string;
  doc_id: string;
  space_id: string;
  project_id: string;
  project_key: string | null;
  key_alias: string | null;
  title: string;
  description: string;
  status: string;
  priority: Priority;
  assignees: string[];
  labels: string[];
  label_names: string[];
  comments: CommentDto[];
  created_by: string;
  /** Unix seconds. */
  created_at: number;
  /** Due date, unix seconds. Absent = none. */
  due_date?: number | null;
  estimate?: number | null;
  /** Subscribed actors, independent of assignment (INBOX-9). */
  followers?: string[];
  /** Targeted milestone id (SCOPE-1). */
  milestone?: string | null;
  /** Scheduled cycle id (BOARD-11). */
  cycle?: string | null;
  /** Attachment metadata (CREATE-5). */
  attachments?: AttachmentMetaDto[];
  provisional: boolean;
  /** Malformed stored records, kept beside the valid projection rather than
   * silently dropped or laundered into sentinel values. */
  corrupt_records?: CorruptRecord[];
}

/** Attachment metadata on an issue (CREATE-5) — payloads via `attachment_get`. */
export interface AttachmentMetaDto {
  id: string;
  name: string;
  mime?: string;
  size: number;
  by?: string;
  ts: number;
  comment?: string;
}

/** One project milestone with derived progress (SCOPE-1). */
export interface MilestoneDto {
  id: string;
  name: string;
  target_date?: number | null;
  total: number;
  done: number;
}

export interface CorruptRecord {
  locus: string;
  reason: string;
  raw?: Record<string, string>;
}

export interface FieldChange {
  field: string;
  from: string | null;
  to: string | null;
}

/** One edge in the issue graph — `dto.rs` `LinkDto`. */
export interface LinkDto {
  /** `blocks` | `relates` | `duplicates`. */
  kind: string;
  /** `out` | `in` — whether this issue is the source or the target of the edge. */
  direction: string;
  row: Row;
}

/**
 * An issue's graph neighborhood — `dto.rs` `GraphView`, reply to `IssueGraph`.
 *
 * Read from the catalog *structure* doc without opening any issue doc, so it is
 * cheap. `parent`/`children` are the sub-issue tree (a tree-move CRDT, so concurrent
 * reparents can't converge to a cycle); `blocked_by` is the transitive set of open
 * issues that block this one, computed by the daemon (not just direct `blocks` edges).
 */
export interface GraphView {
  schema_version: number;
  reff: string;
  doc_id: string;
  parent: Row | null;
  children: Row[];
  links: LinkDto[];
  blocked_by: Row[];
}

export interface ActivityEvent {
  seq: number;
  doc_id: string | null;
  reff: string;
  kind: string;
  changes: FieldChange[];
  actor: string | null;
  actor_nick: string;
  text: string;
  /** Unix seconds. */
  ts: number;
  /** Non-blocking LWW collision note (A§9). */
  collision: boolean;
}

/** A ref that resolved to several issues (UI.md §3.2). A first-class outcome, not an error. */
export interface Candidate {
  reff: string;
  key_alias: string | null;
  title: string;
}

export interface InboxEntry {
  /** Unix seconds — the read-watermark axis. */
  ts: number;
  /** `assigned` | `comment` | `status`. */
  kind: string;
  reff: string;
  doc_id: string;
  title: string;
  detail: string;
  /** Comments only — the one in-doc field with a real author. `null` = actor unknown. */
  actor?: string | null;
  actor_nick?: string | null;
}

export interface MemberDto {
  key: string;
  /** "admin" | "member" — from the signed ACL graph. */
  role: string;
  me: boolean;
  /** Present for agents: the actor whose standing sponsors this identity. */
  sponsor?: string | null;
  /** Local petname; never synced. The trusted half of the identity model. */
  alias: string;
}

/**
 * One entry in the membership audit log — `dto.rs` `MemberLogEntry`.
 *
 * Unlike in-doc activity attribution (advisory, non-goal 6), `actor` here is
 * **verified**: the signature covers the op, so this is who really signed it.
 * `authorized` is the replay verdict — `false` means the op was rejected as
 * unauthorized or couldn't be decoded, which is a real thing to be able to see.
 */
export interface MemberLogEntry {
  /** The op's content-address (its signed-DAG node id). */
  op: string;
  /** The signing author's key — verified, not claimed. */
  actor: string;
  /** `add_member` | `remove_member` | `set_role` | `add_agent` | `unknown`. */
  kind: string;
  /** The key the op acts on. Absent for an undecodable op. */
  subject?: string | null;
  /** `admin` | `member`, for role-bearing ops. */
  role?: string | null;
  /** Whether replay honored the op (false = unauthorized or undecodable). */
  authorized: boolean;
}

/**
 * One effective scoped capability assignment — `dto.rs` `AssignmentDto`.
 *
 * A role grant (`access_grant`) expands the role's pinned definition into one of
 * these per capability, each with its own `grant_id` (the revocation handle).
 * `resource` empty = the Space; `[projectId]` = that project's scope.
 */
export interface AssignmentDto {
  grant_id: string;
  actor: string;
  world: string;
  capability: string;
  resource: string[];
}

/** One project status update — `dto.rs` `ProjectUpdateDto` (SCOPE-1). */
export interface ProjectUpdateDto {
  id: string;
  /** Authoring actor key. */
  author: string;
  /** Post time, unix seconds. */
  ts: number;
  body: string;
  /** `on_track` | `at_risk` | `off_track` | "" (none). */
  health?: string;
}

/** A pinned seed ("remote") — a bootstrap + backfill anchor, never trust. */
export interface SeedDto {
  id: string;
  nick: string;
  space: string;
  state: string;
  online: boolean;
}

export interface PresenceEntry {
  id: string;
  nick: string;
  state: string;
  online: boolean;
  last_seen_secs: number;
}

export interface Event {
  seq: number;
  kind: string;
  id: string;
  nick: string;
  text: string;
  ts: number;
}

/**
 * `control.rs` `StatusInfo`.
 *
 * `space` is nullable, and `membership` is how a still-unadmitted joiner
 * learns admission is in progress rather than staring at an empty board.
 */
export interface StatusInfo {
  id: string;
  nick: string;
  /** Space display name. (Was `room` in the pre-v0.4.2 shape.) */
  name: string;
  /** Space overview description (SCOPE-2; empty when unset). */
  description?: string;
  online_peers: number;
  space: string | null;
  issues: number;
  projects: number;
  /** True means zero counts are unavailable, not an empty space. */
  counts_unavailable?: boolean;
  /** `admin` | `member` | `pending`. */
  membership: string;
  degraded_recovery?: DegradedRecoveryHolder[];
  recovery?: RecoveryStatus | null;
}

export interface RecoveryArtifactFailure {
  kind: "undecryptable" | "io";
  detail: string;
}

export interface DegradedRecoveryHolder {
  transcript: string;
  reason: RecoveryArtifactFailure;
  is_current_authority?: boolean | null;
}

export interface RecoveryStatus {
  authority?: string | null;
  scheme: "Single" | "FrostThreshold" | "GeneralAccess";
  k: number;
  n: number;
  local_custody:
    | { state: "not_a_holder" }
    | { state: "ready" }
    | { state: "missing" }
    | { state: "backup_unverified" }
    | { state: "unreadable"; detail: RecoveryArtifactFailure };
}

// ---- the supervisor surface (serve-level, not control-plane) ----------------

/** Whose key a space's daemon signs with (`serve::spaces::SpaceIdentity`). */
export type SpaceIdentity = { kind: "own" } | { kind: "agent"; name: string };

export interface ProjectBrief {
  key: string;
  name: string;
}

export interface SpaceRow {
  id: string;
  space: string;
  name: string;
  path: string;
  origin: string;
  last_opened: number;
  /** `up` | `idle` | `missing`. */
  status: "up" | "idle" | "missing";
  identity: SpaceIdentity;
  projects: ProjectBrief[];
}

export interface SpacesReply {
  spaces: SpaceRow[];
}

/** An agent's space is observable, not operable — writes are refused server-side. */
export const isReadOnly = (s: SpaceRow): boolean => s.identity.kind === "agent";

// ---- the doorbell -----------------------------------------------------------

export type CatalogScope = { scope: string; project?: string | null };

/**
 * A dirty-set frame, tagged with the space it rang for.
 *
 * Never state: the client re-reads the authoritative projection and never patches
 * from the frame (UI.md §4.2). `reset` — or an `epoch` change, which is a daemon
 * restart — means rebaseline from scratch; `App` treats them identically.
 *
 * `activity_advanced` and `presence_advanced` are carried faithfully but not yet
 * read: this client re-reads on any ring rather than per dirty scope. See
 * `doorbell.ts`.
 */
export interface SpaceDoorbell {
  space: string;
  epoch: number;
  seq: number;
  reset: boolean;
  dirty_by_project: Record<string, string[]>;
  dirty_catalog: CatalogScope[];
  activity_advanced: boolean;
  presence_advanced: boolean;
}

// ---- the control-plane envelopes -------------------------------------------

/** A board position for `issue_move` — `control.rs` `BoardPos`, tagged by `at`. */
export type BoardPos =
  | { at: "top" }
  | { at: "bottom" }
  | { at: "before"; reff: string }
  | { at: "after"; reff: string };

export interface Filter {
  mine?: boolean;
  status?: string | null;
  label?: string | null;
  /** Include done + tombstoned rows (UI.md §2.2). */
  all?: boolean;
}

/**
 * `control.rs` `Request`, internally tagged by `cmd`.
 *
 * Field names are the Rust ones, verbatim — several are *not* what the CLI flag
 * suggests, and guessing them is how the old viewer broke. The ones that bite:
 * `issue_edit` takes `description` (not `body`); `assign` takes `add: bool` (not
 * `remove`); `label` takes `add[]`/`remove[]` (not the CLI's `+x -y` tokens — the
 * daemon wants them already split); and the `--as NAME` flag is `as_name`,
 * because `as` is a Rust keyword.
 *
 * Anything `#[serde(default)]` in Rust is optional here. `subscribe`, `connect`,
 * `seed_add`, `seed_remove`, `config_reload` and `stop` are deliberately absent:
 * `subscribe` is refused on the RPC path (use the doorbell stream), and the rest
 * have no browser surface yet — add them here when they grow one.
 */
export type Request =
  | { cmd: "issue_new"; title: string; project?: string | null; project_hint?: string | null; assignees?: string[]; priority?: Priority | null; labels?: string[]; body?: string | null; due?: string | null; estimate?: number | null }
  /** `due`: `YYYY-MM-DD` (UTC), unix seconds, or `"none"` to clear; `estimate`:
   *  a number as a string, or `"none"` to clear. Absent = untouched. */
  | { cmd: "issue_edit"; reff: string; title?: string | null; status?: string | null; priority?: string | null; description?: string | null; due?: string | null; estimate?: string | null }
  | { cmd: "issue_move"; reff: string; project?: string | null; pos?: BoardPos | null }
  | { cmd: "assign"; reff: string; who: string[]; add?: boolean }
  | { cmd: "label"; reff: string; add?: string[]; remove?: string[] }
  | { cmd: "comment"; reff: string; body: string; reply_to?: string | null }
  /** Toggle an emoji reaction on a comment. Writes no history event. */
  | { cmd: "react"; reff: string; comment: string; emoji: string; on?: boolean }
  | { cmd: "issue_delete"; reff: string }
  /** Clears the tombstone. Restore wins over a concurrent delete. */
  | { cmd: "issue_restore"; reff: string }
  /** `kind` is `blocks` | `relates` | `duplicates`; `reff` is the edge's source
   *  (`reff` blocks `target`), so "blocked by" is the same verb with the ends
   *  swapped. `relates` is symmetric — the daemon canonicalizes the endpoints. */
  | { cmd: "issue_link"; reff: string; kind: string; target: string }
  | { cmd: "issue_unlink"; reff: string; kind: string; target: string }
  /** `parent: null` clears. The daemon refuses cycles (tree-move CRDT). */
  | { cmd: "issue_parent"; reff: string; parent?: string | null }
  | { cmd: "issue_start"; reff: string }
  | { cmd: "issue_done"; reff: string }
  | { cmd: "issue_stop"; reff: string }
  | { cmd: "issue_view"; reff: string }
  | { cmd: "list"; project?: string | null; filter?: Filter }
  | { cmd: "board"; project?: string | null; project_hint?: string | null }
  | { cmd: "history"; reff: string }
  | { cmd: "issue_graph"; reff: string }
  | { cmd: "project_new"; name: string; key: string; color?: string | null }
  | { cmd: "project_list" }
  | {
      cmd: "project_edit";
      project: string;
      name?: string | null;
      color?: string | null;
      description?: string | null;
      lead?: string | null;
      start?: string | null;
      target?: string | null;
      /** Soft-hide toggle: true archives, false restores, absent leaves it. */
      archived?: boolean | null;
    }
  /** Reply is `updates` — the project's status feed, newest first. */
  | { cmd: "project_updates"; project: string }
  | { cmd: "project_update_post"; project: string; body: string; health?: string | null }
  /** Subscribe to an issue without being assigned (INBOX-9). */
  | { cmd: "follow"; reff: string; on?: boolean }
  /** Reply is `milestones` — the project's milestones with progress (SCOPE-1). */
  | { cmd: "milestone_list"; project: string }
  | { cmd: "milestone_set"; project: string; milestone?: string | null; name?: string | null; target?: string | null; remove?: boolean }
  /** Point an issue at a milestone in its project (`null`/"none" clears). */
  | { cmd: "issue_milestone"; reff: string; milestone?: string | null }
  /** Attach a file (standard base64; raw ≤ 256 KiB) — CREATE-5. */
  | { cmd: "attach"; reff: string; name: string; mime?: string | null; data_b64: string; comment?: string | null }
  | { cmd: "detach"; reff: string; id: string }
  /** Reply is `attachment` — the full record incl. payload. */
  | { cmd: "attachment_get"; reff: string; id: string }
  | { cmd: "label_new"; name: string; color?: string | null }
  | { cmd: "label_list" }
  | { cmd: "label_edit"; label: string; name?: string | null; color?: string | null }
  | { cmd: "label_delete"; label: string }
  | { cmd: "space_rename"; name: string }
  | { cmd: "space_describe"; description: string }
  | { cmd: "activity"; since?: number }
  | { cmd: "inbox"; clear?: boolean }
  | { cmd: "member_add"; who: string; admin?: boolean; as_name?: string | null }
  | { cmd: "member_remove"; who: string }
  | { cmd: "key_rotate" }
  | { cmd: "members" }
  | { cmd: "member_log" }
  | { cmd: "member_alias"; who: string; name: string }
  | { cmd: "status" }
  | { cmd: "diagnose"; expected_space?: string | null }
  | { cmd: "id" }
  | { cmd: "invite"; role?: string | null; reusable?: boolean; ttl_hours?: number | null }
  /** Admin-only. Accepts the invite ticket or its 32-hex nonce. */
  | { cmd: "invite_revoke"; invite: string }
  /** Reply is `text` — the revision as pretty JSON (same shape the CLI prints). */
  | { cmd: "workflow_show"; project: string }
  | { cmd: "workflow_set"; project: string; expect_heads: string[]; body_json: string }
  /** Reply is `text` — every role definition as pretty JSON. */
  | { cmd: "role_list" }
  /** Reply is `assignments` — effective scoped grants, optionally one actor. */
  | { cmd: "access_list"; actor?: string | null }
  /** Expand a role's pinned caps and install them for an actor (Space- or
   *  project-scoped). All-or-nothing; authority-first. */
  | { cmd: "access_grant"; actor: string; role: string; project?: string | null }
  /** Revoke one effective capability assignment by its 64-hex grant id. */
  | { cmd: "access_revoke"; grant_id: string }
  | { cmd: "join"; ticket: string }
  | { cmd: "seed_list" }
  | { cmd: "log"; since: number }
  | { cmd: "who" };

/**
 * `control.rs` `Response`, internally tagged by `kind`.
 *
 * The newtype variants (`Issue(Box<IssueView>)`, `Board(Box<BoardView>)`,
 * `Status(Box<StatusInfo>)`, `Diagnosis(..)`) serialize **flattened** under an
 * internal tag — hence the intersections rather than a nested payload field.
 */
export type Response =
  | { kind: "hello"; protocol_version: number }
  | { kind: "ok"; message: string | null }
  | { kind: "ref"; reff: string }
  | ({ kind: "issue" } & IssueView)
  | { kind: "list"; rows: Row[] }
  | ({ kind: "board" } & BoardView)
  | ({ kind: "graph" } & GraphView)
  | { kind: "activity"; events: ActivityEvent[]; last: number }
  | { kind: "inbox"; entries: InboxEntry[]; unread: number }
  | { kind: "projects"; projects: ProjectDto[] }
  | { kind: "updates"; updates: ProjectUpdateDto[] }
  | { kind: "milestones"; milestones: MilestoneDto[] }
  | { kind: "attachment"; name: string; mime: string; data_b64: string }
  | { kind: "labels"; labels: LabelDto[] }
  | { kind: "members"; members: MemberDto[] }
  | { kind: "assignments"; rows: AssignmentDto[] }
  | { kind: "member_log"; entries: MemberLogEntry[] }
  | { kind: "seeds"; seeds: SeedDto[] }
  /** A ref resolved to several — a first-class outcome (exit 2), never an error. */
  | { kind: "candidates"; candidates: Candidate[]; near_miss_for: string | null }
  | ({ kind: "status" } & StatusInfo)
  | { kind: "diagnosis"; [k: string]: unknown }
  | { kind: "text"; text: string }
  | { kind: "events"; events: Event[]; last: number }
  | { kind: "who"; peers: PresenceEntry[] }
  | { kind: "error"; message: string; error_kind: "error" | "not_found" };
