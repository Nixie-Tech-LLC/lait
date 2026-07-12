// TypeScript mirrors of lait's serde DTOs (src/dto.rs). Fields are snake_case to
// match the wire format. Keep in sync with SCHEMA_VERSION on the Rust side.

export type Priority = "none" | "low" | "medium" | "high" | "urgent";
export type StatusCategory = "backlog" | "active" | "done";

export interface ProjectDto {
  id: string;
  name: string;
  key: string;
  color: string;
}

export interface LabelDto {
  id: string;
  name: string;
  color: string;
}

export interface WorkflowState {
  id: string;
  name: string;
  category: StatusCategory;
  color: string;
}

export interface Row {
  reff: string;
  doc_id: string;
  project_id: string;
  key_alias: string | null;
  title: string;
  status: string;
  priority: Priority;
  assignee_summary: string;
  tombstone: boolean;
  provisional: boolean;
}

export interface CommentDto {
  author: string;
  author_nick: string | null;
  ts: number;
  body: string;
}

export interface IssueView {
  schema_version: number;
  reff: string;
  doc_id: string;
  workspace_id: string;
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
  created_at: number;
  provisional: boolean;
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

export interface StatusInfo {
  kind: "status";
  id: string;
  nick: string;
  room: string;
  online_peers: number;
  workspace: string;
  issues: number;
  projects: number;
}

// The default workflow lait seeds into a fresh catalog (src/dto.rs
// default_workflow). Used for status labels/colors in the list view, which only
// carries the status *id*. The board endpoint returns the authoritative states.
export const DEFAULT_WORKFLOW: WorkflowState[] = [
  { id: "backlog", name: "Backlog", category: "backlog", color: "gray" },
  { id: "in_progress", name: "In Progress", category: "active", color: "blue" },
  { id: "in_review", name: "In Review", category: "active", color: "yellow" },
  { id: "done", name: "Done", category: "done", color: "green" },
];

export const PRIORITIES: Priority[] = ["none", "low", "medium", "high", "urgent"];

export interface MemberDto {
  key: string;
  role: string; // "admin" | "member"
  me: boolean;
}

export interface InviteInfo {
  kind: "invite";
  ticket: string;
  url: string;
  qr: string; // inline SVG markup
}

export interface JoinRequest {
  id: string;
  nick: string;
  ts: number;
}
