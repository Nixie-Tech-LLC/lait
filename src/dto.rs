//! Layer-B data-transfer objects: the **stable, versioned, hand-maintained
//! projection** of Layer A (SCHEMA §1, §7.3). These are the shapes the CLI
//! `--json` contract emits and the MCP tools return; they are checked against
//! the MCP tool schemas (see `tests/mcp_parity.rs`) so agent and human surfaces
//! never drift. They are **not** an automatic dump of the Loro layout — a
//! storage refactor must not break these.
//!
//! Also home to the shared plain-domain enums ([`Priority`], [`StatusCategory`],
//! [`WorkflowState`]) used by both the Layer-A wrappers and this projection. A
//! plain enum shared across layers is fine; what the three-layer rule forbids is
//! mirroring the *container layout* automatically.

use serde::{Deserialize, Serialize};

use crate::ids::{DocId, LabelId, ProjectId, UserId, WorkspaceId};

/// Schema version gate (SCHEMA §9). Every top-level DTO carries it so a reader
/// can detect drift; bump on any additive change.
pub const SCHEMA_VERSION: u32 = 1;

/// Issue priority (SCHEMA §5). Stored inside the issue doc as a lowercase
/// string leaf and projected here.
///
/// ```
/// use lait::dto::Priority;
/// assert_eq!(Priority::parse("urgent"), Some(Priority::Urgent));
/// assert_eq!(Priority::parse("h"), Some(Priority::High)); // one-letter alias
/// assert!(Priority::Urgent > Priority::Low);              // orders low→high
/// assert_eq!(serde_json::to_string(&Priority::High).unwrap(), "\"high\"");
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    #[default]
    None,
    Low,
    Medium,
    High,
    Urgent,
}

impl Priority {
    pub fn as_str(&self) -> &'static str {
        match self {
            Priority::None => "none",
            Priority::Low => "low",
            Priority::Medium => "medium",
            Priority::High => "high",
            Priority::Urgent => "urgent",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s.to_ascii_lowercase().as_str() {
            "none" | "" => Priority::None,
            "low" | "l" => Priority::Low,
            "medium" | "med" | "m" => Priority::Medium,
            "high" | "h" => Priority::High,
            "urgent" | "u" => Priority::Urgent,
            _ => return None,
        })
    }

    /// One-letter board badge (UI.md §5.1: `·U/H/M/L·`).
    pub fn badge(&self) -> &'static str {
        match self {
            Priority::None => "-",
            Priority::Low => "L",
            Priority::Medium => "M",
            Priority::High => "H",
            Priority::Urgent => "U",
        }
    }
}

/// Workflow-state category (SCHEMA §4). Governs board columns and the
/// completion rule (S§5.7): a `Done`-category status removes the issue from the
/// board movable list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatusCategory {
    Backlog,
    Active,
    Done,
}

impl StatusCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            StatusCategory::Backlog => "backlog",
            StatusCategory::Active => "active",
            StatusCategory::Done => "done",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "backlog" => StatusCategory::Backlog,
            "active" => StatusCategory::Active,
            "done" => StatusCategory::Done,
            _ => return None,
        })
    }
}

/// An ordered status column (SCHEMA §4). `id` is the `StatusId` stored on the
/// issue's `status` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowState {
    pub id: String,
    pub name: String,
    pub category: StatusCategory,
    pub color: String,
}

/// The default workflow seeded into a fresh Catalog (UI.md §5.1 board columns).
pub fn default_workflow() -> Vec<WorkflowState> {
    vec![
        WorkflowState {
            id: "backlog".into(),
            name: "Backlog".into(),
            category: StatusCategory::Backlog,
            color: "gray".into(),
        },
        WorkflowState {
            id: "in_progress".into(),
            name: "In Progress".into(),
            category: StatusCategory::Active,
            color: "blue".into(),
        },
        WorkflowState {
            id: "in_review".into(),
            name: "In Review".into(),
            category: StatusCategory::Active,
            color: "yellow".into(),
        },
        WorkflowState {
            id: "done".into(),
            name: "Done".into(),
            category: StatusCategory::Done,
            color: "green".into(),
        },
    ]
}

/// The default status id a brand-new issue lands in.
pub const DEFAULT_STATUS: &str = "backlog";

// ----------------------------------------------------------------------------
// Projections (read DTOs)
// ----------------------------------------------------------------------------

/// A project registry entry (SCHEMA §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDto {
    pub id: ProjectId,
    pub name: String,
    pub key: String,
    pub color: String,
}

/// A label registry entry (SCHEMA §4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelDto {
    pub id: LabelId,
    pub name: String,
    pub color: String,
}

/// One board/list row — the `DocMeta` cache projected for rendering (SCHEMA §4,
/// §7.4). Never opens the issue doc. A row whose issue body hasn't arrived is
/// `provisional` (UI.md §3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Canonical short handle (`iss_3f9`), the collision-free id (S§5.4).
    pub reff: String,
    pub doc_id: DocId,
    pub project_id: ProjectId,
    /// Friendly alias `ENG-142` (may disambiguate to `ENG-142b`), advisory.
    pub key_alias: Option<String>,
    pub title: String,
    pub status: String,
    pub priority: Priority,
    pub assignee_summary: String,
    pub tombstone: bool,
    pub provisional: bool,
}

/// A board column: an ordered slice of rows for one workflow state (UI.md §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardColumn {
    pub state: WorkflowState,
    pub rows: Vec<Row>,
}

/// A rendered board — workflow states × ordered rows (UI.md §5.1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardView {
    pub schema_version: u32,
    pub project: ProjectDto,
    pub columns: Vec<BoardColumn>,
}

/// A comment projection (SCHEMA §5.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentDto {
    pub author: UserId,
    pub author_nick: Option<String>,
    pub ts: u64,
    pub body: String,
}

/// The full issue projection — populated by lazily loading the issue doc
/// (UI.md §5.3). `provisional` when only the catalog row is known (§3.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueView {
    pub schema_version: u32,
    pub reff: String,
    pub doc_id: DocId,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub project_key: Option<String>,
    pub key_alias: Option<String>,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: Priority,
    pub assignees: Vec<UserId>,
    pub labels: Vec<LabelId>,
    pub label_names: Vec<String>,
    pub comments: Vec<CommentDto>,
    pub created_by: UserId,
    pub created_at: u64,
    pub provisional: bool,
}

/// One derived activity transition (SCHEMA §7.4). `changes` is a **list** so one
/// Request = one commit = one activity row even when it moved several fields
/// (S§7.1). Pulled via `Activity{since}`, never force-streamed (S§7.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub seq: u64,
    pub doc_id: Option<DocId>,
    pub reff: String,
    pub kind: String,
    pub changes: Vec<FieldChange>,
    pub actor: Option<UserId>,
    pub actor_nick: String,
    pub text: String,
    pub ts: u64,
    /// Non-blocking LWW collision note (A§9): concurrent overwrite detected.
    pub collision: bool,
}

/// A single field transition inside an [`ActivityEvent`] (SCHEMA §7.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// A disambiguation candidate when a ref resolves to many (UI.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub reff: String,
    pub key_alias: Option<String>,
    pub title: String,
}

/// One inbox item — a remote change **addressed to you**, derived at sync-import
/// time and persisted locally (S§8.1 `inbox.json`). Attribution-honest:
/// `actor_nick` is present only for comments (the one in-doc field that carries
/// a real author); assignment/status changes render actor-unknown rather than
/// guessing (S non-goal 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Local receive time (unix secs) — the read-watermark axis (advisory, S§2).
    pub ts: u64,
    /// `assigned` | `comment` | `status`.
    pub kind: String,
    pub reff: String,
    pub doc_id: String,
    pub title: String,
    /// One human line: the comment body, or the status transition.
    pub detail: String,
    /// The attributed author's key (comments only — the one in-doc field with a
    /// real author; `None` = actor unknown). Durable truth in `inbox.json`.
    #[serde(default)]
    pub actor: Option<String>,
    /// The author's display nick, resolved by the daemon at read time from its
    /// live directory (presence nicks + local petnames). Never persisted.
    #[serde(default)]
    pub actor_nick: Option<String>,
}

/// A workspace member projection (P3 members view, UI.md §8). Roles come from the
/// signed ACL graph — the only cryptographically-verified identity in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDto {
    pub key: UserId,
    /// "admin" | "member".
    pub role: String,
    /// Whether this is us.
    pub me: bool,
    /// Local petname you've assigned to this key (empty if none). A private,
    /// never-synced label — the trusted half of the local-petname identity model.
    #[serde(default)]
    pub alias: String,
}

/// A pending join request: someone who announced a join (via `connect`/`join`)
/// and is not yet a member. Derived from the presence event log, not persisted —
/// the request survives only as long as the daemon's event ring (UI.md §8).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestDto {
    /// The requester's ed25519 key (64-hex) — feed straight to `members approve`.
    pub key: String,
    /// Advisory display nick they announced.
    pub nick: String,
    /// When the request was last seen (unix seconds).
    pub ts: u64,
}

/// A pinned seed ("remote") projection for `seed ls` / `remote ls` (A§10). A seed
/// is a bootstrap + backfill anchor, never a trust authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedDto {
    /// The seed's endpoint id (== its ed25519 key, 64-hex).
    pub id: String,
    /// Advisory nick (empty when pinned by bare id).
    pub nick: String,
    /// The workspace id the seed serves.
    pub workspace: String,
    /// "online" | "away" | "offline" from the live presence map.
    pub state: String,
    /// Whether the seed is currently reachable.
    pub online: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn priority_roundtrips() {
        for p in [
            Priority::None,
            Priority::Low,
            Priority::Medium,
            Priority::High,
            Priority::Urgent,
        ] {
            assert_eq!(Priority::parse(p.as_str()), Some(p));
        }
        assert_eq!(Priority::parse("U"), Some(Priority::Urgent));
        assert_eq!(Priority::parse("h"), Some(Priority::High));
        assert_eq!(Priority::parse("bogus"), None);
    }

    #[test]
    fn priority_orders_low_to_high() {
        assert!(Priority::Urgent > Priority::High);
        assert!(Priority::High > Priority::Low);
    }

    #[test]
    fn default_workflow_has_one_done_column() {
        let wf = default_workflow();
        assert_eq!(
            wf.iter()
                .filter(|w| w.category == StatusCategory::Done)
                .count(),
            1
        );
        assert!(wf.iter().any(|w| w.id == DEFAULT_STATUS));
    }

    #[test]
    fn priority_json_is_lowercase() {
        assert_eq!(
            serde_json::to_string(&Priority::Urgent).unwrap(),
            "\"urgent\""
        );
    }
}
