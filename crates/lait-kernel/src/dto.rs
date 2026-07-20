//! Layer-B data-transfer objects: the **stable, versioned, hand-maintained
//! projection** of Layer A. These are the shapes the CLI
//! `--json` contract emits and the MCP tools return; they are checked against
//! the MCP tool schemas (see `tests/mcp_parity.rs`) so agent and human surfaces
//! never drift. They are **not** an automatic dump of the Loro layout — a
//! storage refactor must not break these.
//!
//! Also home to the shared plain-domain enums ([`Priority`], [`StatusCategory`],
//! [`WorkflowState`]) used by both the Layer-A wrappers and this projection. A
//! plain enum shared across layers is fine; what the three-layer rule forbids is
//! mirroring the *container layout* automatically.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SpaceId};

/// Schema version gate. Every top-level DTO carries it so a reader
/// can detect drift; bump on any additive change.
///
/// v2: the actor-identity cutover (`lait/actor/1`) — members, assignees, and
/// attribution are keyed by `ActorId` over a self-managed device set, replacing
/// the `person ≡ key ≡ device` model.
///
/// v3: the space-vocabulary flag day — `genesis.json` keys the space id under
/// `space_id`, and every Loro document stamps it under `spaceId`. A v2 store
/// spells both the old way, so a v3 reader would open it and then project an
/// absent space id; see [`MIN_SUPPORTED_SCHEMA`].
pub const SCHEMA_VERSION: u32 = 3;

/// The oldest on-disk schema this build will open.
///
/// A lower bound exists because "older is fine" is only true while every older
/// shape is still *readable*. v2 stores are not: their space id sits under keys
/// v3 does not look at, so opening one succeeds and then silently projects a
/// store with no space. Refusing is the honest outcome — there is no migration,
/// and a store that opens wrong is worse than a store that will not open.
pub const MIN_SUPPORTED_SCHEMA: u32 = 3;

/// Issue priority. Stored inside the issue document as a lowercase
/// string leaf and projected here.
///
/// ```
/// use lait_kernel::dto::Priority;
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

    /// One-letter board badge: `·U/H/M/L·`.
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

/// Workflow-state category. Governs board columns and the completion rule: a
/// `Done`-category status removes the issue from the
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

/// An ordered status column. `id` is the `StatusId` stored on the
/// issue's `status` field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowState {
    pub id: String,
    pub name: String,
    pub category: StatusCategory,
    pub color: String,
}

/// The default workflow seeded into a fresh catalog.
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
// Corruption (the projection honesty policy)
// ----------------------------------------------------------------------------

/// One stored record that could not be projected into its DTO.
///
/// The policy this type exists to enforce: **a projection never lies.** Three
/// states must stay distinct — *known* (stored and parsed), *unknown*
/// (legitimately not available yet, e.g. a provisional row whose body hasn't
/// synced), and *corrupt* (a value is stored and does not conform to its type).
/// Collapsing them is what produced the failure modes this replaces:
///
/// - `Option<ActorId>` on a field that is never optional in the schema, which
///   makes every consumer re-decide what a missing author means;
/// - a silent `continue`/`filter_map`, which makes the record vanish — counts go
///   wrong, positions shift, and a peer writing malformed keys becomes invisible;
/// - a sentinel like `act_0000…`, which is a *well-typed lie* and the worst of
///   the three, because nothing downstream can tell it from a real id.
///
/// A corrupt record is therefore neither dropped nor laundered: it is lifted out
/// of the typed collection and carried alongside it, so the DTO keeps its true
/// types and the corruption stays auditable under `--json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorruptRecord {
    /// Where the record sat, position included: `comments[3]`. This is what
    /// makes a sidecar list lossless — the index the record occupied in the
    /// valid collection is recoverable, so "3rd comment is corrupt" survives.
    pub locus: String,
    /// Which field failed and how: `author: not an ActorId`. Human-readable;
    /// diagnostics, not a machine contract.
    pub reason: String,
    /// Best-effort raw leaves, for forensics and eventual repair. Never
    /// interpreted — this is evidence, not data.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub raw: BTreeMap<String, String>,
}

impl CorruptRecord {
    /// A corrupt record with no salvaged leaves.
    pub fn new(locus: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            locus: locus.into(),
            reason: reason.into(),
            raw: BTreeMap::new(),
        }
    }

    /// Attach a salvaged raw leaf.
    pub fn with_raw(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.raw.insert(key.into(), value.into());
        self
    }
}

/// The result of projecting one stored record: either the DTO, or the reason it
/// isn't one. Layer-A readers return these so that **no read site has to choose
/// between dropping and laundering** — both bad options are off the table
/// because the type has somewhere honest to put the failure.
///
/// Deliberately **not** `Serialize`. A `Projected` cannot reach the wire; it has
/// to be [`partition`]ed first, which is what guarantees a UI consumer can never
/// receive a malformed record inside a field typed as a valid one. The invariant
/// is structural rather than a matter of caller discipline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Projected<T> {
    Valid(T),
    Corrupt(CorruptRecord),
}

impl<T> Projected<T> {
    /// The DTO, if this record projected cleanly.
    pub fn valid(self) -> Option<T> {
        match self {
            Projected::Valid(v) => Some(v),
            Projected::Corrupt(_) => None,
        }
    }

    pub fn is_corrupt(&self) -> bool {
        matches!(self, Projected::Corrupt(_))
    }
}

/// Split a projected sequence into the valid DTOs and the corruption sidecar,
/// preserving the relative order of each. The single point where corruption
/// leaves the typed path — call it once, at the projection boundary.
pub fn partition<T>(items: impl IntoIterator<Item = Projected<T>>) -> (Vec<T>, Vec<CorruptRecord>) {
    let mut valid = Vec::new();
    let mut corrupt = Vec::new();
    for item in items {
        match item {
            Projected::Valid(v) => valid.push(v),
            Projected::Corrupt(c) => corrupt.push(c),
        }
    }
    (valid, corrupt)
}

// ----------------------------------------------------------------------------
// Projections (read DTOs)
// ----------------------------------------------------------------------------

/// A project registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDto {
    pub id: ProjectId,
    pub name: String,
    pub key: String,
    pub color: String,
}

/// A label registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelDto {
    pub id: LabelId,
    pub name: String,
    pub color: String,
}

/// One board or list row, projected from the `DocMeta` cache for rendering.
/// This projection never opens the issue document. A row whose issue body has
/// not arrived is `provisional`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    /// Canonical collision-free short handle, such as `iss_3f9`.
    pub reff: String,
    pub doc_id: DocId,
    pub project_id: ProjectId,
    /// Friendly alias `ENG-142` (may disambiguate to `ENG-142b`), advisory.
    pub key_alias: Option<String>,
    pub title: String,
    pub status: String,
    pub priority: Priority,
    /// Viewer-relative one-liner (`you +2`) — what a terminal row prints.
    pub assignee_summary: String,
    /// The assignee keys behind that summary.
    ///
    /// Both, not one. `assignee_summary` is *rendered* — it resolves "you" against
    /// the local `DeviceId` and collapses the tail into `+2`, which is exactly right
    /// for a CLI row and useless to a client that wants to draw faces. The keys are
    /// already in `RowMeta` (cached viewer-neutrally, precisely so the summary can
    /// be computed per-viewer), so this projects them rather than making every
    /// graphical client open N issue docs to learn what the catalog already knows.
    pub assignees: Vec<ActorId>,
    pub tombstone: bool,
    pub provisional: bool,
}

/// A board column: an ordered slice of rows for one workflow state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardColumn {
    pub state: WorkflowState,
    pub rows: Vec<Row>,
}

/// A rendered board: workflow states with their ordered rows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoardView {
    pub schema_version: u32,
    pub project: ProjectDto,
    pub columns: Vec<BoardColumn>,
}

/// A comment projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommentDto {
    /// The authoring **actor** — the person, stable across their devices.
    ///
    /// Not optional: the schema has no authorless comment, so an `Option` here
    /// would encode *storage corruption* in a *domain* type and push the
    /// decision onto every consumer. A comment whose stored author doesn't parse
    /// as an [`ActorId`] is not a `CommentDto` with a hole in it — it isn't a
    /// `CommentDto` at all, and is projected as a [`CorruptRecord`] instead.
    pub author: ActorId,
    pub author_nick: Option<String>,
    pub ts: u64,
    pub body: String,
}

/// The full issue projection — populated by lazily loading the issue doc
/// `provisional` is set when only the catalog row is known.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueView {
    pub schema_version: u32,
    pub reff: String,
    pub doc_id: DocId,
    pub space_id: SpaceId,
    pub project_id: ProjectId,
    pub project_key: Option<String>,
    pub key_alias: Option<String>,
    pub title: String,
    pub description: String,
    pub status: String,
    pub priority: Priority,
    pub assignees: Vec<ActorId>,
    pub labels: Vec<LabelId>,
    pub label_names: Vec<String>,
    /// Valid comments only. Every element satisfies the `CommentDto` schema —
    /// a consumer may render these as trusted objects without re-validating.
    pub comments: Vec<CommentDto>,
    pub created_by: ActorId,
    pub created_at: u64,
    pub provisional: bool,
    /// Records under this issue that failed to project (see [`CorruptRecord`]).
    ///
    /// Carried beside the typed collections rather than inside them: the
    /// corruption stays auditable under `--json` for the operator who has to
    /// diagnose it, while a normal UI consumer iterating `comments` cannot
    /// accidentally render a malformed record as a trusted one. Absent from the
    /// JSON entirely when empty, so the healthy shape is unchanged and existing
    /// readers keep working.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corrupt_records: Vec<CorruptRecord>,
}

/// One derived activity transition. `changes` is a list so one request, one
/// commit, and one activity row remain equivalent even when several fields
/// change. Clients pull activity via `Activity { since }`; it is not streamed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivityEvent {
    pub seq: u64,
    pub doc_id: Option<DocId>,
    pub reff: String,
    pub kind: String,
    pub changes: Vec<FieldChange>,
    pub actor: Option<DeviceId>,
    pub actor_nick: String,
    pub text: String,
    pub ts: u64,
    /// Non-blocking LWW collision note: a concurrent overwrite was detected.
    pub collision: bool,
}

/// A single field transition inside an [`ActivityEvent`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldChange {
    pub field: String,
    pub from: Option<String>,
    pub to: Option<String>,
}

/// One issue link projected for the graph view. `direction`
/// is relative to the requested issue: `out` = it names the other, `in` = the
/// other names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinkDto {
    /// `blocks` | `relates` | `duplicates`.
    pub kind: String,
    /// `out` | `in`.
    pub direction: String,
    pub row: Row,
}

/// An issue's graph neighborhood (reply to `IssueGraph`): sub-issue hierarchy,
/// links, and the transitively-open blockers — all read from the catalog
/// structure doc, no issue doc opened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphView {
    pub schema_version: u32,
    pub reff: String,
    pub doc_id: DocId,
    pub parent: Option<Row>,
    pub children: Vec<Row>,
    pub links: Vec<LinkDto>,
    /// Issues that transitively block this one and are still open.
    pub blocked_by: Vec<Row>,
}

/// A disambiguation candidate when a reference resolves to multiple issues.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub reff: String,
    pub key_alias: Option<String>,
    pub title: String,
}

/// One inbox item — a remote change **addressed to you**, derived at sync-import
/// time and persisted locally in `inbox.json`. Attribution remains conservative:
/// `actor_nick` is present only for comments (the one in-doc field that carries
/// a real author); assignment/status changes render actor-unknown rather than
/// guessing (S non-goal 6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxEntry {
    /// Local receive time (Unix seconds), used as the advisory read-watermark axis.
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

/// A space member projection. Roles come from the
/// signed ACL graph — the only cryptographically-verified identity in the system.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberDto {
    /// The member's **actor id** (`act_…`), a self-certifying identity over a set
    /// of device keys rather than a raw key. Kept
    /// as `key` for wire compatibility across client projections.
    pub key: String,
    /// `admin` | `member` | `viewer` | `agent`.
    pub role: String,
    /// Whether this is us (this device speaks for the actor).
    pub me: bool,
    /// For an agent, the sponsoring actor; `None` for humans. The agent's
    /// standing dies with this sponsor.
    #[serde(default)]
    pub sponsor: Option<String>,
    /// Local petname you've assigned (empty if none). A private, never-synced
    /// label — the trusted half of the local-petname identity model.
    #[serde(default)]
    pub alias: String,
}

/// One rendered row of the membership audit log (`lait members log`): the signed
/// ACL DAG replayed in causal order with each operation's verdict.
/// This is **cryptographic provenance** (who was authorized to do what),
/// distinct from the advisory activity feed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberLogEntry {
    /// The op's content-address (its DAG node id).
    pub op: String,
    /// The signing author's key (verified — the signature covers the op).
    pub actor: String,
    /// "add_member" | "remove_member" | "set_role" | "add_agent" | "unknown".
    pub kind: String,
    /// The subject key the op acts on (absent for an undecodable op).
    #[serde(default)]
    pub subject: Option<String>,
    /// "admin" | "member" for role-bearing ops.
    #[serde(default)]
    pub role: Option<String>,
    /// Whether replay honored the op (false = unauthorized or undecodable).
    pub authorized: bool,
}

/// A pending join request: someone who announced a join (via `connect`/`join`)
/// and is not yet a member. Derived from the presence event log, not persisted —
/// the request survives only as long as the daemon's event ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinRequestDto {
    /// The requester's ed25519 key (64-hex) — feed straight to `members approve`.
    pub key: String,
    /// Advisory display nick they announced.
    pub nick: String,
    /// When the request was last seen (unix seconds).
    pub ts: u64,
}

/// A pinned seed ("remote") projection for `seed ls` / `remote ls`. A seed
/// is a bootstrap + backfill anchor, never a trust authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedDto {
    /// The seed's endpoint id (== its ed25519 key, 64-hex).
    pub id: String,
    /// Advisory nick (empty when pinned by bare id).
    pub nick: String,
    /// The space id the seed serves.
    pub space: String,
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
