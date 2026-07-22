//! The product World contract (C4.2) — the frozen Rust mirror of
//! `docs/plans/04-product-world-contract.md`.
//!
//! The World is pure: the daemon adapter mints every id, stamps every
//! timestamp, and resolves every ref/alias **into** the intent before submit.
//! Intents, queries, and effects are canonical JSON (the product's Layer-B
//! convention). Membership authority is mechanics, never a product Body.

use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
use serde::{Deserialize, Serialize};

/// The product World id.
pub const PRODUCT_WORLD: &str = "com.lait.issues";
/// The issue Body schema.
pub const ISSUE_SCHEMA: &str = "issue";
pub const ISSUE_SCHEMA_VERSION: u32 = 1;
pub const ISSUE_ENCODING: &str = "lait.issue.v1";
/// The catalog Body schema (one Body per Space).
pub const CATALOG_SCHEMA: &str = "catalog";
pub const CATALOG_SCHEMA_VERSION: u32 = 1;
pub const CATALOG_ENCODING: &str = "lait.catalog.v1";

/// The legacy projection schema version carried by every view DTO.
pub const VIEW_SCHEMA_VERSION: u32 = 3;

/// The link kinds, frozen.
pub const LINK_KINDS: [&str; 3] = ["blocks", "relates", "duplicates"];
/// The default status a fresh issue carries.
pub const DEFAULT_STATUS: &str = "backlog";

pub fn world_id() -> WorldId {
    WorldId::parse(PRODUCT_WORLD).expect("product world id")
}

// ---- Authorization demands (plan 04 policy vocabulary) --------------------
//
// The World declares a canonical non-empty demand for every mutation and
// query; Mechanics evaluates it at the pinned authority frontier. These are
// the frozen constructors from plan 04's routing table.

use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};

/// The Space-level resource of the Issues World.
fn space_resource() -> PolicyResource {
    PolicyResource::space(PRODUCT_WORLD)
}

/// A Space-scoped capability of the Issues World.
fn space_cap(name: &str) -> PolicyCapability {
    PolicyCapability::new(PRODUCT_WORLD, name)
}

/// `Require(space.admin, Space)` — the admin demand.
pub fn demand_admin() -> Vec<u8> {
    AuthorizationDemand::require(space_cap("space.admin"), space_resource())
        .encode_canonical()
        .expect("canonical admin demand")
}

/// `Any(Require(space.contributor, Space), Require(space.admin, Space))` — the
/// ordinary contributor demand, with admin as an explicit override.
pub fn demand_contributor() -> Vec<u8> {
    AuthorizationDemand::Any(vec![
        AuthorizationDemand::require(space_cap("space.contributor"), space_resource()),
        AuthorizationDemand::require(space_cap("space.admin"), space_resource()),
    ])
    .encode_canonical()
    .expect("canonical contributor demand")
}

/// `Require(space.issue.read, Space)` — every query's read demand.
pub fn demand_read() -> Vec<u8> {
    AuthorizationDemand::require(space_cap("space.issue.read"), space_resource())
        .encode_canonical()
        .expect("canonical read demand")
}

/// The full Space capability set the founder is granted at formation:
/// `(capability, resource)` pairs, plus the Mechanics meta policy-admin grant.
pub fn founder_capabilities() -> Vec<(PolicyCapability, PolicyResource)> {
    ["space.admin", "space.contributor", "space.issue.read"]
        .into_iter()
        .map(|c| (space_cap(c), space_resource()))
        .collect()
}

pub fn issue_schema() -> SchemaId {
    SchemaId::parse(ISSUE_SCHEMA).expect("issue schema id")
}

pub fn catalog_schema() -> SchemaId {
    SchemaId::parse(CATALOG_SCHEMA).expect("catalog schema id")
}

pub fn issue_encoding() -> EncodingId {
    EncodingId::parse(ISSUE_ENCODING).expect("issue encoding id")
}

pub fn catalog_encoding() -> EncodingId {
    EncodingId::parse(CATALOG_ENCODING).expect("catalog encoding id")
}

/// The one catalog Body per Space.
pub fn catalog_body_id() -> BodyId {
    let digest = blake3::hash(b"lait/catalog-body/1");
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest.as_bytes()[..16]);
    BodyId::from_bytes(raw)
}

/// The Body id of an issue: derived deterministically from its `iss_` DocId.
pub fn issue_body_id(doc: &str) -> BodyId {
    let mut h = blake3::Hasher::new();
    h.update(b"lait/issue-body/1");
    h.update(doc.as_bytes());
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&h.finalize().as_bytes()[..16]);
    BodyId::from_bytes(raw)
}

pub fn catalog_key() -> BodyKey {
    BodyKey::new(world_id(), catalog_body_id())
}

pub fn issue_key(doc: &str) -> BodyKey {
    BodyKey::new(world_id(), issue_body_id(doc))
}

/// The catalog board list path for a project.
pub fn board_path(project: &str) -> String {
    format!("board/{}", project.to_ascii_lowercase())
}

/// A board position, resolved to DocIds by the daemon before submit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "at", rename_all = "snake_case")]
pub enum Pos {
    Top,
    Bottom,
    Before { doc: String },
    After { doc: String },
}

/// A label minted by this transaction (create-on-first-use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewLabel {
    pub id: String,
    pub name: String,
    pub color: String,
}

/// The work-state actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkAction {
    Start,
    Done,
    Stop,
}

/// The product intents (schema `issue` v1). Every id/timestamp is supplied by
/// the daemon; the World validates and stages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum IssueIntent {
    /// Seed the catalog Body at Space formation: display name + the default
    /// workflow. Idempotent by content.
    SpaceInit { name: String, ts: u64 },
    IssueNew {
        doc: String,
        project: String,
        title: String,
        priority: String,
        assignees: Vec<String>,
        labels: Vec<String>,
        new_labels: Vec<NewLabel>,
        body: Option<String>,
        actor: String,
        device: String,
        ts: u64,
    },
    IssueEdit {
        doc: String,
        title: Option<String>,
        status: Option<String>,
        priority: Option<String>,
        description: Option<String>,
        device: String,
        ts: u64,
    },
    IssueMove {
        doc: String,
        project: Option<String>,
        pos: Option<Pos>,
        device: String,
        ts: u64,
    },
    Assign {
        doc: String,
        who: Vec<String>,
        add: bool,
        device: String,
        ts: u64,
    },
    Label {
        doc: String,
        add: Vec<String>,
        new_labels: Vec<NewLabel>,
        remove: Vec<String>,
        device: String,
        ts: u64,
    },
    Comment {
        doc: String,
        body: String,
        actor: String,
        device: String,
        ts: u64,
    },
    SetTombstone {
        doc: String,
        on: bool,
        device: String,
        ts: u64,
    },
    Link {
        doc: String,
        kind: String,
        target: String,
        add: bool,
        device: String,
        ts: u64,
    },
    Parent {
        doc: String,
        parent: Option<String>,
        device: String,
        ts: u64,
    },
    WorkState {
        doc: String,
        action: WorkAction,
        actor: String,
        device: String,
        ts: u64,
    },
    ProjectNew {
        id: String,
        name: String,
        key: String,
        device: String,
        ts: u64,
    },
    LabelNew {
        id: String,
        name: String,
        color: String,
        device: String,
        ts: u64,
    },
}

impl IssueIntent {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("intent json")
    }
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// The product queries (read the committed snapshot; derive projections).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum IssueQuery {
    /// The full catalog snapshot the daemon derives refs/aliases and
    /// choose-project from.
    Snapshot,
    View {
        doc: String,
        /// The viewer's actor (for `assignee_summary`), if known.
        me: Option<String>,
    },
    List {
        project: Option<String>,
        label: Option<String>,
        status: Option<String>,
        mine: Option<String>,
        all: bool,
        me: Option<String>,
    },
    Board {
        project: String,
        me: Option<String>,
    },
    Graph {
        doc: String,
        me: Option<String>,
    },
    History {
        doc: String,
    },
    Projects,
    Labels,
}

impl IssueQuery {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("query json")
    }
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// The effect every mutating intent returns: the DocId(s) it touched (the
/// daemon renders the canonical reff).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueEffect {
    pub doc: Option<String>,
    /// Whether the intent was an idempotent no-op (nothing staged).
    #[serde(default)]
    pub unchanged: bool,
}

impl IssueEffect {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("effect json")
    }
    pub fn from_json(bytes: &[u8]) -> Option<Self> {
        serde_json::from_slice(bytes).ok()
    }
}

/// One durable history event appended to an issue's `events` list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssueEvent {
    /// The request kind (`created`, `edited`, `assigned`, …).
    pub k: String,
    /// The committing device (advisory attribution).
    pub d: String,
    /// Unix seconds.
    pub t: u64,
    /// Field changes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub c: Vec<EventChange>,
    /// Free text (comment body, link summary).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub x: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventChange {
    pub f: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
}

/// A stored comment list element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredComment {
    pub a: String,
    pub t: u64,
    pub b: String,
}

/// The default workflow, exactly the legacy seed.
pub fn default_workflow() -> Vec<serde_json::Value> {
    vec![
        serde_json::json!({"id":"backlog","name":"Backlog","category":"backlog","color":"gray"}),
        serde_json::json!({"id":"in_progress","name":"In Progress","category":"active","color":"blue"}),
        serde_json::json!({"id":"in_review","name":"In Review","category":"active","color":"yellow"}),
        serde_json::json!({"id":"done","name":"Done","category":"done","color":"green"}),
    ]
}
