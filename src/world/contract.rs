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
/// The longest reaction emoji accepted, in UTF-8 bytes (a ZWJ family sequence
/// fits; a paragraph does not).
pub const MAX_REACTION_EMOJI_BYTES: usize = 32;
/// The largest accepted estimate. Every scale humans use tops out far below
/// this; the cap exists so a typo cannot become a permanent register.
pub const MAX_ESTIMATE: u32 = 1000;
/// Attachment bounds (CREATE-5): inline sealed records riding the issue Body
/// and its existing sync/E2EE. Deliberately tight — the content-addressed
/// blob store is the large-file follow-on, not this.
pub const MAX_ATTACHMENT_BYTES: usize = 256 * 1024;
pub const MAX_ATTACHMENTS_PER_ISSUE: usize = 8;
/// The triage outcomes, frozen.
pub const TRIAGE_OUTCOMES: [&str; 3] = ["accepted", "declined", "duplicate"];
/// The self-reported health labels (project updates, initiatives).
pub const HEALTH_LABELS: [&str; 3] = ["on_track", "at_risk", "off_track"];

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

/// `Any(Require(<capability>, Space), Require(space.admin, Space))` — a
/// Space-scoped registry/policy mutation with the explicit admin override.
pub fn demand_space_any(capability: &str) -> Vec<u8> {
    AuthorizationDemand::Any(vec![
        AuthorizationDemand::require(space_cap(capability), space_resource()),
        AuthorizationDemand::require(space_cap("space.admin"), space_resource()),
    ])
    .encode_canonical()
    .expect("canonical space-any demand")
}

/// `Any(Require(<capability>, Project(<id>)), Require(space.admin, Space))` —
/// a Project-scoped mutation with the explicit admin override (the shape
/// `project.delete` uses).
pub fn demand_project_any(capability: &str, project: &str) -> Vec<u8> {
    AuthorizationDemand::Any(vec![
        AuthorizationDemand::require(
            space_cap(capability),
            PolicyResource::project(PRODUCT_WORLD, project),
        ),
        AuthorizationDemand::require(space_cap("space.admin"), space_resource()),
    ])
    .encode_canonical()
    .expect("canonical project-any demand")
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

// ---- Capability registry v1 (plan 04) -------------------------------------
//
// The registry is part of the implementation descriptor's policy-table
// commitment, NOT editable Catalog state; changing an entry requires a new
// implementation id, and entries are never repurposed in place.

/// The Space-scoped capability ids, sorted.
pub const SPACE_CAPABILITIES: [&str; 8] = [
    "catalog.label.configure",
    "catalog.workflow.configure",
    "policy.assign",
    "policy.configure",
    "project.create",
    "space.admin",
    "space.contributor",
    "space.issue.read",
];

/// The Project-scoped capability ids, sorted. `workflow.transition.<id>` is a
/// qualified family validated by grammar, not enumerated here.
pub const PROJECT_CAPABILITIES: [&str; 14] = [
    "comment.create",
    "issue.assign",
    "issue.create",
    "issue.delete",
    "issue.edit",
    "issue.label",
    "issue.link",
    "issue.move_in",
    "issue.move_out",
    "issue.parent",
    "issue.restore",
    "project.configure",
    "project.delete",
    "workflow.transition",
];

/// The canonical exhaustive registry bytes: one line per entry,
/// `scope id delegable`, sorted. The `workflow.transition` row stands for
/// the qualified `workflow.transition.<TransitionId>` family.
pub fn capability_registry_bytes() -> Vec<u8> {
    let mut out = String::new();
    for id in SPACE_CAPABILITIES {
        out.push_str("space	");
        out.push_str(id);
        out.push_str(
            "	delegable
",
        );
    }
    for id in PROJECT_CAPABILITIES {
        out.push_str("project	");
        out.push_str(id);
        out.push_str(
            "	delegable
",
        );
    }
    out.into_bytes()
}

/// The policy-table commitment (plan 01): BLAKE3 derive-key, context
/// `lait.world-policy-table.v1`, over the exhaustive registry bytes. This is
/// the commitment the implementation descriptor embeds.
pub fn capability_registry_commitment() -> [u8; 32] {
    blake3::derive_key("lait.world-policy-table.v1", &capability_registry_bytes())
}

/// Whether `name` is a registered Space-scoped capability.
pub fn is_space_capability(name: &str) -> bool {
    SPACE_CAPABILITIES.contains(&name)
}

/// Whether `name` is a registered Project-scoped capability (including the
/// qualified `workflow.transition.<TransitionId>` family).
pub fn is_project_capability(name: &str) -> bool {
    if PROJECT_CAPABILITIES.contains(&name) {
        return true;
    }
    name.strip_prefix("workflow.transition.").is_some_and(|t| {
        !t.is_empty()
            && t.len() <= 64
            && t.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
    })
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

/// The ONE deterministic catalog Body per Space: the first 16 bytes of the
/// BLAKE3 derive-key digest, context `lait.issues.catalog.v1`, over the
/// canonical `(SpaceId, WorldId)` bytes (each length-prefixed big-endian).
/// Joiners adopt this Body through Manifest synchronization; nobody ever
/// creates it locally except the founder's one `InitializeTracker`.
pub fn catalog_body_id(space: &mechanics::ids::SpaceId) -> BodyId {
    let space_bytes = space.as_str().as_bytes();
    let world_bytes = PRODUCT_WORLD.as_bytes();
    let mut input = Vec::with_capacity(4 + space_bytes.len() + world_bytes.len());
    input.extend_from_slice(&(space_bytes.len() as u16).to_be_bytes());
    input.extend_from_slice(space_bytes);
    input.extend_from_slice(&(world_bytes.len() as u16).to_be_bytes());
    input.extend_from_slice(world_bytes);
    let digest = blake3::derive_key("lait.issues.catalog.v1", &input);
    let mut raw = [0u8; 16];
    raw.copy_from_slice(&digest[..16]);
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

pub fn catalog_key(space: &mechanics::ids::SpaceId) -> BodyKey {
    BodyKey::new(world_id(), catalog_body_id(space))
}

pub fn issue_key(doc: &str) -> BodyKey {
    BodyKey::new(world_id(), issue_body_id(doc))
}

/// The catalog board list path for a project.
pub fn board_path(project: &str) -> String {
    format!("board/{}", project.to_ascii_lowercase())
}

/// The reactions set path for one comment. Comment ids are canonically
/// lowercase (`cmt_` + lowercased ULID) precisely so they are path-legal —
/// the frozen path grammar admits only `[a-z0-9_]`.
pub fn reaction_path(comment_id: &str) -> String {
    format!("reactions/{comment_id}")
}

/// Whether `s` is a canonical comment id: `cmt_` + a 26-character lowercased
/// ULID in the kernel's base32 alphabet (`0-9` then `a-v`, the lowercase of
/// [`mechanics::ids`]' encoder). The daemon mints and lowercases; the World
/// re-validates because ids arrive inside the intent.
pub fn is_comment_id(s: &str) -> bool {
    s.strip_prefix("cmt_").is_some_and(|ulid| {
        ulid.len() == 26
            && ulid
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b))
    })
}

/// One reaction as stored in a comment's reactions set: `emoji \t actor`.
/// A set (not a map) so two actors reacting concurrently never clobber, and
/// add-wins semantics keep a reaction that raced its own removal.
pub fn reaction_value(emoji: &str, actor: &str) -> Vec<u8> {
    format!("{emoji}\t{actor}").into_bytes()
}

/// Parse a stored reaction value back into `(emoji, actor)`.
pub fn parse_reaction_value(raw: &[u8]) -> Option<(String, String)> {
    let s = std::str::from_utf8(raw).ok()?;
    let (emoji, actor) = s.split_once('\t')?;
    if emoji.is_empty() || actor.is_empty() {
        return None;
    }
    Some((emoji.to_string(), actor.to_string()))
}

/// Whether `emoji` is acceptable as a reaction: non-empty, bounded, and free
/// of the control/whitespace bytes the storage encoding reserves.
pub fn is_reaction_emoji(emoji: &str) -> bool {
    !emoji.is_empty()
        && emoji.len() <= MAX_REACTION_EMOJI_BYTES
        && !emoji.chars().any(|c| c.is_control() || c.is_whitespace())
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

/// Deserialize a present field (including an explicit `null`) as the OUTER
/// `Some` of a double option — absent stays `None` via `#[serde(default)]`.
fn double_option<'de, T, D>(de: D) -> Result<Option<Option<T>>, D::Error>
where
    T: Deserialize<'de>,
    D: serde::Deserializer<'de>,
{
    Deserialize::deserialize(de).map(Some)
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
    /// The ONE founder-only, crash-resumable formation intent: it atomically
    /// creates the deterministic Catalog with the captured display name,
    /// initialization timestamp, initial project, the built-in role
    /// definitions, the capability-registry commitment, and the default
    /// workflow revision. The composition root persists the complete signed
    /// action before submission and replays the exact bytes after a crash;
    /// the World is a deterministic pure validator/stager (no clock, no id
    /// generator). Joiners adopt the Catalog through Manifest synchronization
    /// and never synthesize it locally.
    InitializeTracker {
        name: String,
        ts: u64,
        project_id: String,
        project_name: String,
        project_key: String,
        device: String,
        /// `(role_id, revision_id hex, definition digest hex)` for the three
        /// built-ins — validated against the golden compiled-in definitions.
        built_in_roles: Vec<(String, String, String)>,
        /// Hex of [`capability_registry_commitment`].
        capability_registry_commitment: String,
        /// Hex of the initial project's default workflow revision id.
        default_workflow_commitment: String,
    },
    IssueNew {
        doc: String,
        project: String,
        title: String,
        priority: String,
        assignees: Vec<String>,
        labels: Vec<String>,
        new_labels: Vec<NewLabel>,
        body: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duedate: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        estimate: Option<u32>,
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
        /// Double-option: absent = untouched, `Some(None)` (JSON `null`) =
        /// clear, `Some(Some(ts))` = set (unix seconds). The custom
        /// deserializer is what keeps `null` distinct from absent — serde's
        /// default reads both as the outer `None`.
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        duedate: Option<Option<u64>>,
        /// Same shape as `duedate`; points on whatever scale the team reads.
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        estimate: Option<Option<u32>>,
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
        /// Daemon-minted canonical comment id. Optional for wire compatibility
        /// with pre-identity intents; a comment stored without one cannot
        /// anchor reactions or replies.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<String>,
        /// The id of the comment being replied to, when this is a reply.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        actor: String,
        device: String,
        ts: u64,
    },
    /// Toggle one actor's emoji reaction on one comment. Deliberately writes
    /// **no history event**: a reaction is a social signal, not a change of
    /// record, and history rows for every 👍 would bury the changes that are.
    React {
        doc: String,
        /// The target comment's canonical id.
        comment: String,
        emoji: String,
        actor: String,
        /// `true` adds, `false` removes.
        on: bool,
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
        color: String,
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
    /// Rename and/or recolor a project in place. `key` is deliberately not
    /// editable — it seeds every alias. An in-place `map_set` over the same
    /// catalog key; LWW, `project.configure`-gated.
    ProjectEdit {
        id: String,
        name: Option<String>,
        color: Option<String>,
        description: Option<String>,
        lead: Option<String>,
        /// Outer `None` leaves the date untouched; inner `None` clears it.
        start_date: Option<Option<u64>>,
        target_date: Option<Option<u64>>,
        /// Soft-hide toggle: `None` leaves it, `Some(bool)` sets it (CUSTOM-9).
        archived: Option<bool>,
        /// Owning team id: `None` leaves it, `Some("")` clears (GOV-7).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        team: Option<String>,
        device: String,
        ts: u64,
    },
    /// Hard-delete an EMPTY project (CUSTOM-10 safe v1): refused while any
    /// issue — live or tombstoned — still carries its `projectid`, else every
    /// project-keyed catalog entry is removed. `project.delete`-gated (with
    /// the admin override).
    ProjectDelete { id: String, device: String, ts: u64 },
    /// Toggle one actor's subscription to an issue (INBOX-9). Like `React`,
    /// writes no history event — following is a personal signal, not a change
    /// of record.
    Follow {
        doc: String,
        actor: String,
        on: bool,
        device: String,
        ts: u64,
    },
    /// Create or edit a project milestone (SCOPE-1): the daemon mints the id
    /// on create; the whole record is rewritten so untouched fields survive.
    MilestoneSet {
        project_id: String,
        id: String,
        name: Option<String>,
        /// Outer `None` leaves the date; inner `None` clears it.
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        target_date: Option<Option<u64>>,
        tombstone: Option<bool>,
        device: String,
        ts: u64,
    },
    /// Point an issue at a milestone (or clear it).
    IssueMilestone {
        doc: String,
        milestone: Option<String>,
        device: String,
        ts: u64,
    },
    /// Create or edit a cycle (BOARD-11); same record shape as milestones.
    CycleSet {
        project_id: String,
        id: String,
        name: Option<String>,
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        start: Option<Option<u64>>,
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        end: Option<Option<u64>>,
        tombstone: Option<bool>,
        device: String,
        ts: u64,
    },
    /// Schedule an issue into a cycle (or clear it).
    IssueCycle {
        doc: String,
        cycle: Option<String>,
        device: String,
        ts: u64,
    },
    /// Create or edit an initiative (SCOPE-8). Membership arrives as the
    /// complete replacement list (the router merges add/remove against the
    /// snapshot), so the record write is LWW-whole like `projects`.
    InitiativeSet {
        id: String,
        name: Option<String>,
        description: Option<String>,
        owner: Option<String>,
        health: Option<String>,
        #[serde(
            default,
            deserialize_with = "double_option",
            skip_serializing_if = "Option::is_none"
        )]
        target_date: Option<Option<u64>>,
        projects: Option<Vec<String>>,
        tombstone: Option<bool>,
        device: String,
        ts: u64,
    },
    /// Create or edit a team (GOV-7). `key` binds at creation and is
    /// immutable after (it seeds nothing yet, but the project-key rule is the
    /// convention). Members arrive as the complete replacement list.
    TeamSet {
        id: String,
        name: Option<String>,
        key: Option<String>,
        icon: Option<String>,
        lead: Option<String>,
        members: Option<Vec<String>>,
        tombstone: Option<bool>,
        device: String,
        ts: u64,
    },
    /// Report work into the triage intake queue (SCOPE-7) — outside every
    /// project workflow until reviewed.
    TriageSubmit {
        id: String,
        title: String,
        body: String,
        source: String,
        actor: String,
        device: String,
        ts: u64,
    },
    /// Decide a pending triage item exactly once. `accepted` atomically
    /// creates the issue (`doc` = the daemon-minted DocId, `project`
    /// required) in the same transaction that stamps the outcome; `duplicate`
    /// names the existing issue in `doc`; `declined` needs neither.
    TriageDecide {
        id: String,
        outcome: String,
        project: Option<String>,
        doc: Option<String>,
        note: String,
        actor: String,
        device: String,
        ts: u64,
    },
    /// Attach a bounded file to an issue (CREATE-5): a sealed record in the
    /// issue Body's `attachments` map, riding the existing sync and E2EE.
    Attach {
        doc: String,
        id: String,
        name: String,
        mime: String,
        data_b64: String,
        comment: Option<String>,
        actor: String,
        device: String,
        ts: u64,
    },
    /// Remove an attachment record.
    Detach {
        doc: String,
        id: String,
        device: String,
        ts: u64,
    },
    /// Append an immutable status update to a project's feed (SCOPE-1). A
    /// grow-only `project_updates` log entry keyed `<project>/<id>`;
    /// `project.configure`-gated like the other project mutations.
    ProjectUpdatePost {
        project_id: String,
        id: String,
        author: String,
        body: String,
        health: String,
        device: String,
        ts: u64,
    },
    /// Rename and/or recolor a label in place. Issues reference labels by id,
    /// so a rename re-points every use for free. `catalog.label.configure`-gated.
    LabelEdit {
        id: String,
        name: Option<String>,
        color: Option<String>,
        device: String,
        ts: u64,
    },
    /// Remove a label from the registry. Ids left on issues resolve to the raw id
    /// (graceful degradation), so this is a hard `MapRemove`. `catalog.label.configure`-gated.
    LabelDelete { id: String, device: String, ts: u64 },
    /// Set the space's mutable display label. The genesis/seed id is
    /// name-independent, so this is a plain LWW `RegisterSet` on the catalog
    /// `name` — never touches identity. `demand_admin`-gated.
    SpaceRename {
        name: String,
        device: String,
        ts: u64,
    },
    /// Set (or clear, with an empty string) the space's overview description — a
    /// plain LWW `RegisterSet` on the catalog `description`, beside `name`
    /// (SCOPE-2). `demand_admin`-gated like the rename.
    SpaceDescribe {
        description: String,
        device: String,
        ts: u64,
    },
    /// Create a custom role definition (a grow-only Catalog revision with no
    /// predecessor). The daemon mints `role_id` (`role_<ULID>`); the World
    /// validates the registry membership of every capability for the declared
    /// scope.
    RoleCreate {
        role_id: String,
        /// `None` = a Space-scoped role; `Some(project)` = Project-scoped
        /// (the project must exist; capabilities must be Project-registered).
        scope_project: Option<String>,
        name: String,
        description: String,
        capabilities: Vec<String>,
        device: String,
        ts: u64,
    },
    /// Edit a custom role: a new revision whose predecessor is the exact
    /// expected head. Built-ins are immutable in every field.
    RoleEdit {
        role_id: String,
        expected_revision: String,
        name: Option<String>,
        description: Option<String>,
        capabilities: Option<Vec<String>>,
        device: String,
        ts: u64,
    },
    /// Tombstone a custom role (a complete revision; grow-only).
    RoleDelete {
        role_id: String,
        expected_revision: String,
        device: String,
        ts: u64,
    },
    /// Resolve concurrent role heads: a successor naming ALL current heads.
    RoleResolve {
        role_id: String,
        expected_heads: Vec<String>,
        /// The complete replacement body (product canonical JSON).
        body_json: String,
        device: String,
        ts: u64,
    },
    /// Replace a project's workflow: a new revision whose predecessors are
    /// exactly the current heads (also the conflict-resolution path).
    WorkflowReplace {
        project_id: String,
        expected_heads: Vec<String>,
        /// The complete replacement body (product canonical JSON).
        body_json: String,
        device: String,
        ts: u64,
    },
}

/// Build the canonical `InitializeTracker` intent from captured formation
/// facts; the golden role/registry/workflow commitments come from this
/// build's compiled-in definitions. The composition root captures the inputs
/// ONCE and persists the signed action before submission.
pub fn initialize_tracker_intent(
    name: &str,
    ts: u64,
    project_id: &str,
    project_name: &str,
    project_key: &str,
    device: &str,
) -> IssueIntent {
    let mut built_in_roles = Vec::new();
    for id in crate::world::roles::BUILT_IN_ROLE_IDS {
        let rev = crate::world::roles::built_in(id).expect("built-in role");
        built_in_roles.push((
            id.to_string(),
            data_encoding::HEXLOWER.encode(&rev.revision_id),
            data_encoding::HEXLOWER.encode(&rev.body.definition_digest()),
        ));
    }
    IssueIntent::InitializeTracker {
        name: name.to_string(),
        ts,
        project_id: project_id.to_string(),
        project_name: project_name.to_string(),
        project_key: project_key.to_string(),
        device: device.to_string(),
        built_in_roles,
        capability_registry_commitment: data_encoding::HEXLOWER
            .encode(&capability_registry_commitment()),
        default_workflow_commitment: crate::world::workflow::default_workflow_revision(project_id)
            .revision_id,
    }
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
    /// A project's status-update feed, newest first (SCOPE-1).
    ProjectUpdates {
        project: String,
    },
    Labels,
    /// Every role definition: built-ins plus custom heads (with conflict
    /// head lists).
    Roles,
    RoleShow {
        role: String,
    },
    /// The space-wide activity feed: every issue event across the tracker,
    /// ordered by `(ts, doc, per-doc index)` with a monotone `seq` cursor over
    /// the whole feed. `since` filters to rows the caller has not yet seen
    /// (`Activity { since: last }` resumes exactly where the previous pull
    /// stopped); `last` in the projection is the total feed length.
    Activity {
        since: u64,
    },
    /// The addressed-to-you inbox, derived in ONE pass over the committed
    /// snapshot: recent events on issues assigned to `actor`, excluding
    /// events authored by `exclude_device` (a device's own edits are not its
    /// inbox), newest first, bounded.
    Inbox {
        actor: String,
        exclude_device: Option<String>,
    },
    /// A project's workflow revision head(s).
    Workflow {
        project: String,
    },
    /// A project's milestones with derived progress (SCOPE-1).
    Milestones {
        project: String,
    },
    /// A project's cycles with derived counts (BOARD-11).
    Cycles {
        project: String,
    },
    /// Every live initiative with its derived roll-up (SCOPE-8).
    Initiatives,
    /// Every live team with its owned projects (GOV-7).
    Teams,
    /// The triage intake queue, pending first (SCOPE-7).
    Triage,
    /// One attachment's full record including the payload (CREATE-5).
    Attachment {
        doc: String,
        id: String,
    },
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
///
/// `id`/`parent` arrived after v0.6 comments shipped, so both are optional
/// with absent-means-absent serialization: pre-existing comments keep their
/// exact stored bytes, and older builds deserialize enriched comments
/// unchanged (serde ignores unknown fields). A comment without an `id`
/// predates identity and simply cannot anchor reactions or replies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredComment {
    pub a: String,
    pub t: u64,
    pub b: String,
    /// Canonical comment id (`cmt_…`, lowercase — see [`is_comment_id`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The comment this one replies to (one level; a reply to a reply names
    /// the same root).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
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
