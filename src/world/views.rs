//! Parsed catalog/issue state and the legacy-shape projections (C4.2).
//!
//! `CatalogState`/`IssueState` decode the collaborative Body views into typed
//! state; the projection builders reproduce the legacy DTO shapes (schema
//! version 3) byte-for-byte, including alias derivation (`KEY-n` with base-26
//! collision suffixes and shortest-unique canonical `iss_` prefixes).

use std::collections::{BTreeMap, BTreeSet};

use replica::CollaborativeView;
use serde::{Deserialize, Serialize};

use crate::dto::{
    BoardColumn, BoardView, CommentDto, IssueView, LabelDto, Priority, ProjectDto, Row,
    StatusCategory, WorkflowState,
};
use crate::ids::{ActorId, DocId, LabelId, ProjectId};

use super::contract::{IssueEvent, StoredComment, DEFAULT_STATUS, VIEW_SCHEMA_VERSION};

const CANONICAL_MIN: usize = 7;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectMeta {
    pub name: String,
    pub key: String,
    pub color: String,
    /// The overview document — freeform markdown. Additive: projects minted
    /// before this field decode with an empty string.
    #[serde(default)]
    pub description: String,
    /// The project lead's actor key (empty = none).
    #[serde(default)]
    pub lead: String,
    /// Planned window, unix seconds (None = unset).
    #[serde(default)]
    pub start_date: Option<u64>,
    #[serde(default)]
    pub target_date: Option<u64>,
    /// Soft-hidden from pickers, default selection, and all-project lists — but
    /// still resolvable by id/KEY (so a direct link opens it) with its aliases
    /// intact. Additive: pre-archive projects decode as live. See CUSTOM-9.
    #[serde(default)]
    pub archived: bool,
    /// The owning team's id (empty = none). Additive (GOV-7).
    #[serde(default)]
    pub team: String,
}

/// One project status update — an immutable post in the project's updates feed
/// (SCOPE-1). Stored as a grow-only catalog log (`project_updates` keyed
/// `<project>/<id>`), mirroring how workflow revisions and roles are logged
/// rather than introducing a per-project collaborative Body: an update is
/// authored once and never edited, so a record is the honest shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectUpdate {
    pub id: String,
    pub project_id: String,
    /// The authoring actor key.
    pub author: String,
    /// Post time, unix seconds.
    pub ts: u64,
    pub body: String,
    /// `on_track` | `at_risk` | `off_track` | "" (none). A self-reported health
    /// signal, free of any derived-metric coupling.
    #[serde(default)]
    pub health: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LabelMeta {
    pub name: String,
    pub color: String,
}

/// One project milestone — an editable record in the Catalog's
/// `project_milestones` map (keyed `<project>/<milestone>`), LWW per record
/// like `projects` (milestones are renamed and retargeted; the whole record is
/// rewritten on edit so untouched fields never drop). Progress is derived
/// from issues' `milestone` registers, never stored (SCOPE-1).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Milestone {
    pub id: String,
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub target_date: Option<u64>,
    #[serde(default)]
    pub tombstone: bool,
}

/// One cycle (time-boxed iteration) — an editable record in the Catalog's
/// `cycles` map (keyed `<project>/<cycle>`), same LWW-record shape as
/// milestones (BOARD-11).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cycle {
    pub id: String,
    pub project_id: String,
    pub name: String,
    /// The box, unix seconds (0 = unset — a named backlog bucket).
    #[serde(default)]
    pub start: u64,
    #[serde(default)]
    pub end: u64,
    #[serde(default)]
    pub tombstone: bool,
}

/// One initiative — the strategic layer above projects (SCOPE-8): a named
/// goal grouping several projects, with owner/health/target date. Progress is
/// derived from the member projects' issues, never stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Initiative {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Owner actor key (empty = none).
    #[serde(default)]
    pub owner: String,
    /// `on_track` | `at_risk` | `off_track` | "" — self-reported, like
    /// project-update health.
    #[serde(default)]
    pub health: String,
    #[serde(default)]
    pub target_date: Option<u64>,
    /// Ordered member project ids.
    #[serde(default)]
    pub projects: Vec<String>,
    #[serde(default)]
    pub tombstone: bool,
}

/// One team — a durable work-owning group (GOV-7). Team membership is
/// product-level (actor keys), managed independently of the space ACL:
/// belonging to a team confers no authority, and the ACL confers no team.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Team {
    pub id: String,
    pub name: String,
    /// Short uppercase handle, immutable after creation (like a project key).
    pub key: String,
    #[serde(default)]
    pub icon: String,
    /// Lead actor key (empty = none).
    #[serde(default)]
    pub lead: String,
    /// Member actor keys, sorted.
    #[serde(default)]
    pub members: Vec<String>,
    #[serde(default)]
    pub tombstone: bool,
}

/// One triage-intake item (SCOPE-7): reported work reviewed BEFORE it enters
/// a project's workflow. Catalog-level (submission needs no project), decided
/// exactly once — the outcome fields are written by the review intent and the
/// record is never edited afterwards.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TriageItem {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// Where this came from (free text: "cli", an integration name, …).
    #[serde(default)]
    pub source: String,
    /// The submitting actor key.
    pub submitted_by: String,
    pub ts: u64,
    /// "" (pending) | `accepted` | `declined` | `duplicate`.
    #[serde(default)]
    pub outcome: String,
    /// The issue the item became (accepted) or duplicates (duplicate).
    #[serde(default)]
    pub doc: String,
    #[serde(default)]
    pub decided_by: String,
    #[serde(default)]
    pub decided_ts: u64,
    #[serde(default)]
    pub note: String,
}

/// The parsed catalog Body.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogState {
    pub name: String,
    /// The space's overview/description — a plain catalog register beside `name`
    /// (SCOPE-2). Additive: a space that predates it decodes as empty.
    pub description: String,
    pub projects: BTreeMap<String, ProjectMeta>,
    pub labels: BTreeMap<String, LabelMeta>,
    pub workflow: Vec<WorkflowState>,
    /// Per-project alias seq high-water.
    pub aliases: BTreeMap<String, u32>,
    /// Per-issue seq.
    pub seqs: BTreeMap<String, u32>,
    pub tombstones: BTreeSet<String>,
    /// `(from, kind, to)` link edges.
    pub edges: BTreeSet<(String, String, String)>,
    /// child doc -> parent doc.
    pub parents: BTreeMap<String, String>,
    /// project id -> ordered `(stable element id, doc id)` board entries.
    pub boards: BTreeMap<String, Vec<(String, String)>>,
    /// project id -> grow-only workflow revision log (every revision ever
    /// committed; heads are revisions no successor names as a predecessor).
    pub workflow_revisions: BTreeMap<String, Vec<crate::world::workflow::WorkflowRevision>>,
    /// role id -> the immutable BUILT-IN definition (seeded at formation).
    pub roles: BTreeMap<String, StoredRoleRevision>,
    /// role id -> grow-only custom-role revision log.
    pub role_revisions: BTreeMap<String, Vec<StoredRoleRevision>>,
    /// project id -> grow-only status-update log (SCOPE-1 updates feed).
    pub project_updates: BTreeMap<String, Vec<ProjectUpdate>>,
    /// project id -> milestone id -> milestone (SCOPE-1).
    pub milestones: BTreeMap<String, BTreeMap<String, Milestone>>,
    /// project id -> cycle id -> cycle (BOARD-11).
    pub cycles: BTreeMap<String, BTreeMap<String, Cycle>>,
    /// initiative id -> initiative (SCOPE-8).
    pub initiatives: BTreeMap<String, Initiative>,
    /// team id -> team (GOV-7).
    pub teams: BTreeMap<String, Team>,
    /// triage-intake id -> item (SCOPE-7).
    pub triage: BTreeMap<String, TriageItem>,
}

/// A role revision as stored in the catalog `roles` map: hex revision id,
/// predecessors, and the canonical body.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StoredRoleRevision {
    pub revision_id: String,
    #[serde(default)]
    pub predecessor_ids: Vec<String>,
    pub body: crate::world::roles::RoleBody,
}

fn reg_str(view: &CollaborativeView, path: &str) -> Option<String> {
    view.registers
        .get(path)
        .map(|b| String::from_utf8_lossy(b).into_owned())
}

fn map_str(view: &CollaborativeView, path: &str) -> BTreeMap<String, String> {
    view.maps
        .get(path)
        .map(|m| {
            m.iter()
                .map(|(k, v)| (k.clone(), String::from_utf8_lossy(v).into_owned()))
                .collect()
        })
        .unwrap_or_default()
}

impl CatalogState {
    pub fn from_view(view: Option<&CollaborativeView>) -> Self {
        let Some(view) = view else {
            return Self::default();
        };
        let mut state = Self {
            name: reg_str(view, "name").unwrap_or_default(),
            description: reg_str(view, "description").unwrap_or_default(),
            ..Self::default()
        };
        for (id, raw) in map_str(view, "projects") {
            if let Ok(meta) = serde_json::from_str::<ProjectMeta>(&raw) {
                state.projects.insert(id, meta);
            }
        }
        for (id, raw) in map_str(view, "labels") {
            if let Ok(meta) = serde_json::from_str::<LabelMeta>(&raw) {
                state.labels.insert(id, meta);
            }
        }
        if let Some(list) = view.lists.get("workflow") {
            for element in list {
                if let Ok(ws) = serde_json::from_slice::<WorkflowState>(&element.value) {
                    state.workflow.push(ws);
                }
            }
        }
        if state.workflow.is_empty() {
            state.workflow = default_workflow_states();
        }
        for (key, raw) in map_str(view, "workflow_revisions") {
            // Key: `<project>/<revision hex>` — grow-only log entries.
            let Some((project, _hex)) = key.rsplit_once('/') else {
                continue;
            };
            if let Ok(rev) = serde_json::from_str::<crate::world::workflow::WorkflowRevision>(&raw)
            {
                state
                    .workflow_revisions
                    .entry(project.to_string())
                    .or_default()
                    .push(rev);
            }
        }
        for (key, raw) in map_str(view, "project_updates") {
            // Key: `<project>/<update id>` — grow-only log entries.
            let Some((project, _id)) = key.rsplit_once('/') else {
                continue;
            };
            if let Ok(update) = serde_json::from_str::<ProjectUpdate>(&raw) {
                state
                    .project_updates
                    .entry(project.to_string())
                    .or_default()
                    .push(update);
            }
        }
        for (key, raw) in map_str(view, "project_milestones") {
            let Some((project, _id)) = key.rsplit_once('/') else {
                continue;
            };
            if let Ok(m) = serde_json::from_str::<Milestone>(&raw) {
                state
                    .milestones
                    .entry(project.to_string())
                    .or_default()
                    .insert(m.id.clone(), m);
            }
        }
        for (key, raw) in map_str(view, "cycles") {
            let Some((project, _id)) = key.rsplit_once('/') else {
                continue;
            };
            if let Ok(c) = serde_json::from_str::<Cycle>(&raw) {
                state
                    .cycles
                    .entry(project.to_string())
                    .or_default()
                    .insert(c.id.clone(), c);
            }
        }
        for (id, raw) in map_str(view, "initiatives") {
            if let Ok(i) = serde_json::from_str::<Initiative>(&raw) {
                state.initiatives.insert(id, i);
            }
        }
        for (id, raw) in map_str(view, "teams") {
            if let Ok(t) = serde_json::from_str::<Team>(&raw) {
                state.teams.insert(id, t);
            }
        }
        for (id, raw) in map_str(view, "triage") {
            if let Ok(t) = serde_json::from_str::<TriageItem>(&raw) {
                state.triage.insert(id, t);
            }
        }
        for (id, raw) in map_str(view, "roles") {
            if let Ok(rev) = serde_json::from_str::<StoredRoleRevision>(&raw) {
                state.roles.insert(id, rev);
            }
        }
        for (key, raw) in map_str(view, "role_revisions") {
            let Some((role, _hex)) = key.rsplit_once('/') else {
                continue;
            };
            if let Ok(rev) = serde_json::from_str::<StoredRoleRevision>(&raw) {
                state
                    .role_revisions
                    .entry(role.to_string())
                    .or_default()
                    .push(rev);
            }
        }
        for (project, raw) in map_str(view, "aliases") {
            if let Ok(n) = raw.parse() {
                state.aliases.insert(project, n);
            }
        }
        for (doc, raw) in map_str(view, "seqs") {
            if let Ok(n) = raw.parse() {
                state.seqs.insert(doc, n);
            }
        }
        for (doc, raw) in map_str(view, "tombstones") {
            if raw == "1" {
                state.tombstones.insert(doc);
            }
        }
        if let Some(m) = view.maps.get("edges") {
            for key in m.keys() {
                let mut parts = key.splitn(3, '|');
                if let (Some(f), Some(k), Some(t)) = (parts.next(), parts.next(), parts.next()) {
                    state
                        .edges
                        .insert((f.to_string(), k.to_string(), t.to_string()));
                }
            }
        }
        for (child, parent) in map_str(view, "parents") {
            if !parent.is_empty() {
                state.parents.insert(child, parent);
            }
        }
        for (path, list) in &view.lists {
            if let Some(project_lower) = path.strip_prefix("board/") {
                // Board paths carry the lowercased project id; recover the
                // real id from the project set.
                let project = state
                    .projects
                    .keys()
                    .find(|p| p.to_ascii_lowercase() == project_lower)
                    .cloned()
                    .unwrap_or_else(|| project_lower.to_string());
                state.boards.insert(
                    project,
                    list.iter()
                        .map(|e| {
                            (
                                e.element.clone(),
                                String::from_utf8_lossy(&e.value).into_owned(),
                            )
                        })
                        .collect(),
                );
            }
        }
        state
    }

    /// Every known issue DocId (everything that ever got a seq).
    pub fn doc_ids(&self) -> Vec<String> {
        self.seqs.keys().cloned().collect()
    }

    pub fn workflow_state(&self, id: &str) -> Option<&WorkflowState> {
        self.workflow.iter().find(|w| w.id == id)
    }

    pub fn first_state_in(&self, category: StatusCategory) -> Option<&WorkflowState> {
        self.workflow.iter().find(|w| w.category == category)
    }

    pub fn status_category(&self, status: &str) -> StatusCategory {
        self.workflow_state(status)
            .map(|w| w.category)
            .unwrap_or(StatusCategory::Backlog)
    }
}

/// The parsed issue Body.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueState {
    pub project: String,
    pub title: String,
    pub status: String,
    pub priority: Priority,
    pub created_by: Option<ActorId>,
    pub created_at: u64,
    pub description: String,
    /// Unix seconds; absent register = no due date.
    pub duedate: Option<u64>,
    pub estimate: Option<u32>,
    pub assignees: Vec<ActorId>,
    /// Subscribed actors, independent of assignment (INBOX-9): an add-wins
    /// set mirroring `assignees` storage.
    pub followers: Vec<ActorId>,
    /// The milestone this issue targets (empty register = none; SCOPE-1).
    pub milestone: Option<String>,
    /// The cycle this issue is scheduled in (BOARD-11).
    pub cycle: Option<String>,
    pub labels: Vec<String>,
    pub comments: Vec<StoredComment>,
    /// comment id -> sorted `(emoji, actor)` pairs, parsed from the
    /// `reactions/<comment id>` sets. Malformed values are dropped, not
    /// surfaced — a reaction is not worth a corrupt-record row.
    pub reactions: BTreeMap<String, Vec<(String, String)>>,
    /// Attachment records, metadata only — the base64 payload stays in the
    /// Body map and is served solely by the `Attachment` query, so the
    /// derived-snapshot cache never holds file bytes (CREATE-5).
    pub attachments: Vec<AttachmentMeta>,
    pub events: Vec<IssueEvent>,
}

/// The metadata half of a stored attachment record — everything except
/// `data_b64` (serde ignores it on decode, which is the point).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttachmentMeta {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub mime: String,
    /// Raw (decoded) size in bytes.
    #[serde(default)]
    pub size: u64,
    /// The attaching actor key.
    #[serde(default)]
    pub by: String,
    #[serde(default)]
    pub ts: u64,
    /// The comment this file rode with, when any.
    #[serde(default)]
    pub comment: String,
}

impl IssueState {
    pub fn from_view(view: &CollaborativeView) -> Self {
        let mut assignees: Vec<ActorId> = view
            .sets
            .get("assignees")
            .map(|s| {
                s.iter()
                    .filter_map(|v| ActorId::parse(&String::from_utf8_lossy(v)))
                    .collect()
            })
            .unwrap_or_default();
        assignees.sort();
        let mut followers: Vec<ActorId> = view
            .sets
            .get("followers")
            .map(|s| {
                s.iter()
                    .filter_map(|v| ActorId::parse(&String::from_utf8_lossy(v)))
                    .collect()
            })
            .unwrap_or_default();
        followers.sort();
        let mut attachments: Vec<AttachmentMeta> = view
            .maps
            .get("attachments")
            .map(|m| {
                m.values()
                    .filter_map(|v| serde_json::from_slice::<AttachmentMeta>(v).ok())
                    .collect()
            })
            .unwrap_or_default();
        attachments.sort_by(|a, b| a.ts.cmp(&b.ts).then_with(|| a.id.cmp(&b.id)));
        let mut labels: Vec<String> = view
            .sets
            .get("labels")
            .map(|s| {
                s.iter()
                    .map(|v| String::from_utf8_lossy(v).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        labels.sort();
        let comments = view
            .lists
            .get("comments")
            .map(|l| {
                l.iter()
                    .filter_map(|e| serde_json::from_slice::<StoredComment>(&e.value).ok())
                    .collect()
            })
            .unwrap_or_default();
        let events = view
            .lists
            .get("events")
            .map(|l| {
                l.iter()
                    .filter_map(|e| serde_json::from_slice::<IssueEvent>(&e.value).ok())
                    .collect()
            })
            .unwrap_or_default();
        let mut reactions: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for (path, values) in &view.sets {
            let Some(comment) = path.strip_prefix("reactions/") else {
                continue;
            };
            let mut pairs: Vec<(String, String)> = values
                .iter()
                .filter_map(|v| super::contract::parse_reaction_value(v))
                .collect();
            pairs.sort();
            if !pairs.is_empty() {
                reactions.insert(comment.to_string(), pairs);
            }
        }
        Self {
            project: reg_str(view, "projectid").unwrap_or_default(),
            title: reg_str(view, "title").unwrap_or_default(),
            status: reg_str(view, "status").unwrap_or_else(|| DEFAULT_STATUS.to_string()),
            priority: Priority::parse(&reg_str(view, "priority").unwrap_or_default())
                .unwrap_or(Priority::None),
            created_by: reg_str(view, "createdby").and_then(|s| ActorId::parse(&s)),
            created_at: reg_str(view, "createdat")
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            description: view.texts.get("description").cloned().unwrap_or_default(),
            duedate: reg_str(view, "duedate").and_then(|s| s.parse().ok()),
            estimate: reg_str(view, "estimate").and_then(|s| s.parse().ok()),
            assignees,
            followers,
            milestone: reg_str(view, "milestone").filter(|m| !m.is_empty()),
            cycle: reg_str(view, "cycle").filter(|c| !c.is_empty()),
            labels,
            comments,
            reactions,
            attachments,
            events,
        }
    }
}

/// The derived alias table for one catalog + doc set (deterministic; the
/// legacy `AliasTable` semantics).
#[derive(Debug, Clone, Default)]
pub struct DerivedAliases {
    pub by_doc: BTreeMap<String, String>,
    pub by_alias: BTreeMap<String, String>,
    pub canonical: BTreeMap<String, String>,
}

fn lcp_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// `1 -> "b", 2 -> "c", …, 25 -> "z", 26 -> "aa"` collision suffix (legacy).
fn collision_suffix(i: usize) -> String {
    let mut n = i;
    let mut s = String::new();
    let alphabet = b"abcdefghijklmnopqrstuvwxyz";
    loop {
        let rem = n % 26;
        s.insert(0, alphabet[rem] as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s
}

pub fn derive_aliases<'a>(
    catalog: &CatalogState,
    project_of: impl Fn(&str) -> Option<&'a str>,
) -> DerivedAliases {
    let mut out = DerivedAliases::default();
    let mut docs: Vec<String> = catalog.doc_ids();
    docs.sort();
    // Canonical: shortest prefix (≥ CANONICAL_MIN) unshared with neighbours.
    for (i, doc) in docs.iter().enumerate() {
        let Some(ulid) = doc.strip_prefix(DocId::PREFIX) else {
            continue;
        };
        let lp = if i > 0 {
            docs[i - 1]
                .strip_prefix(DocId::PREFIX)
                .map(|p| lcp_len(ulid, p))
                .unwrap_or(0)
        } else {
            0
        };
        let ls = docs
            .get(i + 1)
            .and_then(|s| s.strip_prefix(DocId::PREFIX))
            .map(|s| lcp_len(ulid, s))
            .unwrap_or(0);
        let k = (lp.max(ls) + 1).clamp(CANONICAL_MIN, ulid.len());
        out.canonical
            .insert(doc.clone(), format!("{}{}", DocId::PREFIX, &ulid[..k]));
    }
    // KEY-n aliases with deterministic collision suffixes.
    let mut groups: BTreeMap<(String, u32), Vec<String>> = BTreeMap::new();
    for doc in &docs {
        let Some(&seq) = catalog.seqs.get(doc) else {
            continue;
        };
        // Live issues are present in board order. Done issues are deliberately
        // removed from that movable list, so their authoritative Issue body is
        // the fallback that keeps KEY-n aliases stable after completion.
        let project = catalog
            .boards
            .iter()
            .find(|(_, entries)| entries.iter().any(|(_, d)| d == doc))
            .map(|(p, _)| p.as_str())
            .or_else(|| project_of(doc));
        if let Some(project) = project {
            groups
                .entry((project.to_string(), seq))
                .or_default()
                .push(doc.clone());
        }
    }
    for ((project, seq), mut members) in groups {
        let Some(key) = catalog.projects.get(&project).map(|p| p.key.clone()) else {
            continue;
        };
        members.sort();
        for (i, doc) in members.iter().enumerate() {
            let alias = if i == 0 {
                format!("{key}-{seq}")
            } else {
                format!("{key}-{seq}{}", collision_suffix(i))
            };
            out.by_alias.insert(alias.to_ascii_lowercase(), doc.clone());
            out.by_doc.insert(doc.clone(), alias);
        }
    }
    out
}

pub fn canonical_for(aliases: &DerivedAliases, doc: &str) -> String {
    aliases.canonical.get(doc).cloned().unwrap_or_else(|| {
        DocId::parse(doc)
            .map(|d| d.short(CANONICAL_MIN))
            .unwrap_or_else(|| doc.to_string())
    })
}

fn assignee_summary(assignees: &[ActorId], me: Option<&ActorId>) -> String {
    let mine = me.is_some_and(|m| assignees.contains(m));
    match (assignees.len(), mine) {
        (0, _) => String::new(),
        (1, true) => "you".to_string(),
        (n, true) => format!("you +{}", n - 1),
        (n, false) => {
            let first = assignees[0].short();
            if n == 1 {
                first
            } else {
                format!("{first} +{}", n - 1)
            }
        }
    }
}

/// Build a legacy Row for one issue.
pub fn project_row(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    doc: &str,
    issue: Option<&IssueState>,
    me: Option<&ActorId>,
) -> Row {
    let (title, status, priority, assignees, project, due_date, estimate) = match issue {
        Some(i) => (
            i.title.clone(),
            i.status.clone(),
            i.priority,
            i.assignees.clone(),
            i.project.clone(),
            i.duedate,
            i.estimate,
        ),
        None => (
            String::new(),
            DEFAULT_STATUS.to_string(),
            Priority::None,
            Vec::new(),
            String::new(),
            None,
            None,
        ),
    };
    Row {
        reff: canonical_for(aliases, doc),
        doc_id: DocId::parse(doc).unwrap_or_else(|| {
            DocId::parse("iss_00000000000000000000000000").expect("zero doc id")
        }),
        project_id: ProjectId::parse(&project).unwrap_or_else(|| {
            ProjectId::parse("prj_00000000000000000000000000").expect("zero project id")
        }),
        key_alias: aliases.by_doc.get(doc).cloned(),
        title,
        status,
        priority,
        assignee_summary: assignee_summary(&assignees, me),
        assignees,
        tombstone: catalog.tombstones.contains(doc),
        provisional: issue.is_none(),
        due_date,
        estimate,
        label_names: issue
            .map(|i| {
                i.labels
                    .iter()
                    .map(|id| {
                        catalog
                            .labels
                            .get(id)
                            .map(|l| l.name.clone())
                            .unwrap_or_else(|| id.clone())
                    })
                    .collect()
            })
            .unwrap_or_default(),
        // Sub-issue progress is a board-projection concern (it needs the issues
        // map to classify each child's status); the base row leaves it absent.
        child_done: None,
        child_total: None,
    }
}

/// Build the legacy IssueView.
#[allow(clippy::too_many_arguments)]
pub fn issue_view(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    space: &crate::ids::SpaceId,
    doc: &str,
    issue: &IssueState,
) -> IssueView {
    let label_names = issue
        .labels
        .iter()
        .map(|id| {
            catalog
                .labels
                .get(id)
                .map(|l| l.name.clone())
                .unwrap_or_else(|| id.clone())
        })
        .collect();
    IssueView {
        schema_version: VIEW_SCHEMA_VERSION,
        reff: canonical_for(aliases, doc),
        doc_id: DocId::parse(doc).expect("doc id"),
        space_id: space.clone(),
        project_id: ProjectId::parse(&issue.project)
            .unwrap_or_else(|| ProjectId::parse("prj_00000000000000000000000000").expect("zero")),
        project_key: catalog.projects.get(&issue.project).map(|p| p.key.clone()),
        key_alias: aliases.by_doc.get(doc).cloned(),
        title: issue.title.clone(),
        description: issue.description.clone(),
        status: issue.status.clone(),
        priority: issue.priority,
        assignees: issue.assignees.clone(),
        labels: issue
            .labels
            .iter()
            .filter_map(|l| LabelId::parse(l))
            .collect(),
        label_names,
        comments: issue
            .comments
            .iter()
            .filter_map(|c| {
                Some(CommentDto {
                    author: ActorId::parse(&c.a)?,
                    author_nick: None,
                    ts: c.t,
                    body: c.b.clone(),
                    id: c.id.clone(),
                    parent: c.parent.clone(),
                    reactions: c
                        .id
                        .as_deref()
                        .and_then(|id| issue.reactions.get(id))
                        .map(|pairs| group_reactions(pairs))
                        .unwrap_or_default(),
                })
            })
            .collect(),
        created_by: issue
            .created_by
            .clone()
            .unwrap_or_else(|| ActorId::from_incept_hash(&"0".repeat(64))),
        created_at: issue.created_at,
        due_date: issue.duedate,
        estimate: issue.estimate,
        followers: issue.followers.clone(),
        milestone: issue.milestone.clone(),
        cycle: issue.cycle.clone(),
        attachments: issue
            .attachments
            .iter()
            .map(|a| crate::dto::AttachmentMetaDto {
                id: a.id.clone(),
                name: a.name.clone(),
                mime: a.mime.clone(),
                size: a.size,
                by: a.by.clone(),
                ts: a.ts,
                comment: a.comment.clone(),
            })
            .collect(),
        provisional: false,
        corrupt_records: Vec::new(),
    }
}

/// Group one comment's `(emoji, actor)` pairs into per-emoji actor lists,
/// first-appearance emoji order (the pairs arrive sorted, so this is
/// deterministic across replicas).
fn group_reactions(pairs: &[(String, String)]) -> Vec<crate::dto::ReactionDto> {
    let mut out: Vec<crate::dto::ReactionDto> = Vec::new();
    for (emoji, actor) in pairs {
        let Some(actor) = ActorId::parse(actor) else {
            continue;
        };
        match out.iter_mut().find(|r| &r.emoji == emoji) {
            Some(r) => r.actors.push(actor),
            None => out.push(crate::dto::ReactionDto {
                emoji: emoji.clone(),
                actors: vec![actor],
            }),
        }
    }
    out
}

pub fn project_dto(id: &str, meta: &ProjectMeta) -> Option<ProjectDto> {
    Some(ProjectDto {
        id: ProjectId::parse(id)?,
        name: meta.name.clone(),
        key: meta.key.clone(),
        color: meta.color.clone(),
        description: meta.description.clone(),
        lead: meta.lead.clone(),
        start_date: meta.start_date,
        target_date: meta.target_date,
        archived: meta.archived,
        team: meta.team.clone(),
    })
}

pub fn label_dto(id: &str, meta: &LabelMeta) -> Option<LabelDto> {
    Some(LabelDto {
        id: LabelId::parse(id)?,
        name: meta.name.clone(),
        color: meta.color.clone(),
    })
}

/// Build the legacy BoardView.
pub fn board_view(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    project_id: &str,
    issues: &BTreeMap<String, std::sync::Arc<IssueState>>,
    me: Option<&ActorId>,
) -> Option<BoardView> {
    let meta = catalog.projects.get(project_id)?;
    let project = project_dto(project_id, meta)?;
    // Live members of this project.
    let members: Vec<&String> = issues
        .iter()
        .filter(|(doc, i)| i.project == project_id && !catalog.tombstones.contains(*doc))
        .map(|(doc, _)| doc)
        .collect();
    let board_order: Vec<String> = catalog
        .boards
        .get(project_id)
        .map(|b| b.iter().map(|(_, d)| d.clone()).collect())
        .unwrap_or_default();
    // Sub-issue progress per parent, computed once: total = live children,
    // done = children whose status is a Done-category state. Built from the same
    // `catalog.parents` edge map the graph view reads, minus tombstoned children.
    let mut child_progress: BTreeMap<&str, (u32, u32)> = BTreeMap::new();
    for (child, parent) in &catalog.parents {
        if catalog.tombstones.contains(child) {
            continue;
        }
        let entry = child_progress.entry(parent.as_str()).or_insert((0, 0));
        entry.1 += 1;
        let done = issues
            .get(child)
            .is_some_and(|i| catalog.status_category(&i.status) == StatusCategory::Done);
        if done {
            entry.0 += 1;
        }
    }
    // Build a board row and stamp its sub-issue progress (absent when childless).
    let row_of = |doc: &str| -> Row {
        let mut row = project_row(
            catalog,
            aliases,
            doc,
            issues.get(doc).map(|i| i.as_ref()),
            me,
        );
        if let Some((done, total)) = child_progress.get(doc) {
            row.child_done = Some(*done);
            row.child_total = Some(*total);
        }
        row
    };
    let mut columns = Vec::new();
    for state in &catalog.workflow {
        let mut rows: Vec<Row> = Vec::new();
        let in_state = |doc: &str| issues.get(doc).is_some_and(|i| i.status == state.id);
        if state.category == StatusCategory::Done {
            let mut done: Vec<&&String> = members.iter().filter(|d| in_state(d)).collect();
            done.sort_by(|a, b| {
                let ia = issues.get(**a).map(|i| i.created_at).unwrap_or(0);
                let ib = issues.get(**b).map(|i| i.created_at).unwrap_or(0);
                ib.cmp(&ia).then_with(|| b.cmp(a))
            });
            for doc in done {
                rows.push(row_of(doc));
            }
        } else {
            let mut seen = BTreeSet::new();
            for doc in &board_order {
                if members.contains(&doc) && in_state(doc) && seen.insert(doc.clone()) {
                    rows.push(row_of(doc));
                }
            }
            let mut unlisted: Vec<&&String> = members
                .iter()
                .filter(|d| in_state(d) && !seen.contains(**d))
                .collect();
            unlisted.sort();
            for doc in unlisted {
                rows.push(row_of(doc));
            }
        }
        columns.push(BoardColumn {
            state: state.clone(),
            rows,
        });
    }
    Some(BoardView {
        schema_version: VIEW_SCHEMA_VERSION,
        project,
        columns,
    })
}

pub fn default_workflow_states() -> Vec<WorkflowState> {
    super::contract::default_workflow()
        .into_iter()
        .filter_map(|v| serde_json::from_value(v).ok())
        .collect()
}

/// Revision-head computation over a grow-only log: the heads are entries no
/// other entry names as a predecessor. One head is usable; several are an
/// explicit conflict the caller must surface.
fn heads_of<T, I: Fn(&T) -> &str, P: Fn(&T) -> &[String]>(
    log: &[T],
    id_of: I,
    preds_of: P,
) -> Vec<&T> {
    use std::collections::BTreeSet;
    let referenced: BTreeSet<&str> = log
        .iter()
        .flat_map(|r| preds_of(r).iter().map(|s| s.as_str()))
        .collect();
    log.iter()
        .filter(|r| !referenced.contains(id_of(r)))
        .collect()
}

impl CatalogState {
    /// The workflow revision heads for a project (empty = never seeded;
    /// more than one = concurrent edits pending explicit resolution).
    pub fn workflow_heads(&self, project: &str) -> Vec<&crate::world::workflow::WorkflowRevision> {
        self.workflow_revisions
            .get(project)
            .map(|log| heads_of(log, |r| r.revision_id.as_str(), |r| &r.predecessor_ids))
            .unwrap_or_default()
    }

    /// The single usable workflow head, or `None` (missing or conflicted).
    pub fn workflow_head(
        &self,
        project: &str,
    ) -> Option<&crate::world::workflow::WorkflowRevision> {
        let heads = self.workflow_heads(project);
        match heads.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }

    /// The custom-role revision heads for a role id.
    pub fn role_heads(&self, role: &str) -> Vec<&StoredRoleRevision> {
        self.role_revisions
            .get(role)
            .map(|log| heads_of(log, |r| r.revision_id.as_str(), |r| &r.predecessor_ids))
            .unwrap_or_default()
    }

    /// The single usable role head: a built-in's immutable definition, or the
    /// custom role's sole head. `None` for unknown or conflicted roles.
    pub fn role_head(&self, role: &str) -> Option<&StoredRoleRevision> {
        if let Some(built_in) = self.roles.get(role) {
            return Some(built_in);
        }
        let heads = self.role_heads(role);
        match heads.as_slice() {
            [one] => Some(one),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completed_issue_keeps_alias_from_authoritative_project() {
        let doc = "iss_01JU6A5CHEI9UR3SGKEK05KIAR";
        let mut catalog = CatalogState::default();
        catalog.projects.insert(
            "prj_board".into(),
            ProjectMeta {
                name: "Board".into(),
                key: "BOARD".into(),
                color: "blue".into(),
                ..Default::default()
            },
        );
        catalog.seqs.insert(doc.into(), 5);

        let aliases = derive_aliases(&catalog, |candidate| {
            (candidate == doc).then_some("prj_board")
        });

        assert_eq!(aliases.by_doc.get(doc).map(String::as_str), Some("BOARD-5"));
        assert_eq!(
            aliases.by_alias.get("board-5").map(String::as_str),
            Some(doc)
        );
    }
}
