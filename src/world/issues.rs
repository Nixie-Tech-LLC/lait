//! The product's private compatibility World adapter (C4.2).
//!
//! `IssuesWorld` implements the public `runtime::World` contract over the
//! frozen mapping in `contract.rs`: current Issues behavior expressed as
//! collaborative Body operations. It is deliberately **not** a reusable
//! first-party World crate — it lives in the product, registers through the
//! same `RuntimeBuilder` any consumer uses, and touches nothing below the
//! World boundary. The World is pure: ids, timestamps, and resolved refs
//! arrive inside the intent; validation is re-checked here (the daemon
//! pre-validates for friendly errors), and every accepted intent stages one
//! atomic multi-Body transaction (issue + catalog together — the legacy split
//! `persist_issue_and_row` failure mode does not exist here).

use std::collections::BTreeMap;

use replica::body::{BodyOp, BodySchema, CollaborativeSchema, MutationModel};
use replica::ids::BodyKey;
use runtime::{
    BodyDeclaration, World, WorldContext, WorldEffect, WorldError, WorldIntent, WorldProjection,
    WorldQuery,
};

use crate::acl::Grant;
use crate::dto::{ActivityEvent, FieldChange, Priority, StatusCategory};
use crate::ids::{ActorId, DocId};

use super::contract::{
    self, board_path, catalog_key, issue_key, EventChange, IssueEffect, IssueEvent, IssueIntent,
    IssueQuery, Pos, StoredComment, WorkAction, DEFAULT_STATUS, LINK_KINDS, VIEW_SCHEMA_VERSION,
};
use super::views::{
    board_view, canonical_for, derive_aliases, issue_view, label_dto, project_dto, project_row,
    CatalogState, DerivedAliases, IssueState,
};

/// The registered product World.
pub struct IssuesWorld {
    id: replica::ids::WorldId,
    schemas: Vec<BodySchema>,
}

impl Default for IssuesWorld {
    fn default() -> Self {
        Self::new()
    }
}

impl IssuesWorld {
    pub fn new() -> Self {
        Self {
            id: contract::world_id(),
            schemas: vec![
                BodySchema {
                    id: contract::issue_schema(),
                    version: contract::ISSUE_SCHEMA_VERSION,
                    encoding: contract::issue_encoding(),
                    mutation: MutationModel::Collaborative(CollaborativeSchema::default()),
                    readable_predecessors: vec![],
                },
                BodySchema {
                    id: contract::catalog_schema(),
                    version: contract::CATALOG_SCHEMA_VERSION,
                    encoding: contract::catalog_encoding(),
                    mutation: MutationModel::Collaborative(CollaborativeSchema::default()),
                    readable_predecessors: vec![],
                },
            ],
        }
    }

    /// The registration the composition root hands to `RuntimeBuilder`.
    pub fn registration() -> runtime::WorldRegistration {
        let world = Self::new();
        runtime::WorldRegistration {
            id: world.id.clone(),
            implementation_version: runtime::WorldVersion(1),
            schemas: world.schemas.clone(),
            limits: runtime::WorldLimits::default(),
        }
    }

    /// The reviewed implementation descriptor this build ships. Its canonical
    /// id is the authority identity the founder activates and every product
    /// transaction pins. `policy_protocol`/`implementation_version` are 1; the
    /// policy-table commitment and artifact identity are build-embedded
    /// release ids (fixed here until a versioned policy table lands).
    pub fn implementation_descriptor() -> runtime::implementation::WorldImplementationDescriptor {
        let world = Self::new();
        runtime::implementation::WorldImplementationDescriptor::from_schemas(
            world.id.clone(),
            1,
            1,
            &world.schemas,
            *blake3::hash(b"lait.issues.policy-table.v1").as_bytes(),
            *blake3::hash(b"lait.issues.artifact.v1").as_bytes(),
        )
    }
}

/// A staged transaction under construction.
#[derive(Default)]
struct Staging {
    ops: Vec<(BodyKey, BodyOp)>,
    scopes: Vec<BodyKey>,
    declarations: Vec<BodyDeclaration>,
    /// The canonical demand this mutation requires (defaults to contributor).
    demand: Option<Vec<u8>>,
}

impl Staging {
    fn declare_issue(&mut self, key: &BodyKey) {
        if !self.declarations.iter().any(|d| &d.key == key) {
            self.declarations.push(BodyDeclaration {
                key: key.clone(),
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
            });
        }
        if !self.scopes.contains(key) {
            self.scopes.push(key.clone());
        }
    }

    fn declare_catalog(&mut self) {
        let key = catalog_key();
        if !self.declarations.iter().any(|d| d.key == key) {
            self.declarations.push(BodyDeclaration {
                key: key.clone(),
                schema: contract::catalog_schema(),
                schema_version: contract::CATALOG_SCHEMA_VERSION,
            });
        }
        if !self.scopes.contains(&key) {
            self.scopes.push(key);
        }
    }

    fn issue(&mut self, key: &BodyKey, op: BodyOp) {
        self.declare_issue(key);
        self.ops.push((key.clone(), op));
    }

    fn catalog(&mut self, op: BodyOp) {
        self.declare_catalog();
        self.ops.push((catalog_key(), op));
    }

    /// Set the demand this mutation requires (an admin-only intent overrides
    /// the contributor default).
    fn require(&mut self, demand: Vec<u8>) {
        self.demand = Some(demand);
    }

    fn into_effect(self, doc: Option<String>) -> WorldEffect {
        let demand = self.demand.unwrap_or_else(contract::demand_contributor);
        WorldEffect {
            operations: self.ops,
            scopes: self.scopes,
            effect: IssueEffect {
                doc,
                unchanged: false,
            }
            .to_json(),
            declarations: self.declarations,
            demand,
        }
    }
}

fn reg(path: &str, value: impl Into<Vec<u8>>) -> BodyOp {
    BodyOp::RegisterSet {
        path: path.into(),
        value: value.into(),
    }
}

fn map_set(path: &str, key: impl Into<String>, value: impl Into<Vec<u8>>) -> BodyOp {
    BodyOp::MapSet {
        path: path.into(),
        key: key.into(),
        value: value.into(),
    }
}

fn unchanged_effect(doc: Option<String>) -> WorldEffect {
    WorldEffect {
        operations: vec![],
        scopes: vec![],
        effect: IssueEffect {
            doc,
            unchanged: true,
        }
        .to_json(),
        declarations: vec![],
        // A no-op still declares a demand (the read baseline every member
        // holds); it commits nothing, so the receipt is over an empty tx.
        demand: contract::demand_read(),
    }
}

/// Load the catalog state from the committed snapshot.
fn catalog_state(ctx: &WorldContext<'_>) -> CatalogState {
    let view = ctx.read_collaborative(&catalog_key());
    CatalogState::from_view(view.as_ref())
}

fn issue_state(ctx: &WorldContext<'_>, doc: &str) -> Option<IssueState> {
    ctx.read_collaborative(&issue_key(doc))
        .map(|v| IssueState::from_view(&v))
}

/// Append one history event to an issue's `events` list.
fn push_event(staging: &mut Staging, ctx: &WorldContext<'_>, doc: &str, event: &IssueEvent) {
    let key = issue_key(doc);
    let len = ctx
        .read_collaborative(&key)
        .and_then(|v| v.lists.get("events").map(|l| l.len() as u64))
        .unwrap_or(0);
    staging.issue(
        &key,
        BodyOp::ListInsert {
            path: "events".into(),
            index: len,
            value: serde_json::to_vec(event).expect("event json"),
        },
    );
}

fn event(kind: &str, device: &str, ts: u64) -> IssueEvent {
    IssueEvent {
        k: kind.into(),
        d: device.into(),
        t: ts,
        c: vec![],
        x: String::new(),
    }
}

/// Board helpers, staged against the CURRENT catalog view.
fn board_entries(catalog: &CatalogState, project: &str) -> Vec<(String, String)> {
    catalog.boards.get(project).cloned().unwrap_or_default()
}

fn board_insert_top(staging: &mut Staging, catalog: &CatalogState, project: &str, doc: &str) {
    if board_entries(catalog, project)
        .iter()
        .any(|(_, d)| d == doc)
    {
        return;
    }
    staging.catalog(BodyOp::ListInsert {
        path: board_path(project),
        index: 0,
        value: doc.as_bytes().to_vec(),
    });
}

fn board_remove(staging: &mut Staging, catalog: &CatalogState, project: &str, doc: &str) {
    if let Some((element, _)) = board_entries(catalog, project)
        .into_iter()
        .find(|(_, d)| d == doc)
    {
        staging.catalog(BodyOp::ListRemove {
            path: board_path(project),
            element,
        });
    }
}

/// The legacy `board_move` index math over the current entries.
fn board_move(
    staging: &mut Staging,
    catalog: &CatalogState,
    project: &str,
    doc: &str,
    anchor: &str,
    after: bool,
) {
    let entries = board_entries(catalog, project);
    let len = entries.len();
    let doc_pos = entries.iter().position(|(_, d)| d == doc);
    let anchor_pos = entries.iter().position(|(_, d)| d == anchor);
    match (doc_pos, anchor_pos) {
        (Some(from), Some(a)) => {
            use std::cmp::Ordering;
            let to = match from.cmp(&a) {
                Ordering::Equal => return,
                Ordering::Greater => {
                    if after {
                        a + 1
                    } else {
                        a
                    }
                }
                Ordering::Less => {
                    if after {
                        a
                    } else {
                        a.saturating_sub(1)
                    }
                }
            };
            let to = to.min(len.saturating_sub(1));
            staging.catalog(BodyOp::ListMove {
                path: board_path(project),
                element: entries[from].0.clone(),
                index: to as u64,
            });
        }
        (None, Some(a)) => {
            let at = if after { a + 1 } else { a }.min(len);
            staging.catalog(BodyOp::ListInsert {
                path: board_path(project),
                index: at as u64,
                value: doc.as_bytes().to_vec(),
            });
        }
        (Some(from), None) => {
            if len > 0 {
                staging.catalog(BodyOp::ListMove {
                    path: board_path(project),
                    element: entries[from].0.clone(),
                    index: (len - 1) as u64,
                });
            }
        }
        (None, None) => {
            staging.catalog(BodyOp::ListInsert {
                path: board_path(project),
                index: len as u64,
                value: doc.as_bytes().to_vec(),
            });
        }
    }
}

/// A minimal char-coordinate splice from `old` to `new` (legacy `LoroText
/// update` behavior: concurrent edits merge instead of last-write-wins).
fn text_splice(old: &str, new: &str) -> Option<(u64, u64, String)> {
    if old == new {
        return None;
    }
    let old_chars: Vec<char> = old.chars().collect();
    let new_chars: Vec<char> = new.chars().collect();
    let mut prefix = 0;
    while prefix < old_chars.len()
        && prefix < new_chars.len()
        && old_chars[prefix] == new_chars[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < old_chars.len() - prefix
        && suffix < new_chars.len() - prefix
        && old_chars[old_chars.len() - 1 - suffix] == new_chars[new_chars.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let delete = (old_chars.len() - prefix - suffix) as u64;
    let insert: String = new_chars[prefix..new_chars.len() - suffix].iter().collect();
    Some((prefix as u64, delete, insert))
}

/// Walk the parent map from `start` upward, returning true if `needle` is an
/// ancestor (cycle-safe).
fn is_ancestor(catalog: &CatalogState, start: &str, needle: &str) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let mut cursor = start.to_string();
    while let Some(parent) = catalog.parents.get(&cursor) {
        if !seen.insert(parent.clone()) {
            return false; // pre-existing cycle: stop, do not loop
        }
        if parent == needle {
            return true;
        }
        cursor = parent.clone();
    }
    false
}

impl World for IssuesWorld {
    fn id(&self) -> replica::ids::WorldId {
        self.id.clone()
    }

    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }

    fn submit(
        &self,
        ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        if !ctx.principal().standing.has(&Grant::Write) {
            return Err(WorldError::Denied);
        }
        let intent = IssueIntent::from_json(&intent.payload).ok_or(WorldError::InvalidRequest)?;
        let catalog = catalog_state(ctx);
        let mut staging = Staging::default();
        match intent {
            IssueIntent::SpaceInit { name, ts: _ } => {
                // Idempotent: a seeded catalog stays untouched.
                let already = ctx
                    .read_collaborative(&catalog_key())
                    .is_some_and(|v| v.lists.get("workflow").is_some_and(|l| !l.is_empty()));
                if already {
                    return Ok(unchanged_effect(None));
                }
                staging.catalog(reg("name", name.into_bytes()));
                for (i, state) in contract::default_workflow().into_iter().enumerate() {
                    staging.catalog(BodyOp::ListInsert {
                        path: "workflow".into(),
                        index: i as u64,
                        value: serde_json::to_vec(&state).expect("workflow json"),
                    });
                }
                // Tracker initialization is a founder-composition admin action.
                staging.require(contract::demand_admin());
                Ok(staging.into_effect(None))
            }
            IssueIntent::IssueNew {
                doc,
                project,
                title,
                priority,
                assignees,
                labels,
                new_labels,
                body,
                actor,
                device,
                ts,
            } => {
                if title.trim().is_empty() || DocId::parse(&doc).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                if !catalog.projects.contains_key(&project) {
                    return Err(WorldError::InvalidRequest);
                }
                if Priority::parse(&priority).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                for label in &labels {
                    if !catalog.labels.contains_key(label) {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                let key = issue_key(&doc);
                staging.issue(&key, BodyOp::Create);
                staging.issue(&key, reg("projectid", project.as_bytes().to_vec()));
                staging.issue(&key, reg("title", title.as_bytes().to_vec()));
                staging.issue(&key, reg("status", DEFAULT_STATUS.as_bytes().to_vec()));
                staging.issue(&key, reg("priority", priority.as_bytes().to_vec()));
                staging.issue(&key, reg("createdby", actor.as_bytes().to_vec()));
                staging.issue(&key, reg("createdat", ts.to_string().into_bytes()));
                if let Some(body) = body.filter(|b| !b.is_empty()) {
                    staging.issue(
                        &key,
                        BodyOp::TextSplice {
                            path: "description".into(),
                            index: 0,
                            delete: 0,
                            insert: body,
                        },
                    );
                }
                for who in &assignees {
                    staging.issue(
                        &key,
                        BodyOp::SetAdd {
                            path: "assignees".into(),
                            value: who.as_bytes().to_vec(),
                        },
                    );
                }
                for new_label in &new_labels {
                    staging.catalog(map_set(
                        "labels",
                        new_label.id.clone(),
                        serde_json::to_vec(&serde_json::json!({
                            "name": new_label.name,
                            "color": new_label.color,
                        }))
                        .expect("label json"),
                    ));
                }
                for label in labels.iter().chain(new_labels.iter().map(|l| &l.id)) {
                    staging.issue(
                        &key,
                        BodyOp::SetAdd {
                            path: "labels".into(),
                            value: label.as_bytes().to_vec(),
                        },
                    );
                }
                // Alias seq + board, in the same atomic transaction.
                let next = catalog.aliases.get(&project).copied().unwrap_or(0) + 1;
                staging.catalog(map_set("aliases", project.clone(), next.to_string()));
                staging.catalog(map_set("seqs", doc.clone(), next.to_string()));
                board_insert_top(&mut staging, &catalog, &project, &doc);
                push_event(&mut staging, ctx, &doc, &event("created", &device, ts));
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::IssueEdit {
                doc,
                title,
                status,
                priority,
                description,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if title.is_none()
                    && status.is_none()
                    && priority.is_none()
                    && description.is_none()
                {
                    return Err(WorldError::InvalidRequest);
                }
                if let Some(status) = &status {
                    if catalog.workflow_state(status).is_none() {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                if let Some(priority) = &priority {
                    if Priority::parse(priority).is_none() {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                let key = issue_key(&doc);
                let mut changes = Vec::new();
                if let Some(title) = &title {
                    changes.push(EventChange {
                        f: "title".into(),
                        from: Some(issue.title.clone()),
                        to: Some(title.clone()),
                    });
                    staging.issue(&key, reg("title", title.as_bytes().to_vec()));
                }
                if let Some(status) = &status {
                    changes.push(EventChange {
                        f: "status".into(),
                        from: Some(issue.status.clone()),
                        to: Some(status.clone()),
                    });
                    staging.issue(&key, reg("status", status.as_bytes().to_vec()));
                    let was_done = catalog.status_category(&issue.status) == StatusCategory::Done;
                    let is_done = catalog.status_category(status) == StatusCategory::Done;
                    if is_done && !was_done {
                        board_remove(&mut staging, &catalog, &issue.project, &doc);
                    } else if was_done && !is_done {
                        board_insert_top(&mut staging, &catalog, &issue.project, &doc);
                    }
                }
                if let Some(priority) = &priority {
                    changes.push(EventChange {
                        f: "priority".into(),
                        from: Some(issue.priority.as_str().to_string()),
                        to: Some(priority.clone()),
                    });
                    staging.issue(&key, reg("priority", priority.as_bytes().to_vec()));
                }
                if let Some(description) = &description {
                    if let Some((index, delete, insert)) =
                        text_splice(&issue.description, description)
                    {
                        staging.issue(
                            &key,
                            BodyOp::TextSplice {
                                path: "description".into(),
                                index,
                                delete,
                                insert,
                            },
                        );
                        changes.push(EventChange {
                            f: "description".into(),
                            from: None,
                            to: None,
                        });
                    }
                }
                if staging.ops.is_empty() {
                    return Ok(unchanged_effect(Some(doc)));
                }
                let mut ev = event("edited", &device, ts);
                ev.c = changes;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::IssueMove {
                doc,
                project,
                pos,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let mut effective = issue.project.clone();
                if let Some(target) = &project {
                    if !catalog.projects.contains_key(target) {
                        return Err(WorldError::InvalidRequest);
                    }
                    if target != &issue.project {
                        staging.issue(
                            &issue_key(&doc),
                            reg("projectid", target.as_bytes().to_vec()),
                        );
                        board_remove(&mut staging, &catalog, &issue.project, &doc);
                        board_insert_top(&mut staging, &catalog, target, &doc);
                        effective = target.clone();
                    }
                }
                match pos {
                    None => {}
                    Some(Pos::Top) => board_insert_top(&mut staging, &catalog, &effective, &doc),
                    Some(Pos::Bottom) => {
                        board_remove(&mut staging, &catalog, &effective, &doc);
                        // Insert computed against the current view minus doc.
                        let len = board_entries(&catalog, &effective)
                            .iter()
                            .filter(|(_, d)| d != &doc)
                            .count();
                        staging.catalog(BodyOp::ListInsert {
                            path: board_path(&effective),
                            index: len as u64,
                            value: doc.as_bytes().to_vec(),
                        });
                    }
                    Some(Pos::Before { doc: anchor }) => {
                        board_move(&mut staging, &catalog, &effective, &doc, &anchor, false)
                    }
                    Some(Pos::After { doc: anchor }) => {
                        board_move(&mut staging, &catalog, &effective, &doc, &anchor, true)
                    }
                }
                if staging.ops.is_empty() {
                    return Ok(unchanged_effect(Some(doc)));
                }
                push_event(&mut staging, ctx, &doc, &event("moved", &device, ts));
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Assign {
                doc,
                who,
                add,
                device,
                ts,
            } => {
                let _issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let key = issue_key(&doc);
                for actor in &who {
                    if ActorId::parse(actor).is_none() {
                        return Err(WorldError::InvalidRequest);
                    }
                    let op = if add {
                        BodyOp::SetAdd {
                            path: "assignees".into(),
                            value: actor.as_bytes().to_vec(),
                        }
                    } else {
                        BodyOp::SetRemove {
                            path: "assignees".into(),
                            value: actor.as_bytes().to_vec(),
                        }
                    };
                    staging.issue(&key, op);
                }
                let mut ev = event(if add { "assigned" } else { "unassigned" }, &device, ts);
                ev.c = who
                    .iter()
                    .map(|w| EventChange {
                        f: "assignees".into(),
                        from: (!add).then(|| w.clone()),
                        to: add.then(|| w.clone()),
                    })
                    .collect();
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Label {
                doc,
                add,
                new_labels,
                remove,
                device,
                ts,
            } => {
                let _issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                for label in &add {
                    if !catalog.labels.contains_key(label) {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                for label in &remove {
                    if !catalog.labels.contains_key(label) {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                let key = issue_key(&doc);
                for new_label in &new_labels {
                    staging.catalog(map_set(
                        "labels",
                        new_label.id.clone(),
                        serde_json::to_vec(&serde_json::json!({
                            "name": new_label.name,
                            "color": new_label.color,
                        }))
                        .expect("label json"),
                    ));
                }
                for label in add.iter().chain(new_labels.iter().map(|l| &l.id)) {
                    staging.issue(
                        &key,
                        BodyOp::SetAdd {
                            path: "labels".into(),
                            value: label.as_bytes().to_vec(),
                        },
                    );
                }
                for label in &remove {
                    staging.issue(
                        &key,
                        BodyOp::SetRemove {
                            path: "labels".into(),
                            value: label.as_bytes().to_vec(),
                        },
                    );
                }
                push_event(&mut staging, ctx, &doc, &event("labeled", &device, ts));
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Comment {
                doc,
                body,
                actor,
                device,
                ts,
            } => {
                if body.is_empty() || ActorId::parse(&actor).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let key = issue_key(&doc);
                staging.issue(
                    &key,
                    BodyOp::ListInsert {
                        path: "comments".into(),
                        index: issue.comments.len() as u64,
                        value: serde_json::to_vec(&StoredComment {
                            a: actor,
                            t: ts,
                            b: body.clone(),
                        })
                        .expect("comment json"),
                    },
                );
                let mut ev = event("commented", &device, ts);
                ev.x = body;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::SetTombstone {
                doc,
                on,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                staging.catalog(map_set(
                    "tombstones",
                    doc.clone(),
                    if on { "1" } else { "0" },
                ));
                if on {
                    board_remove(&mut staging, &catalog, &issue.project, &doc);
                } else {
                    board_insert_top(&mut staging, &catalog, &issue.project, &doc);
                }
                push_event(
                    &mut staging,
                    ctx,
                    &doc,
                    &event(if on { "deleted" } else { "restored" }, &device, ts),
                );
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Link {
                doc,
                kind,
                target,
                add,
                device,
                ts,
            } => {
                let kind = kind.to_ascii_lowercase();
                if !LINK_KINDS.contains(&kind.as_str()) || doc == target {
                    return Err(WorldError::InvalidRequest);
                }
                let _issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let _other = issue_state(ctx, &target).ok_or(WorldError::InvalidRequest)?;
                // `relates` is symmetric: canonicalize by sorted endpoints.
                let (from, to) = if kind == "relates" && target < doc {
                    (target.clone(), doc.clone())
                } else {
                    (doc.clone(), target.clone())
                };
                let edge = format!("{from}|{kind}|{to}");
                if add {
                    staging.catalog(map_set("edges", edge, "1"));
                } else {
                    if !catalog
                        .edges
                        .contains(&(from.clone(), kind.clone(), to.clone()))
                    {
                        return Err(WorldError::InvalidRequest);
                    }
                    staging.catalog(BodyOp::MapRemove {
                        path: "edges".into(),
                        key: edge,
                    });
                }
                let mut ev = event(if add { "linked" } else { "unlinked" }, &device, ts);
                ev.x = format!("{kind} {target}");
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Parent {
                doc,
                parent,
                device,
                ts,
            } => {
                let _issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if let Some(parent) = &parent {
                    if parent == &doc {
                        return Err(WorldError::Conflict);
                    }
                    let _p = issue_state(ctx, parent).ok_or(WorldError::InvalidRequest)?;
                    if is_ancestor(&catalog, parent, &doc) {
                        return Err(WorldError::Conflict);
                    }
                }
                staging.catalog(map_set(
                    "parents",
                    doc.clone(),
                    parent.clone().unwrap_or_default(),
                ));
                let mut ev = event("parented", &device, ts);
                ev.x = parent.unwrap_or_else(|| "unparented".into());
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::WorkState {
                doc,
                action,
                actor,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if ActorId::parse(&actor).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                let (category, kind) = match action {
                    WorkAction::Start => (StatusCategory::Active, "started"),
                    WorkAction::Done => (StatusCategory::Done, "finished"),
                    WorkAction::Stop => (StatusCategory::Backlog, "stopped"),
                };
                let target = catalog
                    .first_state_in(category)
                    .ok_or(WorldError::Conflict)?
                    .clone();
                let key = issue_key(&doc);
                let mut changes = Vec::new();
                if issue.status != target.id {
                    changes.push(EventChange {
                        f: "status".into(),
                        from: Some(issue.status.clone()),
                        to: Some(target.id.clone()),
                    });
                    staging.issue(&key, reg("status", target.id.as_bytes().to_vec()));
                    let was_done = catalog.status_category(&issue.status) == StatusCategory::Done;
                    let is_done = category == StatusCategory::Done;
                    if is_done && !was_done {
                        board_remove(&mut staging, &catalog, &issue.project, &doc);
                    } else if was_done && !is_done {
                        board_insert_top(&mut staging, &catalog, &issue.project, &doc);
                    }
                }
                let me = ActorId::parse(&actor).expect("validated above");
                let assigned = issue.assignees.contains(&me);
                match action {
                    WorkAction::Start if !assigned => {
                        changes.push(EventChange {
                            f: "assignees".into(),
                            from: None,
                            to: Some("@me".into()),
                        });
                        staging.issue(
                            &key,
                            BodyOp::SetAdd {
                                path: "assignees".into(),
                                value: actor.as_bytes().to_vec(),
                            },
                        );
                    }
                    WorkAction::Stop if assigned => {
                        changes.push(EventChange {
                            f: "assignees".into(),
                            from: Some("@me".into()),
                            to: None,
                        });
                        staging.issue(
                            &key,
                            BodyOp::SetRemove {
                                path: "assignees".into(),
                                value: actor.as_bytes().to_vec(),
                            },
                        );
                    }
                    _ => {}
                }
                if staging.ops.is_empty() {
                    // The idempotent no-op: nothing committed, nothing rung.
                    return Ok(unchanged_effect(Some(doc)));
                }
                let mut ev = event(kind, &device, ts);
                ev.c = changes;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::ProjectNew {
                id,
                name,
                key,
                device: _,
                ts: _,
            } => {
                let key = key.trim().to_ascii_uppercase();
                if name.trim().is_empty()
                    || key.is_empty()
                    || key.len() > 8
                    || !key.bytes().all(|b| b.is_ascii_alphabetic())
                {
                    return Err(WorldError::InvalidRequest);
                }
                if catalog.projects.values().any(|p| p.key == key) {
                    return Err(WorldError::Conflict);
                }
                staging.catalog(map_set(
                    "projects",
                    id,
                    serde_json::to_vec(&serde_json::json!({
                        "name": name.trim(),
                        "key": key,
                        "color": "blue",
                    }))
                    .expect("project json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::LabelNew {
                id,
                name,
                color,
                device: _,
                ts: _,
            } => {
                if name.trim().is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                if catalog
                    .labels
                    .values()
                    .any(|l| l.name.eq_ignore_ascii_case(&name))
                {
                    return Err(WorldError::Conflict);
                }
                staging.catalog(map_set(
                    "labels",
                    id,
                    serde_json::to_vec(&serde_json::json!({
                        "name": name,
                        "color": color,
                    }))
                    .expect("label json"),
                ));
                Ok(staging.into_effect(None))
            }
        }
    }

    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let query = IssueQuery::from_json(&query.payload).ok_or(WorldError::InvalidRequest)?;
        let catalog = catalog_state(ctx);
        let aliases = derive_aliases(&catalog);
        let projection = |bytes: Vec<u8>| WorldProjection {
            schema: contract::issue_schema(),
            schema_version: contract::ISSUE_SCHEMA_VERSION,
            bytes,
            frontier: replica::ReplicaFrontier::EMPTY, // stamped by Runtime
            demand: contract::demand_read(),
        };
        let load_issues = |ctx: &WorldContext<'_>| -> BTreeMap<String, IssueState> {
            catalog
                .doc_ids()
                .into_iter()
                .filter_map(|doc| issue_state(ctx, &doc).map(|s| (doc, s)))
                .collect()
        };
        match query {
            IssueQuery::Snapshot => {
                let value = serde_json::json!({
                    "catalog": catalog,
                    "aliases": {
                        "by_doc": aliases.by_doc,
                        "by_alias": aliases.by_alias,
                        "canonical": aliases.canonical,
                    },
                });
                Ok(projection(serde_json::to_vec(&value).expect("snapshot")))
            }
            IssueQuery::View { doc, me } => {
                let me = me.and_then(|m| ActorId::parse(&m));
                let issue = issue_state(ctx, &doc);
                let view = match issue {
                    Some(issue) => {
                        // The space id rides in the projection consumer; the
                        // World does not know it — stamp a placeholder the
                        // daemon replaces? No: the daemon supplies it in the
                        // query. Provisional views come from the row path.
                        issue_view(&catalog, &aliases, &space_placeholder(), &doc, &issue)
                    }
                    None => provisional_view(&catalog, &aliases, &doc),
                };
                let _ = me;
                Ok(projection(serde_json::to_vec(&view).expect("view json")))
            }
            IssueQuery::List {
                project,
                label,
                status,
                mine,
                all,
                me,
            } => {
                let me = me.and_then(|m| ActorId::parse(&m));
                let mine = mine.and_then(|m| ActorId::parse(&m));
                let issues = load_issues(ctx);
                let mut rows: Vec<(String, Row2)> = Vec::new();
                for (doc, issue) in &issues {
                    if let Some(project) = &project {
                        if &issue.project != project {
                            continue;
                        }
                    }
                    let tomb = catalog.tombstones.contains(doc);
                    let done = catalog.status_category(&issue.status) == StatusCategory::Done;
                    if !all && (tomb || done) {
                        continue;
                    }
                    if let Some(status) = &status {
                        if &issue.status != status {
                            continue;
                        }
                    }
                    if let Some(label) = &label {
                        if !issue.labels.contains(label) {
                            continue;
                        }
                    }
                    if let Some(mine) = &mine {
                        if !issue.assignees.contains(mine) {
                            continue;
                        }
                    }
                    rows.push((
                        doc.clone(),
                        Row2 {
                            row: project_row(&catalog, &aliases, doc, Some(issue), me.as_ref()),
                            priority: issue.priority,
                        },
                    ));
                }
                rows.sort_by(|(da, a), (db, b)| {
                    b.priority.cmp(&a.priority).then_with(|| da.cmp(db))
                });
                let rows: Vec<crate::dto::Row> = rows.into_iter().map(|(_, r)| r.row).collect();
                Ok(projection(serde_json::to_vec(&rows).expect("rows json")))
            }
            IssueQuery::Board { project, me } => {
                let me = me.and_then(|m| ActorId::parse(&m));
                let issues = load_issues(ctx);
                let view = board_view(&catalog, &aliases, &project, &issues, me.as_ref())
                    .ok_or(WorldError::InvalidRequest)?;
                Ok(projection(serde_json::to_vec(&view).expect("board json")))
            }
            IssueQuery::Graph { doc, me } => {
                let me = me.and_then(|m| ActorId::parse(&m));
                let issues = load_issues(ctx);
                let view = graph_view(&catalog, &aliases, &doc, &issues, me.as_ref());
                Ok(projection(serde_json::to_vec(&view).expect("graph json")))
            }
            IssueQuery::History { doc } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let reff = canonical_for(&aliases, &doc);
                let events: Vec<ActivityEvent> = issue
                    .events
                    .iter()
                    .enumerate()
                    .map(|(i, e)| ActivityEvent {
                        seq: (i + 1) as u64,
                        doc_id: DocId::parse(&doc),
                        reff: reff.clone(),
                        kind: e.k.clone(),
                        changes: e
                            .c
                            .iter()
                            .map(|c| FieldChange {
                                field: c.f.clone(),
                                from: c.from.clone(),
                                to: c.to.clone(),
                            })
                            .collect(),
                        actor: crate::ids::DeviceId::parse(&e.d),
                        actor_nick: String::new(),
                        text: e.x.clone(),
                        ts: e.t,
                        collision: false,
                    })
                    .collect();
                let last = events.len() as u64;
                let value = serde_json::json!({ "events": events, "last": last });
                Ok(projection(serde_json::to_vec(&value).expect("history")))
            }
            IssueQuery::Projects => {
                let projects: Vec<crate::dto::ProjectDto> = catalog
                    .projects
                    .iter()
                    .filter_map(|(id, meta)| project_dto(id, meta))
                    .collect();
                let mut projects = projects;
                projects.sort_by(|a, b| a.key.cmp(&b.key));
                Ok(projection(
                    serde_json::to_vec(&projects).expect("projects json"),
                ))
            }
            IssueQuery::Labels => {
                let labels: Vec<crate::dto::LabelDto> = catalog
                    .labels
                    .iter()
                    .filter_map(|(id, meta)| label_dto(id, meta))
                    .collect();
                let mut labels = labels;
                labels.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(projection(
                    serde_json::to_vec(&labels).expect("labels json"),
                ))
            }
        }
    }
}

struct Row2 {
    row: crate::dto::Row,
    priority: Priority,
}

fn space_placeholder() -> crate::ids::SpaceId {
    // IssueView carries the SpaceId; the daemon-side adapter overwrites it
    // with the Station's Space before returning the view to a client.
    crate::ids::SpaceId::from_digest([0u8; 16])
}

fn provisional_view(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    doc: &str,
) -> crate::dto::IssueView {
    let row = project_row(catalog, aliases, doc, None, None);
    crate::dto::IssueView {
        schema_version: VIEW_SCHEMA_VERSION,
        reff: row.reff,
        doc_id: row.doc_id,
        space_id: space_placeholder(),
        project_id: row.project_id,
        project_key: None,
        key_alias: row.key_alias,
        title: row.title,
        description: String::new(),
        status: row.status,
        priority: row.priority,
        assignees: vec![],
        labels: vec![],
        label_names: vec![],
        comments: vec![],
        created_by: ActorId::from_incept_hash(&"0".repeat(64)),
        created_at: 0,
        provisional: true,
        corrupt_records: vec![],
    }
}

fn graph_view(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    doc: &str,
    issues: &BTreeMap<String, IssueState>,
    me: Option<&ActorId>,
) -> crate::dto::GraphView {
    let live = |d: &str| issues.contains_key(d) && !catalog.tombstones.contains(d);
    let row = |d: &str| project_row(catalog, aliases, d, issues.get(d), me);
    let parent = catalog.parents.get(doc).filter(|p| live(p)).map(|p| row(p));
    let mut children: Vec<crate::dto::Row> = catalog
        .parents
        .iter()
        .filter(|(c, p)| p.as_str() == doc && live(c))
        .map(|(c, _)| row(c))
        .collect();
    children.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
    let mut links = Vec::new();
    for (from, kind, to) in &catalog.edges {
        if from == doc && live(to) {
            links.push(crate::dto::LinkDto {
                kind: kind.clone(),
                direction: "out".into(),
                row: row(to),
            });
        } else if to == doc && live(from) {
            links.push(crate::dto::LinkDto {
                kind: kind.clone(),
                direction: "in".into(),
                row: row(from),
            });
        }
    }
    // Transitive open blockers via BFS backward over `blocks` edges.
    let mut blocked_by = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::new();
    queue.push_back(doc.to_string());
    visited.insert(doc.to_string());
    while let Some(cursor) = queue.pop_front() {
        for (from, kind, to) in &catalog.edges {
            if kind == "blocks" && to == &cursor && visited.insert(from.clone()) {
                let open = issues
                    .get(from)
                    .is_some_and(|i| catalog.status_category(&i.status) != StatusCategory::Done);
                if live(from) && open {
                    blocked_by.push(row(from));
                    queue.push_back(from.clone());
                }
            }
        }
    }
    crate::dto::GraphView {
        schema_version: VIEW_SCHEMA_VERSION,
        reff: canonical_for(aliases, doc),
        doc_id: DocId::parse(doc).expect("doc id"),
        parent,
        children,
        links,
        blocked_by,
    }
}
