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
use std::sync::Arc;

use replica::body::{BodyOp, BodySchema, CollaborativeSchema, MutationModel};
use replica::ids::BodyKey;
use runtime::{
    BodyDeclaration, World, WorldContext, WorldEffect, WorldError, WorldIntent, WorldProjection,
    WorldQuery,
};

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
    /// The derived read-model cache, keyed by the EXACT Manifest root each
    /// query is pinned to — registered in `tests/mixed_root_guard.rs` with its
    /// mixed-root rejection proof. A hit is only ever the same root, so output
    /// mixing two roots is unrepresentable; per-issue entries are additionally
    /// reused across roots ONLY under a reader-issued version stamp
    /// ([`runtime::world::BodyReader::body_stamp`]) that guarantees
    /// byte-equivalence.
    cache: std::sync::Mutex<RootKeyedCache>,
}

/// See [`IssuesWorld::cache`].
#[derive(Default)]
struct RootKeyedCache {
    /// `(manifest root, derived snapshot)` — a bounded, most-recent-last list.
    roots: Vec<([u8; 32], Arc<DerivedSnapshot>)>,
    /// Per-issue parsed state: `doc -> (stamp, state)`.
    issues: std::collections::HashMap<String, (Vec<u8>, Arc<IssueState>)>,
}

/// The immutable read model every query arm consumes: the integrity-checked
/// catalog, its derived aliases, and every issue's parsed state — all from ONE
/// committed snapshot (one Manifest root).
struct DerivedSnapshot {
    catalog: Arc<CatalogState>,
    aliases: Arc<DerivedAliases>,
    issues: BTreeMap<String, Arc<IssueState>>,
}

/// How many recent roots stay warm: the current root plus the previous one
/// (a doorbell-raced query may still be pinned to the prior root).
const CACHED_ROOTS: usize = 2;

impl IssuesWorld {
    /// The derived read model for THIS context's Manifest root: served from
    /// the cache when the root is warm, else built from the committed snapshot
    /// (reusing per-issue parses whose reader stamp is unchanged) and cached
    /// under the root. A zero root (fixture contexts without a snapshot
    /// identity) is never cached.
    fn derived_snapshot(&self, ctx: &WorldContext<'_>) -> Result<Arc<DerivedSnapshot>, WorldError> {
        let root = ctx.manifest_root();
        let identified = root != [0u8; 32];
        if identified {
            let cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
            if let Some((_, snap)) = cache.roots.iter().find(|(r, _)| r == &root) {
                return Ok(snap.clone());
            }
        }
        let catalog = Arc::new(catalog_state(ctx)?);
        let mut cache = self.cache.lock().unwrap_or_else(|p| p.into_inner());
        let mut issues: BTreeMap<String, Arc<IssueState>> = BTreeMap::new();
        for doc in catalog.doc_ids() {
            let stamp = ctx.body_stamp(&issue_key(&doc));
            let state = match (&stamp, cache.issues.get(&doc)) {
                (Some(stamp), Some((cached_stamp, state))) if stamp == cached_stamp => {
                    state.clone()
                }
                _ => match issue_state(ctx, &doc) {
                    Some(state) => Arc::new(state),
                    None => continue,
                },
            };
            if let Some(stamp) = stamp {
                cache.issues.insert(doc.clone(), (stamp, state.clone()));
            }
            issues.insert(doc, state);
        }
        let aliases = Arc::new(derive_aliases(&catalog, |doc| {
            issues.get(doc).map(|issue| issue.project.as_str())
        }));
        // Registered docs are the live set: drop parses for departed docs.
        cache.issues.retain(|doc, _| issues.contains_key(doc));
        let snap = Arc::new(DerivedSnapshot {
            catalog,
            aliases,
            issues,
        });
        if identified {
            cache.roots.retain(|(r, _)| r != &root);
            cache.roots.push((root, snap.clone()));
            if cache.roots.len() > CACHED_ROOTS {
                let drop_count = cache.roots.len() - CACHED_ROOTS;
                cache.roots.drain(..drop_count);
            }
        }
        Ok(snap)
    }
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
            cache: std::sync::Mutex::new(RootKeyedCache::default()),
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
struct Staging {
    /// The Space the transaction commits in — the deterministic Catalog's
    /// identity input.
    space: mechanics::ids::SpaceId,
    ops: Vec<(BodyKey, BodyOp)>,
    scopes: Vec<BodyKey>,
    declarations: Vec<BodyDeclaration>,
    /// Whether a catalog op must carry the creation declaration — true exactly
    /// when the committed snapshot holds no Catalog yet (first-ever write).
    declare_catalog_on_use: bool,
    /// The canonical demand this mutation requires (defaults to contributor).
    demand: Option<Vec<u8>>,
}

impl Staging {
    fn for_space(space: mechanics::ids::SpaceId, declare_catalog_on_use: bool) -> Self {
        Self {
            space,
            ops: Vec::new(),
            scopes: Vec::new(),
            declarations: Vec::new(),
            declare_catalog_on_use,
            demand: None,
        }
    }
}

impl Staging {
    /// Declarations ride ONLY the transaction that may create a Body.
    ///
    /// A Body's `(schema, version)` binding is immutable once recorded, and a
    /// later declaration must equal it exactly — so declaring the compiled-in
    /// version on every write would turn the first schema-version bump into a
    /// `ContractViolation` against every pre-existing Body. An existing Body
    /// resolves its own binding without any declaration; only creation needs
    /// one, so only creation carries one.
    fn declare_issue(&mut self, key: &BodyKey) {
        if !self.declarations.iter().any(|d| &d.key == key) {
            self.declarations.push(BodyDeclaration {
                key: key.clone(),
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
            });
        }
    }

    /// See [`Self::declare_issue`] — attached exactly when this transaction
    /// may bring the Catalog into being (`declare_catalog_on_use`). Joiners
    /// adopt the Catalog through Manifest synchronization and never
    /// re-declare it.
    fn declare_catalog(&mut self) {
        let key = catalog_key(&self.space);
        if !self.declarations.iter().any(|d| d.key == key) {
            self.declarations.push(BodyDeclaration {
                key: key.clone(),
                schema: contract::catalog_schema(),
                schema_version: contract::CATALOG_SCHEMA_VERSION,
            });
        }
    }

    fn issue(&mut self, key: &BodyKey, op: BodyOp) {
        if matches!(op, BodyOp::Create) {
            self.declare_issue(key);
        }
        if !self.scopes.contains(key) {
            self.scopes.push(key.clone());
        }
        self.ops.push((key.clone(), op));
    }

    fn catalog(&mut self, op: BodyOp) {
        if self.declare_catalog_on_use {
            self.declare_catalog();
        }
        let key = catalog_key(&self.space);
        if !self.scopes.contains(&key) {
            self.scopes.push(key.clone());
        }
        self.ops.push((key, op));
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

/// The committed Catalog view with singleton-integrity enforcement: exactly
/// the ONE deterministic Catalog key for this Space, or nothing (not yet
/// initialized/adopted). Any other catalog-schema Body — wrong key, a
/// duplicate semantic Catalog, an unrelated Catalog-shaped Body — is typed
/// [`WorldError::WorldStateCorrupt`]; the World never selects among, merges,
/// repairs, or silently recreates Catalogs.
fn checked_catalog_view(
    ctx: &WorldContext<'_>,
) -> Result<Option<replica::CollaborativeView>, WorldError> {
    let expected = catalog_key(&ctx.principal().space);
    let catalogs = ctx.bodies_with_schema(&contract::world_id(), &contract::catalog_schema());
    match catalogs.as_slice() {
        [] => Ok(None),
        [one] if one == &expected => match ctx.read_collaborative(&expected) {
            Some(view) => Ok(Some(view)),
            // Bound as a catalog but unreadable under the collaborative
            // model: a wrong-model/encoding Body, not a missing one.
            None => Err(WorldError::WorldStateCorrupt),
        },
        _ => Err(WorldError::WorldStateCorrupt),
    }
}

/// Load the catalog state from the committed snapshot (integrity-checked).
fn catalog_state(ctx: &WorldContext<'_>) -> Result<CatalogState, WorldError> {
    Ok(CatalogState::from_view(checked_catalog_view(ctx)?.as_ref()))
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

/// Resolve the deterministic transition gate `from -> to` for a project: the
/// demand template stored on the selected transition of the project's current
/// workflow revision, plus the receipt-bound transition evidence. A missing
/// revision on an existing project is corrupt catalog state; an edge the
/// workflow does not define is an invalid transition — never inferred.
fn transition_gate(
    catalog: &CatalogState,
    project: &str,
    from: &str,
    to: &str,
) -> Result<(Vec<u8>, crate::world::workflow::WorkflowTransitionEvidence), WorldError> {
    // The single usable head gates transitions; concurrent heads block them
    // (and further ordinary edits) until `workflow set --expect-head`
    // resolves. A project with NO revision at all is corrupt catalog state.
    if !catalog.workflow_revisions.contains_key(project) {
        return Err(WorldError::WorldStateCorrupt);
    }
    let revision = catalog.workflow_head(project).ok_or(WorldError::Conflict)?;
    let transition = revision
        .body
        .transition_for(from, to)
        .ok_or(WorldError::InvalidRequest)?;
    let demand = transition.demand_template.resolve(project);
    let bytes = demand
        .encode_canonical()
        .map_err(|_| WorldError::ContractViolation)?;
    let digest = demand.digest().map_err(|_| WorldError::ContractViolation)?;
    let evidence = crate::world::workflow::WorkflowTransitionEvidence {
        transition_id: transition.transition_id.clone(),
        workflow_revision_id: revision.revision_id.clone(),
        source_state: from.to_string(),
        destination_state: to.to_string(),
        resolved_demand_digest: data_encoding::HEXLOWER.encode(&digest),
    };
    Ok((bytes, evidence))
}

/// Whether every capability id is registered for the declared scope kind
/// (sorted, unique, non-empty).
fn validate_role_caps(
    caps: &[String],
    scope: crate::world::roles::ScopeKind,
) -> Result<(), WorldError> {
    if caps.is_empty() {
        return Err(WorldError::InvalidRequest);
    }
    let mut sorted = caps.to_vec();
    sorted.sort();
    sorted.dedup();
    if sorted.len() != caps.len() {
        return Err(WorldError::InvalidRequest);
    }
    let registered = |c: &str| match scope {
        crate::world::roles::ScopeKind::Space => contract::is_space_capability(c),
        crate::world::roles::ScopeKind::Project => contract::is_project_capability(c),
    };
    if caps.iter().any(|c| !registered(c)) {
        return Err(WorldError::InvalidRequest);
    }
    Ok(())
}

/// The single usable custom-role head, which must match `expected` exactly.
/// Multiple heads are a typed conflict that blocks edits until resolved.
fn expect_single_head<'a>(
    catalog: &'a CatalogState,
    role_id: &str,
    expected: &str,
) -> Result<&'a crate::world::views::StoredRoleRevision, WorldError> {
    let heads = catalog.role_heads(role_id);
    match heads.as_slice() {
        [] => Err(WorldError::InvalidRequest),
        [one] if one.body.tombstone => Err(WorldError::InvalidRequest),
        [one] if one.revision_id == expected => Ok(one),
        [_one] => Err(WorldError::Conflict),
        _ => Err(WorldError::Conflict),
    }
}

fn decode_hex32(hex: &str) -> Result<[u8; 32], WorldError> {
    let raw = data_encoding::HEXLOWER
        .decode(hex.as_bytes())
        .map_err(|_| WorldError::InvalidRequest)?;
    raw.as_slice()
        .try_into()
        .map_err(|_| WorldError::InvalidRequest)
}

/// Stage one role revision into the grow-only log.
fn stage_role_revision(staging: &mut Staging, revision: &crate::world::roles::RoleRevision) {
    let stored = crate::world::views::StoredRoleRevision {
        revision_id: data_encoding::HEXLOWER.encode(&revision.revision_id),
        predecessor_ids: revision
            .predecessor_ids
            .iter()
            .map(|p| data_encoding::HEXLOWER.encode(p))
            .collect(),
        body: revision.body.clone(),
    };
    staging.catalog(map_set(
        "role_revisions",
        format!("{}/{}", revision.body.role_id, stored.revision_id),
        serde_json::to_vec(&stored).expect("role revision json"),
    ));
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
        let intent = IssueIntent::from_json(&intent.payload).ok_or(WorldError::InvalidRequest)?;
        let catalog_view = checked_catalog_view(ctx)?;
        let catalog = CatalogState::from_view(catalog_view.as_ref());
        let mut staging = Staging::for_space(ctx.principal().space.clone(), catalog_view.is_none());
        drop(catalog_view);
        match intent {
            IssueIntent::InitializeTracker {
                name,
                ts,
                project_id,
                project_name,
                project_key,
                device: _,
                built_in_roles,
                capability_registry_commitment,
                default_workflow_commitment,
            } => {
                // A deterministic pure validator/stager: every captured value
                // arrives in the intent (the composition root persisted the
                // signed bytes); the World calls no clock and mints no id.
                let project_key = project_key.trim().to_ascii_uppercase();
                if project_name.trim().is_empty()
                    || project_key.is_empty()
                    || project_key.len() > 8
                    || !project_key.bytes().all(|b| b.is_ascii_alphabetic())
                    || project_id.is_empty()
                    || ts == 0
                {
                    return Err(WorldError::InvalidRequest);
                }
                // The golden commitments must match this implementation's
                // compiled-in definitions exactly.
                let registry_hex =
                    data_encoding::HEXLOWER.encode(&contract::capability_registry_commitment());
                if capability_registry_commitment != registry_hex {
                    return Err(WorldError::InvalidRequest);
                }
                let workflow_revision =
                    crate::world::workflow::default_workflow_revision(&project_id);
                if default_workflow_commitment != workflow_revision.revision_id {
                    return Err(WorldError::InvalidRequest);
                }
                let mut goldens: Vec<(String, String, String)> = Vec::new();
                for id in crate::world::roles::BUILT_IN_ROLE_IDS {
                    let rev = crate::world::roles::built_in(id).expect("built-in role");
                    goldens.push((
                        id.to_string(),
                        data_encoding::HEXLOWER.encode(&rev.revision_id),
                        data_encoding::HEXLOWER.encode(&rev.body.definition_digest()),
                    ));
                }
                if built_in_roles != goldens {
                    return Err(WorldError::InvalidRequest);
                }
                // The deterministic Catalog must not exist yet: joiners adopt
                // it through Manifest synchronization and never create it, and
                // a second initialization never merges into the first. An
                // exact replay is answered by the request receipt before the
                // World runs; a content-identical re-run is a no-op.
                if let Some(view) = checked_catalog_view(ctx)? {
                    let initialized = view.lists.get("workflow").is_some_and(|l| !l.is_empty());
                    if initialized {
                        return Ok(unchanged_effect(None));
                    }
                    return Err(WorldError::Conflict);
                }
                // ---- one atomic Catalog transaction: display name, legacy
                // workflow states, the workflow revision, the initial project,
                // the built-in role definitions, and the registry commitment.
                staging.catalog(reg("name", name.into_bytes()));
                staging.catalog(reg("initialized_at", ts.to_string().into_bytes()));
                staging.catalog(reg(
                    "capability_registry",
                    registry_hex.clone().into_bytes(),
                ));
                for (i, state) in contract::default_workflow().into_iter().enumerate() {
                    staging.catalog(BodyOp::ListInsert {
                        path: "workflow".into(),
                        index: i as u64,
                        value: serde_json::to_vec(&state).expect("workflow json"),
                    });
                }
                staging.catalog(map_set(
                    "workflow_revisions",
                    format!("{project_id}/{}", workflow_revision.revision_id),
                    serde_json::to_vec(&workflow_revision).expect("workflow revision json"),
                ));
                staging.catalog(map_set(
                    "projects",
                    project_id.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "name": project_name.trim(),
                        "key": project_key,
                        "color": "blue",
                    }))
                    .expect("project json"),
                ));
                for id in crate::world::roles::BUILT_IN_ROLE_IDS {
                    let rev = crate::world::roles::built_in(id).expect("built-in role");
                    staging.catalog(map_set(
                        "roles",
                        id,
                        serde_json::to_vec(&serde_json::json!({
                            "revision_id": data_encoding::HEXLOWER.encode(&rev.revision_id),
                            "predecessor_ids": [],
                            "body": serde_json::from_slice::<serde_json::Value>(
                                &rev.body.canonical_json()
                            )
                            .expect("role body json"),
                        }))
                        .expect("role json"),
                    ));
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
                duedate,
                estimate,
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
                if duedate == Some(0) || estimate.is_some_and(|e| e > contract::MAX_ESTIMATE) {
                    return Err(WorldError::InvalidRequest);
                }
                let key = issue_key(&doc);
                staging.issue(&key, BodyOp::Create);
                staging.issue(&key, reg("projectid", project.as_bytes().to_vec()));
                staging.issue(&key, reg("title", title.as_bytes().to_vec()));
                staging.issue(&key, reg("status", DEFAULT_STATUS.as_bytes().to_vec()));
                staging.issue(&key, reg("priority", priority.as_bytes().to_vec()));
                staging.issue(&key, reg("createdby", actor.as_bytes().to_vec()));
                staging.issue(&key, reg("createdat", ts.to_string().into_bytes()));
                if let Some(due) = duedate {
                    staging.issue(&key, reg("duedate", due.to_string().into_bytes()));
                }
                if let Some(points) = estimate {
                    staging.issue(&key, reg("estimate", points.to_string().into_bytes()));
                }
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
                duedate,
                estimate,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if title.is_none()
                    && status.is_none()
                    && priority.is_none()
                    && description.is_none()
                    && duedate.is_none()
                    && estimate.is_none()
                {
                    return Err(WorldError::InvalidRequest);
                }
                if duedate == Some(Some(0))
                    || estimate
                        .flatten()
                        .is_some_and(|e| e > contract::MAX_ESTIMATE)
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
                let mut transition_evidence = None;
                if let Some(status) = &status {
                    if *status != issue.status {
                        // The deterministic transition gate: the demand
                        // template stored on the workflow's selected edge, and
                        // the evidence the receipt binds through the demand,
                        // intent and operations digests.
                        let (demand, evidence) =
                            transition_gate(&catalog, &issue.project, &issue.status, status)?;
                        staging.require(demand);
                        transition_evidence = Some(evidence);
                    }
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
                if let Some(duedate) = duedate {
                    if duedate != issue.duedate {
                        changes.push(EventChange {
                            f: "duedate".into(),
                            from: issue.duedate.map(|d| d.to_string()),
                            to: duedate.map(|d| d.to_string()),
                        });
                        match duedate {
                            Some(due) => {
                                staging.issue(&key, reg("duedate", due.to_string().into_bytes()))
                            }
                            None => staging.issue(
                                &key,
                                BodyOp::RegisterClear {
                                    path: "duedate".into(),
                                },
                            ),
                        }
                    }
                }
                if let Some(estimate) = estimate {
                    if estimate != issue.estimate {
                        changes.push(EventChange {
                            f: "estimate".into(),
                            from: issue.estimate.map(|e| e.to_string()),
                            to: estimate.map(|e| e.to_string()),
                        });
                        match estimate {
                            Some(points) => staging
                                .issue(&key, reg("estimate", points.to_string().into_bytes())),
                            None => staging.issue(
                                &key,
                                BodyOp::RegisterClear {
                                    path: "estimate".into(),
                                },
                            ),
                        }
                    }
                }
                if staging.ops.is_empty() {
                    return Ok(unchanged_effect(Some(doc)));
                }
                let mut ev = event("edited", &device, ts);
                ev.c = changes;
                if let Some(evidence) = &transition_evidence {
                    // The transition evidence rides the durable history event,
                    // inside the operations digest the receipt binds.
                    ev.x = serde_json::to_string(evidence).expect("transition evidence json");
                }
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
                id,
                parent,
                actor,
                device,
                ts,
            } => {
                if body.is_empty() || ActorId::parse(&actor).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if let Some(id) = &id {
                    // The daemon mints; the World re-validates — including
                    // uniqueness, because a duplicated id would fuse two
                    // comments' reactions and replies.
                    if !contract::is_comment_id(id)
                        || issue.comments.iter().any(|c| c.id.as_deref() == Some(id))
                    {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                if let Some(parent) = &parent {
                    // A reply needs an addressable target: an existing comment
                    // that carries an id (pre-identity comments cannot anchor
                    // threads) and is itself a root — one level, no ladders.
                    let target = issue
                        .comments
                        .iter()
                        .find(|c| c.id.as_deref() == Some(parent.as_str()))
                        .ok_or(WorldError::InvalidRequest)?;
                    if id.is_none() || target.parent.is_some() {
                        return Err(WorldError::InvalidRequest);
                    }
                }
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
                            id,
                            parent,
                        })
                        .expect("comment json"),
                    },
                );
                let mut ev = event("commented", &device, ts);
                ev.x = body;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::React {
                doc,
                comment,
                emoji,
                actor,
                on,
                device: _,
                ts: _,
            } => {
                if ActorId::parse(&actor).is_none()
                    || !contract::is_comment_id(&comment)
                    || !contract::is_reaction_emoji(&emoji)
                {
                    return Err(WorldError::InvalidRequest);
                }
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if !issue
                    .comments
                    .iter()
                    .any(|c| c.id.as_deref() == Some(comment.as_str()))
                {
                    return Err(WorldError::InvalidRequest);
                }
                let value = contract::reaction_value(&emoji, &actor);
                let path = contract::reaction_path(&comment);
                staging.issue(
                    &issue_key(&doc),
                    if on {
                        BodyOp::SetAdd { path, value }
                    } else {
                        BodyOp::SetRemove { path, value }
                    },
                );
                // No history event, deliberately — see the intent's contract
                // note: a reaction is a social signal, not a change of record.
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
                let mut transition_evidence = None;
                if issue.status != target.id {
                    // The category target's resulting edge must exist in the
                    // project's workflow revision and authorize.
                    let (demand, evidence) =
                        transition_gate(&catalog, &issue.project, &issue.status, &target.id)?;
                    staging.require(demand);
                    transition_evidence = Some(evidence);
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
                if let Some(evidence) = &transition_evidence {
                    ev.x = serde_json::to_string(evidence).expect("transition evidence json");
                }
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::ProjectNew {
                id,
                name,
                key,
                color,
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
                    id.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "name": name.trim(),
                        "key": key,
                        "color": color,
                    }))
                    .expect("project json"),
                ));
                // Every project carries a workflow revision from birth: the
                // deterministic default (free movement, every edge an explicit
                // replaceable gate).
                let revision = crate::world::workflow::default_workflow_revision(&id);
                staging.catalog(map_set(
                    "workflow_revisions",
                    format!("{id}/{}", revision.revision_id),
                    serde_json::to_vec(&revision).expect("workflow revision json"),
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
            IssueIntent::ProjectEdit {
                id,
                name,
                color,
                description,
                lead,
                start_date,
                target_date,
                archived,
                team,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("project.configure"));
                let current = catalog
                    .projects
                    .get(&id)
                    .ok_or(WorldError::InvalidRequest)?;
                let mut meta = current.clone();
                if let Some(name) = name {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        return Err(WorldError::InvalidRequest);
                    }
                    // No name-uniqueness guard: projects are unique on KEY, not
                    // name (which stays immutable here), so two may share a name.
                    meta.name = name;
                }
                if let Some(color) = color {
                    meta.color = color;
                }
                if let Some(description) = description {
                    meta.description = description;
                }
                if let Some(lead) = lead {
                    meta.lead = lead;
                }
                if let Some(start) = start_date {
                    meta.start_date = start;
                }
                if let Some(target) = target_date {
                    meta.target_date = target;
                }
                if let Some(archived) = archived {
                    meta.archived = archived;
                }
                if let Some(team) = team {
                    // Empty clears; a set names a live team.
                    if !team.is_empty() && !catalog.teams.get(&team).is_some_and(|t| !t.tombstone) {
                        return Err(WorldError::InvalidRequest);
                    }
                    meta.team = team;
                }
                // Nothing changed: don't emit an op that would look like an edit.
                if meta == *current {
                    return Ok(staging.into_effect(None));
                }
                // Serialize the whole record so an edit never drops a field the
                // caller didn't touch.
                staging.catalog(map_set(
                    "projects",
                    id.clone(),
                    serde_json::to_vec(&meta).expect("project json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::ProjectUpdatePost {
                project_id,
                id,
                author,
                body,
                health,
                device: _,
                ts,
            } => {
                staging.require(contract::demand_space_any("project.configure"));
                if !catalog.projects.contains_key(&project_id) {
                    return Err(WorldError::InvalidRequest);
                }
                let body = body.trim();
                if body.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let update = crate::world::views::ProjectUpdate {
                    id: id.clone(),
                    project_id: project_id.clone(),
                    author,
                    ts,
                    body: body.to_string(),
                    health,
                };
                staging.catalog(map_set(
                    "project_updates",
                    format!("{project_id}/{id}"),
                    serde_json::to_vec(&update).expect("project update json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::LabelEdit {
                id,
                name,
                color,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("catalog.label.configure"));
                let current = catalog.labels.get(&id).ok_or(WorldError::InvalidRequest)?;
                let mut meta = current.clone();
                if let Some(name) = name {
                    let name = name.trim().to_string();
                    if name.is_empty() {
                        return Err(WorldError::InvalidRequest);
                    }
                    // Case-insensitive uniqueness against the OTHER labels — the
                    // same guard `LabelNew` applies, minus this label itself.
                    if catalog
                        .labels
                        .iter()
                        .any(|(lid, l)| lid != &id && l.name.eq_ignore_ascii_case(&name))
                    {
                        return Err(WorldError::Conflict);
                    }
                    meta.name = name;
                }
                if let Some(color) = color {
                    meta.color = color;
                }
                if meta == *current {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(map_set(
                    "labels",
                    id.clone(),
                    serde_json::to_vec(&serde_json::json!({
                        "name": meta.name,
                        "color": meta.color,
                    }))
                    .expect("label json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::LabelDelete {
                id,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("catalog.label.configure"));
                if !catalog.labels.contains_key(&id) {
                    return Err(WorldError::InvalidRequest);
                }
                staging.catalog(BodyOp::MapRemove {
                    path: "labels".into(),
                    key: id,
                });
                Ok(staging.into_effect(None))
            }
            IssueIntent::SpaceRename {
                name,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_admin());
                let name = name.trim();
                if name.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                if catalog.name == name {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(reg("name", name.to_string().into_bytes()));
                Ok(staging.into_effect(None))
            }
            IssueIntent::SpaceDescribe {
                description,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_admin());
                // Empty clears; no trim so intentional leading/trailing prose is
                // preserved. LWW on the catalog `description` register.
                if catalog.description == description {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(reg("description", description.into_bytes()));
                Ok(staging.into_effect(None))
            }
            IssueIntent::RoleCreate {
                role_id,
                scope_project,
                name,
                description,
                capabilities,
                device: _,
                ts: _,
            } => {
                // Custom ids only: `role_<ULID>`; built-in ids and free-form
                // ids reject. The daemon mints the id; the World re-validates.
                if !role_id.starts_with("role_")
                    || role_id.len() > 64
                    || crate::world::roles::built_in(&role_id).is_some()
                {
                    return Err(WorldError::InvalidRequest);
                }
                if catalog.roles.contains_key(&role_id)
                    || catalog.role_revisions.contains_key(&role_id)
                {
                    return Err(WorldError::Conflict);
                }
                let scope_kind = match &scope_project {
                    None => crate::world::roles::ScopeKind::Space,
                    Some(project) => {
                        if !catalog.projects.contains_key(project) {
                            return Err(WorldError::InvalidRequest);
                        }
                        crate::world::roles::ScopeKind::Project
                    }
                };
                validate_role_caps(&capabilities, scope_kind)?;
                let body = crate::world::roles::RoleBody {
                    role_id: role_id.clone(),
                    scope_kind,
                    name,
                    description,
                    capabilities,
                    tombstone: false,
                };
                let revision = crate::world::roles::build_revision(body, vec![])
                    .map_err(|_| WorldError::InvalidRequest)?;
                stage_role_revision(&mut staging, &revision);
                staging.require(contract::demand_space_any("policy.configure"));
                Ok(staging.into_effect(None))
            }
            IssueIntent::RoleEdit {
                role_id,
                expected_revision,
                name,
                description,
                capabilities,
                device: _,
                ts: _,
            } => {
                if catalog.roles.contains_key(&role_id) {
                    // Built-ins are immutable in every field.
                    return Err(WorldError::InvalidRequest);
                }
                let head = expect_single_head(&catalog, &role_id, &expected_revision)?;
                let mut body = head.body.clone();
                if let Some(name) = name {
                    body.name = name;
                }
                if let Some(description) = description {
                    body.description = description;
                }
                if let Some(capabilities) = capabilities {
                    validate_role_caps(&capabilities, body.scope_kind)?;
                    body.capabilities = capabilities;
                }
                let predecessor = decode_hex32(&expected_revision)?;
                let revision = crate::world::roles::build_revision(body, vec![predecessor])
                    .map_err(|_| WorldError::InvalidRequest)?;
                stage_role_revision(&mut staging, &revision);
                staging.require(contract::demand_space_any("policy.configure"));
                Ok(staging.into_effect(None))
            }
            IssueIntent::RoleDelete {
                role_id,
                expected_revision,
                device: _,
                ts: _,
            } => {
                if catalog.roles.contains_key(&role_id) {
                    return Err(WorldError::InvalidRequest);
                }
                let head = expect_single_head(&catalog, &role_id, &expected_revision)?;
                let mut body = head.body.clone();
                body.tombstone = true;
                let predecessor = decode_hex32(&expected_revision)?;
                let revision = crate::world::roles::build_revision(body, vec![predecessor])
                    .map_err(|_| WorldError::InvalidRequest)?;
                stage_role_revision(&mut staging, &revision);
                staging.require(contract::demand_space_any("policy.configure"));
                Ok(staging.into_effect(None))
            }
            IssueIntent::RoleResolve {
                role_id,
                expected_heads,
                body_json,
                device: _,
                ts: _,
            } => {
                if catalog.roles.contains_key(&role_id) {
                    return Err(WorldError::InvalidRequest);
                }
                let mut current: Vec<String> = catalog
                    .role_heads(&role_id)
                    .iter()
                    .map(|h| h.revision_id.clone())
                    .collect();
                current.sort();
                let mut expected = expected_heads.clone();
                expected.sort();
                expected.dedup();
                if current.is_empty() || current != expected {
                    return Err(WorldError::Conflict);
                }
                let body: crate::world::roles::RoleBody =
                    serde_json::from_str(&body_json).map_err(|_| WorldError::InvalidRequest)?;
                if body.role_id != role_id {
                    return Err(WorldError::InvalidRequest);
                }
                validate_role_caps(&body.capabilities, body.scope_kind)?;
                let predecessors: Vec<[u8; 32]> = expected
                    .iter()
                    .map(|h| decode_hex32(h))
                    .collect::<Result<_, _>>()?;
                let revision = crate::world::roles::build_revision(body, predecessors)
                    .map_err(|_| WorldError::InvalidRequest)?;
                stage_role_revision(&mut staging, &revision);
                staging.require(contract::demand_space_any("policy.configure"));
                Ok(staging.into_effect(None))
            }
            IssueIntent::WorkflowReplace {
                project_id,
                expected_heads,
                body_json,
                device: _,
                ts: _,
            } => {
                if !catalog.projects.contains_key(&project_id) {
                    return Err(WorldError::InvalidRequest);
                }
                let mut current: Vec<String> = catalog
                    .workflow_heads(&project_id)
                    .iter()
                    .map(|h| h.revision_id.clone())
                    .collect();
                current.sort();
                let mut expected = expected_heads.clone();
                expected.sort();
                expected.dedup();
                if current.is_empty() || current != expected {
                    return Err(WorldError::Conflict);
                }
                let body: crate::world::workflow::WorkflowBody =
                    serde_json::from_str(&body_json).map_err(|_| WorldError::InvalidRequest)?;
                if body.project_id != project_id {
                    return Err(WorldError::InvalidRequest);
                }
                let predecessors: Vec<[u8; 32]> = expected
                    .iter()
                    .map(|h| decode_hex32(h))
                    .collect::<Result<_, _>>()?;
                let revision = crate::world::workflow::build_revision(body, predecessors)
                    .map_err(|_| WorldError::InvalidRequest)?;
                staging.catalog(map_set(
                    "workflow_revisions",
                    format!("{project_id}/{}", revision.revision_id),
                    serde_json::to_vec(&revision).expect("workflow revision json"),
                ));
                staging.require(contract::demand_space_any("catalog.workflow.configure"));
                Ok(staging.into_effect(None))
            }
            IssueIntent::ProjectDelete {
                id,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_project_any("project.delete", &id));
                if !catalog.projects.contains_key(&id) {
                    return Err(WorldError::InvalidRequest);
                }
                // The safe v1 (CUSTOM-10): a project still referenced by ANY
                // issue — live or tombstoned — refuses. Every doc's alias keys
                // off its project; deleting under one would orphan it
                // silently. Reassign (`issue move`) or archive instead.
                let referenced = ctx
                    .bodies_with_schema(&contract::world_id(), &contract::issue_schema())
                    .iter()
                    .filter_map(|key| ctx.read_collaborative(key))
                    .any(|view| IssueState::from_view(&view).project == id);
                if referenced {
                    return Err(WorldError::Conflict);
                }
                let map_remove = |path: &str, key: String| BodyOp::MapRemove {
                    path: path.into(),
                    key,
                };
                staging.catalog(map_remove("projects", id.clone()));
                if catalog.aliases.contains_key(&id) {
                    staging.catalog(map_remove("aliases", id.clone()));
                }
                for rev in catalog.workflow_revisions.get(&id).into_iter().flatten() {
                    staging.catalog(map_remove(
                        "workflow_revisions",
                        format!("{id}/{}", rev.revision_id),
                    ));
                }
                for update in catalog.project_updates.get(&id).into_iter().flatten() {
                    staging.catalog(map_remove("project_updates", format!("{id}/{}", update.id)));
                }
                for mid in catalog
                    .milestones
                    .get(&id)
                    .into_iter()
                    .flat_map(|m| m.keys())
                {
                    staging.catalog(map_remove("project_milestones", format!("{id}/{mid}")));
                }
                for cid in catalog.cycles.get(&id).into_iter().flat_map(|c| c.keys()) {
                    staging.catalog(map_remove("cycles", format!("{id}/{cid}")));
                }
                // Initiatives referencing the project drop it from their
                // member list in the same transaction.
                for (iid, initiative) in &catalog.initiatives {
                    if initiative.projects.contains(&id) {
                        let mut updated = initiative.clone();
                        updated.projects.retain(|p| p != &id);
                        staging.catalog(map_set(
                            "initiatives",
                            iid.clone(),
                            serde_json::to_vec(&updated).expect("initiative json"),
                        ));
                    }
                }
                Ok(staging.into_effect(None))
            }
            IssueIntent::Follow {
                doc,
                actor,
                on,
                device: _,
                ts: _,
            } => {
                if ActorId::parse(&actor).is_none() {
                    return Err(WorldError::InvalidRequest);
                }
                let _issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let value = actor.into_bytes();
                staging.issue(
                    &issue_key(&doc),
                    if on {
                        BodyOp::SetAdd {
                            path: "followers".into(),
                            value,
                        }
                    } else {
                        BodyOp::SetRemove {
                            path: "followers".into(),
                            value,
                        }
                    },
                );
                // No history event, like `React` — following is a personal
                // signal, not a change of record.
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::MilestoneSet {
                project_id,
                id,
                name,
                target_date,
                tombstone,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("project.configure"));
                if !catalog.projects.contains_key(&project_id) || id.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let current = catalog
                    .milestones
                    .get(&project_id)
                    .and_then(|m| m.get(&id))
                    .cloned();
                let mut record = match current.clone() {
                    Some(m) => m,
                    None => {
                        let name = name.clone().unwrap_or_default();
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        crate::world::views::Milestone {
                            id: id.clone(),
                            project_id: project_id.clone(),
                            name: name.trim().to_string(),
                            target_date: None,
                            tombstone: false,
                        }
                    }
                };
                if current.is_some() {
                    if let Some(name) = &name {
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        record.name = name.trim().to_string();
                    }
                }
                if let Some(target) = target_date {
                    record.target_date = target;
                }
                if let Some(tombstone) = tombstone {
                    record.tombstone = tombstone;
                }
                if current.as_ref() == Some(&record) {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(map_set(
                    "project_milestones",
                    format!("{project_id}/{id}"),
                    serde_json::to_vec(&record).expect("milestone json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::IssueMilestone {
                doc,
                milestone,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let label = match &milestone {
                    Some(m) => {
                        let record = catalog
                            .milestones
                            .get(&issue.project)
                            .and_then(|ms| ms.get(m))
                            .filter(|r| !r.tombstone)
                            .ok_or(WorldError::InvalidRequest)?;
                        staging.issue(&issue_key(&doc), reg("milestone", m.as_bytes().to_vec()));
                        record.name.clone()
                    }
                    None => {
                        staging.issue(
                            &issue_key(&doc),
                            BodyOp::RegisterClear {
                                path: "milestone".into(),
                            },
                        );
                        "none".into()
                    }
                };
                if issue.milestone == milestone {
                    return Ok(unchanged_effect(Some(doc)));
                }
                let mut ev = event("milestoned", &device, ts);
                ev.x = label;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::CycleSet {
                project_id,
                id,
                name,
                start,
                end,
                tombstone,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("project.configure"));
                if !catalog.projects.contains_key(&project_id) || id.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let current = catalog
                    .cycles
                    .get(&project_id)
                    .and_then(|c| c.get(&id))
                    .cloned();
                let mut record = match current.clone() {
                    Some(c) => c,
                    None => {
                        let name = name.clone().unwrap_or_default();
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        crate::world::views::Cycle {
                            id: id.clone(),
                            project_id: project_id.clone(),
                            name: name.trim().to_string(),
                            start: 0,
                            end: 0,
                            tombstone: false,
                        }
                    }
                };
                if current.is_some() {
                    if let Some(name) = &name {
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        record.name = name.trim().to_string();
                    }
                }
                if let Some(start) = start {
                    record.start = start.unwrap_or(0);
                }
                if let Some(end) = end {
                    record.end = end.unwrap_or(0);
                }
                if record.start != 0 && record.end != 0 && record.end < record.start {
                    return Err(WorldError::InvalidRequest);
                }
                if let Some(tombstone) = tombstone {
                    record.tombstone = tombstone;
                }
                if current.as_ref() == Some(&record) {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(map_set(
                    "cycles",
                    format!("{project_id}/{id}"),
                    serde_json::to_vec(&record).expect("cycle json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::IssueCycle {
                doc,
                cycle,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let label = match &cycle {
                    Some(c) => {
                        let record = catalog
                            .cycles
                            .get(&issue.project)
                            .and_then(|cs| cs.get(c))
                            .filter(|r| !r.tombstone)
                            .ok_or(WorldError::InvalidRequest)?;
                        staging.issue(&issue_key(&doc), reg("cycle", c.as_bytes().to_vec()));
                        record.name.clone()
                    }
                    None => {
                        staging.issue(
                            &issue_key(&doc),
                            BodyOp::RegisterClear {
                                path: "cycle".into(),
                            },
                        );
                        "none".into()
                    }
                };
                if issue.cycle == cycle {
                    return Ok(unchanged_effect(Some(doc)));
                }
                let mut ev = event("cycled", &device, ts);
                ev.x = label;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::InitiativeSet {
                id,
                name,
                description,
                owner,
                health,
                target_date,
                projects,
                tombstone,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_space_any("project.create"));
                if id.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let current = catalog.initiatives.get(&id).cloned();
                let mut record = match current.clone() {
                    Some(i) => i,
                    None => {
                        let name = name.clone().unwrap_or_default();
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        crate::world::views::Initiative {
                            id: id.clone(),
                            name: name.trim().to_string(),
                            ..Default::default()
                        }
                    }
                };
                if current.is_some() {
                    if let Some(name) = &name {
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        record.name = name.trim().to_string();
                    }
                }
                if let Some(description) = description {
                    record.description = description;
                }
                if let Some(owner) = owner {
                    if !owner.is_empty() && ActorId::parse(&owner).is_none() {
                        return Err(WorldError::InvalidRequest);
                    }
                    record.owner = owner;
                }
                if let Some(health) = health {
                    if !health.is_empty() && !contract::HEALTH_LABELS.contains(&health.as_str()) {
                        return Err(WorldError::InvalidRequest);
                    }
                    record.health = health;
                }
                if let Some(target) = target_date {
                    record.target_date = target;
                }
                if let Some(projects) = projects {
                    for project in &projects {
                        if !catalog.projects.contains_key(project) {
                            return Err(WorldError::InvalidRequest);
                        }
                    }
                    record.projects = projects;
                }
                if let Some(tombstone) = tombstone {
                    record.tombstone = tombstone;
                }
                if current.as_ref() == Some(&record) {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(map_set(
                    "initiatives",
                    id.clone(),
                    serde_json::to_vec(&record).expect("initiative json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::TeamSet {
                id,
                name,
                key,
                icon,
                lead,
                members,
                tombstone,
                device: _,
                ts: _,
            } => {
                staging.require(contract::demand_admin());
                if id.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let current = catalog.teams.get(&id).cloned();
                let mut record = match current.clone() {
                    Some(t) => t,
                    None => {
                        let name = name.clone().unwrap_or_default();
                        let key = key.clone().unwrap_or_default().to_ascii_uppercase();
                        if name.trim().is_empty()
                            || key.is_empty()
                            || key.len() > 8
                            || !key.bytes().all(|b| b.is_ascii_alphabetic())
                        {
                            return Err(WorldError::InvalidRequest);
                        }
                        if catalog.teams.values().any(|t| !t.tombstone && t.key == key) {
                            return Err(WorldError::Conflict);
                        }
                        crate::world::views::Team {
                            id: id.clone(),
                            name: name.trim().to_string(),
                            key,
                            ..Default::default()
                        }
                    }
                };
                if current.is_some() {
                    // The key binds at creation, like a project key.
                    if key.is_some_and(|k| k.to_ascii_uppercase() != record.key) {
                        return Err(WorldError::InvalidRequest);
                    }
                    if let Some(name) = &name {
                        if name.trim().is_empty() {
                            return Err(WorldError::InvalidRequest);
                        }
                        record.name = name.trim().to_string();
                    }
                }
                if let Some(icon) = icon {
                    record.icon = icon;
                }
                if let Some(lead) = lead {
                    if !lead.is_empty() && ActorId::parse(&lead).is_none() {
                        return Err(WorldError::InvalidRequest);
                    }
                    record.lead = lead;
                }
                if let Some(mut members) = members {
                    for member in &members {
                        if ActorId::parse(member).is_none() {
                            return Err(WorldError::InvalidRequest);
                        }
                    }
                    members.sort();
                    members.dedup();
                    record.members = members;
                }
                if let Some(tombstone) = tombstone {
                    record.tombstone = tombstone;
                }
                if current.as_ref() == Some(&record) {
                    return Ok(staging.into_effect(None));
                }
                staging.catalog(map_set(
                    "teams",
                    id.clone(),
                    serde_json::to_vec(&record).expect("team json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::TriageSubmit {
                id,
                title,
                body,
                source,
                actor,
                device: _,
                ts,
            } => {
                if title.trim().is_empty()
                    || id.is_empty()
                    || ActorId::parse(&actor).is_none()
                    || catalog.triage.contains_key(&id)
                {
                    return Err(WorldError::InvalidRequest);
                }
                let item = crate::world::views::TriageItem {
                    id: id.clone(),
                    title: title.trim().to_string(),
                    body,
                    source,
                    submitted_by: actor,
                    ts,
                    ..Default::default()
                };
                staging.catalog(map_set(
                    "triage",
                    id,
                    serde_json::to_vec(&item).expect("triage json"),
                ));
                Ok(staging.into_effect(None))
            }
            IssueIntent::TriageDecide {
                id,
                outcome,
                project,
                doc,
                note,
                actor,
                device,
                ts,
            } => {
                staging.require(contract::demand_space_any("project.create"));
                if !contract::TRIAGE_OUTCOMES.contains(&outcome.as_str())
                    || ActorId::parse(&actor).is_none()
                {
                    return Err(WorldError::InvalidRequest);
                }
                let item = catalog.triage.get(&id).ok_or(WorldError::InvalidRequest)?;
                // Decided exactly once.
                if !item.outcome.is_empty() {
                    return Err(WorldError::Conflict);
                }
                let mut decided = item.clone();
                decided.outcome = outcome.clone();
                decided.decided_by = actor.clone();
                decided.decided_ts = ts;
                decided.note = note;
                match outcome.as_str() {
                    "accepted" => {
                        // Atomically create the issue in the same transaction
                        // that stamps the outcome — an accept can never half
                        // happen.
                        let project = project.ok_or(WorldError::InvalidRequest)?;
                        let doc = doc.ok_or(WorldError::InvalidRequest)?;
                        if !catalog.projects.contains_key(&project) || DocId::parse(&doc).is_none()
                        {
                            return Err(WorldError::InvalidRequest);
                        }
                        let key = issue_key(&doc);
                        staging.issue(&key, BodyOp::Create);
                        staging.issue(&key, reg("projectid", project.as_bytes().to_vec()));
                        staging.issue(&key, reg("title", item.title.as_bytes().to_vec()));
                        staging.issue(&key, reg("status", DEFAULT_STATUS.as_bytes().to_vec()));
                        staging.issue(&key, reg("priority", "none".as_bytes().to_vec()));
                        staging.issue(
                            &key,
                            reg("createdby", item.submitted_by.as_bytes().to_vec()),
                        );
                        staging.issue(&key, reg("createdat", ts.to_string().into_bytes()));
                        if !item.body.is_empty() {
                            staging.issue(
                                &key,
                                BodyOp::TextSplice {
                                    path: "description".into(),
                                    index: 0,
                                    delete: 0,
                                    insert: item.body.clone(),
                                },
                            );
                        }
                        let next = catalog.aliases.get(&project).copied().unwrap_or(0) + 1;
                        staging.catalog(map_set("aliases", project.clone(), next.to_string()));
                        staging.catalog(map_set("seqs", doc.clone(), next.to_string()));
                        board_insert_top(&mut staging, &catalog, &project, &doc);
                        push_event(&mut staging, ctx, &doc, &event("created", &device, ts));
                        decided.doc = doc;
                    }
                    "duplicate" => {
                        let doc = doc.ok_or(WorldError::InvalidRequest)?;
                        let _target = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                        decided.doc = doc;
                    }
                    _ => {}
                }
                staging.catalog(map_set(
                    "triage",
                    id,
                    serde_json::to_vec(&decided).expect("triage json"),
                ));
                let doc = (!decided.doc.is_empty() && decided.outcome == "accepted")
                    .then(|| decided.doc.clone());
                Ok(staging.into_effect(doc))
            }
            IssueIntent::Attach {
                doc,
                id,
                name,
                mime,
                data_b64,
                comment,
                actor,
                device,
                ts,
            } => {
                if ActorId::parse(&actor).is_none()
                    || !id.starts_with("att_")
                    || name.trim().is_empty()
                {
                    return Err(WorldError::InvalidRequest);
                }
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                if issue.attachments.iter().any(|a| a.id == id) {
                    return Err(WorldError::InvalidRequest);
                }
                if issue.attachments.len() >= contract::MAX_ATTACHMENTS_PER_ISSUE {
                    return Err(WorldError::LimitExceeded);
                }
                let raw = data_encoding::BASE64
                    .decode(data_b64.as_bytes())
                    .map_err(|_| WorldError::InvalidRequest)?;
                if raw.is_empty() || raw.len() > contract::MAX_ATTACHMENT_BYTES {
                    return Err(WorldError::LimitExceeded);
                }
                if let Some(comment) = &comment {
                    if !issue
                        .comments
                        .iter()
                        .any(|c| c.id.as_deref() == Some(comment.as_str()))
                    {
                        return Err(WorldError::InvalidRequest);
                    }
                }
                let name = name.trim().to_string();
                let record = serde_json::json!({
                    "id": id,
                    "name": name,
                    "mime": mime,
                    "size": raw.len() as u64,
                    "by": actor,
                    "ts": ts,
                    "comment": comment.unwrap_or_default(),
                    "data_b64": data_b64,
                });
                staging.issue(
                    &issue_key(&doc),
                    BodyOp::MapSet {
                        path: "attachments".into(),
                        key: id,
                        value: serde_json::to_vec(&record).expect("attachment json"),
                    },
                );
                let mut ev = event("attached", &device, ts);
                ev.x = name;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
            IssueIntent::Detach {
                doc,
                id,
                device,
                ts,
            } => {
                let issue = issue_state(ctx, &doc).ok_or(WorldError::InvalidRequest)?;
                let Some(meta) = issue.attachments.iter().find(|a| a.id == id) else {
                    return Err(WorldError::InvalidRequest);
                };
                let name = meta.name.clone();
                staging.issue(
                    &issue_key(&doc),
                    BodyOp::MapRemove {
                        path: "attachments".into(),
                        key: id,
                    },
                );
                let mut ev = event("detached", &device, ts);
                ev.x = name;
                push_event(&mut staging, ctx, &doc, &ev);
                Ok(staging.into_effect(Some(doc)))
            }
        }
    }

    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let query = IssueQuery::from_json(&query.payload).ok_or(WorldError::InvalidRequest)?;
        // ONE derived read model per Manifest root; every arm below reads the
        // same immutable snapshot (see [`IssuesWorld::derived_snapshot`]).
        let snap = self.derived_snapshot(ctx)?;
        let catalog: &CatalogState = &snap.catalog;
        let aliases: &DerivedAliases = &snap.aliases;
        let projection = |bytes: Vec<u8>| WorldProjection {
            schema: contract::issue_schema(),
            schema_version: contract::ISSUE_SCHEMA_VERSION,
            bytes,
            frontier: replica::ReplicaFrontier::EMPTY, // stamped by Runtime
            demand: contract::demand_read(),
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
                let issue = snap.issues.get(&doc);
                let view = match issue {
                    Some(issue) => {
                        // The space id rides in the projection consumer; the
                        // World does not know it — stamp a placeholder the
                        // daemon replaces? No: the daemon supplies it in the
                        // query. Provisional views come from the row path.
                        issue_view(catalog, aliases, &space_placeholder(), &doc, issue)
                    }
                    None => provisional_view(catalog, aliases, &doc),
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
                let mut rows: Vec<(String, Row2)> = Vec::new();
                for (doc, issue) in &snap.issues {
                    if let Some(project) = &project {
                        if &issue.project != project {
                            continue;
                        }
                    } else if catalog
                        .projects
                        .get(&issue.project)
                        .is_some_and(|m| m.archived)
                    {
                        // No explicit project: an archived project's issues stay
                        // out of the all-project list (CUSTOM-9). Opening the
                        // project by ref passes `project` and bypasses this.
                        continue;
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
                            row: project_row(catalog, aliases, doc, Some(issue), me.as_ref()),
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
                let view = board_view(catalog, aliases, &project, &snap.issues, me.as_ref())
                    .ok_or(WorldError::InvalidRequest)?;
                Ok(projection(serde_json::to_vec(&view).expect("board json")))
            }
            IssueQuery::Graph { doc, me } => {
                let me = me.and_then(|m| ActorId::parse(&m));
                let view = graph_view(catalog, aliases, &doc, &snap.issues, me.as_ref());
                Ok(projection(serde_json::to_vec(&view).expect("graph json")))
            }
            IssueQuery::History { doc } => {
                let issue = snap.issues.get(&doc).ok_or(WorldError::InvalidRequest)?;
                let reff = canonical_for(aliases, &doc);
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
            IssueQuery::Activity { since } => {
                // The whole-space feed: every event of every issue (tombstoned
                // issues keep their history — the rows already happened),
                // ordered deterministically by `(ts, doc, per-doc index)` so
                // every converged replica derives the identical sequence. The
                // cursor is a position in that total order: `since = last`
                // resumes exactly after the previously served tail.
                let mut feed: Vec<(u64, &String, usize, &IssueEvent)> = Vec::new();
                for (doc, issue) in &snap.issues {
                    for (i, e) in issue.events.iter().enumerate() {
                        feed.push((e.t, doc, i, e));
                    }
                }
                feed.sort_by(|a, b| (a.0, a.1, a.2).cmp(&(b.0, b.1, b.2)));
                let last = feed.len() as u64;
                let events: Vec<ActivityEvent> = feed
                    .into_iter()
                    .enumerate()
                    .map(|(pos, (_, doc, _, e))| ActivityEvent {
                        seq: (pos + 1) as u64,
                        doc_id: DocId::parse(doc),
                        reff: canonical_for(aliases, doc),
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
                    .filter(|e| e.seq > since)
                    .collect();
                let value = serde_json::json!({ "events": events, "last": last });
                Ok(projection(serde_json::to_vec(&value).expect("activity")))
            }
            IssueQuery::Inbox {
                actor,
                exclude_device,
            } => {
                let actor = ActorId::parse(&actor).ok_or(WorldError::InvalidRequest)?;
                let mut entries: Vec<serde_json::Value> = Vec::new();
                for (doc, issue) in &snap.issues {
                    // Addressed-to-you: assigned, or subscribed (INBOX-9) —
                    // followers receive the same event kinds without holding
                    // the assignment.
                    if !issue.assignees.contains(&actor) && !issue.followers.contains(&actor) {
                        continue;
                    }
                    let reff = canonical_for(aliases, doc);
                    for e in &issue.events {
                        let kind = match e.k.as_str() {
                            "assigned" => "assigned",
                            "commented" => "comment",
                            "started" | "finished" | "stopped" => "status",
                            "edited" if e.c.iter().any(|c| c.f == "status") => "status",
                            _ => continue,
                        };
                        if exclude_device.as_deref() == Some(e.d.as_str()) {
                            continue;
                        }
                        entries.push(serde_json::json!({
                            "ts": e.t,
                            "kind": kind,
                            "reff": reff,
                            "doc_id": doc,
                            "title": issue.title,
                            "detail": e.x,
                            "actor": e.d,
                        }));
                    }
                }
                entries.sort_by(|a, b| b["ts"].as_u64().cmp(&a["ts"].as_u64()));
                entries.truncate(500);
                Ok(projection(serde_json::to_vec(&entries).expect("inbox")))
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
            IssueQuery::ProjectUpdates { project } => {
                let mut updates: Vec<crate::dto::ProjectUpdateDto> = catalog
                    .project_updates
                    .get(&project)
                    .into_iter()
                    .flatten()
                    .map(|u| crate::dto::ProjectUpdateDto {
                        id: u.id.clone(),
                        author: u.author.clone(),
                        ts: u.ts,
                        body: u.body.clone(),
                        health: u.health.clone(),
                    })
                    .collect();
                // Newest first; ids are ULIDs so id order is time order, a stable
                // tiebreak when two updates share a second.
                updates.sort_by(|a, b| b.ts.cmp(&a.ts).then_with(|| b.id.cmp(&a.id)));
                Ok(projection(
                    serde_json::to_vec(&updates).expect("project updates json"),
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
            IssueQuery::Roles => {
                let mut roles: Vec<serde_json::Value> = Vec::new();
                for (id, rev) in &catalog.roles {
                    roles.push(serde_json::json!({
                        "role_id": id,
                        "built_in": true,
                        "revision": rev,
                        "conflict_heads": [],
                    }));
                }
                for id in catalog.role_revisions.keys() {
                    let heads = catalog.role_heads(id);
                    let head = catalog.role_head(id);
                    roles.push(serde_json::json!({
                        "role_id": id,
                        "built_in": false,
                        "revision": head,
                        "conflict_heads": if head.is_some() {
                            Vec::new()
                        } else {
                            heads.iter().map(|h| h.revision_id.clone()).collect()
                        },
                    }));
                }
                roles.sort_by(|a, b| a["role_id"].as_str().cmp(&b["role_id"].as_str()));
                Ok(projection(serde_json::to_vec(&roles).expect("roles json")))
            }
            IssueQuery::RoleShow { role } => {
                let heads = catalog.role_heads(&role);
                let head = catalog.role_head(&role);
                if head.is_none() && heads.is_empty() {
                    return Err(WorldError::InvalidRequest);
                }
                let view = serde_json::json!({
                    "role_id": role,
                    "built_in": catalog.roles.contains_key(&role),
                    "revision": head,
                    "conflict_heads": if head.is_some() {
                        Vec::new()
                    } else {
                        heads.iter().map(|h| h.revision_id.clone()).collect()
                    },
                });
                Ok(projection(serde_json::to_vec(&view).expect("role json")))
            }
            IssueQuery::Workflow { project } => {
                if !catalog.projects.contains_key(&project) {
                    return Err(WorldError::InvalidRequest);
                }
                let heads = catalog.workflow_heads(&project);
                let head = catalog.workflow_head(&project);
                let view = serde_json::json!({
                    "project_id": project,
                    "revision": head,
                    "conflict_heads": if head.is_some() {
                        Vec::new()
                    } else {
                        heads.iter().map(|h| h.revision_id.clone()).collect()
                    },
                });
                Ok(projection(
                    serde_json::to_vec(&view).expect("workflow json"),
                ))
            }
            IssueQuery::Milestones { project } => {
                if !catalog.projects.contains_key(&project) {
                    return Err(WorldError::InvalidRequest);
                }
                // Derived progress: live issues of the project targeting each
                // milestone, done = a Done-category status.
                let counts = |mid: &str| -> (u32, u32) {
                    let mut total = 0;
                    let mut done = 0;
                    for (doc, issue) in &snap.issues {
                        if issue.project != project
                            || issue.milestone.as_deref() != Some(mid)
                            || catalog.tombstones.contains(doc)
                        {
                            continue;
                        }
                        total += 1;
                        if catalog.status_category(&issue.status) == StatusCategory::Done {
                            done += 1;
                        }
                    }
                    (done, total)
                };
                let mut rows: Vec<crate::dto::MilestoneDto> = catalog
                    .milestones
                    .get(&project)
                    .into_iter()
                    .flat_map(|m| m.values())
                    .filter(|m| !m.tombstone)
                    .map(|m| {
                        let (done, total) = counts(&m.id);
                        crate::dto::MilestoneDto {
                            id: m.id.clone(),
                            name: m.name.clone(),
                            target_date: m.target_date,
                            total,
                            done,
                        }
                    })
                    .collect();
                rows.sort_by(|a, b| {
                    let key = |d: Option<u64>| d.unwrap_or(u64::MAX);
                    key(a.target_date)
                        .cmp(&key(b.target_date))
                        .then_with(|| a.name.cmp(&b.name))
                });
                Ok(projection(serde_json::to_vec(&rows).expect("milestones")))
            }
            IssueQuery::Cycles { project } => {
                if !catalog.projects.contains_key(&project) {
                    return Err(WorldError::InvalidRequest);
                }
                let counts = |cid: &str| -> (u32, u32) {
                    let mut total = 0;
                    let mut done = 0;
                    for (doc, issue) in &snap.issues {
                        if issue.project != project
                            || issue.cycle.as_deref() != Some(cid)
                            || catalog.tombstones.contains(doc)
                        {
                            continue;
                        }
                        total += 1;
                        if catalog.status_category(&issue.status) == StatusCategory::Done {
                            done += 1;
                        }
                    }
                    (done, total)
                };
                let mut rows: Vec<crate::dto::CycleDto> = catalog
                    .cycles
                    .get(&project)
                    .into_iter()
                    .flat_map(|c| c.values())
                    .filter(|c| !c.tombstone)
                    .map(|c| {
                        let (done, total) = counts(&c.id);
                        crate::dto::CycleDto {
                            id: c.id.clone(),
                            name: c.name.clone(),
                            start: c.start,
                            end: c.end,
                            total,
                            done,
                        }
                    })
                    .collect();
                rows.sort_by(|a, b| a.start.cmp(&b.start).then_with(|| a.name.cmp(&b.name)));
                Ok(projection(serde_json::to_vec(&rows).expect("cycles")))
            }
            IssueQuery::Initiatives => {
                let mut rows: Vec<crate::dto::InitiativeDto> = catalog
                    .initiatives
                    .values()
                    .filter(|i| !i.tombstone)
                    .map(|i| {
                        let mut total = 0;
                        let mut done = 0;
                        for (doc, issue) in &snap.issues {
                            if !i.projects.contains(&issue.project)
                                || catalog.tombstones.contains(doc)
                            {
                                continue;
                            }
                            total += 1;
                            if catalog.status_category(&issue.status) == StatusCategory::Done {
                                done += 1;
                            }
                        }
                        crate::dto::InitiativeDto {
                            id: i.id.clone(),
                            name: i.name.clone(),
                            description: i.description.clone(),
                            owner: i.owner.clone(),
                            health: i.health.clone(),
                            target_date: i.target_date,
                            projects: i
                                .projects
                                .iter()
                                .filter_map(|p| catalog.projects.get(p).map(|m| m.key.clone()))
                                .collect(),
                            total,
                            done,
                        }
                    })
                    .collect();
                rows.sort_by(|a, b| a.name.cmp(&b.name));
                Ok(projection(serde_json::to_vec(&rows).expect("initiatives")))
            }
            IssueQuery::Teams => {
                let mut rows: Vec<crate::dto::TeamDto> = catalog
                    .teams
                    .values()
                    .filter(|t| !t.tombstone)
                    .map(|t| crate::dto::TeamDto {
                        id: t.id.clone(),
                        name: t.name.clone(),
                        key: t.key.clone(),
                        icon: t.icon.clone(),
                        lead: t.lead.clone(),
                        members: t.members.clone(),
                        projects: catalog
                            .projects
                            .values()
                            .filter(|p| p.team == t.id)
                            .map(|p| p.key.clone())
                            .collect(),
                    })
                    .collect();
                rows.sort_by(|a, b| a.key.cmp(&b.key));
                Ok(projection(serde_json::to_vec(&rows).expect("teams")))
            }
            IssueQuery::Triage => {
                let reff_of = |doc: &str| -> String {
                    if doc.is_empty() {
                        String::new()
                    } else {
                        aliases
                            .by_doc
                            .get(doc)
                            .cloned()
                            .unwrap_or_else(|| canonical_for(aliases, doc))
                    }
                };
                let mut rows: Vec<crate::dto::TriageDto> = catalog
                    .triage
                    .values()
                    .map(|t| crate::dto::TriageDto {
                        id: t.id.clone(),
                        title: t.title.clone(),
                        body: t.body.clone(),
                        source: t.source.clone(),
                        submitted_by: t.submitted_by.clone(),
                        ts: t.ts,
                        outcome: t.outcome.clone(),
                        reff: reff_of(&t.doc),
                        decided_by: t.decided_by.clone(),
                        note: t.note.clone(),
                    })
                    .collect();
                // Pending first (newest first); decided after (newest first).
                rows.sort_by(|a, b| {
                    (!a.outcome.is_empty())
                        .cmp(&(!b.outcome.is_empty()))
                        .then_with(|| b.ts.cmp(&a.ts))
                        .then_with(|| a.id.cmp(&b.id))
                });
                Ok(projection(serde_json::to_vec(&rows).expect("triage")))
            }
            IssueQuery::Attachment { doc, id } => {
                // The one read that serves file bytes: straight off the Body
                // map, bypassing the metadata-only snapshot cache.
                let view = ctx
                    .read_collaborative(&issue_key(&doc))
                    .ok_or(WorldError::InvalidRequest)?;
                let raw = view
                    .maps
                    .get("attachments")
                    .and_then(|m| m.get(&id))
                    .ok_or(WorldError::InvalidRequest)?;
                let record: serde_json::Value =
                    serde_json::from_slice(raw).map_err(|_| WorldError::WorldStateCorrupt)?;
                Ok(projection(serde_json::to_vec(&record).expect("attachment")))
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
        due_date: None,
        estimate: None,
        followers: vec![],
        milestone: None,
        cycle: None,
        attachments: vec![],
        provisional: true,
        corrupt_records: vec![],
    }
}

fn graph_view(
    catalog: &CatalogState,
    aliases: &DerivedAliases,
    doc: &str,
    issues: &BTreeMap<String, Arc<IssueState>>,
    me: Option<&ActorId>,
) -> crate::dto::GraphView {
    let live = |d: &str| issues.contains_key(d) && !catalog.tombstones.contains(d);
    let row = |d: &str| project_row(catalog, aliases, d, issues.get(d).map(|i| i.as_ref()), me);
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
