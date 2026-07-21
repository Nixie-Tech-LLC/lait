//! The catalog document stores space structure in one Loro document: the
//! registry of issue documents, project and label configuration, board
//! ordering, workflow columns, the sub-issue hierarchy, the issue-link edge
//! set, and the `DocMeta`
//! row cache that lets lists/boards render without opening issue docs.
//!
//! The catalog is the multi-document container Loro structurally lacks
//! (one Loro doc = one tree): issue docs are *content*, the catalog is *nodes,
//! ordering, hierarchy, and edges* (`docs/DATA-CONTRACT.md`, catalog document).
//!
//! **Structural ownership.** Issue registration, projects, labels, workflow,
//! board ordering, hierarchy, and links are structural state: they control
//! navigation but grant no authority. `DocMeta` row fields are a one-directional
//! cache of the issue doc; every local edit and every import
//! recomputes the row via [`CatalogDoc::upsert_row`]. Nothing writes a row
//! field back into issue content. Signed content-authority events are replayed
//! separately from this structural state.
//!
//! **Cached heads.** `DocMeta.head` is a cache of the issue-doc frontiers:
//! `blake3(frontiers.encode())`. Because mirroring it is a second write to a
//! second doc, the store recomputes every head from the real issue frontiers on
//! load ([`CatalogDoc::upsert_row`] is the single writer of it).
//!
//! **Sub-issues.** The hierarchy is a tree-move CRDT,
//! never an LWW `parentId`: two peers concurrently moving A under B and B under
//! A each perform a locally-legal write whose combination is a cycle — only the
//! merge can adjudicate, and Loro's move algorithm (Kleppmann et al.,
//! IEEE TPDS 2022) converges it to a valid tree on every replica.
//!
//! **Links.** Issue links form an add-wins set keyed
//! `"<from>|<kind>|<to>"`. Referential integrity is filtered at read time (an
//! edge may name a tombstoned or not-yet-synced doc).

use anyhow::{anyhow, Result};
use loro::{
    Container, ExportMode, Frontiers, LoroDoc, LoroList, LoroMap, LoroMovableList, LoroTree,
    TreeID, TreeParentId, ValueOrContainer,
};

use crate::dto::{
    default_workflow, LabelDto, Priority, ProjectDto, StatusCategory, WorkflowState, SCHEMA_VERSION,
};
use crate::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SpaceId};

use crate::issue::IssueDoc;
use crate::loro_ext as lx;
use crate::op::{self, OpCtx};

const ROOT: &str = "catalog";
const K_SCHEMA: &str = "schemaVersion";
const K_NAME: &str = "name";
const C_DOCS: &str = "docs";
const C_PROJECTS: &str = "projects";
const C_BOARDS: &str = "boards";
const C_LABELS: &str = "labels";
const C_WORKFLOW: &str = "workflow";
const C_ACL: &str = "acl";
const C_ALIASES: &str = "aliases";
const C_SUBS: &str = "subs";
const C_EDGES: &str = "edges";
/// The content-authority DAG (`crate::authz`): signed tombstone ops et al.
/// Encrypted with the rest of the catalog — the blind relay learns nothing,
/// while signed replay determines which operations carry authority.
const C_AUTHZ: &str = "authz";
/// The tree-node meta key carrying the issue DocId a `subs` node stands for.
const META_DOC: &str = "docId";

/// Internal read of one `DocMeta` row. The `Row` DTO is projected
/// from this plus viewer context (UI "you" awareness) in the node layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RowMeta {
    pub doc_id: DocId,
    pub project_id: ProjectId,
    pub created_at: u64,
    pub tombstone: bool,
    pub seq: Option<u32>,
    pub title: String,
    pub status: String,
    pub priority: Priority,
    /// Full assignee actor ids. Viewer-relative summaries such as "you +2" are
    /// computed during projection rather than stored in this replicated cache.
    pub assignees: Vec<ActorId>,
    pub head: Vec<u8>,
    /// True when the issue document has not been loaded. Such a row is
    /// provisional until issue content arrives.
    pub provisional: bool,
}

/// One issue link: `from --kind--> to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Edge {
    pub from: DocId,
    pub kind: String,
    pub to: DocId,
}

/// A wrapper around the space's Catalog `LoroDoc`.
pub struct CatalogDoc {
    doc: LoroDoc,
}

impl CatalogDoc {
    /// Create a fresh Catalog for a space, seeding schema + display name +
    /// default workflow + the structure containers.
    pub fn create(
        space_id: &SpaceId,
        name: &str,
        peer: Option<u64>,
        founder: &DeviceId,
    ) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        let root = doc.get_map(ROOT);
        root.insert(K_SCHEMA, SCHEMA_VERSION as i64)?;
        root.insert(lx::K_SPACE, space_id.as_str())?;
        root.insert(K_NAME, name)?;
        root.insert_container(C_DOCS, LoroMap::new())?;
        root.insert_container(C_PROJECTS, LoroMap::new())?;
        root.insert_container(C_BOARDS, LoroMap::new())?;
        root.insert_container(C_LABELS, LoroMap::new())?;
        root.insert_container(C_ALIASES, LoroMap::new())?;
        root.insert_container(C_ACL, LoroList::new())?;
        root.insert_container(C_SUBS, LoroTree::new())?;
        root.insert_container(C_EDGES, LoroMap::new())?;
        root.insert_container(C_AUTHZ, LoroList::new())?;
        let wf = root.insert_container(C_WORKFLOW, LoroMovableList::new())?;
        for (i, state) in default_workflow().into_iter().enumerate() {
            let m = wf.insert_container(i, LoroMap::new())?;
            write_workflow_state(&m, &state)?;
        }
        op::commit_with(&doc, &OpCtx::structure("init", founder));
        Ok(Self { doc })
    }

    /// Load stored snapshot bytes with the fabric's required Loro configuration.
    pub fn from_snapshot(bytes: &[u8], peer: Option<u64>) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        doc.import(bytes)
            .map_err(|e| anyhow!("import catalog snapshot: {e}"))?;
        Ok(Self { doc })
    }

    /// A bare, uninitialized catalog for a joining replica. It must not
    /// `create()` its own containers: `create` mints peer-specific attached
    /// child containers (`docs`/`projects`/…), and merging the founder's ops
    /// would then LWW-resolve the root's child registers non-deterministically to
    /// an empty local container. Starting empty and importing the founder's full
    /// ops adopts the founder's exact container ids, so everything merges.
    pub fn empty(peer: Option<u64>) -> Self {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        Self { doc }
    }

    /// Land staged operations as one metadata-bearing change.
    pub fn apply(&self, ctx: &OpCtx) {
        op::commit_with(&self.doc, ctx);
    }

    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::Snapshot)
            .map_err(|e| anyhow!("export catalog snapshot: {e}"))
    }
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        self.doc
            .import(bytes)
            .map(|_| ())
            .map_err(|e| anyhow!("import catalog update: {e}"))
    }
    /// The catalog oplog frontiers used for catalog-first synchronization.
    pub(crate) fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }
    /// The catalog head digest used in gossip announcements.
    pub fn head_hash(&self) -> Vec<u8> {
        head_hash(&self.head())
    }
    /// Encoded catalog frontiers used in the combined synchronization head.
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head().encode()
    }

    /// The catalog's wire-encoded oplog version vector.
    pub fn oplog_vv_bytes(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }

    /// Export the catalog operations absent from a peer's encoded version vector.
    pub fn export_from_bytes(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
        self.doc
            .export(ExportMode::updates(&vv))
            .map_err(|e| anyhow!("export catalog updates: {e}"))
    }

    /// The deep state as JSON — for convergence assertions and debugging.
    pub fn state_json(&self) -> serde_json::Value {
        use loro::ToJson;
        self.doc.get_deep_value().to_json_value()
    }

    fn root(&self) -> LoroMap {
        self.doc.get_map(ROOT)
    }
    fn container_map(&self, key: &str) -> LoroMap {
        match self.root().get(key) {
            Some(ValueOrContainer::Container(Container::Map(m))) => m,
            _ => self.doc.get_map(key), // fallback (should not happen post-create)
        }
    }
    fn docs(&self) -> LoroMap {
        self.container_map(C_DOCS)
    }
    fn projects(&self) -> LoroMap {
        self.container_map(C_PROJECTS)
    }
    fn labels(&self) -> LoroMap {
        self.container_map(C_LABELS)
    }
    fn boards(&self) -> LoroMap {
        self.container_map(C_BOARDS)
    }
    fn aliases(&self) -> LoroMap {
        self.container_map(C_ALIASES)
    }
    fn workflow_list(&self) -> Option<LoroMovableList> {
        match self.root().get(C_WORKFLOW) {
            Some(ValueOrContainer::Container(Container::MovableList(l))) => Some(l),
            _ => None,
        }
    }

    /// The sub-issue tree. Lazily created on first write so catalogs founded
    /// before the container existed keep working across this additive change.
    fn subs_tree(&self, create: bool) -> Option<LoroTree> {
        match self.root().get(C_SUBS) {
            Some(ValueOrContainer::Container(Container::Tree(t))) => Some(t),
            _ if create => self.root().insert_container(C_SUBS, LoroTree::new()).ok(),
            _ => None,
        }
    }
    /// The issue-link edge set (same lazy-create rule as `subs`).
    fn edges_map(&self, create: bool) -> Option<LoroMap> {
        match self.root().get(C_EDGES) {
            Some(ValueOrContainer::Container(Container::Map(m))) => Some(m),
            _ if create => self.root().insert_container(C_EDGES, LoroMap::new()).ok(),
            _ => None,
        }
    }
    /// The content-authority op list (same lazy-create rule).
    fn authz_list(&self, create: bool) -> Option<LoroList> {
        match self.root().get(C_AUTHZ) {
            Some(ValueOrContainer::Container(Container::List(l))) => Some(l),
            _ if create => self.root().insert_container(C_AUTHZ, LoroList::new()).ok(),
            _ => None,
        }
    }

    // ---- content-authority operations (encrypted signed DAG) ----

    /// Append a signed content-authority op (idempotent by op hash — the same
    /// grow-only-set rule as the membership plane).
    pub fn add_authz_op(&self, op: &crate::sigdag::SignedNode) -> Result<()> {
        let hash = op.hash();
        if self.authz_ops().iter().any(|o| o.hash() == hash) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(op).map_err(|e| anyhow!("encode authz op: {e}"))?;
        let list = self
            .authz_list(true)
            .ok_or_else(|| anyhow!("authz container unavailable"))?;
        list.insert(list.len(), bytes.as_slice())?;
        Ok(())
    }

    /// All content-authority ops currently held.
    pub fn authz_ops(&self) -> Vec<crate::sigdag::SignedNode> {
        let Some(list) = self.authz_list(false) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(loro::LoroValue::Binary(b))) = list.get(i) {
                if let Ok(op) = postcard::from_bytes::<crate::sigdag::SignedNode>(&b) {
                    out.push(op);
                }
            }
        }
        out
    }

    /// The authz DAG's current heads — the parents for the next op.
    pub fn authz_heads(&self) -> Vec<String> {
        let ops = self.authz_ops();
        let mut is_parent = std::collections::HashSet::new();
        for o in &ops {
            for p in &o.parents {
                is_parent.insert(p.clone());
            }
        }
        ops.iter()
            .map(|o| o.hash())
            .filter(|h| !is_parent.contains(h))
            .collect()
    }

    pub fn space_id(&self) -> Option<SpaceId> {
        lx::get_str(&self.root(), lx::K_SPACE).and_then(|s| SpaceId::parse(&s))
    }
    /// The space's human display name — a synced LWW register, purely
    /// cosmetic: renaming never re-topics (the gossip topic derives from the
    /// space id) and never invalidates tickets. Empty until the founder's
    /// catalog arrives on a fresh joiner.
    pub fn space_name(&self) -> String {
        lx::get_str(&self.root(), K_NAME).unwrap_or_default()
    }
    pub fn set_space_name(&self, name: &str) -> Result<()> {
        self.root().insert(K_NAME, name)?;
        Ok(())
    }
    pub fn schema_version(&self) -> u32 {
        lx::get_u64(&self.root(), K_SCHEMA).unwrap_or(0) as u32
    }

    // ---- projects ----

    pub fn add_project(&self, id: &ProjectId, name: &str, key: &str, color: &str) -> Result<()> {
        let m = self
            .projects()
            .insert_container(id.as_str(), LoroMap::new())?;
        m.insert("id", id.as_str())?;
        m.insert("name", name)?;
        m.insert("key", key)?;
        m.insert("color", color)?;
        // ensure a board list + alias high-water exist for this project
        if lx::get_map(&self.boards(), id.as_str()).is_none()
            && !matches!(
                self.boards().get(id.as_str()),
                Some(ValueOrContainer::Container(Container::MovableList(_)))
            )
        {
            self.boards()
                .insert_container(id.as_str(), LoroMovableList::new())?;
        }
        if self.aliases().get(id.as_str()).is_none() {
            self.aliases().insert(id.as_str(), 0i64)?;
        }
        Ok(())
    }

    pub fn projects_list(&self) -> Vec<ProjectDto> {
        let projects = self.projects();
        let mut out = Vec::new();
        for k in lx::map_keys(&projects) {
            if let Some(m) = lx::get_map(&projects, &k) {
                if let Some(id) = ProjectId::parse(&k) {
                    out.push(ProjectDto {
                        id,
                        name: lx::get_str(&m, "name").unwrap_or_default(),
                        key: lx::get_str(&m, "key").unwrap_or_default(),
                        color: lx::get_str(&m, "color").unwrap_or_default(),
                    });
                }
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        out
    }

    pub fn project(&self, id: &ProjectId) -> Option<ProjectDto> {
        self.projects_list().into_iter().find(|p| &p.id == id)
    }
    pub fn project_by_key(&self, key: &str) -> Option<ProjectDto> {
        let key = key.to_ascii_uppercase();
        self.projects_list()
            .into_iter()
            .find(|p| p.key.to_ascii_uppercase() == key)
    }

    // ---- labels ----

    pub fn add_label(&self, id: &LabelId, name: &str, color: &str) -> Result<()> {
        let m = self
            .labels()
            .insert_container(id.as_str(), LoroMap::new())?;
        m.insert("id", id.as_str())?;
        m.insert("name", name)?;
        m.insert("color", color)?;
        Ok(())
    }
    pub fn labels_list(&self) -> Vec<LabelDto> {
        let labels = self.labels();
        let mut out = Vec::new();
        for k in lx::map_keys(&labels) {
            if let (Some(m), Some(id)) = (lx::get_map(&labels, &k), LabelId::parse(&k)) {
                out.push(LabelDto {
                    id,
                    name: lx::get_str(&m, "name").unwrap_or_default(),
                    color: lx::get_str(&m, "color").unwrap_or_default(),
                });
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        out
    }
    pub fn label(&self, id: &LabelId) -> Option<LabelDto> {
        self.labels_list().into_iter().find(|l| &l.id == id)
    }
    pub fn label_by_name(&self, name: &str) -> Option<LabelDto> {
        let n = name.to_ascii_lowercase();
        self.labels_list()
            .into_iter()
            .find(|l| l.name.to_ascii_lowercase() == n)
    }

    // ---- workflow ----

    pub fn workflow(&self) -> Vec<WorkflowState> {
        let Some(list) = self.workflow_list() else {
            return default_workflow();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Container(Container::Map(m))) = list.get(i) {
                out.push(read_workflow_state(&m));
            }
        }
        if out.is_empty() {
            default_workflow()
        } else {
            out
        }
    }
    pub fn workflow_state(&self, id: &str) -> Option<WorkflowState> {
        self.workflow().into_iter().find(|w| w.id == id)
    }

    // ---- docs / rows (the DocMeta cache) ----

    pub fn has_doc(&self, doc_id: &DocId) -> bool {
        self.docs().get(doc_id.as_str()).is_some()
    }
    pub fn doc_ids(&self) -> Vec<DocId> {
        lx::map_keys(&self.docs())
            .into_iter()
            .filter_map(|k| DocId::parse(&k))
            .collect()
    }

    fn row_map(&self, doc_id: &DocId) -> Option<LoroMap> {
        lx::get_map(&self.docs(), doc_id.as_str())
    }

    /// Read one `DocMeta` row.
    pub fn row(&self, doc_id: &DocId) -> Option<RowMeta> {
        let m = self.row_map(doc_id)?;
        let project_id = lx::get_str(&m, "projectId").and_then(|s| ProjectId::parse(&s))?;
        let assignees = lx::get_str(&m, "assignees")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .filter_map(ActorId::parse)
            .collect();
        Some(RowMeta {
            doc_id: doc_id.clone(),
            project_id,
            created_at: lx::get_u64(&m, "createdAt").unwrap_or(0),
            tombstone: lx::get_bool(&m, "tombstone").unwrap_or(false),
            seq: lx::get_u64(&m, "seq").map(|v| v as u32),
            title: lx::get_str(&m, "title").unwrap_or_default(),
            status: lx::get_str(&m, "status").unwrap_or_default(),
            priority: lx::get_str(&m, "priority")
                .and_then(|s| Priority::parse(&s))
                .unwrap_or_default(),
            assignees,
            head: lx::get_bytes(&m, "head").unwrap_or_default(),
            provisional: lx::get_bool(&m, "provisional").unwrap_or(false),
        })
    }

    /// All rows (unordered).
    pub fn all_rows(&self) -> Vec<RowMeta> {
        self.doc_ids()
            .into_iter()
            .filter_map(|id| self.row(&id))
            .collect()
    }

    /// Recompute a document's `DocMeta`
    /// row *from the issue doc* — the only writer of the cache fields. Called on
    /// every local edit and every import. Creates the row if absent (preserving
    /// `seq`/`tombstone`). `head` is `blake3(issue.frontiers.encode())`.
    pub fn upsert_row(&self, issue: &IssueDoc) -> Result<()> {
        let doc_id = issue
            .doc_id()
            .ok_or_else(|| anyhow!("issue doc missing its id"))?;
        let project_id = issue
            .project_id()
            .ok_or_else(|| anyhow!("issue doc missing projectId"))?;
        let existing = self.row_map(&doc_id);
        let m = match existing {
            Some(m) => m,
            None => {
                let m = self
                    .docs()
                    .insert_container(doc_id.as_str(), LoroMap::new())?;
                m.insert("kind", "issue")?;
                m.insert("createdAt", issue.created_at() as i64)?;
                m
            }
        };
        // Cache fields flow only from issue content into the catalog row.
        m.insert("projectId", project_id.as_str())?;
        m.insert("title", issue.title().as_str())?;
        m.insert("status", issue.status().as_str())?;
        m.insert("priority", issue.priority().as_str())?;
        let assignees = issue
            .assignees()
            .iter()
            .map(|u| u.as_str().to_string())
            .collect::<Vec<_>>()
            .join(",");
        m.insert("assignees", assignees.as_str())?;
        let head = issue.head_hash();
        m.insert("head", head.as_slice())?;
        Ok(())
    }

    /// Set or clear the deletion tombstone without removing the document.
    pub fn set_tombstone(&self, doc_id: &DocId, tombstone: bool) -> Result<()> {
        let m = self
            .row_map(doc_id)
            .ok_or_else(|| anyhow!("no such doc row: {doc_id}"))?;
        m.insert("tombstone", tombstone)?;
        Ok(())
    }

    /// Assign the KEY-n alias seq for a fresh doc: read the project high-water,
    /// increment, persist, and stamp the row. Two offline nodes can
    /// assign the same seq; collisions disambiguate at projection time.
    pub fn assign_alias_seq(&self, doc_id: &DocId, project_id: &ProjectId) -> Result<u32> {
        let current = lx::get_u64(&self.aliases(), project_id.as_str()).unwrap_or(0) as u32;
        let next = current + 1;
        self.aliases().insert(project_id.as_str(), next as i64)?;
        self.set_seq(doc_id, next)?;
        Ok(next)
    }

    /// Directly stamp a doc's KEY-n `seq` (used by sync reconciliation and
    /// tests to reproduce an offline double-assignment collision).
    pub fn set_seq(&self, doc_id: &DocId, seq: u32) -> Result<()> {
        if let Some(m) = self.row_map(doc_id) {
            m.insert("seq", seq as i64)?;
        }
        Ok(())
    }

    // ---- boards (movable list stores ordering only) ----

    fn board_list(&self, project_id: &ProjectId) -> Result<LoroMovableList> {
        match self.boards().get(project_id.as_str()) {
            Some(ValueOrContainer::Container(Container::MovableList(l))) => Ok(l),
            _ => Ok(self
                .boards()
                .insert_container(project_id.as_str(), LoroMovableList::new())?),
        }
    }

    /// The board's stored ordering (raw movable list). The render rule (dedup,
    /// append-belonging-unlisted, ignore-not-belonging) is applied at projection
    /// time, not here.
    pub fn board_order(&self, project_id: &ProjectId) -> Vec<DocId> {
        match self.boards().get(project_id.as_str()) {
            Some(ValueOrContainer::Container(Container::MovableList(l))) => lx::list_strings(&l)
                .into_iter()
                .filter_map(|s| DocId::parse(&s))
                .collect(),
            _ => Vec::new(),
        }
    }

    pub fn board_insert_top(&self, project_id: &ProjectId, doc_id: &DocId) -> Result<()> {
        let l = self.board_list(project_id)?;
        if lx::list_index_of(&l, doc_id.as_str()).is_none() {
            l.insert(0, doc_id.as_str())?;
        }
        Ok(())
    }
    pub fn board_insert_bottom(&self, project_id: &ProjectId, doc_id: &DocId) -> Result<()> {
        let l = self.board_list(project_id)?;
        if lx::list_index_of(&l, doc_id.as_str()).is_none() {
            l.insert(l.len(), doc_id.as_str())?;
        }
        Ok(())
    }
    pub fn board_remove(&self, project_id: &ProjectId, doc_id: &DocId) -> Result<()> {
        let l = self.board_list(project_id)?;
        if let Some(i) = lx::list_index_of(&l, doc_id.as_str()) {
            l.delete(i, 1)?;
        }
        Ok(())
    }

    /// Move `doc_id` to just before/after `anchor` in the board (a real
    /// `IssueMove` reorder). When the document is already listed this uses
    /// the movable list's native `mov` rather than delete-then-insert. Under
    /// concurrency, two peers moving the **same** doc converge
    /// to one position with **no duplicate** in the raw list, instead of each
    /// contributing a surviving insert. Inserts if not yet present.
    pub fn board_move(
        &self,
        project_id: &ProjectId,
        doc_id: &DocId,
        anchor: &DocId,
        after: bool,
    ) -> Result<()> {
        use std::cmp::Ordering;
        let l = self.board_list(project_id)?;
        let cur = lx::list_index_of(&l, doc_id.as_str());
        let anchor_idx = lx::list_index_of(&l, anchor.as_str());
        match (cur, anchor_idx) {
            // reorder an existing element relative to an existing anchor — the
            // native, conflict-free path.
            (Some(from), Some(a)) => {
                if from == a {
                    return Ok(()); // anchor is the doc itself: no-op
                }
                // desired FINAL index (loro `mov(from,to)` targets the final idx),
                // accounting for the doc's own removal shifting the anchor.
                let to = match (after, from.cmp(&a)) {
                    (false, Ordering::Greater) => a,
                    (false, Ordering::Less) => a - 1,
                    (true, Ordering::Greater) => a + 1,
                    (true, Ordering::Less) => a,
                    (_, Ordering::Equal) => return Ok(()),
                };
                let to = to.min(l.len().saturating_sub(1));
                l.mov(from, to)?;
            }
            // not yet listed: insert at the anchor-relative position.
            (None, Some(a)) => {
                let target = if after { a + 1 } else { a };
                l.insert(target.min(l.len()), doc_id.as_str())?;
            }
            // anchor gone (or list empty): append; move an existing one to the end.
            (Some(from), None) => {
                let last = l.len().saturating_sub(1);
                if from != last {
                    l.mov(from, last)?;
                }
            }
            (None, None) => {
                l.insert(l.len(), doc_id.as_str())?;
            }
        }
        Ok(())
    }

    // ---- subs (sub-issue hierarchy as a tree-move CRDT) ----

    /// Find the tree node standing for `doc_id`, skipping deleted nodes.
    fn node_for(&self, tree: &LoroTree, doc_id: &DocId) -> Option<TreeID> {
        tree.nodes().into_iter().find(|n| {
            !tree.is_node_deleted(n).unwrap_or(true)
                && tree
                    .get_meta(*n)
                    .ok()
                    .and_then(|m| lx::get_str(&m, META_DOC))
                    .as_deref()
                    == Some(doc_id.as_str())
        })
    }

    fn node_for_or_create(&self, tree: &LoroTree, doc_id: &DocId) -> Result<TreeID> {
        if let Some(n) = self.node_for(tree, doc_id) {
            return Ok(n);
        }
        let n = tree.create(TreeParentId::Root)?;
        tree.get_meta(n)?.insert(META_DOC, doc_id.as_str())?;
        Ok(n)
    }

    /// Parent `child` under `parent`, or unparent it (`None` → back to root).
    /// A *locally visible* cycle is rejected with a friendly error; a cycle
    /// formed only by concurrent moves is resolved by Loro's merge
    /// (the greater-timestamped move is ignored by the tree-move algorithm).
    pub fn set_parent(&self, child: &DocId, parent: Option<&DocId>) -> Result<()> {
        let tree = self
            .subs_tree(true)
            .ok_or_else(|| anyhow!("subs container unavailable"))?;
        let child_node = self.node_for_or_create(&tree, child)?;
        let target = match parent {
            Some(p) => TreeParentId::Node(self.node_for_or_create(&tree, p)?),
            None => TreeParentId::Root,
        };
        tree.mov(child_node, target).map_err(|e| match e {
            loro::LoroError::TreeError(loro::LoroTreeError::CyclicMoveError) => {
                anyhow!("that would make an issue its own ancestor")
            }
            other => anyhow!("move sub-issue: {other}"),
        })
    }

    /// The parent issue of `doc_id` in the sub-issue tree, if any.
    pub fn parent_of(&self, doc_id: &DocId) -> Option<DocId> {
        let tree = self.subs_tree(false)?;
        let node = self.node_for(&tree, doc_id)?;
        match tree.parent(node) {
            Some(TreeParentId::Node(p)) => tree
                .get_meta(p)
                .ok()
                .and_then(|m| lx::get_str(&m, META_DOC))
                .and_then(|s| DocId::parse(&s)),
            _ => None,
        }
    }

    /// The child issues of `doc_id` in the sub-issue tree.
    pub fn children_of(&self, doc_id: &DocId) -> Vec<DocId> {
        let Some(tree) = self.subs_tree(false) else {
            return Vec::new();
        };
        let Some(node) = self.node_for(&tree, doc_id) else {
            return Vec::new();
        };
        tree.children(TreeParentId::Node(node))
            .unwrap_or_default()
            .into_iter()
            .filter(|n| !tree.is_node_deleted(n).unwrap_or(true))
            .filter_map(|n| {
                tree.get_meta(n)
                    .ok()
                    .and_then(|m| lx::get_str(&m, META_DOC))
                    .and_then(|s| DocId::parse(&s))
            })
            .collect()
    }

    /// Every (child, parent) pair in the hierarchy — the adjacency projection's
    /// rebuild source (parent `None` = a root node with children).
    pub fn sub_pairs(&self) -> Vec<(DocId, Option<DocId>)> {
        let Some(tree) = self.subs_tree(false) else {
            return Vec::new();
        };
        let doc_of = |n: TreeID| {
            tree.get_meta(n)
                .ok()
                .and_then(|m| lx::get_str(&m, META_DOC))
                .and_then(|s| DocId::parse(&s))
        };
        tree.nodes()
            .into_iter()
            .filter(|n| !tree.is_node_deleted(n).unwrap_or(true))
            .filter_map(|n| {
                let child = doc_of(n)?;
                let parent = match tree.parent(n) {
                    Some(TreeParentId::Node(p)) => doc_of(p),
                    _ => None,
                };
                Some((child, parent))
            })
            .collect()
    }

    // ---- edges (issue links as an add-wins set) ----

    fn edge_key(from: &DocId, kind: &str, to: &DocId) -> String {
        format!("{from}|{kind}|{to}")
    }

    /// Add a link. Concurrent adds converge trivially (add-wins set).
    pub fn edge_add(&self, from: &DocId, kind: &str, to: &DocId) -> Result<()> {
        if kind.is_empty() || kind.contains('|') {
            anyhow::bail!("bad link kind '{kind}'");
        }
        self.edges_map(true)
            .ok_or_else(|| anyhow!("edges container unavailable"))?
            .insert(&Self::edge_key(from, kind, to), true)?;
        Ok(())
    }

    /// Remove a link (a real key delete — set membership has no undelete
    /// semantics to preserve, unlike doc tombstones).
    pub fn edge_remove(&self, from: &DocId, kind: &str, to: &DocId) -> Result<bool> {
        let Some(m) = self.edges_map(false) else {
            return Ok(false);
        };
        let key = Self::edge_key(from, kind, to);
        if m.get(&key).is_some() {
            m.delete(&key)?;
            return Ok(true);
        }
        Ok(false)
    }

    /// Every link in the space. Referential integrity (tombstoned/unknown
    /// endpoints) is the *caller's* read-time filter — the set itself is honest.
    pub fn edges(&self) -> Vec<Edge> {
        let Some(m) = self.edges_map(false) else {
            return Vec::new();
        };
        lx::present_keys(&m)
            .into_iter()
            .filter_map(|k| {
                let mut parts = k.split('|');
                let from = DocId::parse(parts.next()?)?;
                let kind = parts.next()?.to_string();
                let to = DocId::parse(parts.next()?)?;
                Some(Edge { from, kind, to })
            })
            .collect()
    }
}

/// Returns the opaque 32-byte `DocMeta.head` digest:
/// `blake3(frontiers.encode())`.
pub(crate) fn head_hash(frontiers: &Frontiers) -> Vec<u8> {
    blake3::hash(&frontiers.encode()).as_bytes().to_vec()
}

fn write_workflow_state(m: &LoroMap, s: &WorkflowState) -> Result<()> {
    m.insert("id", s.id.as_str())?;
    m.insert("name", s.name.as_str())?;
    m.insert("category", s.category.as_str())?;
    m.insert("color", s.color.as_str())?;
    Ok(())
}
fn read_workflow_state(m: &LoroMap) -> WorkflowState {
    WorkflowState {
        id: lx::get_str(m, "id").unwrap_or_default(),
        name: lx::get_str(m, "name").unwrap_or_default(),
        category: lx::get_str(m, "category")
            .and_then(|s| StatusCategory::parse(&s))
            .unwrap_or(StatusCategory::Backlog),
        color: lx::get_str(m, "color").unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SystemUlidSource;
    use crate::issue::{IssueDoc, NewIssue};

    fn ws() -> SpaceId {
        SpaceId::mint(&SystemUlidSource)
    }
    fn device() -> DeviceId {
        DeviceId::from_key_string("a".repeat(64))
    }
    fn actor() -> ActorId {
        ActorId::from_incept_hash(&"a".repeat(64))
    }
    fn ctx(kind: &str) -> OpCtx {
        OpCtx::structure(kind, &device())
    }

    fn cat() -> (CatalogDoc, SpaceId, ProjectId) {
        let w = ws();
        let c = CatalogDoc::create(&w, "test", None, &device()).unwrap();
        let p = ProjectId::mint(&SystemUlidSource);
        c.add_project(&p, "Engineering", "ENG", "blue").unwrap();
        c.apply(&ctx("project_new"));
        (c, w, p)
    }

    fn make_issue(w: &SpaceId, p: &ProjectId, title: &str) -> IssueDoc {
        IssueDoc::create(NewIssue {
            doc_id: DocId::mint(&SystemUlidSource),
            space_id: w.clone(),
            project_id: p.clone(),
            title: title.into(),
            priority: Priority::Medium,
            created_by: actor(),
            committed_by: device(),
            created_at: 42,
            body: None,
            peer: None,
        })
        .unwrap()
    }

    #[test]
    fn create_seeds_schema_and_workflow() {
        let (c, w, _p) = cat();
        assert_eq!(c.schema_version(), SCHEMA_VERSION);
        assert_eq!(c.space_id(), Some(w));
        let wf = c.workflow();
        assert_eq!(wf.len(), 4);
        assert!(wf.iter().any(|s| s.category == StatusCategory::Done));
    }

    #[test]
    fn projects_and_labels_registries() {
        let (c, _w, p) = cat();
        assert_eq!(
            c.project_by_key("eng").map(|x| x.id.clone()),
            Some(p.clone())
        );
        assert_eq!(c.projects_list().len(), 1);
        let l = LabelId::mint(&SystemUlidSource);
        c.add_label(&l, "bug", "red").unwrap();
        c.apply(&ctx("label_new"));
        assert_eq!(c.label_by_name("BUG").map(|x| x.id), Some(l));
    }

    #[test]
    fn upsert_row_caches_from_issue_doc() {
        // The writer-direction invariant: the row reflects the issue doc.
        let (c, w, p) = cat();
        let issue = make_issue(&w, &p, "fix login");
        c.upsert_row(&issue).unwrap();
        c.apply(&ctx("row"));
        let row = c.row(&issue.doc_id().unwrap()).unwrap();
        assert_eq!(row.title, "fix login");
        assert_eq!(row.status, "backlog");
        assert_eq!(row.priority, Priority::Medium);
        assert_eq!(row.project_id, p);
        assert_eq!(row.head, issue.head_hash());
        // edit the issue → recompute → row follows
        issue.set_title("fix login race").unwrap();
        issue.set_status("done").unwrap();
        issue.apply(&OpCtx::content("edited", &device()));
        c.upsert_row(&issue).unwrap();
        c.apply(&ctx("row"));
        let row = c.row(&issue.doc_id().unwrap()).unwrap();
        assert_eq!(row.title, "fix login race");
        assert_eq!(row.status, "done");
    }

    #[test]
    fn alias_seq_is_monotonic_per_project() {
        let (c, w, p) = cat();
        let i1 = make_issue(&w, &p, "one");
        c.upsert_row(&i1).unwrap();
        let s1 = c.assign_alias_seq(&i1.doc_id().unwrap(), &p).unwrap();
        let i2 = make_issue(&w, &p, "two");
        c.upsert_row(&i2).unwrap();
        let s2 = c.assign_alias_seq(&i2.doc_id().unwrap(), &p).unwrap();
        assert_eq!((s1, s2), (1, 2));
        assert_eq!(c.row(&i1.doc_id().unwrap()).unwrap().seq, Some(1));
    }

    #[test]
    fn board_ordering_insert_move_remove_no_dup() {
        let (c, w, p) = cat();
        let a = make_issue(&w, &p, "a");
        let b = make_issue(&w, &p, "b");
        let d = make_issue(&w, &p, "c");
        for i in [&a, &b, &d] {
            c.upsert_row(i).unwrap();
            c.board_insert_bottom(&p, &i.doc_id().unwrap()).unwrap();
        }
        c.apply(&ctx("seed"));
        let (ai, bi, ci) = (
            a.doc_id().unwrap(),
            b.doc_id().unwrap(),
            d.doc_id().unwrap(),
        );
        assert_eq!(c.board_order(&p), vec![ai.clone(), bi.clone(), ci.clone()]);
        // move c before a
        c.board_move(&p, &ci, &ai, false).unwrap();
        c.apply(&ctx("moved"));
        assert_eq!(c.board_order(&p), vec![ci.clone(), ai.clone(), bi.clone()]);
        // inserting an existing doc doesn't dup
        c.board_insert_bottom(&p, &ai).unwrap();
        c.apply(&ctx("moved"));
        assert_eq!(c.board_order(&p).len(), 3);
        // remove
        c.board_remove(&p, &ai).unwrap();
        c.apply(&ctx("moved"));
        assert_eq!(c.board_order(&p), vec![ci, bi]);
    }

    #[test]
    fn board_move_after_positions_correctly() {
        let (c, w, p) = cat();
        let ids: Vec<DocId> = ["a", "b", "d", "e"]
            .iter()
            .map(|t| {
                let i = make_issue(&w, &p, t);
                let id = i.doc_id().unwrap();
                c.upsert_row(&i).unwrap();
                c.board_insert_bottom(&p, &id).unwrap();
                id
            })
            .collect();
        c.apply(&ctx("seed"));
        // move a (idx 0) AFTER d (idx 2): expect [b, d, a, e]
        c.board_move(&p, &ids[0], &ids[2], true).unwrap();
        c.apply(&ctx("moved"));
        assert_eq!(
            c.board_order(&p),
            vec![
                ids[1].clone(),
                ids[2].clone(),
                ids[0].clone(),
                ids[3].clone()
            ]
        );
    }

    #[test]
    fn concurrent_same_doc_move_converges_without_duplicate() {
        // Native moves must converge without duplicating an item when replicas
        // concurrently move that same item to different positions.
        let (c, w, p) = cat();
        let ids: Vec<DocId> = ["a", "b", "d", "e"]
            .iter()
            .map(|t| {
                let i = make_issue(&w, &p, t);
                let id = i.doc_id().unwrap();
                c.upsert_row(&i).unwrap();
                c.board_insert_bottom(&p, &id).unwrap();
                id
            })
            .collect();
        c.apply(&ctx("seed"));
        // fork a replica from a snapshot
        let snap = c.snapshot().unwrap();
        let c2 = CatalogDoc::from_snapshot(&snap, None).unwrap();
        // both replicas move `a` concurrently to different anchors
        c.board_move(&p, &ids[0], &ids[3], true).unwrap(); // a after e
        c.apply(&ctx("moved"));
        c2.board_move(&p, &ids[0], &ids[1], true).unwrap(); // a after b
        c2.apply(&ctx("moved"));
        // sync both directions
        c.import(&c2.snapshot().unwrap()).unwrap();
        c2.import(&c.snapshot().unwrap()).unwrap();
        let o1 = c.board_order(&p);
        let o2 = c2.board_order(&p);
        assert_eq!(o1, o2, "raw board orders converge byte-identical");
        // `a` appears exactly once — no duplicate from concurrent moves.
        assert_eq!(
            o1.iter().filter(|d| **d == ids[0]).count(),
            1,
            "native mov must not duplicate a doc under concurrent same-doc moves: {o1:?}"
        );
        assert_eq!(o1.len(), 4);
    }

    #[test]
    fn sub_hierarchy_parent_children_roundtrip() {
        let (c, w, p) = cat();
        let epic = make_issue(&w, &p, "epic").doc_id().unwrap();
        let a = make_issue(&w, &p, "a").doc_id().unwrap();
        let b = make_issue(&w, &p, "b").doc_id().unwrap();
        c.set_parent(&a, Some(&epic)).unwrap();
        c.set_parent(&b, Some(&epic)).unwrap();
        c.apply(&ctx("parent"));
        assert_eq!(c.parent_of(&a), Some(epic.clone()));
        let mut kids = c.children_of(&epic);
        kids.sort();
        let mut expect = vec![a.clone(), b.clone()];
        expect.sort();
        assert_eq!(kids, expect);
        // unparent
        c.set_parent(&a, None).unwrap();
        c.apply(&ctx("parent"));
        assert_eq!(c.parent_of(&a), None);
        assert_eq!(c.children_of(&epic), vec![b]);
    }

    #[test]
    fn sub_hierarchy_rejects_local_cycle() {
        let (c, w, p) = cat();
        let a = make_issue(&w, &p, "a").doc_id().unwrap();
        let b = make_issue(&w, &p, "b").doc_id().unwrap();
        c.set_parent(&b, Some(&a)).unwrap();
        c.apply(&ctx("parent"));
        let err = c.set_parent(&a, Some(&b)).unwrap_err();
        assert!(
            err.to_string().contains("ancestor"),
            "cycle rejected with a friendly error: {err}"
        );
    }

    #[test]
    fn concurrent_cycle_converges_to_a_valid_tree() {
        // The tree-move convergence guarantee (Kleppmann et al., TPDS 2022):
        // A→B and B→A performed concurrently converge on every replica to a
        // tree, never a cycle — the exact scenario an LWW parentId cannot survive.
        let (c, w, p) = cat();
        let a = make_issue(&w, &p, "a").doc_id().unwrap();
        let b = make_issue(&w, &p, "b").doc_id().unwrap();
        // materialize both nodes before forking so replicas share tree ids
        c.set_parent(&a, None).unwrap();
        c.set_parent(&b, None).unwrap();
        c.apply(&ctx("seed"));
        let c2 = CatalogDoc::from_snapshot(&c.snapshot().unwrap(), None).unwrap();

        c.set_parent(&b, Some(&a)).unwrap(); // replica 1: B under A
        c.apply(&ctx("parent"));
        c2.set_parent(&a, Some(&b)).unwrap(); // replica 2: A under B (concurrent)
        c2.apply(&ctx("parent"));

        c.import(&c2.snapshot().unwrap()).unwrap();
        c2.import(&c.snapshot().unwrap()).unwrap();

        assert_eq!(c.parent_of(&a), c2.parent_of(&a), "converged");
        assert_eq!(c.parent_of(&b), c2.parent_of(&b), "converged");
        // no cycle: at most one of the two parent links survives
        let cycle = c.parent_of(&a) == Some(b.clone()) && c.parent_of(&b) == Some(a.clone());
        assert!(!cycle, "concurrent moves must never converge to a cycle");
    }

    #[test]
    fn edges_add_remove_and_concurrent_union() {
        let (c, w, p) = cat();
        let a = make_issue(&w, &p, "a").doc_id().unwrap();
        let b = make_issue(&w, &p, "b").doc_id().unwrap();
        let d = make_issue(&w, &p, "d").doc_id().unwrap();
        c.edge_add(&a, "blocks", &b).unwrap();
        c.apply(&ctx("link"));
        let c2 = CatalogDoc::from_snapshot(&c.snapshot().unwrap(), None).unwrap();
        // concurrent adds on both replicas
        c.edge_add(&a, "relates", &d).unwrap();
        c.apply(&ctx("link"));
        c2.edge_add(&b, "blocks", &d).unwrap();
        c2.apply(&ctx("link"));
        c.import(&c2.snapshot().unwrap()).unwrap();
        c2.import(&c.snapshot().unwrap()).unwrap();
        let mut e1: Vec<String> = c
            .edges()
            .iter()
            .map(|e| format!("{}|{}|{}", e.from, e.kind, e.to))
            .collect();
        let mut e2: Vec<String> = c2
            .edges()
            .iter()
            .map(|e| format!("{}|{}|{}", e.from, e.kind, e.to))
            .collect();
        e1.sort();
        e2.sort();
        assert_eq!(e1, e2, "edge sets converge");
        assert_eq!(e1.len(), 3, "all three concurrent adds survive");
        // remove
        assert!(c.edge_remove(&a, "blocks", &b).unwrap());
        c.apply(&ctx("unlink"));
        assert_eq!(c.edges().len(), 2);
        assert!(!c.edge_remove(&a, "blocks", &b).unwrap(), "idempotent");
    }

    #[test]
    fn snapshot_roundtrip_preserves_catalog() {
        let (c, w, p) = cat();
        let i = make_issue(&w, &p, "keep me");
        c.upsert_row(&i).unwrap();
        c.board_insert_top(&p, &i.doc_id().unwrap()).unwrap();
        let child = make_issue(&w, &p, "child").doc_id().unwrap();
        c.set_parent(&child, Some(&i.doc_id().unwrap())).unwrap();
        c.edge_add(&child, "blocks", &i.doc_id().unwrap()).unwrap();
        c.apply(&ctx("seed"));
        let snap = c.snapshot().unwrap();
        let loaded = CatalogDoc::from_snapshot(&snap, None).unwrap();
        assert_eq!(loaded.project_by_key("ENG").map(|x| x.id), Some(p.clone()));
        assert_eq!(loaded.row(&i.doc_id().unwrap()).unwrap().title, "keep me");
        assert_eq!(loaded.board_order(&p).len(), 1);
        assert_eq!(loaded.parent_of(&child), Some(i.doc_id().unwrap()));
        assert_eq!(loaded.edges().len(), 1);
    }
}
