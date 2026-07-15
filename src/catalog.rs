//! Layer A — the Catalog document (SCHEMA §4). ONE Loro document per workspace:
//! the authoritative registry of which issue docs exist, project/label config,
//! board ordering, the workflow columns, the (P3) signed ACL log, and the
//! `DocMeta` row cache that lets lists/boards render without opening issue docs.
//!
//! **Authority (S§3).** `Catalog.docs` existence, `projects`, `labels`,
//! `workflow`, board *ordering*, and `acl` are authoritative. `DocMeta` row
//! fields are a **one-directional cache** of the issue doc (S§3.1): the issue
//! doc is always truth; every local edit and every import recomputes the row via
//! [`CatalogDoc::upsert_row`]. Nothing writes a row field as if it were
//! authoritative.
//!
//! **`head` (S§3.2).** `DocMeta.head` is a cache of the issue-doc frontiers —
//! `blake3(frontiers.encode())`. Because mirroring it is a second write to a
//! second doc, the store recomputes every head from the real issue frontiers on
//! load ([`CatalogDoc::upsert_row`] is the single writer of it).

use anyhow::{anyhow, Result};
use loro::{
    Container, ExportMode, Frontiers, LoroDoc, LoroList, LoroMap, LoroMovableList, ValueOrContainer,
};

use crate::dto::{
    default_workflow, LabelDto, Priority, ProjectDto, StatusCategory, WorkflowState, SCHEMA_VERSION,
};
use crate::ids::{DocId, LabelId, ProjectId, UserId, WorkspaceId};
use crate::issue::IssueDoc;
use crate::loro_ext as lx;

const ROOT: &str = "catalog";
const K_SCHEMA: &str = "schemaVersion";
const K_WORKSPACE: &str = "workspaceId";
const K_NAME: &str = "name";
const C_DOCS: &str = "docs";
const C_PROJECTS: &str = "projects";
const C_BOARDS: &str = "boards";
const C_LABELS: &str = "labels";
const C_WORKFLOW: &str = "workflow";
const C_ACL: &str = "acl";
const C_ALIASES: &str = "aliases";

/// Internal read of one `DocMeta` row (SCHEMA §4). The `Row` DTO is projected
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
    /// Full assignee keys (viewer-neutral cache; the "you +2" summary and the ●
    /// dot are computed at projection time from the local `UserId`). This is a
    /// faithful extension of the S§4 `assigneeSummary` cache: a shared cache
    /// cannot store a viewer-relative "you", so we cache the keys and render the
    /// summary per-viewer (recorded in the decision log).
    pub assignees: Vec<UserId>,
    pub head: Vec<u8>,
    /// True when the issue doc itself hasn't been loaded yet (post-P1); the row
    /// is provisional (UI.md §3.3). At P0 every doc is local, so always false.
    pub provisional: bool,
}

/// A wrapper around the workspace's Catalog `LoroDoc`.
pub struct CatalogDoc {
    doc: LoroDoc,
}

impl CatalogDoc {
    /// Create a fresh Catalog for a workspace, seeding schema + display name +
    /// default workflow.
    pub fn create(workspace_id: &WorkspaceId, name: &str) -> Result<Self> {
        let doc = LoroDoc::new();
        let root = doc.get_map(ROOT);
        root.insert(K_SCHEMA, SCHEMA_VERSION as i64)?;
        root.insert(K_WORKSPACE, workspace_id.as_str())?;
        root.insert(K_NAME, name)?;
        root.insert_container(C_DOCS, LoroMap::new())?;
        root.insert_container(C_PROJECTS, LoroMap::new())?;
        root.insert_container(C_BOARDS, LoroMap::new())?;
        root.insert_container(C_LABELS, LoroMap::new())?;
        root.insert_container(C_ALIASES, LoroMap::new())?;
        root.insert_container(C_ACL, LoroList::new())?;
        let wf = root.insert_container(C_WORKFLOW, LoroMovableList::new())?;
        for (i, state) in default_workflow().into_iter().enumerate() {
            let m = wf.insert_container(i, LoroMap::new())?;
            write_workflow_state(&m, &state)?;
        }
        doc.commit();
        Ok(Self { doc })
    }

    pub fn from_doc(doc: LoroDoc) -> Self {
        Self { doc }
    }
    /// A bare, uninitialized catalog — used by a JOINER (A§10). A joiner must NOT
    /// `create()` its own containers: `create` mints peer-specific attached
    /// child containers (`docs`/`projects`/…), and merging the founder's ops
    /// would then LWW-resolve the root's child registers non-deterministically to
    /// an empty local container. Starting empty and importing the founder's full
    /// ops adopts the founder's exact container ids, so everything merges.
    pub fn empty() -> Self {
        Self {
            doc: LoroDoc::new(),
        }
    }
    pub fn doc(&self) -> &LoroDoc {
        &self.doc
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
    /// The catalog's own oplog frontiers — the catalog-first sync digest (A§8).
    pub fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }

    /// The catalog's oplog version vector (for the catalog-first VV-diff, A§8).
    pub fn oplog_vv(&self) -> loro::VersionVector {
        self.doc.oplog_vv()
    }

    /// Export only the catalog ops a peer at `from` lacks (A§8 phase 1).
    pub fn export_from(&self, from: &loro::VersionVector) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::updates(from))
            .map_err(|e| anyhow!("export catalog updates: {e}"))
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

    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        lx::get_str(&self.root(), K_WORKSPACE).and_then(|s| WorkspaceId::parse(&s))
    }
    /// The workspace's human display name — a synced LWW register, purely
    /// cosmetic: renaming never re-topics (the gossip topic derives from the
    /// workspace id) and never invalidates tickets. Empty until the founder's
    /// catalog arrives on a fresh joiner.
    pub fn workspace_name(&self) -> String {
        lx::get_str(&self.root(), K_NAME).unwrap_or_default()
    }
    pub fn set_workspace_name(&self, name: &str) -> Result<()> {
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
            .map(|s| UserId::from_key_string(s.to_string()))
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

    /// **The writer-direction invariant (S§3.1).** Recompute a doc's `DocMeta`
    /// row *from the issue doc* — the only writer of the cache fields. Called on
    /// every local edit and every import. Creates the row if absent (preserving
    /// `seq`/`tombstone`). `head` is `blake3(issue.frontiers.encode())` (S§3.2).
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
        // cache fields (issue-doc is truth)
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
        let head = head_hash(&issue.head());
        m.insert("head", head.as_slice())?;
        Ok(())
    }

    /// Set (or clear) the deletion tombstone (S§5.6). The doc still exists.
    pub fn set_tombstone(&self, doc_id: &DocId, tombstone: bool) -> Result<()> {
        let m = self
            .row_map(doc_id)
            .ok_or_else(|| anyhow!("no such doc row: {doc_id}"))?;
        m.insert("tombstone", tombstone)?;
        Ok(())
    }

    /// Assign the KEY-n alias seq for a fresh doc: read the project high-water,
    /// increment, persist, and stamp the row (S§5.4). Two offline nodes can
    /// assign the same seq; collisions disambiguate at projection time.
    pub fn assign_alias_seq(&self, doc_id: &DocId, project_id: &ProjectId) -> Result<u32> {
        let current = lx::get_u64(&self.aliases(), project_id.as_str()).unwrap_or(0) as u32;
        let next = current + 1;
        self.aliases().insert(project_id.as_str(), next as i64)?;
        self.set_seq(doc_id, next)?;
        Ok(next)
    }

    /// Directly stamp a doc's KEY-n `seq` (used by sync reconciliation and
    /// tests to reproduce an offline double-assign collision, S§5.4).
    pub fn set_seq(&self, doc_id: &DocId, seq: u32) -> Result<()> {
        if let Some(m) = self.row_map(doc_id) {
            m.insert("seq", seq as i64)?;
        }
        Ok(())
    }

    // ---- boards (movable list = ordering only, S§5.5) ----

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
    /// time (S§5.5), not here.
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
    /// `IssueMove` reorder, UI.md §5.1). When the doc is already listed this uses
    /// the movable list's native `mov` (a single conflict-free move op — the A§9
    /// "native movable-list win") rather than delete-then-insert; that matters
    /// under concurrency: two peers concurrently moving the **same** doc converge
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
}

/// The opaque `DocMeta.head` digest: `blake3(frontiers.encode())` → 32 bytes
/// (SCHEMA §3.2, `head: value<bytes32>`).
pub fn head_hash(frontiers: &Frontiers) -> Vec<u8> {
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

    fn ws() -> WorkspaceId {
        WorkspaceId::mint(&SystemUlidSource)
    }

    fn cat() -> (CatalogDoc, WorkspaceId, ProjectId) {
        let w = ws();
        let c = CatalogDoc::create(&w, "test").unwrap();
        let p = ProjectId::mint(&SystemUlidSource);
        c.add_project(&p, "Engineering", "ENG", "blue").unwrap();
        c.doc().commit();
        (c, w, p)
    }

    fn make_issue(w: &WorkspaceId, p: &ProjectId, title: &str) -> IssueDoc {
        IssueDoc::create(NewIssue {
            doc_id: DocId::mint(&SystemUlidSource),
            workspace_id: w.clone(),
            project_id: p.clone(),
            title: title.into(),
            priority: Priority::Medium,
            created_by: UserId::from_key_string("a".repeat(64)),
            created_at: 42,
            body: None,
        })
        .unwrap()
    }

    #[test]
    fn create_seeds_schema_and_workflow() {
        let (c, w, _p) = cat();
        assert_eq!(c.schema_version(), SCHEMA_VERSION);
        assert_eq!(c.workspace_id(), Some(w));
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
        c.doc().commit();
        assert_eq!(c.label_by_name("BUG").map(|x| x.id), Some(l));
    }

    #[test]
    fn upsert_row_caches_from_issue_doc() {
        // The writer-direction invariant: the row reflects the issue doc.
        let (c, w, p) = cat();
        let issue = make_issue(&w, &p, "fix login");
        c.upsert_row(&issue).unwrap();
        c.doc().commit();
        let row = c.row(&issue.doc_id().unwrap()).unwrap();
        assert_eq!(row.title, "fix login");
        assert_eq!(row.status, "backlog");
        assert_eq!(row.priority, Priority::Medium);
        assert_eq!(row.project_id, p);
        assert_eq!(row.head, head_hash(&issue.head()));
        // edit the issue → recompute → row follows
        issue.set_title("fix login race").unwrap();
        issue.set_status("done").unwrap();
        issue.commit();
        c.upsert_row(&issue).unwrap();
        c.doc().commit();
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
        c.doc().commit();
        let (ai, bi, ci) = (
            a.doc_id().unwrap(),
            b.doc_id().unwrap(),
            d.doc_id().unwrap(),
        );
        assert_eq!(c.board_order(&p), vec![ai.clone(), bi.clone(), ci.clone()]);
        // move c before a
        c.board_move(&p, &ci, &ai, false).unwrap();
        c.doc().commit();
        assert_eq!(c.board_order(&p), vec![ci.clone(), ai.clone(), bi.clone()]);
        // inserting an existing doc doesn't dup
        c.board_insert_bottom(&p, &ai).unwrap();
        c.doc().commit();
        assert_eq!(c.board_order(&p).len(), 3);
        // remove
        c.board_remove(&p, &ai).unwrap();
        c.doc().commit();
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
        c.doc().commit();
        // move a (idx 0) AFTER d (idx 2): expect [b, d, a, e]
        c.board_move(&p, &ids[0], &ids[2], true).unwrap();
        c.doc().commit();
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
        // The finding from the adversarial convergence pass: a delete-then-insert
        // board_move duplicates a doc when two peers move the SAME doc; the native
        // `mov` converges to one position with no raw-list duplicate (A§9).
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
        c.doc().commit();
        // fork a replica from a snapshot
        let snap = c.snapshot().unwrap();
        let c2 = CatalogDoc::from_doc({
            let d = LoroDoc::new();
            d.import(&snap).unwrap();
            d
        });
        // both replicas move `a` concurrently to different anchors
        c.board_move(&p, &ids[0], &ids[3], true).unwrap(); // a after e
        c.doc().commit();
        c2.board_move(&p, &ids[0], &ids[1], true).unwrap(); // a after b
        c2.doc().commit();
        // sync both directions
        c.import(&c2.snapshot().unwrap()).unwrap();
        c2.import(&c.snapshot().unwrap()).unwrap();
        c.doc().commit();
        c2.doc().commit();
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
    fn snapshot_roundtrip_preserves_catalog() {
        let (c, w, p) = cat();
        let i = make_issue(&w, &p, "keep me");
        c.upsert_row(&i).unwrap();
        c.board_insert_top(&p, &i.doc_id().unwrap()).unwrap();
        c.doc().commit();
        let snap = c.snapshot().unwrap();
        let loaded = CatalogDoc::from_doc({
            let d = LoroDoc::new();
            d.import(&snap).unwrap();
            d
        });
        assert_eq!(loaded.project_by_key("ENG").map(|x| x.id), Some(p.clone()));
        assert_eq!(loaded.row(&i.doc_id().unwrap()).unwrap().title, "keep me");
        assert_eq!(loaded.board_order(&p).len(), 1);
    }
}
