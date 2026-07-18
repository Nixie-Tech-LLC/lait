//! Layer A — the Issue document (SCHEMA §5). One Loro document per issue,
//! addressed by [`DocId`]. This wrapper owns the container layout and exposes
//! typed reads/writes; **all merge semantics live in Loro** (S§1). A "register"
//! is a single key in the root `LoroMap` resolved by Lamport order (LWW).
//!
//! Fields (S§5):
//! - `id`, `workspaceId`, `projectId`, `createdBy`, `createdAt` — value leaves.
//! - `title`, `status`, `priority` — LWW value leaves.
//! - `description` — `LoroText` (RGA char-merge, co-editable; writes are a
//!   **splice**, never a full-buffer replace — see [`IssueDoc::set_description`]).
//! - `assignees`, `labels` — `LoroMap<Id, true>` present-key sets (S§5.2).
//! - `comments` — `LoroList<Comment>`, insertion-order union (S§5.3).
//!
//! `projectId` is the **single source of project membership** (S§5.5).
//!
//! Mutation contract (LAIT-DATA-CONTRACT §5-§6): callers stage typed writes and
//! land them with exactly one [`IssueDoc::apply`] per Request — the only commit
//! path, and it stamps the op metadata every change must carry.

use anyhow::{anyhow, Result};
use loro::{ExportMode, Frontiers, LoroDoc};

use crate::dto::{CommentDto, Priority, DEFAULT_STATUS};
use crate::ids::{ActorId, DocId, LabelId, ProjectId, UserId, WorkspaceId};

use crate::loro_ext as lx;
use crate::op::{self, OpCtx};

const ROOT: &str = "issue";
const K_ID: &str = "id";
const K_WORKSPACE: &str = "workspaceId";
const K_PROJECT: &str = "projectId";
const K_TITLE: &str = "title";
const K_STATUS: &str = "status";
const K_PRIORITY: &str = "priority";
const K_CREATED_BY: &str = "createdBy";
const K_CREATED_AT: &str = "createdAt";
const C_DESCRIPTION: &str = "description";
const C_ASSIGNEES: &str = "assignees";
const C_LABELS: &str = "labels";
const C_COMMENTS: &str = "comments";

/// Parameters for creating a fresh issue.
pub struct NewIssue {
    pub doc_id: DocId,
    pub workspace_id: WorkspaceId,
    pub project_id: ProjectId,
    pub title: String,
    pub priority: Priority,
    /// The authoring **actor** (identity), stable across the author's devices.
    pub created_by: ActorId,
    /// The device that committed (the advisory commit stamp — non-goal 6).
    pub committed_by: UserId,
    pub created_at: u64,
    pub body: Option<String>,
    /// The store's stable peer id (contract §5): one version-vector entry per
    /// store lifetime instead of one per session. `None` (tests, replicas)
    /// keeps the engine's fresh random peer.
    pub peer: Option<u64>,
}

/// A wrapper around one issue's `LoroDoc`.
pub struct IssueDoc {
    doc: LoroDoc,
}

impl IssueDoc {
    /// Create a brand-new issue document, committing the initial state as one
    /// `created` op.
    pub fn create(spec: NewIssue) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, spec.peer);
        let root = doc.get_map(ROOT);
        root.insert(K_ID, spec.doc_id.as_str())?;
        root.insert(K_WORKSPACE, spec.workspace_id.as_str())?;
        root.insert(K_PROJECT, spec.project_id.as_str())?;
        root.insert(K_TITLE, spec.title.as_str())?;
        root.insert(K_STATUS, DEFAULT_STATUS)?;
        root.insert(K_PRIORITY, spec.priority.as_str())?;
        root.insert(K_CREATED_BY, spec.created_by.as_str())?;
        root.insert(K_CREATED_AT, spec.created_at as i64)?;
        let committed_by = spec.committed_by.clone();
        // create the description text container (empty or seeded body)
        let desc = root.insert_container(C_DESCRIPTION, loro::LoroText::new())?;
        if let Some(body) = spec.body {
            if !body.is_empty() {
                desc.insert(0, &body)?;
            }
        }
        root.insert_container(C_ASSIGNEES, loro::LoroMap::new())?;
        root.insert_container(C_LABELS, loro::LoroMap::new())?;
        root.insert_container(C_COMMENTS, loro::LoroList::new())?;
        op::commit_with(&doc, &OpCtx::content("created", &committed_by));
        Ok(Self { doc })
    }

    /// Load from stored/synced snapshot bytes (the only public constructor from
    /// bytes — it applies the contract's engine configuration before any write
    /// can happen on the loaded doc).
    pub fn from_snapshot(bytes: &[u8], peer: Option<u64>) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        doc.import(bytes)
            .map_err(|e| anyhow!("import issue snapshot: {e}"))?;
        Ok(Self { doc })
    }

    /// The raw engine handle — never leaves the engine (contract §6).
    pub(crate) fn raw(&self) -> &LoroDoc {
        &self.doc
    }

    /// Export a full snapshot (durable store / cold-start sync). Retains the
    /// full oplog: the snapshot IS the history (contract §5).
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::Snapshot)
            .map_err(|e| anyhow!("export issue snapshot: {e}"))
    }

    /// Import bytes (a snapshot or an update) into this doc.
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        self.doc
            .import(bytes)
            .map(|_| ())
            .map_err(|e| anyhow!("import issue update: {e}"))
    }

    /// The issue doc's oplog frontiers — the causal head used as the sync digest
    /// (SCHEMA §3.2, §8). Engine-internal; the world sees [`Self::head_hash`].
    pub(crate) fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }

    /// The opaque `DocMeta.head` digest of this doc (S§3.2).
    pub fn head_hash(&self) -> Vec<u8> {
        crate::catalog::head_hash(&self.head())
    }

    /// This doc's oplog version vector, wire-encoded (per-doc VV-diff sync, A§8).
    pub fn oplog_vv_bytes(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }

    /// Export only the ops a peer lacks, from its wire-encoded VV (A§8).
    pub fn export_from_bytes(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
        self.doc
            .export(ExportMode::updates(&vv))
            .map_err(|e| anyhow!("export issue updates: {e}"))
    }

    /// The deep state as JSON — for convergence assertions and debugging.
    pub fn state_json(&self) -> serde_json::Value {
        use loro::ToJson;
        self.doc.get_deep_value().to_json_value()
    }

    fn root(&self) -> loro::LoroMap {
        self.doc.get_map(ROOT)
    }

    /// The `description` `LoroText`, nested under the root `issue` map.
    fn description_text(&self) -> Option<loro::LoroText> {
        match self.root().get(C_DESCRIPTION) {
            Some(loro::ValueOrContainer::Container(loro::Container::Text(t))) => Some(t),
            _ => None,
        }
    }

    /// The `comments` `LoroList`, nested under the root `issue` map.
    fn comments_list(&self) -> Option<loro::LoroList> {
        match self.root().get(C_COMMENTS) {
            Some(loro::ValueOrContainer::Container(loro::Container::List(l))) => Some(l),
            _ => None,
        }
    }

    // ---- reads ----

    pub fn doc_id(&self) -> Option<DocId> {
        lx::get_str(&self.root(), K_ID).and_then(|s| DocId::parse(&s))
    }
    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        lx::get_str(&self.root(), K_WORKSPACE).and_then(|s| WorkspaceId::parse(&s))
    }
    pub fn project_id(&self) -> Option<ProjectId> {
        lx::get_str(&self.root(), K_PROJECT).and_then(|s| ProjectId::parse(&s))
    }
    pub fn title(&self) -> String {
        lx::get_str(&self.root(), K_TITLE).unwrap_or_default()
    }
    pub fn status(&self) -> String {
        lx::get_str(&self.root(), K_STATUS).unwrap_or_else(|| DEFAULT_STATUS.to_string())
    }
    pub fn priority(&self) -> Priority {
        lx::get_str(&self.root(), K_PRIORITY)
            .and_then(|s| Priority::parse(&s))
            .unwrap_or_default()
    }
    pub fn created_by(&self) -> Option<ActorId> {
        lx::get_str(&self.root(), K_CREATED_BY).and_then(|s| ActorId::parse(&s))
    }
    pub fn created_at(&self) -> u64 {
        lx::get_u64(&self.root(), K_CREATED_AT).unwrap_or(0)
    }
    pub fn description(&self) -> String {
        self.description_text()
            .map(|t| t.to_string())
            .unwrap_or_default()
    }

    /// Assignee **actors** present in the set (S§5.2). Actor-keyed since the
    /// lait/actor/1 cutover, so an actor's assignment is stable across its
    /// devices.
    pub fn assignees(&self) -> Vec<ActorId> {
        let mut out: Vec<ActorId> = lx::get_map(&self.root(), C_ASSIGNEES)
            .map(|m| lx::present_keys(&m))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| ActorId::parse(&s))
            .collect();
        out.sort();
        out
    }

    /// Label ids present in the set (S§5.2).
    pub fn labels(&self) -> Vec<LabelId> {
        let mut out: Vec<LabelId> = lx::get_map(&self.root(), C_LABELS)
            .map(|m| lx::present_keys(&m))
            .unwrap_or_default()
            .into_iter()
            .filter_map(|s| LabelId::parse(&s))
            .collect();
        out.sort();
        out
    }

    /// Comments in insertion order (S§5.3).
    pub fn comments(&self) -> Vec<CommentDto> {
        let Some(list) = self.comments_list() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            let Some(v) = list.get(i) else { continue };
            let m = match v {
                loro::ValueOrContainer::Container(loro::Container::Map(m)) => m,
                _ => continue,
            };
            out.push(CommentDto {
                author: UserId::from_key_string(lx::get_str(&m, "author").unwrap_or_default()),
                author_nick: None,
                ts: lx::get_u64(&m, "ts").unwrap_or(0),
                body: lx::get_str(&m, "body").unwrap_or_default(),
            });
        }
        out
    }

    // ---- writes (staged; landed by exactly one `apply` per Request, S§7.1) ----

    pub fn set_title(&self, title: &str) -> Result<()> {
        self.root().insert(K_TITLE, title)?;
        Ok(())
    }
    pub fn set_status(&self, status: &str) -> Result<()> {
        self.root().insert(K_STATUS, status)?;
        Ok(())
    }
    pub fn set_priority(&self, priority: Priority) -> Result<()> {
        self.root().insert(K_PRIORITY, priority.as_str())?;
        Ok(())
    }
    pub fn set_project(&self, project: &ProjectId) -> Result<()> {
        self.root().insert(K_PROJECT, project.as_str())?;
        Ok(())
    }

    /// Set the description as a **splice**: the engine computes the minimal
    /// edit, so a concurrent edit by another peer RGA-merges cleanly instead of
    /// concatenating both full bodies (the P0 full-buffer replace did exactly
    /// that — contract §3.1), and the oplog records the actual edit instead of
    /// a delete-all/insert-all pair per save.
    pub fn set_description(&self, body: &str) -> Result<()> {
        let t = self
            .description_text()
            .ok_or_else(|| anyhow!("description container missing"))?;
        t.update(body, loro::UpdateOptions::default())
            .map_err(|e| anyhow!("splice description: {e}"))?;
        Ok(())
    }

    pub fn add_assignee(&self, actor: &ActorId) -> Result<()> {
        lx::get_map(&self.root(), C_ASSIGNEES)
            .ok_or_else(|| anyhow!("assignees container missing"))?
            .insert(actor.as_str(), true)?;
        Ok(())
    }
    pub fn remove_assignee(&self, actor: &ActorId) -> Result<()> {
        if let Some(m) = lx::get_map(&self.root(), C_ASSIGNEES) {
            if m.get(actor.as_str()).is_some() {
                m.delete(actor.as_str())?;
            }
        }
        Ok(())
    }
    pub fn add_label(&self, label: &LabelId) -> Result<()> {
        lx::get_map(&self.root(), C_LABELS)
            .ok_or_else(|| anyhow!("labels container missing"))?
            .insert(label.as_str(), true)?;
        Ok(())
    }
    pub fn remove_label(&self, label: &LabelId) -> Result<()> {
        if let Some(m) = lx::get_map(&self.root(), C_LABELS) {
            if m.get(label.as_str()).is_some() {
                m.delete(label.as_str())?;
            }
        }
        Ok(())
    }

    /// Append an immutable comment (S§5.3).
    pub fn add_comment(&self, author: &UserId, ts: u64, body: &str) -> Result<()> {
        let list = self
            .comments_list()
            .ok_or_else(|| anyhow!("comments container missing"))?;
        let map = list.insert_container(list.len(), loro::LoroMap::new())?;
        map.insert("author", author.as_str())?;
        map.insert("ts", ts as i64)?;
        map.insert("body", body)?;
        Ok(())
    }

    /// Land the staged ops as one metadata-carrying change — the only commit
    /// path (one Request = one apply = one change; S§7.1, contract §6).
    pub fn apply(&self, ctx: &OpCtx) {
        op::commit_with(&self.doc, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SystemUlidSource;

    fn ws() -> WorkspaceId {
        WorkspaceId::mint(&SystemUlidSource)
    }
    fn prj() -> ProjectId {
        ProjectId::mint(&SystemUlidSource)
    }
    fn doc() -> DocId {
        DocId::mint(&SystemUlidSource)
    }
    fn user() -> UserId {
        UserId::from_key_string("a".repeat(64))
    }
    fn actor(c: char) -> ActorId {
        ActorId::from_incept_hash(&c.to_string().repeat(64))
    }
    fn ctx(kind: &str) -> OpCtx {
        OpCtx::content(kind, &user())
    }

    fn sample() -> IssueDoc {
        IssueDoc::create(NewIssue {
            doc_id: doc(),
            workspace_id: ws(),
            project_id: prj(),
            title: "fix login".into(),
            priority: Priority::High,
            created_by: actor('a'),
            committed_by: user(),
            created_at: 1000,
            body: Some("the token refresh races".into()),
            peer: None,
        })
        .unwrap()
    }

    #[test]
    fn create_and_read_back() {
        let i = sample();
        assert_eq!(i.title(), "fix login");
        assert_eq!(i.status(), "backlog");
        assert_eq!(i.priority(), Priority::High);
        assert_eq!(i.description(), "the token refresh races");
        assert_eq!(i.created_at(), 1000);
        assert!(i.doc_id().is_some());
        assert!(i.assignees().is_empty());
    }

    #[test]
    fn edit_lww_fields() {
        let i = sample();
        i.set_title("fix login race").unwrap();
        i.set_status("in_progress").unwrap();
        i.set_priority(Priority::Urgent).unwrap();
        i.apply(&ctx("edited"));
        assert_eq!(i.title(), "fix login race");
        assert_eq!(i.status(), "in_progress");
        assert_eq!(i.priority(), Priority::Urgent);
    }

    #[test]
    fn assignees_are_a_present_key_set() {
        let i = sample();
        let u1 = actor('c');
        let u2 = actor('d');
        i.add_assignee(&u1).unwrap();
        i.add_assignee(&u2).unwrap();
        i.apply(&ctx("assigned"));
        assert_eq!(i.assignees().len(), 2);
        i.remove_assignee(&u1).unwrap();
        i.apply(&ctx("unassigned"));
        assert_eq!(i.assignees(), vec![u2]);
    }

    #[test]
    fn labels_add_remove() {
        let i = sample();
        let l = LabelId::mint(&SystemUlidSource);
        i.add_label(&l).unwrap();
        i.apply(&ctx("labeled"));
        assert_eq!(i.labels(), vec![l.clone()]);
        i.remove_label(&l).unwrap();
        i.apply(&ctx("labeled"));
        assert!(i.labels().is_empty());
    }

    #[test]
    fn comments_append_immutably() {
        let i = sample();
        i.add_comment(&user(), 10, "first").unwrap();
        i.add_comment(&user(), 20, "second").unwrap();
        i.apply(&ctx("commented"));
        let cs = i.comments();
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].body, "first");
        assert_eq!(cs[1].ts, 20);
    }

    #[test]
    fn description_splices_and_merges_concurrent_edits() {
        // The contract §3.1 fix: a splice write means two peers editing
        // different parts of the body RGA-merge cleanly, instead of the
        // full-buffer replace concatenating both bodies.
        let i = sample();
        i.set_description("the token refresh races").unwrap();
        i.apply(&ctx("edited"));
        let replica = IssueDoc::from_snapshot(&i.snapshot().unwrap(), None).unwrap();

        i.set_description("the token refresh races on cold start")
            .unwrap();
        i.apply(&ctx("edited"));
        replica.set_description("The token refresh races").unwrap();
        replica.apply(&ctx("edited"));

        i.import(&replica.export_from_bytes(&[]).unwrap()).unwrap();
        replica.import(&i.export_from_bytes(&[]).unwrap()).unwrap();
        assert_eq!(i.description(), replica.description(), "converged");
        assert_eq!(
            i.description(),
            "The token refresh races on cold start",
            "both edits survive — no body duplication"
        );
    }

    #[test]
    fn snapshot_roundtrip_preserves_state() {
        let i = sample();
        i.set_status("done").unwrap();
        i.apply(&ctx("edited"));
        let snap = i.snapshot().unwrap();
        let loaded = IssueDoc::from_snapshot(&snap, None).unwrap();
        assert_eq!(loaded.title(), "fix login");
        assert_eq!(loaded.status(), "done");
    }

    #[test]
    fn history_survives_snapshot_roundtrip_with_metadata() {
        // Contract §5: per-request changes with kind/actor/ts, durable on disk.
        let i = sample();
        i.set_status("in_progress").unwrap();
        i.apply(&ctx("started"));
        i.set_status("done").unwrap();
        i.apply(&ctx("finished"));
        let loaded = IssueDoc::from_snapshot(&i.snapshot().unwrap(), None).unwrap();
        let hist = crate::history::issue_history(&loaded);
        assert_eq!(hist.len(), 3, "created + started + finished");
        assert_eq!(hist[0].kind.as_deref(), Some("created"));
        assert_eq!(hist[1].kind.as_deref(), Some("started"));
        assert_eq!(hist[2].kind.as_deref(), Some("finished"));
        assert_eq!(hist[2].actor, Some(user()));
        assert!(hist[2].ts > 0, "real wall-clock on every change");
        let status_change = hist[2]
            .changes
            .iter()
            .find(|c| c.field == "status")
            .expect("status transition recorded");
        assert_eq!(status_change.from.as_deref(), Some("in_progress"));
        assert_eq!(status_change.to.as_deref(), Some("done"));
    }
}
