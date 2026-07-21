//! One Loro document per issue,
//! addressed by [`DocId`]. This wrapper owns the container layout and exposes
//! typed reads and writes. CRDT merge semantics live in Loro. A "register"
//! is a single key in the root `LoroMap` resolved by Lamport order (LWW).
//!
//! Stored fields:
//! - `id`, `spaceId`, `projectId`, `createdBy`, `createdAt` — value leaves.
//! - `title`, `status`, `priority` — LWW value leaves.
//! - `description` — `LoroText` (RGA char-merge, co-editable; writes are a
//!   **splice**, never a full-buffer replace — see [`IssueDoc::set_description`]).
//! - `assignees`, `labels` — `LoroMap<Id, true>` present-key sets.
//! - `comments` — `LoroList<Comment>`, insertion-order union.
//!
//! `projectId` is the source of project membership; board lists store order only.
//!
//! Callers stage typed writes and
//! land them with exactly one [`IssueDoc::apply`] per Request — the only commit
//! path, and it stamps the op metadata every change must carry.

use anyhow::{anyhow, Result};
use loro::{ExportMode, Frontiers, LoroDoc};

use crate::dto::{CommentDto, CorruptRecord, Priority, Projected, DEFAULT_STATUS};
use crate::ids::{ActorId, DeviceId, DocId, LabelId, ProjectId, SpaceId};

use crate::loro_ext as lx;
use crate::op::{self, OpCtx};

/// Project one stored comment map into a [`CommentDto`], or say why it isn't
/// one. The single definition of "is this comment well-formed", shared by the
/// document read ([`IssueDoc::comments`]) and the oplog diff walk
/// ([`crate::history`]) so the two can never disagree about the same record.
///
/// Only `author` is a corruption trigger. It is the field with no defensible
/// default: the schema types it [`ActorId`], and any substitute — a sentinel, a
/// laundered string — is a well-typed lie that mis-attributes authorship
/// downstream. `ts` and `body` keep their tolerant defaults (0 / empty) because
/// a comment with a missing timestamp or an empty body is still a comment a
/// person can read and act on; degrading it to a corruption report would hide
/// real content behind a diagnostic.
pub(crate) fn project_comment(m: &loro::LoroMap, locus: String) -> Projected<CommentDto> {
    let raw_author = lx::get_str(m, "author");
    let Some(author) = raw_author.as_deref().and_then(ActorId::parse) else {
        let reason = match &raw_author {
            Some(_) => "author: not an ActorId",
            None => "author: absent",
        };
        let mut record = CorruptRecord::new(locus, reason);
        if let Some(a) = raw_author {
            record = record.with_raw("author", a);
        }
        if let Some(b) = lx::get_str(m, "body") {
            record = record.with_raw("body", b);
        }
        return Projected::Corrupt(record);
    };
    Projected::Valid(CommentDto {
        author,
        author_nick: None,
        ts: lx::get_u64(m, "ts").unwrap_or(0),
        body: lx::get_str(m, "body").unwrap_or_default(),
    })
}

const ROOT: &str = "issue";
const K_ID: &str = "id";
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
    pub space_id: SpaceId,
    pub project_id: ProjectId,
    pub title: String,
    pub priority: Priority,
    /// The authoring **actor** (identity), stable across the author's devices.
    pub created_by: ActorId,
    /// The device that committed, recorded as an advisory stamp.
    pub committed_by: DeviceId,
    pub created_at: u64,
    pub body: Option<String>,
    /// The store's stable peer id: one version-vector entry per
    /// store lifetime instead of one per session. `None` (tests, replicas)
    /// keeps Loro's fresh random peer.
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
        root.insert(lx::K_SPACE, spec.space_id.as_str())?;
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
    /// bytes; it applies the fabric's required Loro configuration before any write
    /// can happen on the loaded doc).
    pub fn from_snapshot(bytes: &[u8], peer: Option<u64>) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        doc.import(bytes)
            .map_err(|e| anyhow!("import issue snapshot: {e}"))?;
        Ok(Self { doc })
    }

    /// The raw Loro handle, restricted to fabric internals.
    pub(crate) fn raw(&self) -> &LoroDoc {
        &self.doc
    }

    /// Export a full snapshot (durable store / cold-start sync). Retains the
    /// full oplog, which is the durable history source.
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

    /// The issue document's oplog frontiers: the causal head used as the sync
    /// digest. Fabric-internal; external callers use [`Self::head_hash`].
    pub(crate) fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }

    /// The opaque `DocMeta.head` digest of this document.
    pub fn head_hash(&self) -> Vec<u8> {
        crate::catalog::head_hash(&self.head())
    }

    /// This document's wire-encoded oplog version vector.
    pub fn oplog_vv_bytes(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }

    /// Export operations absent from a peer's encoded version vector.
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
    pub fn space_id(&self) -> Option<SpaceId> {
        lx::get_str(&self.root(), lx::K_SPACE).and_then(|s| SpaceId::parse(&s))
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

    /// Assignee actors present in the set. Actor-keying keeps assignment stable
    /// across device changes.
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

    /// Label ids present in the set.
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

    /// Comments in insertion order, each either projected or reported
    /// corrupt. Nothing is dropped: a malformed element keeps its position in
    /// the sequence, so the caller's counts stay right and a peer writing bad
    /// records stays visible instead of silently vanishing.
    pub fn comments(&self) -> Vec<Projected<CommentDto>> {
        let Some(list) = self.comments_list() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            let locus = format!("comments[{i}]");
            let Some(v) = list.get(i) else {
                out.push(Projected::Corrupt(CorruptRecord::new(
                    locus,
                    "list element is absent",
                )));
                continue;
            };
            match v {
                loro::ValueOrContainer::Container(loro::Container::Map(m)) => {
                    out.push(project_comment(&m, locus));
                }
                _ => out.push(Projected::Corrupt(CorruptRecord::new(
                    locus,
                    "list element is not a map",
                ))),
            }
        }
        out
    }

    // ---- staged writes, landed by one `apply` per accepted request ----

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

    /// Set the description as a **splice**: Loro computes the minimal
    /// edit, so a concurrent edit by another peer RGA-merges cleanly instead of
    /// concatenating both full bodies, and the oplog records the actual edit instead of
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

    /// Append an immutable comment. `author` is the actor, not the
    /// signing device: a comment is authored by a person, so attribution must
    /// survive that person adding, rotating, or recovering a device. The device
    /// that committed is still recorded — advisorily, on the change itself, via
    /// [`OpCtx`] — so "who wrote it" and "which device landed it" stay separate
    /// facts, exactly as [`NewIssue::created_by`] / [`NewIssue::committed_by`].
    pub fn add_comment(&self, author: &ActorId, ts: u64, body: &str) -> Result<()> {
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
    /// path: one accepted request becomes one apply and one change.
    pub fn apply(&self, ctx: &OpCtx) {
        op::commit_with(&self.doc, ctx);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::SystemUlidSource;

    fn ws() -> SpaceId {
        SpaceId::mint(&SystemUlidSource)
    }
    fn prj() -> ProjectId {
        ProjectId::mint(&SystemUlidSource)
    }
    fn doc() -> DocId {
        DocId::mint(&SystemUlidSource)
    }
    fn device() -> DeviceId {
        DeviceId::from_key_string("a".repeat(64))
    }
    fn actor(c: char) -> ActorId {
        ActorId::from_incept_hash(&c.to_string().repeat(64))
    }
    fn ctx(kind: &str) -> OpCtx {
        OpCtx::content(kind, &device())
    }

    fn sample() -> IssueDoc {
        IssueDoc::create(NewIssue {
            doc_id: doc(),
            space_id: ws(),
            project_id: prj(),
            title: "fix login".into(),
            priority: Priority::High,
            created_by: actor('a'),
            committed_by: device(),
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
        i.add_comment(&actor('a'), 10, "first").unwrap();
        i.add_comment(&actor('a'), 20, "second").unwrap();
        i.apply(&ctx("commented"));
        let (cs, corrupt) = crate::dto::partition(i.comments());
        assert!(corrupt.is_empty());
        assert_eq!(cs.len(), 2);
        assert_eq!(cs[0].body, "first");
        assert_eq!(cs[1].ts, 20);
        assert_eq!(cs[0].author, actor('a'));
    }

    /// The point of actor-authored comments: one person on two devices is one
    /// author. `add_comment` never sees a device key, so there is no way for
    /// the authoring device to leak into attribution — and a later revoke of
    /// that device cannot orphan the comment.
    #[test]
    fn comment_author_is_the_actor_not_the_device() {
        let i = sample();
        i.add_comment(&actor('b'), 10, "from laptop").unwrap();
        i.add_comment(&actor('b'), 20, "from phone").unwrap();
        i.apply(&ctx("commented"));
        let (cs, _) = crate::dto::partition(i.comments());
        let authors: Vec<_> = cs.iter().map(|c| c.author.clone()).collect();
        assert_eq!(
            authors,
            vec![actor('b'), actor('b')],
            "the same actor on two devices is one author"
        );
    }

    /// The corruption policy, end to end. A comment whose stored `author` is not
    /// an `ActorId` must not be dropped (the count would lie and the bad record
    /// would be invisible), must not be laundered into a well-typed fake, and
    /// must not degrade `CommentDto` into an optional-author shape. It is lifted
    /// out as a `CorruptRecord` that names where it sat and what was wrong.
    #[test]
    fn malformed_comment_author_is_reported_not_dropped_or_laundered() {
        let i = sample();
        i.add_comment(&actor('a'), 10, "well-formed").unwrap();
        // Write a comment the typed API cannot express: author is a device key,
        // not an actor id — exactly the pre-cutover shape a stale peer would send.
        let list = i.comments_list().unwrap();
        let m = list
            .insert_container(list.len(), loro::LoroMap::new())
            .unwrap();
        m.insert("author", "a".repeat(64).as_str()).unwrap();
        m.insert("ts", 20i64).unwrap();
        m.insert("body", "from a stale peer").unwrap();
        i.apply(&ctx("commented"));

        let projected = i.comments();
        assert_eq!(projected.len(), 2, "nothing is dropped");
        let (valid, corrupt) = crate::dto::partition(projected);

        assert_eq!(
            valid.len(),
            1,
            "only the well-formed comment is a CommentDto"
        );
        assert_eq!(valid[0].author, actor('a'));

        assert_eq!(corrupt.len(), 1);
        assert_eq!(corrupt[0].locus, "comments[1]", "position is preserved");
        assert!(
            corrupt[0].reason.contains("author"),
            "names the failing field: {}",
            corrupt[0].reason
        );
        assert_eq!(
            corrupt[0].raw.get("body").map(String::as_str),
            Some("from a stale peer"),
            "the record stays auditable"
        );
    }

    #[test]
    fn description_splices_and_merges_concurrent_edits() {
        // A splice write lets two peers editing
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
        // Per-request changes retain kind, committing device, and timestamp.
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
        assert_eq!(hist[2].actor, Some(device()));
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
