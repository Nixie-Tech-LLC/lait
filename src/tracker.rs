//! The daemon's issue-tracking core — the bridge from Layer B (the control
//! façade, [`crate::control`]) to Layer A (the Loro docs, [`crate::catalog`] +
//! [`crate::issue`]) over the git-backed [`crate::store`]. Fully testable
//! in-process (no socket, no iroh, injected clock), which is where the SCHEMA and
//! control-plane invariants are exercised.
//!
//! **Validate-then-commit (UI.md §4.3, S§7.5).** Every mutating request fully
//! resolves refs and validates *before* any Loro commit; on failure it returns
//! `Response::Error` having touched nothing and produced **no** dirty-set (so no
//! doorbell rings), which is what makes an optimistic client's rollback
//! race-free. There is no CAS (S§7.2): the only failures are pre-commit.
//!
//! **Writer-direction (S§3.1).** Every mutation ends by recomputing the issue's
//! `DocMeta` row from the issue doc via [`CatalogDoc::upsert_row`] — the issue
//! doc is always truth; the row is a one-directional cache.

use std::collections::{BTreeMap, HashMap, VecDeque};

use anyhow::{anyhow, Result};

use crate::acl::{self, AclOp, AclState, Role, SignedOp};
use crate::catalog::{CatalogDoc, RowMeta};
use crate::control::{BoardPos, CatalogScope, Filter, Request, Response};
use crate::crypto::{self, WorkspaceKey};
use crate::dto::{
    ActivityEvent, BoardColumn, BoardView, CommentDto, FieldChange, IssueView, LabelDto, Priority,
    ProjectDto, Row, StatusCategory, SCHEMA_VERSION,
};
use crate::ids::{DocId, LabelId, ProjectId, UlidSource, UserId, WorkspaceId};
use crate::index::{self, AliasTable, RefResolution};
use crate::issue::{IssueDoc, NewIssue};
use crate::membership::MembershipDoc;
use crate::store::{Genesis, Store};

/// A 4-byte big-endian epoch tag prefixed to every AEAD ciphertext so the reader
/// selects the right key-epoch from its keyring (lazy revocation, A§11).
fn epoch_prefix(epoch: u32, mut blob: Vec<u8>) -> Vec<u8> {
    let mut out = epoch.to_be_bytes().to_vec();
    out.append(&mut blob);
    out
}
fn split_epoch(blob: &[u8]) -> Option<(u32, &[u8])> {
    if blob.len() < 4 {
        return None;
    }
    let (e, rest) = blob.split_at(4);
    Some((u32::from_be_bytes([e[0], e[1], e[2], e[3]]), rest))
}

/// The batched, project-keyed dirty-set a mutation produces (UI.md §4.2). The
/// node layer stamps it with an epoch + session `seq` to form a `Doorbell`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DirtySet {
    pub dirty_by_project: HashMap<String, Vec<String>>,
    pub dirty_catalog: Vec<CatalogScope>,
    pub activity_advanced: bool,
}

impl DirtySet {
    fn issue(project: &ProjectId, doc: &DocId) -> Self {
        let mut m = HashMap::new();
        m.insert(project.as_str().to_string(), vec![doc.as_str().to_string()]);
        DirtySet {
            dirty_by_project: m,
            dirty_catalog: Vec::new(),
            activity_advanced: true,
        }
    }
    fn with_scope(mut self, scope: CatalogScope) -> Self {
        self.dirty_catalog.push(scope);
        self
    }
    fn catalog(scope: CatalogScope) -> Self {
        DirtySet {
            dirty_by_project: HashMap::new(),
            dirty_catalog: vec![scope],
            activity_advanced: false,
        }
    }

    /// Coalesce another dirty-set into this one (daemon-side doorbell batching,
    /// UI.md §4.2): a whole sync-import transaction becomes one frame.
    pub fn merge(&mut self, other: DirtySet) {
        for (proj, docs) in other.dirty_by_project {
            let e = self.dirty_by_project.entry(proj).or_default();
            for d in docs {
                if !e.contains(&d) {
                    e.push(d);
                }
            }
        }
        for s in other.dirty_catalog {
            if !self.dirty_catalog.contains(&s) {
                self.dirty_catalog.push(s);
            }
        }
        self.activity_advanced |= other.activity_advanced;
    }

    /// A dirty-set marking the catalog registries (projects/labels/workflow)
    /// dirty — used when a sync imported a catalog diff whose structure moved.
    pub fn catalog_structure() -> Self {
        DirtySet {
            dirty_by_project: HashMap::new(),
            dirty_catalog: vec![
                CatalogScope::Projects,
                CatalogScope::Labels,
                CatalogScope::Workflow,
            ],
            activity_advanced: false,
        }
    }

    /// Whether this dirty-set carries anything worth ringing a doorbell for.
    pub fn is_empty(&self) -> bool {
        self.dirty_by_project.is_empty() && self.dirty_catalog.is_empty() && !self.activity_advanced
    }
}

const ACTIVITY_RING: usize = 1000;

/// One issue doc a puller must fetch during catalog-first sync (A§8): the
/// `doc_id` plus the puller's local version vector for it (empty ⇒ fetch all).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocNeed {
    pub doc_id: String,
    pub vv: Vec<u8>,
}

/// The issue-tracking core.
pub struct Tracker {
    store: Store,
    catalog: CatalogDoc,
    issues: HashMap<DocId, IssueDoc>,
    aliases: AliasTable,
    me: UserId,
    my_nick: String,
    workspace_id: WorkspaceId,
    activity: VecDeque<ActivityEvent>,
    activity_seq: u64,
    clock: Box<dyn UlidSource + Send + Sync>,
    // ---- P3 E2EE ----
    /// The plaintext membership layer (signed ACL + sealed key envelopes).
    membership: MembershipDoc,
    /// The genesis trust root (workspace id + founding admin keys, S§6).
    genesis: Genesis,
    /// Our ed25519 secret seed — signs ACL ops and unseals key envelopes.
    seed: [u8; 32],
    /// Every key-epoch we can unseal (a keyring; older epochs stay decryptable —
    /// lazy revocation). Empty ⇒ we are not a member and see only ciphertext.
    keyring: BTreeMap<u32, WorkspaceKey>,
}

impl Tracker {
    /// Open the tracker over a store, creating the workspace (genesis + catalog)
    /// on first run. Performs the **load-time head recompute** (S§3.2): heads and
    /// rows are recomputed from the real issue-doc frontiers, never trusted from
    /// disk, so a crash between an issue commit and its row mirror self-heals.
    pub fn open(
        store: Store,
        me: UserId,
        my_nick: String,
        seed: [u8; 32],
        clock: Box<dyn UlidSource + Send + Sync>,
    ) -> Result<Self> {
        let existing = store.load_catalog()?;
        let (catalog, workspace_id, membership, genesis, fresh) = match existing {
            Some(cat) => {
                let ws = cat
                    .workspace_id()
                    .ok_or_else(|| anyhow!("catalog missing workspaceId"))?;
                let membership = match store.load_membership()? {
                    Some(m) => m,
                    None => {
                        let m = MembershipDoc::create(&ws)?;
                        store.save_membership(&m)?;
                        m
                    }
                };
                let genesis = store.genesis()?.unwrap_or_else(|| Genesis {
                    workspace_id: ws.clone(),
                    founding_admins: vec![me.clone()],
                });
                (cat, ws, membership, genesis, false)
            }
            None => {
                // fresh workspace — we are the founding admin (S§6). Mint the
                // workspace key and seal it to ourselves at epoch 0.
                let ws = WorkspaceId::mint(&*clock);
                let cat = CatalogDoc::create(&ws)?;
                cat.doc().commit();
                let genesis = Genesis {
                    workspace_id: ws.clone(),
                    founding_admins: vec![me.clone()],
                };
                store.write_genesis(&genesis)?;
                store.save_catalog(&cat)?;
                let membership = MembershipDoc::create(&ws)?;
                let key = crypto::random_key();
                if let Some(sealed) = crypto::seal_to(&me, &key) {
                    membership.put_sealed(0, &me, &sealed)?;
                }
                membership.doc().commit();
                store.save_membership(&membership)?;
                store.commit("init workspace");
                (cat, ws, membership, genesis, true)
            }
        };

        let mut tracker = Tracker {
            store,
            catalog,
            issues: HashMap::new(),
            aliases: AliasTable::default(),
            me,
            my_nick,
            workspace_id,
            activity: VecDeque::new(),
            activity_seq: 0,
            clock,
            membership,
            genesis,
            seed,
            keyring: BTreeMap::new(),
        };
        tracker.refresh_keyring();
        if fresh {
            debug_assert!(tracker.current_key().is_some(), "founder must hold the key");
        }
        tracker.recompute_all_rows()?;
        tracker.rebuild_aliases();
        Ok(tracker)
    }

    /// Rebuild the keyring: unseal every epoch's envelope addressed to us (A§11
    /// lazy revocation — we keep older epoch keys so already-synced content stays
    /// readable). Called after any membership change/import.
    fn refresh_keyring(&mut self) {
        for epoch in 0..=self.membership.current_epoch() {
            if self.keyring.contains_key(&epoch) {
                continue;
            }
            if let Some(sealed) = self.membership.get_sealed(epoch, &self.me) {
                if let Some(raw) = crypto::open_sealed(&self.seed, &self.me, &sealed) {
                    if let Ok(key) = <WorkspaceKey>::try_from(raw.as_slice()) {
                        self.keyring.insert(epoch, key);
                    }
                }
            }
        }
    }

    fn current_epoch(&self) -> u32 {
        self.membership.current_epoch()
    }
    fn current_key(&self) -> Option<&WorkspaceKey> {
        self.keyring.get(&self.current_epoch())
    }

    /// Encrypt a sync payload with the current-epoch key (epoch-tagged). If we
    /// hold no key (shouldn't happen for a provider — it's a member), the payload
    /// passes through in the clear so a single-node P0 workspace still works.
    fn encrypt_payload(&self, plaintext: Vec<u8>) -> Vec<u8> {
        match self.current_key() {
            Some(key) => epoch_prefix(self.current_epoch(), crypto::aead_encrypt(key, &plaintext)),
            None => plaintext,
        }
    }
    /// Decrypt a sync payload using the epoch tag + our keyring. `None` if we
    /// lack that epoch's key — the blind-relay / non-member outcome: a non-member
    /// (empty keyring) or a removed member (missing the new epoch) learns nothing
    /// and simply imports nothing (A§11). Every provider is a member and thus
    /// always encrypts, so there is no plaintext-passthrough case.
    fn decrypt_payload(&self, blob: &[u8]) -> Option<Vec<u8>> {
        let (epoch, ct) = split_epoch(blob)?;
        let key = self.keyring.get(&epoch)?;
        crypto::aead_decrypt(key, ct)
    }

    /// Load-time invariant (S§3.2): recompute every head/row from the real issue
    /// docs. Lazily caches each issue doc.
    fn recompute_all_rows(&mut self) -> Result<()> {
        let mut changed = false;
        for doc_id in self.store.issue_doc_ids() {
            if let Some(issue) = self.store.load_issue(&doc_id)? {
                self.catalog.upsert_row(&issue)?;
                self.issues.insert(doc_id, issue);
                changed = true;
            }
        }
        if changed {
            self.catalog.doc().commit();
            self.store.save_catalog(&self.catalog)?;
        }
        Ok(())
    }

    fn rebuild_aliases(&mut self) {
        self.aliases = AliasTable::build(&self.catalog);
    }

    fn now_secs(&self) -> u64 {
        self.clock.now_ms() / 1000
    }

    // Test/inspection accessors.
    pub fn workspace_id(&self) -> &WorkspaceId {
        &self.workspace_id
    }
    pub fn issue_count(&self) -> usize {
        self.catalog
            .all_rows()
            .iter()
            .filter(|r| !r.tombstone)
            .count()
    }
    pub fn project_count(&self) -> usize {
        self.catalog.projects_list().len()
    }
    pub fn catalog(&self) -> &CatalogDoc {
        &self.catalog
    }

    /// Get a cached issue doc, loading it from the store on first access (lazy).
    fn issue(&mut self, doc_id: &DocId) -> Result<Option<&IssueDoc>> {
        if !self.issues.contains_key(doc_id) {
            if let Some(loaded) = self.store.load_issue(doc_id)? {
                self.issues.insert(doc_id.clone(), loaded);
            } else {
                return Ok(None);
            }
        }
        Ok(self.issues.get(doc_id))
    }

    // ---- dispatch ----

    /// Handle a tracker request. Returns the response plus an optional dirty-set
    /// (present only when a commit happened — never on error, so a doorbell never
    /// rings for a rejected write; UI.md §4.3).
    pub fn handle(&mut self, req: Request) -> (Response, Option<DirtySet>) {
        let r = match req {
            Request::IssueNew {
                title,
                project,
                assignees,
                priority,
                labels,
                body,
            } => self.issue_new(title, project, assignees, priority, labels, body),
            Request::IssueEdit {
                reff,
                title,
                status,
                priority,
            } => self.issue_edit(reff, title, status, priority),
            Request::IssueMove { reff, project, pos } => self.issue_move(reff, project, pos),
            Request::Assign { reff, who, add } => self.assign(reff, who, add),
            Request::Label { reff, add, remove } => self.label(reff, add, remove),
            Request::Comment { reff, body } => self.comment(reff, body),
            Request::IssueDelete { reff } => self.issue_delete(reff),
            Request::IssueView { reff } => self.issue_view(reff).map(|r| (r, None)),
            Request::List { project, filter } => self.list(project, filter).map(|r| (r, None)),
            Request::Board { project } => self.board(project).map(|r| (r, None)),
            Request::History { reff } => self.history(reff).map(|r| (r, None)),
            Request::ProjectNew { name, key } => self.project_new(name, key),
            Request::ProjectList => Ok((self.project_list(), None)),
            Request::LabelNew { name, color } => self.label_new(name, color),
            Request::LabelList => Ok((self.label_list(), None)),
            Request::Activity { since } => Ok((self.activity_response(since), None)),
            // `as_name` is a node-layer local-petname concern; the tracker only
            // seals the ACL op, so it ignores it here.
            Request::MemberAdd { who, admin, .. } => Ok(self.member_add_cmd(who, admin)),
            Request::MemberRemove { who } => Ok(self.member_remove_cmd(who)),
            Request::KeyRotate => Ok(self.key_rotate_cmd()),
            Request::Members => Ok((self.members_response(), None)),
            other => Err(anyhow!("not a tracker request: {other:?}")),
        };
        match r {
            Ok((resp, dirty)) => (resp, dirty),
            Err(e) => (Response::err(format!("{e:#}")), None),
        }
    }

    // ---- resolution helpers ----

    /// Resolve an issue ref → DocId, or a candidate/zero outcome as a `Response`.
    fn resolve_issue(&self, reff: &str) -> std::result::Result<DocId, Response> {
        match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => Ok(id),
            RefResolution::Zero => Err(Response::not_found(format!("no issue matches '{reff}'"))),
            RefResolution::Many(cands) => Err(Response::Candidates { candidates: cands }),
        }
    }

    fn resolve_project(&self, input: &str) -> Option<ProjectDto> {
        index::resolve_project(&self.catalog, input)
    }

    /// The default project for a new issue when none is given: the only project,
    /// else an error asking for one.
    fn default_project(&self) -> Result<ProjectDto> {
        let projects = self.catalog.projects_list();
        match projects.len() {
            1 => Ok(projects.into_iter().next().unwrap()),
            0 => Err(anyhow!(
                "no projects yet — create one first: `lait projects new <name> --key KEY`"
            )),
            _ => Err(anyhow!("more than one project — specify one with -p <KEY>")),
        }
    }

    // ---- mutations ----

    #[allow(clippy::too_many_arguments)]
    fn issue_new(
        &mut self,
        title: String,
        project: Option<String>,
        assignees: Vec<String>,
        priority: Option<String>,
        labels: Vec<String>,
        body: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        // ---- validate (no commits yet) ----
        if title.trim().is_empty() {
            return Ok((Response::err("title must not be empty"), None));
        }
        let project = match project {
            Some(p) => match self.resolve_project(&p) {
                Some(pr) => pr,
                None => {
                    return Ok((
                        Response::not_found(format!("no project matches '{p}'")),
                        None,
                    ))
                }
            },
            None => match self.default_project() {
                Ok(pr) => pr,
                Err(e) => return Ok((Response::err(format!("{e:#}")), None)),
            },
        };
        let priority = match priority {
            Some(p) => match Priority::parse(&p) {
                Some(pr) => pr,
                None => return Ok((Response::err(format!("bad priority '{p}'")), None)),
            },
            None => Priority::None,
        };
        // resolve assignees + labels up front (validate-then-commit)
        let mut assignee_ids = Vec::new();
        for a in &assignees {
            match index::resolve_user(a, &self.me) {
                Some(u) => assignee_ids.push(u),
                None => return Ok((Response::not_found(format!("no user matches '{a}'")), None)),
            }
        }
        let mut label_ids = Vec::new();
        for l in &labels {
            match self.resolve_label(l) {
                Some(id) => label_ids.push(id),
                None => return Ok((Response::not_found(format!("no label matches '{l}'")), None)),
            }
        }

        // ---- apply ----
        let doc_id = DocId::mint(&*self.clock);
        let issue = IssueDoc::create(NewIssue {
            doc_id: doc_id.clone(),
            workspace_id: self.workspace_id.clone(),
            project_id: project.id.clone(),
            title: title.clone(),
            priority,
            created_by: self.me.clone(),
            created_at: self.now_secs(),
            body,
        })?;
        for u in &assignee_ids {
            issue.add_assignee(u)?;
        }
        for l in &label_ids {
            issue.add_label(l)?;
        }
        issue.commit();

        self.catalog.upsert_row(&issue)?;
        self.catalog.assign_alias_seq(&doc_id, &project.id)?;
        self.catalog.board_insert_top(&project.id, &doc_id)?;
        self.catalog.doc().commit();

        self.store.save_issue(&issue)?;
        self.store.save_catalog(&self.catalog)?;
        self.issues.insert(doc_id.clone(), issue);
        self.rebuild_aliases();
        self.store.commit(&format!("new issue {doc_id}"));

        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "created", vec![], &title);
        let dirty = DirtySet::issue(&project.id, &doc_id).with_scope(CatalogScope::Boards {
            project: project.id.as_str().to_string(),
        });
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    fn issue_edit(
        &mut self,
        reff: String,
        title: Option<String>,
        status: Option<String>,
        priority: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        // validate status/priority before touching anything
        if let Some(s) = &status {
            if self.catalog.workflow_state(s).is_none() {
                return Ok((Response::err(format!("no such status '{s}'")), None));
            }
        }
        let new_priority = match &priority {
            Some(p) => match Priority::parse(p) {
                Some(pr) => Some(pr),
                None => return Ok((Response::err(format!("bad priority '{p}'")), None)),
            },
            None => None,
        };
        if title.is_none() && status.is_none() && priority.is_none() {
            return Ok((Response::err("nothing to edit"), None));
        }

        let project_id;
        let mut changes = Vec::new();
        let mut status_transition: Option<(String, String)> = None;
        {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            project_id = issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?;
            if let Some(t) = &title {
                let from = issue.title();
                issue.set_title(t)?;
                changes.push(FieldChange {
                    field: "title".into(),
                    from: Some(from),
                    to: Some(t.clone()),
                });
            }
            if let Some(s) = &status {
                let from = issue.status();
                issue.set_status(s)?;
                changes.push(FieldChange {
                    field: "status".into(),
                    from: Some(from.clone()),
                    to: Some(s.clone()),
                });
                status_transition = Some((from, s.clone()));
            }
            if let Some(p) = new_priority {
                let from = issue.priority();
                issue.set_priority(p)?;
                changes.push(FieldChange {
                    field: "priority".into(),
                    from: Some(from.as_str().to_string()),
                    to: Some(p.as_str().to_string()),
                });
            }
            issue.commit();
        }
        // completion policy (S§5.7): entering a done-category status removes the
        // doc from the board list; reopening re-inserts it at the top.
        if let Some((from, to)) = &status_transition {
            let from_done = self.is_done_status(from);
            let to_done = self.is_done_status(to);
            if to_done && !from_done {
                self.catalog.board_remove(&project_id, &doc_id)?;
            } else if from_done && !to_done {
                self.catalog.board_insert_top(&project_id, &doc_id)?;
            }
        }

        self.persist_issue_and_row(&doc_id)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "edited", changes, "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    fn issue_move(
        &mut self,
        reff: String,
        project: Option<String>,
        pos: Option<BoardPos>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        // validate target project + anchors up front
        let new_project = match &project {
            Some(p) => match self.resolve_project(p) {
                Some(pr) => Some(pr),
                None => {
                    return Ok((
                        Response::not_found(format!("no project matches '{p}'")),
                        None,
                    ))
                }
            },
            None => None,
        };
        let anchor = match &pos {
            Some(BoardPos::Before { reff }) | Some(BoardPos::After { reff }) => {
                match self.resolve_issue(reff) {
                    Ok(id) => Some(id),
                    Err(resp) => return Ok((resp, None)),
                }
            }
            _ => None,
        };

        let old_project = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?
        };

        // 1. project membership is truth (S§5.5): write Issue.projectId first.
        let effective_project = if let Some(np) = &new_project {
            if np.id != old_project {
                let issue = self.issues.get(&doc_id).unwrap();
                issue.set_project(&np.id)?;
                issue.commit();
                // fix both board lists (cache maintenance)
                self.catalog.board_remove(&old_project, &doc_id)?;
                self.catalog.board_insert_top(&np.id, &doc_id)?;
            }
            np.id.clone()
        } else {
            old_project.clone()
        };

        // 2. board ordering (cache) within the effective project.
        if let Some(pos) = &pos {
            match pos {
                BoardPos::Top => self.catalog.board_insert_top(&effective_project, &doc_id)?,
                BoardPos::Bottom => {
                    self.catalog.board_remove(&effective_project, &doc_id)?;
                    self.catalog
                        .board_insert_bottom(&effective_project, &doc_id)?;
                }
                BoardPos::Before { .. } => {
                    if let Some(a) = &anchor {
                        self.catalog
                            .board_move(&effective_project, &doc_id, a, false)?;
                    }
                }
                BoardPos::After { .. } => {
                    if let Some(a) = &anchor {
                        self.catalog
                            .board_move(&effective_project, &doc_id, a, true)?;
                    }
                }
            }
        }

        self.persist_issue_and_row(&doc_id)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "moved", vec![], "");
        let mut dirty =
            DirtySet::issue(&effective_project, &doc_id).with_scope(CatalogScope::Boards {
                project: effective_project.as_str().to_string(),
            });
        if effective_project != old_project {
            dirty = dirty.with_scope(CatalogScope::Boards {
                project: old_project.as_str().to_string(),
            });
        }
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    fn assign(
        &mut self,
        reff: String,
        who: Vec<String>,
        add: bool,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let mut users = Vec::new();
        for w in &who {
            match index::resolve_user(w, &self.me) {
                Some(u) => users.push(u),
                None => return Ok((Response::not_found(format!("no user matches '{w}'")), None)),
            }
        }
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            for u in &users {
                if add {
                    issue.add_assignee(u)?;
                } else {
                    issue.remove_assignee(u)?;
                }
            }
            issue.commit();
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(
            Some(&doc_id),
            &reff,
            if add { "assigned" } else { "unassigned" },
            vec![],
            "",
        );
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    fn label(
        &mut self,
        reff: String,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let mut add_ids = Vec::new();
        for l in &add {
            match self.resolve_label(l) {
                Some(id) => add_ids.push(id),
                None => return Ok((Response::not_found(format!("no label matches '{l}'")), None)),
            }
        }
        let mut remove_ids = Vec::new();
        for l in &remove {
            match self.resolve_label(l) {
                Some(id) => remove_ids.push(id),
                None => return Ok((Response::not_found(format!("no label matches '{l}'")), None)),
            }
        }
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            for l in &add_ids {
                issue.add_label(l)?;
            }
            for l in &remove_ids {
                issue.remove_label(l)?;
            }
            issue.commit();
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "labeled", vec![], "");
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    fn comment(&mut self, reff: String, body: String) -> Result<(Response, Option<DirtySet>)> {
        if body.trim().is_empty() {
            return Ok((Response::err("comment body must not be empty"), None));
        }
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let ts = self.now_secs();
        let me = self.me.clone();
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            issue.add_comment(&me, ts, &body)?;
            issue.commit();
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "commented", vec![], &body);
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    fn issue_delete(&mut self, reff: String) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let project_id = self
            .catalog
            .row(&doc_id)
            .map(|r| r.project_id)
            .ok_or_else(|| anyhow!("no such row"))?;
        // tombstone (S§5.6) + remove from board ordering
        self.catalog.set_tombstone(&doc_id, true)?;
        self.catalog.board_remove(&project_id, &doc_id)?;
        self.catalog.doc().commit();
        self.store.save_catalog(&self.catalog)?;
        self.store.commit(&format!("delete {doc_id}"));
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "deleted", vec![], "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        Ok((
            Response::Ok {
                message: Some(format!("deleted {reff}")),
            },
            Some(dirty),
        ))
    }

    fn project_new(&mut self, name: String, key: String) -> Result<(Response, Option<DirtySet>)> {
        let key = key.trim().to_ascii_uppercase();
        if name.trim().is_empty() || key.is_empty() {
            return Ok((Response::err("project name and key are required"), None));
        }
        if self.catalog.project_by_key(&key).is_some() {
            return Ok((
                Response::err(format!("project key '{key}' already exists")),
                None,
            ));
        }
        let id = ProjectId::mint(&*self.clock);
        self.catalog.add_project(&id, name.trim(), &key, "blue")?;
        self.catalog.doc().commit();
        self.store.save_catalog(&self.catalog)?;
        self.store.commit(&format!("new project {key}"));
        Ok((
            Response::Ref { reff: key },
            Some(DirtySet::catalog(CatalogScope::Projects)),
        ))
    }

    fn label_new(
        &mut self,
        name: String,
        color: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        if name.trim().is_empty() {
            return Ok((Response::err("label name is required"), None));
        }
        if self.catalog.label_by_name(name.trim()).is_some() {
            return Ok((
                Response::err(format!("label '{name}' already exists")),
                None,
            ));
        }
        let id = LabelId::mint(&*self.clock);
        self.catalog
            .add_label(&id, name.trim(), color.as_deref().unwrap_or("gray"))?;
        self.catalog.doc().commit();
        self.store.save_catalog(&self.catalog)?;
        self.store.commit(&format!("new label {}", name.trim()));
        Ok((
            Response::Ref {
                reff: name.trim().to_string(),
            },
            Some(DirtySet::catalog(CatalogScope::Labels)),
        ))
    }

    fn resolve_label(&self, input: &str) -> Option<LabelId> {
        let input = input.trim();
        if input.starts_with(LabelId::PREFIX) {
            if let Some(id) = LabelId::parse(input) {
                if self.catalog.label(&id).is_some() {
                    return Some(id);
                }
            }
        }
        self.catalog.label_by_name(input).map(|l| l.id)
    }

    /// Persist an issue doc + recompute its row + save the catalog (the common
    /// tail of every issue mutation).
    fn persist_issue_and_row(&mut self, doc_id: &DocId) -> Result<()> {
        let issue = self
            .issues
            .get(doc_id)
            .ok_or_else(|| anyhow!("issue not loaded"))?;
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.doc().commit();
        self.store.save_catalog(&self.catalog)?;
        self.rebuild_aliases();
        self.store.commit(&format!("edit {doc_id}"));
        Ok(())
    }

    // ---- projections (reads) ----

    fn is_done_status(&self, status: &str) -> bool {
        self.catalog
            .workflow_state(status)
            .map(|w| w.category == StatusCategory::Done)
            .unwrap_or(false)
    }

    /// Viewer-aware assignee summary (UI.md §5.1): "you", "you +2", "ab", "".
    fn assignee_summary(&self, assignees: &[UserId]) -> String {
        if assignees.is_empty() {
            return String::new();
        }
        let mine = assignees.contains(&self.me);
        let head = if mine {
            "you".to_string()
        } else {
            assignees[0].short()
        };
        if assignees.len() > 1 {
            format!("{head} +{}", assignees.len() - 1)
        } else {
            head
        }
    }

    fn project_row(&self, row: &RowMeta) -> Row {
        Row {
            reff: self.aliases.canonical_for(&row.doc_id),
            doc_id: row.doc_id.clone(),
            project_id: row.project_id.clone(),
            key_alias: self.aliases.alias_for(&row.doc_id),
            title: row.title.clone(),
            status: row.status.clone(),
            priority: row.priority,
            assignee_summary: self.assignee_summary(&row.assignees),
            tombstone: row.tombstone,
            provisional: row.provisional,
        }
    }

    fn list(&self, project: Option<String>, filter: Filter) -> Result<Response> {
        let project_filter = match &project {
            Some(p) => match self.resolve_project(p) {
                Some(pr) => Some(pr.id),
                None => return Ok(Response::not_found(format!("no project matches '{p}'"))),
            },
            None => None,
        };
        let label_filter = match &filter.label {
            Some(l) => match self.resolve_label(l) {
                Some(id) => Some(id),
                None => return Ok(Response::not_found(format!("no label matches '{l}'"))),
            },
            None => None,
        };
        let mut rows: Vec<Row> = self
            .catalog
            .all_rows()
            .into_iter()
            .filter(|r| {
                project_filter
                    .as_ref()
                    .map(|p| &r.project_id == p)
                    .unwrap_or(true)
            })
            .filter(|r| filter.all || !index::is_hidden_by_default(&self.catalog, r))
            .filter(|r| {
                filter
                    .status
                    .as_ref()
                    .map(|s| &r.status == s)
                    .unwrap_or(true)
            })
            .filter(|r| !filter.mine || r.assignees.contains(&self.me))
            .map(|r| self.project_row(&r))
            .collect();
        // label filter requires the issue doc's labels (not cached in the row);
        // apply it against loaded docs. (P0: all docs local.)
        if let Some(lid) = &label_filter {
            rows.retain(|row| {
                self.issues
                    .get(&row.doc_id)
                    .map(|i| i.labels().contains(lid))
                    .unwrap_or(false)
            });
        }
        // stable order: priority desc, then created (ULID) asc via doc_id.
        rows.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.doc_id.cmp(&b.doc_id)));
        Ok(Response::List { rows })
    }

    /// Build the board (UI.md §5.1) applying the S§5.5 render rule:
    /// rows whose `projectId == P`, in `boards[P]` order, deduplicated,
    /// belonging-but-unlisted appended, listed-but-not-belonging ignored; the
    /// Done column via the append rule ordered by wall-clock desc (S§5.7).
    fn board(&self, project: String) -> Result<Response> {
        let Some(project_dto) = self.resolve_project(&project) else {
            return Ok(Response::not_found(format!(
                "no project matches '{project}'"
            )));
        };
        let pid = &project_dto.id;
        let rows_by_doc: HashMap<String, RowMeta> = self
            .catalog
            .all_rows()
            .into_iter()
            .filter(|r| &r.project_id == pid && !r.tombstone)
            .map(|r| (r.doc_id.as_str().to_string(), r))
            .collect();
        let ordered = self.catalog.board_order(pid); // non-done, ordered
        let workflow = self.catalog.workflow();

        let mut columns = Vec::new();
        for state in &workflow {
            let mut rows: Vec<Row> = Vec::new();
            let mut seen = std::collections::HashSet::new();
            if state.category == StatusCategory::Done {
                // append rule (S§5.7): belonging rows in this done state, ordered
                // by wall-clock desc (they've left the board movable list).
                let mut done: Vec<&RowMeta> = rows_by_doc
                    .values()
                    .filter(|r| r.status == state.id)
                    .collect();
                done.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then(b.doc_id.cmp(&a.doc_id))
                });
                for r in done {
                    if seen.insert(r.doc_id.as_str().to_string()) {
                        rows.push(self.project_row(r));
                    }
                }
            } else {
                // board-ordered docs whose status maps to this column.
                for doc in &ordered {
                    if let Some(r) = rows_by_doc.get(doc.as_str()) {
                        if r.status == state.id && seen.insert(doc.as_str().to_string()) {
                            rows.push(self.project_row(r));
                        }
                    }
                }
                // belonging-but-unlisted (not in board order) appended.
                let mut unlisted: Vec<&RowMeta> = rows_by_doc
                    .values()
                    .filter(|r| r.status == state.id && !seen.contains(r.doc_id.as_str()))
                    .collect();
                unlisted.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
                for r in unlisted {
                    if seen.insert(r.doc_id.as_str().to_string()) {
                        rows.push(self.project_row(r));
                    }
                }
            }
            columns.push(BoardColumn {
                state: state.clone(),
                rows,
            });
        }
        Ok(Response::Board(Box::new(BoardView {
            schema_version: SCHEMA_VERSION,
            project: project_dto,
            columns,
        })))
    }

    fn issue_view(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        // Clone viewer context up front so it doesn't conflict with the issue
        // borrow below.
        let me = self.me.clone();
        let ws = self.workspace_id.clone();
        let canonical = self.aliases.canonical_for(&doc_id);
        let row = self.catalog.row(&doc_id);
        let project = row
            .as_ref()
            .and_then(|r| self.catalog.project(&r.project_id));
        let key_alias = self.aliases.alias_for(&doc_id);
        let label_names: HashMap<String, String> = self
            .catalog
            .labels_list()
            .into_iter()
            .map(|l| (l.id.as_str().to_string(), l.name))
            .collect();

        let issue = match self.issue(&doc_id)? {
            Some(i) => i,
            None => {
                // provisional: only the row is known (post-P1, UI.md §3.3).
                let row = row.ok_or_else(|| anyhow!("no such issue"))?;
                return Ok(Response::Issue(Box::new(IssueView {
                    schema_version: SCHEMA_VERSION,
                    reff: canonical.clone(),
                    doc_id,
                    workspace_id: ws.clone(),
                    project_id: row.project_id,
                    project_key: project.map(|p| p.key),
                    key_alias,
                    title: row.title,
                    description: String::new(),
                    status: row.status,
                    priority: row.priority,
                    assignees: row.assignees,
                    labels: vec![],
                    label_names: vec![],
                    comments: vec![],
                    created_by: me.clone(),
                    created_at: row.created_at,
                    provisional: true,
                })));
            }
        };
        let labels = issue.labels();
        let label_display = labels
            .iter()
            .map(|l| {
                label_names
                    .get(l.as_str())
                    .cloned()
                    .unwrap_or_else(|| l.short(4))
            })
            .collect();
        let comments: Vec<CommentDto> = issue.comments();
        let view = IssueView {
            schema_version: SCHEMA_VERSION,
            reff: canonical.clone(),
            doc_id: doc_id.clone(),
            workspace_id: issue.workspace_id().unwrap_or_else(|| ws.clone()),
            project_id: issue
                .project_id()
                .unwrap_or_else(|| row.as_ref().unwrap().project_id.clone()),
            project_key: project.map(|p| p.key),
            key_alias,
            title: issue.title(),
            description: issue.description(),
            status: issue.status(),
            priority: issue.priority(),
            assignees: issue.assignees(),
            labels,
            label_names: label_display,
            comments,
            created_by: issue.created_by().unwrap_or_else(|| me.clone()),
            created_at: issue.created_at(),
            provisional: false,
        };
        Ok(Response::Issue(Box::new(view)))
    }

    fn history(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        let events: Vec<ActivityEvent> = self
            .activity
            .iter()
            .filter(|e| e.doc_id.as_ref() == Some(&doc_id))
            .cloned()
            .collect();
        let last = events.last().map(|e| e.seq).unwrap_or(0);
        Ok(Response::Activity { events, last })
    }

    fn project_list(&self) -> Response {
        Response::Projects {
            projects: self.catalog.projects_list(),
        }
    }
    fn label_list(&self) -> Response {
        let labels: Vec<LabelDto> = self.catalog.labels_list();
        Response::Labels { labels }
    }

    // ---- activity feed ----

    fn push_activity(
        &mut self,
        doc_id: Option<&DocId>,
        reff: &str,
        kind: &str,
        changes: Vec<FieldChange>,
        text: &str,
    ) {
        self.activity_seq += 1;
        self.activity.push_back(ActivityEvent {
            seq: self.activity_seq,
            doc_id: doc_id.cloned(),
            reff: reff.to_string(),
            kind: kind.to_string(),
            changes,
            actor: Some(self.me.clone()),
            actor_nick: self.my_nick.clone(),
            text: text.to_string(),
            ts: self.now_secs(),
            collision: false,
        });
        while self.activity.len() > ACTIVITY_RING {
            self.activity.pop_front();
        }
    }

    fn activity_response(&self, since: u64) -> Response {
        let events: Vec<ActivityEvent> = self
            .activity
            .iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect();
        let last = self.activity.back().map(|e| e.seq).unwrap_or(since);
        Response::Activity { events, last }
    }

    /// The current activity high-water (for doorbell `activity_advanced` clients).
    pub fn activity_high_water(&self) -> u64 {
        self.activity_seq
    }

    // ---- P1 sync (A§8 catalog-first). The network layer (node/sync) calls these
    // under the tracker lock; all QUIC IO happens outside the lock. ----

    /// The workspace id as a string (sync handshake guard).
    pub fn workspace_str(&self) -> String {
        self.workspace_id.to_string()
    }

    /// The catalog's oplog version vector, wire-encoded (sync handshake).
    pub fn catalog_vv_bytes(&self) -> Vec<u8> {
        self.catalog.oplog_vv().encode()
    }

    /// The catalog head digest, wire form (gossip announce, A§8).
    pub fn catalog_head_bytes(&self) -> Vec<u8> {
        crate::catalog::head_hash(&self.catalog.head())
    }

    /// A combined sync head over catalog + membership (the gossip announce
    /// trigger). A membership-only change (e.g. `member add`, which doesn't touch
    /// the catalog) still moves this head so peers pull and receive it (A§8/§11).
    pub fn sync_head_bytes(&self) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(&self.catalog.head().encode());
        h.update(&self.membership.head().encode());
        h.finalize().as_bytes().to_vec()
    }

    /// Whether this node's workspace is still empty (no projects, no docs) — a
    /// freshly-minted workspace that may adopt a peer's on join.
    pub fn is_empty_workspace(&self) -> bool {
        self.catalog.projects_list().is_empty() && self.catalog.doc_ids().is_empty()
    }

    /// Adopt a workspace id from a join ticket (A§6/A§10): re-root an *empty*
    /// workspace onto the ticket's genesis so its catalog can then converge with
    /// the founder's over sync. Never clobbers a workspace that already holds
    /// real data. Returns whether an adoption happened.
    pub fn adopt_workspace(&mut self, ws: &str, founder: &str) -> Result<bool> {
        let Some(ws_id) = WorkspaceId::parse(ws) else {
            return Ok(false);
        };
        if ws_id == self.workspace_id || !self.is_empty_workspace() {
            return Ok(false);
        }
        // The genesis trust root comes from the ticket: the founder (ticket host)
        // is the founding admin whose signed ACL a joiner validates against (S§6).
        let founding_admins = UserId::parse(founder).map(|u| vec![u]).unwrap_or_default();
        let genesis = Genesis {
            workspace_id: ws_id.clone(),
            founding_admins,
        };
        // A joiner adopts EMPTY docs (not create()) so importing the founder's
        // full catalog/membership yields identical container ids (see
        // CatalogDoc::empty). Container init would otherwise conflict on merge.
        let catalog = CatalogDoc::empty();
        let membership = MembershipDoc::empty();
        self.store.write_genesis(&genesis)?;
        self.store.save_catalog(&catalog)?;
        self.store.save_membership(&membership)?;
        self.workspace_id = ws_id;
        self.catalog = catalog;
        self.membership = membership;
        self.genesis = genesis;
        self.keyring.clear(); // not a member yet — no key until the founder adds us
        self.rebuild_aliases();
        self.store.commit("adopt workspace from ticket");
        Ok(true)
    }

    // ---- membership sync (plaintext, A§11 two-protocol split) ----

    /// The membership doc's oplog VV, wire-encoded.
    pub fn membership_vv_bytes(&self) -> Vec<u8> {
        self.membership.oplog_vv().encode()
    }
    /// **Provider side.** Export the membership ops (plaintext) a puller lacks.
    pub fn export_membership_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
        self.membership.export_from(&vv)
    }
    /// **Puller side.** Import a membership update (plaintext), then refresh our
    /// keyring — we may have just been added and can now decrypt the workspace.
    pub fn import_membership(&mut self, update: &[u8]) -> Result<()> {
        self.membership.import(update)?;
        self.membership.doc().commit();
        self.store.save_membership(&self.membership)?;
        self.refresh_keyring();
        Ok(())
    }

    // ---- membership / ACL operations (P3, S§6, A§11) ----

    /// The materialized ACL state (deterministic replay from genesis, S§6).
    pub fn acl_state(&self) -> AclState {
        acl::replay(&self.genesis, &self.membership.ops())
    }
    pub fn is_member(&self, user: &UserId) -> bool {
        self.acl_state().is_member(user)
    }
    /// Members (key, role, is_me) for the members view (UI.md §8).
    pub fn members(&self) -> Vec<(UserId, Role, bool)> {
        self.acl_state()
            .members()
            .into_iter()
            .map(|(k, r)| {
                let me = k == self.me;
                (k, r, me)
            })
            .collect()
    }

    /// Add a member (signed AddMember op) and seal every key-epoch we hold to
    /// them so they can read the workspace (S§6, A§11). Admin-only.
    pub fn member_add(&mut self, user: &UserId, role: Role) -> (Response, Option<DirtySet>) {
        if !self.acl_state().is_admin(&self.me) {
            return (Response::err("only an admin can add members"), None);
        }
        let op = acl::sign_op(
            &self.seed,
            &AclOp::AddMember {
                key: user.clone(),
                role,
            },
            self.membership.heads(),
            &self.workspace_id,
        );
        if let Err(e) = self.member_apply(op, |t| {
            let epochs: Vec<(u32, WorkspaceKey)> =
                t.keyring.iter().map(|(e, k)| (*e, *k)).collect();
            for (epoch, key) in epochs {
                if let Some(sealed) = crypto::seal_to(user, &key) {
                    t.membership.put_sealed(epoch, user, &sealed)?;
                }
            }
            Ok(())
        }) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(None, &user.short(), "member_added", vec![], &user.short());
        (
            Response::Ok {
                message: Some(format!("added member {}", user.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// **Pattern A auto-approval.** Admit a joiner who presented a valid,
    /// admin-signed invite grant, sealing them the key exactly like [`member_add`]
    /// but with no human `approve` step. The transport layer has already verified
    /// the issuer signature, workspace binding, and expiry; here we enforce the
    /// remaining, state-dependent checks: the issuer must be a *current* admin, we
    /// must be an admin able to seal, and a single-use nonce must be unspent. The
    /// nonce is burned inside the same commit as the AddMember op (atomic — no
    /// window where a member is added but the invite stays live). Idempotent: a
    /// re-presented grant or an already-member joiner is a harmless no-op.
    ///
    /// [`member_add`]: Self::member_add
    pub fn redeem_invite(
        &mut self,
        issuer: &UserId,
        joiner: &UserId,
        nonce: &[u8; 16],
        single_use: bool,
    ) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        // Authority: only a grant signed by a current admin admits anyone.
        if !acl.is_admin(issuer) {
            return (
                Response::err("invite issuer is not a workspace admin"),
                None,
            );
        }
        // We can only seal the key if we ourselves are an admin holding it; if not,
        // stay silent and let the request sit for a human admin (graceful fallback).
        if !acl.is_admin(&self.me) {
            return (Response::err("this node is not an admin"), None);
        }
        // Single-use replay guard.
        if single_use && self.membership.is_redeemed(nonce) {
            return (Response::err("invite already redeemed"), None);
        }
        // Idempotent: already a member ⇒ nothing to seal, no ACL churn. (A repeat
        // of an *already-spent* single-use nonce was rejected by the guard above.)
        if acl.is_member(joiner) {
            return (
                Response::Ok {
                    message: Some(format!("{} is already a member", joiner.short())),
                },
                None,
            );
        }
        let op = acl::sign_op(
            &self.seed,
            &AclOp::AddMember {
                key: joiner.clone(),
                role: Role::Member,
            },
            self.membership.heads(),
            &self.workspace_id,
        );
        let nonce = *nonce;
        if let Err(e) = self.member_apply(op, |t| {
            let epochs: Vec<(u32, WorkspaceKey)> =
                t.keyring.iter().map(|(e, k)| (*e, *k)).collect();
            for (epoch, key) in epochs {
                if let Some(sealed) = crypto::seal_to(joiner, &key) {
                    t.membership.put_sealed(epoch, joiner, &sealed)?;
                }
            }
            if single_use {
                t.membership.mark_redeemed(&nonce, joiner)?;
            }
            Ok(())
        }) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(
            None,
            &joiner.short(),
            "member_added",
            vec![],
            &joiner.short(),
        );
        (
            Response::Ok {
                message: Some(format!("auto-approved {} via invite", joiner.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Remove a member (signed RemoveMember op) and **rotate the workspace key**
    /// (lazy revocation, A§3 non-goal 2): a new epoch sealed only to the remaining
    /// members, so the removed member cannot read *future* content. Admin-only.
    pub fn member_remove(&mut self, user: &UserId) -> (Response, Option<DirtySet>) {
        if !self.acl_state().is_admin(&self.me) {
            return (Response::err("only an admin can remove members"), None);
        }
        if user == &self.me {
            return (Response::err("refusing to remove yourself"), None);
        }
        let op = acl::sign_op(
            &self.seed,
            &AclOp::RemoveMember { key: user.clone() },
            self.membership.heads(),
            &self.workspace_id,
        );
        if let Err(e) = self.member_apply(op, |t| t.rotate_key()) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(None, &user.short(), "member_removed", vec![], &user.short());
        (
            Response::Ok {
                message: Some(format!(
                    "removed member {} and rotated the key",
                    user.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Rotate the workspace key without a membership change (key hygiene).
    pub fn key_rotate_cmd(&mut self) -> (Response, Option<DirtySet>) {
        if !self.acl_state().is_admin(&self.me) {
            return (Response::err("only an admin can rotate the key"), None);
        }
        match self.rotate_key() {
            Ok(()) => {
                if let Err(e) = self.persist_membership() {
                    return (Response::err(format!("{e:#}")), None);
                }
                (
                    Response::Ok {
                        message: Some(format!("rotated to key epoch {}", self.current_epoch())),
                    },
                    Some(DirtySet::catalog(CatalogScope::Acl)),
                )
            }
            Err(e) => (Response::err(format!("{e:#}")), None),
        }
    }

    fn member_add_cmd(&mut self, who: String, admin: bool) -> (Response, Option<DirtySet>) {
        let Some(user) = index::resolve_user(&who, &self.me) else {
            return (
                Response::not_found(format!("no user matches '{who}'")),
                None,
            );
        };
        let role = if admin { Role::Admin } else { Role::Member };
        self.member_add(&user, role)
    }
    fn member_remove_cmd(&mut self, who: String) -> (Response, Option<DirtySet>) {
        let Some(user) = index::resolve_user(&who, &self.me) else {
            return (
                Response::not_found(format!("no user matches '{who}'")),
                None,
            );
        };
        self.member_remove(&user)
    }
    fn members_response(&self) -> Response {
        let members = self
            .members()
            .into_iter()
            .map(|(key, role, me)| crate::dto::MemberDto {
                key,
                role: match role {
                    Role::Admin => "admin".into(),
                    Role::Member => "member".into(),
                },
                me,
                // Local petnames live outside the tracker (never synced); the node
                // layer overlays them onto this projection after the fact.
                alias: String::new(),
            })
            .collect();
        Response::Members { members }
    }

    /// Apply a signed op + an extra key-sealing step, then commit + persist.
    fn member_apply(
        &mut self,
        op: SignedOp,
        extra: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        self.membership.add_op(&op)?;
        extra(self)?;
        self.persist_membership()
    }

    fn persist_membership(&mut self) -> Result<()> {
        self.membership.doc().commit();
        self.store.save_membership(&self.membership)?;
        self.store.commit("membership change");
        self.refresh_keyring();
        Ok(())
    }

    /// Mint a new key-epoch, sealed to every *current* member (computed AFTER any
    /// just-applied remove op), and adopt it into our keyring.
    fn rotate_key(&mut self) -> Result<()> {
        let new_epoch = self.current_epoch() + 1;
        let new_key = crypto::random_key();
        self.membership.set_epoch(new_epoch)?;
        for (member, _role) in self.acl_state().members() {
            if let Some(sealed) = crypto::seal_to(&member, &new_key) {
                self.membership.put_sealed(new_epoch, &member, &sealed)?;
            }
        }
        self.keyring.insert(new_epoch, new_key);
        Ok(())
    }

    /// **Provider side.** Export the catalog ops a puller at `peer_vv` lacks,
    /// **encrypted** with the current workspace key (blind-relay envelope, A§11).
    pub fn export_catalog_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
        Ok(self.encrypt_payload(self.catalog.export_from(&vv)?))
    }

    /// **Provider side.** Export a single issue doc's updates from `peer_vv`
    /// (encrypted), or `None` if we don't hold that doc.
    pub fn export_doc_from(&mut self, doc_id: &str, peer_vv: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // Clone the epoch/key context before the issue borrow.
        let plain = match self.issue(&id)? {
            Some(issue) => {
                let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
                issue.export_from(&vv)?
            }
            None => return Ok(None),
        };
        Ok(Some(self.encrypt_payload(plain)))
    }

    /// **Puller side.** Import the provider's catalog update, recompute rows for
    /// docs we hold (writer-direction on import, S§3.1), and return the set of
    /// issue docs we must fetch: those we lack, or whose catalog `head` no longer
    /// matches our local issue-doc head (A§8 "the rows whose head moved").
    pub fn import_catalog_and_compute_needs(&mut self, update: &[u8]) -> Result<Vec<DocNeed>> {
        // Decrypt the blind-relay envelope (A§11). A non-member (no key) can't
        // read the catalog and simply learns nothing — the E2EE outcome.
        let Some(update) = self.decrypt_payload(update) else {
            return Ok(Vec::new());
        };
        self.catalog.import(&update)?;
        self.catalog.doc().commit();
        let mut needs = Vec::new();
        let mut healed = false;
        for doc_id in self.catalog.doc_ids() {
            // Ensure the issue doc is loaded (if we hold it) so we can compare
            // its *real* head against the just-imported catalog row.
            let held = self.issue(&doc_id)?.is_some();
            if held {
                // Writer-direction self-heal (S§3.1): the imported catalog's
                // `head`/row fields LWW-merged to a peer's value, but OUR issue
                // doc is the truth for our row — recompute it from the issue doc.
                let issue = self.issues.get(&doc_id).unwrap();
                let local_head = crate::catalog::head_hash(&issue.head());
                let cat_head = self
                    .catalog
                    .row(&doc_id)
                    .map(|r| r.head)
                    .unwrap_or_default();
                if local_head != cat_head {
                    // heads differ: either we're behind (fetch) — record the need
                    // with our VV — or we're ahead; recomputing the row is correct
                    // either way, and a redundant fetch of an up-to-date doc is a
                    // cheap empty diff.
                    needs.push(DocNeed {
                        doc_id: doc_id.as_str().to_string(),
                        vv: issue.oplog_vv().encode(),
                    });
                }
                self.catalog.upsert_row(issue)?;
                healed = true;
            } else {
                needs.push(DocNeed {
                    doc_id: doc_id.as_str().to_string(),
                    vv: Vec::new(), // we lack it → request a full snapshot/update
                });
            }
        }
        if healed {
            self.catalog.doc().commit();
        }
        self.rebuild_aliases();
        self.store.save_catalog(&self.catalog)?;
        Ok(needs)
    }

    /// **Puller side.** Import a fetched issue-doc update (creating the doc if
    /// new), persist it, and recompute its catalog row from the issue doc
    /// (writer-direction, S§3.1). Returns a dirty-set for a coalesced doorbell.
    pub fn import_doc(&mut self, doc_id: &str, bytes: &[u8]) -> Result<Option<DirtySet>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // Decrypt the blind-relay envelope (A§11); a non-member can't read it.
        let Some(bytes) = self.decrypt_payload(bytes) else {
            return Ok(None);
        };
        // ensure a doc exists to import into (new docs arrive as a snapshot).
        if !self.issues.contains_key(&id) {
            let doc = loro::LoroDoc::new();
            doc.import(&bytes)
                .map_err(|e| anyhow!("import new issue doc: {e}"))?;
            self.issues.insert(id.clone(), IssueDoc::from_doc(doc));
        } else {
            self.issues
                .get(&id)
                .unwrap()
                .import(&bytes)
                .map_err(|e| anyhow!("import issue update: {e}"))?;
        }
        // persist + recompute the row from the issue doc (disjoint field borrows).
        let issue = self.issues.get(&id).unwrap();
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.doc().commit();
        let project_id = issue.project_id();
        self.store.save_catalog(&self.catalog)?;
        self.rebuild_aliases();
        // a synced doc advances the activity feed (pulled, not streamed, S§7.5).
        let reff = self.aliases.canonical_for(&id);
        self.push_activity(Some(&id), &reff, "synced", vec![], "");
        match project_id {
            Some(p) => Ok(Some(DirtySet::issue(&p, &id))),
            None => Ok(None),
        }
    }

    // ---- test/inspection helpers (used by integration invariant tests) ----

    /// Read a `DocMeta` row's cached head (the sync digest) for a ref, if any.
    #[doc(hidden)]
    pub fn row_head_for(&self, reff: &str) -> Option<Vec<u8>> {
        match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => self.catalog.row(&id).map(|r| r.head),
            _ => None,
        }
    }

    /// The live head of a loaded issue doc for a ref (for the load-time
    /// recompute invariant test).
    #[doc(hidden)]
    pub fn issue_head_for(&mut self, reff: &str) -> Option<Vec<u8>> {
        let id = match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => id,
            _ => return None,
        };
        self.issue(&id)
            .ok()
            .flatten()
            .map(|i| crate::catalog::head_hash(&i.head()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::CatalogScope;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Deterministic, Send+Sync clock/entropy: fixed ms, monotonic entropy so
    /// minted ids are distinct (and canonical handles unique) without wall-clock
    /// or RNG flakiness.
    struct FakeClock {
        ms: u64,
        ctr: AtomicU64,
    }
    impl FakeClock {
        fn new(ms: u64) -> Self {
            Self {
                ms,
                ctr: AtomicU64::new(1),
            }
        }
    }
    impl UlidSource for FakeClock {
        fn now_ms(&self) -> u64 {
            self.ms
        }
        fn rand80(&self) -> u128 {
            self.ctr.fetch_add(1, Ordering::SeqCst) as u128
        }
    }

    const ME_SEED: [u8; 32] = [7u8; 32];
    fn me() -> UserId {
        // A real ed25519 key (so the founder can seal the workspace key to itself).
        let pk = ed25519_dalek::SigningKey::from_bytes(&ME_SEED).verifying_key();
        UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
    }

    struct TestNode {
        tracker: Tracker,
        home: std::path::PathBuf,
    }
    impl Drop for TestNode {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.home);
        }
    }

    fn new_node() -> TestNode {
        new_node_as(me(), ME_SEED)
    }

    fn user_from_seed(seed: [u8; 32]) -> UserId {
        let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
        UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
    }

    fn new_node_as(user: UserId, seed: [u8; 32]) -> TestNode {
        let home = std::env::temp_dir().join(format!(
            "gc-trk-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&home).unwrap();
        // Distinct clock per node (seed-derived ms) so two nodes mint DIFFERENT
        // workspace ids — otherwise the deterministic clock collides them and
        // adoption (which requires a differing ws id) would no-op.
        let clock = FakeClock::new(1_000_000 + seed[0] as u64 * 100_000);
        let tracker = Tracker::open(store, user, "tester".into(), seed, Box::new(clock)).unwrap();
        TestNode { tracker, home }
    }

    /// Create a project + return its key.
    fn with_project(t: &mut Tracker) -> String {
        let (resp, _) = t.handle(Request::ProjectNew {
            name: "Engineering".into(),
            key: "ENG".into(),
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        "ENG".to_string()
    }

    fn new_issue(t: &mut Tracker, title: &str) -> String {
        let (resp, dirty) = t.handle(Request::IssueNew {
            title: title.into(),
            project: Some("ENG".into()),
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        });
        assert!(dirty.is_some(), "a create must ring a doorbell");
        match resp {
            Response::Ref { reff } => reff,
            other => panic!("expected Ref, got {other:?}"),
        }
    }

    /// Perf harness (run: `GC_PERF_N=5000 cargo test --release -p lait --lib
    /// perf_seed_and_cold_load -- --ignored --nocapture`). Proves/refutes the
    /// scaling claims: cold-load is O(issues) (loads every doc), board/list reads
    /// are O(catalog) (must stay flat as issue count grows).
    #[test]
    #[ignore]
    fn perf_seed_and_cold_load() {
        use std::time::Instant;
        let n: usize = std::env::var("GC_PERF_N")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5000);
        let home = std::env::temp_dir().join(format!(
            "gc-perf-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&home).unwrap();

        // --- seed N issues through the real Request path ---
        let t0 = Instant::now();
        {
            let store = Store::open(&home).unwrap();
            let clock = FakeClock::new(1_000_000);
            let mut t =
                Tracker::open(store, me(), "perf".into(), ME_SEED, Box::new(clock)).unwrap();
            with_project(&mut t);
            for i in 0..n {
                let (resp, dirty) = t.handle(Request::IssueNew {
                    title: format!("issue {i}"),
                    project: Some("ENG".into()),
                    assignees: vec![],
                    priority: None,
                    labels: vec![],
                    body: None,
                });
                assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
                assert!(dirty.is_some());
            }
        }
        let seed = t0.elapsed();
        let store_bytes = fs_dir_size(&home);

        // --- cold-load: reopen the store (recompute_all_rows loads every doc) ---
        let t1 = Instant::now();
        let store = Store::open(&home).unwrap();
        let clock = FakeClock::new(1_000_000);
        let mut t = Tracker::open(store, me(), "perf".into(), ME_SEED, Box::new(clock)).unwrap();
        let cold_load = t1.elapsed();
        assert_eq!(t.issue_count(), n, "all seeded issues must be present");

        // --- board latency (catalog-only read; must be flat vs n) ---
        let k = 50u32;
        let tb = Instant::now();
        for _ in 0..k {
            let (r, _) = t.handle(Request::Board {
                project: "ENG".into(),
            });
            assert!(matches!(r, Response::Board(_)), "{r:?}");
        }
        let board_avg = tb.elapsed() / k;

        // --- list latency (catalog-only read) ---
        let tl = Instant::now();
        for _ in 0..k {
            let (r, _) = t.handle(Request::List {
                project: Some("ENG".into()),
                filter: Filter::default(),
            });
            assert!(matches!(r, Response::List { .. }), "{r:?}");
        }
        let list_avg = tl.elapsed() / k;

        // --- catalog VV-diff export cost (sync phase-1 whole-catalog cost) ---
        let empty_vv: Vec<u8> = vec![];
        let tc = Instant::now();
        let cat_diff = t.export_catalog_from(&empty_vv).unwrap();
        let catalog_export = tc.elapsed();

        println!(
            "PERF n={n} seed={seed:?} store={store_kb}KB cold_load={cold_load:?} \
             board_avg={board_avg:?} list_avg={list_avg:?} \
             catalog_full_export={catalog_export:?} catalog_bytes={cat_bytes}",
            store_kb = store_bytes / 1024,
            cat_bytes = cat_diff.len(),
        );
        std::fs::remove_dir_all(&home).ok();
    }

    fn fs_dir_size(p: &std::path::Path) -> u64 {
        let mut total = 0;
        if let Ok(rd) = std::fs::read_dir(p) {
            for e in rd.flatten() {
                let md = e.metadata();
                if let Ok(md) = md {
                    if md.is_dir() {
                        total += fs_dir_size(&e.path());
                    } else {
                        total += md.len();
                    }
                }
            }
        }
        total
    }

    #[test]
    fn validate_then_commit_rejects_before_any_change() {
        // A rejected write returns Error, rings NO doorbell, and changes nothing
        // (UI.md §4.3 — makes an optimistic rollback race-free).
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "fix login");
        let before_head = n.tracker.row_head_for(&reff);

        // bad status → Error, no dirty-set (no doorbell), state untouched.
        let (resp, dirty) = n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("nonsense_status".into()),
            priority: None,
        });
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
        assert!(dirty.is_none(), "a rejected write must ring no doorbell");
        assert_eq!(
            n.tracker.row_head_for(&reff),
            before_head,
            "a rejected write must not move the issue head"
        );

        // an unknown ref also errors with no doorbell.
        let (resp, dirty) = n.tracker.handle(Request::IssueEdit {
            reff: "iss_zzzzzzz".into(),
            title: Some("x".into()),
            status: None,
            priority: None,
        });
        assert!(matches!(resp, Response::Error { .. }));
        assert!(dirty.is_none());
    }

    #[test]
    fn one_request_is_one_activity_row_even_multi_field() {
        // S§7.1: a single IssueEdit moving several fields is ONE activity row.
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "t");
        let before = n.tracker.activity_high_water();
        let (resp, _) = n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: Some("t2".into()),
            status: Some("in_progress".into()),
            priority: Some("high".into()),
        });
        assert!(matches!(resp, Response::Ref { .. }));
        assert_eq!(
            n.tracker.activity_high_water() - before,
            1,
            "multi-field edit is one commit is one activity row"
        );
        // and that row carries all three field changes.
        if let Response::Activity { events, .. } = n.tracker.handle(Request::History { reff }).0 {
            let last = events.last().unwrap();
            assert_eq!(last.changes.len(), 3);
        } else {
            panic!("expected activity");
        }
    }

    #[test]
    fn writer_direction_row_follows_issue_doc() {
        // S§3.1: the DocMeta row is recomputed from the issue doc on every edit.
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "orig");
        n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: Some("changed".into()),
            status: Some("in_progress".into()),
            priority: None,
        });
        let rows = match n
            .tracker
            .handle(Request::List {
                project: Some("ENG".into()),
                filter: Filter::default(),
            })
            .0
        {
            Response::List { rows } => rows,
            other => panic!("{other:?}"),
        };
        let row = rows.iter().find(|r| r.reff == reff).unwrap();
        assert_eq!(row.title, "changed");
        assert_eq!(row.status, "in_progress");
    }

    #[test]
    fn load_time_head_recompute_self_heals_stale_row() {
        // S§3.2: a crash between the issue commit and the head mirror leaves a
        // stale head; on reopen the tracker recomputes it from the real issue
        // frontiers. Simulate by editing the issue doc + saving it WITHOUT
        // updating the catalog row, then reopening.
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "heal me");
        let stale_head = n.tracker.row_head_for(&reff).unwrap();

        // Reach into the store: mutate the issue doc and save it, but do NOT
        // touch the catalog (the "crash between two docs" window).
        let store = Store::open(&n.home).unwrap();
        let ids = store.issue_doc_ids();
        let issue = store.load_issue(&ids[0]).unwrap().unwrap();
        issue.set_title("healed on disk").unwrap();
        issue.commit();
        store.save_issue(&issue).unwrap();
        let real_head = crate::catalog::head_hash(&issue.head());
        assert_ne!(real_head, stale_head, "precondition: the head moved");

        // Reopen the tracker — recompute_all_rows must reconcile the row.
        let store2 = Store::open(&n.home).unwrap();
        let mut t2 = Tracker::open(
            store2,
            me(),
            "tester".into(),
            ME_SEED,
            Box::new(FakeClock::new(1_000_000)),
        )
        .unwrap();
        assert_eq!(
            t2.row_head_for(&reff),
            Some(real_head),
            "load-time recompute must heal the stale head"
        );
        assert_eq!(t2.issue_head_for(&reff), t2.row_head_for(&reff));
    }

    #[test]
    fn project_move_is_single_membership_with_self_healing_boards() {
        // S§5.5: Issue.projectId is the single source of membership; board lists
        // self-heal. Moving A from ENG to OPS leaves it in exactly one board.
        let mut n = new_node();
        with_project(&mut n.tracker);
        n.tracker.handle(Request::ProjectNew {
            name: "Operations".into(),
            key: "OPS".into(),
        });
        let reff = new_issue(&mut n.tracker, "movable");

        let (resp, dirty) = n.tracker.handle(Request::IssueMove {
            reff: reff.clone(),
            project: Some("OPS".into()),
            pos: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        // the doorbell dirties BOTH boards (old + new).
        let scopes = dirty.unwrap().dirty_catalog;
        assert!(
            scopes
                .iter()
                .filter(|s| matches!(s, CatalogScope::Boards { .. }))
                .count()
                >= 2,
            "a cross-project move dirties both boards: {scopes:?}"
        );

        // ENG board no longer lists it; OPS board does; exactly one membership.
        let eng = board_reffs(&mut n.tracker, "ENG");
        let ops = board_reffs(&mut n.tracker, "OPS");
        assert!(!eng.contains(&reff), "old project board must drop it");
        assert!(ops.contains(&reff), "new project board must list it");
    }

    fn board_reffs(t: &mut Tracker, project: &str) -> Vec<String> {
        match t
            .handle(Request::Board {
                project: project.into(),
            })
            .0
        {
            Response::Board(b) => b
                .columns
                .iter()
                .flat_map(|c| c.rows.iter().map(|r| r.reff.clone()))
                .collect(),
            other => panic!("{other:?}"),
        }
    }

    /// In-process E2EE: a non-member can't decrypt; after `member_add` + a
    /// membership sync the added member unseals the key and decrypts the catalog
    /// + issue docs; after `member_remove` + rotation new content is unreadable.
    fn sync_membership(from: &mut Tracker, to: &mut Tracker) {
        let vv = to.membership_vv_bytes();
        let upd = from.export_membership_from(&vv).unwrap();
        to.import_membership(&upd).unwrap();
    }
    fn sync_all(from: &mut Tracker, to: &mut Tracker) {
        sync_membership(from, to);
        let cvv = to.catalog_vv_bytes();
        let cupd = from.export_catalog_from(&cvv).unwrap();
        let needs = to.import_catalog_and_compute_needs(&cupd).unwrap();
        for need in needs {
            if let Ok(Some(bytes)) = from.export_doc_from(&need.doc_id, &need.vv) {
                to.import_doc(&need.doc_id, &bytes).unwrap();
            }
        }
    }
    fn titles(t: &mut Tracker) -> Vec<String> {
        match t
            .handle(Request::List {
                project: None,
                filter: Filter::default(),
            })
            .0
        {
            Response::List { rows } => rows.into_iter().map(|r| r.title).collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn e2ee_membership_gates_decryption() {
        let mut a = new_node(); // founder + admin
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret issue");

        let b_seed = [8u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_node_as(b_user.clone(), b_seed);
        let a_ws = a.tracker.workspace_str();
        assert!(
            b.tracker.adopt_workspace(&a_ws, me().as_str()).unwrap(),
            "B adopts A's workspace"
        );

        // Before add: B syncs but cannot decrypt — sees only ciphertext.
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(
            titles(&mut b.tracker).is_empty(),
            "non-member decrypts nothing"
        );
        assert!(!b.tracker.is_member(&b_user));

        // A adds B → B syncs membership, unseals the key, decrypts everything.
        let (resp, _) = a.tracker.member_add(&b_user, Role::Member);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.is_member(&b_user), "B is now a member");
        assert_eq!(
            titles(&mut b.tracker),
            vec!["secret issue".to_string()],
            "B decrypts"
        );

        // A removes B + rotates; new content is encrypted under an epoch B lacks.
        let (resp, _) = a.tracker.member_remove(&b_user);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        new_issue(&mut a.tracker, "post-removal");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(
            !titles(&mut b.tracker).iter().any(|t| t == "post-removal"),
            "lazy revocation: removed member can't read post-removal content"
        );
    }

    #[test]
    fn redeem_invite_seals_joiner_and_burns_single_use_nonce() {
        let mut a = new_node(); // founder + admin (me())
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "gated issue");
        let joiner = user_from_seed([8u8; 32]);
        let nonce = [1u8; 16];

        let (resp, dirty) = a.tracker.redeem_invite(&me(), &joiner, &nonce, true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            dirty.is_some(),
            "a successful admit dirties the catalog/ACL"
        );
        assert!(a.tracker.is_member(&joiner), "joiner is now a member");
        assert!(
            a.tracker.membership.is_redeemed(&nonce),
            "single-use nonce is burned in the same commit"
        );

        // Replay: the same nonce must not seat a second, different joiner.
        let other = user_from_seed([9u8; 32]);
        let (resp2, dirty2) = a.tracker.redeem_invite(&me(), &other, &nonce, true);
        assert!(
            matches!(resp2, Response::Error { .. }),
            "spent nonce is rejected: {resp2:?}"
        );
        assert!(dirty2.is_none(), "a rejected replay changes nothing");
        assert!(!a.tracker.is_member(&other), "replay seats no one");
    }

    #[test]
    fn redeem_invite_rejects_a_non_admin_issuer() {
        let mut a = new_node(); // only me() is an admin
        let issuer = user_from_seed([5u8; 32]); // never added to the ACL
        let joiner = user_from_seed([8u8; 32]);

        let (resp, dirty) = a.tracker.redeem_invite(&issuer, &joiner, &[2u8; 16], true);
        assert!(
            matches!(resp, Response::Error { .. }),
            "a pass signed by a non-admin is not honored: {resp:?}"
        );
        assert!(dirty.is_none());
        assert!(
            !a.tracker.is_member(&joiner),
            "no membership granted on a bad issuer"
        );
    }

    #[test]
    fn redeem_invite_is_idempotent_for_an_existing_member() {
        let mut a = new_node();
        let joiner = user_from_seed([8u8; 32]);
        let (_r, _d) = a.tracker.member_add(&joiner, Role::Member);
        assert!(a.tracker.is_member(&joiner));

        let (resp, dirty) = a.tracker.redeem_invite(&me(), &joiner, &[3u8; 16], true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(dirty.is_none(), "already a member ⇒ no ACL churn");
    }

    #[test]
    fn redeem_invite_reusable_pass_admits_many_without_burning() {
        let mut a = new_node();
        let nonce = [4u8; 16];
        let j1 = user_from_seed([8u8; 32]);
        let j2 = user_from_seed([9u8; 32]);

        let (r1, _) = a.tracker.redeem_invite(&me(), &j1, &nonce, false);
        let (r2, _) = a.tracker.redeem_invite(&me(), &j2, &nonce, false);
        assert!(matches!(r1, Response::Ok { .. }) && matches!(r2, Response::Ok { .. }));
        assert!(a.tracker.is_member(&j1) && a.tracker.is_member(&j2));
        assert!(
            !a.tracker.membership.is_redeemed(&nonce),
            "a reusable pass is never burned"
        );
    }

    #[test]
    fn completion_leaves_board_list_but_stays_in_docs() {
        // S§5.7: a done issue is removed from boards[proj] but stays in docs and
        // renders in the Done column via the append rule.
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "finish me");
        let board_len = |t: &Tracker| {
            let pid = t.catalog().project_by_key("ENG").unwrap().id;
            t.catalog().board_order(&pid).len()
        };
        assert_eq!(board_len(&n.tracker), 1);
        n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("done".into()),
            priority: None,
        });
        // board movable list is now empty (bounded to the active set)...
        assert_eq!(board_len(&n.tracker), 0);
        // ...but the issue still renders in the Done column.
        let done_present = match n
            .tracker
            .handle(Request::Board {
                project: "ENG".into(),
            })
            .0
        {
            Response::Board(b) => b
                .columns
                .iter()
                .find(|c| c.state.id == "done")
                .map(|c| c.rows.iter().any(|r| r.reff == reff))
                .unwrap_or(false),
            _ => false,
        };
        assert!(done_present, "done issue renders in the Done column");
        // and it is still counted as an existing issue.
        assert_eq!(n.tracker.issue_count(), 1);
    }
}
