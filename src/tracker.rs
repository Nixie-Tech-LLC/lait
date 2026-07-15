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

/// The three work-state intents (`start`/`done`/`stop`, UI.md §2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkAction {
    Start,
    Done,
    Stop,
}

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

/// Derive a project key from a human name: ≥2 words → uppercase initials (max
/// 4), one word → its first 4 letters, empty → "PRJ". Always 1–4 ASCII letters,
/// so `KEY-n` aliases and git-branch inference stay parseable.
pub fn derive_project_key(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .collect();
    let key: String = match words.len() {
        0 => "PRJ".to_string(),
        1 => words[0].chars().take(4).collect(),
        _ => words
            .iter()
            .take(4)
            .filter_map(|w| w.chars().next())
            .collect(),
    };
    key.to_ascii_uppercase()
}

/// Found a fresh workspace in `store` — the `lait init` path, and the ONLY
/// place a workspace comes into existence on this machine besides
/// [`join_workspace_store`]. Mints the genesis with `me` as founding admin
/// (S§6), creates the catalog carrying the display `name`, seals the epoch-0
/// workspace key to ourselves, and seeds the first project (named after the
/// workspace, key derived) so `lait new` works immediately. Errors if the store
/// already holds a workspace. Returns the workspace id and the seeded project.
pub fn found_workspace(
    store: &Store,
    me: &UserId,
    name: &str,
    clock: &dyn UlidSource,
) -> Result<(WorkspaceId, ProjectDto)> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a workspace");
    }
    let ws = WorkspaceId::mint(clock);
    let cat = CatalogDoc::create(&ws, name)?;
    // Seed the first project so a fresh workspace is usable on the very next
    // command. Plain catalog data — a joiner never hits this path.
    let project_name = if name.trim().is_empty() {
        "Main"
    } else {
        name.trim()
    };
    let project_id = ProjectId::mint(clock);
    let project_key = derive_project_key(project_name);
    cat.add_project(&project_id, project_name, &project_key, "blue")?;
    cat.doc().commit();
    let genesis = Genesis {
        workspace_id: ws.clone(),
        founding_admins: vec![me.clone()],
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&cat)?;
    let membership = MembershipDoc::create(&ws)?;
    let key = crypto::random_key();
    if let Some(sealed) = crypto::seal_to(me, &key) {
        membership.put_sealed(0, me, &sealed)?;
    }
    membership.doc().commit();
    store.save_membership(&membership)?;
    store.commit("init workspace");
    let project = cat
        .project(&project_id)
        .ok_or_else(|| anyhow!("seeded project vanished"))?;
    Ok((ws, project))
}

/// Bootstrap a store from a join ticket — the `lait join` path (A§6/A§10).
/// Writes the ticket's genesis (the host is the founding admin whose signed ACL
/// the joiner validates against) and **empty** catalog/membership docs, so
/// importing the founder's ops adopts identical container ids (see
/// [`CatalogDoc::empty`] — `create()` would mint conflicting containers).
/// Errors if the store already holds a workspace; the CLI guarantees it doesn't.
pub fn join_workspace_store(store: &Store, workspace: &str, founder: &str) -> Result<WorkspaceId> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a workspace");
    }
    let ws_id = WorkspaceId::parse(workspace)
        .ok_or_else(|| anyhow!("invalid workspace id in ticket: {workspace}"))?;
    let founding_admins = UserId::parse(founder).map(|u| vec![u]).unwrap_or_default();
    let genesis = Genesis {
        workspace_id: ws_id.clone(),
        founding_admins,
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&CatalogDoc::empty())?;
    store.save_membership(&MembershipDoc::empty())?;
    store.commit("join workspace from ticket");
    Ok(ws_id)
}

impl Tracker {
    /// Open the tracker over an **initialized** store — a missing catalog or
    /// genesis is an error, never a founding event (workspaces are born only in
    /// [`found_workspace`] / [`join_workspace_store`]). Performs the **load-time
    /// head recompute** (S§3.2): heads and rows are recomputed from the real
    /// issue-doc frontiers, never trusted from disk, so a crash between an issue
    /// commit and its row mirror self-heals.
    pub fn open(
        store: Store,
        me: UserId,
        my_nick: String,
        seed: [u8; 32],
        clock: Box<dyn UlidSource + Send + Sync>,
    ) -> Result<Self> {
        let catalog = store.load_catalog()?.ok_or_else(|| {
            anyhow!(
                "store not initialized — found no workspace here (run `lait init` or `lait join`)"
            )
        })?;
        let genesis = store.genesis()?.ok_or_else(|| {
            anyhow!("store missing genesis.json — corrupt or pre-rewrite store; re-init or re-join")
        })?;
        // A joiner's catalog is empty (no workspaceId) until the founder's ops
        // arrive over sync; the genesis is the local root of truth. A catalog
        // that DOES carry an id must agree with it.
        let workspace_id = match catalog.workspace_id() {
            Some(ws) if ws != genesis.workspace_id => {
                anyhow::bail!(
                    "catalog workspace {ws} does not match genesis {} — corrupt store",
                    genesis.workspace_id
                )
            }
            Some(ws) => ws,
            None => genesis.workspace_id.clone(),
        };
        let membership = match store.load_membership()? {
            Some(m) => m,
            None => {
                // Defensive only — both creation verbs write a membership doc.
                let m = MembershipDoc::empty();
                store.save_membership(&m)?;
                m
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
    /// The synced display name (empty on a joiner until the catalog arrives).
    pub fn workspace_name(&self) -> String {
        self.catalog.workspace_name()
    }
    /// Update the display nick (a `ConfigReload` applying `user.nick` live).
    /// Affects future activity attribution; nothing durable to rewrite.
    pub fn set_nick(&mut self, nick: String) {
        self.my_nick = nick;
    }
    /// Advisory project snapshot for the machine-level workspace registry.
    pub fn project_briefs(&self) -> Vec<crate::workspaces::ProjectBrief> {
        self.catalog
            .projects_list()
            .into_iter()
            .map(|p| crate::workspaces::ProjectBrief {
                key: p.key,
                name: p.name,
            })
            .collect()
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
                project_hint,
                assignees,
                priority,
                labels,
                body,
            } => self.issue_new(
                title,
                project,
                project_hint,
                assignees,
                priority,
                labels,
                body,
            ),
            Request::IssueEdit {
                reff,
                title,
                status,
                priority,
                description,
            } => self.issue_edit(reff, title, status, priority, description),
            Request::IssueMove { reff, project, pos } => self.issue_move(reff, project, pos),
            Request::Assign { reff, who, add } => self.assign(reff, who, add),
            Request::Label { reff, add, remove } => self.label(reff, add, remove),
            Request::Comment { reff, body } => self.comment(reff, body),
            Request::IssueDelete { reff } => self.issue_delete(reff),
            Request::IssueStart { reff } => self.work_state(reff, WorkAction::Start),
            Request::IssueDone { reff } => self.work_state(reff, WorkAction::Done),
            Request::IssueStop { reff } => self.work_state(reff, WorkAction::Stop),
            Request::IssueView { reff } => self.issue_view(reff).map(|r| (r, None)),
            Request::List { project, filter } => self.list(project, filter).map(|r| (r, None)),
            Request::Board {
                project,
                project_hint,
            } => self.board(project, project_hint).map(|r| (r, None)),
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

    /// Resolve the target/view project for a command. Precedence: explicit
    /// `-p`/positional (miss = hard error) → environment hint (the CLI's
    /// git-branch key — used only if it resolves, so a branch named `wip-2`
    /// never breaks `new`) → configured `project.default` (user-chosen, so a
    /// stale value errors loudly) → the sole project → a teaching error.
    fn choose_project(
        &self,
        explicit: Option<&str>,
        hint: Option<&str>,
    ) -> std::result::Result<ProjectDto, Response> {
        if let Some(p) = explicit {
            return self
                .resolve_project(p)
                .ok_or_else(|| Response::not_found(format!("no project matches '{p}'")));
        }
        if let Some(h) = hint {
            if let Some(pr) = self.resolve_project(h) {
                return Ok(pr);
            }
        }
        // Read fresh per request — no boot cache, so `lait config set` applies
        // to the very next command with no daemon notify.
        let settings = crate::config::Settings::load(Some(self.store.home_path()));
        if let Some(dflt) = settings.default_project() {
            return self.resolve_project(&dflt).ok_or_else(|| {
                Response::err(format!(
                    "project.default is '{dflt}' but no such project exists — fix it: `lait config set project.default <KEY>`"
                ))
            });
        }
        let projects = self.catalog.projects_list();
        match projects.len() {
            1 => Ok(projects.into_iter().next().unwrap()),
            0 => Err(Response::err(
                "no projects visible yet — still syncing, or create one: `lait projects new <name> --key <KEY>`",
            )),
            _ => {
                let keys: Vec<&str> = projects.iter().map(|p| p.key.as_str()).collect();
                Err(Response::err(format!(
                    "more than one project ({}) — pass -p <KEY> or set a default: `lait config set project.default <KEY>`",
                    keys.join(", ")
                )))
            }
        }
    }

    // ---- mutations ----

    #[allow(clippy::too_many_arguments)]
    fn issue_new(
        &mut self,
        title: String,
        project: Option<String>,
        project_hint: Option<String>,
        assignees: Vec<String>,
        priority: Option<String>,
        labels: Vec<String>,
        body: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        // ---- validate (no commits yet) ----
        if title.trim().is_empty() {
            return Ok((Response::err("title must not be empty"), None));
        }
        let project = match self.choose_project(project.as_deref(), project_hint.as_deref()) {
            Ok(pr) => pr,
            Err(resp) => return Ok((resp, None)),
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
        // Labels resolve-or-create (first use = creation, UI.md §2.2) — but the
        // whole batch is validated before anything is minted, so a bad input
        // later in the list can't leave stray labels behind.
        if let Some(l) = labels.iter().find(|l| self.invalid_label_input(l)) {
            return Ok((Response::not_found(format!("no label matches '{l}'")), None));
        }
        let mut label_ids = Vec::new();
        let mut created_label = false;
        for l in &labels {
            let (id, created) = self.resolve_or_create_label(l)?;
            created_label |= created;
            label_ids.push(id);
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
        // Incremental alias upkeep (O(log N)): a fresh doc + its two sorted
        // neighbours, not an O(N²) full rebuild.
        self.aliases.reconcile_doc(&self.catalog, &doc_id);
        // Durable already (fsync'd above); the git snapshot is coalesced by the
        // daemon's periodic checkpoint — no `git add -A` on the create path.
        self.store.mark_dirty();

        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "created", vec![], &title);
        let mut dirty = DirtySet::issue(&project.id, &doc_id).with_scope(CatalogScope::Boards {
            project: project.id.as_str().to_string(),
        });
        if created_label {
            dirty = dirty.with_scope(CatalogScope::Labels);
        }
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    fn issue_edit(
        &mut self,
        reff: String,
        title: Option<String>,
        status: Option<String>,
        priority: Option<String>,
        description: Option<String>,
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
        if title.is_none() && status.is_none() && priority.is_none() && description.is_none() {
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
            if let Some(d) = &description {
                // Full-buffer replace (P0, UI.md §5.3). Bodies are too big for
                // the activity row — record the transition, elide the values.
                issue.set_description(d)?;
                changes.push(FieldChange {
                    field: "description".into(),
                    from: None,
                    to: None,
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

    /// One work-state transition (UI.md §2 `start`/`done`/`stop`): the fields a
    /// single human intent moves — status by workflow *category* plus the
    /// viewer's assignment — in ONE Loro commit = one activity row (S§7.1).
    /// Returns a fresh `Response::Issue` snapshot (the CLI derives the git
    /// branch name from the title); a no-op (already there) returns the
    /// snapshot with no commit, no activity, no doorbell.
    fn work_state(
        &mut self,
        reff: String,
        action: WorkAction,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let (cat, kind) = match action {
            WorkAction::Start => (StatusCategory::Active, "started"),
            WorkAction::Done => (StatusCategory::Done, "finished"),
            WorkAction::Stop => (StatusCategory::Backlog, "stopped"),
        };
        let Some(target) = self.first_state_in(cat) else {
            return Ok((
                Response::err(format!(
                    "this space's workflow has no {}-category status",
                    cat.as_str()
                )),
                None,
            ));
        };
        let me = self.me.clone();

        let project_id;
        let mut changes = Vec::new();
        let status_transition: (String, String);
        {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            project_id = issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?;
            let from = issue.status();
            if from != target.id {
                issue.set_status(&target.id)?;
                changes.push(FieldChange {
                    field: "status".into(),
                    from: Some(from.clone()),
                    to: Some(target.id.clone()),
                });
            }
            status_transition = (from, target.id.clone());
            let assigned_to_me = issue.assignees().contains(&me);
            match action {
                WorkAction::Start if !assigned_to_me => {
                    issue.add_assignee(&me)?;
                    changes.push(FieldChange {
                        field: "assignees".into(),
                        from: None,
                        to: Some("@me".into()),
                    });
                }
                WorkAction::Stop if assigned_to_me => {
                    issue.remove_assignee(&me)?;
                    changes.push(FieldChange {
                        field: "assignees".into(),
                        from: Some("@me".into()),
                        to: None,
                    });
                }
                _ => {}
            }
            if changes.is_empty() {
                // Already exactly there — idempotent: no commit, no activity.
                return self.issue_view(reff).map(|r| (r, None));
            }
            issue.commit();
        }
        // completion policy (S§5.7): entering a done-category status removes the
        // doc from the board list; leaving one re-inserts it at the top.
        {
            let (from, to) = &status_transition;
            let from_done = self.is_done_status(from);
            let to_done = self.is_done_status(to);
            if to_done && !from_done {
                self.catalog.board_remove(&project_id, &doc_id)?;
            } else if from_done && !to_done {
                self.catalog.board_insert_top(&project_id, &doc_id)?;
            }
        }

        self.persist_issue_and_row(&doc_id)?;
        let canonical = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &canonical, kind, changes, "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        self.issue_view(canonical).map(|r| (r, Some(dirty)))
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
        // Adds create the label on first use (labels are vocabulary, not
        // ceremony — UI.md §2.2); removals still error on unknown (removing a
        // label that never existed is a typo, not intent). Everything that can
        // fail is validated BEFORE anything is created (validate-then-commit).
        if let Some(l) = add.iter().find(|l| self.invalid_label_input(l)) {
            return Ok((Response::not_found(format!("no label matches '{l}'")), None));
        }
        let mut remove_ids = Vec::new();
        for l in &remove {
            match self.resolve_label(l) {
                Some(id) => remove_ids.push(id),
                None => return Ok((Response::not_found(format!("no label matches '{l}'")), None)),
            }
        }
        let mut created_any = false;
        let mut add_ids = Vec::new();
        for l in &add {
            let (id, created) = self.resolve_or_create_label(l)?;
            created_any |= created;
            add_ids.push(id);
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
        let mut dirty = DirtySet::issue(&project_id, &doc_id);
        if created_any {
            dirty = dirty.with_scope(CatalogScope::Labels);
        }
        Ok((Response::Ref { reff }, Some(dirty)))
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
        self.store.mark_dirty();
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
        // 1–8 ASCII letters: anything else breaks `KEY-n` alias parsing and
        // git-branch inference (both scan for one alphabetic run).
        if key.len() > 8 || !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Ok((
                Response::err(format!(
                    "bad project key '{key}' — use 1-8 ASCII letters (it becomes the KEY in KEY-1 refs)"
                )),
                None,
            ));
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

    /// Whether an ADD-path label input can never resolve or be created: a
    /// `lbl_`-prefixed id that doesn't exist (an id reference is a pointer, and
    /// a dangling pointer is a typo, not a new name), or an empty name. Checked
    /// for the WHOLE batch before any creation, preserving validate-then-commit.
    fn invalid_label_input(&self, input: &str) -> bool {
        let name = input.trim();
        (name.is_empty() || name.starts_with(LabelId::PREFIX))
            && self.resolve_label(input).is_none()
    }

    /// Resolve a label for an ADD path, creating it on first use (gray). The
    /// caller has already rejected [`Self::invalid_label_input`]s.
    fn resolve_or_create_label(&mut self, input: &str) -> Result<(LabelId, bool)> {
        if let Some(id) = self.resolve_label(input) {
            return Ok((id, false));
        }
        let id = LabelId::mint(&*self.clock);
        self.catalog.add_label(&id, input.trim(), "gray")?;
        Ok((id, true))
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
        // Incremental alias upkeep. The table is a pure function of {DocId set,
        // projectId, seq}: a plain field edit changes none of these, so this is a
        // cheap O(1) no-op (one row read + a group-key compare). A *project move*
        // (`issue_move`) does change projectId, and this is what re-groups its
        // `KEY-n` alias (ENG-5 → DSN-5) — so keep it on the common tail rather
        // than making each mutation remember whether it moved the issue.
        self.aliases.reconcile_doc(&self.catalog, doc_id);
        // Coalesced git snapshot (see `new_issue`): keep `git add -A` off the
        // per-edit path; the daemon's checkpoint tick commits the batch.
        self.store.mark_dirty();
        Ok(())
    }

    /// Coalesce all pending durable-store mutations into one git commit
    /// (best-effort, inspectability only). Driven by the daemon's checkpoint
    /// tick and by tests/harness; a no-op when nothing is pending.
    pub fn checkpoint(&self) -> bool {
        self.store.checkpoint()
    }

    // ---- projections (reads) ----

    fn is_done_status(&self, status: &str) -> bool {
        self.catalog
            .workflow_state(status)
            .map(|w| w.category == StatusCategory::Done)
            .unwrap_or(false)
    }

    /// The first workflow state in a category — where the work-state verbs land
    /// (tracks whatever column set this space's workflow has).
    fn first_state_in(&self, cat: StatusCategory) -> Option<crate::dto::WorkflowState> {
        self.catalog
            .workflow()
            .into_iter()
            .find(|w| w.category == cat)
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
    fn board(&self, project: Option<String>, project_hint: Option<String>) -> Result<Response> {
        let project_dto = match self.choose_project(project.as_deref(), project_hint.as_deref()) {
            Ok(pr) => pr,
            Err(resp) => return Ok(resp),
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
        // Incremental alias upkeep after a catalog reconcile: reconcile every doc
        // the catalog now knows (O(1) per already-consistent doc, so O(N) total —
        // no O(N²) rebuild on every sync round). New peer docs and any offline
        // seq reconciliation are absorbed here.
        for id in self.catalog.doc_ids() {
            self.aliases.reconcile_doc(&self.catalog, &id);
        }
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
        // Capture the pre-import state relevant to *this viewer* — the only
        // honest source for the inbox (S§8.1): remote ops carry no trusted
        // actor, so "addressed to you" is detected as a state transition, not
        // read from attribution. `None` ⇒ the doc is new to this node.
        let prior = self.issues.get(&id).map(|i| {
            (
                i.assignees().contains(&self.me),
                i.status(),
                i.comments().len(),
            )
        });
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
        // Incremental upkeep for the one fetched doc (new or updated), O(log N).
        self.aliases.reconcile_doc(&self.catalog, &id);
        // a synced doc advances the activity feed (pulled, not streamed, S§7.5).
        let reff = self.aliases.canonical_for(&id);
        self.push_activity(Some(&id), &reff, "synced", vec![], "");
        // Inbox entries carry the friendly `KEY-n` handle when one exists —
        // they're read by a human scanning a summary line.
        let inbox_reff = self.aliases.alias_for(&id).unwrap_or(reff);
        self.derive_inbox_entries(&id, &inbox_reff, prior);
        match project_id {
            Some(p) => Ok(Some(DirtySet::issue(&p, &id))),
            None => Ok(None),
        }
    }

    /// Emit durable inbox entries for a just-imported doc: assignments to me,
    /// new comments on my work or mentioning `@mynick`, and status moves on my
    /// work. Backfill-bounded by construction: a brand-new-to-me doc (`prior ==
    /// None`) contributes at most one `assigned` entry, never a comment/status
    /// flood. Best-effort — inbox failure never affects the import.
    fn derive_inbox_entries(
        &mut self,
        id: &DocId,
        reff: &str,
        prior: Option<(bool, String, usize)>,
    ) {
        let Some(issue) = self.issues.get(id) else {
            return;
        };
        let me = &self.me;
        let now = self.clock.now_ms() / 1000;
        let title = issue.title();
        let assignees = issue.assignees();
        let assigned_to_me = assignees.contains(me);
        let my_issue = assigned_to_me || issue.created_by().as_ref() == Some(me);
        let entry = |kind: &str, detail: String, actor: Option<String>| crate::dto::InboxEntry {
            ts: now,
            kind: kind.into(),
            reff: reff.to_string(),
            doc_id: id.as_str().to_string(),
            title: title.clone(),
            detail,
            actor,
            actor_nick: None,
        };
        let mut entries = Vec::new();
        match prior {
            None => {
                if assigned_to_me {
                    entries.push(entry("assigned", "you were assigned".into(), None));
                }
            }
            Some((was_assigned_to_me, prior_status, prior_comments)) => {
                if !was_assigned_to_me && assigned_to_me {
                    entries.push(entry("assigned", "you were assigned".into(), None));
                }
                let status = issue.status();
                if status != prior_status && my_issue {
                    entries.push(entry("status", format!("{prior_status} → {status}"), None));
                }
                let mention = format!("@{}", self.my_nick).to_ascii_lowercase();
                for c in issue.comments().into_iter().skip(prior_comments) {
                    if &c.author == me {
                        continue;
                    }
                    let mentioned =
                        !self.my_nick.is_empty() && c.body.to_ascii_lowercase().contains(&mention);
                    if my_issue || mentioned {
                        entries.push(entry(
                            "comment",
                            c.body.clone(),
                            Some(c.author.as_str().to_string()),
                        ));
                    }
                }
            }
        }
        crate::inbox::append(self.store.home_path(), entries);
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
        // workspace ids — otherwise the deterministic clock collides them.
        let clock = FakeClock::new(1_000_000 + seed[0] as u64 * 100_000);
        // Explicit founding (no lazy mint): seeds the "Testbed" workspace with
        // its default TEST project, so trackers open like real founder stores.
        found_workspace(&store, &user, "Testbed", &clock).unwrap();
        let tracker = Tracker::open(store, user, "tester".into(), seed, Box::new(clock)).unwrap();
        TestNode { tracker, home }
    }

    /// A node whose store was bootstrapped from a ticket (the `lait join` path):
    /// genesis rooted on `ws`/`founder`, empty catalog/membership awaiting sync.
    fn new_joiner_node_as(user: UserId, seed: [u8; 32], ws: &str, founder: &str) -> TestNode {
        let home = std::env::temp_dir().join(format!(
            "gc-trk-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&home).unwrap();
        join_workspace_store(&store, ws, founder).unwrap();
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
            project_hint: None,
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
        // Git snapshotting is deferred off the mutation path (mark_dirty), so the
        // seed measures the tracker/store cost WITHOUT a `git add -A` per create;
        // the whole batch is committed by one explicit `checkpoint` afterwards.
        let t0 = Instant::now();
        let checkpoint;
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
                    project_hint: None,
                    assignees: vec![],
                    priority: None,
                    labels: vec![],
                    body: None,
                });
                assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
                assert!(dirty.is_some());
            }
            // One coalesced git commit for all N creates (the daemon does this on
            // a periodic tick; here we drive it explicitly to measure it).
            let c0 = Instant::now();
            t.checkpoint();
            checkpoint = c0.elapsed();
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
                project: Some("ENG".into()),
                project_hint: None,
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
            "PERF n={n} seed={seed:?} checkpoint={checkpoint:?} store={store_kb}KB \
             cold_load={cold_load:?} board_avg={board_avg:?} list_avg={list_avg:?} \
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
            description: None,
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
            description: None,
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
            description: None,
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
            description: None,
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

        // Regression guard for the incremental alias upkeep: a project move
        // changes projectId, so the `KEY-n` alias must re-group ENG-1 → OPS-1
        // (with only incremental `reconcile_doc` on the edit tail, a stale table
        // would keep showing ENG-1 on the OPS board row).
        let ops_aliases = board_key_aliases(&mut n.tracker, "OPS");
        assert!(
            ops_aliases.contains(&"OPS-1".to_string()),
            "moved issue's alias must re-group to the new project: {ops_aliases:?}"
        );
    }

    fn board_key_aliases(t: &mut Tracker, project: &str) -> Vec<String> {
        match t
            .handle(Request::Board {
                project: Some(project.into()),
                project_hint: None,
            })
            .0
        {
            Response::Board(b) => b
                .columns
                .iter()
                .flat_map(|c| c.rows.iter().filter_map(|r| r.key_alias.clone()))
                .collect(),
            other => panic!("{other:?}"),
        }
    }

    fn board_reffs(t: &mut Tracker, project: &str) -> Vec<String> {
        match t
            .handle(Request::Board {
                project: Some(project.into()),
                project_hint: None,
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
        let a_ws = a.tracker.workspace_str();
        // B's store is bootstrapped from the ticket (the `lait join` path).
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, me().as_str());
        assert_eq!(
            b.tracker.workspace_str(),
            a_ws,
            "B is rooted on A's workspace"
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
            description: None,
        });
        // board movable list is now empty (bounded to the active set)...
        assert_eq!(board_len(&n.tracker), 0);
        // ...but the issue still renders in the Done column.
        let done_present = match n
            .tracker
            .handle(Request::Board {
                project: Some("ENG".into()),
                project_hint: None,
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

    #[test]
    fn derive_project_key_shapes() {
        assert_eq!(derive_project_key("Engineering"), "ENGI");
        assert_eq!(derive_project_key("lait"), "LAIT");
        assert_eq!(derive_project_key("my cool app"), "MCA");
        assert_eq!(
            derive_project_key("Media Automation Stack Thing Extra"),
            "MAST"
        );
        assert_eq!(derive_project_key("x-1"), "X");
        assert_eq!(derive_project_key("42"), "PRJ");
        assert_eq!(derive_project_key(""), "PRJ");
        // Always alias/branch-parseable: 1-8 ASCII letters.
        for name in ["Engineering", "a b c d e f", "ünïcödé", "--- ---"] {
            let k = derive_project_key(name);
            assert!(
                (1..=8).contains(&k.len()) && k.chars().all(|c| c.is_ascii_uppercase()),
                "{name} → {k}"
            );
        }
    }

    #[test]
    fn founding_seeds_a_usable_workspace() {
        let mut n = new_node();
        // The founder can create an issue immediately — no `projects new` first.
        let (resp, dirty) = n.tracker.handle(Request::IssueNew {
            title: "first".into(),
            project: None,
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        assert!(dirty.is_some());
        assert_eq!(n.tracker.project_count(), 1, "exactly the seeded project");
        assert_eq!(n.tracker.workspace_name(), "Testbed");
        let seeded = &n.tracker.catalog().projects_list()[0];
        assert_eq!(seeded.key, "TEST", "key derived from the workspace name");
    }

    #[test]
    fn founding_twice_errors() {
        let n = new_node();
        let store = Store::open(&n.home).unwrap();
        let err = found_workspace(&store, &me(), "Again", &FakeClock::new(1)).unwrap_err();
        assert!(
            format!("{err:#}").contains("already initialized"),
            "{err:#}"
        );
    }

    #[test]
    fn open_errors_on_an_uninitialized_store() {
        let home = std::env::temp_dir().join(format!(
            "gc-trk-noinit-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&home).unwrap();
        let err = match Tracker::open(
            store,
            me(),
            "tester".into(),
            ME_SEED,
            Box::new(FakeClock::new(1)),
        ) {
            Ok(_) => panic!("open must not lazily found a workspace"),
            Err(e) => e,
        };
        assert!(
            format!("{err:#}").contains("not initialized"),
            "no lazy mint: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn choose_project_chain() {
        let mut n = new_node(); // seeded TEST project
                                // Sole project: no -p needed.
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: None,
        });
        assert!(matches!(resp, Response::Board(_)), "{resp:?}");

        with_project(&mut n.tracker); // + ENG → ambiguous
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: None,
        });
        let msg = match resp {
            Response::Error { ref message, .. } => message.clone(),
            other => panic!("expected teaching error, got {other:?}"),
        };
        assert!(msg.contains("TEST") && msg.contains("ENG"), "{msg}");
        assert!(msg.contains("project.default"), "teaches the fix: {msg}");

        // A resolvable hint (the CLI's git-branch key) breaks the tie…
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: Some("eng".into()),
        });
        assert!(
            matches!(resp, Response::Board(_)),
            "hint resolves: {resp:?}"
        );
        // …an unresolvable hint falls through silently (back to ambiguous).
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: Some("wip".into()),
        });
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

        // Explicit beats everything, and an explicit miss is a hard error.
        let (resp, _) = n.tracker.handle(Request::Board {
            project: Some("NOPE".into()),
            project_hint: Some("eng".into()),
        });
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

        // A configured default resolves the ambiguity…
        let mut store_cfg = crate::config::ConfigMap::default();
        store_cfg.set("project.default", "ENG");
        store_cfg
            .save(&crate::config::store_config_path(&n.home))
            .unwrap();
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: None,
        });
        assert!(matches!(resp, Response::Board(_)), "{resp:?}");
        // …but a stale one errors loudly instead of silently rotting.
        let mut store_cfg = crate::config::ConfigMap::default();
        store_cfg.set("project.default", "GONE");
        store_cfg
            .save(&crate::config::store_config_path(&n.home))
            .unwrap();
        let (resp, _) = n.tracker.handle(Request::Board {
            project: None,
            project_hint: None,
        });
        let msg = match resp {
            Response::Error { ref message, .. } => message.clone(),
            other => panic!("expected stale-default error, got {other:?}"),
        };
        assert!(msg.contains("GONE"), "{msg}");
    }

    #[test]
    fn work_state_verbs_are_atomic_and_idempotent() {
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "flaky reconnect");
        let me = me();

        // start: one request = assignee + status in ONE commit / ONE activity row.
        let before = n.tracker.activity_high_water();
        let (resp, dirty) = n.tracker.handle(Request::IssueStart { reff: reff.clone() });
        let v = match resp {
            Response::Issue(v) => v,
            other => panic!("start returns the fresh snapshot, got {other:?}"),
        };
        assert_eq!(v.status, "in_progress", "first Active-category state");
        assert!(v.assignees.contains(&me), "start assigns the caller");
        assert!(dirty.is_some());
        assert_eq!(
            n.tracker.activity_high_water(),
            before + 1,
            "one intent = one activity row"
        );

        // idempotent: already started → snapshot back, no commit, no doorbell.
        let (resp, dirty) = n.tracker.handle(Request::IssueStart { reff: reff.clone() });
        assert!(matches!(resp, Response::Issue(_)));
        assert!(dirty.is_none(), "no-op start must not ring");
        assert_eq!(n.tracker.activity_high_water(), before + 1);

        // done: status only (assignee kept), board list emptied (S§5.7).
        let (resp, _) = n.tracker.handle(Request::IssueDone { reff: reff.clone() });
        let v = match resp {
            Response::Issue(v) => v,
            other => panic!("{other:?}"),
        };
        assert_eq!(v.status, "done");
        assert!(v.assignees.contains(&me), "done keeps the assignee");

        // stop: back to backlog, unassigned.
        let (resp, _) = n.tracker.handle(Request::IssueStop { reff });
        let v = match resp {
            Response::Issue(v) => v,
            other => panic!("{other:?}"),
        };
        assert_eq!(v.status, "backlog", "first Backlog-category state");
        assert!(!v.assignees.contains(&me), "stop unassigns the caller");
    }

    #[test]
    fn labels_are_created_on_first_use_for_adds_only() {
        let mut n = new_node();
        with_project(&mut n.tracker);
        // Creating an issue with an unknown label mints it (gray).
        let (resp, dirty) = n.tracker.handle(Request::IssueNew {
            title: "tagged".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec!["perf".into()],
            body: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        assert!(
            dirty.unwrap().dirty_catalog.contains(&CatalogScope::Labels),
            "a minted label dirties the Labels scope"
        );
        assert!(
            n.tracker.catalog().label_by_name("perf").is_some(),
            "label exists after first use"
        );

        // `label <ref> +new` also creates; `-unknown` (remove) still errors.
        let reff = new_issue(&mut n.tracker, "plain");
        let (resp, _) = n.tracker.handle(Request::Label {
            reff: reff.clone(),
            add: vec!["ux".into()],
            remove: vec![],
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        assert!(n.tracker.catalog().label_by_name("ux").is_some());
        let (resp, dirty) = n.tracker.handle(Request::Label {
            reff,
            add: vec![],
            remove: vec!["never-existed".into()],
        });
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
        assert!(dirty.is_none());

        // A dangling lbl_ id is a typo, not a new name — and creates nothing.
        let count_before = n.tracker.catalog().labels_list().len();
        let (resp, _) = n.tracker.handle(Request::IssueNew {
            title: "typo".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec!["lbl_00000000000000000000000000".into()],
            body: None,
        });
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
        assert_eq!(n.tracker.catalog().labels_list().len(), count_before);
    }

    #[test]
    fn inbox_derives_addressed_to_me_from_imports() {
        let mut a = new_node(); // founder
        with_project(&mut a.tracker);
        let b_seed = [8u8; 32];
        let b_user = user_from_seed(b_seed);
        let a_ws = a.tracker.workspace_str();
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, me().as_str());
        let (resp, _) = a.tracker.member_add(&b_user, Role::Member);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // A files an issue assigned to B, then syncs: the doc is NEW to B, so
        // backfill emits exactly ONE entry (assigned), no comment/status flood.
        let (resp, _) = a.tracker.handle(Request::IssueNew {
            title: "for bob".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![b_user.as_str().to_string()],
            priority: None,
            labels: vec![],
            body: None,
        });
        let reff = match resp {
            Response::Ref { reff } => reff,
            other => panic!("{other:?}"),
        };
        sync_all(&mut a.tracker, &mut b.tracker);
        let (entries, unread) = crate::inbox::list(&b.home);
        assert_eq!(entries.len(), 1, "backfill-bounded: {entries:?}");
        assert_eq!(entries[0].kind, "assigned");
        assert_eq!(unread, 1);

        // A comments + moves status; B's next import derives both, with the
        // comment attributed to A's real key (the one honest author field).
        let (resp, _) = a.tracker.handle(Request::Comment {
            reff: reff.clone(),
            body: "root cause found".into(),
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        let (resp, _) = a.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        let (entries, _) = crate::inbox::list(&b.home);
        assert_eq!(entries.len(), 3, "{entries:?}");
        let comment = entries.iter().find(|e| e.kind == "comment").unwrap();
        assert_eq!(comment.detail, "root cause found");
        assert_eq!(comment.actor.as_deref(), Some(me().as_str()));
        let status = entries.iter().find(|e| e.kind == "status").unwrap();
        assert!(status.detail.contains("in_progress"), "{status:?}");

        // A's own local mutations never enter A's inbox; and B's imports of an
        // issue that isn't B's produce nothing.
        assert!(crate::inbox::list(&a.home).0.is_empty());
        new_issue(&mut a.tracker, "not bob's");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert_eq!(
            crate::inbox::list(&b.home).0.len(),
            3,
            "unrelated docs stay out"
        );
    }

    #[test]
    fn project_key_charset_is_validated() {
        let mut n = new_node();
        for bad in ["A-1", "MY KEY", "TOOLONGKEY", "42"] {
            let (resp, dirty) = n.tracker.handle(Request::ProjectNew {
                name: "X".into(),
                key: bad.into(),
            });
            assert!(
                matches!(resp, Response::Error { .. }),
                "'{bad}' should be rejected, got {resp:?}"
            );
            assert!(dirty.is_none());
        }
    }
}
