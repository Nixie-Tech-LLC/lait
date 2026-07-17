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

use anyhow::{anyhow, Context, Result};

use crate::acl::{self, AclAction, AclOp, AclState, Grant, SignedOp};
use crate::actor::{self, ActorPlane};
use crate::authz;
use crate::catalog::{CatalogDoc, RowMeta};
use crate::control::{BoardPos, CatalogScope, Filter, Request, Response};
use crate::crypto::{self, WorkspaceKey};
use crate::dto::{
    ActivityEvent, BoardColumn, BoardView, CommentDto, FieldChange, GraphView, IssueView, LabelDto,
    LinkDto, Priority, ProjectDto, Row, StatusCategory, SCHEMA_VERSION,
};
use crate::engine::history;
use crate::engine::op::OpCtx;
use crate::ids::{ActorId, DocId, LabelId, ProjectId, UlidSource, UserId, WorkspaceId};
use crate::index::{self, AliasTable, RefResolution};
use crate::issue::{IssueDoc, NewIssue};
use crate::membership::MembershipDoc;
use crate::store::{Genesis, Store};

/// Issue-link kinds the Layer-B façade accepts (contract §3.2). `relates` is
/// symmetric and canonicalized (sorted endpoints) so one edge represents it.
pub const LINK_KINDS: [&str; 3] = ["blocks", "relates", "duplicates"];

/// A 16-byte content-addressed epoch id prefixed to every AEAD ciphertext so the
/// reader selects the right key from its keyring (lazy revocation, A§11).
/// Content-addressed (not a counter) so concurrent rotations never collide.
fn epoch_prefix(id: &[u8; 16], mut blob: Vec<u8>) -> Vec<u8> {
    let mut out = id.to_vec();
    out.append(&mut blob);
    out
}
fn split_epoch(blob: &[u8]) -> Option<([u8; 16], &[u8])> {
    if blob.len() < 16 {
        return None;
    }
    let (e, rest) = blob.split_at(16);
    Some((e.try_into().ok()?, rest))
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
    keyring: BTreeMap<[u8; 16], WorkspaceKey>,
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
    device_seed: &[u8; 32],
    name: &str,
    clock: &dyn UlidSource,
) -> Result<(WorkspaceId, ProjectDto)> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a workspace");
    }
    let ws = WorkspaceId::mint(clock);
    let cat = CatalogDoc::create(&ws, name, Some(store.peer_id()), me)?;
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
    cat.apply(&OpCtx::structure("project_new", me));

    // Provision the founder's recovery key (pre-rotation commitment) and incept
    // the founding actor — the genesis anchors trust in the *actor*, so the
    // founder can rotate devices without re-founding (lait/actor/1).
    let (recovery_commit, recovery_seed) = mint_recovery();
    persist_recovery_key(store, &recovery_seed)?;
    let (incept_ev, actor_id) =
        actor::incept_single(device_seed, &ws, rand16(), rand16(), Some(recovery_commit));

    let genesis = Genesis {
        workspace_id: ws.clone(),
        founding_actors: vec![actor_id.clone()],
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&cat)?;
    let membership = MembershipDoc::create(&ws, Some(store.peer_id()), me)?;
    membership.add_actor_event(&incept_ev)?;
    // Mint the founding key epoch (id-addressed, generation 0) via a SIGNED
    // MintEpoch op authored by the founder, and seal it to the founder's device.
    // The signed mint is what any replica adopts — never a raw epoch record.
    let key = crypto::random_key();
    let epoch0 = rand16();
    let key_commit = *blake3::hash(&key).as_bytes();
    let mint = acl::sign_op(
        device_seed,
        &AclOp {
            action: AclAction::MintEpoch {
                id: epoch0,
                gen: 0,
                key_commit,
                members: vec![actor_id.clone()],
            },
            by: actor_id.clone(),
            actor_asof: vec![incept_ev.hash()],
            nonce: None,
        },
        membership.heads(),
        &ws,
    );
    membership.add_op(&mint)?;
    if let Some(sealed) = crypto::seal_to(me, &key) {
        membership.put_sealed(&epoch0, me, &sealed)?;
    }
    membership.apply(&OpCtx::authority("found", me));
    store.save_membership(&membership)?;
    store.commit("init workspace");
    let project = cat
        .project(&project_id)
        .ok_or_else(|| anyhow!("seeded project vanished"))?;
    Ok((ws, project))
}

/// 16 random bytes (an actor inception / consent nonce). Non-deterministic by
/// design — an inception id must be unpredictable, so this never routes through
/// the injected [`UlidSource`] clock.
fn rand16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

/// Mint a recovery keypair: returns (commitment, secret seed). The secret is
/// written to `recovery.key` and should be moved offline; the commitment is
/// public (it rides the inception).
fn mint_recovery() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom");
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    let recovery_pub = UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()));
    let commit = actor::recovery_commitment(&recovery_pub).expect("valid recovery pubkey");
    (commit, seed)
}

/// Persist the recovery secret beside the store. This is a root credential (the
/// pre-rotation escrow — losing it forfeits recovery, never workspace access),
/// so it is created **owner-only from the start** (never world-readable, even
/// for an instant) and any permission error is propagated, never swallowed.
fn persist_recovery_key(store: &Store, seed: &[u8; 32]) -> Result<()> {
    use std::io::Write;
    let home = store.home_path();
    // Tighten the parent dir to owner-only on unix before writing the secret.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(home, std::fs::Permissions::from_mode(0o700))
            .context("restrict store home permissions for recovery.key")?;
    }
    let path = home.join("recovery.key");
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(&path).context("create recovery.key")?;
    f.write_all(data_encoding::HEXLOWER.encode(seed).as_bytes())
        .context("write recovery.key")?;
    f.sync_all().context("fsync recovery.key")?;
    Ok(())
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
    // Fail loud on a missing/garbled founder anchor rather than minting a genesis
    // with no admin (which would silently brick the join — no actor could ever
    // authorize a membership op).
    let founder_actor = crate::ids::ActorId::parse(founder).ok_or_else(|| {
        anyhow!("ticket has no valid founder actor — it may be truncated or from an older lait; ask for a fresh one")
    })?;
    let founding_actors = vec![founder_actor];
    let genesis = Genesis {
        workspace_id: ws_id.clone(),
        founding_actors,
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&CatalogDoc::empty(Some(store.peer_id())))?;
    store.save_membership(&MembershipDoc::empty(Some(store.peer_id())))?;
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
                let m = MembershipDoc::empty(Some(store.peer_id()));
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

    /// Rebuild the keyring: unseal every **authorized** epoch's envelope
    /// addressed to our device (A§11 lazy revocation — we keep older keys so
    /// already-synced content stays readable). Called after any membership
    /// change/import.
    ///
    /// Two authenticity gates, both essential: we consider only epochs a valid
    /// writer-signed [`acl::AclAction::MintEpoch`] authorized (never a raw synced
    /// epoch), and we adopt the unsealed key only if `blake3(key)` matches that
    /// mint's `key_commit` — so a forged sealed envelope (an attacker overwriting
    /// our `(epoch, device)` slot with a key it chose) is rejected, not adopted.
    fn refresh_keyring(&mut self) {
        for e in self.acl_state().epochs() {
            if self.keyring.contains_key(&e.id) {
                continue;
            }
            if let Some(sealed) = self.membership.get_sealed(&e.id, &self.me) {
                if let Some(raw) = crypto::open_sealed(&self.seed, &self.me, &sealed) {
                    if let Ok(key) = <WorkspaceKey>::try_from(raw.as_slice()) {
                        // Bind the envelope to the signed mint: reject a key whose
                        // hash does not match the committed value.
                        if *blake3::hash(&key).as_bytes() == e.key_commit {
                            self.keyring.insert(e.id, key);
                        }
                    }
                }
            }
        }
    }

    /// The deterministic active epoch (the encryption target): the highest
    /// `(gen, id)` among **authorized** epochs — a pure function of the signed
    /// mint set, so every replica agrees even after concurrent rotations, and an
    /// injected (unauthorized) epoch is never selected.
    fn active_epoch(&self) -> Option<acl::EpochAuth> {
        self.acl_state()
            .epochs()
            .into_iter()
            .max_by(|a, b| a.gen.cmp(&b.gen).then_with(|| a.id.cmp(&b.id)))
    }

    /// Encrypt a sync payload with the active-epoch key (id-tagged).
    ///
    /// Two distinct "no key" cases, and only ONE may pass through in clear:
    /// - **No epochs exist at all** — a genuine keyless single-node P0 workspace
    ///   that holds no protected content: pass through.
    /// - **An active epoch exists but we lack its key** — the mid-seal window
    ///   (a freshly added or recovered device awaiting self-heal). We may hold
    ///   *older* content decrypted locally, so we must **never** emit it in
    ///   clear; serve nothing until we hold the active key.
    fn encrypt_payload(&self, plaintext: Vec<u8>) -> Vec<u8> {
        match self.active_epoch() {
            Some(e) => match self.keyring.get(&e.id) {
                Some(key) => epoch_prefix(&e.id, crypto::aead_encrypt(key, &plaintext)),
                // We can't encrypt under the active epoch — refuse to ship
                // cleartext (E2EE). An empty payload decrypts to nothing.
                None => Vec::new(),
            },
            None => plaintext,
        }
    }
    /// Decrypt a sync payload using the epoch id tag + our keyring. `None` if we
    /// lack that epoch's key — the blind-relay / non-member outcome: a non-member
    /// (empty keyring) or a removed member (missing the new epoch) learns nothing
    /// and simply imports nothing (A§11).
    fn decrypt_payload(&self, blob: &[u8]) -> Option<Vec<u8>> {
        let (id, ct) = split_epoch(blob)?;
        let key = self.keyring.get(&id)?;
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
            self.catalog.apply(&OpCtx::structure("row_heal", &self.me));
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

    /// Whether this request mutates workspace **content** (and so needs write
    /// standing). Membership, device, and recovery ops are excluded — they carry
    /// their own admin/self gates. Anything unlisted defaults to un-gated here,
    /// so a missed variant fails open to today's behavior, never a false denial.
    fn requires_write(req: &Request) -> bool {
        matches!(
            req,
            Request::IssueNew { .. }
                | Request::IssueEdit { .. }
                | Request::IssueMove { .. }
                | Request::Assign { .. }
                | Request::Label { .. }
                | Request::Comment { .. }
                | Request::IssueDelete { .. }
                | Request::IssueRestore { .. }
                | Request::IssueLink { .. }
                | Request::IssueUnlink { .. }
                | Request::IssueParent { .. }
                | Request::IssueStart { .. }
                | Request::IssueDone { .. }
                | Request::IssueStop { .. }
                | Request::ProjectNew { .. }
                | Request::LabelNew { .. }
        )
    }

    /// Whether this device's actor currently holds content-write standing
    /// (`can_write` = Admin or Write grant). A viewer, agent, or non-member is
    /// false.
    fn can_write_now(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().can_write(&a))
    }

    /// Handle a tracker request. Returns the response plus an optional dirty-set
    /// (present only when a commit happened — never on error, so a doorbell never
    /// rings for a rejected write; UI.md §4.3).
    pub fn handle(&mut self, req: Request) -> (Response, Option<DirtySet>) {
        // View-only enforcement. A member with no Write/Admin grant (a viewer)
        // is sealed the key and reads freely, but holds no content authority, so
        // it may not mutate workspace content. Non-members and agents are refused
        // for the same reason. Device/membership/recovery ops are self- or admin-
        // gated in their own handlers, so they are NOT gated here (a viewer must
        // still manage its own devices and recover). Signed content ops
        // (tombstones) are additionally void in the authz plane on every replica;
        // this gate refuses the unsigned-CRDT writes up front with a clear reason.
        if Self::requires_write(&req) && !self.can_write_now() {
            return (
                Response::err("view-only: your membership grants no write access"),
                None,
            );
        }
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
            Request::IssueRestore { reff } => self.issue_restore(reff),
            Request::IssueLink { reff, kind, target } => self.issue_link(reff, kind, target, true),
            Request::IssueUnlink { reff, kind, target } => {
                self.issue_link(reff, kind, target, false)
            }
            Request::IssueParent { reff, parent } => self.issue_parent(reff, parent),
            Request::IssueGraph { reff } => self.issue_graph(reff).map(|r| (r, None)),
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
            Request::AgentAdd { key } => Ok(self.agent_add_cmd(key)),
            Request::KeyRotate => Ok(self.key_rotate_cmd()),
            Request::DeviceInvite => Ok(self.device_invite_cmd()),
            Request::DeviceAdd { consent } => Ok(self.device_add_cmd(consent)),
            Request::DeviceRevoke { device } => Ok(self.device_revoke_cmd(device)),
            Request::DeviceList => Ok((self.device_list_response(), None)),
            Request::Recover => Ok(self.recover()),
            Request::Members => Ok((self.members_response(), None)),
            Request::MemberLog => Ok((self.member_log_response(), None)),
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
            // Nothing matched — offer the closest handles rather than a dead end.
            // The candidate machinery already exists for the ambiguous case; a
            // typo is the more common way to get here.
            RefResolution::Zero => {
                let near = index::near_misses(&self.catalog, &self.aliases, reff, 5);
                if near.is_empty() {
                    Err(Response::not_found(format!("no issue matches '{reff}'")))
                } else {
                    Err(Response::Candidates {
                        candidates: near,
                        near_miss_for: Some(reff.to_string()),
                    })
                }
            }
            RefResolution::Many(cands) => Err(Response::Candidates {
                candidates: cands,
                near_miss_for: None,
            }),
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
            match self.resolve_actor(a) {
                Some(act) => assignee_ids.push(act),
                None => {
                    return Ok((
                        Response::not_found(format!("no known member matches '{a}'")),
                        None,
                    ))
                }
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
            created_by: match self.my_actor() {
                Some(a) => a,
                None => return Ok((Response::err("this device has no actor identity"), None)),
            },
            committed_by: self.me.clone(),
            created_at: self.now_secs(),
            body,
            peer: Some(self.store.peer_id()),
        })?;
        for u in &assignee_ids {
            issue.add_assignee(u)?;
        }
        for l in &label_ids {
            issue.add_label(l)?;
        }
        issue.apply(&OpCtx::content("created", &self.me));

        self.catalog.upsert_row(&issue)?;
        self.catalog.assign_alias_seq(&doc_id, &project.id)?;
        self.catalog.board_insert_top(&project.id, &doc_id)?;
        self.catalog.apply(&OpCtx::structure("created", &self.me));

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

        let ctx = OpCtx::content("edited", &self.me);
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
                // Spliced into the RGA text (contract §3.1). Bodies are too big
                // for the activity row — record the transition, elide the values.
                issue.set_description(d)?;
                changes.push(FieldChange {
                    field: "description".into(),
                    from: None,
                    to: None,
                });
            }
            issue.apply(&ctx);
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

        self.persist_issue_and_row(&doc_id, "edited")?;
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
        let me = match self.my_actor() {
            Some(a) => a,
            None => return Ok((Response::err("this device has no actor identity"), None)),
        };
        let ctx = OpCtx::content(kind, &self.me);

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
            issue.apply(&ctx);
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

        self.persist_issue_and_row(&doc_id, kind)?;
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
                issue.apply(&OpCtx::content("moved", &self.me));
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

        self.persist_issue_and_row(&doc_id, "moved")?;
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
            match self.resolve_actor(w) {
                Some(a) => users.push(a),
                None => {
                    return Ok((
                        Response::not_found(format!("no known member matches '{w}'")),
                        None,
                    ))
                }
            }
        }
        let kind = if add { "assigned" } else { "unassigned" };
        let ctx = OpCtx::content(kind, &self.me);
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
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, kind)?;
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
        let ctx = OpCtx::content("labeled", &self.me);
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
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, "labeled")?;
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
        let ctx = OpCtx::content("commented", &self.me);
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            issue.add_comment(&me, ts, &body)?;
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, "commented")?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "commented", vec![], &body);
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    fn issue_delete(&mut self, reff: String) -> Result<(Response, Option<DirtySet>)> {
        self.set_deleted(reff, true)
    }
    fn issue_restore(&mut self, reff: String) -> Result<(Response, Option<DirtySet>)> {
        self.set_deleted(reff, false)
    }

    /// Delete or restore an issue — now a **signed content-authority op**
    /// (contract §3.4): agents cannot delete, every delete is attributable and
    /// reversible, and the catalog tombstone flag becomes a *cache* of the
    /// authz-plane replay. Human members only (an agent holds the key but no
    /// content authority).
    fn set_deleted(&mut self, reff: String, on: bool) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let project_id = self
            .catalog
            .row(&doc_id)
            .map(|r| r.project_id)
            .ok_or_else(|| anyhow!("no such row"))?;
        // Content authority = `can_write` (Admin or Write grant): agents and
        // grant-less viewers hold the key but no delete authority. The authz
        // plane voids their tombstone on every replica; we mirror that here so a
        // direct caller gets a clear refusal rather than a silently-void op.
        let me_actor = match self.my_actor() {
            Some(a) if self.acl_state().can_write(&a) => a,
            _ => {
                return Ok((
                    Response::err("no content authority to delete issues (view-only or agent)"),
                    None,
                ))
            }
        };
        // Sign the tombstone op, embedding both the membership frontier and the
        // actor-log frontier we observed (the at-position anchors), and append it
        // to the encrypted authz DAG.
        let op = authz::AuthzOp {
            action: authz::AuthzAction::Tombstone {
                doc: doc_id.clone(),
                on,
            },
            ts: self.now_secs(),
            asof: self.membership.heads(),
            by: me_actor.clone(),
            actor_asof: self.membership.actor_heads(&me_actor),
        };
        let signed = authz::sign_authz(
            &self.seed,
            &op,
            self.catalog.authz_heads(),
            &self.workspace_id,
        );
        self.catalog.add_authz_op(&signed)?;
        // The tombstone flag + board membership are a cache of the replay.
        let tombstoned = self.authz_state().is_tombstoned(&doc_id);
        self.catalog.set_tombstone(&doc_id, tombstoned)?;
        if tombstoned {
            self.catalog.board_remove(&project_id, &doc_id)?;
        } else {
            self.catalog.board_insert_top(&project_id, &doc_id)?;
        }
        self.catalog.apply(&OpCtx::authority(
            if on { "deleted" } else { "restored" },
            &self.me,
        ));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let reff = self.aliases.canonical_for(&doc_id);
        let verb = if on { "deleted" } else { "restored" };
        self.push_activity(Some(&doc_id), &reff, verb, vec![], "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        Ok((
            Response::Ok {
                message: Some(format!("{verb} {reff}")),
            },
            Some(dirty),
        ))
    }

    /// The materialized content-authority state (deterministic replay of the
    /// encrypted authz DAG against membership, contract §3.4).
    fn authz_state(&self) -> authz::AuthzState {
        authz::replay(
            &self.genesis,
            &self.membership.actor_events(),
            &self.membership.ops(),
            &self.catalog.authz_ops(),
        )
    }

    /// Reconcile catalog tombstone flags to the authz-plane replay after a sync
    /// import (writer-direction for the T2 plane): a peer's signed delete/restore
    /// becomes visible locally. Returns the docs whose visibility changed.
    fn reconcile_tombstones(&mut self) -> Result<Vec<DocId>> {
        let authz = self.authz_state();
        let mut changed = Vec::new();
        for doc_id in self.catalog.doc_ids() {
            if !authz.governs(&doc_id) {
                continue; // legacy docs keep their pre-CRAIT flag untouched
            }
            let want = authz.is_tombstoned(&doc_id);
            let have = self
                .catalog
                .row(&doc_id)
                .map(|r| r.tombstone)
                .unwrap_or(false);
            if want != have {
                self.catalog.set_tombstone(&doc_id, want)?;
                if let Some(pid) = self.catalog.row(&doc_id).map(|r| r.project_id) {
                    if want {
                        self.catalog.board_remove(&pid, &doc_id)?;
                    } else {
                        self.catalog.board_insert_top(&pid, &doc_id)?;
                    }
                }
                changed.push(doc_id);
            }
        }
        if !changed.is_empty() {
            self.catalog
                .apply(&OpCtx::authority("tombstone_sync", &self.me));
        }
        Ok(changed)
    }

    /// Add or remove an issue link (contract §3.2 `edges`). `relates` is
    /// symmetric and canonicalized by sorted endpoints so one edge represents it.
    fn issue_link(
        &mut self,
        reff: String,
        kind: String,
        target: String,
        add: bool,
    ) -> Result<(Response, Option<DirtySet>)> {
        let kind = kind.to_ascii_lowercase();
        if !LINK_KINDS.contains(&kind.as_str()) {
            return Ok((
                Response::err(format!(
                    "unknown link kind '{kind}' — one of: {}",
                    LINK_KINDS.join(", ")
                )),
                None,
            ));
        }
        let from = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let to = match self.resolve_issue(&target) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        if from == to {
            return Ok((Response::err("an issue cannot link to itself"), None));
        }
        let (a, b) = if kind == "relates" && to < from {
            (to.clone(), from.clone())
        } else {
            (from.clone(), to.clone())
        };
        if add {
            self.catalog.edge_add(&a, &kind, &b)?;
        } else if !self.catalog.edge_remove(&a, &kind, &b)? {
            return Ok((
                Response::not_found(format!("no such link: {reff} {kind} {target}")),
                None,
            ));
        }
        let verb = if add { "linked" } else { "unlinked" };
        self.catalog.apply(&OpCtx::structure(verb, &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let canonical = self.aliases.canonical_for(&from);
        let other = self.aliases.canonical_for(&to);
        self.push_activity(
            Some(&from),
            &canonical,
            verb,
            vec![],
            &format!("{kind} {other}"),
        );
        let mut dirty = DirtySet::default();
        for id in [&from, &to] {
            if let Some(r) = self.catalog.row(id) {
                dirty.merge(DirtySet::issue(&r.project_id, id));
            }
        }
        Ok((Response::Ref { reff: canonical }, Some(dirty)))
    }

    /// Set or clear an issue's parent in the sub-issue hierarchy (contract
    /// §3.2 `subs` — a tree-move CRDT, so concurrent conflicting parents can
    /// never converge to a cycle).
    fn issue_parent(
        &mut self,
        reff: String,
        parent: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let child = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let parent_id = match &parent {
            Some(p) => match self.resolve_issue(p) {
                Ok(id) => Some(id),
                Err(resp) => return Ok((resp, None)),
            },
            None => None,
        };
        if parent_id.as_ref() == Some(&child) {
            return Ok((Response::err("an issue cannot be its own parent"), None));
        }
        // validate-then-commit: reject a locally visible cycle before staging
        // any op (the engine's CyclicMoveError is the backstop; concurrent
        // cross-peer cycles are resolved by the merge itself).
        let mut cur = parent_id.clone();
        while let Some(p) = cur {
            if p == child {
                return Ok((
                    Response::err("that would make an issue its own ancestor"),
                    None,
                ));
            }
            cur = self.catalog.parent_of(&p);
        }
        self.catalog.set_parent(&child, parent_id.as_ref())?;
        self.catalog.apply(&OpCtx::structure("parented", &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let canonical = self.aliases.canonical_for(&child);
        let text = match &parent_id {
            Some(p) => format!("under {}", self.aliases.canonical_for(p)),
            None => "unparented".to_string(),
        };
        self.push_activity(Some(&child), &canonical, "parented", vec![], &text);
        let mut dirty = DirtySet::default();
        for id in std::iter::once(&child).chain(parent_id.iter()) {
            if let Some(r) = self.catalog.row(id) {
                dirty.merge(DirtySet::issue(&r.project_id, id));
            }
        }
        Ok((Response::Ref { reff: canonical }, Some(dirty)))
    }

    /// The issue's graph neighborhood: parent, children, links, and the
    /// transitively-open blockers. The catalog IS the graph index — this is a
    /// read over the structure doc, no issue doc is opened.
    fn issue_graph(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        let canonical = self.aliases.canonical_for(&doc_id);
        let rows: HashMap<DocId, RowMeta> = self
            .catalog
            .all_rows()
            .into_iter()
            .map(|r| (r.doc_id.clone(), r))
            .collect();
        let live = |id: &DocId| rows.get(id).filter(|r| !r.tombstone);

        let parent = self
            .catalog
            .parent_of(&doc_id)
            .and_then(|p| live(&p).map(|r| self.project_row(r)));
        let children: Vec<Row> = self
            .catalog
            .children_of(&doc_id)
            .iter()
            .filter_map(|c| live(c).map(|r| self.project_row(r)))
            .collect();

        let edges = self.catalog.edges();
        let mut links = Vec::new();
        for e in &edges {
            let (direction, other) = if e.from == doc_id {
                ("out", &e.to)
            } else if e.to == doc_id {
                ("in", &e.from)
            } else {
                continue;
            };
            if let Some(r) = live(other) {
                links.push(LinkDto {
                    kind: e.kind.clone(),
                    direction: direction.into(),
                    row: self.project_row(r),
                });
            }
        }

        // Transitive open blockers: walk `blocks` edges backwards from this
        // issue; a blocker counts while it is live and not in a done-category
        // status. BFS with a visited set — link cycles are legal in a general
        // edge set and must not hang the walk.
        let mut blocked_by = Vec::new();
        let mut seen: std::collections::HashSet<DocId> = std::collections::HashSet::new();
        let mut queue: VecDeque<DocId> = VecDeque::new();
        seen.insert(doc_id.clone());
        queue.push_back(doc_id.clone());
        while let Some(cur) = queue.pop_front() {
            for e in &edges {
                if e.kind == "blocks" && e.to == cur && seen.insert(e.from.clone()) {
                    if let Some(r) = live(&e.from) {
                        if !self.is_done_status(&r.status) {
                            blocked_by.push(self.project_row(r));
                            queue.push_back(e.from.clone());
                        }
                    }
                }
            }
        }

        Ok(Response::Graph(Box::new(GraphView {
            schema_version: SCHEMA_VERSION,
            reff: canonical,
            doc_id,
            parent,
            children,
            links,
            blocked_by,
        })))
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
        self.catalog
            .apply(&OpCtx::structure("project_new", &self.me));
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
        self.catalog.apply(&OpCtx::structure("label_new", &self.me));
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
    /// tail of every issue mutation). `kind` labels the catalog-side change so
    /// the structure doc's oplog stays as legible as the issue docs'.
    fn persist_issue_and_row(&mut self, doc_id: &DocId, kind: &str) -> Result<()> {
        let issue = self
            .issues
            .get(doc_id)
            .ok_or_else(|| anyhow!("issue not loaded"))?;
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.apply(&OpCtx::structure(kind, &self.me));
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
    /// Actor-keyed: any of an actor's devices renders as "you".
    fn assignee_summary(&self, assignees: &[ActorId]) -> String {
        if assignees.is_empty() {
            return String::new();
        }
        let mine = self.my_actor().is_some_and(|a| assignees.contains(&a));
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
            assignees: row.assignees.clone(),
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
            .filter(|r| !filter.mine || self.my_actor().is_some_and(|a| r.assignees.contains(&a)))
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
                    // Provisional row: the body (hence the authoring actor) hasn't
                    // synced yet.
                    created_by: ActorId::from_incept_hash(&"0".repeat(64)),
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
            created_by: issue
                .created_by()
                .unwrap_or_else(|| ActorId::from_incept_hash(&"0".repeat(64))),
            created_at: issue.created_at(),
            provisional: false,
        };
        Ok(Response::Issue(Box::new(view)))
    }

    /// The issue's history, derived from the **oplog on disk** (contract §5):
    /// durable across daemon restarts, field-level, attributed (advisory) for
    /// remote changes, with DAG-derived collision flags. The per-session
    /// activity ring stays what it is — the workspace feed's batch cursor.
    fn history(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        let canonical = self.aliases.canonical_for(&doc_id);
        let issue = self
            .issue(&doc_id)?
            .ok_or_else(|| anyhow!("issue body not present"))?;
        let events: Vec<ActivityEvent> = history::issue_history(issue)
            .into_iter()
            .enumerate()
            .map(|(i, ch)| ActivityEvent {
                seq: (i + 1) as u64,
                doc_id: Some(doc_id.clone()),
                reff: canonical.clone(),
                kind: ch.kind.unwrap_or_else(|| "change".into()),
                changes: ch.changes,
                actor: ch.actor,
                actor_nick: String::new(),
                text: ch
                    .comments
                    .first()
                    .map(|c| c.body.clone())
                    .unwrap_or_default(),
                ts: ch.ts,
                collision: ch.collision,
            })
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
        self.push_activity_from(ActivityEvent {
            seq: 0,
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
    }

    /// Ring-append a fully-built event (remote imports carry their own actor
    /// and collision flag); `seq` is stamped here.
    fn push_activity_from(&mut self, mut event: ActivityEvent) {
        self.activity_seq += 1;
        event.seq = self.activity_seq;
        self.activity.push_back(event);
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
        self.catalog.oplog_vv_bytes()
    }

    /// The catalog head digest, wire form (gossip announce, A§8).
    pub fn catalog_head_bytes(&self) -> Vec<u8> {
        self.catalog.head_hash()
    }

    /// A combined sync head over catalog + membership (the gossip announce
    /// trigger). A membership-only change (e.g. `member add`, which doesn't touch
    /// the catalog) still moves this head so peers pull and receive it (A§8/§11).
    pub fn sync_head_bytes(&self) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(&self.catalog.head_bytes());
        h.update(&self.membership.head_bytes());
        h.finalize().as_bytes().to_vec()
    }

    // ---- membership sync (plaintext, A§11 two-protocol split) ----

    /// The membership doc's oplog VV, wire-encoded.
    pub fn membership_vv_bytes(&self) -> Vec<u8> {
        self.membership.oplog_vv_bytes()
    }
    /// **Provider side.** Export the membership ops (plaintext) a puller lacks.
    pub fn export_membership_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        self.membership.export_from_bytes(peer_vv)
    }
    /// **Puller side.** Import a membership update (plaintext), then refresh our
    /// keyring — we may have just been added and can now decrypt the workspace.
    pub fn import_membership(&mut self, update: &[u8]) -> Result<()> {
        self.membership.import(update)?;
        self.store.save_membership(&self.membership)?;
        self.refresh_keyring();
        // Propagate any key we now hold to our own actor's other devices (SEAL-2
        // backstop for a device the rotating author hadn't seen).
        self.heal_member_device_envelopes()?;
        // Two admins removing different members concurrently can leave the active
        // epoch sealed to a since-removed actor after merge; re-seal to the true
        // current set (convergent, admin-only).
        self.heal_stale_epoch()?;
        Ok(())
    }

    // ---- membership / ACL operations (P3, S§6, A§11) ----

    /// The materialized ACL state (deterministic replay from genesis over the
    /// actor plane + the signed ACL ops, S§6 / lait/actor/1).
    pub fn acl_state(&self) -> AclState {
        acl::replay(
            &self.genesis,
            &self.membership.actor_events(),
            &self.membership.ops(),
        )
    }
    /// The actor plane materialized from the membership doc's key-events.
    pub fn actor_plane(&self) -> ActorPlane {
        actor::replay(&self.workspace_id, &self.membership.actor_events())
    }

    /// Ensure this device has an actor identity in this space, returning its
    /// inception event (for a joiner to carry in its `JoinRequest` so an admin
    /// can admit its *actor*). Idempotent: if we already have an actor, the
    /// existing inception is returned; otherwise we provision a recovery key and
    /// self-incept, persisting the event to our membership doc.
    pub fn self_inception(&mut self) -> Result<actor::SignedEvent> {
        if let Some(me) = self.my_actor() {
            let target = me.incept_hash().to_string();
            if let Some(ev) = self
                .membership
                .actor_events()
                .into_iter()
                .find(|e| e.hash() == target)
            {
                return Ok(ev);
            }
        }
        let (recovery_commit, recovery_seed) = mint_recovery();
        persist_recovery_key(&self.store, &recovery_seed)?;
        let (ev, _id) = actor::incept_single(
            &self.seed,
            &self.workspace_id,
            rand16(),
            rand16(),
            Some(recovery_commit),
        );
        self.membership.add_actor_event(&ev)?;
        self.persist_membership("self_incept")?;
        Ok(ev)
    }
    /// This device's own actor, if its inception has been established/synced.
    pub fn my_actor(&self) -> Option<ActorId> {
        self.actor_plane().actor_of_device(&self.me).cloned()
    }
    pub fn is_member_actor(&self, actor: &ActorId) -> bool {
        self.acl_state().is_member(actor)
    }
    /// Whether this device's actor is a member / admin of the workspace.
    pub fn am_i_member(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().is_member(&a))
    }
    pub fn am_i_admin(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().is_admin(&a))
    }
    /// Every device key belonging to a current member actor — the resolvable
    /// identities for the local user directory.
    pub fn member_device_keys(&self) -> Vec<UserId> {
        let plane = self.actor_plane();
        self.acl_state()
            .members()
            .into_iter()
            .flat_map(|(a, _)| plane.devices_of(&a))
            .collect()
    }
    /// Whether a device key currently speaks for a member actor.
    pub fn is_member_device(&self, dev: &UserId) -> bool {
        self.actor_plane()
            .actor_of_device(dev)
            .is_some_and(|a| self.acl_state().is_member(a))
    }
    /// Members (actor, grants, is_me) for the members view (UI.md §8). "is_me"
    /// is true when this device speaks for the actor.
    pub fn members(&self) -> Vec<(ActorId, Vec<Grant>, bool)> {
        let mine = self.my_actor();
        self.acl_state()
            .members()
            .into_iter()
            .map(|(a, g)| {
                let me = mine.as_ref() == Some(&a);
                (a, g, me)
            })
            .collect()
    }

    /// Author a membership op as our own actor, embedding our current actor-log
    /// frontier so a replica resolves our device→actor binding at position.
    fn author_acl(&self, action: AclAction) -> Result<SignedOp> {
        self.author_acl_nonce(action, None)
    }

    /// [`author_acl`] carrying an invite nonce (for `AddMember` via a single-use
    /// invite) so replay can dedup concurrent redemptions.
    ///
    /// [`author_acl`]: Self::author_acl
    fn author_acl_nonce(&self, action: AclAction, nonce: Option<[u8; 16]>) -> Result<SignedOp> {
        let by = self
            .my_actor()
            .ok_or_else(|| anyhow!("this device has no actor identity in this space yet"))?;
        let actor_asof = self.membership.actor_heads(&by);
        Ok(acl::sign_op(
            &self.seed,
            &AclOp {
                action,
                by,
                actor_asof,
                nonce,
            },
            self.membership.heads(),
            &self.workspace_id,
        ))
    }

    /// Seal every key-epoch we hold to **every device** of `actor` — the
    /// self-healing sealing fan-out (SEAL-1/SEAL-2): reaching one live device is
    /// enough for that actor to propagate the key to its siblings, but we seal
    /// all devices we can see for immediacy. The actor's inception must already
    /// be present (callers import it first).
    fn seal_epochs_to_actor(t: &mut Self, actor: &ActorId) -> Result<()> {
        let devices = t.actor_plane().devices_of(actor);
        let epochs: Vec<([u8; 16], WorkspaceKey)> =
            t.keyring.iter().map(|(e, k)| (*e, *k)).collect();
        for (epoch, key) in epochs {
            for d in &devices {
                if let Some(sealed) = crypto::seal_to(d, &key) {
                    t.membership.put_sealed(&epoch, d, &sealed)?;
                }
            }
        }
        Ok(())
    }

    /// Add (or re-grant) a member by actor and seal them the workspace key
    /// (S§6, A§11). Admin-only. The target actor's inception must already be
    /// known locally (the enrollment path imports it first via `redeem_invite`).
    pub fn member_add(
        &mut self,
        actor: &ActorId,
        grants: Vec<Grant>,
    ) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => return (Response::err("only an admin can add members"), None),
        }
        if !self.actor_plane().exists(actor) {
            return (
                Response::err(format!(
                    "unknown actor {} — invite them so their identity arrives first",
                    actor.short()
                )),
                None,
            );
        }
        let op = match self.author_acl(AclAction::AddMember {
            actor: actor.clone(),
            grants,
        }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let target = actor.clone();
        if let Err(e) =
            self.member_apply(op, "member_add", |t| Self::seal_epochs_to_actor(t, &target))
        {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(None, &actor.short(), "member_added", vec![], &actor.short());
        (
            Response::Ok {
                message: Some(format!("added member {}", actor.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Import a joiner's actor **inception** (from a `JoinRequest`) so a manual
    /// `member add <device>` can resolve their actor before admission. Validates
    /// the inception (a forged one is ignored) and is idempotent. Does NOT grant
    /// membership — it only makes the pending joiner's identity locally known.
    /// Returns whether the actor is now known.
    pub fn import_inception(&mut self, incept: &actor::SignedEvent) -> Result<bool> {
        let actor = ActorId::from_incept_hash(&incept.hash());
        if self.actor_plane().exists(&actor) {
            return Ok(true);
        }
        let mut candidate = self.membership.actor_events();
        candidate.push(incept.clone());
        if !actor::replay(&self.workspace_id, &candidate).exists(&actor) {
            return Ok(false); // invalid inception — never enters the container
        }
        self.membership.add_actor_event(incept)?;
        self.persist_membership("incept_import")?;
        Ok(true)
    }

    /// Admit a member by **importing their inception** and sealing them in —
    /// the manual-approve counterpart to [`redeem_invite`] (which additionally
    /// checks an invite grant). Admin-only. The inception is validated (a forged
    /// one is refused) before it enters the actors container.
    ///
    /// [`redeem_invite`]: Self::redeem_invite
    pub fn admit_member(
        &mut self,
        incept: &actor::SignedEvent,
        grants: Vec<Grant>,
    ) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => return (Response::err("only an admin can add members"), None),
        }
        let actor = ActorId::from_incept_hash(&incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(incept.clone());
        if !actor::replay(&self.workspace_id, &candidate).exists(&actor) {
            return (Response::err("invalid actor inception"), None);
        }
        if acl.is_member(&actor) {
            return (
                Response::Ok {
                    message: Some(format!("{} is already a member", actor.short())),
                },
                None,
            );
        }
        let op = match self.author_acl(AclAction::AddMember {
            actor: actor.clone(),
            grants,
        }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let incept = incept.clone();
        let target = actor.clone();
        if let Err(e) = self.member_apply(op, "member_admit", |t| {
            t.membership.add_actor_event(&incept)?;
            Self::seal_epochs_to_actor(t, &target)
        }) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(None, &actor.short(), "member_added", vec![], &actor.short());
        (
            Response::Ok {
                message: Some(format!("added member {}", actor.short())),
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
        issuer_device: &UserId,
        joiner_incept: &actor::SignedEvent,
        nonce: &[u8; 16],
        single_use: bool,
    ) -> (Response, Option<DirtySet>) {
        // The joiner's self-certifying actor id is its inception's hash. Validate
        // the inception cleanly incepts for THIS workspace before admitting it —
        // a forged inception must never enter the actors container.
        let joiner_actor = ActorId::from_incept_hash(&joiner_incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(joiner_incept.clone());
        if !actor::replay(&self.workspace_id, &candidate).exists(&joiner_actor) {
            return (
                Response::err("join request carried an invalid actor inception"),
                None,
            );
        }

        let plane = self.actor_plane();
        let acl = self.acl_state();
        // Authority: the grant's signing device must currently speak for an admin.
        let issuer_ok = plane
            .actor_of_device(issuer_device)
            .is_some_and(|a| acl.is_admin(a));
        if !issuer_ok {
            return (
                Response::err("invite issuer is not a workspace admin"),
                None,
            );
        }
        // We can only seal if we ourselves are an admin holding the key.
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => return (Response::err("this node is not an admin"), None),
        }
        // Single-use replay guard.
        if single_use && self.membership.is_redeemed(nonce) {
            return (Response::err("invite already redeemed"), None);
        }
        // Idempotent: already a member ⇒ nothing to seal, no ACL churn.
        if acl.is_member(&joiner_actor) {
            return (
                Response::Ok {
                    message: Some(format!("{} is already a member", joiner_actor.short())),
                },
                None,
            );
        }
        // Bind the nonce into the op for single-use invites so concurrent
        // redemptions of the same invite converge to one admitted actor.
        let op_nonce = if single_use { Some(*nonce) } else { None };
        let op = match self.author_acl_nonce(
            AclAction::AddMember {
                actor: joiner_actor.clone(),
                grants: vec![Grant::Write],
            },
            op_nonce,
        ) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let nonce = *nonce;
        let incept = joiner_incept.clone();
        let redeemer = joiner_incept.author.clone();
        let target = joiner_actor.clone();
        if let Err(e) = self.member_apply(op, "invite_redeem", |t| {
            // Import the joiner's identity, then seal every epoch to its devices.
            t.membership.add_actor_event(&incept)?;
            Self::seal_epochs_to_actor(t, &target)?;
            if single_use {
                t.membership.mark_redeemed(&nonce, &redeemer)?;
            }
            Ok(())
        }) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(
            None,
            &joiner_actor.short(),
            "member_added",
            vec![],
            &joiner_actor.short(),
        );
        (
            Response::Ok {
                message: Some(format!("auto-approved {} via invite", joiner_actor.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Remove a member (signed RemoveMember op) and **rotate the workspace key**
    /// (lazy revocation, A§3 non-goal 2): a new epoch sealed only to the remaining
    /// members' devices, so the removed actor cannot read *future* content.
    /// Admin-only.
    pub fn member_remove(&mut self, actor: &ActorId) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        let me = match self.my_actor() {
            Some(me) if acl.is_admin(&me) => me,
            _ => return (Response::err("only an admin can remove members"), None),
        };
        if actor == &me {
            return (Response::err("refusing to remove yourself"), None);
        }
        let op = match self.author_acl(AclAction::RemoveMember {
            actor: actor.clone(),
        }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        if let Err(e) = self.member_apply(op, "member_remove", |t| t.rotate_key()) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(
            None,
            &actor.short(),
            "member_removed",
            vec![],
            &actor.short(),
        );
        (
            Response::Ok {
                message: Some(format!(
                    "removed member {} and rotated the key",
                    actor.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Rotate the workspace key without a membership change (key hygiene).
    pub fn key_rotate_cmd(&mut self) -> (Response, Option<DirtySet>) {
        let is_admin = self
            .my_actor()
            .is_some_and(|me| self.acl_state().is_admin(&me));
        if !is_admin {
            return (Response::err("only an admin can rotate the key"), None);
        }
        match self.rotate_key() {
            Ok(()) => {
                if let Err(e) = self.persist_membership("key_rotate") {
                    return (Response::err(format!("{e:#}")), None);
                }
                let gen = self.active_epoch().map(|e| e.gen).unwrap_or(0);
                (
                    Response::Ok {
                        message: Some(format!("rotated the workspace key (generation {gen})")),
                    },
                    Some(DirtySet::catalog(CatalogScope::Acl)),
                )
            }
            Err(e) => (Response::err(format!("{e:#}")), None),
        }
    }

    /// Resolve a `<who>` ref to a known actor: an `act_` id directly, or a
    /// device key / `@me` mapped through the actor plane to its owning actor.
    fn resolve_actor(&self, who: &str) -> Option<ActorId> {
        if let Some(a) = ActorId::parse(who) {
            // A well-formed id resolves only if the actor is actually known to
            // this space — otherwise a typo'd/forged `act_…` would seat or
            // assign a phantom that no inception backs.
            return self.actor_plane().exists(&a).then_some(a);
        }
        let dev = index::resolve_user(who, &self.me)?;
        self.actor_plane().actor_of_device(&dev).cloned()
    }

    fn member_add_cmd(&mut self, who: String, admin: bool) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.resolve_actor(&who) else {
            return (
                Response::not_found(format!(
                    "no known actor matches '{who}' — invite them first so their identity arrives"
                )),
                None,
            );
        };
        let grants = if admin {
            vec![Grant::Admin, Grant::Write]
        } else {
            vec![Grant::Write]
        };
        self.member_add(&actor, grants)
    }
    fn member_remove_cmd(&mut self, who: String) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.resolve_actor(&who) else {
            return (
                Response::not_found(format!("no known actor matches '{who}'")),
                None,
            );
        };
        self.member_remove(&actor)
    }
    fn members_response(&self) -> Response {
        let acl = self.acl_state();
        let mine = self.my_actor();
        let members = acl
            .members()
            .into_iter()
            .map(|(actor, _grants)| {
                let standing = acl.standing(&actor).unwrap_or("member");
                crate::dto::MemberDto {
                    me: mine.as_ref() == Some(&actor),
                    // The sponsoring actor, for agents (empty otherwise).
                    sponsor: acl.sponsor_of(&actor).map(|s| s.as_str().to_string()),
                    key: actor.as_str().to_string(),
                    role: standing.into(),
                    // Local petnames live outside the tracker (never synced); the
                    // node layer overlays them onto this projection after the fact.
                    alias: String::new(),
                }
            })
            .collect();
        Response::Members { members }
    }

    fn agent_add_cmd(&mut self, who: String) -> (Response, Option<DirtySet>) {
        // `who` is the agent's device key (or actor id). The agent self-incepts
        // when it joins, so by sponsor time its actor is known (synced, or
        // imported from the join request by the node layer).
        let Some(actor) = self.resolve_actor(&who) else {
            return (
                Response::not_found(format!(
                    "no known actor for '{who}' — start the agent so it joins the workspace, then sponsor it"
                )),
                None,
            );
        };
        self.agent_add_by_actor(&actor)
    }

    /// The membership audit log — the signed ACL DAG replayed into a rendered,
    /// causally-ordered list of who did what, with each op's verdict (contract
    /// §3.4). Cryptographic provenance, distinct from the advisory activity feed.
    fn member_log_response(&self) -> Response {
        let (_state, audit) = acl::replay_with_audit(
            &self.genesis,
            &self.membership.actor_events(),
            &self.membership.ops(),
        );
        let entries = audit
            .into_iter()
            .map(|e| crate::dto::MemberLogEntry {
                op: e.hash,
                // The signing device key (verified — the signature covers the op).
                actor: e.author.as_str().to_string(),
                kind: e.kind.into(),
                // The subject is now an actor.
                subject: e.subject.map(|s| s.as_str().to_string()),
                role: e.grants.map(|g| {
                    if g.contains(&Grant::Admin) {
                        "admin".into()
                    } else if g.contains(&Grant::Write) {
                        "member".into()
                    } else {
                        "viewer".into()
                    }
                }),
                authorized: e.authorized,
            })
            .collect();
        Response::MemberLog { entries }
    }

    /// Sponsor an agent by importing its inception, then delegating to
    /// [`agent_add_by_actor`]. An agent is a **degenerate actor** (single-device,
    /// no recovery) that self-incepted in its own home.
    ///
    /// [`agent_add_by_actor`]: Self::agent_add_by_actor
    pub fn agent_add(&mut self, agent_incept: &actor::SignedEvent) -> (Response, Option<DirtySet>) {
        let agent_actor = ActorId::from_incept_hash(&agent_incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(agent_incept.clone());
        if !actor::replay(&self.workspace_id, &candidate).exists(&agent_actor) {
            return (Response::err("invalid agent inception"), None);
        }
        if let Err(e) = self.import_inception(agent_incept) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.agent_add_by_actor(&agent_actor)
    }

    /// Sponsor an already-known agent actor (contract §3.4): sign `AddAgent` and
    /// seal it the workspace key. Any human member may sponsor; the agent holds
    /// no membership or content authority, and its standing dies with the
    /// sponsor. The agent's inception must already be present (it self-incepts
    /// on join). Delegation, not elevation.
    pub fn agent_add_by_actor(&mut self, agent_actor: &ActorId) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_human_member(&me) => {}
            _ => {
                return (
                    Response::err("only a human member can sponsor an agent"),
                    None,
                )
            }
        }
        if !self.actor_plane().exists(agent_actor) {
            return (
                Response::err(format!(
                    "unknown agent {} — start it so its identity joins first",
                    agent_actor.short()
                )),
                None,
            );
        }
        if acl.is_member(agent_actor) {
            return (
                Response::err(format!(
                    "{} is already a workspace principal",
                    agent_actor.short()
                )),
                None,
            );
        }
        // The op is authored as the sponsor's actor (its by/asof), so the
        // AddAgent's sponsor = sponsor actor by construction.
        let op = match self.author_acl(AclAction::AddAgent {
            actor: agent_actor.clone(),
        }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let target = agent_actor.clone();
        if let Err(e) =
            self.member_apply(op, "agent_add", |t| Self::seal_epochs_to_actor(t, &target))
        {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(
            None,
            &agent_actor.short(),
            "agent_added",
            vec![],
            &agent_actor.short(),
        );
        (
            Response::Ok {
                message: Some(format!("sponsored agent {}", agent_actor.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    // ---- multi-device (lait/actor/1 device management) ----

    /// A device-enrollment token for adding another device to *this* actor:
    /// `<actor_id> <workspace_id>`. The new machine consumes it with
    /// `device accept`, which produces a consent blob for `device add`.
    fn device_invite_cmd(&self) -> (Response, Option<DirtySet>) {
        match self.my_actor() {
            Some(a) => (
                Response::Text {
                    text: format!("{} {}", a, self.workspace_id),
                },
                None,
            ),
            None => (
                Response::err("this device has no actor identity in this space yet"),
                None,
            ),
        }
    }

    fn device_list_response(&self) -> Response {
        let devices: Vec<String> = self
            .my_actor()
            .map(|a| self.actor_plane().devices_of(&a))
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                let me = if d == self.me { " (this device)" } else { "" };
                format!("{}{}", d.as_str(), me)
            })
            .collect();
        Response::Text {
            text: if devices.is_empty() {
                "no devices".to_string()
            } else {
                devices.join("\n")
            },
        }
    }

    /// Add a device to our actor from its consent blob (hex-encoded
    /// [`actor::DeviceBinding`] from `device accept`), authored by this device,
    /// and **seal every held epoch to it** so it can decrypt immediately (SEAL-1).
    fn device_add_cmd(&mut self, consent_hex: String) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.my_actor() else {
            return (Response::err("this device has no actor identity"), None);
        };
        let binding: actor::DeviceBinding = match data_encoding::HEXLOWER_PERMISSIVE
            .decode(consent_hex.as_bytes())
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
        {
            Some(b) => b,
            None => return (Response::err("could not decode device consent blob"), None),
        };
        if !actor::consent_verify(
            self.workspace_id.as_str(),
            &binding,
            &actor::ConsentCtx::Member { actor: &actor },
        ) {
            return (
                Response::err("device consent is not valid for this actor"),
                None,
            );
        }
        let new_device = binding.device.clone();
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::AddDevice {
                actor: actor.clone(),
                binding,
            },
            self.membership.actor_heads(&actor),
            &self.workspace_id,
        );
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            let held: Vec<([u8; 16], WorkspaceKey)> =
                self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
            for (id, key) in held {
                if let Some(sealed) = crypto::seal_to(&new_device, &key) {
                    self.membership.put_sealed(&id, &new_device, &sealed)?;
                }
            }
            self.persist_membership("device_add")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!("added device {}", new_device.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Revoke a device from our actor. De-listing is self-authored (any member
    /// may do it for their own actor). **Fencing** the device from future content
    /// needs a key rotation, which only an admin may mint: an admin rotates
    /// immediately (re-sealing the fresh epoch to the remaining devices only); a
    /// non-admin de-lists and is told the rotation is pending an admin, rather
    /// than being handed a rotation that would be inert.
    fn device_revoke_cmd(&mut self, device: String) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.my_actor() else {
            return (Response::err("this device has no actor identity"), None);
        };
        let Some(device) = UserId::parse(&device) else {
            return (Response::err("a device is a 64-hex ed25519 key"), None);
        };
        let devices = self.actor_plane().devices_of(&actor);
        if !devices.contains(&device) {
            return (Response::err("not a device of your actor"), None);
        }
        if devices.len() <= 1 {
            return (
                Response::err("cannot revoke your only device — use `recover` instead"),
                None,
            );
        }
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::RevokeDevice {
                actor: actor.clone(),
                device: device.clone(),
            },
            self.membership.actor_heads(&actor),
            &self.workspace_id,
        );
        // De-listing the device is self-authored and always applies. Fully
        // fencing it, though, requires a **key rotation**, which only an admin
        // may mint. Rotate when we can; otherwise apply the revocation and report
        // honestly that content re-keying is pending an admin — never claim a
        // rotation that would be inert (the device would keep reading under the
        // still-active epoch).
        let can_rotate = self.am_i_admin();
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            if can_rotate {
                self.rotate_key()?;
            }
            self.persist_membership("device_revoke")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        let message = if can_rotate {
            format!("revoked device {} and rotated the key", device.short())
        } else {
            format!(
                "revoked device {} from your identity — ask an admin to rotate the workspace key to fence its access to existing content",
                device.short()
            )
        };
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    fn read_recovery_key(&self) -> Option<[u8; 32]> {
        let path = self.store.home_path().join("recovery.key");
        let hex = std::fs::read_to_string(path).ok()?;
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Recover our actor with the offline recovery key: authored by the recovery
    /// key (which must match the standing pre-rotation commitment), it resets the
    /// device set to *this* device. **Lazy** (design): identity/standing is
    /// restored immediately, but this fresh device holds no workspace key until
    /// an admin or surviving peer re-seals it (self-heal on their next sync).
    pub fn recover(&mut self) -> (Response, Option<DirtySet>) {
        let Some(seed) = self.read_recovery_key() else {
            return (
                Response::err(
                    "no recovery.key found beside the store — restore your offline recovery key first",
                ),
                None,
            );
        };
        // Resolve the target actor by its pre-rotation commitment — NOT by the
        // current device set (a genuine recovery runs from a fresh device that is
        // not in the set). The actor whose standing commitment matches our
        // recovery key is the one we can recover.
        let recovery_pub = {
            let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
            UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
        };
        let commit = actor::recovery_commitment(&recovery_pub);
        let plane = self.actor_plane();
        let Some(actor) = plane
            .actors()
            .find(|(_, st)| commit.is_some() && st.recovery_commit == commit)
            .map(|(id, _)| id.clone())
        else {
            return (
                Response::err("no actor in this space matches this recovery key"),
                None,
            );
        };
        let binding = actor::consent_sign(
            &self.seed,
            self.workspace_id.as_str(),
            rand16(),
            &actor::ConsentCtx::Member { actor: &actor },
        );
        let ev = actor::sign_event(
            &seed,
            &actor::ActorOp::Recover {
                actor: actor.clone(),
                devices: vec![binding],
                next_commit: None,
            },
            self.membership.actor_heads(&actor),
            &self.workspace_id,
        );
        // Validate the recovery actually took (commitment match) before persisting.
        let mut candidate = self.membership.actor_events();
        candidate.push(ev.clone());
        let recovered = actor::replay(&self.workspace_id, &candidate)
            .state(&actor)
            .map(|s| s.recovered)
            .unwrap_or(false);
        if !recovered {
            return (
                Response::err("recovery key does not match this actor's commitment"),
                None,
            );
        }
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            self.persist_membership("recover")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "recovered actor {} — device set reset to this device; content access re-seals once a peer syncs",
                    actor.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Apply a signed op + an extra key-sealing step, then commit + persist.
    fn member_apply(
        &mut self,
        op: SignedOp,
        kind: &str,
        extra: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        self.membership.add_op(&op)?;
        extra(self)?;
        self.persist_membership(kind)
    }

    fn persist_membership(&mut self, kind: &str) -> Result<()> {
        self.membership.apply(&OpCtx::authority(kind, &self.me));
        self.store.save_membership(&self.membership)?;
        self.store.commit("membership change");
        self.refresh_keyring();
        Ok(())
    }

    /// Mint a fresh content-addressed key epoch, sealed to every device of every
    /// *current* member (computed AFTER any just-applied remove), and adopt it.
    /// A removed actor's devices are never in this set — the lazy-revocation
    /// fence. Concurrent rotations mint distinct ids, so they coexist rather than
    /// clobber; the deterministic active tip picks one for encryption and
    /// [`heal_stale_epoch`] re-rotates if a merge leaves the tip sealed to a
    /// since-removed actor.
    ///
    /// The mint is a **signed [`acl::AclAction::MintEpoch`]** authored as our own
    /// actor, so the epoch rides the same trust boundary as membership: a replica
    /// adopts it only when this author held write standing at position. If we are
    /// not a writer the op is inert everywhere (never selected, never a key), so
    /// this degrades gracefully rather than splitting state. The op commits to
    /// `blake3(new_key)`, binding the sealed envelopes we write next.
    ///
    /// [`heal_stale_epoch`]: Self::heal_stale_epoch
    fn rotate_key(&mut self) -> Result<()> {
        let gen = match self.active_epoch() {
            Some(e) => e
                .gen
                .checked_add(1)
                .ok_or_else(|| anyhow!("key-epoch generation exhausted"))?,
            None => 0,
        };
        let id = rand16();
        let new_key = crypto::random_key();
        let key_commit = *blake3::hash(&new_key).as_bytes();
        let members: Vec<(ActorId, Vec<Grant>)> = self.acl_state().members();
        let member_actors: Vec<ActorId> = members.iter().map(|(a, _)| a.clone()).collect();
        let op = self.author_acl(AclAction::MintEpoch {
            id,
            gen,
            key_commit,
            members: member_actors,
        })?;
        self.membership.add_op(&op)?;
        let plane = self.actor_plane();
        for (actor, _grants) in &members {
            for d in plane.devices_of(actor) {
                if let Some(sealed) = crypto::seal_to(&d, &new_key) {
                    self.membership.put_sealed(&id, &d, &sealed)?;
                }
            }
        }
        self.keyring.insert(id, new_key);
        Ok(())
    }

    /// Self-heal (SEAL-2), generalized across the whole membership: seal every
    /// epoch key we hold to any device of any *current member actor* that still
    /// lacks an envelope. Admin-ungated and safe — we only ever re-seal keys we
    /// already hold, and only to devices of actors who are entitled to the
    /// workspace key (present in the ACL). A removed actor is not in the member
    /// set, so lazy revocation is preserved.
    ///
    /// This is the backstop that lets any key-holding peer re-provision:
    /// - a *sibling* device added or reinstated after a rotation whose author
    ///   didn't yet see it (`seal to ≥1 device` suffices — SEAL-1), and
    /// - a *fresh recovery device* that reset an actor's key set and therefore
    ///   holds no key of its own; the first synced key-holder re-seals to it.
    fn heal_member_device_envelopes(&mut self) -> Result<()> {
        let held: Vec<([u8; 16], WorkspaceKey)> =
            self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
        if held.is_empty() {
            return Ok(());
        }
        let plane = self.actor_plane();
        let member_devices: Vec<UserId> = self
            .acl_state()
            .members()
            .into_iter()
            .flat_map(|(actor, _)| plane.devices_of(&actor))
            .collect();
        let mut sealed_any = false;
        for (id, key) in held {
            for dev in &member_devices {
                if self.membership.get_sealed(&id, dev).is_none() {
                    if let Some(sealed) = crypto::seal_to(dev, &key) {
                        self.membership.put_sealed(&id, dev, &sealed)?;
                        sealed_any = true;
                    }
                }
            }
        }
        if sealed_any {
            self.persist_membership("device_heal")?;
        }
        Ok(())
    }

    /// Convergent re-seal: if the active epoch's recorded recipient set still
    /// includes an actor who is no longer a member (a concurrent removal of a
    /// *different* member left a stale tip), mint a fresh epoch sealed to the
    /// actual current member set. Deterministic + monotone (the fresh epoch has a
    /// higher generation and a correct recipient set, so it is not itself stale),
    /// so all admins converge on a fenced tip. Admin-only; a non-admin waits.
    fn heal_stale_epoch(&mut self) -> Result<()> {
        let Some(active) = self.active_epoch() else {
            return Ok(());
        };
        // Only an admin can mint, so only an admin can heal.
        if !self.am_i_admin() {
            return Ok(());
        }
        let members: std::collections::BTreeSet<ActorId> = self
            .acl_state()
            .members()
            .into_iter()
            .map(|(a, _)| a)
            .collect();
        // Re-key the active tip if it is compromised or unusable:
        // - its *minter* is no longer a member — a departed member controlled
        //   its recipient list and knows its key, so it must not linger as the
        //   tip (the revocation fence the self-declared `members` list can't give);
        // - a *declared recipient* is no longer a member (a concurrent removal
        //   left a stale tip); or
        // - we hold admin standing yet cannot open it — a peer minted an epoch
        //   we have no key for, so content is frozen under it (liveness). A fresh
        //   mint sealed to the true member set supersedes it and every replica
        //   converges.
        let minter_gone = !members.contains(&active.minted_by);
        let recipient_gone = active.members.iter().any(|m| !members.contains(m));
        let unopenable = !self.keyring.contains_key(&active.id);
        if minter_gone || recipient_gone || unopenable {
            self.rotate_key()?;
            self.persist_membership("epoch_heal")?;
        }
        Ok(())
    }

    /// **Provider side.** Export the catalog ops a puller at `peer_vv` lacks,
    /// **encrypted** with the current workspace key (blind-relay envelope, A§11).
    pub fn export_catalog_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encrypt_payload(self.catalog.export_from_bytes(peer_vv)?))
    }

    /// **Provider side.** Export a single issue doc's updates from `peer_vv`
    /// (encrypted), or `None` if we don't hold that doc.
    pub fn export_doc_from(&mut self, doc_id: &str, peer_vv: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // Clone the epoch/key context before the issue borrow.
        let plain = match self.issue(&id)? {
            Some(issue) => issue.export_from_bytes(peer_vv)?,
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
                let local_head = issue.head_hash();
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
                        vv: issue.oplog_vv_bytes(),
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
            self.catalog.apply(&OpCtx::structure("row_heal", &self.me));
        }
        // A peer's imported catalog may carry new signed tombstone/restore ops
        // in the encrypted authz DAG (contract §3.4). Reconcile the cached
        // tombstone flags to the replay so a remote delete/restore takes effect.
        self.reconcile_tombstones()?;
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
    ///
    /// The activity row and the inbox are derived from the **oplog diff** around
    /// the import (contract §5): field-level changes, exactly-the-new comments
    /// (wherever they merged in the list — CRDT-positional, not index
    /// arithmetic), the DAG concurrency flag, and the incoming changes' advisory
    /// actor claims (their commit messages travel with the ops).
    pub fn import_doc(&mut self, doc_id: &str, bytes: &[u8]) -> Result<Option<DirtySet>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // Decrypt the blind-relay envelope (A§11); a non-member can't read it.
        let Some(bytes) = self.decrypt_payload(bytes) else {
            return Ok(None);
        };
        // Viewer-relative pre-import state for the inbox's assigned/status
        // entries (S§8.1): "addressed to you" is a state transition, never
        // trusted attribution. `None` ⇒ the doc is new to this node.
        let prior = self.issues.get(&id).map(|i| {
            let mine = self.my_actor().is_some_and(|a| i.assignees().contains(&a));
            (mine, i.status())
        });
        let mark = self.issues.get(&id).map(|i| i.import_mark());
        // ensure a doc exists to import into (new docs arrive as a snapshot).
        if !self.issues.contains_key(&id) {
            let doc = IssueDoc::from_snapshot(&bytes, Some(self.store.peer_id()))
                .map_err(|e| anyhow!("import new issue doc: {e}"))?;
            self.issues.insert(id.clone(), doc);
        } else {
            self.issues
                .get(&id)
                .unwrap()
                .import(&bytes)
                .map_err(|e| anyhow!("import issue update: {e}"))?;
        }
        // persist + recompute the row from the issue doc (disjoint field borrows).
        let issue = self.issues.get(&id).unwrap();
        let delta = mark
            .as_ref()
            .map(|m| history::import_delta(issue, m))
            .unwrap_or_default();
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.apply(&OpCtx::structure("synced", &self.me));
        let project_id = issue.project_id();
        self.store.save_catalog(&self.catalog)?;
        // Incremental upkeep for the one fetched doc (new or updated), O(log N).
        self.aliases.reconcile_doc(&self.catalog, &id);
        // a synced doc advances the activity feed (pulled, not streamed, S§7.5).
        let reff = self.aliases.canonical_for(&id);
        // Attribute the row to the incoming ops' actor when it is unambiguous;
        // advisory, exactly like `createdBy` (non-goal 6).
        let actor = match delta.actors.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        };
        self.push_activity_from(ActivityEvent {
            seq: 0, // stamped by push_activity_from
            doc_id: Some(id.clone()),
            reff: reff.clone(),
            kind: "synced".into(),
            changes: delta.fields.clone(),
            actor,
            actor_nick: String::new(),
            text: delta
                .new_comments
                .first()
                .map(|c| c.body.clone())
                .unwrap_or_default(),
            ts: self.now_secs(),
            collision: delta.collision,
        });
        // Inbox entries carry the friendly `KEY-n` handle when one exists —
        // they're read by a human scanning a summary line.
        let inbox_reff = self.aliases.alias_for(&id).unwrap_or(reff);
        self.derive_inbox_entries(&id, &inbox_reff, prior, &delta);
        match project_id {
            Some(p) => Ok(Some(DirtySet::issue(&p, &id))),
            None => Ok(None),
        }
    }

    /// Emit durable inbox entries for a just-imported doc: assignments to me,
    /// new comments on my work or mentioning `@mynick`, and status moves on my
    /// work. Comments come from the import's **oplog diff** (`delta`), so a
    /// concurrent comment that merged mid-list is detected exactly — the
    /// index-arithmetic `skip(prior_len)` this replaces both re-notified an old
    /// comment and dropped the new one in that case. Backfill-bounded by
    /// construction: a brand-new-to-me doc (`prior == None`) contributes at most
    /// one `assigned` entry, never a comment/status flood. Best-effort — inbox
    /// failure never affects the import.
    fn derive_inbox_entries(
        &mut self,
        id: &DocId,
        reff: &str,
        prior: Option<(bool, String)>,
        delta: &history::ImportDelta,
    ) {
        let Some(issue) = self.issues.get(id) else {
            return;
        };
        let my_actor = self.my_actor();
        let now = self.clock.now_ms() / 1000;
        let title = issue.title();
        let assignees = issue.assignees();
        let assigned_to_me = my_actor.as_ref().is_some_and(|a| assignees.contains(a));
        let my_issue = assigned_to_me || (my_actor.is_some() && issue.created_by() == my_actor);
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
            Some((was_assigned_to_me, prior_status)) => {
                if !was_assigned_to_me && assigned_to_me {
                    entries.push(entry("assigned", "you were assigned".into(), None));
                }
                let status = issue.status();
                if status != prior_status && my_issue {
                    entries.push(entry("status", format!("{prior_status} → {status}"), None));
                }
                let mention = format!("@{}", self.my_nick).to_ascii_lowercase();
                for c in &delta.new_comments {
                    // A comment's author is the committing device (advisory); skip
                    // our own comments regardless of which of our devices wrote it.
                    if my_actor
                        .as_ref()
                        .is_some_and(|a| self.actor_plane().actor_of_device(&c.author) == Some(a))
                    {
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
        self.issue(&id).ok().flatten().map(|i| i.head_hash())
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

    /// A single-device actor inception for `seed` in `t`'s workspace (a joiner's
    /// identity, as it would ride in a JoinRequest).
    fn incept_for(seed: [u8; 32], t: &Tracker) -> actor::SignedEvent {
        let (ev, _) = actor::incept_single(
            &seed,
            &t.workspace_id,
            [seed[0]; 16],
            [seed[0] ^ 0x33; 16],
            None,
        );
        ev
    }
    fn actor_of(ev: &actor::SignedEvent) -> ActorId {
        ActorId::from_incept_hash(&ev.hash())
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
        found_workspace(&store, &user, &seed, "Testbed", &clock).unwrap();
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
        issue.apply(&OpCtx::content("edited", &me()));
        store.save_issue(&issue).unwrap();
        let real_head = issue.head_hash();
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
    fn recover_resets_device_set_with_the_offline_key() {
        let mut a = new_node(); // founder, recovery.key provisioned beside the store
        let x = a.tracker.my_actor().unwrap();
        let da = a.tracker.me.clone();

        // Add a second device dB.
        let db_seed = [60u8; 32];
        let db = user_from_seed(db_seed);
        let binding = actor::consent_sign(
            &db_seed,
            &a.tracker.workspace_str(),
            [61u8; 16],
            &actor::ConsentCtx::Member { actor: &x },
        );
        let hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());
        a.tracker.device_add_cmd(hex);
        assert!(a.tracker.actor_plane().is_device_of(&x, &db));

        // Recover with the offline key: device set resets to just this device.
        let (resp, _) = a.tracker.recover();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let devices = a.tracker.actor_plane().devices_of(&x);
        assert_eq!(devices, vec![da], "recovery reset the set to this device");
        assert!(a.tracker.actor_plane().state(&x).unwrap().recovered);
    }

    #[test]
    fn fresh_device_recovers_and_decrypts_after_peer_reseal() {
        // The real recovery scenario: a brand-new device that was NEVER enrolled
        // restores the offline recovery key, recovers the founder actor (resolved
        // by its pre-rotation commitment, not by any device it holds), and — after
        // a key-holding peer syncs and re-seals — decrypts the existing content.
        let mut a = new_node(); // founder dA, recovery.key beside its store
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let x = a.tracker.my_actor().unwrap();
        let a_ws = a.tracker.workspace_str();

        // A fresh device dC bootstraps on X's workspace from a ticket. It is not a
        // device of any actor and holds no key.
        let c_seed = [70u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user.clone(), c_seed, &a_ws, &x.to_string());

        // dC learns the actor plane (X's inception + recovery commitment) and the
        // encrypted catalog, but cannot read it — no key, no membership.
        sync_all(&mut a.tracker, &mut c.tracker);
        assert_eq!(c.tracker.my_actor(), None, "dC is not yet any actor");
        assert!(
            !titles(&mut c.tracker).contains(&"secret".to_string()),
            "a keyless fresh device cannot read the workspace"
        );

        // A keyless device with an active epoch must NEVER serve cleartext.
        let empty_vv = c.tracker.catalog_vv_bytes();
        // (self-export from an empty vv would be the whole catalog, in clear, if
        // the leak were present)
        assert!(
            c.tracker.export_catalog_from(&empty_vv).unwrap().is_empty(),
            "a device that cannot encrypt under the active epoch serves nothing"
        );

        // Restore the offline recovery key beside dC's store and recover.
        let key = std::fs::read(a.home.join("recovery.key")).unwrap();
        std::fs::write(c.home.join("recovery.key"), key).unwrap();
        let (resp, _) = c.tracker.recover();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert_eq!(
            c.tracker.actor_plane().devices_of(&x),
            vec![c_user.clone()],
            "recovery reset X's device set to the fresh device"
        );
        assert_eq!(
            c.tracker.my_actor(),
            Some(x.clone()),
            "dC now resolves to the recovered actor X"
        );
        // Still no key — recovery reset the identity, not the content access.
        assert!(!titles(&mut c.tracker).contains(&"secret".to_string()));

        // dC pushes its recovery to A; A (still holding the key) re-seals the
        // active epoch to dC as part of importing the Recover.
        sync_all(&mut c.tracker, &mut a.tracker);
        // A pushes the freshly sealed envelope + catalog back to dC.
        sync_all(&mut a.tracker, &mut c.tracker);
        assert!(
            titles(&mut c.tracker).contains(&"secret".to_string()),
            "recovered fresh device decrypts once a peer re-seals the epoch"
        );
    }

    #[test]
    fn second_device_decrypts_then_revocation_fences_it() {
        // Multi-device end to end: A adds a second device dB to its actor (seal-
        // on-add), dB decrypts the workspace; A then revokes dB and rotates, and
        // dB is fenced from post-revocation content.
        let mut a = new_node(); // founder, device dA
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let x = a.tracker.my_actor().unwrap(); // the founder actor
        let a_ws = a.tracker.workspace_str();

        // dB (seed 50) consents into actor X (as `device accept` would).
        let db_seed = [50u8; 32];
        let db_user = user_from_seed(db_seed);
        let binding = actor::consent_sign(
            &db_seed,
            &a_ws,
            [51u8; 16],
            &actor::ConsentCtx::Member { actor: &x },
        );
        let consent_hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());

        // A adds dB.
        let (resp, _) = a.tracker.device_add_cmd(consent_hex);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            a.tracker.actor_plane().is_device_of(&x, &db_user),
            "dB is now a device of X"
        );

        // dB bootstraps its own store on X's workspace and syncs — it is the SAME
        // actor (the founder), so it unseals the key and decrypts.
        let mut b = new_joiner_node_as(db_user.clone(), db_seed, &a_ws, &x.to_string());
        sync_all(&mut a.tracker, &mut b.tracker);
        assert_eq!(
            b.tracker.my_actor(),
            Some(x.clone()),
            "dB resolves to actor X"
        );
        assert!(
            titles(&mut b.tracker).contains(&"secret".to_string()),
            "second device decrypts the workspace (seal-on-add)"
        );

        // A revokes dB and rotates; dB loses future content.
        let (resp, _) = a.tracker.device_revoke_cmd(db_user.as_str().to_string());
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            !a.tracker.actor_plane().is_device_of(&x, &db_user),
            "dB revoked from X"
        );
        new_issue(&mut a.tracker, "after-revoke");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(
            !titles(&mut b.tracker).iter().any(|t| t == "after-revoke"),
            "a revoked device is fenced from post-revocation content"
        );
    }

    #[test]
    fn single_use_invite_admits_exactly_one_actor_under_concurrency() {
        // 5b regression: two admins concurrently redeem the SAME single-use
        // invite for different actors; after merge exactly one is admitted, and
        // both replicas agree (nonce bound into the op + deterministic dedup).
        let mut a = new_node(); // founder/admin
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let a_ws = a.tracker.workspace_str();

        let mut b = new_joiner_node_as(user_from_seed([2; 32]), [2; 32], &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.am_i_admin());

        let nonce = [7u8; 16];
        let j1 = incept_for([8; 32], &a.tracker);
        let j2 = incept_for([9; 32], &a.tracker);
        let j1a = actor_of(&j1);
        let j2a = actor_of(&j2);
        let issuer = a.tracker.me.clone(); // an admin's device signed the invite

        // Concurrent redemptions on the two un-merged admins.
        a.tracker.redeem_invite(&issuer, &j1, &nonce, true);
        b.tracker.redeem_invite(&issuer, &j2, &nonce, true);

        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut b.tracker, &mut a.tracker);

        let a1 = a.tracker.is_member_actor(&j1a);
        let a2 = a.tracker.is_member_actor(&j2a);
        let b1 = b.tracker.is_member_actor(&j1a);
        let b2 = b.tracker.is_member_actor(&j2a);
        assert_eq!((a1, a2), (b1, b2), "both replicas agree on the winner");
        assert!(a1 ^ a2, "a single-use invite admits exactly one actor");
    }

    #[test]
    fn concurrent_rotations_converge_and_fence() {
        // 5a regression: two admins remove *different* members concurrently, each
        // rotating the key. Content-addressed epochs + the heal on merge must
        // converge (both admins read post-heal content) and fence both removed
        // members — no split-brain undecryptable key.
        let mut a = new_node(); // founder/admin
        with_project(&mut a.tracker);
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let a_ws = a.tracker.workspace_str();

        let mut b = new_joiner_node_as(user_from_seed([2; 32]), [2; 32], &a_ws, &a_actor);
        let mut c = new_joiner_node_as(user_from_seed([3; 32]), [3; 32], &a_ws, &a_actor);
        let mut d = new_joiner_node_as(user_from_seed([4; 32]), [4; 32], &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        let c_incept = c.tracker.self_inception().unwrap();
        let d_incept = d.tracker.self_inception().unwrap();
        let c_actor = actor_of(&c_incept);
        let d_actor = actor_of(&d_incept);

        // B is a second admin; C and D are members.
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        a.tracker.admit_member(&c_incept, vec![Grant::Write]);
        a.tracker.admit_member(&d_incept, vec![Grant::Write]);
        for n in [&mut b, &mut c, &mut d] {
            sync_all(&mut a.tracker, &mut n.tracker);
        }
        assert!(b.tracker.am_i_admin(), "B synced admin standing");

        // Concurrent removals (no sync between): A removes C, B removes D. Each
        // rotates locally to a fresh content-addressed epoch.
        a.tracker.member_remove(&c_actor);
        b.tracker.member_remove(&d_actor);

        // Merge both ways + a settling round so the heal epoch propagates.
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut b.tracker, &mut a.tracker);
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut b.tracker, &mut a.tracker);

        // The active epoch converged (both admins agree) — no key split-brain.
        assert_eq!(
            a.tracker.active_epoch().map(|e| e.id),
            b.tracker.active_epoch().map(|e| e.id),
            "admins converge on one active epoch after concurrent rotations"
        );

        // Post-heal content is written under the fenced tip and is readable by
        // both surviving admins but not by either removed member.
        new_issue(&mut a.tracker, "afterHeal");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(
            titles(&mut a.tracker).contains(&"afterHeal".to_string()),
            "A reads post-heal content"
        );
        assert!(
            titles(&mut b.tracker).contains(&"afterHeal".to_string()),
            "B reads post-heal content (no split-brain key)"
        );
        sync_all(&mut a.tracker, &mut c.tracker);
        sync_all(&mut a.tracker, &mut d.tracker);
        assert!(
            !titles(&mut c.tracker).iter().any(|t| t == "afterHeal"),
            "removed C is fenced from post-heal content"
        );
        assert!(
            !titles(&mut d.tracker).iter().any(|t| t == "afterHeal"),
            "removed D is fenced from post-heal content"
        );
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
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &a_actor);
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
        assert!(!b.tracker.am_i_member());

        // A adds B → B syncs membership, unseals the key, decrypts everything.
        // B's inception rides to A (here: passed directly, as a JoinRequest would).
        let b_incept = b.tracker.self_inception().unwrap();
        let b_actor = actor_of(&b_incept);
        let (resp, _) = a.tracker.admit_member(&b_incept, vec![Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.am_i_member(), "B is now a member");
        assert_eq!(
            titles(&mut b.tracker),
            vec!["secret issue".to_string()],
            "B decrypts"
        );

        // A removes B + rotates; new content is encrypted under an epoch B lacks.
        let (resp, _) = a.tracker.member_remove(&b_actor);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        new_issue(&mut a.tracker, "post-removal");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(
            !titles(&mut b.tracker).iter().any(|t| t == "post-removal"),
            "lazy revocation: removed member can't read post-removal content"
        );
    }

    #[test]
    fn a_viewer_reads_but_is_refused_writes_until_granted() {
        // The view-only member end to end: B is admitted with EMPTY grants, syncs
        // and decrypts (reads), but every content write is refused until an admin
        // grants Write — then the identical write succeeds.
        let mut a = new_node(); // founder/admin
        let proj = with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "existing");
        let a_ws = a.tracker.workspace_str();
        let a_actor = a.tracker.my_actor().unwrap().to_string();

        let b_seed = [12u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user, b_seed, &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        let b_actor = actor_of(&b_incept);

        // Admit B as a VIEWER (no grants), then sync.
        let (resp, _) = a.tracker.admit_member(&b_incept, vec![]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.am_i_member(), "a viewer is a member");
        assert_eq!(
            b.tracker.acl_state().standing(&b_actor),
            Some("viewer"),
            "empty grants ⇒ viewer standing"
        );
        // Reads work: the viewer decrypts existing content.
        assert!(
            titles(&mut b.tracker).contains(&"existing".to_string()),
            "a viewer decrypts and reads the workspace"
        );

        // Writes are refused, and nothing is committed (no dirty-set).
        let write = |title: &str| Request::IssueNew {
            title: title.into(),
            project: Some(proj.clone()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        };
        let (resp, dirty) = b.tracker.handle(write("sneaky"));
        assert!(
            matches!(resp, Response::Error { .. }) && dirty.is_none(),
            "a viewer's write is refused with no commit: {resp:?}"
        );

        // Admin grants B Write; the same write now succeeds.
        let (resp, _) = a
            .tracker
            .member_add(&b_actor, vec![Grant::Admin, Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        // member_add re-grant is authored against the *actor* frontier; grant
        // Write specifically (Admin+Write here) and sync so B sees its new grant.
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.can_write_now(), "B now holds write standing");
        let (resp, dirty) = b.tracker.handle(write("now allowed"));
        assert!(
            matches!(resp, Response::Ref { .. }) && dirty.is_some(),
            "a granted member's write succeeds: {resp:?}"
        );
    }

    #[test]
    fn injected_epoch_without_an_authorized_mint_is_never_adopted() {
        // Regression for the unauthenticated-epoch hijack. An attacker on the
        // workspace topic pushes a membership diff that injects a HIGHER-gen epoch
        // — a FORGED MintEpoch signed by an actor it self-incepted (so the
        // device→actor binding resolves) but that is NOT a member/writer, plus a
        // sealed envelope carrying an attacker-chosen key. Because the mint fails
        // the write-standing check in acl::replay, the epoch is never authorized,
        // so the victim never selects it and never adopts the attacker's key.
        use crate::membership::MembershipDoc;
        let mut a = new_node(); // founder/admin (victim)
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let victim_dev = a.tracker.me.clone();
        let victim_actor = a.tracker.my_actor().unwrap();
        let ws = a.tracker.workspace_id().clone();
        let legit_epoch = a.tracker.active_epoch().unwrap().id;
        let a_vv = a.tracker.membership_vv_bytes();

        // Attacker self-incepts an actor that never joined, then forges the mint.
        let atk_seed = [0x33u8; 32];
        let atk_dev = user_from_seed(atk_seed);
        let (atk_incept, atk_actor) =
            actor::incept_single(&atk_seed, &ws, [0x44u8; 16], [0x45u8; 16], None);
        let attacker_key = crate::crypto::random_key(); // the attacker knows this
        let poison_id = [0xEEu8; 16];
        let key_commit = *blake3::hash(&attacker_key).as_bytes();

        let evil = MembershipDoc::empty(None);
        evil.import(&a.tracker.export_membership_from(&[]).unwrap())
            .unwrap();
        evil.add_actor_event(&atk_incept).unwrap();
        let forged_mint = acl::sign_op(
            &atk_seed,
            &AclOp {
                action: AclAction::MintEpoch {
                    id: poison_id,
                    gen: 9999, // far above the legit tip — would win IF authorized
                    key_commit,
                    members: vec![victim_actor.clone()],
                },
                by: atk_actor.clone(),
                actor_asof: vec![atk_incept.hash()],
                nonce: None,
            },
            evil.heads(),
            &ws,
        );
        evil.add_op(&forged_mint).unwrap();
        let sealed = crate::crypto::seal_to(&victim_dev, &attacker_key).unwrap();
        evil.put_sealed(&poison_id, &victim_dev, &sealed).unwrap();
        evil.apply(&crate::engine::op::OpCtx::authority("poison", &atk_dev));
        let diff = evil.export_from_bytes(&a_vv).unwrap();

        // Victim imports it over sync (import_membership is ungated by design).
        a.tracker.import_membership(&diff).unwrap();

        // The forged epoch is NOT authorized, so it is never the active tip...
        assert_eq!(
            a.tracker.active_epoch().map(|e| e.id),
            Some(legit_epoch),
            "an injected epoch with no authorized mint must never be selected"
        );
        // ...and new content stays under the legit key — the attacker cannot read.
        new_issue(&mut a.tracker, "STILL-SECRET-after-injection");
        let export = a.tracker.export_catalog_from(&[]).unwrap();
        let (_id, ct) = export.split_at(16);
        assert!(
            crate::crypto::aead_decrypt(&attacker_key, ct).is_none(),
            "the attacker's key must not decrypt the victim's content"
        );
    }

    #[test]
    fn heal_supersedes_the_epoch_of_a_removed_minter() {
        // Backstop for the revocation bypass (a minter controls its epoch's
        // recipient list and key): if the active epoch was minted by an actor who
        // is later removed, an admin's heal re-keys it, so the departed member's
        // key never lingers as the live tip.
        let mut a = new_node(); // founder/admin A
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let a_actor = a.tracker.my_actor().unwrap();
        let a_ws = a.tracker.workspace_str();

        // B joins, is admitted as an ADMIN, and syncs.
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &a_actor.to_string());
        let b_incept = b.tracker.self_inception().unwrap();
        let b_actor = actor_of(&b_incept);
        let (resp, _) = a
            .tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);

        // B (admin) rotates the key: the active epoch is now minted by B.
        let (resp, _) = b.tracker.key_rotate_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut b.tracker, &mut a.tracker);
        assert_eq!(
            a.tracker.active_epoch().unwrap().minted_by,
            b_actor,
            "the active epoch was minted by B"
        );

        // A removes B WITHOUT the auto-rotation (author the op directly), leaving
        // B's epoch as the active tip — the concurrent-race residual heal guards.
        let rm = a
            .tracker
            .author_acl(AclAction::RemoveMember {
                actor: b_actor.clone(),
            })
            .unwrap();
        a.tracker.membership.add_op(&rm).unwrap();
        a.tracker
            .persist_membership("test_remove_no_rotate")
            .unwrap();
        assert!(!a.tracker.acl_state().is_member(&b_actor), "B is removed");
        assert_eq!(
            a.tracker.active_epoch().unwrap().minted_by,
            b_actor,
            "B's epoch is still the tip before heal"
        );

        // Heal: A sees the tip was minted by a non-member and re-keys.
        a.tracker.heal_stale_epoch().unwrap();
        let healed = a.tracker.active_epoch().unwrap();
        assert_eq!(healed.minted_by, a_actor, "A re-keyed the tip away from B");
        assert!(
            !a.tracker
                .membership
                .sealed_devices(&healed.id)
                .contains(&b_user),
            "the healed epoch is not sealed to the removed member's device"
        );
    }

    #[test]
    fn a_non_admin_device_revoke_is_honest_about_pending_rotation() {
        // A non-admin can de-list its own device but cannot mint the key rotation
        // that fences it, so the command says the rotation is pending an admin
        // rather than claiming a rotation that would be inert.
        let mut a = new_node(); // founder/admin
        let a_ws = a.tracker.workspace_str();
        let a_actor = a.tracker.my_actor().unwrap();

        // B joins as a plain WRITER (no admin).
        let b_seed = [41u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user, b_seed, &a_ws, &a_actor.to_string());
        let b_incept = b.tracker.self_inception().unwrap();
        let b_actor = actor_of(&b_incept);
        a.tracker.admit_member(&b_incept, vec![Grant::Write]); // writer, not admin
        sync_all(&mut a.tracker, &mut b.tracker);

        // B adds a second device so it has one to revoke.
        let b2_seed = [42u8; 32];
        let b2_user = user_from_seed(b2_seed);
        let binding = actor::consent_sign(
            &b2_seed,
            &a_ws,
            [43u8; 16],
            &actor::ConsentCtx::Member { actor: &b_actor },
        );
        let hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());
        let (resp, _) = b.tracker.device_add_cmd(hex);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        let gen_before = b.tracker.active_epoch().map(|e| e.gen);
        // B (non-admin) revokes its second device.
        let (resp, _) = b.tracker.device_revoke_cmd(b2_user.as_str().to_string());
        match resp {
            Response::Ok { message: Some(m) } => {
                assert!(
                    m.contains("admin"),
                    "expected a pending-rotation notice: {m}"
                )
            }
            other => panic!("expected Ok with a pending-rotation notice, got {other:?}"),
        }
        // The device is de-listed, but a non-admin's mint is inert: no rotation.
        assert!(
            !b.tracker.actor_plane().is_device_of(&b_actor, &b2_user),
            "the second device is de-listed"
        );
        assert_eq!(
            b.tracker.active_epoch().map(|e| e.gen),
            gen_before,
            "a non-admin cannot rotate the key"
        );
    }

    #[test]
    fn redeem_invite_seals_joiner_and_burns_single_use_nonce() {
        let mut a = new_node(); // founder + admin (me())
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "gated issue");
        let j_incept = incept_for([8u8; 32], &a.tracker);
        let j_actor = actor_of(&j_incept);
        let nonce = [1u8; 16];

        let (resp, dirty) = a.tracker.redeem_invite(&me(), &j_incept, &nonce, true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            dirty.is_some(),
            "a successful admit dirties the catalog/ACL"
        );
        assert!(
            a.tracker.is_member_actor(&j_actor),
            "joiner is now a member"
        );
        assert!(
            a.tracker.membership.is_redeemed(&nonce),
            "single-use nonce is burned in the same commit"
        );

        // Replay: the same nonce must not seat a second, different joiner.
        let other = incept_for([9u8; 32], &a.tracker);
        let (resp2, dirty2) = a.tracker.redeem_invite(&me(), &other, &nonce, true);
        assert!(
            matches!(resp2, Response::Error { .. }),
            "spent nonce is rejected: {resp2:?}"
        );
        assert!(dirty2.is_none(), "a rejected replay changes nothing");
        assert!(
            !a.tracker.is_member_actor(&actor_of(&other)),
            "replay seats no one"
        );
    }

    #[test]
    fn redeem_invite_rejects_a_non_admin_issuer() {
        let mut a = new_node(); // only me() is an admin
        let issuer = user_from_seed([5u8; 32]); // never added to the ACL
        let j_incept = incept_for([8u8; 32], &a.tracker);

        let (resp, dirty) = a
            .tracker
            .redeem_invite(&issuer, &j_incept, &[2u8; 16], true);
        assert!(
            matches!(resp, Response::Error { .. }),
            "a pass signed by a non-admin is not honored: {resp:?}"
        );
        assert!(dirty.is_none());
        assert!(
            !a.tracker.is_member_actor(&actor_of(&j_incept)),
            "no membership granted on a bad issuer"
        );
    }

    #[test]
    fn redeem_invite_is_idempotent_for_an_existing_member() {
        let mut a = new_node();
        let j_incept = incept_for([8u8; 32], &a.tracker);
        let j_actor = actor_of(&j_incept);
        let (_r, _d) = a.tracker.admit_member(&j_incept, vec![Grant::Write]);
        assert!(a.tracker.is_member_actor(&j_actor));

        let (resp, dirty) = a.tracker.redeem_invite(&me(), &j_incept, &[3u8; 16], true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(dirty.is_none(), "already a member ⇒ no ACL churn");
    }

    #[test]
    fn redeem_invite_reusable_pass_admits_many_without_burning() {
        let mut a = new_node();
        let nonce = [4u8; 16];
        let j1 = incept_for([8u8; 32], &a.tracker);
        let j2 = incept_for([9u8; 32], &a.tracker);

        let (r1, _) = a.tracker.redeem_invite(&me(), &j1, &nonce, false);
        let (r2, _) = a.tracker.redeem_invite(&me(), &j2, &nonce, false);
        assert!(matches!(r1, Response::Ok { .. }) && matches!(r2, Response::Ok { .. }));
        assert!(
            a.tracker.is_member_actor(&actor_of(&j1)) && a.tracker.is_member_actor(&actor_of(&j2))
        );
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
        let err =
            found_workspace(&store, &me(), &[1u8; 32], "Again", &FakeClock::new(1)).unwrap_err();
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
        let me_actor = n.tracker.my_actor().unwrap();

        // start: one request = assignee + status in ONE commit / ONE activity row.
        let before = n.tracker.activity_high_water();
        let (resp, dirty) = n.tracker.handle(Request::IssueStart { reff: reff.clone() });
        let v = match resp {
            Response::Issue(v) => v,
            other => panic!("start returns the fresh snapshot, got {other:?}"),
        };
        assert_eq!(v.status, "in_progress", "first Active-category state");
        assert!(v.assignees.contains(&me_actor), "start assigns the caller");
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
        assert!(v.assignees.contains(&me_actor), "done keeps the assignee");

        // stop: back to backlog, unassigned.
        let (resp, _) = n.tracker.handle(Request::IssueStop { reff });
        let v = match resp {
            Response::Issue(v) => v,
            other => panic!("{other:?}"),
        };
        assert_eq!(v.status, "backlog", "first Backlog-category state");
        assert!(
            !v.assignees.contains(&me_actor),
            "stop unassigns the caller"
        );
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
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        let (resp, _) = a.tracker.admit_member(&b_incept, vec![Grant::Write]);
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
    fn history_survives_daemon_restart() {
        // The contract §5 headline: `lait history` is derived from the oplog on
        // disk, not a per-session ring — a fresh tracker over the same store
        // (the daemon-restart case, which idle-shutdown makes the NORMAL case)
        // returns the full feed with kinds, actors, timestamps and transitions.
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "durable");
        let (resp, _) = n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: Some("high".into()),
            description: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

        // "Restart": a brand-new tracker over the same store. The old activity
        // ring is dropped with the old instance.
        let store2 = Store::open(&n.home).unwrap();
        let mut t2 = Tracker::open(
            store2,
            me(),
            "tester".into(),
            ME_SEED,
            Box::new(FakeClock::new(1_000_000)),
        )
        .unwrap();
        let (resp, _) = t2.handle(Request::History { reff });
        let events = match resp {
            Response::Activity { events, .. } => events,
            other => panic!("{other:?}"),
        };
        assert_eq!(events.len(), 2, "created + edited: {events:?}");
        assert_eq!(events[0].kind, "created");
        assert_eq!(events[1].kind, "edited");
        assert_eq!(events[1].actor, Some(me()), "advisory actor survives");
        let status = events[1]
            .changes
            .iter()
            .find(|c| c.field == "status")
            .expect("status transition recorded");
        assert_eq!(status.from.as_deref(), Some("backlog"));
        assert_eq!(status.to.as_deref(), Some("in_progress"));
        assert!(
            events[1].changes.iter().any(|c| c.field == "priority"),
            "multi-field edit keeps all transitions: {events:?}"
        );
    }

    #[test]
    fn synced_rows_carry_field_changes_actor_and_collision() {
        // Contract §5 + A§9: a remote change arrives with field-level changes
        // and its (advisory) actor, and a genuinely concurrent import raises
        // the DAG collision flag — the compensating control for LWW fields.
        let mut a = new_node();
        with_project(&mut a.tracker);
        let b_seed = [9u8; 32];
        let b_user = user_from_seed(b_seed);
        let a_ws = a.tracker.workspace_str();
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        let (resp, _) = a.tracker.admit_member(&b_incept, vec![Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let reff = new_issue(&mut a.tracker, "contested");
        sync_all(&mut a.tracker, &mut b.tracker);

        // Concurrent edits: A moves the title while B moves the status.
        let (resp, _) = a.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: Some("renamed by a".into()),
            status: None,
            priority: None,
            description: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        let (resp, _) = b.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

        let before = b.tracker.activity_high_water();
        // Drive A's concurrent doc edit into B directly. (A single
        // catalog-triggered pull can transiently *skip* a concurrent same-doc
        // edit: the catalog row `head` is one LWW cell both peers write, so
        // when the puller wins that race `local_head == cat_head` looks
        // up-to-date though the provider holds a concurrent op. It self-heals
        // over bidirectional gossip rounds — a convergence lag orthogonal to
        // this test, which is about the *import* producing a correct synced
        // row. An empty VV requests the full doc; import is idempotent and the
        // concurrent branch still registers.)
        let did = a.tracker.resolve_issue(&reff).unwrap().to_string();
        let enc = a.tracker.export_doc_from(&did, &[]).unwrap().unwrap();
        b.tracker.import_doc(&did, &enc).unwrap();
        let (resp, _) = b.tracker.handle(Request::Activity { since: before });
        let events = match resp {
            Response::Activity { events, .. } => events,
            other => panic!("{other:?}"),
        };
        let synced = events
            .iter()
            .find(|e| e.kind == "synced")
            .expect("import produces a synced row");
        assert!(
            synced
                .changes
                .iter()
                .any(|c| { c.field == "title" && c.to.as_deref() == Some("renamed by a") }),
            "field-level change on the synced row: {synced:?}"
        );
        assert_eq!(
            synced.actor,
            Some(me()),
            "the incoming change's advisory actor is surfaced"
        );
        assert!(
            synced.collision,
            "concurrent branches must raise the collision flag: {synced:?}"
        );
    }

    #[test]
    fn link_parent_graph_roundtrip() {
        let mut n = new_node();
        with_project(&mut n.tracker);
        new_issue(&mut n.tracker, "epic");
        new_issue(&mut n.tracker, "child");
        new_issue(&mut n.tracker, "blocker");
        // Re-resolve after all creates: a canonical short handle minted earlier
        // can become ambiguous once same-millisecond siblings share its prefix.
        let by_title = |t: &mut Tracker, title: &str| -> String {
            match t
                .handle(Request::List {
                    project: None,
                    filter: Filter::default(),
                })
                .0
            {
                Response::List { rows } => rows
                    .into_iter()
                    .find(|r| r.title == title)
                    .map(|r| r.reff)
                    .expect("row present"),
                other => panic!("{other:?}"),
            }
        };
        let epic = by_title(&mut n.tracker, "epic");
        let child = by_title(&mut n.tracker, "child");
        let blocker = by_title(&mut n.tracker, "blocker");

        let (resp, dirty) = n.tracker.handle(Request::IssueParent {
            reff: child.clone(),
            parent: Some(epic.clone()),
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        assert!(dirty.is_some(), "a parent change rings a doorbell");

        let (resp, _) = n.tracker.handle(Request::IssueLink {
            reff: blocker.clone(),
            kind: "blocks".into(),
            target: child.clone(),
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

        let (resp, _) = n.tracker.handle(Request::IssueGraph {
            reff: child.clone(),
        });
        let g = match resp {
            Response::Graph(g) => g,
            other => panic!("{other:?}"),
        };
        assert_eq!(g.parent.as_ref().map(|r| r.title.as_str()), Some("epic"));
        assert_eq!(g.links.len(), 1);
        assert_eq!(g.links[0].kind, "blocks");
        assert_eq!(g.links[0].direction, "in");
        assert_eq!(
            g.blocked_by
                .iter()
                .map(|r| r.title.as_str())
                .collect::<Vec<_>>(),
            vec!["blocker"],
            "open blocker surfaces transitively"
        );

        // Finishing the blocker clears the blocked_by set (it is open-only)…
        let (resp, _) = n.tracker.handle(Request::IssueDone {
            reff: blocker.clone(),
        });
        assert!(matches!(resp, Response::Issue(_)), "{resp:?}");
        let (resp, _) = n.tracker.handle(Request::IssueGraph {
            reff: child.clone(),
        });
        let g = match resp {
            Response::Graph(g) => g,
            other => panic!("{other:?}"),
        };
        assert!(g.blocked_by.is_empty(), "{:?}", g.blocked_by);
        // …while the link itself remains until unlinked.
        assert_eq!(g.links.len(), 1);
        let (resp, _) = n.tracker.handle(Request::IssueUnlink {
            reff: blocker.clone(),
            kind: "blocks".into(),
            target: child.clone(),
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

        // Cycle guard: the epic cannot become its own descendant.
        let (resp, dirty) = n.tracker.handle(Request::IssueParent {
            reff: epic.clone(),
            parent: Some(child.clone()),
        });
        assert!(
            matches!(&resp, Response::Error { message, .. } if message.contains("ancestor")),
            "{resp:?}"
        );
        assert!(dirty.is_none(), "a rejected parent rings no doorbell");

        // Unparent restores a top-level issue.
        let (resp, _) = n.tracker.handle(Request::IssueParent {
            reff: child.clone(),
            parent: None,
        });
        assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
        let (resp, _) = n.tracker.handle(Request::IssueGraph { reff: child });
        match resp {
            Response::Graph(g) => assert!(g.parent.is_none()),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn signed_delete_syncs_agents_cannot_delete_and_restore_wins() {
        // CRAIT (contract §3.4) end to end through the real sync path:
        //  - a member's signed delete propagates to a peer (tombstone is a
        //    cache of the authz replay, reconciled on import),
        //  - a sponsored agent cannot delete (no content authority),
        //  - restore clears it, and the members log attributes everything.
        let mut a = new_node(); // founder/admin
        with_project(&mut a.tracker);
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let a_ws = a.tracker.workspace_str();
        let a_actor = a.tracker.my_actor().unwrap().to_string();
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &a_actor);
        let b_incept = b.tracker.self_inception().unwrap();
        let (resp, _) = a.tracker.admit_member(&b_incept, vec![Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        // B must sync to learn it is a member before it can act as one.
        sync_all(&mut a.tracker, &mut b.tracker);
        let b_actor = actor_of(&b_incept);
        assert!(
            b.tracker.acl_state().is_human_member(&b_actor),
            "B sees itself"
        );

        // B sponsors an agent (the agent self-incepted its degenerate actor).
        let agent_incept = incept_for([99u8; 32], &b.tracker);
        let agent_actor = actor_of(&agent_incept);
        let (resp, _) = b.tracker.agent_add(&agent_incept);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(b.tracker.acl_state().is_agent(&agent_actor));
        assert_eq!(
            b.tracker.acl_state().sponsor_of(&agent_actor),
            Some(&b_actor),
            "the agent's sponsor is B"
        );
        assert!(
            !b.tracker.acl_state().is_human_member(&agent_actor),
            "an agent is not a human member"
        );

        let reff = new_issue(&mut a.tracker, "delete me");
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut b.tracker, &mut a.tracker);

        // B (a human member) deletes; it must appear deleted on A after sync.
        let (resp, _) = b
            .tracker
            .handle(Request::IssueDelete { reff: reff.clone() });
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            b.tracker
                .authz_state()
                .is_tombstoned(&b.tracker.resolve_issue(&reff).unwrap()),
            "deleted locally on B"
        );
        sync_all(&mut b.tracker, &mut a.tracker);
        let a_id = a.tracker.resolve_issue(&reff).unwrap();
        assert!(
            a.tracker.catalog().row(&a_id).unwrap().tombstone,
            "a peer's signed delete reconciles into A's tombstone cache"
        );

        // Restore on A, sync back: restore clears it on B (restore-wins).
        let (resp, _) = a
            .tracker
            .handle(Request::IssueRestore { reff: reff.clone() });
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        let b_id = b.tracker.resolve_issue(&reff).unwrap();
        assert!(
            !b.tracker.catalog().row(&b_id).unwrap().tombstone,
            "the restore propagates and clears the tombstone on B"
        );

        // The members log is cryptographic provenance, in causal order.
        let log = match a.tracker.handle(Request::MemberLog).0 {
            Response::MemberLog { entries } => entries,
            other => panic!("{other:?}"),
        };
        assert!(
            log.iter().any(|e| e.kind == "add_member" && e.authorized),
            "the member-add is logged authorized: {log:?}"
        );
        assert!(
            log.iter().any(|e| e.kind == "add_agent" && e.authorized),
            "the agent sponsorship is logged authorized: {log:?}"
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

    /// The read contract the **web viewer** depends on, pinned so an engine change
    /// can't silently rot it.
    ///
    /// This exists because it already happened once. The engine moved per-issue
    /// history from a session ring onto the durable oplog, which changed how an
    /// `ActivityEvent` attributes: `actor` became the real per-op key and
    /// `actor_nick` went empty. The viewer read `actor_nick` for the display name,
    /// so every history row lost its author — and nothing caught it, because
    /// `tests/viewer_parity.rs` guards *Request field names*, never *Response
    /// semantics*. This is the missing half: a behavioral pin on the values the
    /// client reads. If one of these assertions fails, a viewer that depends on it
    /// (`viewer/src/core/activity.ts`) needs updating in the same change.
    #[test]
    fn history_is_the_contract_the_viewer_reads() {
        let mut n = new_node();
        with_project(&mut n.tracker);
        let reff = new_issue(&mut n.tracker, "fix login");
        n.tracker.handle(Request::IssueEdit {
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        });
        n.tracker.handle(Request::Comment {
            reff: reff.clone(),
            body: "on it".into(),
        });

        let (resp, _) = n.tracker.handle(Request::History { reff });
        let events = match resp {
            Response::Activity { events, .. } => events,
            other => panic!("History must reply Activity, got {other:?}"),
        };
        assert!(
            !events.is_empty(),
            "a created+edited+commented issue has history"
        );

        for e in &events {
            // 1. Attribution travels in `actor` (a key the client resolves), NOT in
            //    `actor_nick`. The viewer's describeEvent resolves `actor`; if this
            //    flips, it shows no name. This is the exact regression, pinned.
            assert!(
                !e.actor_nick.is_empty() || e.actor.is_some(),
                "event {:?} has neither actor nor actor_nick — viewer would show no author",
                e.kind
            );
            if let Some(actor) = &e.actor {
                assert_eq!(
                    actor.as_str().len(),
                    64,
                    "actor must be a full key the viewer can resolve to a member: {actor:?}"
                );
            }

            // 2. Durable history carries real timestamps (the viewer renders `when(ts)`).
            assert_ne!(
                e.ts, 0,
                "history event {:?} has ts 0 — not a durable op",
                e.kind
            );

            // 3. No synthetic `synced` in per-issue history. The viewer's
            //    synced->no-name special case is for the workspace Activity feed
            //    only; a `synced` here would make it drop a real author.
            assert_ne!(
                e.kind, "synced",
                "per-issue history must be real ops, not a synced marker"
            );
        }

        // 4. The states the viewer walks are present as real ops, each attributed.
        let created = events.iter().find(|e| e.kind == "created");
        assert!(created.is_some(), "history includes the `created` op");
        assert!(
            created.unwrap().actor.is_some(),
            "even `created` carries a resolvable actor — the viewer names it"
        );
    }
}
