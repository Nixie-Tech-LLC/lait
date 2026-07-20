//! The daemon's issue-tracking core — the bridge from Layer B (the control
//! façade, [`crate::control`]) to Layer A (the Loro docs, [`crate::catalog`] +
//! [`crate::issue`]) over the git-backed [`crate::store`]. Fully testable
//! in-process (no socket, no iroh, injected clock), which is where the SCHEMA and
//! control-plane invariants are exercised.
//!
//! **Validate then commit.** Every mutating request fully
//! resolves refs and validates *before* any Loro commit; on failure it returns
//! `Response::Error` having touched nothing and produced **no** dirty-set (so no
//! doorbell rings), which is what makes an optimistic client's rollback
//! race-free. There is no compare-and-swap token: failures occur before commit.
//!
//! **Writer-direction projection.** Every mutation ends by recomputing the issue's
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
    ActivityEvent, BoardColumn, BoardView, FieldChange, GraphView, IssueView, LabelDto, LinkDto,
    Priority, ProjectDto, Row, StatusCategory, SCHEMA_VERSION,
};
use crate::engine::history;
use crate::engine::op::OpCtx;
use crate::genesis::Genesis;
use crate::ids::{ActorId, DocId, LabelId, ProjectId, UlidSource, UserId, WorkspaceId};
use crate::index::{self, AliasTable, RefResolution};
use crate::issue::{IssueDoc, NewIssue};
use crate::membership::MembershipDoc;
use crate::store::Store;

/// Issue-link kinds accepted by the control interface. `relates` is
/// symmetric and canonicalized (sorted endpoints) so one edge represents it.
pub const LINK_KINDS: [&str; 3] = ["blocks", "relates", "duplicates"];

/// A 16-byte content-addressed epoch id prefixed to every AEAD ciphertext so the
/// reader selects the right key from its keyring during lazy revocation.
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

/// The batched, project-keyed dirty set produced by a mutation. The
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
    /// a whole sync-import transaction becomes one frame.
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

/// The three work-state intents: `start`, `done`, and `stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WorkAction {
    Start,
    Done,
    Stop,
}

/// One issue document a puller must fetch during catalog-first sync: the
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
    // ---- workspace encryption ----
    /// The plaintext membership layer (signed ACL + sealed key envelopes).
    membership: MembershipDoc,
    /// The genesis trust root: workspace ID and founding administrator keys.
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
/// creates the catalog carrying the display `name`, seals the epoch-0
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
    // Self-certifying workspace id (lait/space/1): derive it from the founding
    // device + a random salt so the id commits to its trust root. The salt is
    // chosen BEFORE the founding actor is incepted — an inception is scoped to a
    // workspace id, so the id cannot itself depend on the inception. Derive from
    // the SEED's public key (the inception's author), so the id commits to
    // exactly the key that signs the founding inception.
    let founding_device = crypto::user_from_seed(device_seed);
    let salt = rand16();
    // Mint the workspace's break-glass recovery key (a solo bootstrap key the
    // founder holds — later elevated to a FROST group key via Rotate) and fold its
    // commitment into the id, so root recovery is authorized offline against a
    // value bound at birth, never a compromised current admin (lait/space/1 W5).
    let (recovery_pub, recovery_secret) = crate::space::mint_recovery_key();
    let recovery_root = crate::space::recovery_commit(&recovery_pub).expect("valid recovery key");
    let ws = crate::space::derive_workspace_id(&founding_device, &salt, &recovery_root);
    persist_space_recovery(store, &recovery_secret)?;
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
        salt,
        recovery_root,
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
    let recovery_pub = crypto::user_from_seed(&seed);
    let commit = actor::recovery_commitment(&recovery_pub).expect("valid recovery pubkey");
    (commit, seed)
}

/// Persist the recovery secret beside the store. This is a root credential (the
/// pre-rotation escrow — losing it forfeits recovery, never workspace access),
/// so it is created **owner-only from the start** (never world-readable, even
/// for an instant) and any permission error is propagated, never swallowed.
/// The state of a device-local ceremony artifact.
///
/// Three states, not two: an artifact that is present but unreadable is neither
/// usable nor absent, and reporting it as absent would hide the loss of a
/// holder's recovery capability.
///
/// `Unreadable` keeps the **typed** cause rather than a rendered string. An
/// access-denied error, a corrupt file or a transient I/O fault must not be
/// diagnosed as "this belongs to another Windows account": that is one specific
/// cause among several, and guessing it sends an operator to the wrong remedy.
#[derive(Debug)]
pub enum ArtifactRead {
    Missing,
    Present(Vec<u8>),
    Unreadable(crate::secretfs::SecretError),
}

/// Why a recovery artifact could not be produced, for structured reporting.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum RecoveryArtifactFailure {
    /// Wrapped for a different Windows account or machine. The bytes are intact;
    /// this identity cannot open them.
    Undecryptable(String),
    /// Present but could not be read at all — permissions, corruption, I/O.
    Io(String),
}

/// Argon2 cost for a share package's passphrase slot.
///
/// Production always pays the real cost. Tests would otherwise spend minutes in
/// a debug-build KDF across many exports, and a slow suite is a suite that stops
/// being run — but the weak parameters must never be reachable from a release
/// binary, hence `cfg(test)` rather than a caller-supplied value.
#[cfg(not(test))]
fn custody_kdf_params() -> crate::custody::Argon2Params {
    crate::custody::Argon2Params::default()
}
#[cfg(test)]
fn custody_kdf_params() -> crate::custody::Argon2Params {
    crate::custody::Argon2Params {
        m_cost_kib: 64,
        t_cost: 1,
        p_cost: 1,
    }
}

/// What this device can say about recovery readiness.
///
/// Deliberately does NOT assert that recovery is possible. This node knows its
/// own custody and the arrangement's shape; it does not know whether other
/// holders still have their shares, and claiming they do would be the most
/// dangerous kind of reassurance — believed, unverifiable, and only disproved
/// during an actual emergency.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RecoveryStatus {
    /// Short form of the standing authority's key, or `None` when this device
    /// cannot attribute the standing key to any arrangement it has seen.
    pub authority: Option<String>,
    pub scheme: crate::authority::AuthorityScheme,
    /// Phase B reports the shape. Phase D will report policy branches and
    /// qualified-set readiness instead.
    pub k: u16,
    pub n: u16,
    pub local_custody: LocalCustodyState,
}

/// This device's standing as a custodian.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "state", content = "detail", rename_all = "snake_case")]
pub enum LocalCustodyState {
    /// Not a holder — nothing is expected of this device.
    NotAHolder,
    /// Holding usable material.
    Ready,
    /// Expected to hold a share and does not.
    Missing,
    /// The share is present but cannot be produced.
    Unreadable(RecoveryArtifactFailure),
    /// Holding a share of an **indispensable** arrangement with no verified
    /// portable backup. Distinct from `Ready` because the share is usable today
    /// and unrecoverable tomorrow, and that difference is invisible until it
    /// matters.
    BackupUnverified,
}

/// A holder whose share exists on this device but cannot be used.
///
/// Structured rather than preformatted, so status, diagnosis and the CLI can
/// each render it as they see fit.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DegradedRecoveryHolder {
    /// The DKG transcript whose share is unusable.
    pub transcript: String,
    pub reason: RecoveryArtifactFailure,
    /// `Some(true)` when this transcript IS the standing recovery authority,
    /// `None` when currency could not be established (the public-key package
    /// was itself unreadable).
    pub is_current_authority: Option<bool>,
}

fn persist_recovery_key(store: &Store, seed: &[u8; 32]) -> Result<()> {
    let home = store.home_path();
    // Tighten the parent dir to owner-only before writing the secret.
    crate::secretfs::create_private_dir(home)
        .context("restrict store home permissions for recovery.key")?;
    // Portable for the same reason as `space-recovery.key`: an actor-recovery
    // key is useless if it cannot be carried to the device doing the recovering.
    crate::secretfs::write_private(
        &home.join("recovery.key"),
        data_encoding::HEXLOWER.encode(seed).as_bytes(),
        crate::secretfs::Create::New,
        crate::secretfs::Wrap::Portable,
    )
    .context("write recovery.key")
}

/// Persist the workspace **break-glass recovery** secret beside the store as
/// `space-recovery.key` (owner-only, move it offline). A root credential, so it is
/// created owner-only from the start and errors propagate. Elevating to a K-of-N
/// group key later replaces this with per-holder DKG shares.
fn persist_space_recovery(store: &Store, secret: &[u8; 32]) -> Result<()> {
    let home = store.home_path();
    crate::secretfs::create_private_dir(home)
        .context("restrict store home permissions for space-recovery.key")?;
    // PORTABLE, deliberately. The operator is told to move this offline, so a
    // device-bound wrap would make the copy in the safe unopenable — losing the
    // workspace's last resort to protect it from a threat the file ACL already
    // covers.
    crate::secretfs::write_private(
        &home.join("space-recovery.key"),
        data_encoding::HEXLOWER.encode(secret).as_bytes(),
        crate::secretfs::Create::New,
        crate::secretfs::Wrap::Portable,
    )
    .context("write space-recovery.key")
}

/// Bootstrap a store from a join ticket: the `lait join` path.
/// Writes the ticket's genesis (the host is the founding admin whose signed ACL
/// the joiner validates against) and **empty** catalog/membership docs, so
/// importing the founder's ops adopts identical container ids (see
/// [`CatalogDoc::empty`] — `create()` would mint conflicting containers).
/// Errors if the store already holds a workspace; the CLI guarantees it doesn't.
pub fn join_workspace_store(
    store: &Store,
    workspace: &str,
    salt: &[u8; 16],
    recovery_root: &[u8; 32],
    founder_inception: &actor::SignedEvent,
) -> Result<WorkspaceId> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a workspace");
    }
    let ws_id = WorkspaceId::parse(workspace)
        .ok_or_else(|| anyhow!("invalid workspace id in ticket: {workspace}"))?;
    // Verify the trust root offline: the id must commit to the founder AND the
    // recovery set, and the founding inception must validly incept for THIS
    // workspace. A tampered anchor fails here rather than silently forking the
    // joiner (lait/space/1).
    let founder_actor =
        crate::space::verify_founding(&ws_id, salt, recovery_root, founder_inception)
            .context("verify workspace founding — ask for a fresh invite")?;
    let genesis = Genesis {
        workspace_id: ws_id.clone(),
        founding_actors: vec![founder_actor],
        salt: *salt,
        recovery_root: *recovery_root,
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&CatalogDoc::empty(Some(store.peer_id())))?;
    // Seed the verified founding inception so the actor plane roots correctly
    // from the first replay, before any sync. The seed is committed through
    // `apply` like every other write; `save_membership`
    // exports, and an export implicitly commits whatever is pending, so a bare
    // stage here would seal the joiner's trust root into an anonymous,
    // tier-less change. The actor claim is the inception's own author (the
    // founder's device): we are landing *their* signed event, not authoring one.
    let membership = MembershipDoc::empty(Some(store.peer_id()));
    membership.add_actor_event(founder_inception)?;
    membership.apply(&OpCtx::authority("join_seed", &founder_inception.author));
    store.save_membership(&membership)?;
    store.commit("join workspace from ticket");
    Ok(ws_id)
}

impl Tracker {
    /// Open the tracker over an **initialized** store — a missing catalog or
    /// genesis is an error, never a founding event (workspaces are born only in
    /// [`found_workspace`] / [`join_workspace_store`]). Performs the **load-time
    /// head recompute**: heads and rows are recomputed from the real
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
    /// addressed to our device. Lazy revocation retains older keys so
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
    /// - **No epochs exist at all** — a genuine keyless single-node workspace
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
    /// and simply imports nothing.
    fn decrypt_payload(&self, blob: &[u8]) -> Option<Vec<u8>> {
        let (id, ct) = split_epoch(blob)?;
        let key = self.keyring.get(&id)?;
        crypto::aead_decrypt(key, ct)
    }

    /// Load-time invariant: recompute every head and row from the real issue
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
    /// rings for a rejected write).
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
            Request::InviteRevoke { invite } => Ok(self.invite_revoke_cmd(invite)),
            Request::DeviceInvite => Ok(self.device_invite_cmd()),
            Request::DeviceAdd { consent } => Ok(self.device_add_cmd(consent)),
            Request::DeviceRevoke { device } => Ok(self.device_revoke_cmd(device)),
            Request::DeviceList => Ok((self.device_list_response(), None)),
            Request::Recover => Ok(self.recover()),
            Request::SpaceRecover => Ok(self.space_recover_cmd()),
            Request::SpaceElevate { cofounders, k } => Ok(self.space_elevate_cmd(cofounders, k)),
            Request::SpaceElevateApprove { session, proposal } => {
                Ok(self.space_elevate_approve_cmd(session, proposal))
            }
            Request::SpaceCustodyExport { path, passphrase } => {
                Ok(self.space_custody_export_cmd(path, passphrase))
            }
            Request::SpaceCustodyImport {
                path,
                passphrase,
                force,
            } => Ok(self.space_custody_import_cmd(path, passphrase, force)),
            Request::SpaceRecoverApprove { session, expect } => {
                Ok(self.space_recover_approve_cmd(session, expect))
            }
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
        // Labels resolve or create on first use, but the
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
                // Spliced into the RGA text. Bodies are too big
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
        // Entering a done-category status removes the issue from active boards.
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

    /// One `start`, `done`, or `stop` work-state transition: the fields a
    /// single human intent moves — status by workflow *category* plus the
    /// viewer's assignment, in one Loro commit and one activity row.
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
        // Entering a done-category status removes the issue from active boards.
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

        // Project membership is authoritative: write Issue.projectId first.
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
        // ceremony); removals still error on unknown (removing a
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
        // The comment is attributed to the *actor* (the person); the device that
        // landed it rides the change's `OpCtx` as the advisory commit stamp.
        let me = match self.my_actor() {
            Some(a) => a,
            None => return Ok((Response::err("this device has no actor identity"), None)),
        };
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
    /// Agents cannot delete; every deletion is attributable and
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
    /// encrypted authorization DAG against membership). Roots on the
    /// **effective** genesis for the same reason [`Self::acl_state`] does: after
    /// a break-glass `Recover`, content authority must follow the recovered
    /// admins, not the superseded birth root.
    fn authz_state(&self) -> authz::AuthzState {
        authz::replay(
            &self.effective_genesis(),
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
                continue; // Documents outside the authorization DAG keep their legacy flag.
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

    /// Add or remove an issue link in `edges`. `relates` is
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

    /// Set or clear an issue's parent in the sub-issue hierarchy. The `subs`
    /// tree-move CRDT prevents conflicting concurrent moves from converging to
    /// a cycle.
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

    /// Viewer-aware assignee summary: "you", "you +2", "ab", or "".
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
        // apply it against the locally loaded documents.
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

    /// Build the board, deduplicating its ordering projection:
    /// rows whose `projectId == P`, in `boards[P]` order, deduplicated,
    /// belonging-but-unlisted appended, listed-but-not-belonging ignored; the
    /// The done column uses append order sorted by descending wall-clock time.
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
                // Append matching rows in this done state, ordered
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
                // Provisional: only the catalog row is known until sync completes.
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
                    corrupt_records: Vec::new(),
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
        // The projection boundary: corruption leaves the typed path exactly
        // here, once, and travels to the caller in the sidecar instead of
        // hiding inside `comments`.
        let (comments, corrupt_records) = crate::dto::partition(issue.comments());
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
            corrupt_records,
        };
        Ok(Response::Issue(Box::new(view)))
    }

    /// The issue's history, derived from the **oplog on disk**:
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

    // ---- catalog-first peer sync; the network layer calls these ----
    // under the tracker lock; all QUIC IO happens outside the lock. ----

    /// The workspace id as a string (sync handshake guard).
    pub fn workspace_str(&self) -> String {
        self.workspace_id.to_string()
    }

    /// The catalog's oplog version vector, wire-encoded (sync handshake).
    pub fn catalog_vv_bytes(&self) -> Vec<u8> {
        self.catalog.oplog_vv_bytes()
    }

    /// The wire-form catalog head digest used in gossip announcements.
    pub fn catalog_head_bytes(&self) -> Vec<u8> {
        self.catalog.head_hash()
    }

    /// A combined sync head over catalog + membership (the gossip announce
    /// trigger). A membership-only change (e.g. `member add`, which doesn't touch
    /// the catalog) still moves this head so peers pull and receive it.
    pub fn sync_head_bytes(&self) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(&self.catalog.head_bytes());
        h.update(&self.membership.head_bytes());
        h.finalize().as_bytes().to_vec()
    }

    // ---- plaintext membership sync, separate from encrypted content sync ----

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
        // Propagate newly held keys to sibling devices that the rotating author
        // may not have seen.
        self.heal_member_device_envelopes()?;
        // Two admins removing different members concurrently can leave the active
        // epoch sealed to a since-removed actor after merge; re-seal to the true
        // current set (convergent, admin-only).
        self.heal_epoch()?;
        // After a break-glass re-root syncs in, the new root's epochs are all the
        // old (de-authorized) admin's — mint a fresh one so the recovered root has
        // a readable, fenced content key.
        self.bootstrap_root_epoch_if_needed()?;
        // Advance any FROST recovery-elevation ceremony this device is part of as
        // the peers' round packages arrive. Never fatal to import: ceremony work is
        // driven off peer-controlled data, so a bad package is logged and skipped.
        if let Err(e) = self.dkg_advance() {
            tracing::warn!("ceremony advance during import failed (skipped): {e:#}");
        }
        Ok(())
    }

    // ---- membership and authorization operations ----

    /// The genesis as seen *after* any break-glass recovery: `founding_actors` is
    /// the space plane's effective root (`lait/space/1`), not the immutable birth
    /// seed. With no recovery this is the birth genesis unchanged.
    fn effective_genesis(&self) -> Genesis {
        let root = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        Genesis {
            founding_actors: root.root,
            ..self.genesis.clone()
        }
    }

    /// The materialized ACL state (deterministic replay from the *effective* root
    /// over the actor plane and signed ACL operations (`lait/actor/1`). Seeding
    /// from the recovery-aware root is the one integration point of the space
    /// plane: after a threshold `Recover`, replay roots on the recovered admins.
    pub fn acl_state(&self) -> AclState {
        acl::replay(
            &self.effective_genesis(),
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
    /// The workspace's founding actor — the genesis trust root every replica
    /// must share. An invite ticket MUST carry THIS (not the inviter's own
    /// actor): a joiner roots `acl::replay` on the ticket's founder, so anchoring
    /// on anyone but the true founder forks the joiner onto a genesis where the
    /// real founder — and the founding key-epoch — hold no authority.
    pub fn founding_actor(&self) -> Option<ActorId> {
        self.genesis.founding_actors.first().cloned()
    }
    /// The verifiable founding proof to put in a ticket (`lait/space/1`): the
    /// `(salt, founder_inception)` a joiner checks the workspace id against. Any
    /// correctly-joined node holds both — the salt in genesis, the founder's
    /// inception in the membership actor log.
    pub fn founding_proof(&self) -> Option<([u8; 16], [u8; 32], actor::SignedEvent)> {
        let founder = self.genesis.founding_actors.first()?;
        let incept = self
            .membership
            .actor_events()
            .into_iter()
            .find(|ev| ActorId::from_incept_hash(&ev.hash()) == *founder)?;
        Some((self.genesis.salt, self.genesis.recovery_root, incept))
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
    /// Members (actor, grants, and `is_me`) for the members view. `is_me`
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

    /// Seal every key epoch we hold to **every device** of `actor`. Reaching one
    /// live device is
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
    /// Administrator-only. The target actor's inception must already be
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
        // Revocation kill switch: an admin-signed RevokeInvite voids this nonce
        // convergently — the only way to retire a leaked (esp. reusable) invite.
        if acl.is_invite_revoked(nonce) {
            return (Response::err("this invite has been revoked"), None);
        }
        // Single-use replay guard — read from the SIGNED ACL (an authorized
        // AddMember that spent this nonce), never an unsigned side container.
        // The convergent nonce dedup in replay is the real guarantee; this is the
        // fast-fail so we don't author a doomed op.
        if single_use && acl.is_nonce_spent(nonce) {
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
        let incept = joiner_incept.clone();
        let target = joiner_actor.clone();
        if let Err(e) = self.member_apply(op, "invite_redeem", |t| {
            // Import the joiner's identity, then seal every epoch to its devices.
            // The single-use nonce is recorded by the AddMember op itself (bound
            // above), so replay is the redemption record — no side container.
            t.membership.add_actor_event(&incept)?;
            Self::seal_epochs_to_actor(t, &target)?;
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
    /// using lazy revocation: a new epoch is sealed only to the remaining
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

    /// Revoke an outstanding invite (admin-only). Accepts the invite's 32-hex
    /// nonce or a full ticket to lift it from. Authors a signed
    /// [`AclAction::RevokeInvite`]; once it syncs, no admin admits via that nonce
    /// — the kill switch for a leaked (especially reusable) invite.
    pub fn invite_revoke_cmd(&mut self, invite: String) -> (Response, Option<DirtySet>) {
        if !self.am_i_admin() {
            return (Response::err("only an admin can revoke an invite"), None);
        }
        let Some(nonce) = Self::parse_invite_nonce(&invite) else {
            return (
                Response::err("not a valid invite — pass the ticket or its 32-hex nonce"),
                None,
            );
        };
        let op = match self.author_acl(AclAction::RevokeInvite { nonce }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        // Whether it was *already* spent decides what we can honestly promise.
        let already_spent = self.acl_state().is_nonce_spent(&nonce);
        if let Err(e) = self.member_apply(op, "invite_revoke", |_| Ok(())) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Never claim the invite was undone. A redemption that causally precedes
        // this revoke stands (it was legitimate); a concurrent one is evicted on
        // merge and the key rotates — but in both cases content already shared
        // stays readable by whoever was admitted. That is lazy revocation, and
        // no amount of re-keying closes it.
        // `spent_nonces` is grow-only, so a spent nonce says an admission
        // *happened* — not that the actor is still a member. They may have been
        // removed since. Point at the member list rather than asserting a seat.
        let message = if already_spent {
            "the invite had already been redeemed, so revoking it does not undo \
             that admission. Check the member list and remove the actor if they \
             should no longer have access."
        } else {
            "revoked the invite — it admits no one from here on. If it was \
             redeemed elsewhere before this synced, that member is removed and \
             the key rotates on merge, but content shared before then stays \
             readable by them."
        };
        (
            Response::Ok {
                message: Some(message.into()),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Extract an invite nonce from either a full ticket (via its signed invite)
    /// or a raw 32-hex string.
    fn parse_invite_nonce(input: &str) -> Option<[u8; 16]> {
        let s = input.trim();
        if let Ok(ticket) = s.parse::<crate::proto::WorkspaceTicket>() {
            // A ticket only carries a nonce if it embeds a signed invite.
            let (_pk, grant) = ticket.invite?.verify().ok()?;
            return Some(grant.nonce);
        }
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Load the workspace break-glass recovery seed held beside the store (the
    /// solo bootstrap key). `None` once elevated to a group key held as DKG shares.
    fn read_space_recovery_key(&self) -> Option<[u8; 32]> {
        let path = self.store.home_path().join("space-recovery.key");
        let bytes = crate::secretfs::read_private(&path).ok().flatten()?;
        let hex = String::from_utf8(bytes).ok()?;
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Break-glass **workspace recovery** (lait/space/1 W5). Authors a signed
    /// `Recover` with the workspace recovery key, re-rooting the space to THIS
    /// device and re-keying to fence the old root. For a solo bootstrap key the
    /// held secret signs directly; a K-of-N group key instead produces the group
    /// signature via a FROST ceremony and assembles the same event (the plane
    /// verifies one signature either way — the threshold is invisible here).
    ///
    /// The private `bootstrap_root_epoch_if_needed` helper performs the re-key.
    pub fn space_recover_cmd(&mut self) -> (Response, Option<DirtySet>) {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        // Solo path: a held recovery key that IS the current authority signs the
        // Recover directly.
        if let Some(secret) = self.read_space_recovery_key() {
            let held = crate::space::recovery_commit(&crate::space::recovery_pub_of(&secret));
            if held == Some(cur.recovery_commit) {
                return self.space_recover_solo(&cur, &secret);
            }
        }
        // Group path: this device holds a threshold share of the current group
        // recovery key — open (or drive) a FROST signing ceremony that produces
        // the Recover group signature. The plane verifies one signature either
        // way; the threshold is invisible to it.
        if self.active_dkg_session().is_some() {
            return self.space_recover_group(&cur);
        }
        // Distinguish "this device never held a share" from "the share is right
        // here and cannot be opened". Collapsing those would send a holder to
        // look elsewhere for material sitting on the disk in front of them.
        let degraded = self.degraded_recovery_holders();
        if !degraded.is_empty() {
            let detail = degraded
                .iter()
                .map(|h| {
                    // The cause decides the remedy, so it must not be guessed:
                    // an I/O or permissions fault is not an account mismatch.
                    let why = match &h.reason {
                        RecoveryArtifactFailure::Undecryptable(m) => {
                            format!("protected under another Windows account or machine ({m})")
                        }
                        RecoveryArtifactFailure::Io(m) => {
                            format!("present but could not be read ({m})")
                        }
                    };
                    let scope = match h.is_current_authority {
                        Some(true) => "the current recovery key",
                        // Unproven currency is reported as such rather than
                        // asserted either way.
                        None => "a recovery key whose group could not be identified",
                        Some(false) => unreachable!("superseded groups are filtered out"),
                    };
                    format!("  transcript {}: {scope} — {why}", h.transcript)
                })
                .collect::<Vec<_>>()
                .join("\n");
            return (
                Response::err(format!(
                    "this device holds a FROST share that cannot be used:\n{detail}\n\
                     This device cannot take part in recovery. Recovery remains \
                     possible only if the configured authority requirements can \
                     still be satisfied by the other holders, which this device \
                     cannot verify."
                )),
                None,
            );
        }
        (
            Response::err(
                "no way to recover from this device — need either the workspace's current space-recovery.key beside the store, or a threshold share of the current group recovery key",
            ),
            None,
        )
    }

    fn space_recover_solo(
        &mut self,
        cur: &crate::space::RootState,
        secret: &[u8; 32],
    ) -> (Response, Option<DirtySet>) {
        // Re-root to this device's actor (self-incept if needed).
        let me_actor = match self.self_inception() {
            Ok(ev) => ActorId::from_incept_hash(&ev.hash()),
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let ev = crate::space::sign_op(secret, &op, vec![], &self.workspace_id);
        let res = (|| -> Result<()> {
            self.membership.add_space_event(&ev)?;
            self.persist_membership("space_recover")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        // The new root bootstraps a fresh content key (fencing the old root).
        if let Err(e) = self.bootstrap_root_epoch_if_needed() {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "recovered the workspace — root reset to {} and re-keyed",
                    me_actor.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// The signing transcript holders should converge on for one
    /// `(authority, target, op)` request, if any is already open.
    ///
    /// Content-derived transcript ids make concurrency visible: two holders
    /// independently requesting the same recovery author different nodes and so
    /// open different transcripts, and commitments split across both. The rule
    /// is **prefer the lowest id** — deterministic, no coordinator.
    ///
    /// It is a *preference*, not an override, because correctness never depended
    /// on it: both transcripts sign `Recover { gen: cur.gen + 1 }`, and whichever
    /// installs first advances the generation, so the space plane's monotonicity
    /// guard rejects the loser. A split therefore costs liveness only. Strictly
    /// preferring the lowest id would abandon a transcript that is one share from
    /// completing in favour of one that may never gather K — the wrong trade for
    /// break-glass — so a transcript that has already reached threshold wins.
    fn canonical_signing_session(
        &self,
        board: &crate::dkg::CeremonyBoard,
        authority: &crate::dkg::TranscriptId,
        target: crate::dkg::SignTarget,
        op_bytes: &[u8],
        threshold: u16,
    ) -> Option<crate::dkg::TranscriptId> {
        let mut matching: Vec<(&crate::dkg::TranscriptId, &crate::dkg::SignTranscript)> = board
            .signing
            .iter()
            .filter(|(_, t)| {
                t.request.as_ref().is_some_and(|r| match &r.op {
                    crate::dkg::CeremonyOp::SignRequest {
                        authority: a,
                        target: g,
                        op,
                        ..
                    } => a == authority && *g == target && op.as_slice() == op_bytes,
                    _ => false,
                })
            })
            .collect();
        if matching.is_empty() {
            return None;
        }
        // A transcript already at threshold is one aggregation away; take it.
        let complete = matching.iter().find(|(_, t)| {
            t.rounds
                .iter()
                .filter(|v| matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. }))
                .count()
                >= threshold as usize
        });
        if let Some((id, _)) = complete {
            return Some(**id);
        }
        matching.sort_by_key(|(id, _)| **id);
        Some(*matching[0].0)
    }

    /// Break-glass recovery under a K-of-N group key: post a signing request for a
    /// Recover re-rooting to this device (joining one already open for this gen),
    /// then drive the ceremony as far as this device can. Holders converge on the
    /// group signature and any of them installs it; idempotent across re-runs.
    fn space_recover_group(
        &mut self,
        cur: &crate::space::RootState,
    ) -> (Response, Option<DirtySet>) {
        let me_actor = match self.self_inception() {
            Ok(ev) => ActorId::from_incept_hash(&ev.hash()),
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let Some(authority) = self.active_dkg_session() else {
            return (
                Response::err("this device holds no share of the current group recovery key"),
                None,
            );
        };
        let op = crate::space::SpaceOp::Recover {
            new_root: vec![me_actor.clone()],
            gen: cur.gen + 1,
        };
        let op_bytes = match postcard::to_stdvec(&op) {
            Ok(b) => b,
            Err(e) => return (Response::err(format!("encode recover op: {e}")), None),
        };
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        // Join the transcript holders converge on, or open one.
        let existing = self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            threshold,
        );
        let signing = match existing {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::SpaceOp,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let Some(id) = crate::dkg::TranscriptId::of(&ev) else {
                    return (Response::err("could not derive the request id"), None);
                };
                if let Err(e) = self
                    .membership
                    .add_ceremony_event(&ev)
                    .and_then(|()| self.persist_membership("sign_request"))
                {
                    return (Response::err(format!("{e:#}")), None);
                }
                id
            }
        };
        // Record LOCAL intent for this transcript's op so our node co-signs this
        // recovery (the consent gate in `sign_advance_session`).
        if let Err(e) = self.dkg_write(&signing, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        let after = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let installed = after.gen > cur.gen && after.root == vec![me_actor.clone()];
        let message = if installed {
            format!(
                "recovered the workspace — root reset to {} and re-keyed",
                me_actor.short()
            )
        } else {
            format!(
                "group recovery under way (session {}) — each other holder must approve it with `space recover-approve {}` until the threshold co-signs",
                signing.to_hex(),
                signing.to_hex(),
            )
        };
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Co-sign a pending break-glass recovery request as a holder of the current
    /// group key. This is the explicit consent that `sign_advance_session` demands:
    /// the holder has verified out-of-band that `session` re-roots the workspace to
    /// the agreed party, and records local intent so their share is contributed to
    /// exactly that op (and no other request on the board).
    pub fn space_recover_approve_cmd(
        &mut self,
        session_hex: String,
        expect: Vec<String>,
    ) -> (Response, Option<DirtySet>) {
        // Strict parse: a session id names a filesystem artifact, so a
        // permissive decode would let two spellings name one transcript.
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return (
                Response::err("not a valid recovery session id (64 lowercase hex chars)"),
                None,
            );
        };
        if self.active_dkg_session().is_none() {
            return (
                Response::err("this device holds no share of the current group recovery key — nothing to co-sign"),
                None,
            );
        }
        // The holder MUST state which actor(s) they expect this recovery to re-root
        // to, so consent binds to the roots — not to an opaque session id whose
        // request could re-root anywhere. Resolve them up front.
        if expect.is_empty() {
            return (
                Response::err(
                    "name the actor(s) you expect this recovery to re-root to (`--to <actor>`); refusing to co-sign a session blind",
                ),
                None,
            );
        }
        let mut expected: Vec<ActorId> = Vec::with_capacity(expect.len());
        for who in &expect {
            let Some(a) = self.resolve_actor(who) else {
                return (
                    Response::not_found(format!(
                        "no known actor matches '{who}' — sync the recovering device's identity first"
                    )),
                    None,
                );
            };
            expected.push(a);
        }
        expected.sort();
        expected.dedup();
        // The exact op the request asks the group to sign, taken from the
        // VERIFIED board and from the transcript the id names — not from the
        // first raw decode that happens to match.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let request = board.signing.get(&session).and_then(|t| t.request.as_ref());
        let Some((op_bytes, req_target)) = request.and_then(|r| match &r.op {
            crate::dkg::CeremonyOp::SignRequest { op, target, .. } => Some((op.clone(), *target)),
            _ => None,
        }) else {
            return (
                Response::err(
                    "no pending recovery request for that session (sync from the initiator first)",
                ),
                None,
            );
        };
        // A recovery approval consents to a SPACE op. Refuse to lend consent to
        // a request aimed at any other plane — approving a ceremony proposal is
        // a different decision and must not ride this command.
        if req_target != crate::dkg::SignTarget::SpaceOp {
            return (
                Response::err(
                    "that request is not a workspace-recovery request — refusing to co-sign",
                ),
                None,
            );
        }
        // It must be a Recover for the next generation re-rooting to EXACTLY the
        // actor set the holder named — refuse to co-sign anything else.
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let target = match postcard::from_bytes::<crate::space::SpaceOp>(&op_bytes) {
            Ok(crate::space::SpaceOp::Recover { new_root, gen })
                if gen == cur.gen + 1 && !new_root.is_empty() =>
            {
                new_root
            }
            _ => {
                return (
                    Response::err(
                        "that request is not a current-generation Recover — refusing to co-sign",
                    ),
                    None,
                );
            }
        };
        let mut got = target.clone();
        got.sort();
        got.dedup();
        if got != expected {
            let roots = target
                .iter()
                .map(|a| a.short())
                .collect::<Vec<_>>()
                .join(", ");
            return (
                Response::err(format!(
                    "that request re-roots to {roots}, not the actor(s) you named — refusing to co-sign"
                )),
                None,
            );
        }
        if let Err(e) = self.dkg_write(&session, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        let roots = target
            .iter()
            .map(|a| a.short())
            .collect::<Vec<_>>()
            .join(", ");
        (
            Response::Ok {
                message: Some(format!(
                    "co-signed the recovery re-rooting the workspace to {roots} — it installs once the threshold has co-signed"
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// After a re-root the old admin's epochs are de-authorized, so the new root
    /// has no readable active epoch — mint a fresh one (idempotent: a no-op unless
    /// we are an admin holding no authorized active epoch). Fires here and on
    /// import, so whichever node completes the threshold re-keys.
    fn bootstrap_root_epoch_if_needed(&mut self) -> Result<()> {
        if self.am_i_admin() && self.active_epoch().is_none() {
            self.rotate_key()?;
            self.persist_membership("recover_bootstrap_epoch")?;
        }
        Ok(())
    }

    // ---- FROST recovery elevation (solo key → K-of-N DKG group key) ----

    /// Path of a ceremony artifact. The transcript component is always
    /// [`TranscriptId::to_hex`] — canonical lowercase hex, validated when the id
    /// was constructed — so no remote-derived string ever reaches the filesystem
    /// and two spellings can never name one artifact.
    ///
    /// [`TranscriptId::to_hex`]: crate::dkg::TranscriptId::to_hex
    fn dkg_path(&self, t: &crate::dkg::TranscriptId, label: &str) -> std::path::PathBuf {
        self.store
            .home_path()
            .join("dkg")
            .join(format!("{}-{label}", t.to_hex()))
    }
    fn dkg_has(&self, t: &crate::dkg::TranscriptId, label: &str) -> bool {
        self.dkg_path(t, label).exists()
    }
    /// The state of a ceremony artifact on this device.
    ///
    /// `Unreadable` must never be flattened into `Missing`. A share protected
    /// under a different Windows account or machine is *present* — the holder
    /// exists but cannot act — and for an N-of-N group that is the difference
    /// between a degraded holder and an unrecoverable workspace. Operators need
    /// to see which one they have.
    fn dkg_artifact(&self, t: &crate::dkg::TranscriptId, label: &str) -> ArtifactRead {
        match crate::secretfs::read_private(&self.dkg_path(t, label)) {
            Ok(Some(v)) => ArtifactRead::Present(v),
            Ok(None) => ArtifactRead::Missing,
            Err(e) => {
                tracing::error!(
                    "ceremony artifact {label} for transcript {} is present but unreadable: {e}",
                    t.to_hex()
                );
                ArtifactRead::Unreadable(e)
            }
        }
    }

    /// The bytes of a ceremony artifact, or `None` if it is absent **or**
    /// unreadable. Callers that must distinguish those — anything reporting to
    /// an operator — use [`Self::dkg_artifact`] instead.
    fn dkg_read(&self, t: &crate::dkg::TranscriptId, label: &str) -> Option<Vec<u8>> {
        match self.dkg_artifact(t, label) {
            ArtifactRead::Present(v) => Some(v),
            _ => None,
        }
    }

    /// Holders on this device whose share exists but cannot be used, restricted
    /// to transcripts that are — or might be — the workspace's **current**
    /// recovery authority.
    ///
    /// The currency check matters: an unreadable share from a superseded group
    /// is not a recovery problem, so announcing "this device has a share for the
    /// workspace recovery key" on its account would be false. Candidates are
    /// filtered through: public-key package, derived group key, recovery commit,
    /// standing RootState.
    ///
    /// A transcript whose package cannot be read yields `is_current_authority`
    /// of `None` and is still reported: we cannot prove it is live, but nor can
    /// we rule it out, and dropping the one artifact an operator needs to hear
    /// about would be the worse error.
    pub fn degraded_recovery_holders(&self) -> Vec<DegradedRecoveryHolder> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        board
            .dkg
            .keys()
            .filter_map(|id| {
                let reason = match self.dkg_artifact(id, "share") {
                    ArtifactRead::Unreadable(crate::secretfs::SecretError::Undecryptable(m)) => {
                        RecoveryArtifactFailure::Undecryptable(m)
                    }
                    ArtifactRead::Unreadable(crate::secretfs::SecretError::Io(e)) => {
                        RecoveryArtifactFailure::Io(e.to_string())
                    }
                    _ => return None,
                };
                // Currency is DERIVED from the public-key package, never trusted
                // from a file naming the group key.
                let is_current_authority = match self.dkg_artifact(id, "pkp") {
                    ArtifactRead::Present(pkp) => Some(
                        crate::dkg::group_key_of_package(&pkp)
                            .ok()
                            .and_then(|g| crate::space::recovery_commit(&g))
                            == Some(cur.recovery_commit),
                    ),
                    _ => None,
                };
                // A share we can PROVE belongs to a superseded group is not a
                // recovery problem: it could not recover this workspace even if
                // it were readable, so reporting it would be false.
                if is_current_authority == Some(false) {
                    return None;
                }
                Some(DegradedRecoveryHolder {
                    transcript: id.to_hex(),
                    reason,
                    is_current_authority,
                })
            })
            .collect()
    }
    /// Write a ceremony artifact owner-only. Device-bound: shares, round secrets
    /// and nonces belong to this holder on this machine and are never carried
    /// elsewhere, unlike the break-glass keys (see [`crate::secretfs::Wrap`]).
    fn dkg_write(&self, t: &crate::dkg::TranscriptId, label: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::DeviceBound,
        )
        .context("write dkg artifact")
    }
    /// Write a ceremony artifact owner-only but **portable** - no device
    /// binding. For public material that must stay legible after a store is
    /// restored onto another account (see [`crate::secretfs::Wrap::Portable`]).
    fn dkg_write_portable(
        &self,
        t: &crate::dkg::TranscriptId,
        label: &str,
        bytes: &[u8],
    ) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::Portable,
        )
        .context("write portable dkg artifact")
    }

    /// Write a ceremony artifact that must not already exist. For single-use
    /// material (signing nonces): an existing record has to be *examined* — it
    /// may already be bound to a signing package — never silently replaced.
    fn dkg_write_new(&self, t: &crate::dkg::TranscriptId, label: &str, bytes: &[u8]) -> Result<()> {
        let dir = self.store.home_path().join("dkg");
        crate::secretfs::create_private_dir(&dir).context("create dkg dir")?;
        crate::secretfs::write_private(
            &self.dkg_path(t, label),
            bytes,
            crate::secretfs::Create::New,
            crate::secretfs::Wrap::DeviceBound,
        )
        .context("write single-use dkg artifact")
    }

    /// Begin elevating the recovery authority to a `k`-of-N FROST group key over
    /// `cofounders` (their device keys) + this device. Only the holder of the
    /// current recovery key may elevate (they install the result). Posts the DKG
    /// proposal and this node's first round, then the ceremony advances on sync.
    pub fn space_elevate_cmd(
        &mut self,
        cofounders: Vec<String>,
        k: u16,
    ) -> (Response, Option<DirtySet>) {
        // Must hold the current recovery key to install the resulting Rotate.
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let holds_solo = self
            .read_space_recovery_key()
            .and_then(|s| crate::space::recovery_commit(&crate::space::recovery_pub_of(&s)))
            == Some(cur.recovery_commit);
        // Group→group reconfiguration: we hold a share of the standing group, so
        // we can OPEN the grant request even though we cannot sign it alone.
        let holds_share = self.active_dkg_session().is_some();
        if !holds_solo && !holds_share {
            return (
                Response::err(
                    "only the current recovery authority can elevate: run this where space-recovery.key lives, or on a device holding a share of the current group key",
                ),
                None,
            );
        }
        // Assemble the sorted participant set (co-founders + me). Sorted and
        // deduped here AND re-checked by every acceptor: a hostile proposer must
        // not be able to hand honest nodes a malformed participant list.
        let mut set: std::collections::BTreeSet<UserId> = std::collections::BTreeSet::new();
        for c in cofounders {
            match UserId::parse(&c) {
                Some(u) => {
                    set.insert(u);
                }
                None => {
                    return (
                        Response::err(format!("'{c}' is not a device key (64 hex chars)")),
                        None,
                    )
                }
            }
        }
        set.insert(self.me.clone());
        let participants: Vec<UserId> = set.into_iter().collect();
        let n = participants.len() as u16;
        // k == 0 means "all holders" (N-of-N) — the safe default.
        let k = if k == 0 { n } else { k };
        if !(1..=n).contains(&k) || n < 2 {
            return (
                Response::err("elevation needs ≥2 participants and threshold in 1..=N"),
                None,
            );
        }
        if !self.rotation_can_complete(&participants) {
            return (
                Response::err(
                    "too few of the current holders are in the proposed arrangement: installing the result needs the current group to sign the rotation, and only a participant of the new ceremony can derive the key it installs. Include at least the current threshold of existing holders.",
                ),
                None,
            );
        }
        // Sign the proposal FIRST: its id is the hash of the signed node, so it
        // does not exist until now. `nonce` keeps two identical elevations by
        // the same initiator from colliding — Ed25519 signing is deterministic,
        // so without it the same (n, k, participants) would hash identically.
        let Some(current) = self.current_authority() else {
            return (
                Response::err(
                    "cannot determine the arrangement operating the current recovery key — sync the ceremony that produced it first",
                ),
                None,
            );
        };
        let principals: Vec<crate::authority::PrincipalId> = participants
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
        let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
            rand16(),
            k,
            principals,
            current,
        ));
        let _ = n;
        let ev = crate::dkg::sign_ceremony(&self.seed, &propose, &self.workspace_id);
        let Some(transcript) = crate::dkg::TranscriptId::of(&ev) else {
            return (Response::err("could not derive the proposal id"), None);
        };
        // Local consent record for the ceremony itself, keyed by the transcript
        // it consents to. Written before posting so a crash leaves an orphan
        // marker (harmless) rather than a proposal nobody will install.
        if let Err(e) = self.dkg_write(&transcript, "intent", transcript.to_hex().as_bytes()) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self
            .membership
            .add_ceremony_event(&ev)
            .and_then(|()| self.persist_membership("dkg_propose"))
        {
            return (Response::err(format!("{e:#}")), None);
        }

        // Authorization. The device signature on the proposal proves only
        // control of a device; what every participant checks is a grant from the
        // standing authority. How that grant is produced is the ONLY thing that
        // differs between a solo and a group authority — the grant object itself
        // is identical either way, which is what B1 bought.
        let message = if holds_solo {
            let Some(secret) = self.read_space_recovery_key() else {
                return (
                    Response::err("recovery key disappeared mid-elevation"),
                    None,
                );
            };
            let grant = crate::dkg::sign_authority_grant(&secret, &self.workspace_id, &transcript);
            let auth_ev = crate::dkg::sign_ceremony(
                &self.seed,
                &crate::dkg::CeremonyOp::DkgAuthorize(grant),
                &self.workspace_id,
            );
            if let Err(e) = self
                .membership
                .add_ceremony_event(&auth_ev)
                .and_then(|()| self.persist_membership("dkg_authorize"))
            {
                return (Response::err(format!("{e:#}")), None);
            }
            format!(
                "started {k}-of-{n} recovery elevation — the DKG completes automatically as the co-founders' nodes sync; the group key installs once every share is in"
            )
        } else {
            // The standing authority is a group, so the grant needs a threshold
            // signature. Open a signing request for it; the other holders consent
            // with `space elevate-approve`, and the aggregate lands as the grant.
            match self.open_grant_request(&transcript).map(|(id, _)| id) {
                Ok(signing) => format!(
                    "proposed a {k}-of-{n} recovery arrangement (proposal {}) — the current group must authorize it: each holder runs `space elevate-approve {} --proposal {}`",
                    transcript.to_hex(),
                    signing.to_hex(),
                    transcript.to_hex(),
                ),
                Err(e) => return (Response::err(format!("{e:#}")), None),
            }
        };
        let _ = self.dkg_advance();
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Open (or join) a threshold-signing transcript asking the standing group to
    /// authorize `proposal`, and record our own consent to it.
    ///
    /// The request carries the grant bytes verbatim as its op, so what the group
    /// signs is exactly the object `authority_grant_of` will later verify — the
    /// signing path never constructs the payload a second way.
    fn open_grant_request(
        &mut self,
        proposal: &crate::dkg::TranscriptId,
    ) -> Result<(crate::dkg::TranscriptId, bool)> {
        let authority = self
            .active_dkg_session()
            .ok_or_else(|| anyhow!("this device holds no share of the current group key"))?;
        let group_key = self
            .group_key_of_transcript(&authority)
            .ok_or_else(|| anyhow!("cannot derive the current group key"))?;
        let (op_bytes, _payload) =
            crate::dkg::authority_grant_payload(&self.workspace_id, &group_key, proposal);
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        let mut changed = false;
        let signing = match self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::AuthorityGrant,
            &op_bytes,
            threshold,
        ) {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::AuthorityGrant,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.membership.add_ceremony_event(&ev)?;
                self.persist_membership("grant_request")?;
                changed = true;
                id
            }
        };
        if self.dkg_read(&signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            self.dkg_write(&signing, "intent", &op_bytes)?;
            changed = true;
        }
        Ok((signing, changed))
    }

    /// Co-sign a pending authority-grant request as a holder of the current
    /// group key.
    ///
    /// Consent binds to the **proposal**, not to an opaque session id: the caller
    /// must name the proposal they believe is being authorized, and the request
    /// must actually be for that one. Approving a session blind would mean
    /// lending a share to whatever configuration happened to be proposed —
    /// including one that hands the next authority to someone else.
    pub fn space_elevate_approve_cmd(
        &mut self,
        session_hex: String,
        expect_proposal: String,
    ) -> (Response, Option<DirtySet>) {
        let Some(session) = crate::dkg::TranscriptId::parse_hex(session_hex.trim()) else {
            return (
                Response::err("not a valid request id (64 lowercase hex chars)"),
                None,
            );
        };
        let Some(expected) = crate::dkg::TranscriptId::parse_hex(expect_proposal.trim()) else {
            return (
                Response::err(
                    "name the proposal you expect this to authorize (`--proposal <64-hex>`)",
                ),
                None,
            );
        };
        if self.active_dkg_session().is_none() {
            return (
                Response::err(
                    "this device holds no share of the current group key — nothing to co-sign",
                ),
                None,
            );
        }
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let Some((op_bytes, target)) = board
            .signing
            .get(&session)
            .and_then(|t| t.request.as_ref())
            .and_then(|r| match &r.op {
                crate::dkg::CeremonyOp::SignRequest { op, target, .. } => {
                    Some((op.clone(), *target))
                }
                _ => None,
            })
        else {
            return (
                Response::err("no pending request for that id (sync from the initiator first)"),
                None,
            );
        };
        if target != crate::dkg::SignTarget::AuthorityGrant {
            return (
                Response::err("that request is not an authority grant — refusing to co-sign"),
                None,
            );
        }
        let Ok(grant) = postcard::from_bytes::<crate::dkg::AuthorityGrant>(&op_bytes) else {
            return (
                Response::err("that request does not carry a well-formed grant"),
                None,
            );
        };
        if grant.proposal != expected {
            return (
                Response::err(format!(
                    "that request authorizes proposal {}, not the one you named — refusing to co-sign",
                    grant.proposal.to_hex()
                )),
                None,
            );
        }
        // The proposal must be one we can see and would accept on its own terms:
        // well formed, a transition we implement, and replacing the authority
        // actually standing. Otherwise a holder could be talked into authorizing
        // a ceremony that is unusable or aimed at the wrong authority.
        let Some(proposal) = board
            .dkg
            .get(&expected)
            .and_then(|t| t.proposal.as_ref())
            .and_then(|v| match &v.op {
                crate::dkg::CeremonyOp::DkgPropose(p) => Some(p.clone()),
                _ => None,
            })
        else {
            return (
                Response::err("that proposal has not synced here yet — sync and retry"),
                None,
            );
        };
        let Some(cfg) = proposal.frost_config() else {
            return (
                Response::err("that proposal is malformed or uses an unsupported transition"),
                None,
            );
        };
        if !self.claims_the_standing_authority(proposal.current_authority()) {
            return (
                Response::err(
                    "that proposal does not replace the authority standing here — refusing to co-sign",
                ),
                None,
            );
        }
        // A holder must not authorize a ceremony that cannot be installed. The
        // proposer checks this too, but a hostile or stale proposer does not, and
        // the cost of being wrong is a permanently stalled rotation.
        let proposed: Vec<UserId> = cfg
            .participants
            .iter()
            .filter_map(|p| p.as_device())
            .collect();
        if !self.rotation_can_complete(&proposed) {
            return (
                Response::err(
                    "refusing to authorize: too few of the current holders are in the proposed arrangement, so the resulting key could never be installed",
                ),
                None,
            );
        }
        if let Err(e) = self.dkg_write(&session, "intent", &op_bytes) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Consent to the CEREMONY as well, not only to the grant that authorizes
        // it. The holder named this proposal explicitly, so this is exactly what
        // they agreed to — and without it they would authorize a ceremony they
        // then refuse to help install, stalling the rotation at the last step
        // with no indication why.
        if let Err(e) = self.dkg_write(&expected, "intent", expected.to_hex().as_bytes()) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_advance() {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "co-signed the authorization for a {}-of-{} arrangement — it takes effect once the threshold has signed",
                    cfg.k,
                    cfg.participants.len()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Drive every FROST ceremony this device participates in to a fixpoint, based
    /// on what has synced. Idempotent: posts each round once, and installs the
    /// group key (via a space `Rotate`) once, by the recovery-key holder. Called
    /// by `space_elevate_cmd`, an explicit advance, and on import.
    ///
    /// The ceremony board is grow-only and re-scanned each import; completed and
    /// abandoned sessions are never pruned, so a member could pad it to inflate
    /// per-import work (bounded per call by the `guard` below). Session GC/expiry
    /// is future work — see the `C_CEREMONY` container in `engine::membership`.
    pub fn dkg_advance(&mut self) -> Result<bool> {
        let mut any = false;
        // A ceremony has a bounded number of steps; the guard is a backstop
        // against any unforeseen non-convergence, never reached in normal flow.
        let mut guard = 0;
        while self.dkg_advance_once()? {
            any = true;
            guard += 1;
            if guard > 64 {
                break;
            }
        }
        Ok(any)
    }

    fn dkg_advance_once(&mut self) -> Result<bool> {
        // ONE verified pass over the board. Everything below reads from this —
        // discovery included. Previously sessions were discovered by decoding
        // events *unverified* and the whole board was then re-verified once per
        // discovered session, so forged events both manufactured transcripts and
        // multiplied the work (`transcripts × board`, attacker-controlled on
        // both axes).
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        // Per-transcript advancement is best-effort: a malformed, signature-valid
        // package from one participant must never fail the whole import (which
        // would wedge membership sync permanently on the persisted event). Isolate
        // and log each transcript's error instead of propagating it.
        let mut progressed = false;
        // DKG transcripts naming me as a participant, under an *accepted*
        // proposal. Acceptance (not just a valid signature) is the gate — see
        // `accepted_proposal`.
        let dkg_ids: Vec<crate::dkg::TranscriptId> = board
            .dkg
            .iter()
            .filter(|(id, t)| {
                self.accepted_proposal(id, t)
                    .is_some_and(|(_, _, participants)| participants.contains(&self.me))
            })
            .map(|(id, _)| *id)
            .collect();
        for id in dkg_ids {
            let t = &board.dkg[&id];
            match self.dkg_advance_session(&id, t) {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("dkg ceremony advance failed (skipped): {e:#}"),
            }
        }
        // Threshold-signing transcripts I can co-sign.
        let sign_ids: Vec<crate::dkg::TranscriptId> = board.signing.keys().copied().collect();
        for id in sign_ids {
            let t = &board.signing[&id];
            match self.sign_advance_session(&id, t, &board) {
                Ok(p) => progressed |= p,
                Err(e) => tracing::warn!("recovery signing advance failed (skipped): {e:#}"),
            }
        }
        Ok(progressed)
    }

    /// Whether `claimed` really is the authority standing here.
    ///
    /// Two checks, and the second is only available to some nodes:
    ///
    /// Both halves are checkable by every node, whether or not it holds a share:
    ///
    /// - **The key must commit to the standing commitment.** A hash comparison
    ///   against `RootState.recovery_commit`; always worked.
    /// - **The arrangement must match the standing configuration.** Rotation records the
    ///   configuration id on the space plane, so `RootState.configuration` gives
    ///   it for every replica through replay. Without that replicated arrangement, a non-holder could not learn
    ///   the arrangement and acceptance fell back to key-alone — sound only while
    ///   `RotateKey` always changed the key. `Reshare` breaks that, which is why
    ///   the gap had to close before same-key transitions exist.
    ///
    /// The public key still arrives *in the proposal* (the proposer names it) and
    /// is verified against the on-plane commitment; the configuration now arrives
    /// on-plane too, so the "accept because we cannot tell" escape hatch is gone.
    fn claims_the_standing_authority(&self, claimed: &crate::authority::AuthorityId) -> bool {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        crate::space::recovery_commit(&claimed.public_key) == Some(cur.recovery_commit)
            && claimed.configuration == cur.configuration
    }

    /// Whether a proposed participant set leaves the current group able to
    /// install the result.
    ///
    /// Installing a rotation needs the *current* authority to sign it, and a
    /// signer only reaches that point if it can derive the candidate key —
    /// which requires holding the new ceremony's public package, i.e. being one
    /// of its participants. So at least `k_current` members of the current
    /// arrangement must also be in the proposed one.
    ///
    /// Checked at authorization time because the failure is otherwise silent and
    /// terminal: a ceremony with too little overlap authorizes cleanly, runs the
    /// whole DKG, collects custody attestations, and then stalls forever at
    /// installation with every participant believing it succeeded.
    fn rotation_can_complete(&self, proposed: &[UserId]) -> bool {
        let Some(current) = self.standing_dkg_session() else {
            // A solo authority signs the rotation by itself; no overlap needed.
            return true;
        };
        let Some(cfg) = self
            .dkg_manifest(&current)
            .and_then(|m| m.configuration.as_frost_threshold())
        else {
            // Cannot determine the current arrangement, so cannot judge. Let the
            // ceremony proceed rather than block on our own ignorance.
            return true;
        };
        let overlap = cfg
            .participants
            .iter()
            .filter_map(|p| p.as_device())
            .filter(|d| proposed.contains(d))
            .count();
        overlap >= cfg.k as usize
    }

    /// Whether `dkg`'s arrangement is **indispensable**: every holder is
    /// required, so no share is redundant and losing one ends the authority.
    fn is_indispensable(&self, dkg: &crate::dkg::TranscriptId) -> bool {
        self.dkg_manifest(dkg)
            .and_then(|m| m.configuration.as_frost_threshold())
            .is_some_and(|c| c.k as usize == c.participants.len())
    }

    /// Custodians of `dkg` that have **not** attested portable custody.
    ///
    /// Only meaningful for an indispensable arrangement; a redundant one can
    /// afford to lose a holder, so it does not gate on this.
    fn custody_outstanding(
        &self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
        participants: &[UserId],
    ) -> Vec<UserId> {
        if !self.is_indispensable(dkg) {
            return Vec::new();
        }
        let acked = t.custody_acks();
        participants
            .iter()
            .filter(|p| !acked.contains(p))
            .cloned()
            .collect()
    }

    /// Export this device's share for `dkg` as a portable package, verify it by
    /// reopening it, and attest that on the board.
    ///
    /// The verification is the point. Writing a file proves nothing — the
    /// failure this guards against is a package that cannot be reopened, which
    /// is indistinguishable from a good one until the day it is needed. So the
    /// package is read back from disk and opened through the **portable** slot
    /// specifically, never the local convenience path, before anything is
    /// attested.
    pub fn space_custody_export_cmd(
        &mut self,
        path: String,
        passphrase: String,
    ) -> (Response, Option<DirtySet>) {
        if passphrase.chars().count() < 12 {
            return (
                Response::err(
                    "choose a passphrase of at least 12 characters — this is the only thing standing between an attacker with the file and your share",
                ),
                None,
            );
        }
        // The ceremony to export for: one we hold a share of. A pending
        // arrangement takes precedence, since that is the one whose install is
        // waiting on this attestation.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let standing = self.active_dkg_session();
        let Some(dkg) = board
            .dkg
            .keys()
            .find(|id| self.dkg_read(id, "share").is_some() && Some(**id) != standing)
            .copied()
            .or(standing)
        else {
            return (Response::err("this device holds no share to export"), None);
        };
        let Some(t) = board.dkg.get(&dkg) else {
            return (Response::err("that ceremony is not on the board"), None);
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return (Response::err("that ceremony is not accepted here"), None);
        };
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return (
                Response::err("no acceptance record for that ceremony"),
                None,
            );
        };
        let (Some(share), Some(pkp)) = (self.dkg_read(&dkg, "share"), self.dkg_read(&dkg, "pkp"))
        else {
            return (
                Response::err("this device's share for that ceremony is missing or unreadable"),
                None,
            );
        };
        let Ok(group_key) = crate::dkg::group_key_of_package(&pkp) else {
            return (Response::err("the public-key package is unusable"), None);
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return (Response::err("this device is not a participant"), None);
        };
        let principal = crate::authority::PrincipalId::of_device(&self.me);
        let leaf = crate::authority::LeafId::of_principal(&principal);
        let authority =
            crate::authority::AuthorityId::new(group_key.clone(), &manifest.configuration);
        let payload = crate::custody::SharePayload::Frost(crate::custody::FrostSharePayload {
            key_share: share,
            public_package: pkp,
            index: index as u16 + 1,
        });
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&rand16());
        let package = match crate::custody::AuthoritySharePackage::seal(
            &self.workspace_id,
            &authority,
            &dkg.to_hex(),
            &principal,
            &leaf,
            &payload,
            &[crate::custody::SlotSpec::Passphrase {
                passphrase: passphrase.clone(),
                salt,
                params: custody_kdf_params(),
            }],
        ) {
            Ok(p) => p,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let bytes = match postcard::to_stdvec(&package) {
            Ok(b) => b,
            Err(e) => return (Response::err(format!("encode package: {e}")), None),
        };
        let out = std::path::PathBuf::from(&path);
        if let Some(parent) = out.parent() {
            if !parent.as_os_str().is_empty() {
                if let Err(e) = crate::secretfs::create_private_dir(parent) {
                    return (Response::err(format!("{e:#}")), None);
                }
            }
        }
        // Portable: a share package is meant to be carried off this machine, so
        // it must not be wrapped to this account.
        if let Err(e) = crate::secretfs::write_private(
            &out,
            &bytes,
            crate::secretfs::Create::Replace,
            crate::secretfs::Wrap::Portable,
        ) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Read back from disk and open through the portable slot. Verifying the
        // in-memory value would test nothing that could actually fail.
        let reread = match crate::secretfs::read_private(&out) {
            Ok(Some(b)) => b,
            Ok(None) => return (Response::err("the package vanished after writing"), None),
            Err(e) => {
                return (
                    Response::err(format!("re-reading the package failed: {e}")),
                    None,
                )
            }
        };
        let restored: crate::custody::AuthoritySharePackage = match postcard::from_bytes(&reread) {
            Ok(p) => p,
            Err(e) => {
                return (
                    Response::err(format!("the written package does not decode: {e}")),
                    None,
                )
            }
        };
        let expect = crate::custody::PackageExpectation {
            workspace: &self.workspace_id,
            authority: &authority,
            ceremony: &dkg.to_hex(),
            leaf: &leaf,
            group_key: &group_key,
            index: index as u16 + 1,
        };
        if let Err(e) =
            restored.verify_and_open(&crate::custody::UnlockKey::Passphrase(passphrase), &expect)
        {
            return (
                Response::err(format!(
                    "the exported package could not be reopened, so it was NOT attested: {e:#}"
                )),
                None,
            );
        }
        if let Err(e) = self.post_ceremony(crate::dkg::CeremonyOp::CustodyAck { dkg }) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Recompute from the board so the count reflects our own attestation.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let outstanding = board
            .dkg
            .get(&dkg)
            .map(|t| self.custody_outstanding(&dkg, t, &participants))
            .unwrap_or_default();
        let note = if !self.is_indispensable(&dkg) {
            "this arrangement tolerates a lost holder, so no attestation is required to install it"
                .to_string()
        } else if outstanding.is_empty() {
            "every custodian has attested — the arrangement can now install".to_string()
        } else {
            format!("still waiting on {} custodian(s)", outstanding.len())
        };
        (
            Response::Ok {
                message: Some(format!(
                    "exported and verified your share package to {path} — {note}. Keep it somewhere the passphrase alone cannot be found."
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Restore a share from a portable package written by
    /// [`Self::space_custody_export_cmd`].
    ///
    /// This is the half that makes the backup mean anything. Without it the
    /// package preserves the material and the product still cannot resume
    /// signing after an account or machine loss — which is not what "DPAPI loss
    /// does not destroy an owner" claims.
    ///
    /// Refuses to replace a share that is already readable unless `force`: the
    /// common case for running this by mistake is a working device, and
    /// overwriting good material with an older package would turn a typo into
    /// the loss it exists to prevent.
    pub fn space_custody_import_cmd(
        &mut self,
        path: String,
        passphrase: String,
        force: bool,
    ) -> (Response, Option<DirtySet>) {
        let bytes = match crate::secretfs::read_private(std::path::Path::new(&path)) {
            Ok(Some(b)) => b,
            Ok(None) => return (Response::not_found(format!("no package at {path}")), None),
            Err(e) => return (Response::err(format!("reading {path}: {e}")), None),
        };
        let package: crate::custody::AuthoritySharePackage = match postcard::from_bytes(&bytes) {
            Ok(p) => p,
            Err(e) => {
                return (
                    Response::err(format!("that file is not a share package: {e}")),
                    None,
                )
            }
        };
        if package.workspace != self.workspace_id {
            return (
                Response::err("that package belongs to a different workspace"),
                None,
            );
        }
        // Resolve the ceremony it claims, from the board — never from the
        // package. A package names its own ceremony; that is a claim, not proof.
        let Some(dkg) = crate::dkg::TranscriptId::parse_hex(&package.ceremony) else {
            return (Response::err("that package names no valid ceremony"), None);
        };
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let Some(t) = board.dkg.get(&dkg) else {
            return (
                Response::err(
                    "that ceremony is not on this device's board — sync the workspace first",
                ),
                None,
            );
        };
        let Some((_, _, participants)) = self.accepted_proposal(&dkg, t) else {
            return (
                Response::err("that ceremony is not accepted here — it may not be authorized"),
                None,
            );
        };
        let Some(index) = participants.iter().position(|p| p == &self.me) else {
            return (
                Response::err("this device is not a participant of that ceremony"),
                None,
            );
        };
        let index = index as u16 + 1;
        let Some(manifest) = self.dkg_manifest(&dkg) else {
            return (
                Response::err("no acceptance record for that ceremony"),
                None,
            );
        };
        // Refuse to clobber usable material.
        if !force && matches!(self.dkg_artifact(&dkg, "share"), ArtifactRead::Present(_)) {
            return (
                Response::err(
                    "this device already holds a readable share for that ceremony — pass --force only if you mean to replace it",
                ),
                None,
            );
        }
        // The expected group key comes from the board's ceremony where possible,
        // so a package cannot introduce a group this device never accepted. When
        // the local public package is gone (the very case this command exists
        // for), fall back to the package's own — still bound by the authority
        // and workspace checks, and validated against the private half below.
        let expected_group = match self.dkg_artifact(&dkg, "pkp") {
            ArtifactRead::Present(pkp) => match crate::dkg::group_key_of_package(&pkp) {
                Ok(k) => k,
                Err(e) => {
                    return (
                        Response::err(format!("local public package unusable: {e}")),
                        None,
                    )
                }
            },
            _ => package.authority.public_key.clone(),
        };
        let authority =
            crate::authority::AuthorityId::new(expected_group.clone(), &manifest.configuration);
        let principal = crate::authority::PrincipalId::of_device(&self.me);
        let leaf = crate::authority::LeafId::of_principal(&principal);
        let expect = crate::custody::PackageExpectation {
            workspace: &self.workspace_id,
            authority: &authority,
            ceremony: &package.ceremony,
            leaf: &leaf,
            group_key: &expected_group,
            index,
        };
        // `verify_and_open` performs the private-half validation, so a package
        // that opens but carries unusable material never reaches storage.
        let payload = match package
            .verify_and_open(&crate::custody::UnlockKey::Passphrase(passphrase), &expect)
        {
            Ok(p) => p,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let crate::custody::SharePayload::Frost(f) = payload else {
            return (
                Response::err("that package carries a share this build cannot use"),
                None,
            );
        };
        // Write the public package first: if the process dies between the two,
        // a share without its package is unusable and looks broken, whereas a
        // package without a share is simply an absent share — the recoverable
        // side of the failure.
        if let Err(e) = self.dkg_write_portable(&dkg, "pkp", &f.public_package) {
            return (Response::err(format!("{e:#}")), None);
        }
        if let Err(e) = self.dkg_write(&dkg, "share", &f.key_share) {
            return (Response::err(format!("{e:#}")), None);
        }
        // Prove the restore actually worked by reading back what was stored,
        // rather than trusting the write. This is the same discipline as export:
        // the failure being guarded is one that only shows up on re-read.
        let restored = match (
            self.dkg_artifact(&dkg, "share"),
            self.dkg_artifact(&dkg, "pkp"),
        ) {
            (ArtifactRead::Present(s), ArtifactRead::Present(p)) => (s, p),
            _ => {
                return (
                    Response::err("the restored share could not be read back"),
                    None,
                )
            }
        };
        if let Err(e) = crate::dkg::validate_share(&restored.0, &restored.1, index) {
            return (
                Response::err(format!("the restored share does not validate: {e:#}")),
                None,
            );
        }
        let _ = self.dkg_advance();
        (
            Response::Ok {
                message: Some(format!(
                    "restored and verified your share for ceremony {} — this device can take part in recovery again",
                    dkg.to_hex()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// What this device can say about recovery right now.
    pub fn recovery_status(&self) -> RecoveryStatus {
        let authority = self.current_authority();
        // Shape describes the STANDING arrangement. Deriving it from a session
        // we can use would report a fictitious 1-of-1 for exactly the holder
        // whose share has gone missing — the case where the real shape matters
        // most, because it says whether anyone else can still recover.
        let standing = self.standing_dkg_session();
        let scheme = standing
            .and_then(|id| self.dkg_manifest(&id))
            .map(|m| m.configuration.scheme)
            .unwrap_or(crate::authority::AuthorityScheme::Single);
        let (k, n) = standing
            .and_then(|id| self.dkg_manifest(&id))
            .and_then(|m| m.configuration.as_frost_threshold())
            .map(|c| (c.k, c.participants.len() as u16))
            .unwrap_or((1, 1));
        // Consider every ceremony this device is a custodian of, not only the
        // standing one. A PENDING indispensable arrangement is precisely the
        // case worth reporting: its install is blocked on this device, and
        // saying "Ready" because some other authority is currently fine would
        // hide the one thing the operator needs to act on.
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let mine: Vec<crate::dkg::TranscriptId> = board
            .dkg
            .iter()
            .filter(|(id, t)| {
                self.accepted_proposal(id, t)
                    .is_some_and(|(_, _, ps)| ps.contains(&self.me))
            })
            .map(|(id, _)| *id)
            .collect();
        // Worst state wins: an unusable share outranks an unbacked one, which
        // outranks a healthy one.
        let mut state = if self.read_space_recovery_key().is_some() && standing.is_none() {
            LocalCustodyState::Ready
        } else {
            // Anyone else starts as not-a-holder and is upgraded by whatever
            // shares they turn out to hold.
            LocalCustodyState::NotAHolder
        };
        for id in &mine {
            match self.dkg_artifact(id, "share") {
                ArtifactRead::Unreadable(e) => {
                    return RecoveryStatus {
                        authority: authority.map(|a| a.public_key.short()),
                        scheme,
                        k,
                        n,
                        local_custody: LocalCustodyState::Unreadable(match e {
                            crate::secretfs::SecretError::Undecryptable(m) => {
                                RecoveryArtifactFailure::Undecryptable(m)
                            }
                            crate::secretfs::SecretError::Io(e) => {
                                RecoveryArtifactFailure::Io(e.to_string())
                            }
                        }),
                    };
                }
                ArtifactRead::Present(_) => {
                    let attested = board
                        .dkg
                        .get(id)
                        .map(|t| t.custody_acks().contains(&self.me))
                        .unwrap_or(false);
                    if self.is_indispensable(id) && !attested {
                        state = LocalCustodyState::BackupUnverified;
                    } else if state == LocalCustodyState::NotAHolder {
                        state = LocalCustodyState::Ready;
                    }
                }
                ArtifactRead::Missing => {
                    // Only a gap in the STANDING authority is a missing share;
                    // mid-DKG absence is ordinary progress, not a fault.
                    //
                    // This compares against the standing session rather than the
                    // usable one. `active_dkg_session` requires a readable share,
                    // so asking it here could never be true when the share is
                    // missing — the condition was unreachable, and a holder whose
                    // standing share disappeared reported as "not a holder".
                    if Some(*id) == standing && state == LocalCustodyState::NotAHolder {
                        state = LocalCustodyState::Missing;
                    }
                }
            }
        }
        let local_custody = state;
        RecoveryStatus {
            authority: authority.map(|a| a.public_key.short()),
            scheme,
            k,
            n,
            local_custody,
        }
    }

    /// The authority standing right now: its public key, and the arrangement
    /// operating it.
    ///
    /// The key comes from the space plane. The *arrangement* does not — the
    /// plane deliberately knows nothing about signing topology — so it comes
    /// from this device's own acceptance record for the ceremony that produced
    /// the key. A solo bootstrap key has no ceremony and is `Single` by
    /// construction.
    ///
    /// Deliberately reads manifests rather than re-deriving acceptance from the
    /// board: acceptance already asks "does this proposal replace the standing
    /// authority?", so resolving the standing authority through acceptance would
    /// be mutually recursive. The manifest is written only *after* a genuine
    /// acceptance, and the group key is still DERIVED from the public-key
    /// package rather than read from a file naming it, so the filesystem is an
    /// index here and not a source of authority.
    ///
    /// `None` when a group key is standing that this device cannot attribute to
    /// any accepted ceremony: we know a key is in force but not what governs it,
    /// and answering `Single` there would let a proposal claim to replace an
    /// arrangement nobody has seen.
    fn current_authority(&self) -> Option<crate::authority::AuthorityId> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        if let Some(secret) = self.read_space_recovery_key() {
            let pubkey = crate::space::recovery_pub_of(&secret);
            if crate::space::recovery_commit(&pubkey) == Some(cur.recovery_commit) {
                return Some(crate::authority::AuthorityId::single(pubkey));
            }
        }
        for (id, manifest) in self.dkg_manifests() {
            let Some(group_key) = self.group_key_of_transcript(&id) else {
                continue;
            };
            if crate::space::recovery_commit(&group_key) == Some(cur.recovery_commit) {
                return Some(crate::authority::AuthorityId::new(
                    group_key,
                    &manifest.configuration,
                ));
            }
        }
        None
    }

    /// Every acceptance record on this device, keyed by transcript.
    fn dkg_manifests(&self) -> Vec<(crate::dkg::TranscriptId, crate::dkg::DkgManifest)> {
        let dir = self.store.home_path().join("dkg");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(hex) = name.strip_suffix("-manifest") else {
                continue;
            };
            // Strict: a non-canonical filename names no transcript.
            let Some(id) = crate::dkg::TranscriptId::parse_hex(hex) else {
                continue;
            };
            if let Some(m) = self.dkg_manifest(&id) {
                out.push((id, m));
            }
        }
        out
    }

    /// The verified, retention-filtered ceremony board.
    ///
    /// The **only** way this file obtains a board. `parse_board` alone leaves
    /// signing rounds unrestricted, so a caller that forgot the second step
    /// would silently reintroduce an unbounded signing projection; routing every
    /// caller through here makes that impossible to forget.
    ///
    /// The fallback resolves an authority whose proposal is not in the
    /// projection through this device's own accepted manifest — authenticated
    /// local state, never a participant list taken from the signing request.
    fn ceremony_board(
        &self,
        events: &[crate::space::SignedSpaceEvent],
    ) -> crate::dkg::CeremonyBoard {
        let mut board = crate::dkg::parse_board(events, &self.workspace_id);
        board.restrict_signing_rounds(|authority| {
            self.dkg_manifest(authority).and_then(|m| {
                m.configuration
                    .as_frost_threshold()?
                    .participants
                    .iter()
                    .map(|p| p.as_device())
                    .collect()
            })
        });
        board
    }

    /// A DKG transcript's configuration, **only if the proposal is accepted**.
    ///
    /// The device signature on a proposal proves control of a device and nothing
    /// more. Acceptance requires an authorization signed by the key that is the
    /// workspace's recovery authority — without this, any device could post a
    /// proposal for a transcript and supply its `(n, k, participants)`, which on
    /// the node that initiated an elevation and holds the recovery key would be
    /// installed as the new recovery authority.
    ///
    /// Two ways to satisfy it, and the second is not a weaker path:
    /// - the authorizer IS the standing authority; or
    /// - we recorded a [`crate::dkg::DkgManifest`] for this exact proposal
    ///   earlier, i.e. it was the standing authority when we accepted. Required
    ///   because a successful elevation *rotates* the authority: re-checking
    ///   against the standing key would un-accept every transcript at the moment
    ///   it succeeds, orphaning holders mid-DKG.
    ///
    /// Well-formedness is re-checked here rather than trusted from the proposer:
    /// `space_elevate_cmd` sorts and dedupes, but a hostile proposer does not.
    fn accepted_proposal(
        &self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Option<(u16, u16, Vec<UserId>)> {
        let proposal = t.proposal.as_ref()?;
        let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal.op else {
            return None;
        };
        // Well-formedness and scheme support are the configuration's own rules,
        // re-checked at every acceptor rather than trusted from the proposer.
        // `frost_config` also refuses a transition this phase does not implement
        // (Reshare), so an unimplemented promise cannot enter a ceremony.
        let cfg = p.frost_config()?;
        let participants = p.frost_devices()?;
        let (n, k) = (participants.len() as u16, cfg.k);

        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        // `parse_board` already checked every detached signature; what it cannot
        // know is which signer is the standing authority. Scanning ALL retained
        // authorizations — rather than one slot — is what stops a wrong-key
        // authorization from displacing the right one, and makes the outcome a
        // function of authority validation rather than of board order.
        // Fresh acceptance needs BOTH: the proposal targets the authority
        // standing right now, and a grant from that authority is present.
        //
        // The target check lives here rather than as a hard gate because a
        // successful ceremony rotates the authority it named — so a gate would
        // make every transcript un-accept itself at the moment it succeeded,
        // stranding holders mid-DKG and orphaning the very group it created.
        let fresh = self.claims_the_standing_authority(p.current_authority())
            && t.auths
                .values()
                .any(|g| crate::space::recovery_commit(&g.author) == Some(cur.recovery_commit));
        // Or: the authority that was standing when we accepted, whose
        // authorization must still be present. A successful elevation rotates
        // the authority, so `fresh` alone would un-accept every transcript at the
        // moment it succeeds and orphan holders mid-DKG.
        let recorded = self.dkg_manifest(dkg).is_some_and(|m| {
            m.proposal == *dkg
                && m.proposal_author == proposal.author
                && m.configuration == p.configuration
                && t.auths.contains_key(&m.authorized_by)
        });
        (fresh || recorded).then(|| (n, k, participants.clone()))
    }

    /// This transcript's local acceptance record, if we wrote one.
    fn dkg_manifest(&self, dkg: &crate::dkg::TranscriptId) -> Option<crate::dkg::DkgManifest> {
        postcard::from_bytes(&self.dkg_read(dkg, "manifest")?).ok()
    }

    /// The DKG transcript whose group key is the workspace's **standing**
    /// recovery authority, whether or not this device can use its share.
    ///
    /// Separate from [`Self::active_dkg_session`] because conflating them makes
    /// two states unreportable. The old single accessor required a readable
    /// share, so a holder whose standing share went missing or unreadable
    /// resolved to `None` and was reported as "not a holder" — the one answer
    /// that is definitely wrong — and the arrangement's shape fell back to a
    /// fictitious 1-of-1.
    ///
    /// Resolution does not depend on the share: the public-key package is stored
    /// portable precisely so a device that has lost its secret can still say
    /// which group it belongs to. Failing that, an acceptance record names the
    /// configuration.
    fn standing_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        self.dkg_manifests().into_iter().find_map(|(id, _)| {
            (self
                .group_key_of_transcript(&id)
                .as_ref()
                .and_then(crate::space::recovery_commit)
                == Some(cur.recovery_commit))
            .then_some(id)
        })
    }

    /// The standing transcript **whose share this device can actually use**.
    ///
    /// This is the signing accessor: everything that needs to produce a
    /// signature needs a readable share, and a holder that cannot read its own
    /// share must not be treated as able to contribute.
    fn active_dkg_session(&self) -> Option<crate::dkg::TranscriptId> {
        let id = self.standing_dkg_session()?;
        matches!(self.dkg_artifact(&id, "share"), ArtifactRead::Present(_)).then_some(id)
    }

    /// This transcript's group key, recomputed from the stored public-key
    /// package. Never read from a `-group` file: a plaintext artifact naming the
    /// rotation target is a swap target, and the value is derivable.
    fn group_key_of_transcript(&self, t: &crate::dkg::TranscriptId) -> Option<UserId> {
        crate::dkg::group_key_of_package(&self.dkg_read(t, "pkp")?).ok()
    }

    /// Advance one FROST threshold-signing transcript over the bulletin board.
    ///
    /// Any available K holders can sign, not a predetermined K. That needs a
    /// single canonical answer to "which K", because a signature share binds to
    /// the whole signing package and two holders signing under different
    /// packages produce shares that do not aggregate — and a holder signing
    /// twice under different packages with one nonce leaks its share outright.
    ///
    /// The answer is the [`SigningPlan`], published by the coordinator the
    /// request names. Holders do not trust it: every selected signer re-derives
    /// the message, checks each commitment against what its author actually
    /// posted, confirms its own commitment is unchanged, and only then binds its
    /// nonce record to the plan. What the coordinator supplies is a *choice*,
    /// not an input to the cryptography.
    ///
    /// [`SigningPlan`]: crate::dkg::SigningPlan
    fn sign_advance_session(
        &mut self,
        signing: &crate::dkg::TranscriptId,
        t: &crate::dkg::SignTranscript,
        board: &crate::dkg::CeremonyBoard,
    ) -> Result<bool> {
        let Some(request) = t.request.as_ref() else {
            return Ok(false);
        };
        let crate::dkg::CeremonyOp::SignRequest {
            authority,
            target,
            coordinator,
            op: op_bytes,
            ..
        } = &request.op
        else {
            return Ok(false);
        };
        let Some(dkg_t) = board.dkg.get(authority) else {
            return Ok(false);
        };
        let Some((_, threshold, participants)) = self.accepted_proposal(authority, dkg_t) else {
            return Ok(false);
        };
        let (Some(share), Some(pkp)) = (
            self.dkg_read(authority, "share"),
            self.dkg_read(authority, "pkp"),
        ) else {
            return Ok(false);
        };
        let Ok(group_key) = crate::dkg::group_key_of_package(&pkp) else {
            return Ok(false);
        };
        let index_of = |dev: &UserId| {
            participants
                .iter()
                .position(|p| p == dev)
                .map(|i| i as u16 + 1)
        };
        let Some(my_index) = index_of(&self.me) else {
            return Ok(false);
        };
        // Consent gate: we contribute only to a request we ourselves authorized,
        // byte-for-byte. Without it, posting a Recover-to-me request would let
        // honest holders' shares hand the workspace over.
        if self.dkg_read(signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            return Ok(false);
        }
        // Domain separation. The message is built under the domain matching what
        // the signature is FOR, and the finished signature is installed on the
        // matching plane. Postcard is not self-describing and
        // `CeremonyOp::DkgPropose` shares variant tag 0 with `SpaceOp::Recover`,
        // so signing ceremony bytes under the space domain would not merely be
        // misfiled — it would be a type-confusion primitive. No default arm: a
        // future target must make an explicit choice here.
        let domain: &[u8] = match target {
            crate::dkg::SignTarget::SpaceOp => crate::space::SPACE_EVENT_DOMAIN,
            crate::dkg::SignTarget::AuthorityGrant => crate::dkg::AUTHORITY_GRANT_DOMAIN,
        };
        let message = crate::sigdag::payload_to_sign(
            domain,
            op_bytes,
            &group_key,
            &[],
            self.workspace_id.as_str(),
        );

        // Every commitment posted so far, keyed by index, taken from the authors
        // who actually posted them.
        let mut posted: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::SignRound1 { commitments, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    posted.entry(i).or_insert_with(|| commitments.clone());
                }
            }
        }
        let i_posted_r1 = posted.contains_key(&my_index);

        // Step 1 — commit. EVERY holder commits, not only a predetermined K:
        // that is what makes any available K able to sign. The nonce record is
        // created exclusively, since single-use material that already exists
        // must be examined rather than overwritten.
        if !i_posted_r1 && !self.dkg_has(signing, "nonce") {
            let (nonces, commitments) = crate::dkg::sign_round1(&share)?;
            let pending = crate::dkg::PendingNonce {
                signing: *signing,
                // Bound at step 3, once the coordinator has fixed the plan.
                binding: [0u8; 32],
                nonces,
            };
            self.dkg_write_new(signing, "nonce", &postcard::to_stdvec(&pending)?)?;
            self.post_ceremony(crate::dkg::CeremonyOp::SignRound1 {
                signing: *signing,
                commitments,
            })?;
            return Ok(true);
        }

        // Step 2 — the coordinator freezes a plan once enough holders have
        // committed. Only the named coordinator may do this, and only once.
        let existing_plan = t.plan();
        if existing_plan.is_none() && &self.me == coordinator && posted.len() >= threshold as usize
        {
            // Take the lowest `threshold` indices among those that committed.
            // Any qualified subset would do; a deterministic rule keeps a
            // coordinator restarted mid-flight from producing a second plan.
            let chosen: Vec<u16> = posted.keys().copied().take(threshold as usize).collect();
            let commitments: crate::dkg::Packages =
                chosen.iter().map(|i| (*i, posted[i].clone())).collect();
            let signers: Vec<crate::authority::LeafId> = chosen
                .iter()
                .map(|i| {
                    crate::authority::LeafId::of_principal(
                        &crate::authority::PrincipalId::of_device(&participants[*i as usize - 1]),
                    )
                })
                .collect();
            let Some(config) = self.dkg_manifest(authority).map(|m| m.configuration) else {
                return Ok(false);
            };
            let plan = crate::dkg::SigningPlan {
                signing: *signing,
                authority: crate::authority::AuthorityId::new(group_key.clone(), &config),
                message_commitment: *blake3::hash(&message).as_bytes(),
                signers,
                commitments,
                witness: crate::dkg::AccessWitness::FrostThreshold {
                    k: threshold,
                    participant_indices: chosen,
                },
            };
            self.post_ceremony(crate::dkg::CeremonyOp::SignPlan {
                signing: *signing,
                plan: plan.encode(),
            })?;
            return Ok(true);
        }
        let Some(plan) = existing_plan else {
            return Ok(false);
        };

        // Step 3 — validate the plan, then sign under it.
        //
        // Nothing here trusts the coordinator's arithmetic. The message is
        // re-derived; every commitment is checked against the round-1 event its
        // author actually posted; our own commitment must be the one we hold a
        // nonce for. A coordinator can choose WHO signs; it cannot choose WHAT
        // they sign or forge a commitment on their behalf.
        let crate::dkg::AccessWitness::FrostThreshold {
            k,
            participant_indices,
        } = &plan.witness
        else {
            // A witness this build cannot evaluate is refused rather than
            // assumed valid.
            return Ok(false);
        };
        let plan_ok = plan.signing == *signing
            && plan.authority.public_key == group_key
            && plan.message_commitment == *blake3::hash(&message).as_bytes()
            && *k == threshold
            && participant_indices.len() == threshold as usize
            && plan.commitments.len() == threshold as usize
            && plan.signers.len() == threshold as usize
            // Canonical ordering, so two coordinators cannot produce differing
            // encodings of the same choice.
            && participant_indices.windows(2).all(|w| w[0] < w[1])
            && participant_indices
                .iter()
                .all(|i| *i >= 1 && (*i as usize) <= participants.len())
            && plan.commitments.keys().eq(participant_indices.iter())
            // Authenticity: each commitment must be what that participant
            // actually posted, not what the coordinator says they posted.
            && plan
                .commitments
                .iter()
                .all(|(i, c)| posted.get(i) == Some(c));
        if !plan_ok {
            anyhow::bail!("refusing to sign: the coordinator's plan does not validate");
        }
        let in_plan = participant_indices.contains(&my_index);
        let i_posted_r2 = t.rounds.iter().any(|v| {
            v.author == self.me && matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. })
        });
        if in_plan && !i_posted_r2 {
            let Some(raw) = self.dkg_read(signing, "nonce") else {
                return Ok(false);
            };
            let mut pending: crate::dkg::PendingNonce = postcard::from_bytes(&raw)?;
            // Our own commitment in the plan must be the one these nonces
            // produced. This is the check that makes a shifted signer set safe.
            if plan.commitments.get(&my_index) != posted.get(&my_index) {
                anyhow::bail!("refusing to sign: the plan carries a commitment we did not post");
            }
            let binding = crate::dkg::nonce_binding(signing, &message, &plan);
            // THE nonce-reuse gate. One stored record may produce shares for
            // exactly one plan; if the plan moved under us, refuse rather than
            // sign. The comparison — not the deletion — is what prevents reuse,
            // since a crash between publishing and deleting always leaves the
            // record behind.
            if pending.binding == [0u8; 32] {
                pending.binding = binding;
                self.dkg_write(signing, "nonce", &postcard::to_stdvec(&pending)?)?;
            } else if pending.binding != binding {
                anyhow::bail!(
                    "refusing to sign: this transcript's signing plan changed after commitment (signing again would reuse the nonce and leak the key share)"
                );
            }
            let share_sig =
                crate::dkg::sign_round2(&plan.commitments, &message, &pending.nonces, &share)?;
            self.post_ceremony(crate::dkg::CeremonyOp::SignRound2 {
                signing: *signing,
                share: share_sig,
            })?;
            // `post_ceremony` persisted the share, so the one-use material can
            // go. Order matters: never delete before the share is durable.
            let _ = std::fs::remove_file(self.dkg_path(signing, "nonce"));
            return Ok(true);
        }

        // Step 4 — any participant aggregates the plan's shares and installs.
        let mut r2: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::SignRound2 { share, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    if participant_indices.contains(&i) {
                        r2.entry(i).or_insert_with(|| share.clone());
                    }
                }
            }
        }
        if r2.len() == threshold as usize {
            let sig = crate::dkg::aggregate(&plan.commitments, &message, &r2, &pkp)?;
            let node = crate::sigdag::assemble_signed(op_bytes.clone(), group_key, sig, vec![]);
            match target {
                crate::dkg::SignTarget::SpaceOp => {
                    let fresh = !self
                        .membership
                        .space_events()
                        .iter()
                        .any(|e| e.hash() == node.hash());
                    if fresh
                        && node.verify_sig(
                            crate::space::SPACE_EVENT_DOMAIN,
                            self.workspace_id.as_str(),
                        )
                    {
                        self.membership.add_space_event(&node)?;
                        self.persist_membership("group_recover")?;
                        self.bootstrap_root_epoch_if_needed()?;
                        return Ok(true);
                    }
                }
                crate::dkg::SignTarget::AuthorityGrant => {
                    if crate::dkg::authority_grant_of(&node, &self.workspace_id).is_some() {
                        let already = self.membership.ceremony_events().iter().any(|e| {
                            matches!(
                                postcard::from_bytes::<crate::dkg::CeremonyOp>(&e.op),
                                Ok(crate::dkg::CeremonyOp::DkgAuthorize(g)) if g.hash() == node.hash()
                            )
                        });
                        if !already {
                            self.post_ceremony(crate::dkg::CeremonyOp::DkgAuthorize(node))?;
                            return Ok(true);
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    /// Advance one DKG transcript. Configuration comes **only** from the
    /// accepted proposal ([`Self::accepted_proposal`]) — never from whichever
    /// signature-valid proposal happens to sort first, which is how a rogue
    /// proposal could previously substitute `(n, k, participants)` into a
    /// transcript an honest initiator had opened.
    fn dkg_advance_session(
        &mut self,
        dkg: &crate::dkg::TranscriptId,
        t: &crate::dkg::DkgTranscript,
    ) -> Result<bool> {
        let Some((n, k, participants)) = self.accepted_proposal(dkg, t) else {
            return Ok(false);
        };
        // Record acceptance the first time we act on this proposal, so a later
        // rotation of the authority cannot orphan a transcript mid-DKG.
        if self.dkg_manifest(dkg).is_none() {
            let cur = crate::space::replay(
                &self.genesis,
                &self.workspace_id,
                &self.membership.space_events(),
            );
            // Pin WHICH authorization we accepted, not merely that one existed.
            let authorized_by = t
                .auths
                .values()
                .find(|g| crate::space::recovery_commit(&g.author) == Some(cur.recovery_commit))
                .map(|g| g.author.clone());
            if let (Some(proposal), Some(authorized_by)) = (t.proposal.as_ref(), authorized_by) {
                let crate::dkg::CeremonyOp::DkgPropose(p) = &proposal.op else {
                    return Ok(false);
                };
                let manifest = crate::dkg::DkgManifest {
                    proposal: *dkg,
                    proposal_author: proposal.author.clone(),
                    authorized_by,
                    configuration: p.configuration.clone(),
                };
                self.dkg_write(dkg, "manifest", &postcard::to_stdvec(&manifest)?)?;
            }
        }
        let index_of = |dev: &UserId| {
            participants
                .iter()
                .position(|p| p == dev)
                .map(|i| i as u16 + 1)
        };
        let Some(my_index) = index_of(&self.me) else {
            return Ok(false);
        };

        // Round-1 packages posted so far, keyed by participant index. Authors
        // outside the participant set resolve to no index and are dropped.
        let mut round1: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::DkgRound1 { package, .. } = &v.op {
                if let Some(i) = index_of(&v.author) {
                    round1.entry(i).or_insert_with(|| package.clone());
                }
            }
        }
        let i_posted_round1 = round1.contains_key(&my_index);

        // Step 1 — post my round-1.
        if !i_posted_round1 {
            let (s1, pkg) = crate::dkg::dkg_round1(my_index, n, k)?;
            self.dkg_write(dkg, "r1", &s1)?;
            self.post_ceremony(crate::dkg::CeremonyOp::DkgRound1 {
                dkg: *dkg,
                package: pkg,
            })?;
            return Ok(true);
        }

        // Step 2 — once all N round-1s are in, post my (sealed) round-2 shares.
        let i_posted_round2 = t.rounds.iter().any(|v| {
            v.author == self.me && matches!(v.op, crate::dkg::CeremonyOp::DkgRound2 { .. })
        });
        if round1.len() == n as usize && !i_posted_round2 && self.dkg_has(dkg, "r1") {
            let others: crate::dkg::Packages = round1
                .iter()
                .filter(|(i, _)| **i != my_index)
                .map(|(i, v)| (*i, v.clone()))
                .collect();
            let (s2, outgoing) =
                crate::dkg::dkg_round2(&self.dkg_read(dkg, "r1").unwrap(), &others)?;
            self.dkg_write(dkg, "r2", &s2)?;
            for (recipient_index, pkg) in outgoing {
                let recipient = participants[recipient_index as usize - 1].clone();
                let Some(sealed) = crypto::seal_to(&recipient, &pkg) else {
                    continue;
                };
                self.post_ceremony(crate::dkg::CeremonyOp::DkgRound2 {
                    dkg: *dkg,
                    to: recipient,
                    sealed,
                })?;
            }
            return Ok(true);
        }

        // Step 3 — once all round-2 shares sent TO me are in, finalize my key
        // share. Only `r2`, `share` and `pkp` are persisted: everything else the
        // old code stored (`group`, `index`, `threshold`, `participants`) is
        // derivable from the accepted proposal or the public-key package, and a
        // trusted plaintext copy is only a swap target.
        let mut round2_to_me: crate::dkg::Packages = std::collections::BTreeMap::new();
        for v in &t.rounds {
            if let crate::dkg::CeremonyOp::DkgRound2 { to, sealed, .. } = &v.op {
                if to == &self.me {
                    if let (Some(sender_i), Some(pkg)) = (
                        index_of(&v.author),
                        crypto::open_sealed(&self.seed, &self.me, sealed),
                    ) {
                        round2_to_me.entry(sender_i).or_insert(pkg);
                    }
                }
            }
        }
        if round2_to_me.len() == n as usize - 1
            && self.dkg_has(dkg, "r2")
            && !self.dkg_has(dkg, "share")
        {
            let others: crate::dkg::Packages = round1
                .iter()
                .filter(|(i, _)| **i != my_index)
                .map(|(i, v)| (*i, v.clone()))
                .collect();
            let (share, pkp, _group_key) =
                crate::dkg::dkg_round3(&self.dkg_read(dkg, "r2").unwrap(), &others, &round2_to_me)?;
            self.dkg_write(dkg, "share", &share)?;
            // The public-key package is PUBLIC: it needs owner-only permissions,
            // not device binding. Wrapping it would mean an account migration
            // also destroyed our ability to tell which group a stranded share
            // belongs to - the check `degraded_recovery_holders` depends on. The
            // group key is still DERIVED from it rather than trusted from a file
            // naming the key, so portability costs nothing.
            self.dkg_write_portable(dkg, "pkp", &pkp)?;
            return Ok(true);
        }

        // Step 4 — the recovery-key holder installs the group key with a Rotate.
        //
        // SECURITY. Four things must hold, and each closes a distinct path:
        // - the proposal is ACCEPTED (checked above): the recovery authority
        //   signed this exact transcript, so its configuration is not attacker-
        //   chosen;
        // - local `intent` names THIS transcript: we consented to this exact
        //   proposal, not merely to "an elevation" (the old marker was the
        //   constant `b"elevate"`, which a substituted config satisfied just as
        //   well as the real one);
        // - the group key is DERIVED from the stored public-key package, not
        //   read from a plaintext file that could be swapped;
        // - we still hold the current recovery key, and it is not already
        //   installed.
        if !self.dkg_has(dkg, "share") {
            return Ok(false);
        }
        let consented = self
            .dkg_read(dkg, "intent")
            .and_then(|b| String::from_utf8(b).ok())
            .is_some_and(|h| h == dkg.to_hex());
        if !consented {
            return Ok(false);
        }
        let Some(group_key) = self.group_key_of_transcript(dkg) else {
            return Ok(false);
        };
        let cur = crate::space::replay(
            &self.genesis,
            &self.workspace_id,
            &self.membership.space_events(),
        );
        let already = crate::space::recovery_commit(&group_key) == Some(cur.recovery_commit);
        if already {
            return Ok(false);
        }
        // The arrangement operating the new key is the candidate ceremony's own
        // configuration, committed on the space plane by the rotation, so
        // every replica (holder or not) learns the standing arrangement by
        // replay. Deterministic from the accepted proposal, so all group holders
        // sign byte-identical rotate ops.
        let Some(next_configuration) = self.dkg_manifest(dkg).map(|m| m.configuration.id()) else {
            return Ok(false);
        };
        // An INDISPENSABLE arrangement must not install until every custodian
        // has verified a portable backup. Otherwise an N-of-N authority can be
        // created in a state where one holder's share exists only behind a
        // Windows profile, and the workspace learns that on the day it needs to
        // recover — the day it is too late to fix.
        //
        // The gate reads signed attestations from the board rather than local
        // state, so no *other* node can install ahead of the checks. A redundant
        // arrangement is not gated: it can afford to lose a holder, which is
        // what redundancy means.
        let outstanding = self.custody_outstanding(dkg, t, &participants);
        if !outstanding.is_empty() {
            tracing::info!(
                "holding the rotation for {}: {} custodian(s) have not verified a portable backup",
                dkg.to_hex(),
                outstanding.len()
            );
            return Ok(false);
        }
        // Solo authority: sign the rotation directly.
        if let Some(secret) = self.read_space_recovery_key() {
            if crate::space::recovery_commit(&crate::space::recovery_pub_of(&secret))
                == Some(cur.recovery_commit)
            {
                let op = crate::space::SpaceOp::Rotate {
                    new_recovery_key: group_key,
                    next_configuration,
                    gen: cur.gen + 1,
                };
                let ev = crate::space::sign_op(&secret, &op, vec![], &self.workspace_id);
                self.membership.add_space_event(&ev)?;
                self.persist_membership("dkg_install")?;
                return Ok(true);
            }
        }
        // Group authority: the rotation itself needs a threshold signature.
        //
        // The grant said "this ceremony may create a candidate authority"; the
        // rotation says "install this exact candidate key". They are separate
        // authorizations, and the second must not be inferred from the first —
        // otherwise consenting to a ceremony would silently consent to whatever
        // key someone later claims it produced.
        //
        // What makes it safe to open and consent automatically here is that
        // `group_key` was DERIVED from this device's own public-key package for
        // this transcript, moments ago. Every holder does the same derivation
        // independently on its own node, so no holder is ever asked to trust a
        // key it did not compute. A holder that cannot derive it — not a
        // participant in the new ceremony — never reaches this point and so
        // never signs.
        if self.active_dkg_session().is_some() {
            let (_, changed) =
                self.open_rotation_request(&group_key, next_configuration, cur.gen + 1)?;
            return Ok(changed);
        }
        Ok(false)
    }

    /// Open (or join) a threshold-signing transcript asking the standing group to
    /// install `new_key` as the recovery authority, and record our consent.
    ///
    /// Requires the caller to have derived `new_key` itself. Note the resulting
    /// constraint: the signing threshold of the *current* group must overlap the
    /// participants of the *new* ceremony, because only a new participant holds
    /// the package the key is derived from. Replacing one holder satisfies this
    /// easily; a handover to a wholly disjoint set does not, and would need an
    /// attested candidate key rather than a locally derived one.
    fn open_rotation_request(
        &mut self,
        new_key: &UserId,
        next_configuration: crate::authority::AuthorityConfigurationId,
        gen: u32,
    ) -> Result<(crate::dkg::TranscriptId, bool)> {
        let authority = self
            .active_dkg_session()
            .ok_or_else(|| anyhow!("this device holds no share of the current group key"))?;
        let op = crate::space::SpaceOp::Rotate {
            new_recovery_key: new_key.clone(),
            next_configuration,
            gen,
        };
        let op_bytes = postcard::to_stdvec(&op)?;
        let events = self.membership.ceremony_events();
        let board = self.ceremony_board(&events);
        let threshold = board
            .dkg
            .get(&authority)
            .and_then(|t| self.accepted_proposal(&authority, t))
            .map(|(_, k, _)| k)
            .unwrap_or(0);
        let mut changed = false;
        let signing = match self.canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            threshold,
        ) {
            Some(id) => id,
            None => {
                let req = crate::dkg::CeremonyOp::SignRequest {
                    nonce: rand16(),
                    authority,
                    target: crate::dkg::SignTarget::SpaceOp,
                    coordinator: self.me.clone(),
                    op: op_bytes.clone(),
                };
                let ev = crate::dkg::sign_ceremony(&self.seed, &req, &self.workspace_id);
                let id = crate::dkg::TranscriptId::of(&ev)
                    .ok_or_else(|| anyhow!("could not derive the request id"))?;
                self.membership.add_ceremony_event(&ev)?;
                self.persist_membership("rotate_request")?;
                changed = true;
                id
            }
        };
        if self.dkg_read(&signing, "intent").as_deref() != Some(op_bytes.as_slice()) {
            self.dkg_write(&signing, "intent", &op_bytes)?;
            changed = true;
        }
        Ok((signing, changed))
    }

    fn post_ceremony(&mut self, op: crate::dkg::CeremonyOp) -> Result<()> {
        let ev = crate::dkg::sign_ceremony(&self.seed, &op, &self.workspace_id);
        self.membership.add_ceremony_event(&ev)?;
        self.persist_membership("dkg_round")
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

    /// The membership audit log: the signed ACL DAG replayed into a rendered,
    /// causally ordered list of operations and their verdicts. This provides
    /// cryptographic provenance, unlike the advisory activity feed.
    fn member_log_response(&self) -> Response {
        let (_state, audit) = acl::replay_with_audit(
            &self.effective_genesis(),
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

    /// Sponsor an already-known agent actor: sign `AddAgent` and
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
    /// and seal every held epoch to it so it can decrypt immediately.
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
        let bytes = crate::secretfs::read_private(&path).ok().flatten()?;
        let hex = String::from_utf8(bytes).ok()?;
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
        let recovery_pub = crypto::user_from_seed(&seed);
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
    /// [`heal_epoch`] re-rotates if a merge leaves the tip sealed to a
    /// since-removed actor.
    ///
    /// The mint is a **signed [`acl::AclAction::MintEpoch`]** authored as our own
    /// actor, so the epoch rides the same trust boundary as membership: a replica
    /// adopts it only when this author held write standing at position. If we are
    /// not a writer the op is inert everywhere (never selected, never a key), so
    /// this degrades gracefully rather than splitting state. The op commits to
    /// `blake3(new_key)`, binding the sealed envelopes we write next.
    ///
    /// [`heal_epoch`]: Self::heal_epoch
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

    /// Repair missing envelopes across the membership by sealing every
    /// epoch key we hold to any device of any *current member actor* that still
    /// lacks an envelope. Admin-ungated and safe — we only ever re-seal keys we
    /// already hold, and only to devices of actors who are entitled to the
    /// workspace key (present in the ACL). A removed actor is not in the member
    /// set, so lazy revocation is preserved.
    ///
    /// This is the backstop that lets any key-holding peer re-provision:
    /// - a *sibling* device added or reinstated after a rotation whose author
    ///   did not yet see it (reaching one device is sufficient), and
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

    /// Convergent re-key, covering both reasons a merge can leave the tip unfit.
    /// Admin-only (only an admin can mint); a non-admin waits — see
    /// [`rekey_pending_notice`] for what it is told meanwhile.
    ///
    /// **Staleness** — the active epoch is compromised or unusable:
    /// - its *minter* is no longer a member — a departed member controlled its
    ///   recipient list and knows its key, so it must not linger as the tip;
    /// - a *declared recipient* is no longer a member (a concurrent removal left
    ///   a stale tip); or
    /// - we hold admin standing yet cannot open it — a peer minted an epoch we
    ///   have no key for, so content is frozen under it (liveness).
    ///
    /// **Revoke fences** — replay evicted an actor whose invite was revoked
    /// concurrently with their redemption ([`acl::RekeyFence`]). They are out of
    /// the member set but still hold every epoch key sealed to them at
    /// admission, so only a mint *causally after* the revoke fences them off.
    /// Replay discharges fences it can see satisfied, so a non-empty list is
    /// exactly the outstanding work.
    ///
    /// Both are evaluated against **one** ACL snapshot and discharged by **one**
    /// rotation: a fresh mint rides the current frontier, so it descends every
    /// outstanding fence at once and is itself neither stale nor fenced. Two
    /// separately effectful heals would let the first rotate and the second
    /// mint again off a pre-rotation snapshot.
    ///
    /// Unstaggered on purpose: each observing admin may mint once, concurrent
    /// mints share a generation, `(gen, id)` selects deterministically, and the
    /// next import sees the fences discharged and stops. Bounded and convergent,
    /// the same shape the staleness heal already relied on.
    ///
    /// [`rekey_pending_notice`]: Self::rekey_pending_notice
    fn heal_epoch(&mut self) -> Result<()> {
        // Only an admin can mint, so only an admin can heal. Note this is the
        // *only* gate: `rotate_key` draws a fresh random key and seals it with
        // public device identities, so it never needs the outgoing key —
        // gating on possession would strand the admin who cannot open the tip,
        // which is precisely the `unopenable` case below.
        if !self.am_i_admin() {
            return Ok(());
        }
        let acl = self.acl_state();
        let stale = match self.active_epoch() {
            Some(active) => {
                let members: std::collections::BTreeSet<ActorId> =
                    acl.members().into_iter().map(|(a, _)| a).collect();
                let minter_gone = !members.contains(&active.minted_by);
                let recipient_gone = active.members.iter().any(|m| !members.contains(m));
                let unopenable = !self.keyring.contains_key(&active.id);
                minter_gone || recipient_gone || unopenable
            }
            // No epoch yet ⇒ nothing to be stale. A fence is still actionable.
            None => false,
        };
        if stale || !acl.rekey_fences().is_empty() {
            self.rotate_key()?;
            self.persist_membership("epoch_heal")?;
        }
        Ok(())
    }

    /// Outstanding rekey obligations this node cannot discharge itself, for the
    /// status surface. `Some` only when we are **not** an admin (an admin heals
    /// on import instead of reporting), so a plain member learns that a revoked
    /// invite's admittee still holds live keys until an admin syncs.
    ///
    /// Callers must not describe this as the invite being undone. Rotation
    /// fences *future* content only: everything encrypted under the epochs the
    /// evicted actor was sealed stays readable by them permanently (lazy
    /// revocation — see [`acl::RekeyFence`]).
    ///
    /// The wording says *may* hold *a* key, not *the current* key: which epoch
    /// is the active tip is decided by `(gen, id)` selection, and a concurrent
    /// mint the evicted actor was never sealed can win it. What we can state is
    /// that they hold a workspace key able to encrypt new content until an admin
    /// rotates past the fence.
    pub fn rekey_pending_notice(&self) -> Option<String> {
        if self.am_i_admin() {
            return None;
        }
        let acl = self.acl_state();
        let fences = acl.rekey_fences();
        if fences.is_empty() {
            return None;
        }
        let who: Vec<String> = fences.iter().map(|f| f.evicted.short()).collect();
        let (subject, verb, key) = if who.len() == 1 {
            ("was", "has", "a workspace key")
        } else {
            ("were", "have", "workspace keys")
        };
        Some(format!(
            "revoked invite: {} {subject} admitted concurrently and {verb} been \
             removed, but may still hold {key} that can encrypt new content. An \
             admin must sync to rotate the key. Content already shared remains \
             readable by them.",
            who.join(", ")
        ))
    }

    /// **Provider side.** Export the catalog ops a puller at `peer_vv` lacks,
    /// **encrypted** with the current workspace key in a blind-relay envelope.
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
    /// documents we hold, recompute their projections, and return the set of
    /// issue docs we must fetch: those we lack, or whose catalog `head` no longer
    /// matches our local issue-document head.
    pub fn import_catalog_and_compute_needs(&mut self, update: &[u8]) -> Result<Vec<DocNeed>> {
        // A non-member has no key and cannot decrypt the blind-relay envelope.
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
                // Writer-direction self-heal: the imported catalog's
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
        // in the encrypted authorization DAG. Reconcile the cached
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
    /// using writer-direction projection. Returns a dirty set for a coalesced doorbell.
    ///
    /// The activity row and the inbox are derived from the **oplog diff** around
    /// the import: field-level changes, exactly the new comments
    /// (wherever they merged in the list — CRDT-positional, not index
    /// arithmetic), the DAG concurrency flag, and the incoming changes' advisory
    /// actor claims (their commit messages travel with the ops).
    pub fn import_doc(&mut self, doc_id: &str, bytes: &[u8]) -> Result<Option<DirtySet>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // A non-member has no key and cannot decrypt the blind-relay envelope.
        let Some(bytes) = self.decrypt_payload(bytes) else {
            return Ok(None);
        };
        // Viewer-relative pre-import state for the inbox's assigned/status
        // entries: "addressed to you" is a state transition, never
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
        // A synced document advances the activity feed by pull, never by streamed rows.
        let reff = self.aliases.canonical_for(&id);
        // Attribute the row to the incoming ops' committing **device** when it
        // is unambiguous — deliberately not resolved to an actor. This is a
        // sync/commit stamp (`committedBy`), not authorship (`createdBy`): which
        // device landed the ops is the fact worth keeping when a peer misbehaves,
        // and it survives that device later leaving its actor. Advisory either
        // way — self-asserted in the commit message (non-goal 6).
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
                    // A comment's author *is* the actor, so this is a direct
                    // comparison — no device→actor resolution, which used to
                    // silently fail once the authoring device was revoked and
                    // start notifying us about our own past comments.
                    if my_actor.as_ref() == Some(&c.author) {
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
    /// A flat-FROST rotation proposal naming `t`'s CURRENT authority, so the
    /// only reason a test proposal is rejected is the thing that test is about.
    fn test_proposal(
        t: &Tracker,
        nonce: [u8; 16],
        k: u16,
        participants: Vec<UserId>,
    ) -> crate::dkg::KeyCeremonyProposal {
        let principals: Vec<crate::authority::PrincipalId> = participants
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
        crate::dkg::frost_rotation_proposal(
            nonce,
            k,
            principals,
            t.current_authority()
                .expect("a fresh node knows its solo authority"),
        )
    }

    /// Perform the custody step an indispensable arrangement requires: export a
    /// portable package, verify it by reopening, and attest on the board.
    fn attest_custody(node: &mut TestNode, tag: &str) {
        let path = node.home.join(format!("custody-{tag}.pkg"));
        let (resp, _) = node.tracker.space_custody_export_cmd(
            path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
        );
        assert!(
            matches!(resp, Response::Ok { .. }),
            "custody export: {resp:?}"
        );
    }

    fn me() -> UserId {
        // A real ed25519 key (so the founder can seal the workspace key to itself).
        crypto::user_from_seed(&ME_SEED)
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
        crypto::user_from_seed(&seed)
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
    /// genesis rooted on the verified founding proof `(salt, founder_inception)`,
    /// empty catalog/membership awaiting sync. Obtain the proof from the founder
    /// node via `founding_proof()`.
    fn new_joiner_node_as(
        user: UserId,
        seed: [u8; 32],
        ws: &str,
        proof: &([u8; 16], [u8; 32], actor::SignedEvent),
    ) -> TestNode {
        let home = std::env::temp_dir().join(format!(
            "gc-trk-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&home).unwrap();
        let store = Store::open(&home).unwrap();
        join_workspace_store(&store, ws, &proof.0, &proof.1, &proof.2).unwrap();
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
        // making an optimistic rollback race-free.
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
        // A single IssueEdit moving several fields produces one activity row.
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
        // The DocMeta row is recomputed from the issue document on every edit.
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
        // A crash between the issue commit and the head mirror leaves a
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
        // Issue.projectId is the single source of project membership; board lists
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
    /// Sync every ordered pair, `rounds` times. Nodes left out of the slice are
    /// genuinely absent: ceremonies advance on import, so a node that never
    /// syncs never contributes.
    fn sync_mesh(nodes: &mut [TestNode], rounds: usize) {
        let n = nodes.len();
        for _ in 0..rounds {
            for i in 0..n {
                for j in 0..n {
                    if i == j {
                        continue;
                    }
                    let (from, to) = if i < j {
                        let (l, r) = nodes.split_at_mut(j);
                        (&mut l[i], &mut r[0])
                    } else {
                        let (l, r) = nodes.split_at_mut(i);
                        (&mut r[0], &mut l[j])
                    };
                    sync_all(&mut from.tracker, &mut to.tracker);
                }
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
        let mut c = new_joiner_node_as(
            c_user.clone(),
            c_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );

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
        let mut b = new_joiner_node_as(
            db_user.clone(),
            db_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        // Two admins concurrently redeem the same single-use
        // invite for different actors; after merge exactly one is admitted, and
        // both replicas agree (nonce bound into the op + deterministic dedup).
        let mut a = new_node(); // founder/admin
        let a_ws = a.tracker.workspace_str();

        let mut b = new_joiner_node_as(
            user_from_seed([2; 32]),
            [2; 32],
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        // Two admins remove different members concurrently, each
        // rotating the key. Content-addressed epochs + the heal on merge must
        // converge (both admins read post-heal content) and fence both removed
        // members — no split-brain undecryptable key.
        let mut a = new_node(); // founder/admin
        with_project(&mut a.tracker);
        let a_ws = a.tracker.workspace_str();

        let mut b = new_joiner_node_as(
            user_from_seed([2; 32]),
            [2; 32],
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let mut c = new_joiner_node_as(
            user_from_seed([3; 32]),
            [3; 32],
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let mut d = new_joiner_node_as(
            user_from_seed([4; 32]),
            [4; 32],
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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

        let b_seed = [12u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user, b_seed, &a_ws, &a.tracker.founding_proof().unwrap());
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
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        a.tracker.heal_epoch().unwrap();
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

        // B joins as a plain WRITER (no admin).
        let b_seed = [41u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user, b_seed, &a_ws, &a.tracker.founding_proof().unwrap());
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
    fn a_non_founder_invite_roots_the_joiner_on_the_true_founder() {
        // Fork guard: a ticket must anchor on the workspace's founding actor, not
        // the inviter. A joiner roots acl::replay on the ticket's founder, so an
        // inviter-anchored ticket would fork the joiner onto a genesis where the
        // real founder — and the founding key-epoch — carry no authority.
        let mut a = new_node(); // founder A
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "founders-secret");
        let a_actor = a.tracker.my_actor().unwrap();
        let a_ws = a.tracker.workspace_str();

        // B joins rooted on A (as A's ticket would), admitted admin, and syncs.
        let b_seed = [51u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user, b_seed, &a_ws, &a.tracker.founding_proof().unwrap());
        let b_incept = b.tracker.self_inception().unwrap();
        let b_actor = actor_of(&b_incept);
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);
        assert!(b.tracker.am_i_member());
        // The fix: B (a non-founder) anchors an invite on the FOUNDER, not itself.
        assert_eq!(
            b.tracker.founding_actor(),
            Some(a_actor.clone()),
            "a joiner anchors on the true founder"
        );
        assert_ne!(
            b.tracker.founding_actor(),
            Some(b_actor.clone()),
            "never on the inviter"
        );

        // C joins on the founding proof B would ship (which is A's, not B's), is
        // admitted by B, and syncs through B. Rooted on A, C converges — sees the
        // founder's authority AND adopts the founder's key-epoch to read content.
        let c_seed = [52u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user, c_seed, &a_ws, &b.tracker.founding_proof().unwrap());
        let c_incept = c.tracker.self_inception().unwrap();
        b.tracker.admit_member(&c_incept, vec![Grant::Write]);
        sync_all(&mut b.tracker, &mut c.tracker);
        assert!(c.tracker.am_i_member(), "C is a member");
        assert!(
            c.tracker.acl_state().is_admin(&a_actor),
            "C sees the true founder as admin (not forked away from it)"
        );
        assert!(
            titles(&mut c.tracker).contains(&"founders-secret".to_string()),
            "C adopts the founder's key-epoch and reads founder content"
        );

        // Negative control — the fork is now CRYPTOGRAPHICALLY impossible. A
        // forged ticket that presents the inviter's own inception as the founder
        // for A's workspace is rejected at join: the self-certifying id does not
        // commit to B's device (lait/space/1), so verify_founding fails.
        let (a_salt, a_rr, _a_incept) = a.tracker.founding_proof().unwrap();
        let forged_home = std::env::temp_dir().join(format!(
            "gc-trk-{}-{}",
            std::process::id(),
            DocId::mint(&crate::ids::SystemUlidSource)
        ));
        std::fs::create_dir_all(&forged_home).unwrap();
        let forged_store = Store::open(&forged_home).unwrap();
        let err = join_workspace_store(&forged_store, &a_ws, &a_salt, &a_rr, &b_incept);
        assert!(
            err.is_err(),
            "a ticket rooting on the inviter's inception is rejected, not forked"
        );
        let _ = std::fs::remove_dir_all(&forged_home);
    }

    #[test]
    fn break_glass_recovery_re_roots_the_workspace() {
        // W5: the live admin (A) is lost/compromised. A holder restores the
        // offline workspace recovery key on a FRESH device C and recovers —
        // re-rooting the workspace to C, evicting A, convergently for all peers.
        let mut a = new_node(); // founder A; 1-of-1 space recovery key beside its store
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "old");
        let a_actor = a.tracker.my_actor().unwrap();
        let a_ws = a.tracker.workspace_str();

        // Fresh device C bootstraps on A's workspace (verifies the founding), then
        // syncs the state from a survivor (here A) — the realistic break-glass
        // flow: pull the workspace, then re-root.
        let c_seed = [71u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user, c_seed, &a_ws, &a.tracker.founding_proof().unwrap());
        sync_all(&mut a.tracker, &mut c.tracker);

        // The offline recovery key is restored beside C's store.
        std::fs::copy(
            a.home.join("space-recovery.key"),
            c.home.join("space-recovery.key"),
        )
        .unwrap();

        // C recovers: the solo recovery key re-roots the space to C.
        let (resp, _) = c.tracker.space_recover_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let c_actor = c.tracker.my_actor().unwrap();
        assert!(
            c.tracker.acl_state().is_admin(&c_actor),
            "the recovered device is the new root admin"
        );
        assert!(
            !c.tracker.acl_state().is_admin(&a_actor),
            "the old root no longer holds authority"
        );

        // Convergent: A syncs C's recovery and agrees it is no longer the root.
        sync_all(&mut c.tracker, &mut a.tracker);
        assert!(
            a.tracker.acl_state().is_admin(&c_actor) && !a.tracker.acl_state().is_admin(&a_actor),
            "every replica converges on the recovered root"
        );
    }

    #[test]
    fn elevate_solo_recovery_to_a_2_of_2_dkg_group_key() {
        // W5 elevation (the "airplane" story): A founds solo with a bootstrap
        // recovery key, later adds co-founder B and elevates the recovery authority
        // to a 2-of-2 FROST group key via a DKG that rides the synced bulletin
        // board — no dealer, no secret ever leaves its holder.
        let mut a = new_node(); // founder A, holds solo space-recovery.key
        with_project(&mut a.tracker);
        let a_ws = a.tracker.workspace_str();
        let commit0 = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        )
        .recovery_commit;

        // Co-founder B joins and is admitted; both sync.
        let b_seed = [81u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);

        // A elevates to a 2-of-2 over {A, B}.
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // Drive the DKG to a fixpoint via sync round-trips (each import advances).
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }

        // The recovery authority is now the DKG group key, not A's solo key.
        let after = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert!(!after.recovered); // no re-root happened, only a Rotate
        assert_ne!(
            after.recovery_commit, commit0,
            "the recovery authority rotated to the group key"
        );
        // Both replicas converge on the same new authority.
        let b_after = crate::space::replay(
            &b.tracker.genesis,
            &b.tracker.workspace_id,
            &b.tracker.membership.space_events(),
        );
        assert_eq!(after.recovery_commit, b_after.recovery_commit);

        // The standing arrangement is replicated on the space plane, not just the key. Both
        // replicas agree on it, it is no longer `Single`, and it is the exact
        // 2-of-2 configuration the elevation built — learnable by replay without
        // holding a share.
        assert_eq!(after.configuration, b_after.configuration);
        assert_ne!(
            after.configuration,
            crate::authority::AuthorityConfigurationId::single(),
            "the workspace is no longer a solo authority"
        );
        let dkg = a.tracker.standing_dkg_session().expect("standing group");
        let expected = a
            .tracker
            .dkg_manifest(&dkg)
            .expect("manifest")
            .configuration
            .id();
        assert_eq!(
            after.configuration, expected,
            "the on-plane configuration is the arrangement the ceremony produced"
        );

        // A's solo key is retired: recovery now runs through the group ceremony,
        // and a lone holder cannot meet the 2-of-2 threshold by itself.
        let (resp, _) = a.tracker.space_recover_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let still = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert!(
            !still.recovered,
            "one holder alone cannot complete a 2-of-2 group recovery"
        );
    }

    /// Content-derived transcript ids make concurrency visible: two holders
    /// independently requesting the same recovery author different nodes, so they
    /// open different transcripts and commitments would split across both.
    /// Holders converge on the lowest id.
    #[test]
    fn concurrent_signing_requests_converge_on_the_lowest_transcript() {
        let a = new_node();
        let authority = crate::dkg::TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let op_bytes = vec![1u8, 2, 3];
        let mk = |nonce: [u8; 16]| crate::dkg::CeremonyOp::SignRequest {
            nonce,
            authority,
            target: crate::dkg::SignTarget::SpaceOp,
            coordinator: a.tracker.me.clone(),
            op: op_bytes.clone(),
        };
        let e1 = crate::dkg::sign_ceremony(&[1u8; 32], &mk([1u8; 16]), &a.tracker.workspace_id);
        let e2 = crate::dkg::sign_ceremony(&[2u8; 32], &mk([2u8; 16]), &a.tracker.workspace_id);
        let (id1, id2) = (
            crate::dkg::TranscriptId::of(&e1).unwrap(),
            crate::dkg::TranscriptId::of(&e2).unwrap(),
        );
        assert_ne!(id1, id2, "distinct authors open distinct transcripts");
        a.tracker.membership.add_ceremony_event(&e1).unwrap();
        a.tracker.membership.add_ceremony_event(&e2).unwrap();

        let events = a.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &a.tracker.workspace_id);
        let chosen = a
            .tracker
            .canonical_signing_session(
                &board,
                &authority,
                crate::dkg::SignTarget::SpaceOp,
                &op_bytes,
                2,
            )
            .expect("one of the two");
        assert_eq!(chosen, id1.min(id2), "the lowest id wins");
    }

    /// The tie-break is a preference, not an override. Abandoning a transcript
    /// that is one share from completing, in favour of a lower one that may
    /// never gather K, is the wrong trade for break-glass — and correctness never
    /// depended on it, since both sign gen+1 and the space plane's monotonicity
    /// guard rejects the loser.
    #[test]
    fn a_signing_transcript_at_threshold_beats_a_lower_incomplete_one() {
        let a = new_node();
        let authority = crate::dkg::TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
        let op_bytes = vec![1u8, 2, 3];
        let mk = |nonce: [u8; 16]| crate::dkg::CeremonyOp::SignRequest {
            nonce,
            authority,
            target: crate::dkg::SignTarget::SpaceOp,
            coordinator: a.tracker.me.clone(),
            op: op_bytes.clone(),
        };
        let e1 = crate::dkg::sign_ceremony(&[1u8; 32], &mk([1u8; 16]), &a.tracker.workspace_id);
        let e2 = crate::dkg::sign_ceremony(&[2u8; 32], &mk([2u8; 16]), &a.tracker.workspace_id);
        let (id1, id2) = (
            crate::dkg::TranscriptId::of(&e1).unwrap(),
            crate::dkg::TranscriptId::of(&e2).unwrap(),
        );
        let (low, high) = if id1 < id2 { (id1, id2) } else { (id2, id1) };
        a.tracker.membership.add_ceremony_event(&e1).unwrap();
        a.tracker.membership.add_ceremony_event(&e2).unwrap();
        // Two shares land on the HIGHER transcript, reaching a threshold of 2.
        for seed in [[3u8; 32], [4u8; 32]] {
            let ev = crate::dkg::sign_ceremony(
                &seed,
                &crate::dkg::CeremonyOp::SignRound2 {
                    signing: high,
                    share: vec![0u8; 32],
                },
                &a.tracker.workspace_id,
            );
            a.tracker.membership.add_ceremony_event(&ev).unwrap();
        }

        let events = a.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &a.tracker.workspace_id);
        let chosen = a
            .tracker
            .canonical_signing_session(
                &board,
                &authority,
                crate::dkg::SignTarget::SpaceOp,
                &op_bytes,
                2,
            )
            .unwrap();
        assert_eq!(chosen, high, "a transcript at threshold is not abandoned");
        assert_ne!(chosen, low);
    }

    /// A FROST nonce may produce a share for exactly one signing
    /// package. Producing shares for two under one nonce gives two equations in
    /// one unknown and yields the holder's signing share — so if the package has
    /// moved since we committed, the signer must refuse rather than sign.
    ///
    /// Drives a real 2-of-2 group to the point where a nonce record exists, then
    /// repoints the record's binding as a package change would, and asserts no
    /// second share is ever published.
    #[test]
    fn a_nonce_bound_to_another_package_refuses_to_sign() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);

        // Elevate {A, B} to a 2-of-2 group recovery key.
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }

        // B opens a break-glass recovery: this commits B's nonces.
        let (resp, _) = b.tracker.space_recover_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let events = b.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &b.tracker.workspace_id);
        let signing = *board.signing.keys().next().expect("B opened a request");
        let raw = b
            .tracker
            .dkg_read(&signing, "nonce")
            .expect("B committed nonces");
        let mut pending: crate::dkg::PendingNonce = postcard::from_bytes(&raw).unwrap();

        // Pin the record to a package B will never see — exactly what a shifted
        // signer set or a changed message would produce.
        pending.binding = [0xAB; 32];
        b.tracker
            .dkg_write(&signing, "nonce", &postcard::to_stdvec(&pending).unwrap())
            .unwrap();

        // A consents, so the signer set completes and B would otherwise sign.
        let b_actor = b.tracker.my_actor().unwrap();
        for _ in 0..4 {
            sync_all(&mut b.tracker, &mut a.tracker);
            sync_all(&mut a.tracker, &mut b.tracker);
        }
        let (resp, _) = a
            .tracker
            .space_recover_approve_cmd(signing.to_hex(), vec![b_actor.as_str().to_string()]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }

        // B published no share, and the nonce record survives — the refusal is
        // the comparison, not the deletion, precisely so a crash between
        // publishing and deleting cannot re-open the door.
        let events = b.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &b.tracker.workspace_id);
        let b_shares = board.signing[&signing]
            .rounds
            .iter()
            .filter(|v| {
                v.author == b.tracker.me
                    && matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. })
            })
            .count();
        assert_eq!(
            b_shares, 0,
            "a nonce pinned to a different package must never produce a share"
        );
        assert!(
            b.tracker.dkg_read(&signing, "nonce").is_some(),
            "the record is kept for inspection rather than silently replaced"
        );
    }

    /// A share protected under a different Windows account is *present*, not
    /// absent — the holder exists and cannot act. Break-glass recovery must say
    /// which of those it is, because for an N-of-N group it is the difference
    /// between a degraded holder and an unrecoverable workspace.
    #[test]
    fn an_unreadable_share_is_reported_as_degraded_not_absent() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let dkg_id = b.tracker.active_dkg_session().expect("B holds a share");
        assert!(
            b.tracker.degraded_recovery_holders().is_empty(),
            "a healthy holder reports nothing"
        );

        // Simulate a store restored onto another Windows account: the bytes are
        // present and wrapped, but this identity cannot open them.
        let mut corrupt = b"lait-dpapi-1\n".to_vec();
        corrupt.extend_from_slice(&[0xAB; 96]);
        std::fs::write(b.tracker.dkg_path(&dkg_id, "share"), &corrupt).unwrap();

        // The share is neither usable nor absent, and is named as such.
        assert!(matches!(
            b.tracker.dkg_artifact(&dkg_id, "share"),
            ArtifactRead::Unreadable(_)
        ));
        let reported = b.tracker.degraded_recovery_holders();
        assert_eq!(reported.len(), 1, "one degraded transcript");
        assert_eq!(
            reported[0].transcript,
            dkg_id.to_hex(),
            "named by transcript"
        );
        assert!(
            matches!(
                reported[0].reason,
                RecoveryArtifactFailure::Undecryptable(_)
            ),
            "an undecryptable wrap is reported as such"
        );
        assert_eq!(
            reported[0].is_current_authority,
            Some(true),
            "the public-key package is portable, so currency is still provable \
             after the share becomes unreadable"
        );

        // Break-glass tells the operator what actually happened rather than
        // "no way to recover from this device".
        let (resp, _) = b.tracker.space_recover_cmd();
        match resp {
            Response::Error { message, .. } => {
                assert!(
                    message.contains("another Windows account"),
                    "must name the actual cause: {message}"
                );
                assert!(
                    message.contains("current recovery key"),
                    "must say this share is for the live authority: {message}"
                );
                assert!(
                    message.contains(&dkg_id.to_hex()),
                    "must name the transcript: {message}"
                );
                assert!(
                    message.contains("cannot take part in recovery"),
                    "must say what THIS device can do: {message}"
                );
                assert!(
                    !message.contains("can still recover the workspace"),
                    "must not claim other holders can recover — this device cannot know that: {message}"
                );
            }
            other => panic!("expected a typed failure, got {other:?}"),
        }
    }

    /// A share belonging to a group that is **not** the workspace's recovery
    /// authority is not a recovery problem: it could not recover this workspace
    /// even if it were readable. Announcing it as "a share for the workspace
    /// recovery key" would be false, so currency is established from the
    /// public-key package before anything is reported.
    #[test]
    fn an_unreadable_share_for_another_group_is_not_reported() {
        let mut a = new_node();

        // A real 2-of-2 DKG for a group unrelated to this workspace, so its
        // public-key package parses and derives a group key that is genuinely
        // not the standing recovery authority.
        let (s1_a, p1_a) = crate::dkg::dkg_round1(1, 2, 2).unwrap();
        let (s1_b, p1_b) = crate::dkg::dkg_round1(2, 2, 2).unwrap();
        let others_a: crate::dkg::Packages = [(2u16, p1_b.clone())].into_iter().collect();
        let others_b: crate::dkg::Packages = [(1u16, p1_a.clone())].into_iter().collect();
        let (s2_a, out_a) = crate::dkg::dkg_round2(&s1_a, &others_a).unwrap();
        let (_s2_b, out_b) = crate::dkg::dkg_round2(&s1_b, &others_b).unwrap();
        let to_a: crate::dkg::Packages = [(2u16, out_b[&1].clone())].into_iter().collect();
        let (_share, pkp, foreign_group) = crate::dkg::dkg_round3(&s2_a, &others_a, &to_a).unwrap();
        let _ = out_a;
        assert_ne!(
            crate::space::recovery_commit(&foreign_group),
            Some(
                crate::space::replay(
                    &a.tracker.genesis,
                    &a.tracker.workspace_id,
                    &a.tracker.membership.space_events(),
                )
                .recovery_commit
            ),
            "the fixture group is not this workspace's authority"
        );

        // Put a transcript for it on the board so it is a candidate at all.
        let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(
            &a.tracker,
            [5u8; 16],
            2,
            vec![a.tracker.me.clone(), user_from_seed([31u8; 32])],
        ));
        let ev = crate::dkg::sign_ceremony(&[31u8; 32], &propose, &a.tracker.workspace_id);
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.persist_membership("foreign").unwrap();

        // Its package is readable; its share is not.
        a.tracker.dkg_write_portable(&id, "pkp", &pkp).unwrap();
        let mut corrupt = b"lait-dpapi-1\n".to_vec();
        corrupt.extend_from_slice(&[0xAB; 96]);
        std::fs::write(a.tracker.dkg_path(&id, "share"), &corrupt).unwrap();
        assert!(matches!(
            a.tracker.dkg_artifact(&id, "share"),
            ArtifactRead::Unreadable(_)
        ));

        assert!(
            a.tracker.degraded_recovery_holders().is_empty(),
            "a share for another group must not be announced as the workspace recovery key"
        );

        // But if the package itself cannot be read, currency is UNKNOWN — and an
        // unknown share is reported rather than silently dropped.
        std::fs::write(a.tracker.dkg_path(&id, "pkp"), &corrupt).unwrap();
        let reported = a.tracker.degraded_recovery_holders();
        assert_eq!(reported.len(), 1, "unprovable currency is still surfaced");
        assert_eq!(
            reported[0].is_current_authority, None,
            "and is reported as undetermined rather than asserted either way"
        );
    }

    /// An I/O failure is not an account mismatch. Diagnosing every read failure
    /// as DPAPI identity would send an operator to the wrong remedy.
    #[test]
    fn an_io_failure_is_not_diagnosed_as_an_account_mismatch() {
        let dir = std::env::temp_dir().join(format!("lait-io-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        crate::secretfs::create_private_dir(&dir).unwrap();
        // A directory where a file is expected: present, but unreadable for a
        // filesystem reason rather than a cryptographic one.
        let path = dir.join("share");
        std::fs::create_dir(&path).unwrap();
        match crate::secretfs::read_private(&path) {
            Err(crate::secretfs::SecretError::Io(_)) => {}
            other => panic!("expected a typed Io failure, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node that cannot mint must be TOLD it is waiting on one. The automatic
    /// repair covers admins; a plain member observing a revoke-fenced eviction
    /// has no way to discharge the fence itself, and until now nothing said so.
    ///
    /// This is the accessor the diagnose `keys` gate reads, so it is worth
    /// pinning that it actually fires rather than being permanently `None`.
    #[test]
    fn a_non_admin_is_told_a_rekey_is_pending() {
        let mut a = new_node(); // founder/admin A
        with_project(&mut a.tracker);
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();

        // B is a second ADMIN (so it can redeem), C a plain writer.
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let mut c = new_joiner_node_as(user_from_seed(c_seed), c_seed, &a_ws, &proof);
        let b_incept = b.tracker.self_inception().unwrap();
        let c_incept = c.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        a.tracker.admit_member(&c_incept, vec![Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut a.tracker, &mut c.tracker);
        assert!(!c.tracker.am_i_admin(), "C cannot mint");
        assert!(
            c.tracker.rekey_pending_notice().is_none(),
            "nothing pending in the steady state"
        );

        // PARTITION: B redeems an invite that A concurrently revokes.
        let nonce = [7u8; 16];
        let x_incept = incept_for([61u8; 32], &b.tracker);
        let x_actor = actor_of(&x_incept);
        let (resp, _) = b.tracker.redeem_invite(&b_user, &x_incept, &nonce, true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let (resp, _) = a
            .tracker
            .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // C observes BOTH branches before any admin has rotated past the fence.
        sync_membership(&mut b.tracker, &mut c.tracker);
        sync_membership(&mut a.tracker, &mut c.tracker);

        assert!(
            !c.tracker.is_member_actor(&x_actor),
            "revoke wins on C as well"
        );
        let notice = c
            .tracker
            .rekey_pending_notice()
            .expect("C cannot discharge the fence and must be told");
        assert!(
            notice.contains(&x_actor.short()),
            "names the evicted actor: {notice}"
        );
        assert!(
            notice.contains("admin must sync"),
            "says who can fix it: {notice}"
        );
        assert!(
            notice.contains("already shared"),
            "states the residual — rotation fences future content only: {notice}"
        );

        // Once an admin rotates past the fence, the notice clears.
        sync_membership(&mut b.tracker, &mut a.tracker);
        sync_membership(&mut a.tracker, &mut c.tracker);
        assert!(
            c.tracker.rekey_pending_notice().is_none(),
            "a discharged fence stops warning"
        );
    }

    /// A proposal names the authority it replaces, so one authorized under a
    /// past authority cannot be replayed against the current one. Without this,
    /// a grant would mean "some ceremony may run" rather than "this ceremony may
    /// replace this exact authority".
    #[test]
    fn a_proposal_naming_the_wrong_authority_is_rejected() {
        let mut a = new_node();
        let secret = a.tracker.read_space_recovery_key().expect("solo key");

        // A well-formed proposal whose `current` is some other authority.
        let stranger = crate::authority::AuthorityId::single(user_from_seed([123u8; 32]));
        let principals = {
            let mut v: Vec<crate::authority::PrincipalId> =
                [a.tracker.me.clone(), user_from_seed([44u8; 32])]
                    .iter()
                    .map(crate::authority::PrincipalId::of_device)
                    .collect();
            v.sort();
            v
        };
        let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
            [6u8; 16], 2, principals, stranger,
        ));
        let ev = crate::dkg::sign_ceremony(&[44u8; 32], &propose, &a.tracker.workspace_id);
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        // Authorized by the REAL recovery key: only the named authority is wrong.
        let grant = crate::dkg::sign_authority_grant(&secret, &a.tracker.workspace_id, &id);
        let aev = crate::dkg::sign_ceremony(
            &[44u8; 32],
            &crate::dkg::CeremonyOp::DkgAuthorize(grant),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("wrong_authority").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&id).is_none(),
            "a proposal must name the authority it actually replaces"
        );
    }

    /// Acceptance checks the arrangement against the replicated standing
    /// configuration, so a proposal naming the correct key but the wrong
    /// configuration is rejected — the case the old key-alone acceptance let
    /// through, and the one that had to close before same-key transitions.
    #[test]
    fn a_proposal_with_the_right_key_but_wrong_configuration_is_rejected() {
        let mut a = new_node();
        let secret = a.tracker.read_space_recovery_key().expect("solo key");
        let standing = a.tracker.current_authority().expect("solo authority");

        // Same key (the real standing solo key), but claim it is operated by a
        // group arrangement it is not.
        let mut members: Vec<crate::authority::PrincipalId> =
            [a.tracker.me.clone(), user_from_seed([44u8; 32])]
                .iter()
                .map(crate::authority::PrincipalId::of_device)
                .collect();
        members.sort();
        let lying_cfg = crate::authority::AuthorityConfiguration::frost_threshold(
            &crate::authority::FrostThresholdConfig {
                k: 2,
                participants: members.clone(),
            },
        );
        let lie = crate::authority::AuthorityId::new(standing.public_key.clone(), &lying_cfg);
        assert_eq!(
            crate::space::recovery_commit(&lie.public_key),
            crate::space::recovery_commit(&standing.public_key),
            "the KEY is genuinely the standing one"
        );
        assert_ne!(
            lie.configuration, standing.configuration,
            "only the claimed arrangement differs"
        );

        let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
            [6u8; 16], 2, members, lie,
        ));
        let ev = crate::dkg::sign_ceremony(&[44u8; 32], &propose, &a.tracker.workspace_id);
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        let grant = crate::dkg::sign_authority_grant(&secret, &a.tracker.workspace_id, &id);
        let aev = crate::dkg::sign_ceremony(
            &[44u8; 32],
            &crate::dkg::CeremonyOp::DkgAuthorize(grant),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("wrong_config").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&id).is_none(),
            "a proposal must name the standing configuration, not just the standing key"
        );
    }

    /// `Reshare` keeps the public key and changes only the arrangement. It needs
    /// a protocol that never reconstructs the secret, which does not exist yet —
    /// so the variant round-trips in the format but must never be acted on.
    /// Accepting one would promise a transition the code cannot perform.
    #[test]
    fn a_reshare_proposal_is_refused_until_the_protocol_exists() {
        let mut a = new_node();
        let secret = a.tracker.read_space_recovery_key().expect("solo key");
        let current = a.tracker.current_authority().expect("solo authority");
        let mut principals: Vec<crate::authority::PrincipalId> =
            [a.tracker.me.clone(), user_from_seed([45u8; 32])]
                .iter()
                .map(crate::authority::PrincipalId::of_device)
                .collect();
        principals.sort();

        let proposal = crate::dkg::KeyCeremonyProposal {
            nonce: [7u8; 16],
            configuration: crate::authority::AuthorityConfiguration::frost_threshold(
                &crate::authority::FrostThresholdConfig {
                    k: 2,
                    participants: principals,
                },
            ),
            transition: crate::dkg::ProposedTransition::Reshare { authority: current },
        };
        // Everything else is impeccable: well-formed configuration, real grant.
        assert!(proposal.configuration.is_well_formed());
        assert!(
            proposal.frost_config().is_none(),
            "an unimplemented transition yields no usable configuration"
        );

        let ev = crate::dkg::sign_ceremony(
            &[45u8; 32],
            &crate::dkg::CeremonyOp::DkgPropose(proposal),
            &a.tracker.workspace_id,
        );
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        let grant = crate::dkg::sign_authority_grant(&secret, &a.tracker.workspace_id, &id);
        let aev = crate::dkg::sign_ceremony(
            &[45u8; 32],
            &crate::dkg::CeremonyOp::DkgAuthorize(grant),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("reshare").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&id).is_none() && a.tracker.dkg_read(&id, "r1").is_none(),
            "resharing must not be attempted before a same-key protocol exists"
        );
    }

    /// B3 + B4 end to end: a standing GROUP authorizes its own replacement and
    /// signs the rotation that installs it.
    ///
    /// This is the lifecycle the one-way door used to block. Nothing here can be
    /// done by a solo key: the current authority is a group, so the grant needs
    /// a threshold signature (B3) and so does the rotation (B4).
    #[test]
    fn a_group_authorizes_and_installs_its_own_replacement() {
        let mut a = new_node(); // founder, holds the bootstrap solo key
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();

        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user.clone(), c_seed, &a_ws, &proof);
        for incept in [
            b.tracker.self_inception().unwrap(),
            c.tracker.self_inception().unwrap(),
        ] {
            a.tracker
                .admit_member(&incept, vec![Grant::Admin, Grant::Write]);
        }
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut a.tracker, &mut c.tracker);

        // ---- solo → group: {A, B} 2-of-2.
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..8 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let after_first = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert_eq!(after_first.gen, 1, "the 2-of-2 group key is installed");
        let first_authority = a
            .tracker
            .current_authority()
            .expect("A can attribute the standing key");
        assert_eq!(
            first_authority.public_key,
            a.tracker
                .group_key_of_transcript(&a.tracker.active_dkg_session().unwrap())
                .unwrap(),
            "the standing authority IS the group we just built"
        );

        // ---- group → group: {A, B, C} 2-of-3, proposed by a group holder.
        // A no longer has a usable solo key, so this can only proceed by
        // threshold authorization.
        let (resp, _) = a.tracker.space_elevate_cmd(
            vec![b_user.as_str().to_string(), c_user.as_str().to_string()],
            2,
        );
        let msg = match resp {
            Response::Ok { message: Some(m) } => m,
            other => panic!("expected a pending group authorization, got {other:?}"),
        };
        assert!(
            msg.contains("elevate-approve"),
            "a group elevation must ask the other holders to authorize: {msg}"
        );

        // Pull the request and the proposal ids off the verified board.
        let events = a.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &a.tracker.workspace_id);
        let (signing, proposal) = board
            .signing
            .iter()
            .find_map(|(id, t)| match &t.request.as_ref()?.op {
                crate::dkg::CeremonyOp::SignRequest {
                    target: crate::dkg::SignTarget::AuthorityGrant,
                    op,
                    ..
                } => {
                    let g: crate::dkg::AuthorityGrant = postcard::from_bytes(op).ok()?;
                    Some((*id, g.proposal))
                }
                _ => None,
            })
            .expect("A opened a grant request");

        // B, the other current holder, must consent — and consent binds to the
        // proposal, not to an opaque session id.
        for _ in 0..4 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let (bad, _) = b
            .tracker
            .space_elevate_approve_cmd(signing.to_hex(), "f".repeat(64));
        assert!(
            matches!(bad, Response::Error { .. }),
            "approving a session while naming the wrong proposal must be refused: {bad:?}"
        );
        let (resp, _) = b
            .tracker
            .space_elevate_approve_cmd(signing.to_hex(), proposal.to_hex());
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // Everything else is automatic: the group signs the grant, the new DKG
        // runs, the group signs the rotation, the plane installs it.
        for _ in 0..8 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut c.tracker);
            sync_all(&mut c.tracker, &mut a.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
            sync_all(&mut c.tracker, &mut b.tracker);
            sync_all(&mut a.tracker, &mut c.tracker);
        }

        let after_second = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert_eq!(
            after_second.gen, 2,
            "the group authorized and installed its own replacement"
        );
        assert_ne!(
            after_second.recovery_commit, after_first.recovery_commit,
            "rotation produces a DIFFERENT key — this is not a reshare"
        );

        // C, who held no share of the old group, holds one of the new authority.
        let c_authority = c
            .tracker
            .current_authority()
            .expect("C can attribute the standing key");
        assert_eq!(
            c_authority.public_key.as_str(),
            a.tracker.current_authority().unwrap().public_key.as_str(),
            "every holder agrees on the standing authority"
        );
        let c_cfg = c
            .tracker
            .dkg_manifests()
            .into_iter()
            .find(|(id, _)| {
                c.tracker.group_key_of_transcript(id).as_ref() == Some(&c_authority.public_key)
            })
            .map(|(_, m)| m.configuration)
            .expect("C accepted the ceremony that produced it");
        let frost = c_cfg.as_frost_threshold().unwrap();
        assert_eq!(
            (frost.k, frost.participants.len()),
            (2, 3),
            "the new arrangement is the 2-of-3 that was proposed"
        );
    }

    /// B6: **any** available K can sign, not a predetermined K.
    ///
    /// The old rule fixed the signer set to the `threshold` lowest-index
    /// holders, so a 2-of-3 could not recover without holder #1 — which is not
    /// threshold availability in any useful sense. This drives a recovery with
    /// holder #1 deliberately absent: it never syncs, so it never contributes.
    #[test]
    fn any_k_of_n_can_sign_without_the_lowest_index_holder() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user.clone(), c_seed, &a_ws, &proof);
        for incept in [
            b.tracker.self_inception().unwrap(),
            c.tracker.self_inception().unwrap(),
        ] {
            a.tracker
                .admit_member(&incept, vec![Grant::Admin, Grant::Write]);
        }
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut a.tracker, &mut c.tracker);

        // A 2-of-3 group over {A, B, C}.
        let (resp, _) = a.tracker.space_elevate_cmd(
            vec![b_user.as_str().to_string(), c_user.as_str().to_string()],
            2,
        );
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let mut nodes = vec![a, b, c];
        sync_mesh(&mut nodes, 8);
        assert_eq!(
            crate::space::replay(
                &nodes[0].tracker.genesis,
                &nodes[0].tracker.workspace_id,
                &nodes[0].tracker.membership.space_events(),
            )
            .gen,
            1,
            "the 2-of-3 group key is installed"
        );

        // Participant index is position in the sorted device list, so sorting
        // the nodes the same way tells us who holder #1 is.
        nodes.sort_by(|x, y| x.tracker.me.as_str().cmp(y.tracker.me.as_str()));
        let absent = nodes.remove(0); // index 1 — the one the old rule required
        assert_eq!(nodes.len(), 2, "two holders remain: exactly the threshold");

        // The remaining two recover, with #1 never syncing again.
        let recovering = nodes[0].tracker.my_actor().unwrap();
        let (resp, _) = nodes[0].tracker.space_recover_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_mesh(&mut nodes, 3);

        let events = nodes[1].tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &nodes[1].tracker.workspace_id);
        let session = *board
            .signing
            .keys()
            .next()
            .expect("a recovery request reached the other holder");
        let (resp, _) = nodes[1]
            .tracker
            .space_recover_approve_cmd(session.to_hex(), vec![recovering.as_str().to_string()]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_mesh(&mut nodes, 8);

        let after = crate::space::replay(
            &nodes[0].tracker.genesis,
            &nodes[0].tracker.workspace_id,
            &nodes[0].tracker.membership.space_events(),
        );
        assert!(
            after.recovered && after.root == vec![recovering.clone()],
            "two of three signed a recovery without holder #1"
        );

        // And the plan says so: the chosen signers are indices 2 and 3.
        let events = nodes[0].tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &nodes[0].tracker.workspace_id);
        let plan = board
            .signing
            .values()
            .find_map(|t| t.plan())
            .expect("the coordinator published a plan");
        let crate::dkg::AccessWitness::FrostThreshold {
            k,
            participant_indices,
        } = &plan.witness
        else {
            panic!("flat FROST witness expected");
        };
        assert_eq!(*k, 2);
        assert_eq!(
            participant_indices,
            &vec![2u16, 3u16],
            "the signer set excludes holder #1 — the point of any-K"
        );
        drop(absent);
    }

    /// B7: an indispensable arrangement must not install until every custodian
    /// has verified a portable backup.
    ///
    /// The failure this prevents is silent and delayed: an N-of-N group created
    /// while one holder's share exists only behind a Windows profile looks
    /// perfectly healthy, and the workspace finds out on the day it needs to
    /// recover. So the gate reads signed attestations from the board — local
    /// state would let another node install ahead of the checks.
    #[test]
    fn an_indispensable_arrangement_waits_for_verified_custody() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);

        let commit0 = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        )
        .recovery_commit;

        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..8 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }

        // The DKG is complete — both hold shares — but nothing has installed.
        let dkg = *crate::dkg::parse_board(
            &a.tracker.membership.ceremony_events(),
            &a.tracker.workspace_id,
        )
        .dkg
        .keys()
        .next()
        .unwrap();
        assert!(a.tracker.dkg_read(&dkg, "share").is_some());
        assert!(b.tracker.dkg_read(&dkg, "share").is_some());
        assert_eq!(
            crate::space::replay(
                &a.tracker.genesis,
                &a.tracker.workspace_id,
                &a.tracker.membership.space_events(),
            )
            .recovery_commit,
            commit0,
            "an indispensable arrangement must not install on unverified custody"
        );

        // Status says exactly why, rather than reporting a healthy holder.
        assert_eq!(
            a.tracker.recovery_status().local_custody,
            LocalCustodyState::BackupUnverified,
            "holding a share is not the same as being able to keep it"
        );

        // One custodian attests: still blocked, because ALL are required.
        attest_custody(&mut a, "a");
        for _ in 0..4 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        assert_eq!(
            crate::space::replay(
                &a.tracker.genesis,
                &a.tracker.workspace_id,
                &a.tracker.membership.space_events(),
            )
            .recovery_commit,
            commit0,
            "one of two attestations is not enough for an N-of-N arrangement"
        );

        // Both attest: it installs.
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        assert_ne!(
            crate::space::replay(
                &a.tracker.genesis,
                &a.tracker.workspace_id,
                &a.tracker.membership.space_events(),
            )
            .recovery_commit,
            commit0,
            "with every custodian verified, the arrangement installs"
        );
        assert_eq!(
            a.tracker.recovery_status().local_custody,
            LocalCustodyState::Ready
        );
        let st = a.tracker.recovery_status();
        assert_eq!((st.k, st.n), (2, 2));
        assert_eq!(st.scheme, crate::authority::AuthorityScheme::FrostThreshold);
    }

    /// A redundant arrangement is NOT gated: tolerating a lost holder is what
    /// redundancy means, so requiring every custodian to attest would impose a
    /// cost the shape does not need.
    #[test]
    fn a_redundant_arrangement_installs_without_universal_attestation() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user.clone(), c_seed, &a_ws, &proof);
        for incept in [
            b.tracker.self_inception().unwrap(),
            c.tracker.self_inception().unwrap(),
        ] {
            a.tracker
                .admit_member(&incept, vec![Grant::Admin, Grant::Write]);
        }
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut a.tracker, &mut c.tracker);

        let (resp, _) = a.tracker.space_elevate_cmd(
            vec![b_user.as_str().to_string(), c_user.as_str().to_string()],
            2, // 2-of-3: one holder may be lost
        );
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let mut nodes = vec![a, b, c];
        sync_mesh(&mut nodes, 8);
        assert_eq!(
            crate::space::replay(
                &nodes[0].tracker.genesis,
                &nodes[0].tracker.workspace_id,
                &nodes[0].tracker.membership.space_events(),
            )
            .gen,
            1,
            "a redundant arrangement installs without attestation"
        );
        assert_eq!(
            nodes[0].tracker.recovery_status().local_custody,
            LocalCustodyState::Ready,
            "and its holders are Ready, not BackupUnverified"
        );
    }

    /// A custody backup must be restorable, not merely preserved.
    ///
    /// Simulates the case the whole custody design exists for: a holder loses
    /// its local material (account or machine gone) and comes back with the
    /// portable package. Before the import path existed, the share survived and
    /// the product still could not resume signing with it.
    #[test]
    fn a_lost_share_is_restored_from_its_portable_package() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let dkg = b.tracker.standing_dkg_session().expect("standing group");

        // B exports a portable package, then loses its local material.
        let pkg_path = b.home.join("rescue.pkg");
        let (resp, _) = b.tracker.space_custody_export_cmd(
            pkg_path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
        );
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        // Only the SHARE goes. The public-key package is stored portable exactly
        // so it survives an account change — which is what lets this device still
        // say which group it belongs to after losing the ability to sign for it.
        std::fs::remove_file(b.tracker.dkg_path(&dkg, "share")).unwrap();

        // Report the lost share as missing rather than claiming this device is
        // not a holder; the arrangement's real shape must survive the loss.
        let st = b.tracker.recovery_status();
        assert_eq!(
            st.local_custody,
            LocalCustodyState::Missing,
            "a holder whose standing share vanished is Missing, not NotAHolder"
        );
        assert_eq!(
            (st.k, st.n),
            (2, 2),
            "the standing arrangement's shape does not collapse to 1-of-1"
        );
        assert!(
            b.tracker.active_dkg_session().is_none(),
            "and it cannot sign"
        );

        // The package brings it back.
        let (resp, _) = b.tracker.space_custody_import_cmd(
            pkg_path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
            false,
        );
        assert!(matches!(resp, Response::Ok { .. }), "restore: {resp:?}");
        assert_eq!(
            b.tracker.recovery_status().local_custody,
            LocalCustodyState::Ready
        );
        assert_eq!(
            b.tracker.active_dkg_session(),
            Some(dkg),
            "the restored holder can sign again"
        );

        // Re-importing over usable material is refused unless forced, so a
        // mistaken run cannot turn a working device into the loss it prevents.
        let (resp, _) = b.tracker.space_custody_import_cmd(
            pkg_path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
            false,
        );
        assert!(
            matches!(resp, Response::Error { .. }),
            "must not clobber a readable share: {resp:?}"
        );
        let (resp, _) = b.tracker.space_custody_import_cmd(
            pkg_path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
            true,
        );
        assert!(matches!(resp, Response::Ok { .. }), "forced: {resp:?}");

        // A wrong passphrase restores nothing.
        let (resp, _) = b.tracker.space_custody_import_cmd(
            pkg_path.to_string_lossy().to_string(),
            "not-the-right-passphrase".into(),
            true,
        );
        assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

        // Losing the public package too is a harder case, and the honest answer
        // is that this device can no longer tell which group it belonged to —
        // so it reports NotAHolder rather than inventing a shape. The package
        // still restores it, because the package carries its own public half.
        std::fs::remove_file(b.tracker.dkg_path(&dkg, "share")).unwrap();
        std::fs::remove_file(b.tracker.dkg_path(&dkg, "pkp")).unwrap();
        assert_eq!(
            b.tracker.recovery_status().local_custody,
            LocalCustodyState::NotAHolder,
            "with no public package there is nothing to attribute the device to"
        );
        let (resp, _) = b.tracker.space_custody_import_cmd(
            pkg_path.to_string_lossy().to_string(),
            "a-sufficiently-long-passphrase".into(),
            true,
        );
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert_eq!(
            b.tracker.active_dkg_session(),
            Some(dkg),
            "the package carries its own public half, so it restores both"
        );
    }

    /// A rotation whose new arrangement excludes too many current
    /// holders can never be installed, because only a participant of the new
    /// ceremony can derive the key the current group must sign for.
    ///
    /// It must be refused at authorization. Otherwise it authorizes cleanly,
    /// runs the whole DKG, collects custody attestations, and stalls forever at
    /// the last step with everyone believing it worked.
    #[test]
    fn a_rotation_that_could_never_install_is_refused_up_front() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let c_user = user_from_seed(c_seed);
        let mut c = new_joiner_node_as(c_user.clone(), c_seed, &a_ws, &proof);
        let d_seed = [41u8; 32];
        let d_user = user_from_seed(d_seed);
        let mut d = new_joiner_node_as(d_user.clone(), d_seed, &a_ws, &proof);
        for incept in [
            b.tracker.self_inception().unwrap(),
            c.tracker.self_inception().unwrap(),
            d.tracker.self_inception().unwrap(),
        ] {
            a.tracker
                .admit_member(&incept, vec![Grant::Admin, Grant::Write]);
        }
        for other in [&mut b, &mut c, &mut d] {
            sync_all(&mut a.tracker, &mut other.tracker);
        }

        // A 2-of-2 group over {A, B}.
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        assert!(
            a.tracker.standing_dkg_session().is_some(),
            "group installed"
        );

        // Now propose a handover to {C, D} — disjoint from the current holders.
        // The current group is 2-of-2, so it needs BOTH of {A, B} to sign the
        // rotation, and neither would be able to derive the new key.
        let (resp, _) = a.tracker.space_elevate_cmd(
            vec![c_user.as_str().to_string(), d_user.as_str().to_string()],
            2,
        );
        match resp {
            Response::Error { message, .. } => assert!(
                message.contains("current holders"),
                "must explain why it cannot work: {message}"
            ),
            other => panic!("a disjoint handover must be refused, got {other:?}"),
        }

        // Keeping one current holder is still not enough for a 2-of-2: two
        // signatures are needed and only one signer could derive the key.
        let (resp, _) = a.tracker.space_elevate_cmd(
            vec![b_user.as_str().to_string(), c_user.as_str().to_string()],
            2,
        );
        // {A, B, C}: both current holders are present, so this one CAN install.
        assert!(
            matches!(resp, Response::Ok { .. }),
            "an overlapping arrangement is allowed: {resp:?}"
        );
    }

    /// A rogue proposal carries a perfectly
    /// valid *device* signature — authentication was never the missing piece.
    /// Without an authorization from the recovery authority, no honest node may
    /// spend a single DKG round on it, because acting on it is what would
    /// eventually let its configuration be installed as the recovery authority.
    #[test]
    fn an_unauthorized_proposal_moves_no_honest_node() {
        let mut a = new_node(); // founder; holds the solo recovery key
        let a_ws = a.tracker.workspace_str();
        let rogue_seed = [77u8; 32];
        let rogue = user_from_seed(rogue_seed);

        // The attacker names A as a participant, with a threshold they control.
        let propose =
            crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.tracker, [1u8; 16], 2, {
                let mut v = vec![a.tracker.me.clone(), rogue.clone()];
                v.sort();
                v
            }));
        let ev = crate::dkg::sign_ceremony(&rogue_seed, &propose, &a.tracker.workspace_id);
        assert!(
            ev.verify_sig(crate::dkg::CEREMONY_DOMAIN, &a_ws),
            "the rogue proposal is genuinely signature-valid"
        );
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.persist_membership("rogue").unwrap();

        a.tracker.dkg_advance().unwrap();

        assert!(
            a.tracker.dkg_read(&id, "r1").is_none(),
            "no round-1 secret was computed for an unauthorized proposal"
        );
        assert!(
            a.tracker.dkg_manifest(&id).is_none(),
            "and no acceptance was recorded"
        );
        // Nothing reached the space plane either.
        let cur = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert_eq!(cur.gen, 0, "the recovery authority is untouched");
    }

    /// The same rogue proposal, now injected into a transcript alongside a
    /// *genuine* authorization for a different proposal. Authorization is bound
    /// to one proposal hash, so it cannot be lifted to cover another.
    #[test]
    fn an_authorization_cannot_be_lifted_to_another_proposal() {
        let mut a = new_node();
        let rogue_seed = [78u8; 32];
        let rogue = user_from_seed(rogue_seed);
        let secret = a.tracker.read_space_recovery_key().expect("solo key");

        let propose =
            crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.tracker, [2u8; 16], 2, {
                let mut v = vec![a.tracker.me.clone(), rogue.clone()];
                v.sort();
                v
            }));
        let ev = crate::dkg::sign_ceremony(&rogue_seed, &propose, &a.tracker.workspace_id);
        let rogue_id = crate::dkg::TranscriptId::of(&ev).unwrap();

        // A real authorization, by the real recovery key — but for a DIFFERENT
        // proposal id. Re-pointing it at the rogue proposal must not verify.
        let other = crate::dkg::TranscriptId::parse_hex(&"c".repeat(64)).unwrap();
        // A real grant, by the real recovery key — but for a DIFFERENT proposal.
        // Re-pointing it at the rogue proposal breaks the signature, because the
        // proposal id is inside the signed payload rather than beside it.
        let real = crate::dkg::sign_authority_grant(&secret, &a.tracker.workspace_id, &other);
        let mut lifted = real.clone();
        lifted.op =
            postcard::to_stdvec(&crate::dkg::AuthorityGrant { proposal: rogue_id }).unwrap();
        let aev = crate::dkg::sign_ceremony(
            &rogue_seed,
            &crate::dkg::CeremonyOp::DkgAuthorize(lifted),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("lifted").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&rogue_id).is_none()
                && a.tracker.dkg_read(&rogue_id, "r1").is_none(),
            "an authorization for another proposal authorizes nothing here"
        );
    }

    /// A proposal authorized by a key that is no longer the recovery authority
    /// is not accepted. Guards the case where an old solo key, superseded by a
    /// group, is used to authorize a fresh elevation back to attacker control.
    #[test]
    fn a_proposal_authorized_by_a_superseded_authority_is_rejected() {
        let mut a = new_node();
        let stale_seed = [66u8; 32]; // never the workspace's recovery key
        let rogue = user_from_seed([79u8; 32]);

        let propose =
            crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.tracker, [3u8; 16], 2, {
                let mut v = vec![a.tracker.me.clone(), rogue];
                v.sort();
                v
            }));
        let ev = crate::dkg::sign_ceremony(&stale_seed, &propose, &a.tracker.workspace_id);
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        // Well-formed authorization, signed by a key that is not the authority.
        let grant = crate::dkg::sign_authority_grant(&stale_seed, &a.tracker.workspace_id, &id);
        assert!(
            crate::dkg::authority_grant_of(&grant, &a.tracker.workspace_id).is_some(),
            "the grant itself is well formed — only the signer is wrong"
        );
        let aev = crate::dkg::sign_ceremony(
            &stale_seed,
            &crate::dkg::CeremonyOp::DkgAuthorize(grant),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("stale").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&id).is_none() && a.tracker.dkg_read(&id, "r1").is_none(),
            "authorization must come from the STANDING recovery authority"
        );
    }

    /// A malformed participant list is rejected at the acceptor, not merely at
    /// the proposer. `space_elevate_cmd` sorts and dedupes; a hostile proposer
    /// does not, and duplicate entries would corrupt the index→participant map.
    #[test]
    fn a_malformed_participant_list_is_rejected_by_the_acceptor() {
        let mut a = new_node();
        let secret = a.tracker.read_space_recovery_key().expect("solo key");
        let me = a.tracker.me.clone();

        // Duplicated participant, and n disagreeing with the list length.
        let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(
            &a.tracker,
            [4u8; 16],
            2,
            vec![me.clone(), me.clone()],
        ));
        let ev = crate::dkg::sign_ceremony(&[80u8; 32], &propose, &a.tracker.workspace_id);
        let id = crate::dkg::TranscriptId::of(&ev).unwrap();
        // Authorized by the REAL recovery key — only the shape is wrong.
        let grant = crate::dkg::sign_authority_grant(&secret, &a.tracker.workspace_id, &id);
        let aev = crate::dkg::sign_ceremony(
            &[80u8; 32],
            &crate::dkg::CeremonyOp::DkgAuthorize(grant),
            &a.tracker.workspace_id,
        );
        a.tracker.membership.add_ceremony_event(&ev).unwrap();
        a.tracker.membership.add_ceremony_event(&aev).unwrap();
        a.tracker.persist_membership("malformed").unwrap();

        a.tracker.dkg_advance().unwrap();
        assert!(
            a.tracker.dkg_manifest(&id).is_none() && a.tracker.dkg_read(&id, "r1").is_none(),
            "a duplicated/miscounted participant list is not well-formed"
        );
    }

    /// The rotation target is derived from the stored public-key package, so
    /// swapping that artifact cannot redirect the recovery authority — it
    /// produces an unusable package rather than an attacker-chosen group key.
    #[test]
    fn a_swapped_public_key_package_cannot_redirect_the_rotation() {
        let mut a = new_node();
        let a_ws = a.tracker.workspace_str();
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);

        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let installed = crate::space::replay(
            &a.tracker.genesis,
            &a.tracker.workspace_id,
            &a.tracker.membership.space_events(),
        );
        assert_eq!(installed.gen, 1, "the group key was installed");

        // Corrupt the local public-key package; the group key is derived from it,
        // so it can no longer be resolved and the share stops being usable.
        let dkg_id = a.tracker.active_dkg_session().expect("A holds a share");
        a.tracker.dkg_write(&dkg_id, "pkp", b"swapped").unwrap();
        assert!(
            a.tracker.group_key_of_transcript(&dkg_id).is_none(),
            "a swapped package yields no group key rather than an attacker's"
        );
        assert!(
            a.tracker.active_dkg_session().is_none(),
            "and the transcript no longer resolves as the live authority"
        );
    }
    #[test]
    fn group_break_glass_recovery_needs_the_threshold_and_re_roots() {
        // After elevation to a 2-of-2 group key, break-glass recovery is a FROST
        // signing ceremony: a holder (B) requests a Recover, both holders co-sign
        // over the synced bulletin board, and the aggregated group signature
        // re-roots the workspace — convergently, with no solo key anywhere.
        let mut a = new_node();
        with_project(&mut a.tracker);
        let a_ws = a.tracker.workspace_str();
        let a_actor = a.tracker.my_actor().unwrap();

        let b_seed = [82u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        a.tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        sync_all(&mut a.tracker, &mut b.tracker);

        // Elevate {A, B} to a 2-of-2 group recovery key.
        let (resp, _) = a
            .tracker
            .space_elevate_cmd(vec![b_user.as_str().to_string()], 2);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        // 2-of-2 is indispensable: both custodians must verify a portable
        // backup before the arrangement may install.
        attest_custody(&mut a, "a");
        attest_custody(&mut b, "b");
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }
        let elevated = crate::space::replay(
            &b.tracker.genesis,
            &b.tracker.workspace_id,
            &b.tracker.membership.space_events(),
        );
        assert!(!elevated.recovered);

        // B triggers break-glass recovery, re-rooting to itself.
        let (resp, _) = b.tracker.space_recover_cmd();
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let b_actor = b.tracker.my_actor().unwrap();
        // The transcript id B posted its request under — the hash of the signed
        // request node, read off the verified board.
        let events = b.tracker.membership.ceremony_events();
        let board = crate::dkg::parse_board(&events, &b.tracker.workspace_id);
        let session_hex = board
            .signing
            .keys()
            .next()
            .map(|id| id.to_hex())
            .expect("B posted a recovery request");

        // SECURITY: ceremony automation runs on every import, but it must not
        // co-sign B's UNSOLICITED request. Sync the request to A and spin the
        // ceremony; nothing recovers, because A has given no local consent. Were
        // this to auto-sign, any member could re-root the workspace to itself.
        for _ in 0..6 {
            sync_all(&mut b.tracker, &mut a.tracker);
            sync_all(&mut a.tracker, &mut b.tracker);
        }
        assert!(
            !crate::space::replay(
                &b.tracker.genesis,
                &b.tracker.workspace_id,
                &b.tracker.membership.space_events(),
            )
            .recovered,
            "passive sync must not auto-co-sign a recovery no other holder consented to"
        );

        // A must name the expected target: approving with the WRONG target is
        // refused before any share is contributed (consent binds to the roots).
        let (bad, _) = a
            .tracker
            .space_recover_approve_cmd(session_hex.clone(), vec![a_actor.as_str().to_string()]);
        assert!(
            matches!(bad, Response::Error { .. }),
            "approving a mismatched target must be refused: {bad:?}"
        );
        // A explicitly co-signs, having verified out-of-band that it re-roots to B.
        let (resp, _) = a
            .tracker
            .space_recover_approve_cmd(session_hex, vec![b_actor.as_str().to_string()]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // Now the threshold consents; the group signature aggregates and installs.
        for _ in 0..6 {
            sync_all(&mut a.tracker, &mut b.tracker);
            sync_all(&mut b.tracker, &mut a.tracker);
        }

        // The workspace is re-rooted to B, evicting A, convergently on both.
        for t in [&b.tracker, &a.tracker] {
            let acl = t.acl_state();
            assert!(acl.is_admin(&b_actor), "recovered root is the new admin");
            assert!(!acl.is_admin(&a_actor), "old root is evicted");
        }
        let rb = crate::space::replay(
            &b.tracker.genesis,
            &b.tracker.workspace_id,
            &b.tracker.membership.space_events(),
        );
        assert!(rb.recovered && rb.root == vec![b_actor]);
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
            a.tracker.acl_state().is_nonce_spent(&nonce),
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
    fn a_revoked_invite_admits_no_one() {
        // The kill switch: once an admin revokes a nonce, no redemption via it
        // seats anyone — the only way to retire a leaked (esp. reusable) invite.
        let mut a = new_node(); // founder + admin
        let nonce = [7u8; 16];
        let j_incept = incept_for([61u8; 32], &a.tracker);
        let j_actor = actor_of(&j_incept);

        let (resp, _) = a
            .tracker
            .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(a.tracker.acl_state().is_invite_revoked(&nonce));

        let (resp, dirty) = a.tracker.redeem_invite(&me(), &j_incept, &nonce, true);
        assert!(
            matches!(resp, Response::Error { .. }) && dirty.is_none(),
            "a revoked invite admits no one: {resp:?}"
        );
        assert!(!a.tracker.is_member_actor(&j_actor));

        // A different, un-revoked nonce still admits the same joiner.
        let (resp, dirty) = a.tracker.redeem_invite(&me(), &j_incept, &[8u8; 16], true);
        assert!(
            matches!(resp, Response::Ok { .. }) && dirty.is_some(),
            "{resp:?}"
        );
        assert!(a.tracker.is_member_actor(&j_actor));
    }

    /// Unstaggered repair is bounded: admins that observe the fence independently
    /// each mint once, the concurrent mints converge by `(gen, id)`, and once a
    /// discharging epoch is visible no further import mints again.
    ///
    /// Only two of the three can race by construction — B has to redeem *before*
    /// seeing the revoke (`redeem_invite` refuses a revoked nonce outright), so
    /// B necessarily learns of the fence together with someone's mint. That is
    /// itself the stop-minting property, asserted at the end.
    #[test]
    fn concurrent_fence_repairs_converge_and_then_stop() {
        let mut a = new_node(); // founder + admin A
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let a_ws = a.tracker.workspace_str();
        let proof = a.tracker.founding_proof().unwrap();

        // B and C join as admins.
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(b_user.clone(), b_seed, &a_ws, &proof);
        let c_seed = [31u8; 32];
        let mut c = new_joiner_node_as(user_from_seed(c_seed), c_seed, &a_ws, &proof);
        for incept in [
            b.tracker.self_inception().unwrap(),
            c.tracker.self_inception().unwrap(),
        ] {
            let (resp, _) = a
                .tracker
                .admit_member(&incept, vec![Grant::Admin, Grant::Write]);
            assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        }
        sync_all(&mut a.tracker, &mut b.tracker);
        sync_all(&mut a.tracker, &mut c.tracker);
        let gen_before = a.tracker.active_epoch().unwrap().gen;

        // ---- PARTITION: B redeems, A revokes ----
        let nonce = [7u8; 16];
        let x_seed = [61u8; 32];
        let x_user = user_from_seed(x_seed);
        let x_incept = incept_for(x_seed, &b.tracker);
        let x_actor = actor_of(&x_incept);
        let (resp, _) = b.tracker.redeem_invite(&b_user, &x_incept, &nonce, true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        let (resp, _) = a
            .tracker
            .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // C sees the redemption first (no fence yet), then the revoke — so C
        // raises the fence and repairs without having seen anyone else's mint.
        sync_membership(&mut b.tracker, &mut c.tracker);
        assert_eq!(
            c.tracker.active_epoch().unwrap().gen,
            gen_before,
            "a redemption alone raises no fence"
        );
        sync_membership(&mut a.tracker, &mut c.tracker);
        // A independently receives the redemption and repairs too.
        sync_membership(&mut b.tracker, &mut a.tracker);

        let a_epoch = a.tracker.active_epoch().unwrap();
        let c_epoch = c.tracker.active_epoch().unwrap();
        assert_eq!(
            (a_epoch.gen, c_epoch.gen),
            (gen_before + 1, gen_before + 1),
            "both admins minted once, at the same generation"
        );
        assert_ne!(a_epoch.id, c_epoch.id, "the mints are genuinely concurrent");

        // ---- MERGE: converge on one tip ----
        sync_membership(&mut a.tracker, &mut c.tracker);
        sync_membership(&mut c.tracker, &mut a.tracker);
        let winner = a.tracker.active_epoch().unwrap();
        assert_eq!(
            c.tracker.active_epoch().unwrap().id,
            winner.id,
            "(gen, id) selects one tip on both replicas"
        );
        assert_eq!(
            winner.gen,
            gen_before + 1,
            "converging on a concurrent mint does not escalate the generation"
        );

        // B learns of the fence and a discharging epoch together: no new mint.
        sync_membership(&mut a.tracker, &mut b.tracker);
        assert_eq!(
            b.tracker.active_epoch().unwrap().id,
            winner.id,
            "B adopts the fenced tip rather than minting again"
        );
        // And a further round of imports is inert everywhere.
        sync_membership(&mut b.tracker, &mut a.tracker);
        sync_membership(&mut a.tracker, &mut c.tracker);
        assert_eq!(
            a.tracker.active_epoch().unwrap().id,
            winner.id,
            "a satisfied fence never re-raises"
        );
        assert_eq!(c.tracker.active_epoch().unwrap().id, winner.id);

        // The security property, on the tip everyone settled on.
        for node in [&a, &b, &c] {
            assert!(!node.tracker.is_member_actor(&x_actor), "X is evicted");
            assert!(
                node.tracker.acl_state().rekey_fences().is_empty(),
                "no outstanding obligation"
            );
            assert!(
                !node
                    .tracker
                    .membership
                    .sealed_devices(&winner.id)
                    .contains(&x_user),
                "X holds no key for the converged tip"
            );
        }
    }

    /// End-to-end kill switch across a partition: A revokes a leaked invite
    /// while B concurrently redeems it. After merge the admitted actor must be
    /// out of the member set *and* fenced off the live key.
    ///
    /// The fence has to be **causal**, not a recipient-list comparison, and this
    /// test pins why: `seal_epochs_to_actor` seals epochs to a joiner by writing
    /// blobs into the membership store without ever touching `EpochAuth.members`,
    /// so the admitted actor holds the live key while absent from its declared
    /// recipient list. The asserts below show every state trigger reading
    /// "healthy" at the moment the key is compromised.
    #[test]
    fn a_concurrently_revoked_invite_is_fenced_by_an_automatic_rekey() {
        let mut a = new_node(); // founder + admin A
        with_project(&mut a.tracker);
        new_issue(&mut a.tracker, "secret");
        let a_ws = a.tracker.workspace_str();

        // B joins as a second ADMIN and syncs.
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
        let b_incept = b.tracker.self_inception().unwrap();
        let (resp, _) = a
            .tracker
            .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        sync_all(&mut a.tracker, &mut b.tracker);
        let epoch_before = b.tracker.active_epoch().expect("an epoch exists");

        // ---- PARTITION ----
        // A revokes the leaked invite.
        let nonce = [7u8; 16];
        let (resp, _) = a
            .tracker
            .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce));
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

        // B, not having seen the revoke, redeems it for X — sealing X the epochs
        // live at that moment.
        let x_seed = [61u8; 32];
        let x_user = user_from_seed(x_seed);
        let x_incept = incept_for(x_seed, &b.tracker);
        let x_actor = actor_of(&x_incept);
        let (resp, _) = b.tracker.redeem_invite(&b_user, &x_incept, &nonce, true);
        assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
        assert!(
            b.tracker
                .membership
                .sealed_devices(&epoch_before.id)
                .contains(&x_user),
            "X holds the live epoch's key"
        );
        assert!(
            !epoch_before.members.contains(&x_actor),
            "yet X never appears in that epoch's declared recipient list — the \
             blind spot a recipient-set trigger cannot see through"
        );

        // ---- MERGE ----
        sync_membership(&mut b.tracker, &mut a.tracker);
        sync_membership(&mut a.tracker, &mut b.tracker);

        // Revoke wins: X is out, and the fence was discharged by a rotation.
        assert!(
            !a.tracker.is_member_actor(&x_actor),
            "revoke wins over the concurrent redemption"
        );
        assert!(
            a.tracker.acl_state().rekey_fences().is_empty(),
            "the rekey obligation was discharged automatically on import"
        );
        let active = a.tracker.active_epoch().unwrap();
        assert!(
            active.gen > epoch_before.gen,
            "an admin rotated past the fence on merge"
        );
        assert!(
            !a.tracker
                .membership
                .sealed_devices(&active.id)
                .contains(&x_user),
            "the evicted actor holds no key for the fenced epoch"
        );

        // Convergent: B lands on the same tip and mints nothing further.
        let gen_after = active.gen;
        sync_membership(&mut a.tracker, &mut b.tracker);
        assert_eq!(
            b.tracker.active_epoch().map(|e| e.gen),
            Some(gen_after),
            "B converges on the fenced tip without minting again"
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
            !a.tracker.acl_state().is_nonce_spent(&nonce),
            "a reusable pass is never burned"
        );
    }

    #[test]
    fn completion_leaves_board_list_but_stays_in_docs() {
        // A done issue is removed from boards[proj] but stays in docs and
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

        // Done changes status only, keeps the assignee, and empties the board list.
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
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        // comment attributed to A's **actor** — the person, not the device that
        // happened to type it, so the attribution outlives A rotating devices.
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
        let a_actor = a.tracker.my_actor().expect("A has an actor identity");
        assert_eq!(
            comment.actor.as_deref(),
            Some(a_actor.as_str()),
            "a comment is attributed to the authoring actor, not its device key"
        );
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
        // `lait history` is derived from the oplog on
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
        // A remote change arrives with field-level changes
        // and its (advisory) actor, and a genuinely concurrent import raises
        // the DAG collision flag — the compensating control for LWW fields.
        let mut a = new_node();
        with_project(&mut a.tracker);
        let b_seed = [9u8; 32];
        let b_user = user_from_seed(b_seed);
        let a_ws = a.tracker.workspace_str();
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
        // Exercise signed authorization operations through the real sync path:
        //  - a member's signed delete propagates to a peer (tombstone is a
        //    cache of the authz replay, reconciled on import),
        //  - a sponsored agent cannot delete (no content authority),
        //  - restore clears it, and the members log attributes everything.
        let mut a = new_node(); // founder/admin
        with_project(&mut a.tracker);
        let b_seed = [21u8; 32];
        let b_user = user_from_seed(b_seed);
        let a_ws = a.tracker.workspace_str();
        let mut b = new_joiner_node_as(
            b_user.clone(),
            b_seed,
            &a_ws,
            &a.tracker.founding_proof().unwrap(),
        );
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
