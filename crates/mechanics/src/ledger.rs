//! The authority ledger — mechanics' canonical journaled effect store and
//! materialization spine.
//!
//! One ledger per Space. It durably holds the Space's **signed authority
//! effects** — actor-plane events, ACL ops, and ceremony/space events, each a
//! [`SignedNode`] under its plane's domain — plus the sealed per-device
//! key-epoch envelopes, an [`crate::acl::ReplayCheckpoint`] materialization
//! for every committed frontier, and the [`BatchReceipt`] of every committed
//! batch. Everything commits through the semantics-free [`journal`] crate at
//! **one** linearization point per batch: verified effect objects, sealed-key
//! objects, the resulting checkpoint, its receipt, and the meta index land
//! atomically or not at all — no prefix of a batch can survive an invalid
//! later record, and a crash exposes the complete old or complete new ledger.
//!
//! **Frontiers are head sets, not opaque local state.** An authority frontier
//! canonically encodes the per-plane DAG heads (sorted, deduped), so any
//! holder of the same signed history can resolve the exact effect closure a
//! remote transaction was authorized against — the foundation of historical
//! authorization: standing is always evaluated **at the referenced frontier**,
//! never against current state. A frontier whose heads are not locally held is
//! missing history (retryable), not a validation pass.
//!
//! Effects remain the semantic source of truth; checkpoints are canonical
//! durable materializations of their deterministic replay and can never
//! introduce facts absent from them. A checkpoint whose semantics version
//! predates the current replay semantics is rebuilt from the signed effects —
//! an explicit, verified recovery, never a silent cache miss.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::acl::{self, AclState, ReplayCheckpoint, SignedOp};
use crate::actor::{self, ActorPlane, SignedEvent};
use crate::genesis::Genesis;
use crate::ids::{ActorId, DeviceId, SpaceId};
use crate::space::SignedSpaceEvent;
use journal::{JournalError, JournaledStore, ObjectRef};

/// The replay-semantics version persisted in every checkpoint. Bumping it
/// forces an explicit rebuild of all checkpoints from the signed effects.
pub const LEDGER_SEMANTICS_VERSION: u16 = 1;

/// BLAKE3 derive-key context for the frontier digest.
const FRONTIER_CONTEXT: &str = "lait.authority-frontier.v1";
/// BLAKE3 derive-key context for the batch digest.
const BATCH_CONTEXT: &str = "lait.authority-batch.v1";

/// Why a ledger operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerError {
    /// A batch record failed validation (undecodable, wrong Space binding,
    /// bad signature, unknown kind). The **whole batch** was refused; the
    /// durable ledger is unchanged.
    InvalidRecord(String),
    /// A referenced frontier names effects this ledger does not hold. The
    /// caller may retry once the missing history arrives.
    MissingHistory(String),
    /// A referenced frontier is malformed (non-canonical bytes, unknown
    /// version, unsorted or duplicate heads).
    MalformedFrontier(String),
    /// The durable store failed (see [`JournalError`]).
    Journal(JournalError),
    /// The durable ledger failed integrity validation on open.
    Corrupt(String),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::InvalidRecord(m) => write!(f, "invalid authority record: {m}"),
            LedgerError::MissingHistory(m) => write!(f, "missing authority history: {m}"),
            LedgerError::MalformedFrontier(m) => write!(f, "malformed authority frontier: {m}"),
            LedgerError::Journal(e) => write!(f, "authority journal: {e}"),
            LedgerError::Corrupt(m) => write!(f, "authority ledger corrupt: {m}"),
        }
    }
}
impl std::error::Error for LedgerError {}

impl From<JournalError> for LedgerError {
    fn from(e: JournalError) -> Self {
        LedgerError::Journal(e)
    }
}

/// One replicated **authoritative** effect: a signed node on one of the three
/// mechanics authority planes. The canonical wire encoding is postcard of this
/// enum (variant tags 0/1/2 — [`CeremonyMaterial`] owns the distinct tag 3 and
/// is *not* a `LedgerEffect`: ceremony transcript traffic never enters an
/// authority frontier).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerEffect {
    /// Actor-plane event (inception, device add/revoke, recovery rotate).
    Actor(SignedEvent),
    /// Membership/ACL op (add/remove/grants/epoch mint/invite revoke).
    Acl(SignedOp),
    /// A **terminal** space-authority event (`Recover` / `Rotate` / `Reshare`
    /// installation) under the Space-event signing domain — the ONLY ceremony
    /// outcome that is an authority effect. A successful transcript produces
    /// exactly one of these; proposals, rounds, custody attestations and
    /// completion progress are [`CeremonyMaterial`] and never appear here.
    SpaceAuthority(SignedSpaceEvent),
}

impl LedgerEffect {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode ledger effect")
    }

    /// Canonical decode: exact re-encode equality, so a non-canonical byte
    /// stream can never alias a canonical effect.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let effect: LedgerEffect = postcard::from_bytes(bytes)
            .map_err(|e| LedgerError::InvalidRecord(format!("undecodable effect: {e}")))?;
        if effect.encode() != bytes {
            return Err(LedgerError::InvalidRecord(
                "non-canonical effect encoding".into(),
            ));
        }
        Ok(effect)
    }

    /// The effect's content hash — its inner signed node's DAG hash.
    pub fn hash(&self) -> String {
        match self {
            LedgerEffect::Actor(n) | LedgerEffect::Acl(n) | LedgerEffect::SpaceAuthority(n) => {
                n.hash()
            }
        }
    }

    /// Verify the effect's signature under its plane's domain for `space`.
    /// Each variant admits exactly ONE signing domain — a ceremony-domain node
    /// wrapped as `SpaceAuthority` (or any other cross-domain substitution)
    /// fails here, refusing the whole batch before journal mutation.
    pub fn verify(&self, space: &SpaceId) -> bool {
        match self {
            LedgerEffect::Actor(n) => n.verify_sig(actor::ACTOR_DOMAIN, space.as_str()),
            LedgerEffect::Acl(n) => n.verify_sig(acl::ACL_DOMAIN, space.as_str()),
            LedgerEffect::SpaceAuthority(n) => {
                n.verify_sig(crate::space::SPACE_EVENT_DOMAIN, space.as_str())
            }
        }
    }

    fn kind(&self) -> u8 {
        match self {
            LedgerEffect::Actor(_) => 0,
            LedgerEffect::Acl(_) => 1,
            LedgerEffect::SpaceAuthority(_) => 2,
        }
    }

    fn parents(&self) -> &[String] {
        match self {
            LedgerEffect::Actor(n) | LedgerEffect::Acl(n) | LedgerEffect::SpaceAuthority(n) => {
                &n.parents
            }
        }
    }
}

/// The encoded material-class tag [`CeremonyMaterial`] leads with — distinct
/// from every [`LedgerEffect`] variant tag (0/1/2), so neither class of bytes
/// can decode as the other.
pub const CEREMONY_MATERIAL_TAG: u8 = 3;

/// One replicated **ceremony-material** record: a FROST ceremony-board node
/// (proposal, authorization, DKG/signing round, custody attestation,
/// completion/abort progress) under the ceremony signing domain.
///
/// Ceremony material shares the one crash-safe Mechanics journal and the
/// mechanics-material Contact channel with authority effects, but it is a
/// distinct tagged material class with its own bounded synchronization cursor:
/// it never enters an [`AuthorityFrontier`], an authority checkpoint, a World
/// transaction, or an authorization receipt, and lifetime transcript traffic
/// never grows an ordinary frontier.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyMaterial {
    /// Always [`CEREMONY_MATERIAL_TAG`]; validated on decode.
    tag: u8,
    /// The signed ceremony-board node (verified ONLY under the ceremony
    /// domain — a Space-event-domain node substituted here rejects).
    pub node: SignedSpaceEvent,
}

impl CeremonyMaterial {
    pub fn new(node: SignedSpaceEvent) -> Self {
        Self {
            tag: CEREMONY_MATERIAL_TAG,
            node,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode ceremony material")
    }

    /// Canonical decode: tag check plus exact re-encode equality.
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let material: CeremonyMaterial = postcard::from_bytes(bytes)
            .map_err(|e| LedgerError::InvalidRecord(format!("undecodable ceremony record: {e}")))?;
        if material.tag != CEREMONY_MATERIAL_TAG {
            return Err(LedgerError::InvalidRecord(format!(
                "ceremony record carries material-class tag {} (expected {CEREMONY_MATERIAL_TAG})",
                material.tag
            )));
        }
        if material.encode() != bytes {
            return Err(LedgerError::InvalidRecord(
                "non-canonical ceremony record encoding".into(),
            ));
        }
        Ok(material)
    }

    /// The node's content hash.
    pub fn hash(&self) -> String {
        self.node.hash()
    }

    /// Verify under the **ceremony** signing domain only. A terminal
    /// Space-authority event smuggled into the ceremony class fails here.
    pub fn verify(&self, space: &SpaceId) -> bool {
        self.node
            .verify_sig(crate::dkg::CEREMONY_DOMAIN, space.as_str())
    }
}

/// BLAKE3 derive-key context for a ceremony compaction audit commitment.
const CEREMONY_AUDIT_CONTEXT: &str = "lait.ceremony-audit.v1";

/// The durable audit record terminal ceremony compaction leaves behind: a
/// commitment over the exact dropped packet hashes, so the terminal outcome
/// remains auditable after its transcript traffic is reclaimed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeremonyAuditRecord {
    pub version: u16,
    pub space: SpaceId,
    /// Sorted hashes of the dropped ceremony packets.
    pub dropped: Vec<String>,
    /// The commitment over `space` + `dropped` (derive-key, domain-separated).
    pub commitment: [u8; 32],
}

impl CeremonyAuditRecord {
    fn build(space: &SpaceId, mut dropped: Vec<String>) -> Self {
        dropped.sort();
        dropped.dedup();
        let mut input = Vec::new();
        input.extend_from_slice(space.as_str().as_bytes());
        input.push(0x00);
        for h in &dropped {
            input.extend_from_slice(&(h.len() as u64).to_be_bytes());
            input.extend_from_slice(h.as_bytes());
        }
        let commitment = blake3::derive_key(CEREMONY_AUDIT_CONTEXT, &input);
        Self {
            version: 1,
            space: space.clone(),
            dropped,
            commitment,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode ceremony audit")
    }

    fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        postcard::from_bytes(bytes)
            .map_err(|e| LedgerError::Corrupt(format!("ceremony audit: {e}")))
    }
}

/// A staged sealed-key key with its decoded record and canonical bytes.
type StagedSealed = (([u8; 16], DeviceId), SealedKeyRecord, Vec<u8>);
/// A staged sealed-key index entry: key, plaintext-sealed bytes, object ref.
type StagedSealedRef = (([u8; 16], DeviceId), Vec<u8>, ObjectRef);

/// A sealed key-epoch envelope addressed to one device — distribution
/// material that rides beside the effects (its *authorization* is the signed
/// `MintEpoch` op; a forged envelope is inert because adoption checks the
/// mint's key commitment).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedKeyRecord {
    pub epoch: [u8; 16],
    pub device: DeviceId,
    pub sealed: Vec<u8>,
}

impl SealedKeyRecord {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode sealed key record")
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let rec: SealedKeyRecord = postcard::from_bytes(bytes)
            .map_err(|e| LedgerError::InvalidRecord(format!("undecodable sealed key: {e}")))?;
        if rec.encode() != bytes {
            return Err(LedgerError::InvalidRecord(
                "non-canonical sealed key encoding".into(),
            ));
        }
        Ok(rec)
    }
}

/// The canonical head-set body an authority frontier encodes: per-plane DAG
/// heads, sorted and deduped. The encoded `version` is the wire version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FrontierBody {
    version: u16,
    acl_heads: Vec<String>,
    actor_heads: Vec<String>,
    /// Heads of the terminal Space-authority plane (kind 2). Terminal effects
    /// are rare — one per completed recovery/elevation/reshare — so this list
    /// stays bounded; ceremony transcript traffic never appears here.
    space_authority_heads: Vec<String>,
}

impl FrontierBody {
    fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode frontier")
    }

    fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        let body: FrontierBody = postcard::from_bytes(bytes)
            .map_err(|e| LedgerError::MalformedFrontier(format!("{e}")))?;
        if body.version != 1 {
            return Err(LedgerError::MalformedFrontier(format!(
                "unsupported frontier version {}",
                body.version
            )));
        }
        for list in [
            &body.acl_heads,
            &body.actor_heads,
            &body.space_authority_heads,
        ] {
            if list.windows(2).any(|w| w[0] >= w[1]) {
                return Err(LedgerError::MalformedFrontier(
                    "frontier heads unsorted or duplicated".into(),
                ));
            }
        }
        if body.encode() != bytes {
            return Err(LedgerError::MalformedFrontier(
                "non-canonical frontier encoding".into(),
            ));
        }
        Ok(body)
    }
}

/// BLAKE3 derive-key context for the checkpoint commitment.
const CHECKPOINT_CONTEXT: &str = "lait.authority-checkpoint.v1";

/// The canonical commitment of one materialized checkpoint: every field of
/// the object is deterministic across nodes holding the same effect closure
/// (topo order, sorted sets, BTree maps), so the commitment is too.
fn checkpoint_commitment(cp: &CheckpointObject) -> [u8; 32] {
    let bytes = postcard::to_stdvec(cp).expect("encode checkpoint");
    blake3::derive_key(CHECKPOINT_CONTEXT, &bytes)
}

/// The companion facts an authorization evaluation binds. Runtime supplies
/// them; the receipt commits to every one.
pub struct AuthorizationRequest<'a> {
    pub world: &'a str,
    pub actor: &'a str,
    pub device: [u8; 32],
    pub authority_frontier: &'a [u8],
    pub parent_manifest_root: [u8; 32],
    pub implementation_id: [u8; 32],
    pub intent_digest: [u8; 32],
    pub demand: &'a [u8],
    pub effect_operations_digest: [u8; 32],
    pub body_transaction_core_digest: [u8; 32],
}

/// Why an authorization evaluation refused. A denial is a typed result and
/// never a receipt.
#[derive(Debug)]
pub enum AuthorizeError {
    /// The demand is unsatisfied, the device resolves to no actor at the
    /// frontier, or the resolved actor differs from the claimed one.
    Denied,
    /// The claimed implementation id is not active at the pinned frontier.
    ImplementationNotActive,
    /// The demand bytes are malformed/non-canonical.
    Demand(crate::demand::DemandError),
    /// Frontier resolution failed (missing history, malformed frontier, or a
    /// durable failure).
    Ledger(LedgerError),
}

impl std::fmt::Display for AuthorizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthorizeError::Denied => write!(f, "demand unsatisfied"),
            AuthorizeError::ImplementationNotActive => {
                write!(f, "implementation not active at the pinned frontier")
            }
            AuthorizeError::Demand(e) => write!(f, "{e}"),
            AuthorizeError::Ledger(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for AuthorizeError {}

/// The exact companion coordinates a remote receipt must bind.
pub struct ReceiptExpectations<'a> {
    pub device: &'a [u8; 32],
    pub authority_frontier: &'a [u8],
    pub parent_manifest_root: &'a [u8; 32],
    pub intent_digest: &'a [u8; 32],
    pub demand: &'a [u8],
    pub effect_operations_digest: &'a [u8; 32],
    pub body_transaction_core_digest: &'a [u8; 32],
}

/// Why remote receipt verification refused.
#[derive(Debug)]
pub enum VerifyError {
    /// A bound field disagrees with the transaction (substitution).
    Binding(&'static str),
    /// The demand is not satisfied at the referenced frontier by the claimed
    /// actor (or the actor does not resolve there).
    Unsatisfied,
    /// Frontier resolution failed (missing history is retryable).
    Ledger(LedgerError),
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::Binding(field) => write!(f, "receipt binding mismatch: {field}"),
            VerifyError::Unsatisfied => write!(f, "demand unsatisfied at the referenced frontier"),
            VerifyError::Ledger(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for VerifyError {}

/// The digest a checkpoint/receipt keys a frontier by.
fn frontier_digest(space: &SpaceId, frontier_bytes: &[u8]) -> [u8; 32] {
    let mut input = Vec::with_capacity(space.as_str().len() + 1 + frontier_bytes.len());
    input.extend_from_slice(space.as_str().as_bytes());
    input.push(0x00);
    input.extend_from_slice(frontier_bytes);
    blake3::derive_key(FRONTIER_CONTEXT, &input)
}

/// The durable receipt of one authority-batch incorporation: the explicit
/// binding an incorporated batch proves — Space, the frontier before, the
/// frontier after, and a digest over the exact ordered canonical batch bytes.
/// A replay of the identical batch returns the identical receipt. This proves
/// **history incorporation**; it is not World authorization evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReceipt {
    pub space: SpaceId,
    pub prior_frontier: Vec<u8>,
    pub resulting_frontier: Vec<u8>,
    pub batch_digest: [u8; 32],
}

impl BatchReceipt {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode batch receipt")
    }
    fn decode(bytes: &[u8]) -> Result<Self, LedgerError> {
        postcard::from_bytes(bytes).map_err(|e| LedgerError::Corrupt(format!("receipt: {e}")))
    }
}

/// Digest over the exact ordered canonical batch bytes: reordering,
/// substituting, or truncating the batch changes it.
pub fn batch_digest(records: &[Vec<u8>]) -> [u8; 32] {
    let mut input = Vec::new();
    input.extend_from_slice(&(records.len() as u64).to_be_bytes());
    for r in records {
        input.extend_from_slice(&(r.len() as u64).to_be_bytes());
        input.extend_from_slice(r);
    }
    blake3::derive_key(BATCH_CONTEXT, &input)
}

/// One durable checkpoint object: the frontier it materializes, the exact
/// effect closure it covers, the replay materialization with provenance, and
/// the semantics version that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct CheckpointObject {
    semantics: u16,
    frontier: Vec<u8>,
    /// Sorted hashes of every effect in the frontier's closure (all planes) —
    /// the effect-set commitment.
    effect_set: Vec<String>,
    /// Sorted hashes of the actor events in the closure (the continuation
    /// precondition input).
    actor_events: Vec<String>,
    /// Sorted hashes of the terminal Space-authority events in the closure —
    /// they seed the effective bootstrap root, so a continuation is only valid
    /// while this set is unchanged.
    space_events: Vec<String>,
    replay: ReplayCheckpoint,
}

/// The ledger's opaque journal metadata: the complete index, persisted at
/// every commit's linearization point.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LedgerMeta {
    version: u8,
    genesis: Genesis,
    /// (effect hash, kind, object)
    effects: Vec<(String, u8, ObjectRef)>,
    /// ((epoch, device), object)
    sealed: Vec<(([u8; 16], DeviceId), ObjectRef)>,
    /// (frontier digest, checkpoint object)
    checkpoints: Vec<([u8; 32], ObjectRef)>,
    /// (batch digest, receipt object)
    receipts: Vec<([u8; 32], ObjectRef)>,
    /// The current frontier's canonical bytes.
    frontier: Vec<u8>,
    /// The ceremony-material log: (sequence, node hash, object), append order.
    ceremony: Vec<(u64, String, ObjectRef)>,
    /// The next ceremony sequence — the bounded synchronization cursor.
    ceremony_next_seq: u64,
    /// Durable compaction audit records: (commitment, object).
    ceremony_audits: Vec<([u8; 32], ObjectRef)>,
}

/// A resolved view of the authority state at one frontier.
#[derive(Clone)]
pub struct StateView {
    pub acl: AclState,
    pub plane: ActorPlane,
    pub frontier: Vec<u8>,
}

impl std::fmt::Debug for StateView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateView")
            .field("frontier", &self.frontier)
            .finish_non_exhaustive()
    }
}

impl StateView {
    /// Whether `signer` (a raw device key) had authoring standing here.
    pub fn signer_can_write(&self, signer: &[u8; 32]) -> bool {
        let device = DeviceId::from_key_bytes(signer);
        match self.plane.actor_of_device(&device) {
            Some(actor) => self.acl.can_write(actor),
            None => false,
        }
    }
    /// Whether `signer` belonged to an admitted member (any standing).
    pub fn signer_is_member(&self, signer: &[u8; 32]) -> bool {
        let device = DeviceId::from_key_bytes(signer);
        match self.plane.actor_of_device(&device) {
            Some(actor) => self.acl.is_member(actor),
            None => false,
        }
    }
}

/// The journaled authority ledger for one Space.
pub struct AuthorityLedger {
    store: JournaledStore,
    genesis: Genesis,
    /// Every held effect, by hash.
    effects: BTreeMap<String, LedgerEffect>,
    effect_refs: BTreeMap<String, (u8, ObjectRef)>,
    sealed: BTreeMap<([u8; 16], DeviceId), (Vec<u8>, ObjectRef)>,
    /// Durable checkpoints by frontier digest.
    checkpoint_refs: BTreeMap<[u8; 32], ObjectRef>,
    /// Decoded checkpoint cache (bounded).
    checkpoint_cache: BTreeMap<[u8; 32], CheckpointObject>,
    receipts: BTreeMap<[u8; 32], BatchReceipt>,
    receipt_refs: BTreeMap<[u8; 32], ObjectRef>,
    frontier: Vec<u8>,
    /// The ceremony-material log, in append (sequence) order.
    ceremony: Vec<(u64, String, SignedSpaceEvent)>,
    /// Held ceremony records by node hash → (sequence, object).
    ceremony_refs: BTreeMap<String, (u64, ObjectRef)>,
    /// The next ceremony sequence to assign (the bounded cursor).
    ceremony_next_seq: u64,
    /// Durable compaction audit records: (commitment, object), oldest first.
    ceremony_audits: Vec<([u8; 32], ObjectRef)>,
    /// The replay-semantics version this handle materializes at (the crate
    /// const in production; parameterized so the explicit rebuild path is
    /// testable).
    semantics: u16,
}

/// Bounded decoded-checkpoint cache size (durable checkpoints remain loadable
/// from their objects; this only bounds memory).
const CHECKPOINT_CACHE_MAX: usize = 64;

impl AuthorityLedger {
    /// Create a fresh ledger for a Space at `root` (fails if one exists).
    pub fn create(root: impl Into<PathBuf>, genesis: Genesis) -> Result<Self, LedgerError> {
        let root = root.into();
        let store = JournaledStore::open(&root)?;
        if store.manifest().is_some() {
            return Err(LedgerError::Corrupt(
                "a ledger already exists at this root".into(),
            ));
        }
        let mut ledger = Self {
            store,
            genesis,
            effects: BTreeMap::new(),
            effect_refs: BTreeMap::new(),
            sealed: BTreeMap::new(),
            checkpoint_refs: BTreeMap::new(),
            checkpoint_cache: BTreeMap::new(),
            receipts: BTreeMap::new(),
            receipt_refs: BTreeMap::new(),
            frontier: Vec::new(),
            ceremony: Vec::new(),
            ceremony_refs: BTreeMap::new(),
            ceremony_next_seq: 0,
            ceremony_audits: Vec::new(),
            semantics: LEDGER_SEMANTICS_VERSION,
        };
        // Commit the empty-frontier baseline: genesis-only state, materialized.
        ledger.commit_batch(&[], &[])?;
        Ok(ledger)
    }

    /// Open an existing ledger, verifying the complete index. Every checkpoint
    /// whose semantics version is stale is discarded (rebuilt lazily from the
    /// signed effects — an explicit verified recovery, not a silent miss).
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, LedgerError> {
        Self::open_expecting_semantics(root, LEDGER_SEMANTICS_VERSION)
    }

    /// [`AuthorityLedger::open`] at an explicit semantics version — the test
    /// seam proving the semantics-version rebuild is a verified recovery from
    /// the signed effects, never a silent cache miss.
    #[doc(hidden)]
    pub fn open_expecting_semantics(
        root: impl Into<PathBuf>,
        semantics: u16,
    ) -> Result<Self, LedgerError> {
        let store = JournaledStore::open(root)?;
        let manifest = store
            .manifest()
            .ok_or_else(|| LedgerError::Corrupt("no committed ledger at this root".into()))?;
        let meta: LedgerMeta = postcard::from_bytes(&manifest.meta)
            .map_err(|e| LedgerError::Corrupt(format!("ledger meta: {e}")))?;
        if meta.version != 1 {
            return Err(LedgerError::Corrupt(format!(
                "unsupported ledger meta version {}",
                meta.version
            )));
        }
        let mut effects = BTreeMap::new();
        let mut effect_refs = BTreeMap::new();
        for (hash, kind, obj) in &meta.effects {
            let bytes = store.read_object(obj)?;
            let effect = LedgerEffect::decode(&bytes)
                .map_err(|e| LedgerError::Corrupt(format!("stored effect {hash}: {e}")))?;
            if effect.hash() != *hash || effect.kind() != *kind {
                return Err(LedgerError::Corrupt(format!(
                    "stored effect {hash} fails its index binding"
                )));
            }
            // Stored effects were verified at ingest; re-verify on open so a
            // corrupted-but-decodable object cannot slip standing forward.
            if !effect.verify(&meta.genesis.space_id) {
                return Err(LedgerError::Corrupt(format!(
                    "stored effect {hash} fails signature verification"
                )));
            }
            effects.insert(hash.clone(), effect);
            effect_refs.insert(hash.clone(), (*kind, *obj));
        }
        let mut sealed = BTreeMap::new();
        for (key, obj) in &meta.sealed {
            let bytes = store.read_object(obj)?;
            let rec = SealedKeyRecord::decode(&bytes)
                .map_err(|e| LedgerError::Corrupt(format!("sealed key: {e}")))?;
            if rec.epoch != key.0 || rec.device != key.1 {
                return Err(LedgerError::Corrupt(
                    "sealed key fails its index binding".into(),
                ));
            }
            sealed.insert(key.clone(), (rec.sealed, *obj));
        }
        let mut receipts = BTreeMap::new();
        let mut receipt_refs = BTreeMap::new();
        for (digest, obj) in &meta.receipts {
            let bytes = store.read_object(obj)?;
            let receipt = BatchReceipt::decode(&bytes)?;
            if receipt.batch_digest != *digest {
                return Err(LedgerError::Corrupt(
                    "receipt fails its index binding".into(),
                ));
            }
            receipts.insert(*digest, receipt);
            receipt_refs.insert(*digest, *obj);
        }
        let mut checkpoint_refs = BTreeMap::new();
        for (digest, obj) in &meta.checkpoints {
            // Verify readability + semantics version now; decode lazily later.
            let bytes = store.read_object(obj)?;
            let cp: CheckpointObject = postcard::from_bytes(&bytes)
                .map_err(|e| LedgerError::Corrupt(format!("checkpoint: {e}")))?;
            if cp.semantics == semantics {
                checkpoint_refs.insert(*digest, *obj);
            }
            // A stale-semantics checkpoint is dropped from the index: state is
            // rebuilt from the signed effects on demand.
        }
        let mut ceremony: Vec<(u64, String, SignedSpaceEvent)> = Vec::new();
        let mut ceremony_refs = BTreeMap::new();
        for (seq, hash, obj) in &meta.ceremony {
            let bytes = store.read_object(obj)?;
            let material = CeremonyMaterial::decode(&bytes)
                .map_err(|e| LedgerError::Corrupt(format!("stored ceremony record: {e}")))?;
            if material.hash() != *hash {
                return Err(LedgerError::Corrupt(format!(
                    "stored ceremony record {hash} fails its index binding"
                )));
            }
            if !material.verify(&meta.genesis.space_id) {
                return Err(LedgerError::Corrupt(format!(
                    "stored ceremony record {hash} fails ceremony-domain verification"
                )));
            }
            ceremony.push((*seq, hash.clone(), material.node));
            ceremony_refs.insert(hash.clone(), (*seq, *obj));
        }
        ceremony.sort_by_key(|(seq, _, _)| *seq);
        if ceremony
            .iter()
            .any(|(seq, _, _)| *seq >= meta.ceremony_next_seq)
        {
            return Err(LedgerError::Corrupt(
                "ceremony log sequence exceeds its cursor".into(),
            ));
        }
        let mut ceremony_audits = Vec::new();
        for (commitment, obj) in &meta.ceremony_audits {
            let bytes = store.read_object(obj)?;
            let audit = CeremonyAuditRecord::decode(&bytes)?;
            if audit.commitment != *commitment
                || CeremonyAuditRecord::build(&meta.genesis.space_id, audit.dropped.clone())
                    .commitment
                    != *commitment
            {
                return Err(LedgerError::Corrupt(
                    "ceremony audit record fails its commitment binding".into(),
                ));
            }
            ceremony_audits.push((*commitment, *obj));
        }
        let frontier = meta.frontier.clone();
        let genesis = meta.genesis.clone();
        let mut ledger = Self {
            store,
            genesis,
            effects,
            effect_refs,
            sealed,
            checkpoint_refs,
            checkpoint_cache: BTreeMap::new(),
            receipts,
            receipt_refs,
            frontier,
            ceremony,
            ceremony_refs,
            ceremony_next_seq: meta.ceremony_next_seq,
            ceremony_audits,
            semantics,
        };
        // The current frontier must be materializable (rebuilds if stale).
        ledger.checkpoint_for(&ledger.frontier.clone())?;
        Ok(ledger)
    }

    /// Test seam: attach a fault injector to the underlying journal.
    pub fn with_fault_injector(mut self, injector: journal::FaultInjector) -> Self {
        self.store.set_fault_injector(injector);
        self
    }

    /// The Space this ledger serves.
    pub fn space(&self) -> &SpaceId {
        &self.genesis.space_id
    }

    /// The Space genesis.
    pub fn genesis(&self) -> &Genesis {
        &self.genesis
    }

    /// The current frontier's canonical bytes.
    pub fn frontier(&self) -> Vec<u8> {
        self.frontier.clone()
    }

    /// The journal's committed sequence — instrumentation for the
    /// zero-writes-on-read gates.
    pub fn journal_sequence(&self) -> u64 {
        self.store.manifest().map(|m| m.sequence).unwrap_or(0)
    }

    /// Every held effect's canonical bytes (the full-set export seam).
    pub fn export_effects(&self) -> Vec<Vec<u8>> {
        self.effects.values().map(|e| e.encode()).collect()
    }

    /// Every held sealed-key record's canonical bytes.
    pub fn export_sealed(&self) -> Vec<Vec<u8>> {
        self.sealed
            .iter()
            .map(|((epoch, device), (sealed, _))| {
                SealedKeyRecord {
                    epoch: *epoch,
                    device: device.clone(),
                    sealed: sealed.clone(),
                }
                .encode()
            })
            .collect()
    }

    /// The sealed envelope for `(epoch, device)`, if held.
    pub fn sealed_for(&self, epoch: &[u8; 16], device: &DeviceId) -> Option<Vec<u8>> {
        self.sealed
            .get(&(*epoch, device.clone()))
            .map(|(bytes, _)| bytes.clone())
    }

    /// Devices holding a sealed envelope for `epoch`.
    pub fn sealed_devices(&self, epoch: &[u8; 16]) -> Vec<DeviceId> {
        self.sealed
            .keys()
            .filter(|(e, _)| e == epoch)
            .map(|(_, d)| d.clone())
            .collect()
    }

    /// All held ACL ops (audit surface).
    pub fn acl_ops(&self) -> Vec<SignedOp> {
        self.effects
            .values()
            .filter_map(|e| match e {
                LedgerEffect::Acl(op) => Some(op.clone()),
                _ => None,
            })
            .collect()
    }

    /// All held actor events.
    pub fn actor_events(&self) -> Vec<SignedEvent> {
        self.effects
            .values()
            .filter_map(|e| match e {
                LedgerEffect::Actor(ev) => Some(ev.clone()),
                _ => None,
            })
            .collect()
    }

    /// All held **terminal** Space-authority events (kind 2) — the input to
    /// `space::replay`. Ceremony transcript traffic is NOT here; see
    /// [`AuthorityLedger::ceremony_nodes`].
    pub fn space_authority_events(&self) -> Vec<SignedSpaceEvent> {
        self.effects
            .values()
            .filter_map(|e| match e {
                LedgerEffect::SpaceAuthority(ev) => Some(ev.clone()),
                _ => None,
            })
            .collect()
    }

    // ---- the ceremony-material class: its own log, cursor and retention ----

    /// The verified ceremony-board nodes, in append order — the bounded
    /// projection input for `dkg::parse_board`.
    pub fn ceremony_nodes(&self) -> Vec<SignedSpaceEvent> {
        self.ceremony.iter().map(|(_, _, n)| n.clone()).collect()
    }

    /// The ceremony log's bounded synchronization cursor: the next sequence
    /// number this ledger will assign. Monotone across appends, restarts and
    /// compaction (compaction never renumbers).
    pub fn ceremony_cursor(&self) -> u64 {
        self.ceremony_next_seq
    }

    /// The held ceremony records with sequence >= `cursor`, as
    /// `(sequence, canonical record bytes)` — the incremental-sync seam. A
    /// consumer resumes from its durable cursor instead of rescanning history.
    pub fn ceremony_after(&self, cursor: u64) -> Vec<(u64, Vec<u8>)> {
        self.ceremony
            .iter()
            .filter(|(seq, _, _)| *seq >= cursor)
            .map(|(seq, _, n)| (*seq, CeremonyMaterial::new(n.clone()).encode()))
            .collect()
    }

    /// Every currently retained ceremony record's canonical bytes (the Contact
    /// export seam). Post-compaction, terminal transcript traffic is absent.
    pub fn export_ceremony(&self) -> Vec<Vec<u8>> {
        self.ceremony
            .iter()
            .map(|(_, _, n)| CeremonyMaterial::new(n.clone()).encode())
            .collect()
    }

    /// The durable ceremony compaction audit commitments, oldest first.
    pub fn ceremony_audit_commitments(&self) -> Vec<[u8; 32]> {
        self.ceremony_audits.iter().map(|(c, _)| *c).collect()
    }

    /// Durably, atomically append one ceremony-material batch: canonical
    /// [`CeremonyMaterial`] records, **validated completely in memory first**
    /// under the ceremony signing domain — one undecodable, misbound, or
    /// cross-domain record refuses the whole batch with the durable ledger
    /// unchanged. Idempotent by node hash: an already-held record is skipped,
    /// and a batch with nothing new writes nothing. The ordinary authority
    /// frontier, checkpoints and receipts are untouched — ceremony material
    /// never enters them. Returns the resulting cursor.
    pub fn commit_ceremony_batch(&mut self, records: &[Vec<u8>]) -> Result<u64, LedgerError> {
        // 1. Validate the complete batch in memory.
        let mut fresh: Vec<(String, SignedSpaceEvent, Vec<u8>)> = Vec::new();
        for record in records {
            let material = CeremonyMaterial::decode(record)?;
            if !material.verify(&self.genesis.space_id) {
                return Err(LedgerError::InvalidRecord(format!(
                    "ceremony record {} fails ceremony-domain verification for this Space",
                    material.hash()
                )));
            }
            let hash = material.hash();
            if self.ceremony_refs.contains_key(&hash) {
                continue; // already held: idempotent
            }
            if fresh.iter().any(|(h, _, _)| h == &hash) {
                continue;
            }
            fresh.push((hash, material.node, record.clone()));
        }
        if fresh.is_empty() {
            return Ok(self.ceremony_next_seq);
        }

        // 2. Stage: assign monotone sequences and object refs.
        let prior_next = self.ceremony_next_seq;
        let mut new_objects: Vec<Vec<u8>> = Vec::new();
        for (hash, node, bytes) in &fresh {
            let obj = ObjectRef {
                hash: journal::object_content_hash(bytes),
                len: bytes.len() as u64,
            };
            let seq = self.ceremony_next_seq;
            self.ceremony_next_seq += 1;
            self.ceremony.push((seq, hash.clone(), node.clone()));
            self.ceremony_refs.insert(hash.clone(), (seq, obj));
            new_objects.push(bytes.clone());
        }
        let (mut keep, meta) = self.assemble_meta();
        let new_hashes: BTreeSet<[u8; 32]> = new_objects
            .iter()
            .map(|b| journal::object_content_hash(b))
            .collect();
        keep.retain(|r| !new_hashes.contains(&r.hash));
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        new_objects.retain(|b| seen.insert(journal::object_content_hash(b)));

        // 3. One journal commit; unwind the staged in-memory state on failure.
        if let Err(e) = self.store.commit(&new_objects, &keep, meta) {
            for (hash, _, _) in &fresh {
                self.ceremony_refs.remove(hash);
            }
            self.ceremony.retain(|(seq, _, _)| *seq < prior_next);
            self.ceremony_next_seq = prior_next;
            return Err(e.into());
        }
        Ok(self.ceremony_next_seq)
    }

    /// Compact terminal ceremony transcript traffic: durably drop the named
    /// packet hashes, recording a [`CeremonyAuditRecord`] whose commitment
    /// covers exactly the dropped set — in the SAME journal commit, so the
    /// audit commitment is durable before (never after) the material is gone.
    /// Every named hash must be held; the cursor is never renumbered. Which
    /// packets are *safe* to drop (terminal, not active, not required for
    /// validation or custody evidence) is the caller's policy — see
    /// `ceremony::terminal_compactable`.
    pub fn compact_ceremony(&mut self, drop_hashes: &[String]) -> Result<[u8; 32], LedgerError> {
        for h in drop_hashes {
            if !self.ceremony_refs.contains_key(h) {
                return Err(LedgerError::InvalidRecord(format!(
                    "compaction names an unheld ceremony record {h}"
                )));
            }
        }
        if drop_hashes.is_empty() {
            return Err(LedgerError::InvalidRecord(
                "compaction with an empty drop set".into(),
            ));
        }
        let audit = CeremonyAuditRecord::build(&self.genesis.space_id, drop_hashes.to_vec());
        let audit_bytes = audit.encode();
        let audit_obj = ObjectRef {
            hash: journal::object_content_hash(&audit_bytes),
            len: audit_bytes.len() as u64,
        };

        // Stage: remove the dropped records, add the audit.
        let dropped: BTreeSet<&String> = drop_hashes.iter().collect();
        let prior_ceremony = self.ceremony.clone();
        let prior_refs = self.ceremony_refs.clone();
        self.ceremony.retain(|(_, h, _)| !dropped.contains(h));
        for h in &dropped {
            self.ceremony_refs.remove(*h);
        }
        self.ceremony_audits.push((audit.commitment, audit_obj));
        let (mut keep, meta) = self.assemble_meta();
        keep.retain(|r| r.hash != audit_obj.hash);

        if let Err(e) = self.store.commit(&[audit_bytes], &keep, meta) {
            self.ceremony = prior_ceremony;
            self.ceremony_refs = prior_refs;
            self.ceremony_audits.pop();
            return Err(e.into());
        }
        Ok(audit.commitment)
    }

    /// The heads of one actor's event log — the `actor_asof` frontier an
    /// authored op embeds and the parents for the actor's next event.
    pub fn actor_heads(&self, actor: &ActorId) -> Vec<String> {
        let mine: Vec<&SignedEvent> = self
            .effects
            .values()
            .filter_map(|e| match e {
                LedgerEffect::Actor(ev) => Some(ev),
                _ => None,
            })
            .filter(|ev| {
                if ev.hash() == actor.incept_hash() {
                    return true;
                }
                postcard::from_bytes::<actor::ActorOp>(&ev.op)
                    .ok()
                    .and_then(|op| op.actor().cloned())
                    .is_some_and(|a| &a == actor)
            })
            .collect();
        let mut is_parent = HashSet::new();
        for e in &mine {
            for p in &e.parents {
                is_parent.insert(p.clone());
            }
        }
        let mut heads: Vec<String> = mine
            .iter()
            .map(|e| e.hash())
            .filter(|h| !is_parent.contains(h))
            .collect();
        heads.sort();
        heads
    }

    /// The ACL DAG heads (the parents a newly authored op names).
    pub fn acl_heads(&self) -> Vec<String> {
        self.plane_heads(1)
    }

    fn plane_heads(&self, kind: u8) -> Vec<String> {
        let mut hashes: BTreeSet<String> = BTreeSet::new();
        let mut referenced: HashSet<String> = HashSet::new();
        for (h, e) in &self.effects {
            if e.kind() != kind {
                continue;
            }
            hashes.insert(h.clone());
            for p in e.parents() {
                referenced.insert(p.clone());
            }
        }
        hashes
            .into_iter()
            .filter(|h| !referenced.contains(h))
            .collect()
    }

    fn current_frontier_body(&self) -> FrontierBody {
        FrontierBody {
            version: 1,
            acl_heads: self.plane_heads(1),
            actor_heads: self.plane_heads(0),
            space_authority_heads: self.plane_heads(2),
        }
    }

    /// The current materialized ACL state (at the current frontier).
    pub fn acl_state(&mut self) -> Result<AclState, LedgerError> {
        let frontier = self.frontier.clone();
        Ok(self.checkpoint_for(&frontier)?.replay.state)
    }

    /// The current actor plane (over all held actor events).
    pub fn actor_plane(&self) -> ActorPlane {
        actor::replay(&self.genesis.space_id, &self.actor_events())
    }

    /// Resolve the authority state **at a referenced historical frontier**.
    /// The frontier must be canonical and every named head locally held;
    /// missing heads are [`LedgerError::MissingHistory`] (retryable), never a
    /// fallback to current state.
    pub fn state_at(&mut self, frontier_bytes: &[u8]) -> Result<StateView, LedgerError> {
        let cp = self.checkpoint_for(frontier_bytes)?;
        let plane_events: Vec<SignedEvent> = cp
            .actor_events
            .iter()
            .filter_map(|h| match self.effects.get(h) {
                Some(LedgerEffect::Actor(ev)) => Some(ev.clone()),
                _ => None,
            })
            .collect();
        Ok(StateView {
            acl: cp.replay.state,
            plane: actor::replay(&self.genesis.space_id, &plane_events),
            frontier: frontier_bytes.to_vec(),
        })
    }

    /// Whether `signer` had authoring standing at the referenced frontier —
    /// the historical-authorization seam Replica consults. Errors (malformed
    /// frontier, missing history) are `false` at this boolean seam; callers
    /// needing the distinction use [`AuthorityLedger::state_at`].
    pub fn signer_authorized_at(&mut self, signer: &[u8; 32], frontier_bytes: &[u8]) -> bool {
        self.state_at(frontier_bytes)
            .map(|view| view.signer_can_write(signer))
            .unwrap_or(false)
    }

    /// The active World implementation id at a referenced frontier.
    pub fn active_implementation_at(
        &mut self,
        frontier_bytes: &[u8],
        world: &str,
    ) -> Result<Option<[u8; 32]>, LedgerError> {
        let cp = self.checkpoint_for(frontier_bytes)?;
        Ok(cp.replay.state.active_implementation(world))
    }

    /// The canonical commitment of the materialized checkpoint at a frontier —
    /// deterministic across every node holding the same effect closure.
    pub fn checkpoint_commitment_at(
        &mut self,
        frontier_bytes: &[u8],
    ) -> Result<[u8; 32], LedgerError> {
        let cp = self.checkpoint_for(frontier_bytes)?;
        Ok(checkpoint_commitment(&cp))
    }

    /// Derive the deterministic [`AuthorizationReceipt`] for a demand at a
    /// pinned frontier, or a typed denial. This is the ONLY constructor of
    /// World-authorization evidence: evaluation runs against the materialized
    /// checkpoint (journaled first if this frontier was not yet
    /// materialized), the canonical witness is selected per the frozen rules,
    /// and every companion coordinate is bound in.
    #[allow(clippy::too_many_arguments)]
    pub fn authorize(
        &mut self,
        request: &AuthorizationRequest<'_>,
    ) -> Result<crate::demand::AuthorizationReceipt, AuthorizeError> {
        let demand = crate::demand::AuthorizationDemand::decode_canonical(request.demand)
            .map_err(AuthorizeError::Demand)?;
        let cp = self
            .checkpoint_for(request.authority_frontier)
            .map_err(AuthorizeError::Ledger)?;
        // Resolve the device to its actor AT the pinned frontier.
        let view = self
            .state_at(request.authority_frontier)
            .map_err(AuthorizeError::Ledger)?;
        let device = DeviceId::from_key_bytes(&request.device);
        let actor = view
            .plane
            .actor_of_device(&device)
            .cloned()
            .ok_or(AuthorizeError::Denied)?;
        if actor.as_str() != request.actor {
            return Err(AuthorizeError::Denied);
        }
        // The implementation id must be active at the pinned frontier.
        match cp.replay.state.active_implementation(request.world) {
            Some(active) if active == request.implementation_id => {}
            _ => return Err(AuthorizeError::ImplementationNotActive),
        }
        let witness = cp
            .replay
            .state
            .evaluate_demand(&actor, &demand)
            .ok_or(AuthorizeError::Denied)?;
        Ok(crate::demand::AuthorizationReceipt {
            space: self.genesis.space_id.as_str().to_string(),
            world: request.world.to_string(),
            actor: actor.as_str().to_string(),
            device: request.device,
            authority_frontier: request.authority_frontier.to_vec(),
            authority_checkpoint_commitment: checkpoint_commitment(&cp),
            policy_evidence_digest: crate::demand::policy_evidence_digest(&witness),
            parent_manifest_root: request.parent_manifest_root,
            implementation_id: request.implementation_id,
            intent_digest: request.intent_digest,
            demand_digest: demand.digest().map_err(AuthorizeError::Demand)?,
            effect_operations_digest: request.effect_operations_digest,
            body_transaction_core_digest: request.body_transaction_core_digest,
            decision: 1,
        })
    }

    /// Verify a remote transaction's authorization receipt against historical
    /// Mechanics state — **no World callback runs**. Recomputes the actor
    /// resolution, checkpoint commitment, implementation activation, demand
    /// evaluation, and witness digest at the receipt's referenced frontier,
    /// and requires every binding to the supplied companion coordinates.
    pub fn verify_receipt(
        &mut self,
        receipt: &crate::demand::AuthorizationReceipt,
        expectations: &ReceiptExpectations<'_>,
    ) -> Result<(), VerifyError> {
        if receipt.space != self.genesis.space_id.as_str() {
            return Err(VerifyError::Binding("space"));
        }
        if receipt.decision != 1 {
            return Err(VerifyError::Binding("decision"));
        }
        if receipt.device != *expectations.device {
            return Err(VerifyError::Binding("device"));
        }
        if receipt.authority_frontier != expectations.authority_frontier {
            return Err(VerifyError::Binding("authority frontier"));
        }
        if receipt.parent_manifest_root != *expectations.parent_manifest_root {
            return Err(VerifyError::Binding("parent manifest root"));
        }
        if receipt.intent_digest != *expectations.intent_digest {
            return Err(VerifyError::Binding("intent digest"));
        }
        if receipt.effect_operations_digest != *expectations.effect_operations_digest {
            return Err(VerifyError::Binding("operations digest"));
        }
        if receipt.body_transaction_core_digest != *expectations.body_transaction_core_digest {
            return Err(VerifyError::Binding("core digest"));
        }
        let demand = crate::demand::AuthorizationDemand::decode_canonical(expectations.demand)
            .map_err(|_| VerifyError::Binding("demand"))?;
        if receipt.demand_digest
            != demand
                .digest()
                .map_err(|_| VerifyError::Binding("demand"))?
        {
            return Err(VerifyError::Binding("demand digest"));
        }
        let cp = self
            .checkpoint_for(&receipt.authority_frontier)
            .map_err(VerifyError::Ledger)?;
        if checkpoint_commitment(&cp) != receipt.authority_checkpoint_commitment {
            return Err(VerifyError::Binding("checkpoint commitment"));
        }
        match cp.replay.state.active_implementation(&receipt.world) {
            Some(active) if active == receipt.implementation_id => {}
            _ => return Err(VerifyError::Binding("implementation id")),
        }
        let view = self
            .state_at(&receipt.authority_frontier)
            .map_err(VerifyError::Ledger)?;
        let device = DeviceId::from_key_bytes(&receipt.device);
        let actor = view
            .plane
            .actor_of_device(&device)
            .cloned()
            .ok_or(VerifyError::Unsatisfied)?;
        if actor.as_str() != receipt.actor {
            return Err(VerifyError::Binding("actor"));
        }
        let witness = cp
            .replay
            .state
            .evaluate_demand(&actor, &demand)
            .ok_or(VerifyError::Unsatisfied)?;
        if crate::demand::policy_evidence_digest(&witness) != receipt.policy_evidence_digest {
            return Err(VerifyError::Binding("policy evidence digest"));
        }
        Ok(())
    }

    /// The closure of a frontier: every effect hash reachable from its heads,
    /// per plane. Missing heads or parents are [`LedgerError::MissingHistory`].
    fn closure_of(&self, body: &FrontierBody) -> Result<BTreeSet<String>, LedgerError> {
        let mut out: BTreeSet<String> = BTreeSet::new();
        let mut stack: Vec<&String> = Vec::new();
        for (heads, kind) in [
            (&body.acl_heads, 1u8),
            (&body.actor_heads, 0u8),
            (&body.space_authority_heads, 2u8),
        ] {
            for h in heads {
                match self.effects.get(h) {
                    Some(e) if e.kind() == kind => stack.push(h),
                    Some(_) => {
                        return Err(LedgerError::MalformedFrontier(format!(
                            "head {h} names an effect on another plane"
                        )))
                    }
                    None => {
                        return Err(LedgerError::MissingHistory(format!(
                            "frontier head {h} is not held"
                        )))
                    }
                }
            }
        }
        while let Some(h) = stack.pop() {
            if !out.insert(h.clone()) {
                continue;
            }
            let effect = &self.effects[h];
            for p in effect.parents() {
                match self.effects.get(p) {
                    Some(_) => stack.push(p),
                    None => {
                        return Err(LedgerError::MissingHistory(format!(
                            "effect {h} names an unheld parent {p}"
                        )))
                    }
                }
            }
        }
        Ok(out)
    }

    /// Load or build (and durably journal) the checkpoint for a frontier.
    fn checkpoint_for(&mut self, frontier_bytes: &[u8]) -> Result<CheckpointObject, LedgerError> {
        let body = FrontierBody::decode(frontier_bytes)?;
        let digest = frontier_digest(&self.genesis.space_id, frontier_bytes);
        if let Some(cp) = self.checkpoint_cache.get(&digest) {
            return Ok(cp.clone());
        }
        if let Some(obj) = self.checkpoint_refs.get(&digest) {
            let bytes = self.store.read_object(obj)?;
            let cp: CheckpointObject = postcard::from_bytes(&bytes)
                .map_err(|e| LedgerError::Corrupt(format!("checkpoint: {e}")))?;
            if cp.semantics == self.semantics && cp.frontier == frontier_bytes {
                self.cache_checkpoint(digest, cp.clone());
                return Ok(cp);
            }
        }
        // Build from the signed effects at the exact closure.
        let cp = self.build_checkpoint(&body, frontier_bytes)?;
        // A newly proven historical frontier is journaled before any receipt
        // is issued on top of it — unless it is the current frontier being
        // rebuilt during open (journaled by the next commit).
        self.persist_checkpoint(&cp)?;
        self.cache_checkpoint(digest, cp.clone());
        Ok(cp)
    }

    fn cache_checkpoint(&mut self, digest: [u8; 32], cp: CheckpointObject) {
        if self.checkpoint_cache.len() >= CHECKPOINT_CACHE_MAX {
            // Bounded: evict the smallest key (deterministic, cheap).
            let evict = self.checkpoint_cache.keys().next().copied();
            if let Some(k) = evict {
                self.checkpoint_cache.remove(&k);
            }
        }
        self.checkpoint_cache.insert(digest, cp);
    }

    /// Replay the closure of `body` into a checkpoint object. Uses the
    /// strict-descendant continuation from the best durable ancestor
    /// checkpoint when its preconditions hold; falls back to complete replay.
    ///
    /// The **effective bootstrap root** seeds the ACL replay: the terminal
    /// Space-authority events in the closure replay to a `RootState`, and a
    /// `Recover` replaces the genesis root exactly as the space plane
    /// specifies. Continuation is only valid while the closure's space-event
    /// set is unchanged (a terminal effect re-seeds the root, so the suffix
    /// rule no longer applies).
    fn build_checkpoint(
        &mut self,
        body: &FrontierBody,
        frontier_bytes: &[u8],
    ) -> Result<CheckpointObject, LedgerError> {
        let closure = self.closure_of(body)?;
        let acl_ops: Vec<SignedOp> = closure
            .iter()
            .filter_map(|h| match self.effects.get(h) {
                Some(LedgerEffect::Acl(op)) => Some(op.clone()),
                _ => None,
            })
            .collect();
        let actor_events: Vec<SignedEvent> = closure
            .iter()
            .filter_map(|h| match self.effects.get(h) {
                Some(LedgerEffect::Actor(ev)) => Some(ev.clone()),
                _ => None,
            })
            .collect();
        let actor_hashes: BTreeSet<String> = actor_events.iter().map(|e| e.hash()).collect();
        let space_events: Vec<SignedSpaceEvent> = closure
            .iter()
            .filter_map(|h| match self.effects.get(h) {
                Some(LedgerEffect::SpaceAuthority(ev)) => Some(ev.clone()),
                _ => None,
            })
            .collect();
        let space_hashes: BTreeSet<String> = space_events.iter().map(|e| e.hash()).collect();
        let root_state = crate::space::replay(&self.genesis, &self.genesis.space_id, &space_events);
        let effective_genesis = Genesis {
            founding_actors: root_state.root,
            ..self.genesis.clone()
        };

        // Try continuation from the current frontier's cached checkpoint (the
        // common case: a new batch extends the tip).
        let replay = self
            .try_continue(&effective_genesis, &space_hashes, &actor_events, &acl_ops)
            .unwrap_or_else(|| {
                let (cp, _) = acl::replay_checkpointed(&effective_genesis, &actor_events, &acl_ops);
                cp
            });

        Ok(CheckpointObject {
            semantics: self.semantics,
            frontier: frontier_bytes.to_vec(),
            effect_set: closure.into_iter().collect(),
            actor_events: actor_hashes.into_iter().collect(),
            space_events: space_hashes.into_iter().collect(),
            replay,
        })
    }

    /// The strict-descendant continuation attempt, from the current frontier's
    /// in-memory checkpoint. Refused when the space-event set changed: a
    /// terminal Space-authority effect re-seeds the effective root, so the
    /// prior materialization is not a valid replay prefix.
    fn try_continue(
        &self,
        effective_genesis: &Genesis,
        space_hashes: &BTreeSet<String>,
        actor_events: &[SignedEvent],
        acl_ops: &[SignedOp],
    ) -> Option<ReplayCheckpoint> {
        let digest = frontier_digest(&self.genesis.space_id, &self.frontier);
        let prior = self.checkpoint_cache.get(&digest)?;
        let prior_space: BTreeSet<String> = prior.space_events.iter().cloned().collect();
        if prior_space != *space_hashes {
            return None;
        }
        let prior_actor: BTreeSet<String> = prior.actor_events.iter().cloned().collect();
        acl::replay_continue(
            &prior.replay,
            &prior_actor,
            effective_genesis,
            actor_events,
            acl_ops,
        )
        .map(|(cp, _)| cp)
    }

    fn persist_checkpoint(&mut self, cp: &CheckpointObject) -> Result<(), LedgerError> {
        let digest = frontier_digest(&self.genesis.space_id, &cp.frontier);
        if self.checkpoint_refs.contains_key(&digest) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(cp).expect("encode checkpoint");
        let obj = ObjectRef {
            hash: journal::object_content_hash(&bytes),
            len: bytes.len() as u64,
        };
        self.checkpoint_refs.insert(digest, obj);
        let (mut keep, meta) = self.assemble_meta();
        // The checkpoint object is written by this commit — not carried.
        keep.retain(|r| r.hash != obj.hash);
        match self.store.commit(&[bytes], &keep, meta) {
            Ok(_) => Ok(()),
            Err(e) => {
                self.checkpoint_refs.remove(&digest);
                Err(e.into())
            }
        }
    }

    /// The complete meta index + keep set over everything currently indexed.
    fn assemble_meta(&self) -> (Vec<ObjectRef>, Vec<u8>) {
        let mut keep: Vec<ObjectRef> = Vec::new();
        let mut effects = Vec::new();
        for (h, (kind, obj)) in &self.effect_refs {
            effects.push((h.clone(), *kind, *obj));
            keep.push(*obj);
        }
        let mut sealed = Vec::new();
        for (key, (_, obj)) in &self.sealed {
            sealed.push((key.clone(), *obj));
            keep.push(*obj);
        }
        let mut checkpoints = Vec::new();
        for (digest, obj) in &self.checkpoint_refs {
            checkpoints.push((*digest, *obj));
            keep.push(*obj);
        }
        let mut receipts = Vec::new();
        for (digest, obj) in &self.receipt_refs {
            receipts.push((*digest, *obj));
            keep.push(*obj);
        }
        let mut ceremony = Vec::new();
        for (seq, hash, _) in &self.ceremony {
            let (_, obj) = self.ceremony_refs[hash];
            ceremony.push((*seq, hash.clone(), obj));
            keep.push(obj);
        }
        let mut ceremony_audits = Vec::new();
        for (commitment, obj) in &self.ceremony_audits {
            ceremony_audits.push((*commitment, *obj));
            keep.push(*obj);
        }
        let meta = LedgerMeta {
            version: 1,
            genesis: self.genesis.clone(),
            effects,
            sealed,
            checkpoints,
            receipts,
            frontier: self.frontier.clone(),
            ceremony,
            ceremony_next_seq: self.ceremony_next_seq,
            ceremony_audits,
        };
        keep.sort_by_key(|r| r.hash);
        keep.dedup_by_key(|r| r.hash);
        // `keep` may name objects being written in this same commit; the
        // journal validates keeps against *existing* objects, so the caller
        // must subtract new objects. assemble_meta callers handle that.
        (
            keep,
            postcard::to_stdvec(&meta).expect("encode ledger meta"),
        )
    }

    /// Durably, atomically commit one authority batch: canonical effect
    /// records plus sealed-key records, **validated completely in memory
    /// first** — one undecodable, misbound, or signature-invalid record
    /// refuses the whole batch with the durable ledger unchanged; no prefix
    /// survives an invalid later record. An exact replay of an
    /// already-committed batch returns the original receipt without a new
    /// journal write.
    pub fn commit_batch(
        &mut self,
        effect_records: &[Vec<u8>],
        sealed_records: &[Vec<u8>],
    ) -> Result<BatchReceipt, LedgerError> {
        // Exact-replay idempotency (effects + sealed both bind the digest).
        let mut all_records: Vec<Vec<u8>> = Vec::new();
        all_records.extend(effect_records.iter().cloned());
        all_records.extend(sealed_records.iter().cloned());
        let digest = batch_digest(&all_records);
        if let Some(receipt) = self.receipts.get(&digest) {
            return Ok(receipt.clone());
        }

        // 1. Validate the complete batch in memory.
        let mut new_effects: Vec<(String, LedgerEffect, Vec<u8>)> = Vec::new();
        for record in effect_records {
            let effect = LedgerEffect::decode(record)?;
            if !effect.verify(&self.genesis.space_id) {
                return Err(LedgerError::InvalidRecord(format!(
                    "effect {} fails signature verification for this Space",
                    effect.hash()
                )));
            }
            let hash = effect.hash();
            if self.effects.contains_key(&hash) {
                continue; // already held: idempotent
            }
            if new_effects.iter().any(|(h, _, _)| h == &hash) {
                continue;
            }
            new_effects.push((hash, effect, record.clone()));
        }
        let mut new_sealed: Vec<StagedSealed> = Vec::new();
        for record in sealed_records {
            let rec = SealedKeyRecord::decode(record)?;
            let key = (rec.epoch, rec.device.clone());
            if self.sealed.contains_key(&key) {
                continue; // first-write-wins: an existing envelope stands
            }
            if new_sealed.iter().any(|(k, _, _)| k == &key) {
                continue;
            }
            new_sealed.push((key, rec, record.clone()));
        }

        // 2. Compute the union replay + resulting frontier in memory.
        let prior_frontier = self.frontier.clone();
        for (hash, effect, _) in &new_effects {
            self.effects.insert(hash.clone(), effect.clone());
        }
        let body = self.current_frontier_body();
        let frontier_bytes = body.encode();
        let build = self.build_checkpoint(&body, &frontier_bytes);
        let checkpoint = match build {
            Ok(cp) => cp,
            Err(e) => {
                for (hash, _, _) in &new_effects {
                    self.effects.remove(hash);
                }
                return Err(e);
            }
        };

        // 3. Assemble the one journal commit: effects, sealed keys, the
        //    checkpoint, the receipt, and the meta index.
        let receipt = BatchReceipt {
            space: self.genesis.space_id.clone(),
            prior_frontier,
            resulting_frontier: frontier_bytes.clone(),
            batch_digest: digest,
        };
        let cp_digest = frontier_digest(&self.genesis.space_id, &frontier_bytes);
        let cp_bytes = postcard::to_stdvec(&checkpoint).expect("encode checkpoint");
        let receipt_bytes = receipt.encode();

        let mut new_objects: Vec<Vec<u8>> = Vec::new();
        let mut staged_effect_refs: Vec<(String, u8, ObjectRef)> = Vec::new();
        for (hash, effect, bytes) in &new_effects {
            let obj = ObjectRef {
                hash: journal::object_content_hash(bytes),
                len: bytes.len() as u64,
            };
            staged_effect_refs.push((hash.clone(), effect.kind(), obj));
            new_objects.push(bytes.clone());
        }
        let mut staged_sealed_refs: Vec<StagedSealedRef> = Vec::new();
        for (key, rec, bytes) in &new_sealed {
            let obj = ObjectRef {
                hash: journal::object_content_hash(bytes),
                len: bytes.len() as u64,
            };
            staged_sealed_refs.push((key.clone(), rec.sealed.clone(), obj));
            new_objects.push(bytes.clone());
        }
        let cp_obj = ObjectRef {
            hash: journal::object_content_hash(&cp_bytes),
            len: cp_bytes.len() as u64,
        };
        new_objects.push(cp_bytes);
        let receipt_obj = ObjectRef {
            hash: journal::object_content_hash(&receipt_bytes),
            len: receipt_bytes.len() as u64,
        };
        new_objects.push(receipt_bytes);

        // Stage the index updates, then build meta over the staged state.
        for (hash, kind, obj) in &staged_effect_refs {
            self.effect_refs.insert(hash.clone(), (*kind, *obj));
        }
        for (key, sealed, obj) in &staged_sealed_refs {
            self.sealed.insert(key.clone(), (sealed.clone(), *obj));
        }
        self.checkpoint_refs.insert(cp_digest, cp_obj);
        self.receipt_refs.insert(digest, receipt_obj);
        self.frontier = frontier_bytes.clone();
        let (mut keep, meta) = self.assemble_meta();
        // New objects are written by this commit — not carried.
        let new_hashes: BTreeSet<[u8; 32]> = new_objects
            .iter()
            .map(|b| journal::object_content_hash(b))
            .collect();
        keep.retain(|r| !new_hashes.contains(&r.hash));

        // Dedup new objects by content (a re-sent byte-identical record).
        let mut seen: BTreeSet<[u8; 32]> = BTreeSet::new();
        new_objects.retain(|b| seen.insert(journal::object_content_hash(b)));

        match self.store.commit(&new_objects, &keep, meta) {
            Ok(_) => {}
            Err(e) => {
                // Unwind the staged in-memory state: the durable ledger is
                // unchanged, so memory must match it.
                for (hash, _, _) in &new_effects {
                    self.effects.remove(hash);
                    self.effect_refs.remove(hash);
                }
                for (key, _, _) in &staged_sealed_refs {
                    self.sealed.remove(key);
                }
                self.checkpoint_refs.remove(&cp_digest);
                self.receipt_refs.remove(&digest);
                self.frontier = receipt.prior_frontier.clone();
                return Err(e.into());
            }
        }
        self.cache_checkpoint(cp_digest, checkpoint);
        self.receipts.insert(digest, receipt.clone());
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{AclAction, AclOp, Grant};
    use crate::ids::SystemUlidSource;

    fn seed(n: u8) -> [u8; 32] {
        [n; 32]
    }

    struct Fx {
        genesis: Genesis,
        founder_seed: [u8; 32],
        founder_actor: ActorId,
        founder_incept: SignedEvent,
    }

    fn fx() -> Fx {
        let space = SpaceId::mint(&SystemUlidSource);
        let (incept, actor_id) = actor::incept_single(&seed(1), &space, [1; 16], [71; 16], None);
        Fx {
            genesis: Genesis {
                space_id: space,
                founding_actors: vec![actor_id.clone()],
                salt: [0u8; 16],
                recovery_root: [0u8; 32],
            },
            founder_seed: seed(1),
            founder_actor: actor_id,
            founder_incept: incept,
        }
    }

    fn incept_other(fx: &Fx, n: u8) -> (SignedEvent, ActorId) {
        actor::incept_single(&seed(n), &fx.genesis.space_id, [n; 16], [n + 70; 16], None)
    }

    fn signed_add(
        fx: &Fx,
        parents: Vec<String>,
        actor_asof: Vec<String>,
        target: &ActorId,
        grants: Vec<Grant>,
    ) -> SignedOp {
        acl::sign_op(
            &fx.founder_seed,
            &AclOp {
                action: AclAction::AddMember {
                    actor: target.clone(),
                    grants,
                },
                by: fx.founder_actor.clone(),
                actor_asof,
                nonce: None,
            },
            parents,
            &fx.genesis.space_id,
        )
    }

    #[test]
    fn create_open_roundtrip_and_empty_frontier() {
        let dir = tempdir();
        let fx = fx();
        let ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let frontier = ledger.frontier();
        drop(ledger);
        let ledger = AuthorityLedger::open(&dir).unwrap();
        assert_eq!(ledger.frontier(), frontier);
        assert_eq!(ledger.space(), &fx.genesis.space_id);
        cleanup(&dir);
    }

    #[test]
    fn batch_is_atomic_no_prefix_survives_an_invalid_record() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let good = LedgerEffect::Actor(fx.founder_incept.clone()).encode();
        let bad = vec![0xFF, 0xEE, 0xDD];
        let before = ledger.frontier();
        let before_seq = ledger.journal_sequence();
        let err = ledger.commit_batch(&[good, bad], &[]).unwrap_err();
        assert!(matches!(err, LedgerError::InvalidRecord(_)));
        assert_eq!(ledger.frontier(), before, "no partial adoption");
        assert_eq!(ledger.journal_sequence(), before_seq, "no journal write");
        // Restart: still unchanged (the *durable* store was untouched).
        drop(ledger);
        let ledger = AuthorityLedger::open(&dir).unwrap();
        assert_eq!(ledger.frontier(), before);
        assert!(ledger.actor_events().is_empty());
        cleanup(&dir);
    }

    #[test]
    fn exact_replay_returns_the_original_receipt() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let batch = vec![LedgerEffect::Actor(fx.founder_incept.clone()).encode()];
        let first = ledger.commit_batch(&batch, &[]).unwrap();
        let seq = ledger.journal_sequence();
        let replay = ledger.commit_batch(&batch, &[]).unwrap();
        assert_eq!(first, replay);
        assert_eq!(ledger.journal_sequence(), seq, "replay writes nothing");
        cleanup(&dir);
    }

    #[test]
    fn historical_standing_survives_current_removal() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let (incept2, actor2) = incept_other(&fx, 2);
        // Batch 1: founder inception + member 2 inception + AddMember(write).
        ledger
            .commit_batch(
                &[
                    LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                    LedgerEffect::Actor(incept2.clone()).encode(),
                ],
                &[],
            )
            .unwrap();
        let add = signed_add(
            &fx,
            ledger.acl_heads(),
            ledger.actor_heads(&fx.founder_actor),
            &actor2,
            vec![Grant::Write],
        );
        ledger
            .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
            .unwrap();
        let member_frontier = ledger.frontier();
        let member_key = crate::crypto::device_from_seed(&seed(2))
            .key_bytes()
            .unwrap();
        assert!(ledger.signer_authorized_at(&member_key, &member_frontier));

        // Remove member 2.
        let remove = acl::sign_op(
            &fx.founder_seed,
            &AclOp {
                action: AclAction::RemoveMember {
                    actor: actor2.clone(),
                },
                by: fx.founder_actor.clone(),
                actor_asof: ledger.actor_heads(&fx.founder_actor),
                nonce: None,
            },
            ledger.acl_heads(),
            &fx.genesis.space_id,
        );
        ledger
            .commit_batch(&[LedgerEffect::Acl(remove).encode()], &[])
            .unwrap();
        let removed_frontier = ledger.frontier();

        // Removed **currently**, still authorized **at the old frontier**.
        assert!(
            ledger.signer_authorized_at(&member_key, &member_frontier),
            "historical authorization is at the referenced frontier"
        );
        assert!(
            !ledger.signer_authorized_at(&member_key, &removed_frontier),
            "current frontier reflects the removal"
        );
        cleanup(&dir);
    }

    #[test]
    fn unauthorized_at_referenced_frontier_despite_current_standing() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let (incept2, actor2) = incept_other(&fx, 2);
        ledger
            .commit_batch(
                &[
                    LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                    LedgerEffect::Actor(incept2.clone()).encode(),
                ],
                &[],
            )
            .unwrap();
        let before_frontier = ledger.frontier();
        let add = signed_add(
            &fx,
            ledger.acl_heads(),
            ledger.actor_heads(&fx.founder_actor),
            &actor2,
            vec![Grant::Write],
        );
        ledger
            .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
            .unwrap();
        let member_key = crate::crypto::device_from_seed(&seed(2))
            .key_bytes()
            .unwrap();
        assert!(ledger.signer_authorized_at(&member_key, &ledger.frontier().clone()));
        assert!(
            !ledger.signer_authorized_at(&member_key, &before_frontier),
            "authorized now but NOT at the referenced earlier frontier"
        );
        cleanup(&dir);
    }

    #[test]
    fn unknown_frontier_is_missing_history_not_a_pass() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let fake = FrontierBody {
            version: 1,
            acl_heads: vec!["ab".repeat(32)],
            actor_heads: vec![],
            space_authority_heads: vec![],
        }
        .encode();
        match ledger.state_at(&fake) {
            Err(LedgerError::MissingHistory(_)) => {}
            other => panic!("expected MissingHistory, got {other:?}"),
        }
        let founder_key = crate::crypto::device_from_seed(&fx.founder_seed)
            .key_bytes()
            .unwrap();
        assert!(!ledger.signer_authorized_at(&founder_key, &fake));
        cleanup(&dir);
    }

    #[test]
    fn malformed_frontiers_reject() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis).unwrap();
        for bytes in [
            vec![],
            vec![0xFF; 4],
            FrontierBody {
                version: 2,
                acl_heads: vec![],
                actor_heads: vec![],
                space_authority_heads: vec![],
            }
            .encode(),
        ] {
            match ledger.state_at(&bytes) {
                Err(LedgerError::MalformedFrontier(_)) => {}
                other => panic!("expected MalformedFrontier, got {other:?}"),
            }
        }
        // Unsorted heads reject.
        let mut unsorted = FrontierBody {
            version: 1,
            acl_heads: vec!["bb".repeat(32), "aa".repeat(32)],
            actor_heads: vec![],
            space_authority_heads: vec![],
        };
        let bytes = postcard::to_stdvec(&unsorted).unwrap();
        match ledger.state_at(&bytes) {
            Err(LedgerError::MalformedFrontier(_)) => {}
            other => panic!("expected MalformedFrontier for unsorted, got {other:?}"),
        }
        unsorted.acl_heads.clear();
        cleanup(&dir);
    }

    #[test]
    fn continuation_equals_complete_replay() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        let (incept2, actor2) = incept_other(&fx, 2);
        let (incept3, actor3) = incept_other(&fx, 3);
        ledger
            .commit_batch(
                &[
                    LedgerEffect::Actor(fx.founder_incept.clone()).encode(),
                    LedgerEffect::Actor(incept2).encode(),
                    LedgerEffect::Actor(incept3).encode(),
                ],
                &[],
            )
            .unwrap();
        // A chain of pure-ACL batches: these take the strict-descendant path.
        for target in [&actor2, &actor3] {
            let add = signed_add(
                &fx,
                ledger.acl_heads(),
                ledger.actor_heads(&fx.founder_actor),
                target,
                vec![Grant::Write],
            );
            ledger
                .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
                .unwrap();
        }
        // Differential: the ledger's materialized state equals the complete
        // acl::replay over the same effect sets.
        let expected = acl::replay(&fx.genesis, &ledger.actor_events(), &ledger.acl_ops());
        assert_eq!(ledger.acl_state().unwrap(), expected);
        assert!(expected.can_write(&actor2));
        assert!(expected.can_write(&actor3));
        cleanup(&dir);
    }

    #[test]
    fn reopen_after_crash_between_batches_shows_complete_state() {
        let dir = tempdir();
        let fx = fx();
        let mut ledger = AuthorityLedger::create(&dir, fx.genesis.clone()).unwrap();
        ledger
            .commit_batch(
                &[LedgerEffect::Actor(fx.founder_incept.clone()).encode()],
                &[],
            )
            .unwrap();
        let frontier = ledger.frontier();
        drop(ledger); // "crash": nothing in flight
        let mut ledger = AuthorityLedger::open(&dir).unwrap();
        assert_eq!(ledger.frontier(), frontier);
        assert_eq!(ledger.actor_events().len(), 1);
        // Historical evaluation still works after reopen.
        let founder_key = crate::crypto::device_from_seed(&fx.founder_seed)
            .key_bytes()
            .unwrap();
        assert!(ledger.signer_authorized_at(&founder_key, &frontier));
        cleanup(&dir);
    }

    fn tempdir() -> PathBuf {
        let mut p = std::env::temp_dir();
        let mut raw = [0u8; 8];
        getrandom::fill(&mut raw).unwrap();
        p.push(format!("lait-ledger-test-{}", hex::encode(raw)));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    fn cleanup(p: &std::path::Path) {
        let _ = std::fs::remove_dir_all(p);
    }

    mod hex {
        pub fn encode(bytes: [u8; 8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
    }
}
