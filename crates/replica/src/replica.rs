//! [`Replica`] — the committing semantic layer over a Fabric engine and the
//! canonical durable Body store.
//!
//! Replica translates a validated set of staged [`BodyOp`]s into semantic
//! [`FabricOp`]s, submits them to a Fabric engine for an atomic apply, and
//! advances its semantic frontier **only** from the returned Fabric receipt.
//! It never authors a Loro delta and never fabricates a receipt.
//!
//! **The canonical store.** A durable Replica persists — through the Fabric
//! journal's six-step commit protocol, at one linearization point per
//! transaction — the canonical signed [`BodyTransactionV1`] record, one sealed
//! [`ProtectedBodyPayloadV1`] object per changed Body (`epoch_id[16] ||
//! nonce[12] || ciphertext_and_tag`; no plaintext Body payload is ever at
//! rest), the [`RequestReceiptV1`] idempotency record, and the signed Manifest
//! root/pages over the full Body set. Recovery reopens exactly that graph: a
//! Body whose key-epoch material is locally held is opened, validated, and
//! imported into the engine; a Body whose epoch key is absent is retained
//! **opaquely** — byte-identical, never decrypted, absent from reads — until a
//! key legitimately arrives.
//!
//! **Convergence.** [`Replica::incorporate`] accepts only a signed
//! [`BodyTransactionV1`] plus the exact descriptor-bound protected payloads:
//! mechanics validates the signer's standing at the transaction's referenced
//! authority frontier, every payload must match its descriptor's ciphertext
//! commitment, and only then does material reach the engine — per Body, via
//! [`fabric::Fabric::import_body`], never as a raw engine snapshot. Supported
//! material becomes exact per-Body Fabric changes; unsupported-but-legitimate
//! material (unknown World/schema, or no local key) is retained opaquely and
//! forwarded byte-identically. Body-level tombstones are local retirement:
//! cross-replica deletion is application state inside a Body, so a tombstoned
//! Body simply leaves this Replica's manifest.

use std::collections::BTreeMap;
use std::sync::Arc;

use fabric::{
    journal::ObjectRef, BodyExport, Fabric, FabricError, FabricKey, FabricOp,
    FabricTransactionRequest, JournaledStore, LoroFabric, MemFabric,
};
use mechanics::crypto::BODY_EPOCH_ID_LEN;
use mechanics::ids::SpaceId;
use serde::{Deserialize, Serialize};

use crate::algebra;
use crate::body::{BodyOp, ContentCommitment};
use crate::convergence::ConvergenceOutcome;
use crate::frontier::{AuthorityFrontier, ReplicaFrontier};
use crate::ids::{BodyKey, EncodingId, SchemaId, WorldId};
use crate::manifest::{ManifestEntryV1, ManifestPageV1, ManifestRootV1, MAX_ENTRIES_PER_PAGE};
use crate::protected::{BodyKeySource, ProtectedBodyPayloadV1, ProtectedError, MAX_BODY_BYTES};
use crate::receipt::RequestReceiptV1;
use crate::transaction::{
    AuthoritySource, BodyDescriptorV1, BodyTransactionV1, TransactionSigner, SPACE_ID_LEN,
};

/// Domain separator for deriving a Fabric key from a Body key.
const BODY_KEY_DOMAIN: &[u8] = b"lait/fabric-key/1";
/// Domain separator for advancing the semantic frontier from a commit receipt.
const FRONTIER_DOMAIN: &[u8] = b"lait/replica-frontier/1";
/// Domain separator for advancing a Body's chain frontier from a transaction.
const BODY_CHAIN_DOMAIN: &[u8] = b"lait/body-chain/1";

/// The mutation-model tags shared with [`crate::protected`].
pub use crate::protected::{MUTATION_ATOMIC, MUTATION_COLLABORATIVE};

/// Why a Replica commit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaCommitError {
    /// A staged operation is not supported by the current engine (the in-memory
    /// reference engine is atomic-only).
    UnsupportedOp,
    /// An operation's path violates the frozen path grammar.
    PathInvalid,
    /// An operation exceeds a frozen algebra limit (value/key/insert size).
    OpLimit,
    /// The operation's type conflicts with what its target is already bound to
    /// (atomic vs collaborative Body, or a second collaborative type at a
    /// bound path).
    TypeConflict,
    /// The operation was structurally invalid at apply time (out-of-bounds
    /// index, unknown element id, counter overflow). Nothing was committed.
    InvalidOp(String),
    /// A staged operation addressed a Body whose immutable schema binding
    /// disagrees with the declared binding. Nothing was committed.
    SchemaMismatch,
    /// Incoming material failed legitimacy validation (signature, signer
    /// authority, or payload binding). Nothing was incorporated.
    Illegitimate(String),
    /// The durable store failed integrity validation on open — never repaired
    /// heuristically; recreation guidance is the caller's.
    Integrity(String),
    /// The Fabric engine failed to apply the transaction.
    Fabric(String),
    /// No authorized key material is held for sealing new local material.
    /// Nothing was committed.
    BodyKeyUnavailable,
    /// The durable write of the committed state failed. The acknowledged
    /// frontier did not advance, and the Replica is poisoned (fail-stop) so the
    /// diverged in-memory representation can never acknowledge further commits.
    Durability(String),
    /// The durable commit's authoritative switch happened but its durability
    /// confirmation failed: the outcome is unknown until the store is reopened
    /// (recovery resolves it from the on-disk manifest). The Replica is
    /// poisoned; NEVER retry the operation through this error — reopen and
    /// re-query instead, or a durably applied operation could be duplicated.
    OutcomeUnknown,
    /// A previous durability failure poisoned this Replica; reopen from the
    /// durable store.
    Poisoned,
    /// A request id was reused with a different payload hash. Nothing was
    /// committed; the original receipt is untouched.
    RequestIdConflict,
    /// The application effect exceeded [`crate::receipt::MAX_EFFECT_BYTES`].
    /// Nothing was committed.
    EffectTooLarge,
}

impl std::fmt::Display for ReplicaCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReplicaCommitError {}

/// The outcome of committing a request through the persistent-idempotency
/// scope: either a fresh commit or a replay of the original receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionOutcome {
    /// The request committed now; the receipt records its result.
    Committed(RequestReceiptV1),
    /// The identical request had already committed; the original receipt is
    /// returned and **nothing was reapplied**.
    Replayed(RequestReceiptV1),
}

impl ActionOutcome {
    /// The receipt either way.
    pub fn receipt(&self) -> &RequestReceiptV1 {
        match self {
            ActionOutcome::Committed(r) | ActionOutcome::Replayed(r) => r,
        }
    }
}

/// A Body's immutable schema binding, established at create and never changed
/// implicitly by a later write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyBinding {
    pub schema: SchemaId,
    pub schema_version: u32,
    pub encoding: EncodingId,
    /// [`MUTATION_ATOMIC`] or [`MUTATION_COLLABORATIVE`].
    pub mutation_model: u8,
}

/// One exported unit per retained transaction: the signed record plus its
/// per-Body sealed payload bytes, byte-identical to what was committed or
/// incorporated.
pub type ExportedMaterial = Vec<(BodyTransactionV1, Vec<(BodyKey, Vec<u8>)>)>;

/// The commit attribution a durable transaction is signed with: the Space, the
/// committing device's signing capability, and the authority frontier the
/// request was authorized at.
pub struct CommitContext<'a> {
    pub space: &'a SpaceId,
    pub signer: &'a dyn TransactionSigner,
    pub authority_frontier: AuthorityFrontier,
}

/// The schemas locally supported for interpreting remote material, declared
/// from the runtime's World registry. Anything not declared here takes the
/// opaque-retention branch during Convergence.
#[derive(Debug, Clone, Default)]
pub struct SupportedSchemas {
    entries: BTreeMap<(WorldId, SchemaId, u32), (EncodingId, u8)>,
}

impl SupportedSchemas {
    pub fn new() -> Self {
        Self::default()
    }
    /// Declare a supported `(world, schema, version)` with its encoding and
    /// mutation-model tag.
    pub fn declare(
        &mut self,
        world: WorldId,
        schema: SchemaId,
        version: u32,
        encoding: EncodingId,
        mutation_model: u8,
    ) {
        self.entries
            .insert((world, schema, version), (encoding, mutation_model));
    }
    pub fn lookup(
        &self,
        world: &WorldId,
        schema: &SchemaId,
        version: u32,
    ) -> Option<&(EncodingId, u8)> {
        self.entries.get(&(world.clone(), schema.clone(), version))
    }
}

/// One Body's record in the Replica index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct BodyRecord {
    binding: BodyBinding,
    /// The per-Body chain frontier: a commitment to this Body's transaction
    /// chain (root, height). Atomic concurrent writes resolve to the
    /// deterministic maximum of `(height, root)`; collaborative chains are
    /// bookkeeping (the engine's causal merge is authoritative).
    chain: ReplicaFrontier,
    /// The transaction that last wrote this Body.
    tx: [u8; 16],
    /// Hash of this Body's current descriptor (manifest entry input).
    descriptor_hash: [u8; 32],
    /// Commitment to this Body's current signed transaction bytes.
    tx_commitment: [u8; 32],
    /// The sealed protected payload object (durable stores only).
    protected: Option<ObjectRef>,
    /// The signed transaction record object (durable stores only).
    transaction: Option<ObjectRef>,
    /// Whether the Body is interpreted by the local engine. `false` is the
    /// opaque branch: retained byte-identically, absent from reads.
    interpreted: bool,
}

/// The store's opaque caller metadata: the complete Replica index, persisted
/// with every commit at the journal's manifest linearization point.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoreMetaV1 {
    version: u8,
    space: Option<SpaceId>,
    frontier: ReplicaFrontier,
    bodies: Vec<(BodyKey, BodyRecord)>,
    receipts: Vec<(Vec<u8>, ObjectRef)>,
    manifest_root: Option<ObjectRef>,
    manifest_pages: Vec<ObjectRef>,
}

/// The Orbit's durable local materialization, over a Fabric engine.
pub struct Replica {
    fabric: Box<dyn Fabric + Send>,
    frontier: ReplicaFrontier,
    durable: Option<JournaledStore>,
    poisoned: bool,
    keys: Option<Arc<dyn BodyKeySource>>,
    space: Option<SpaceId>,
    supported: SupportedSchemas,
    bodies: BTreeMap<BodyKey, BodyRecord>,
    receipts: BTreeMap<Vec<u8>, (RequestReceiptV1, Option<ObjectRef>)>,
    /// Opaque retained material kept in memory for non-durable replicas (a
    /// durable store keeps it as objects; this map indexes the raw envelope
    /// bytes + transaction bytes for byte-identical forwarding either way).
    raw_material: BTreeMap<BodyKey, (Vec<u8>, Vec<u8>)>,
}

/// The canonical Fabric key for a Body: `BLAKE3(domain || world || 0x00 || body)`.
fn fabric_key(key: &BodyKey) -> FabricKey {
    let mut h = blake3::Hasher::new();
    h.update(BODY_KEY_DOMAIN);
    h.update(key.world.as_bytes());
    h.update(&[0x00]);
    h.update(&key.body.as_bytes());
    FabricKey::from_bytes(h.finalize().as_bytes().to_vec())
}

/// Advance the Replica frontier from a commit's causal evidence.
fn advance(prev: ReplicaFrontier, causal: &[u8]) -> ReplicaFrontier {
    let mut h = blake3::Hasher::new();
    h.update(FRONTIER_DOMAIN);
    h.update(&prev.root);
    h.update(causal);
    ReplicaFrontier::new(
        *h.finalize().as_bytes(),
        prev.transaction_count.saturating_add(1),
    )
}

/// Advance a Body's chain frontier from the transaction that wrote it.
fn advance_chain(prev: ReplicaFrontier, tx: &[u8; 16]) -> ReplicaFrontier {
    let mut h = blake3::Hasher::new();
    h.update(BODY_CHAIN_DOMAIN);
    h.update(&prev.root);
    h.update(tx);
    ReplicaFrontier::new(
        *h.finalize().as_bytes(),
        prev.transaction_count.saturating_add(1),
    )
}

/// The deterministic atomic-conflict order: height first, then root bytes.
fn chain_order(a: &ReplicaFrontier, b: &ReplicaFrontier) -> std::cmp::Ordering {
    a.transaction_count
        .cmp(&b.transaction_count)
        .then_with(|| a.root.cmp(&b.root))
}

fn mint_tx_id() -> [u8; 16] {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("getrandom");
    raw
}

fn space_bytes(space: &SpaceId) -> Option<[u8; SPACE_ID_LEN]> {
    <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()
}

fn descriptor_hash(d: &BodyDescriptorV1) -> [u8; 32] {
    let bytes = postcard::to_stdvec(d).expect("postcard descriptor");
    *blake3::hash(&bytes).as_bytes()
}

fn tx_commitment(bytes: &[u8]) -> [u8; 32] {
    *blake3::hash(bytes).as_bytes()
}

impl Replica {
    /// Build a Replica over a given Fabric engine (no durability, no keys).
    pub fn new(fabric: Box<dyn Fabric + Send>) -> Self {
        Self {
            fabric,
            frontier: ReplicaFrontier::EMPTY,
            durable: None,
            poisoned: false,
            keys: None,
            space: None,
            supported: SupportedSchemas::default(),
            bodies: BTreeMap::new(),
            receipts: BTreeMap::new(),
            raw_material: BTreeMap::new(),
        }
    }

    /// Build a Replica over the in-memory reference engine.
    pub fn in_memory() -> Self {
        Self::new(Box::new(MemFabric::new()))
    }

    /// Build a Loro-backed Replica with **no** durable store (tests/scratch).
    pub fn loro() -> Self {
        Self::new(Box::new(LoroFabric::new()))
    }

    /// Attach a mechanics-owned key source (required to seal local commits and
    /// open protected material).
    pub fn with_keys(mut self, keys: Arc<dyn BodyKeySource>) -> Self {
        self.keys = Some(keys);
        self
    }

    /// Declare the locally supported schemas (from the runtime's registry).
    /// Remote material outside this set takes the opaque branch.
    pub fn set_supported(&mut self, supported: SupportedSchemas) {
        self.supported = supported;
    }

    /// Open the durable Replica at a journaled store root: run crash recovery,
    /// verify and load the canonical object graph (signed transactions, sealed
    /// Body payloads, receipts, manifest), and import every Body whose key
    /// epoch is locally held into the engine. A Body without local key
    /// material is retained opaquely. Missing or corrupt objects fail
    /// integrity validation without heuristic repair.
    pub fn open_journaled(
        root: impl Into<std::path::PathBuf>,
        keys: Arc<dyn BodyKeySource>,
    ) -> Result<Self, ReplicaCommitError> {
        let store = match JournaledStore::open(root) {
            Ok(s) => s,
            Err(FabricError::Integrity(m)) => return Err(ReplicaCommitError::Integrity(m)),
            Err(e) => return Err(ReplicaCommitError::Durability(e.to_string())),
        };
        let mut replica = Self::new(Box::new(LoroFabric::new())).with_keys(keys.clone());
        let Some(manifest) = store.manifest() else {
            replica.durable = Some(store);
            return Ok(replica);
        };
        let meta: StoreMetaV1 = postcard::from_bytes(&manifest.meta)
            .map_err(|e| ReplicaCommitError::Integrity(format!("store meta: {e}")))?;
        if meta.version != 1 {
            return Err(ReplicaCommitError::Integrity(format!(
                "unsupported store meta version {}",
                meta.version
            )));
        }
        replica.frontier = meta.frontier;
        replica.space = meta.space.clone();
        for (key, mut record) in meta.bodies {
            let (Some(protected_ref), Some(tx_ref)) = (record.protected, record.transaction) else {
                return Err(ReplicaCommitError::Integrity(
                    "body record without durable objects".into(),
                ));
            };
            // The transaction record must decode and verify structurally.
            let tx_bytes = store
                .read_object(&tx_ref)
                .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
            let tx = BodyTransactionV1::decode_canonical(&tx_bytes)
                .map_err(|e| ReplicaCommitError::Integrity(format!("transaction: {e}")))?;
            tx.verify()
                .map_err(|e| ReplicaCommitError::Integrity(format!("transaction: {e}")))?;
            let envelope = store
                .read_object(&protected_ref)
                .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
            let epoch = mechanics::crypto::body_epoch_id(&envelope).ok_or_else(|| {
                ReplicaCommitError::Integrity("protected object without epoch prefix".into())
            })?;
            // A Body retained opaquely stays opaque at reopen: interpreting it
            // later requires explicit revalidation through the incorporation
            // path, never a silent flip on restart. A Body that WAS
            // interpreted must open again — if its epoch key has since gone
            // away it degrades to opaque (retained, unread) rather than
            // failing the whole store.
            match (record.interpreted, keys.opening_key(&epoch)) {
                (true, Some(key_cap)) => {
                    let payload = ProtectedBodyPayloadV1::open(&key_cap, &envelope)
                        .map_err(|e| ReplicaCommitError::Integrity(format!("protected: {e}")))?;
                    replica
                        .fabric
                        .import_body(&fabric_key(&key), &payload.payload)
                        .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
                }
                (true, None) | (false, _) => {
                    record.interpreted = false;
                    replica
                        .raw_material
                        .insert(key.clone(), (envelope, tx_bytes));
                }
            }
            replica.bodies.insert(key, record);
        }
        for (scope, receipt_ref) in meta.receipts {
            let bytes = store
                .read_object(&receipt_ref)
                .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
            let receipt = RequestReceiptV1::decode_canonical(&bytes)
                .map_err(|e| ReplicaCommitError::Integrity(format!("receipt: {e}")))?;
            replica.receipts.insert(scope, (receipt, Some(receipt_ref)));
        }
        replica.durable = Some(store);
        Ok(replica)
    }

    /// Test seam: attach a fault injector to the underlying journaled store
    /// (see [`fabric::journal::FAULT_POINTS`]). No effect without a durable
    /// store.
    pub fn with_store_fault_injector(mut self, injector: fabric::journal::FaultInjector) -> Self {
        if let Some(store) = self.durable.take() {
            self.durable = Some(store.with_fault_injector(injector));
        }
        self
    }

    /// The current semantic frontier.
    pub fn frontier(&self) -> ReplicaFrontier {
        self.frontier
    }

    /// A Body's immutable schema binding, if the Body exists.
    pub fn binding(&self, key: &BodyKey) -> Option<&BodyBinding> {
        self.bodies.get(key).map(|r| &r.binding)
    }

    /// Whether a Body is retained opaquely (present but uninterpretable —
    /// unknown World/schema or missing key material).
    pub fn is_opaque(&self, key: &BodyKey) -> bool {
        self.bodies.get(key).is_some_and(|r| !r.interpreted)
    }

    /// Every Body currently present (interpreted or opaque).
    pub fn body_keys(&self) -> Vec<BodyKey> {
        self.bodies.keys().cloned().collect()
    }

    /// Look up a request in the persistent-idempotency scope
    /// `(Space, World, Device, RequestId)`. An identical payload hash returns
    /// the original receipt — the caller must **not** reapply; a different
    /// payload hash under the same scope is a typed conflict; an unknown scope
    /// is `None` (commit may proceed).
    pub fn lookup_action(
        &self,
        space: &SpaceId,
        world: &WorldId,
        device: &mechanics::ids::DeviceId,
        request: &[u8; 16],
        payload_hash: &[u8; 32],
    ) -> Result<Option<RequestReceiptV1>, ReplicaCommitError> {
        let key = crate::receipt::scope_key(space, world, device, request);
        match self.receipts.get(&key) {
            None => Ok(None),
            Some((r, _)) if &r.payload_hash == payload_hash => Ok(Some(r.clone())),
            Some(_) => Err(ReplicaCommitError::RequestIdConflict),
        }
    }

    /// Commit staged operations **without** durable attribution. Valid only on
    /// a non-durable Replica (tests/scratch): a durable store requires the
    /// signed-transaction path ([`Replica::commit_action`] or
    /// [`Replica::incorporate`]).
    pub fn commit(
        &mut self,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
    ) -> Result<ReplicaFrontier, ReplicaCommitError> {
        if self.durable.is_some() {
            return Err(ReplicaCommitError::Illegitimate(
                "a durable Replica commits only signed, attributed transactions".into(),
            ));
        }
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        let receipt = self.apply_ops(request_label, ops)?;
        // Track minimal body records so bindings/tombstones behave uniformly.
        self.update_records_unattributed(ops);
        self.frontier = advance(self.frontier, receipt.causal().as_bytes());
        Ok(self.frontier)
    }

    /// Commit a request's staged operations under its persistent-idempotency
    /// scope, as one durable signed transaction. Identical replay returns the
    /// original receipt **without reapplying** a single operation; reuse with
    /// a different payload hash is [`ReplicaCommitError::RequestIdConflict`];
    /// a fresh request commits durably — signed transaction record, sealed
    /// per-Body payloads, idempotency receipt, and manifest, at one journal
    /// linearization point — and records its receipt with the transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_action(
        &mut self,
        ctx: &CommitContext<'_>,
        world: &WorldId,
        device: &mechanics::ids::DeviceId,
        request: &[u8; 16],
        payload_hash: &[u8; 32],
        effect: Vec<u8>,
        scopes: Vec<BodyKey>,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
        bindings: &[(BodyKey, BodyBinding)],
    ) -> Result<ActionOutcome, ReplicaCommitError> {
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        if let Some(receipt) =
            self.lookup_action(ctx.space, world, device, request, payload_hash)?
        {
            return Ok(ActionOutcome::Replayed(receipt));
        }
        if effect.len() > crate::receipt::MAX_EFFECT_BYTES {
            return Err(ReplicaCommitError::EffectTooLarge);
        }
        // Space pinning: one store, one Space.
        match &self.space {
            None => self.space = Some(ctx.space.clone()),
            Some(space) if space == ctx.space => {}
            Some(_) => {
                return Err(ReplicaCommitError::Illegitimate(
                    "commit addressed to a different Space".into(),
                ))
            }
        }
        // Validate schema-binding immutability BEFORE anything is applied.
        let bindings: BTreeMap<&BodyKey, &BodyBinding> =
            bindings.iter().map(|(k, b)| (k, b)).collect();
        let mut touched: Vec<BodyKey> = ops.iter().map(|(k, _)| k.clone()).collect();
        touched.sort();
        touched.dedup();
        for key in &touched {
            match (self.bodies.get(key), bindings.get(key)) {
                (Some(record), Some(declared)) if &&record.binding != declared => {
                    return Err(ReplicaCommitError::SchemaMismatch)
                }
                (None, None) => {
                    return Err(ReplicaCommitError::SchemaMismatch);
                }
                _ => {}
            }
        }
        // A durable commit needs sealing material before the engine moves; a
        // non-durable Replica with keys still seals (so its material can be
        // exported), and one without keys commits locally-only.
        let sealing = match self.keys.as_ref().and_then(|k| k.sealing_key()) {
            Some(key) => Some(key),
            None if self.durable.is_some() => return Err(ReplicaCommitError::BodyKeyUnavailable),
            None => None,
        };

        let receipt = self.apply_ops(request_label, ops)?;
        let next_frontier = advance(self.frontier, receipt.causal().as_bytes());
        let tx_id = mint_tx_id();

        // Build per-Body chain advances and records for every touched Body.
        let mut new_records: BTreeMap<BodyKey, Option<BodyRecord>> = BTreeMap::new();
        let mut sealed: Vec<(BodyKey, Vec<u8>, ProtectedBodyPayloadV1)> = Vec::new();
        for key in &touched {
            let export = self.fabric.export_body(&fabric_key(key));
            match export {
                None => {
                    // Tombstoned/removed: local retirement, drops from index.
                    new_records.insert(key.clone(), None);
                }
                Some(export) => {
                    let base = self
                        .bodies
                        .get(key)
                        .map(|r| r.chain)
                        .unwrap_or(ReplicaFrontier::EMPTY);
                    let chain = advance_chain(base, &tx_id);
                    let binding = match bindings.get(key) {
                        Some(b) => (*b).clone(),
                        None => self
                            .bodies
                            .get(key)
                            .map(|r| r.binding.clone())
                            .expect("validated above"),
                    };
                    let payload = ProtectedBodyPayloadV1::new(export, base, chain);
                    let envelope = match &sealing {
                        Some(sealing) => payload.seal(sealing).map_err(|e| {
                            self.poisoned = true;
                            match e {
                                ProtectedError::BodyTooLarge => ReplicaCommitError::OpLimit,
                                _ => ReplicaCommitError::Fabric(e.to_string()),
                            }
                        })?,
                        None => Vec::new(),
                    };
                    new_records.insert(
                        key.clone(),
                        Some(BodyRecord {
                            binding,
                            chain,
                            tx: tx_id,
                            descriptor_hash: [0u8; 32], // filled below
                            tx_commitment: [0u8; 32],   // filled below
                            protected: None,
                            transaction: None,
                            interpreted: true,
                        }),
                    );
                    sealed.push((key.clone(), envelope, payload));
                }
            }
        }

        // Durable path: build the signed transaction + manifest and run the
        // journal protocol at one linearization point.
        let durable_result = if sealing.is_some() {
            let signer_key = ctx.signer.signer_key();
            let mut descriptors: Vec<BodyDescriptorV1> = Vec::new();
            for (key, envelope, _) in &sealed {
                let record = new_records
                    .get(key)
                    .and_then(|r| r.as_ref())
                    .expect("sealed bodies have records");
                descriptors.push(BodyDescriptorV1 {
                    space: space_bytes(ctx.space)
                        .ok_or_else(|| ReplicaCommitError::Illegitimate("space id shape".into()))?,
                    world: key.world.clone(),
                    body: key.body.clone(),
                    schema: record.binding.schema.clone(),
                    schema_version: record.binding.schema_version,
                    encoding: record.binding.encoding.clone(),
                    replica_frontier: next_frontier,
                    content_commitment: ContentCommitment::over_protected_payload(envelope)
                        .as_bytes(),
                    transaction: tx_id,
                    signer: signer_key,
                    authority_frontier: ctx.authority_frontier.clone(),
                });
            }
            descriptors.sort_by_key(|d| d.key());
            let tx = BodyTransactionV1::sign_with(
                ctx.space,
                crate::frontier::TransactionId::from_bytes(tx_id),
                next_frontier,
                ctx.authority_frontier.clone(),
                descriptors,
                ctx.signer,
            )
            .ok_or_else(|| ReplicaCommitError::Illegitimate("sign transaction".into()))?;
            let receipt_record = RequestReceiptV1 {
                version: 1,
                space: ctx.space.clone(),
                world: world.clone(),
                device: device.clone(),
                request: *request,
                payload_hash: *payload_hash,
                effect: effect.clone(),
                scopes: scopes.clone(),
                frontier: next_frontier,
            };
            if self.durable.is_some() {
                Some(self.persist_transaction(
                    ctx,
                    &tx,
                    &sealed,
                    &mut new_records,
                    Some(receipt_record),
                    next_frontier,
                )?)
            } else {
                // Non-durable but keyed: retain the signed material in memory
                // so it can be exported byte-identically.
                let tx_bytes = tx.encode();
                for (key, envelope, _) in &sealed {
                    self.raw_material
                        .insert(key.clone(), (envelope.clone(), tx_bytes.clone()));
                }
                Some(receipt_record)
            }
        } else {
            None
        };

        // Apply the record updates in memory.
        for (key, record) in new_records {
            match record {
                None => {
                    self.bodies.remove(&key);
                    self.raw_material.remove(&key);
                }
                Some(record) => {
                    self.bodies.insert(key, record);
                }
            }
        }
        self.frontier = next_frontier;
        let receipt_record = match durable_result {
            Some(receipt) => receipt,
            None => RequestReceiptV1 {
                version: 1,
                space: ctx.space.clone(),
                world: world.clone(),
                device: device.clone(),
                request: *request,
                payload_hash: *payload_hash,
                effect,
                scopes,
                frontier: next_frontier,
            },
        };
        self.receipts
            .insert(receipt_record.scope_key(), (receipt_record.clone(), None));
        Ok(ActionOutcome::Committed(receipt_record))
    }

    /// Incorporate remote material through the Convergence pipeline. The signed
    /// [`BodyTransactionV1`] is verified — structure, signature, **and signer
    /// standing at its referenced authority frontier through mechanics** — and
    /// every provided payload must match its descriptor's ciphertext
    /// commitment **before** any byte reaches the engine. Supported, openable
    /// material becomes exact per-Body Fabric changes; unsupported-but-
    /// legitimate material is retained opaquely, byte-identically. Never
    /// reachable from a World or an ordinary Session. Durability before
    /// acknowledgment applies exactly as for a local commit.
    pub fn incorporate(
        &mut self,
        ctx: &CommitContext<'_>,
        tx: &BodyTransactionV1,
        payloads: &[(BodyKey, Vec<u8>)],
        authority: &dyn AuthoritySource,
    ) -> Result<ConvergenceOutcome, ReplicaCommitError> {
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        // Legitimacy first: mechanics-validated signature + authority.
        tx.verify_authorized(authority)
            .map_err(|e| ReplicaCommitError::Illegitimate(e.to_string()))?;
        // Space binding.
        let tx_space = std::str::from_utf8(&tx.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or_else(|| ReplicaCommitError::Illegitimate("space id".into()))?;
        match &self.space {
            None => self.space = Some(tx_space.clone()),
            Some(space) if space == &tx_space => {}
            Some(_) => {
                return Err(ReplicaCommitError::Illegitimate(
                    "transaction addressed to a different Space".into(),
                ))
            }
        }
        // Every provided payload must resolve to exactly one descriptor and
        // match its ciphertext commitment; bounds before any allocation.
        let mut resolved: Vec<(&BodyDescriptorV1, &[u8])> = Vec::new();
        for (key, payload) in payloads {
            if payload.len() > MAX_BODY_BYTES {
                return Err(ReplicaCommitError::Illegitimate(
                    "payload exceeds the Body maximum".into(),
                ));
            }
            let descriptor = tx
                .descriptors
                .iter()
                .find(|d| &d.key() == key)
                .ok_or_else(|| {
                    ReplicaCommitError::Illegitimate("payload without a matching descriptor".into())
                })?;
            if !descriptor.commits_to(payload) {
                return Err(ReplicaCommitError::Illegitimate(
                    "payload does not match the signed commitment".into(),
                ));
            }
            resolved.push((descriptor, payload));
        }

        let previous = self.frontier;
        let mut outcome = ConvergenceOutcome::unchanged(previous);
        let mut changed: Vec<(BodyKey, Vec<u8>, Option<BodyRecord>)> = Vec::new();
        let mut engine_causal: Vec<u8> = Vec::new();

        for (descriptor, envelope) in &resolved {
            let key = descriptor.key();
            // Immutable schema binding across replicas too.
            if let Some(record) = self.bodies.get(&key) {
                if record.binding.schema != descriptor.schema
                    || record.binding.schema_version != descriptor.schema_version
                    || record.binding.encoding != descriptor.encoding
                {
                    outcome.rejected += 1;
                    continue;
                }
            }
            let supported =
                self.supported
                    .lookup(&key.world, &descriptor.schema, descriptor.schema_version);
            let epoch = mechanics::crypto::body_epoch_id(envelope);
            let opening = match (&self.keys, epoch) {
                (Some(keys), Some(epoch)) => keys.opening_key(&epoch),
                _ => None,
            };
            match (supported, opening) {
                (Some((encoding, model)), Some(open_key)) => {
                    if encoding != &descriptor.encoding {
                        outcome.rejected += 1;
                        continue;
                    }
                    let payload = match ProtectedBodyPayloadV1::open(&open_key, envelope) {
                        Ok(p) => p,
                        Err(_) => {
                            // InvalidProtectedBody: authenticated rejection.
                            outcome.rejected += 1;
                            continue;
                        }
                    };
                    if payload.mutation_model != *model {
                        outcome.rejected += 1;
                        continue;
                    }
                    let current_chain = self.bodies.get(&key).map(|r| r.chain);
                    let apply = match (&payload.payload, current_chain) {
                        // Fresh body: apply.
                        (_, None) => true,
                        // Already known (chain equality): unchanged.
                        (_, Some(chain)) if chain == payload.resulting_frontier => false,
                        // Descends our current chain: apply.
                        (_, Some(chain)) if chain == payload.base_frontier => true,
                        // Concurrent atomic: the deterministic maximum wins.
                        (BodyExport::Atomic(_), Some(chain)) => {
                            chain_order(&payload.resulting_frontier, &chain)
                                == std::cmp::Ordering::Greater
                        }
                        // Concurrent collaborative: the engine merges causally.
                        (BodyExport::Collaborative(_), Some(_)) => true,
                    };
                    if !apply {
                        outcome.unchanged += 1;
                        continue;
                    }
                    match self.fabric.import_body(&fabric_key(&key), &payload.payload) {
                        Ok(None) => {
                            outcome.unchanged += 1;
                        }
                        Ok(Some(receipt)) => {
                            outcome.accepted += 1;
                            engine_causal.extend_from_slice(receipt.causal().as_bytes());
                            let chain = match &payload.payload {
                                BodyExport::Atomic(_) => payload.resulting_frontier,
                                BodyExport::Collaborative(_) => {
                                    // Bookkeeping: combine deterministically.
                                    match current_chain {
                                        None => payload.resulting_frontier,
                                        Some(chain) => {
                                            combine_chains(&chain, &payload.resulting_frontier)
                                        }
                                    }
                                }
                            };
                            changed.push((
                                key.clone(),
                                envelope.to_vec(),
                                Some(BodyRecord {
                                    binding: BodyBinding {
                                        schema: descriptor.schema.clone(),
                                        schema_version: descriptor.schema_version,
                                        encoding: descriptor.encoding.clone(),
                                        mutation_model: *model,
                                    },
                                    chain,
                                    tx: descriptor.transaction,
                                    descriptor_hash: descriptor_hash(descriptor),
                                    tx_commitment: [0u8; 32], // filled at persist
                                    protected: None,
                                    transaction: None,
                                    interpreted: true,
                                }),
                            ));
                        }
                        Err(FabricError::TypeConflict) => {
                            outcome.rejected += 1;
                        }
                        Err(e) => {
                            self.poisoned = true;
                            return Err(ReplicaCommitError::Fabric(e.to_string()));
                        }
                    }
                }
                _ => {
                    // The opaque branch: authorized, commitment-bound material
                    // for an unavailable World/schema or a missing key epoch.
                    // Retain byte-identically; never call a World, never
                    // decrypt, never import into the engine.
                    let already = self
                        .raw_material
                        .get(&key)
                        .is_some_and(|(bytes, _)| bytes.as_slice() == *envelope);
                    if already {
                        outcome.unchanged += 1;
                        continue;
                    }
                    outcome.unsupported_retained += 1;
                    let model_tag = supported.map(|(_, m)| *m).unwrap_or(0);
                    // A content-derived placeholder chain: deterministic per
                    // envelope, comparable across replicas holding the same
                    // opaque bytes.
                    let chain = ReplicaFrontier::new(
                        *blake3::hash(envelope).as_bytes(),
                        self.bodies
                            .get(&key)
                            .map(|r| r.chain.transaction_count + 1)
                            .unwrap_or(1),
                    );
                    changed.push((
                        key.clone(),
                        envelope.to_vec(),
                        Some(BodyRecord {
                            binding: BodyBinding {
                                schema: descriptor.schema.clone(),
                                schema_version: descriptor.schema_version,
                                encoding: descriptor.encoding.clone(),
                                mutation_model: model_tag,
                            },
                            chain,
                            tx: descriptor.transaction,
                            descriptor_hash: descriptor_hash(descriptor),
                            tx_commitment: [0u8; 32],
                            protected: None,
                            transaction: None,
                            interpreted: false,
                        }),
                    ));
                }
            }
        }

        if changed.is_empty() {
            outcome.current = previous;
            return Ok(outcome);
        }

        // Advance the frontier from the transaction + engine evidence.
        let mut causal = Vec::with_capacity(16 + engine_causal.len());
        causal.extend_from_slice(&tx.transaction);
        causal.extend_from_slice(&engine_causal);
        let next_frontier = advance(previous, &causal);

        // Durable path: retain the received transaction and payload bytes
        // byte-identically at one journal linearization point.
        if self.durable.is_some() {
            let mut records: BTreeMap<BodyKey, Option<BodyRecord>> = changed
                .iter()
                .map(|(k, _, r)| (k.clone(), r.clone()))
                .collect();
            let sealed: Vec<(BodyKey, Vec<u8>, ())> = changed
                .iter()
                .map(|(k, bytes, _)| (k.clone(), bytes.clone(), ()))
                .collect();
            self.persist_incorporation(ctx, tx, &sealed, &mut records, next_frontier)?;
            for (key, record) in records {
                if let Some(record) = record {
                    if !record.interpreted {
                        // Keep the raw bytes indexed for forwarding.
                        if let Some((_, bytes, _)) = changed.iter().find(|(k, _, _)| k == &key) {
                            self.raw_material
                                .insert(key.clone(), (bytes.clone(), tx.encode()));
                        }
                    }
                    self.bodies.insert(key, record);
                }
            }
        } else {
            for (key, bytes, record) in changed {
                if let Some(record) = record {
                    if !record.interpreted {
                        self.raw_material.insert(key.clone(), (bytes, tx.encode()));
                    }
                    self.bodies.insert(key, record);
                }
            }
        }
        self.frontier = next_frontier;
        outcome.current = next_frontier;
        Ok(outcome)
    }

    /// Export this Replica's current material for a peer: for each Body, its
    /// **retained** signed transaction record and protected payload bytes —
    /// byte-identical to what was committed or incorporated, grouped by
    /// transaction. Opaque Bodies forward their retained bytes unchanged.
    pub fn export_material(&self) -> Result<ExportedMaterial, ReplicaCommitError> {
        type Grouped = BTreeMap<[u8; 16], (BodyTransactionV1, Vec<(BodyKey, Vec<u8>)>)>;
        let mut by_tx: Grouped = BTreeMap::new();
        for (key, record) in &self.bodies {
            let (envelope, tx_bytes) = match (&self.durable, self.raw_material.get(key)) {
                (_, Some((envelope, tx_bytes))) => (envelope.clone(), tx_bytes.clone()),
                (Some(store), None) => {
                    let (Some(protected_ref), Some(tx_ref)) =
                        (record.protected, record.transaction)
                    else {
                        continue;
                    };
                    let envelope = store
                        .read_object(&protected_ref)
                        .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
                    let tx_bytes = store
                        .read_object(&tx_ref)
                        .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
                    (envelope, tx_bytes)
                }
                (None, None) => continue,
            };
            let tx = BodyTransactionV1::decode_canonical(&tx_bytes)
                .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
            let entry = by_tx.entry(record.tx).or_insert_with(|| (tx, Vec::new()));
            entry.1.push((key.clone(), envelope));
        }
        Ok(by_tx.into_values().collect())
    }

    /// Apply staged ops to the engine, translating and validating each.
    fn apply_ops(
        &mut self,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
    ) -> Result<fabric::FabricCommitReceipt, ReplicaCommitError> {
        let mut fabric_ops = Vec::with_capacity(ops.len());
        for (key, op) in ops {
            fabric_ops.push(translate(fabric_key(key), op)?);
        }
        match self
            .fabric
            .commit(FabricTransactionRequest::new(request_label, fabric_ops))
        {
            Ok(r) => Ok(r),
            Err(FabricError::Unsupported) => Err(ReplicaCommitError::UnsupportedOp),
            Err(FabricError::TypeConflict) => Err(ReplicaCommitError::TypeConflict),
            Err(FabricError::InvalidOp(m)) => Err(ReplicaCommitError::InvalidOp(m)),
            Err(FabricError::Integrity(m)) => Err(ReplicaCommitError::Integrity(m)),
            Err(FabricError::OutcomeUnknown) => {
                self.poisoned = true;
                Err(ReplicaCommitError::OutcomeUnknown)
            }
            Err(FabricError::Durability(m)) => {
                self.poisoned = true;
                Err(ReplicaCommitError::Durability(m))
            }
        }
    }

    /// Track records for an unattributed (non-durable) commit so bindings and
    /// reads stay consistent in tests.
    fn update_records_unattributed(&mut self, ops: &[(BodyKey, BodyOp)]) {
        let tx = mint_tx_id();
        let mut touched: Vec<BodyKey> = ops.iter().map(|(k, _)| k.clone()).collect();
        touched.sort();
        touched.dedup();
        for key in touched {
            match self.fabric.export_body(&fabric_key(&key)) {
                None => {
                    self.bodies.remove(&key);
                }
                Some(export) => {
                    let base = self
                        .bodies
                        .get(&key)
                        .map(|r| r.chain)
                        .unwrap_or(ReplicaFrontier::EMPTY);
                    let model = match export {
                        BodyExport::Atomic(_) => MUTATION_ATOMIC,
                        BodyExport::Collaborative(_) => MUTATION_COLLABORATIVE,
                    };
                    let record = BodyRecord {
                        binding: self.bodies.get(&key).map(|r| r.binding.clone()).unwrap_or(
                            BodyBinding {
                                schema: SchemaId::parse("unattributed").expect("schema id"),
                                schema_version: 1,
                                encoding: EncodingId::parse("bytes").expect("encoding id"),
                                mutation_model: model,
                            },
                        ),
                        chain: advance_chain(base, &tx),
                        tx,
                        descriptor_hash: [0u8; 32],
                        tx_commitment: [0u8; 32],
                        protected: None,
                        transaction: None,
                        interpreted: true,
                    };
                    self.bodies.insert(key, record);
                }
            }
        }
    }

    /// Persist a local signed transaction: the transaction record, sealed
    /// payloads, receipt, and manifest, at one journal linearization point.
    /// Returns the durable receipt.
    fn persist_transaction(
        &mut self,
        ctx: &CommitContext<'_>,
        tx: &BodyTransactionV1,
        sealed: &[(BodyKey, Vec<u8>, ProtectedBodyPayloadV1)],
        new_records: &mut BTreeMap<BodyKey, Option<BodyRecord>>,
        receipt: Option<RequestReceiptV1>,
        next_frontier: ReplicaFrontier,
    ) -> Result<RequestReceiptV1, ReplicaCommitError> {
        let sealed: Vec<(BodyKey, Vec<u8>, ())> = sealed
            .iter()
            .map(|(k, e, _)| (k.clone(), e.clone(), ()))
            .collect();
        let receipt = receipt.expect("local commits carry a receipt");
        self.persist_graph(ctx, tx, &sealed, new_records, Some(&receipt), next_frontier)?;
        Ok(receipt)
    }

    fn persist_incorporation(
        &mut self,
        ctx: &CommitContext<'_>,
        tx: &BodyTransactionV1,
        sealed: &[(BodyKey, Vec<u8>, ())],
        new_records: &mut BTreeMap<BodyKey, Option<BodyRecord>>,
        next_frontier: ReplicaFrontier,
    ) -> Result<(), ReplicaCommitError> {
        self.persist_graph(ctx, tx, sealed, new_records, None, next_frontier)
    }

    /// The one durable-write path: assemble the canonical object graph and run
    /// the journal protocol. Every failure before the manifest linearization
    /// point poisons this handle (the engine has already applied in memory);
    /// `OutcomeUnknown` demands reopen-not-retry.
    fn persist_graph(
        &mut self,
        ctx: &CommitContext<'_>,
        tx: &BodyTransactionV1,
        sealed: &[(BodyKey, Vec<u8>, ())],
        new_records: &mut BTreeMap<BodyKey, Option<BodyRecord>>,
        receipt: Option<&RequestReceiptV1>,
        next_frontier: ReplicaFrontier,
    ) -> Result<(), ReplicaCommitError> {
        let tx_bytes = tx.encode();
        let tx_ref = object_ref(&tx_bytes);
        let commitment = tx_commitment(&tx_bytes);

        // Fill object refs + descriptor hashes into the new records.
        for (key, envelope, _) in sealed {
            if let Some(Some(record)) = new_records.get_mut(key) {
                record.protected = Some(object_ref(envelope));
                record.transaction = Some(tx_ref);
                record.tx_commitment = commitment;
                if record.descriptor_hash == [0u8; 32] {
                    if let Some(d) = tx.descriptors.iter().find(|d| &d.key() == key) {
                        record.descriptor_hash = descriptor_hash(d);
                    }
                }
            }
        }

        // The post-commit body index: current records overlaid with the new.
        let mut bodies: BTreeMap<BodyKey, BodyRecord> = self.bodies.clone();
        for (key, record) in new_records.iter() {
            match record {
                None => {
                    bodies.remove(key);
                }
                Some(r) => {
                    bodies.insert(key.clone(), r.clone());
                }
            }
        }

        // Manifest pages over the full Body set.
        let space = ctx.space;
        let entries: Vec<ManifestEntryV1> = bodies
            .iter()
            .map(|(key, r)| ManifestEntryV1 {
                key: key.clone(),
                descriptor_hash: r.descriptor_hash,
                transaction_commitment: r.tx_commitment,
            })
            .collect();
        let mut pages: Vec<ManifestPageV1> = Vec::new();
        for (i, chunk) in entries.chunks(MAX_ENTRIES_PER_PAGE).enumerate() {
            pages.push(
                ManifestPageV1::new(space, i as u32, chunk.to_vec())
                    .ok_or_else(|| ReplicaCommitError::Illegitimate("space id shape".into()))?,
            );
        }
        let root = ManifestRootV1::sign_with(
            space,
            next_frontier,
            &pages,
            ctx.authority_frontier.clone(),
            ctx.signer,
        )
        .ok_or_else(|| ReplicaCommitError::Illegitimate("sign manifest root".into()))?;
        let root_bytes = root.encode();
        let page_bytes: Vec<Vec<u8>> = pages.iter().map(|p| p.encode()).collect();

        // Receipts: existing durable refs are kept; the new one is written.
        let mut receipt_meta: Vec<(Vec<u8>, ObjectRef)> = Vec::new();
        let mut keep: Vec<ObjectRef> = Vec::new();
        for (scope, (_, existing_ref)) in &self.receipts {
            if let Some(r) = existing_ref {
                receipt_meta.push((scope.clone(), *r));
                keep.push(*r);
            }
        }
        let receipt_bytes = receipt.map(|r| r.encode());
        if let (Some(receipt), Some(bytes)) = (receipt, &receipt_bytes) {
            receipt_meta.push((receipt.scope_key(), object_ref(bytes)));
        }

        // New objects, deduped by content address.
        let mut new_objects: Vec<Vec<u8>> = Vec::new();
        let mut seen: std::collections::BTreeSet<[u8; 32]> = std::collections::BTreeSet::new();
        let push_obj = |bytes: &Vec<u8>,
                        seen: &mut std::collections::BTreeSet<[u8; 32]>,
                        out: &mut Vec<Vec<u8>>| {
            let r = object_ref(bytes);
            if seen.insert(r.hash) {
                out.push(bytes.clone());
            }
        };
        push_obj(&tx_bytes, &mut seen, &mut new_objects);
        for (_, envelope, _) in sealed {
            push_obj(envelope, &mut seen, &mut new_objects);
        }
        if let Some(bytes) = &receipt_bytes {
            push_obj(bytes, &mut seen, &mut new_objects);
        }
        push_obj(&root_bytes, &mut seen, &mut new_objects);
        for p in &page_bytes {
            push_obj(p, &mut seen, &mut new_objects);
        }

        // Keep: every carried object the post-commit index references.
        for record in bodies.values() {
            if let Some(r) = record.protected {
                if !seen.contains(&r.hash) {
                    keep.push(r);
                }
            }
            if let Some(r) = record.transaction {
                if !seen.contains(&r.hash) {
                    keep.push(r);
                }
            }
        }
        keep.sort_by_key(|r| r.hash);
        keep.dedup_by_key(|r| r.hash);

        let meta = StoreMetaV1 {
            version: 1,
            space: Some(space.clone()),
            frontier: next_frontier,
            bodies: bodies.clone().into_iter().collect(),
            receipts: receipt_meta.clone(),
            manifest_root: Some(object_ref(&root_bytes)),
            manifest_pages: page_bytes.iter().map(|p| object_ref(p)).collect(),
        };
        let meta_bytes =
            postcard::to_stdvec(&meta).map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;

        let store = self.durable.as_mut().expect("durable path");
        match store.commit(&new_objects, &keep, meta_bytes) {
            Ok(_) => {}
            Err(FabricError::OutcomeUnknown) => {
                self.poisoned = true;
                return Err(ReplicaCommitError::OutcomeUnknown);
            }
            Err(e) => {
                self.poisoned = true;
                return Err(ReplicaCommitError::Durability(e.to_string()));
            }
        }
        // Durable receipt refs become authoritative in memory.
        if let (Some(receipt), Some(bytes)) = (receipt, &receipt_bytes) {
            self.receipts.insert(
                receipt.scope_key(),
                (receipt.clone(), Some(object_ref(bytes))),
            );
        }
        Ok(())
    }

    /// Read the committed canonical bytes of an atomic Body, if present and
    /// interpreted (an opaque Body reads as absent).
    pub fn read(&self, key: &BodyKey) -> Option<Vec<u8>> {
        self.fabric.read(&fabric_key(key))
    }

    /// Read the committed collaborative view of a Body, if the key holds one.
    /// List elements carry the stable ids `ListRemove`/`ListMove` take.
    pub fn read_collaborative(&self, key: &BodyKey) -> Option<fabric::CollaborativeView> {
        self.fabric.read_collaborative(&fabric_key(key))
    }
}

/// Combine two collaborative chain frontiers deterministically (order-free).
fn combine_chains(a: &ReplicaFrontier, b: &ReplicaFrontier) -> ReplicaFrontier {
    let (lo, hi) = if a.root <= b.root { (a, b) } else { (b, a) };
    let mut h = blake3::Hasher::new();
    h.update(BODY_CHAIN_DOMAIN);
    h.update(&lo.root);
    h.update(&hi.root);
    ReplicaFrontier::new(
        *h.finalize().as_bytes(),
        a.transaction_count.max(b.transaction_count),
    )
}

fn object_ref(bytes: &[u8]) -> ObjectRef {
    ObjectRef {
        hash: fabric::journal::object_content_hash(bytes),
        len: bytes.len() as u64,
    }
}

/// Validate one staged Body operation against the frozen algebra (path grammar
/// and limits) and translate it into its Fabric operation. Replica owns this
/// translation; a World never authors Fabric operations, and Fabric never sees
/// an op Replica has not validated.
fn translate(key: FabricKey, op: &BodyOp) -> Result<FabricOp, ReplicaCommitError> {
    let path_ok = |p: &str| {
        algebra::valid_path(p)
            .then_some(())
            .ok_or(ReplicaCommitError::PathInvalid)
    };
    let value_ok = |v: &[u8]| {
        (v.len() <= algebra::MAX_VALUE_BYTES)
            .then_some(())
            .ok_or(ReplicaCommitError::OpLimit)
    };
    Ok(match op {
        BodyOp::ReplaceAtomic { value } => FabricOp::PutCanonical {
            key,
            value: value.clone(),
        },
        BodyOp::Create => FabricOp::CreateBody { key },
        BodyOp::Tombstone => FabricOp::Remove { key },
        BodyOp::RegisterSet { path, value } => {
            path_ok(path)?;
            value_ok(value)?;
            FabricOp::RegisterSet {
                key,
                path: path.clone(),
                value: value.clone(),
            }
        }
        BodyOp::RegisterClear { path } => {
            path_ok(path)?;
            FabricOp::RegisterClear {
                key,
                path: path.clone(),
            }
        }
        BodyOp::MapSet {
            path,
            key: entry,
            value,
        } => {
            path_ok(path)?;
            value_ok(value)?;
            if entry.len() > algebra::MAX_MAP_KEY_BYTES {
                return Err(ReplicaCommitError::OpLimit);
            }
            FabricOp::MapSet {
                key,
                path: path.clone(),
                entry: entry.clone(),
                value: value.clone(),
            }
        }
        BodyOp::MapRemove { path, key: entry } => {
            path_ok(path)?;
            FabricOp::MapRemove {
                key,
                path: path.clone(),
                entry: entry.clone(),
            }
        }
        BodyOp::ListInsert { path, index, value } => {
            path_ok(path)?;
            value_ok(value)?;
            FabricOp::ListInsert {
                key,
                path: path.clone(),
                index: *index,
                value: value.clone(),
            }
        }
        BodyOp::ListRemove { path, element } => {
            path_ok(path)?;
            FabricOp::ListRemove {
                key,
                path: path.clone(),
                element: element.clone(),
            }
        }
        BodyOp::ListMove {
            path,
            element,
            index,
        } => {
            path_ok(path)?;
            FabricOp::ListMove {
                key,
                path: path.clone(),
                element: element.clone(),
                index: *index,
            }
        }
        BodyOp::TextSplice {
            path,
            index,
            delete,
            insert,
        } => {
            path_ok(path)?;
            if insert.len() > algebra::MAX_TEXT_INSERT_BYTES {
                return Err(ReplicaCommitError::OpLimit);
            }
            FabricOp::TextSplice {
                key,
                path: path.clone(),
                index: *index,
                delete: *delete,
                insert: insert.clone(),
            }
        }
        BodyOp::SetAdd { path, value } => {
            path_ok(path)?;
            value_ok(value)?;
            FabricOp::SetAdd {
                key,
                path: path.clone(),
                value: value.clone(),
            }
        }
        BodyOp::SetRemove { path, value } => {
            path_ok(path)?;
            value_ok(value)?;
            FabricOp::SetRemove {
                key,
                path: path.clone(),
                value: value.clone(),
            }
        }
        BodyOp::CounterAdd { path, delta } => {
            path_ok(path)?;
            FabricOp::CounterAdd {
                key,
                path: path.clone(),
                delta: *delta,
            }
        }
    })
}

// A note on `BODY_EPOCH_ID_LEN`: referenced for the doc contract; the concrete
// parsing lives in mechanics.
const _: () = assert!(BODY_EPOCH_ID_LEN == 16);
