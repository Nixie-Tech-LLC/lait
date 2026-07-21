//! [`Replica`] — the committing semantic layer over a Fabric engine.
//!
//! Replica translates a validated set of staged [`BodyOp`]s into semantic
//! [`FabricOp`]s, submits them to a Fabric engine for a durable atomic commit,
//! and advances its semantic frontier **only** from the returned
//! [`FabricCommitReceipt`]. It never authors a Loro delta and never fabricates a
//! receipt — the frontier root is derived from the Fabric-issued causal token,
//! so the frontier cannot advance without a real commit.
//!
//! [`Replica::loro`] runs the full algebra (atomic + collaborative) over the
//! Loro-backed engine with per-commit durability; [`Replica::in_memory`] is the
//! atomic-only reference engine for tests. [`Replica::incorporate`] is the
//! Convergence step: incoming material must arrive as a signed
//! [`crate::transaction::BodyTransactionV1`] whose commitment binds the payload,
//! and mechanics validates the signer's standing before any byte reaches the
//! engine. It is never reachable from a World or an ordinary Session.

use fabric::{
    CollaborativeView, Fabric, FabricError, FabricKey, FabricOp, FabricTransactionRequest,
    JournaledStore, LoroFabric, MemFabric,
};
use serde::{Deserialize, Serialize};

use crate::algebra;
use crate::body::BodyOp;
use crate::convergence::ConvergenceOutcome;
use crate::frontier::ReplicaFrontier;
use crate::ids::BodyKey;

/// Domain separator for deriving a Fabric key from a Body key.
const BODY_KEY_DOMAIN: &[u8] = b"lait/fabric-key/1";
/// Domain separator for advancing the semantic frontier from a commit receipt.
const FRONTIER_DOMAIN: &[u8] = b"lait/replica-frontier/1";

/// The reserved World id carried by the interim whole-engine export envelope.
pub const ENGINE_EXPORT_WORLD: &str = "org.lait.engine";
/// The reserved schema id of the interim whole-engine export envelope.
pub const ENGINE_EXPORT_SCHEMA: &str = "engine.export";

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
    /// Incoming material failed legitimacy validation (signature, signer
    /// authority, or payload binding). Nothing was incorporated.
    Illegitimate(String),
    /// The durable store failed integrity validation on open — never repaired
    /// heuristically; recreation guidance is the caller's.
    Integrity(String),
    /// The Fabric engine failed to apply the transaction.
    Fabric(String),
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
    Committed(crate::receipt::RequestReceiptV1),
    /// The identical request had already committed; the original receipt is
    /// returned and **nothing was reapplied**.
    Replayed(crate::receipt::RequestReceiptV1),
}

impl ActionOutcome {
    /// The receipt either way.
    pub fn receipt(&self) -> &crate::receipt::RequestReceiptV1 {
        match self {
            ActionOutcome::Committed(r) | ActionOutcome::Replayed(r) => r,
        }
    }
}

/// The Orbit's durable local materialization, over a Fabric engine.
pub struct Replica {
    fabric: Box<dyn Fabric + Send>,
    frontier: ReplicaFrontier,
    /// When set, every commit runs the journaled store's full commit protocol
    /// **before** it is acknowledged — checkpoint-on-shutdown is not durable
    /// commit semantics.
    durable: Option<JournaledStore>,
    /// Set after a durability failure: the in-memory engine has state the store
    /// does not, so no further commit may be acknowledged.
    poisoned: bool,
    /// The persistent-idempotency index, keyed by the canonical scope key.
    /// The packet and lookup semantics are frozen (C0); its durable
    /// content-addressed representation joins the canonical store in C1.3,
    /// sharing the transaction's journal linearization point.
    receipts: std::collections::BTreeMap<Vec<u8>, crate::receipt::RequestReceiptV1>,
}

/// The serialized durable state of a Replica: the engine snapshot and the
/// semantic frontier, checkpointed together so a restore is consistent.
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    engine: Vec<u8>,
    frontier: ReplicaFrontier,
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

/// Advance a frontier from a Fabric commit receipt's causal token.
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

impl Replica {
    /// Build a Replica over a given Fabric engine (no durability).
    pub fn new(fabric: Box<dyn Fabric + Send>) -> Self {
        Self {
            fabric,
            frontier: ReplicaFrontier::EMPTY,
            durable: None,
            poisoned: false,
            receipts: std::collections::BTreeMap::new(),
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

    /// Open the durable Replica at a journaled store root: run crash recovery,
    /// restore the committed engine state and semantic frontier (the store
    /// manifest's opaque metadata), and from then on run the journaled commit
    /// protocol before acknowledging every commit/incorporation.
    pub fn open_journaled(root: impl Into<std::path::PathBuf>) -> Result<Self, ReplicaCommitError> {
        let store = match JournaledStore::open(root) {
            Ok(s) => s,
            Err(FabricError::Integrity(m)) => return Err(ReplicaCommitError::Integrity(m)),
            Err(e) => return Err(ReplicaCommitError::Durability(e.to_string())),
        };
        let (fabric, frontier) = match store.manifest() {
            None => (LoroFabric::new(), ReplicaFrontier::EMPTY),
            Some(manifest) => {
                let frontier: ReplicaFrontier = postcard::from_bytes(&manifest.meta)
                    .map_err(|e| ReplicaCommitError::Integrity(format!("manifest meta: {e}")))?;
                // The interim representation is one engine-snapshot object; the
                // per-Body object split arrives with the representation cutover.
                let [engine_ref] = manifest.objects.as_slice() else {
                    return Err(ReplicaCommitError::Integrity(
                        "expected exactly one engine object".into(),
                    ));
                };
                let engine = store
                    .read_object(engine_ref)
                    .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
                let fabric = LoroFabric::from_snapshot(&engine)
                    .map_err(|e| ReplicaCommitError::Integrity(e.to_string()))?;
                (fabric, frontier)
            }
        };
        Ok(Self {
            fabric: Box::new(fabric),
            frontier,
            durable: Some(store),
            poisoned: false,
            receipts: std::collections::BTreeMap::new(),
        })
    }

    /// Serialize the full durable state — the engine snapshot plus the semantic
    /// frontier — for a checkpoint. [`Replica::restore_loro`] reopens it.
    pub fn checkpoint(&self) -> Result<Vec<u8>, ReplicaCommitError> {
        let engine = self
            .fabric
            .snapshot()
            .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
        postcard::to_stdvec(&Checkpoint {
            engine,
            frontier: self.frontier,
        })
        .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))
    }

    /// Reopen a durable Loro-backed Replica from a [`Replica::checkpoint`],
    /// restoring both the committed Bodies and the semantic frontier.
    pub fn restore_loro(bytes: &[u8]) -> Result<Self, ReplicaCommitError> {
        let cp: Checkpoint =
            postcard::from_bytes(bytes).map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
        let fabric = LoroFabric::from_snapshot(&cp.engine)
            .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
        Ok(Self {
            fabric: Box::new(fabric),
            frontier: cp.frontier,
            durable: None,
            poisoned: false,
            receipts: std::collections::BTreeMap::new(),
        })
    }

    /// The current semantic frontier.
    pub fn frontier(&self) -> ReplicaFrontier {
        self.frontier
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

    /// Commit a set of staged Body operations. With a durability sink attached,
    /// the committed state (engine snapshot + advanced frontier) is durably
    /// written **before** the commit is acknowledged — success means the commit
    /// is recoverable, not merely applied in memory. On any error the
    /// acknowledged frontier is unchanged; a durability failure additionally
    /// poisons the Replica (fail-stop), because the in-memory engine then holds
    /// state the store does not.
    pub fn commit(
        &mut self,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
    ) -> Result<ReplicaFrontier, ReplicaCommitError> {
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        let mut fabric_ops = Vec::with_capacity(ops.len());
        for (key, op) in ops {
            fabric_ops.push(translate(fabric_key(key), op)?);
        }
        let receipt = match self
            .fabric
            .commit(FabricTransactionRequest::new(request_label, fabric_ops))
        {
            Ok(r) => r,
            Err(FabricError::Unsupported) => return Err(ReplicaCommitError::UnsupportedOp),
            Err(FabricError::TypeConflict) => return Err(ReplicaCommitError::TypeConflict),
            Err(FabricError::InvalidOp(m)) => return Err(ReplicaCommitError::InvalidOp(m)),
            Err(FabricError::Integrity(m)) => return Err(ReplicaCommitError::Integrity(m)),
            Err(FabricError::OutcomeUnknown) => {
                self.poisoned = true;
                return Err(ReplicaCommitError::OutcomeUnknown);
            }
            Err(FabricError::Durability(m)) => {
                // The engine could not restore itself after a failed apply: its
                // in-memory state may have diverged. Fail stop.
                self.poisoned = true;
                return Err(ReplicaCommitError::Durability(m));
            }
        };
        self.persist_and_advance(receipt.causal().as_bytes())
    }

    /// Look up a request in the persistent-idempotency scope
    /// `(Space, World, Device, RequestId)`. An identical payload hash returns
    /// the original receipt — the caller must **not** reapply; a different
    /// payload hash under the same scope is a typed conflict; an unknown scope
    /// is `None` (commit may proceed).
    pub fn lookup_action(
        &self,
        space: &mechanics::ids::SpaceId,
        world: &crate::ids::WorldId,
        device: &mechanics::ids::DeviceId,
        request: &[u8; 16],
        payload_hash: &[u8; 32],
    ) -> Result<Option<crate::receipt::RequestReceiptV1>, ReplicaCommitError> {
        let key = crate::receipt::scope_key(space, world, device, request);
        match self.receipts.get(&key) {
            None => Ok(None),
            Some(r) if &r.payload_hash == payload_hash => Ok(Some(r.clone())),
            Some(_) => Err(ReplicaCommitError::RequestIdConflict),
        }
    }

    /// Commit a request's staged operations under its persistent-idempotency
    /// scope. Identical replay returns the original receipt **without
    /// reapplying** a single operation; reuse with a different payload hash is
    /// [`ReplicaCommitError::RequestIdConflict`]; a fresh request commits
    /// durably and records its receipt with the transaction. The effect bytes
    /// are bounded by [`crate::receipt::MAX_EFFECT_BYTES`] **before** anything
    /// is applied.
    #[allow(clippy::too_many_arguments)]
    pub fn commit_action(
        &mut self,
        space: &mechanics::ids::SpaceId,
        world: &crate::ids::WorldId,
        device: &mechanics::ids::DeviceId,
        request: &[u8; 16],
        payload_hash: &[u8; 32],
        effect: Vec<u8>,
        scopes: Vec<BodyKey>,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
    ) -> Result<ActionOutcome, ReplicaCommitError> {
        if let Some(receipt) = self.lookup_action(space, world, device, request, payload_hash)? {
            return Ok(ActionOutcome::Replayed(receipt));
        }
        if effect.len() > crate::receipt::MAX_EFFECT_BYTES {
            return Err(ReplicaCommitError::EffectTooLarge);
        }
        let frontier = self.commit(request_label, ops)?;
        let receipt = crate::receipt::RequestReceiptV1 {
            version: 1,
            space: space.clone(),
            world: world.clone(),
            device: device.clone(),
            request: *request,
            payload_hash: *payload_hash,
            effect,
            scopes,
            frontier,
        };
        self.receipts.insert(receipt.scope_key(), receipt.clone());
        Ok(ActionOutcome::Committed(receipt))
    }

    /// Export this Replica's representation as a **signed, authority-bound
    /// envelope**: a [`BodyTransactionV1`] whose single descriptor's ciphertext
    /// commitment covers the exported bytes, signed by the exporting device.
    /// The incorporating side verifies the transaction (structure, signature,
    /// **and signer standing at the authority frontier**) and the payload
    /// binding before any byte reaches the engine — there is no unbound merge
    /// path. (Interim: the envelope carries the whole engine representation as
    /// one reserved-World descriptor; the per-Body descriptor split is the
    /// representation cutover.)
    pub fn export_signed(
        &self,
        space: &mechanics::ids::SpaceId,
        authority_frontier: crate::frontier::AuthorityFrontier,
        signer_seed: &[u8; 32],
    ) -> Result<(crate::transaction::BodyTransactionV1, Vec<u8>), ReplicaCommitError> {
        use crate::body::ContentCommitment;
        let payload = self.export_all()?;
        let digest = blake3::hash(&payload);
        let mut body_raw = [0u8; 16];
        body_raw.copy_from_slice(&digest.as_bytes()[..16]);
        let mut tx_raw = [0u8; 16];
        tx_raw.copy_from_slice(&digest.as_bytes()[16..32]);
        let signer = mechanics::crypto::device_from_seed(signer_seed)
            .key_bytes()
            .ok_or_else(|| ReplicaCommitError::Fabric("signer key".into()))?;
        let space_bytes = <[u8; 29]>::try_from(space.as_str().as_bytes())
            .map_err(|_| ReplicaCommitError::Fabric("space id shape".into()))?;
        let descriptor = crate::transaction::BodyDescriptorV1 {
            space: space_bytes,
            world: crate::ids::WorldId::parse(ENGINE_EXPORT_WORLD).expect("reserved world id"),
            body: crate::ids::BodyId::from_bytes(body_raw),
            schema: crate::ids::SchemaId::parse(ENGINE_EXPORT_SCHEMA).expect("reserved schema"),
            schema_version: 1,
            encoding: crate::ids::EncodingId::parse("loro.snapshot").expect("encoding id"),
            replica_frontier: self.frontier,
            content_commitment: ContentCommitment::over_protected_payload(&payload).as_bytes(),
            transaction: tx_raw,
            signer,
            authority_frontier: authority_frontier.clone(),
        };
        let transaction = crate::transaction::BodyTransactionV1::sign(
            space,
            crate::frontier::TransactionId::from_bytes(tx_raw),
            self.frontier,
            authority_frontier,
            vec![descriptor],
            signer_seed,
        )
        .ok_or_else(|| ReplicaCommitError::Fabric("sign export".into()))?;
        Ok((transaction, payload))
    }

    /// Incorporate remote material through the Convergence pipeline: the signed
    /// [`BodyTransactionV1`] is verified — structure, signature, **and signer
    /// standing at its authority frontier through mechanics** — and its
    /// descriptor's ciphertext commitment must cover the payload byte-for-byte
    /// **before** any byte reaches the engine. There is no unvalidated merge
    /// path, and this method is never reachable from a World or an ordinary
    /// Session. Illegitimate material is rejected with nothing incorporated.
    /// Durability before acknowledgment applies exactly as for a local commit;
    /// the frontier advances only from the engine's merge receipt, and
    /// already-known material reports `unchanged`.
    pub fn incorporate(
        &mut self,
        transaction: &crate::transaction::BodyTransactionV1,
        payload: &[u8],
        authority: &dyn crate::transaction::AuthoritySource,
    ) -> Result<ConvergenceOutcome, ReplicaCommitError> {
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        // Legitimacy first: mechanics-validated signature + authority.
        transaction
            .verify_authorized(authority)
            .map_err(|e| ReplicaCommitError::Illegitimate(e.to_string()))?;
        // The envelope must be exactly the reserved engine-export descriptor,
        // and its commitment must bind these bytes.
        let [descriptor] = transaction.descriptors.as_slice() else {
            return Err(ReplicaCommitError::Illegitimate(
                "expected exactly one engine-export descriptor".into(),
            ));
        };
        if descriptor.world.as_str() != ENGINE_EXPORT_WORLD
            || descriptor.schema.as_str() != ENGINE_EXPORT_SCHEMA
        {
            return Err(ReplicaCommitError::Illegitimate(
                "not an engine-export envelope".into(),
            ));
        }
        if !descriptor.commits_to(payload) {
            return Err(ReplicaCommitError::Illegitimate(
                "payload does not match the signed commitment".into(),
            ));
        }
        let previous = self.frontier;
        let receipt = match self.fabric.merge(payload) {
            Ok(r) => r,
            Err(FabricError::Unsupported) => return Err(ReplicaCommitError::UnsupportedOp),
            Err(FabricError::TypeConflict) => return Err(ReplicaCommitError::TypeConflict),
            Err(FabricError::InvalidOp(m)) => return Err(ReplicaCommitError::InvalidOp(m)),
            Err(FabricError::Integrity(m)) => return Err(ReplicaCommitError::Integrity(m)),
            Err(FabricError::OutcomeUnknown) => {
                self.poisoned = true;
                return Err(ReplicaCommitError::OutcomeUnknown);
            }
            Err(FabricError::Durability(m)) => {
                self.poisoned = true;
                return Err(ReplicaCommitError::Durability(m));
            }
        };
        match receipt {
            None => {
                let mut outcome = ConvergenceOutcome::unchanged(previous);
                outcome.unchanged = 1;
                Ok(outcome)
            }
            Some(receipt) => {
                let current = self.persist_and_advance(receipt.causal().as_bytes())?;
                Ok(ConvergenceOutcome {
                    previous,
                    current,
                    accepted: 1,
                    unchanged: 0,
                    rejected: 0,
                    unsupported_retained: 0,
                    retryable: 0,
                })
            }
        }
    }

    /// Export the full representation for a peer to incorporate.
    pub fn export_all(&self) -> Result<Vec<u8>, ReplicaCommitError> {
        self.fabric
            .snapshot()
            .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))
    }

    /// Durability BEFORE acknowledgment: land the post-change state in the
    /// store, then advance the acknowledged frontier from the engine receipt's
    /// causal token. A failed durable write refuses the change and poisons the
    /// Replica (the in-memory engine has state the store does not).
    fn persist_and_advance(
        &mut self,
        causal: &[u8],
    ) -> Result<ReplicaFrontier, ReplicaCommitError> {
        let next = advance(self.frontier, causal);
        if let Some(store) = &mut self.durable {
            let engine = self
                .fabric
                .snapshot()
                .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
            let meta = postcard::to_stdvec(&next)
                .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
            // The full journaled protocol runs here: counter reserve → journal
            // Prepared → objects → MaterialReady → manifest rename → Committed.
            // Post-authoritative cleanup failures are absorbed inside the store
            // (the call still succeeds); only OutcomeUnknown is ambiguous, and
            // it demands reopen-not-retry.
            match store.commit(&[engine], &[], meta) {
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
        }
        self.frontier = next;
        Ok(self.frontier)
    }

    /// Read the committed canonical bytes of an atomic Body, if present.
    pub fn read(&self, key: &BodyKey) -> Option<Vec<u8>> {
        self.fabric.read(&fabric_key(key))
    }

    /// Read the committed collaborative view of a Body, if the key holds one.
    /// List elements carry the stable ids `ListRemove`/`ListMove` take.
    pub fn read_collaborative(&self, key: &BodyKey) -> Option<CollaborativeView> {
        self.fabric.read_collaborative(&fabric_key(key))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{BodyId, WorldId};

    fn key(n: u8) -> BodyKey {
        BodyKey::new(
            WorldId::parse("com.example.notes").unwrap(),
            BodyId::from_bytes([n; 16]),
        )
    }

    #[test]
    fn commit_advances_frontier_and_persists() {
        let mut r = Replica::in_memory();
        assert_eq!(r.frontier(), ReplicaFrontier::EMPTY);
        let f1 = r
            .commit(
                "created",
                &[(
                    key(0),
                    BodyOp::ReplaceAtomic {
                        value: b"hello".to_vec(),
                    },
                )],
            )
            .unwrap();
        assert_eq!(f1.transaction_count, 1);
        assert_ne!(f1, ReplicaFrontier::EMPTY);
        assert_eq!(r.read(&key(0)).as_deref(), Some(&b"hello"[..]));

        // A second commit advances again, deterministically from the receipt.
        let f2 = r.commit("removed", &[(key(0), BodyOp::Tombstone)]).unwrap();
        assert_eq!(f2.transaction_count, 2);
        assert_ne!(f1, f2);
        assert_eq!(r.read(&key(0)), None);
    }

    #[test]
    fn a_loro_replica_checkpoint_restores_bodies_and_frontier() {
        let mut r = Replica::loro();
        let f = r
            .commit(
                "created",
                &[(
                    key(1),
                    BodyOp::ReplaceAtomic {
                        value: b"persist-me".to_vec(),
                    },
                )],
            )
            .unwrap();
        let bytes = r.checkpoint().unwrap();

        // Reopen from the checkpoint: committed Body and frontier both restored.
        let restored = Replica::restore_loro(&bytes).unwrap();
        assert_eq!(restored.frontier(), f);
        assert_eq!(restored.read(&key(1)).as_deref(), Some(&b"persist-me"[..]));
    }

    #[test]
    fn the_full_collaborative_algebra_roundtrips() {
        let mut r = Replica::loro();
        let k = key(3);
        r.commit(
            "created",
            &[
                (k.clone(), BodyOp::Create),
                (
                    k.clone(),
                    BodyOp::RegisterSet {
                        path: "title".into(),
                        value: b"a title".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::MapSet {
                        path: "fields".into(),
                        key: "status".into(),
                        value: b"open".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::ListInsert {
                        path: "items".into(),
                        index: 0,
                        value: b"one".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::ListInsert {
                        path: "items".into(),
                        index: 1,
                        value: b"two".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::TextSplice {
                        path: "notes".into(),
                        index: 0,
                        delete: 0,
                        insert: "hello world".into(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::SetAdd {
                        path: "tags".into(),
                        value: b"bug".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 7,
                    },
                ),
            ],
        )
        .unwrap();

        let v = r.read_collaborative(&k).unwrap();
        assert_eq!(v.registers["title"], b"a title");
        assert_eq!(v.maps["fields"]["status"], b"open");
        assert_eq!(v.lists["items"].len(), 2);
        assert_eq!(v.texts["notes"], "hello world");
        assert_eq!(v.sets["tags"], vec![b"bug".to_vec()]);
        assert_eq!(v.counters["votes"], 7);

        // Mutate through every remaining verb, using the stable element id the
        // view exposed.
        let first = v.lists["items"][0].element.clone();
        let second = v.lists["items"][1].element.clone();
        r.commit(
            "edited",
            &[
                (
                    k.clone(),
                    BodyOp::ListRemove {
                        path: "items".into(),
                        element: first,
                    },
                ),
                (
                    k.clone(),
                    BodyOp::ListInsert {
                        path: "items".into(),
                        index: 1,
                        value: b"three".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::ListMove {
                        path: "items".into(),
                        element: second.clone(),
                        index: 1,
                    },
                ),
                (
                    k.clone(),
                    BodyOp::TextSplice {
                        path: "notes".into(),
                        index: 5,
                        delete: 6,
                        insert: "!".into(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::RegisterClear {
                        path: "title".into(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::MapRemove {
                        path: "fields".into(),
                        key: "status".into(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::SetRemove {
                        path: "tags".into(),
                        value: b"bug".to_vec(),
                    },
                ),
                (
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: -2,
                    },
                ),
            ],
        )
        .unwrap();

        let v = r.read_collaborative(&k).unwrap();
        assert!(!v.registers.contains_key("title"));
        assert!(v.maps["fields"].is_empty());
        let values: Vec<&[u8]> = v.lists["items"]
            .iter()
            .map(|e| e.value.as_slice())
            .collect();
        assert_eq!(values, vec![&b"three"[..], &b"two"[..]], "moved by id");
        assert_eq!(v.texts["notes"], "hello!");
        assert!(v.sets["tags"].is_empty());
        assert_eq!(v.counters["votes"], 5);

        // Checkpoint/restore preserves the collaborative state and ids.
        let bytes = r.checkpoint().unwrap();
        let restored = Replica::restore_loro(&bytes).unwrap();
        assert_eq!(restored.read_collaborative(&k), r.read_collaborative(&k));
        assert_eq!(restored.frontier(), r.frontier());
    }

    #[test]
    fn a_type_conflict_rolls_back_the_whole_batch() {
        let mut r = Replica::loro();
        let k = key(4);
        r.commit(
            "created",
            &[(
                k.clone(),
                BodyOp::RegisterSet {
                    path: "title".into(),
                    value: b"x".to_vec(),
                },
            )],
        )
        .unwrap();
        let before = r.frontier();

        // A batch whose FIRST op is valid and whose SECOND rebinds the path to
        // another type: the whole batch must vanish, including the valid op.
        let err = r
            .commit(
                "edited",
                &[
                    (
                        k.clone(),
                        BodyOp::CounterAdd {
                            path: "votes".into(),
                            delta: 1,
                        },
                    ),
                    (
                        k.clone(),
                        BodyOp::MapSet {
                            path: "title".into(),
                            key: "no".into(),
                            value: b"y".to_vec(),
                        },
                    ),
                ],
            )
            .unwrap_err();
        assert_eq!(err, ReplicaCommitError::TypeConflict);
        assert_eq!(r.frontier(), before, "frontier unchanged");
        let v = r.read_collaborative(&k).unwrap();
        assert!(
            !v.counters.contains_key("votes"),
            "the valid first op was rolled back with the batch"
        );
        assert_eq!(v.registers["title"], b"x");
    }

    #[test]
    fn frozen_algebra_limits_and_paths_are_enforced() {
        let mut r = Replica::loro();
        let k = key(5);
        // Bad path grammar.
        assert_eq!(
            r.commit(
                "x",
                &[(
                    k.clone(),
                    BodyOp::RegisterSet {
                        path: "Bad Path".into(),
                        value: vec![1],
                    },
                )],
            )
            .unwrap_err(),
            ReplicaCommitError::PathInvalid
        );
        // Oversized value.
        assert_eq!(
            r.commit(
                "x",
                &[(
                    k.clone(),
                    BodyOp::RegisterSet {
                        path: "p".into(),
                        value: vec![0u8; crate::algebra::MAX_VALUE_BYTES + 1],
                    },
                )],
            )
            .unwrap_err(),
            ReplicaCommitError::OpLimit
        );
        // Out-of-bounds list index is a typed apply error, nothing committed.
        assert!(matches!(
            r.commit(
                "x",
                &[(
                    k.clone(),
                    BodyOp::ListInsert {
                        path: "items".into(),
                        index: 5,
                        value: vec![1],
                    },
                )],
            )
            .unwrap_err(),
            ReplicaCommitError::InvalidOp(_)
        ));
        assert_eq!(r.frontier(), ReplicaFrontier::EMPTY);
    }

    /// The test mechanics view: authorizes exactly one signer key.
    struct OnlySigner([u8; 32]);
    impl crate::transaction::AuthoritySource for OnlySigner {
        fn signer_authorized(
            &self,
            signer: &[u8; 32],
            _frontier: &crate::frontier::AuthorityFrontier,
        ) -> bool {
            *signer == self.0
        }
    }

    const EXPORT_SEED: [u8; 32] = [91u8; 32];

    fn export_space() -> mechanics::ids::SpaceId {
        mechanics::ids::SpaceId::from_digest([14u8; 16])
    }

    fn export_authority() -> OnlySigner {
        OnlySigner(
            mechanics::crypto::device_from_seed(&EXPORT_SEED)
                .key_bytes()
                .unwrap(),
        )
    }

    fn signed_export(r: &Replica) -> (crate::transaction::BodyTransactionV1, Vec<u8>) {
        r.export_signed(
            &export_space(),
            crate::frontier::AuthorityFrontier::from_canonical_bytes(vec![1]),
            &EXPORT_SEED,
        )
        .unwrap()
    }

    #[test]
    fn two_replicas_converge_through_signed_incorporation() {
        let k = key(6);
        let mut a = Replica::loro();
        a.commit(
            "created",
            &[
                (k.clone(), BodyOp::Create),
                (
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 4,
                    },
                ),
            ],
        )
        .unwrap();

        // A fresh replica incorporates A's SIGNED material: mechanics validates
        // the signer, the commitment binds the payload, then it merges.
        let mut b = Replica::loro();
        let (tx, payload) = signed_export(&a);
        let outcome = b.incorporate(&tx, &payload, &export_authority()).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert!(outcome.advanced());
        assert_eq!(b.read_collaborative(&k), a.read_collaborative(&k));

        // B edits and A incorporates back.
        b.commit(
            "edited",
            &[(
                k.clone(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta: 6,
                },
            )],
        )
        .unwrap();
        let (tx, payload) = signed_export(&b);
        let outcome = a.incorporate(&tx, &payload, &export_authority()).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(a.read_collaborative(&k).unwrap().counters["votes"], 10);

        // Re-incorporating known material is `unchanged`.
        let before = a.frontier();
        let (tx, payload) = signed_export(&b);
        let outcome = a.incorporate(&tx, &payload, &export_authority()).unwrap();
        assert_eq!(outcome.unchanged, 1);
        assert_eq!(outcome.accepted, 0);
        assert!(!outcome.advanced());
        assert_eq!(a.frontier(), before);
    }

    #[test]
    fn illegitimate_material_is_refused_before_the_engine() {
        let k = key(9);
        let mut a = Replica::loro();
        a.commit(
            "created",
            &[(
                k.clone(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta: 1,
                },
            )],
        )
        .unwrap();
        let (tx, payload) = signed_export(&a);

        let mut b = Replica::loro();
        struct Nobody;
        impl crate::transaction::AuthoritySource for Nobody {
            fn signer_authorized(
                &self,
                _s: &[u8; 32],
                _f: &crate::frontier::AuthorityFrontier,
            ) -> bool {
                false
            }
        }
        // An unauthorized signer is refused; nothing incorporated.
        assert!(matches!(
            b.incorporate(&tx, &payload, &Nobody),
            Err(ReplicaCommitError::Illegitimate(_))
        ));
        assert_eq!(b.frontier(), ReplicaFrontier::EMPTY);

        // A payload not matching the signed commitment is refused.
        let mut tampered = payload.clone();
        tampered.push(0);
        assert!(matches!(
            b.incorporate(&tx, &tampered, &export_authority()),
            Err(ReplicaCommitError::Illegitimate(_))
        ));
        assert_eq!(b.frontier(), ReplicaFrontier::EMPTY);
        assert!(b.read_collaborative(&k).is_none());

        // The legitimate envelope still works.
        b.incorporate(&tx, &payload, &export_authority()).unwrap();
        assert_eq!(b.read_collaborative(&k).unwrap().counters["votes"], 1);
    }

    fn temp_store(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("lait-replica-journal-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn journaled_commits_and_incorporation_are_durable_before_acknowledgment() {
        let k = key(7);
        let mut a = Replica::loro();
        a.commit(
            "created",
            &[(
                k.clone(),
                BodyOp::RegisterSet {
                    path: "title".into(),
                    value: b"remote".to_vec(),
                },
            )],
        )
        .unwrap();

        // B runs over a journaled store. As soon as incorporation returns, the
        // store on disk — reopened cold, as after a crash — already holds the
        // incorporated material and the advanced frontier.
        let dir = temp_store("incorporate");
        let mut b = Replica::open_journaled(&dir).unwrap();
        let (tx, payload) = signed_export(&a);
        let outcome = b.incorporate(&tx, &payload, &export_authority()).unwrap();
        assert_eq!(outcome.accepted, 1);
        let frontier = b.frontier();
        drop(b); // crash: no dormancy, no checkpoint call

        let reopened = Replica::open_journaled(&dir).unwrap();
        assert_eq!(reopened.frontier(), frontier);
        assert_eq!(
            reopened.read_collaborative(&k).unwrap().registers["title"],
            b"remote".to_vec(),
            "the journaled store already held the material at acknowledgment"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_journaled_replica_survives_restart_with_collaborative_state() {
        let dir = temp_store("restart");
        let k = key(8);
        let mut r = Replica::open_journaled(&dir).unwrap();
        r.commit(
            "created",
            &[
                (k.clone(), BodyOp::Create),
                (
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 3,
                    },
                ),
            ],
        )
        .unwrap();
        let f1 = r.frontier();
        drop(r);

        let mut r = Replica::open_journaled(&dir).unwrap();
        assert_eq!(r.frontier(), f1);
        assert_eq!(r.read_collaborative(&k).unwrap().counters["votes"], 3);
        // And it keeps committing after restart.
        r.commit(
            "edited",
            &[(
                k.clone(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta: 2,
                },
            )],
        )
        .unwrap();
        assert_eq!(r.read_collaborative(&k).unwrap().counters["votes"], 5);
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn action_scope() -> (
        mechanics::ids::SpaceId,
        WorldId,
        mechanics::ids::DeviceId,
        [u8; 16],
    ) {
        (
            mechanics::ids::SpaceId::from_digest([21u8; 16]),
            WorldId::parse("com.example.notes").unwrap(),
            mechanics::crypto::device_from_seed(&[22u8; 32]),
            [23u8; 16],
        )
    }

    #[test]
    fn identical_replay_returns_the_original_receipt_without_reapplying() {
        let (space, world, device, request) = action_scope();
        let mut r = Replica::loro();
        let k = key(10);
        let ops = vec![(
            k.clone(),
            BodyOp::CounterAdd {
                path: "votes".into(),
                delta: 5,
            },
        )];
        let hash = [1u8; 32];
        let first = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &hash,
                b"bumped".to_vec(),
                vec![k.clone()],
                "bump",
                &ops,
            )
            .unwrap();
        let ActionOutcome::Committed(receipt) = &first else {
            panic!("first commit must be fresh");
        };
        assert_eq!(r.read_collaborative(&k).unwrap().counters["votes"], 5);

        // The identical retry replays the receipt; the non-idempotent
        // CounterAdd is NOT reapplied and the frontier does not move.
        let again = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &hash,
                b"bumped".to_vec(),
                vec![k.clone()],
                "bump",
                &ops,
            )
            .unwrap();
        assert_eq!(again, ActionOutcome::Replayed(receipt.clone()));
        assert_eq!(r.read_collaborative(&k).unwrap().counters["votes"], 5);
        assert_eq!(r.frontier(), receipt.frontier);
    }

    #[test]
    fn conflicting_request_reuse_is_refused_and_commits_nothing() {
        let (space, world, device, request) = action_scope();
        let mut r = Replica::loro();
        let k = key(11);
        r.commit_action(
            &space,
            &world,
            &device,
            &request,
            &[1u8; 32],
            vec![],
            vec![],
            "one",
            &[(
                k.clone(),
                BodyOp::CounterAdd {
                    path: "votes".into(),
                    delta: 1,
                },
            )],
        )
        .unwrap();
        let before = r.frontier();
        // Same scope, DIFFERENT payload hash: refused, nothing applied.
        let err = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &[2u8; 32],
                vec![],
                vec![],
                "two",
                &[(
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 100,
                    },
                )],
            )
            .unwrap_err();
        assert_eq!(err, ReplicaCommitError::RequestIdConflict);
        assert_eq!(r.frontier(), before);
        assert_eq!(r.read_collaborative(&k).unwrap().counters["votes"], 1);
    }

    #[test]
    fn an_oversized_effect_is_refused_before_anything_is_applied() {
        let (space, world, device, request) = action_scope();
        let mut r = Replica::loro();
        let k = key(12);
        let err = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &[1u8; 32],
                vec![0u8; crate::receipt::MAX_EFFECT_BYTES + 1],
                vec![],
                "big",
                &[(
                    k.clone(),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 1,
                    },
                )],
            )
            .unwrap_err();
        assert_eq!(err, ReplicaCommitError::EffectTooLarge);
        assert_eq!(r.frontier(), ReplicaFrontier::EMPTY);
        assert!(r.read_collaborative(&k).is_none());
    }

    #[test]
    fn a_failure_before_linearization_is_retryable_and_commits_exactly_once() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        let (space, world, device, request) = action_scope();
        let dir = temp_store("retryable");
        let arm = Arc::new(AtomicBool::new(true));
        let arm2 = arm.clone();
        // Fail the first attempt BEFORE the manifest linearization point (at
        // the objects write), then let the retry through.
        let mut r = Replica::open_journaled(&dir)
            .unwrap()
            .with_store_fault_injector(Box::new(move |point| {
                point == "objects" && arm2.swap(false, Ordering::SeqCst)
            }));
        let k = key(13);
        let ops = vec![(
            k.clone(),
            BodyOp::CounterAdd {
                path: "votes".into(),
                delta: 3,
            },
        )];
        let err = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &[1u8; 32],
                b"e".to_vec(),
                vec![],
                "bump",
                &ops,
            )
            .unwrap_err();
        // A pre-linearization durable failure poisons this handle (the
        // in-memory engine advanced); the caller reopens and retries.
        assert!(matches!(err, ReplicaCommitError::Durability(_)));
        drop(r);
        let mut r = Replica::open_journaled(&dir).unwrap();
        assert_eq!(
            r.frontier(),
            ReplicaFrontier::EMPTY,
            "nothing durable before the linearization point"
        );
        let outcome = r
            .commit_action(
                &space,
                &world,
                &device,
                &request,
                &[1u8; 32],
                b"e".to_vec(),
                vec![],
                "bump",
                &ops,
            )
            .unwrap();
        assert!(matches!(outcome, ActionOutcome::Committed(_)));
        assert_eq!(
            r.read_collaborative(&k).unwrap().counters["votes"],
            3,
            "the retried operation applied exactly once"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_reference_engine_refuses_collaborative_ops() {
        let mut r = Replica::in_memory();
        let err = r
            .commit(
                "edit",
                &[(
                    key(0),
                    BodyOp::CounterAdd {
                        path: "votes".into(),
                        delta: 1,
                    },
                )],
            )
            .unwrap_err();
        assert_eq!(err, ReplicaCommitError::UnsupportedOp);
        // The frontier did not move.
        assert_eq!(r.frontier(), ReplicaFrontier::EMPTY);
    }
}
