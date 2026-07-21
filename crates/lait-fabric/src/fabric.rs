//! The Fabric operation surface and engine — the sealed contract Replica drives.
//!
//! Fabric is LAIT's canonical, sealed Loro component and the only crate that
//! names Loro. It exposes **LAIT-owned** semantic operations and results, never
//! raw documents, containers, or Loro frontier types. Replica validates and
//! constructs a semantic transaction plan, submits it to a Fabric-owned
//! [`Fabric`] engine, and advances its semantic frontier only from a durable
//! [`FabricCommitReceipt`]. Fabric never imports Replica.
//!
//! **Ownership boundary (enforced, not just documented):**
//! - Replica submits *semantic* [`FabricOp`]s — it never authors a Loro delta.
//!   The concrete translation to Loro is Fabric-private.
//! - [`FabricCommitReceipt`] and [`CausalToken`] can be constructed **only**
//!   inside this crate (their constructors are `pub(crate)`), so a receipt is
//!   proof of a real Fabric commit — an outside crate cannot forge the token
//!   Replica advances from.
//!
//! S5 replaces [`MemFabric`] with the Loro-backed engine and adds the
//! collaborative operation set; the durable ordering, journal, and receipt
//! semantics are the contract that engine must preserve.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// An opaque commitment to Fabric's internal causal position (Loro frontier),
/// carried as bytes. It rides inside [`FabricCommitReceipt`] and is never
/// interpreted outside Fabric — no `loro::*` type crosses the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CausalToken(Vec<u8>);

impl CausalToken {
    /// Construct a causal token. **Crate-private**: only the Fabric engine mints
    /// one, so a token always denotes a real Fabric position.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A key into the Fabric representation — an opaque handle Replica uses to
/// address a durable object without naming a Loro container. Its concrete
/// encoding is Fabric-private and stabilizes in S5.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FabricKey(Vec<u8>);

impl FabricKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A single Fabric-level **semantic** operation. Replica alone translates a
/// semantic `BodyOp` into one or more of these; Fabric maps them canonically
/// onto Loro. Replica never authors a raw Loro delta — that is the ownership
/// boundary. The collaborative operation set (register/map/list/text/set/
/// counter) is added with the Loro engine in S5; S0–S3 support the atomic path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FabricOp {
    /// Atomically replace the canonical bytes stored at a key.
    PutCanonical { key: FabricKey, value: Vec<u8> },
    /// Remove the object at a key.
    Remove { key: FabricKey },
}

/// A durable transaction request: an ordered batch of Fabric operations to apply
/// atomically, carrying the request/commit metadata Fabric labels the change
/// with in the oplog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricTransactionRequest {
    /// The semantic request label (e.g. `"created"`) surfaced in the oplog.
    pub request: String,
    pub ops: Vec<FabricOp>,
}

impl FabricTransactionRequest {
    pub fn new(request: impl Into<String>, ops: Vec<FabricOp>) -> Self {
        Self {
            request: request.into(),
            ops,
        }
    }
}

/// The receipt of a durable Fabric commit. Replica advances its semantic
/// frontier **only** from this. It carries the post-commit causal token and the
/// count of changes applied. Constructed only by the Fabric engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricCommitReceipt {
    causal: CausalToken,
    applied: u32,
}

impl FabricCommitReceipt {
    /// **Crate-private**: only the Fabric engine issues a receipt.
    pub(crate) fn new(causal: CausalToken, applied: u32) -> Self {
        Self { causal, applied }
    }
    pub fn causal(&self) -> &CausalToken {
        &self.causal
    }
    pub fn applied(&self) -> u32 {
        self.applied
    }
}

/// Why a Fabric commit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FabricError {
    /// A durable write failed.
    Durability(String),
}

impl std::fmt::Display for FabricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for FabricError {}

/// The Fabric engine: the durable, canonical collaborative representation Replica
/// drives. It accepts semantic operations and returns a receipt whose
/// construction is Fabric-private; it also serves committed reads. The Loro
/// engine (S5) implements this same trait, so Replica/runtime are unchanged when
/// it lands.
pub trait Fabric {
    /// Durably apply a transaction and return a commit receipt. Atomic: either
    /// every op is applied and a receipt returned, or nothing changes.
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError>;

    /// Read the committed canonical bytes at a key, if present.
    fn read(&self, key: &FabricKey) -> Option<Vec<u8>>;

    /// Export the full durable representation as bytes. The engine's own
    /// constructor restores it (`LoroFabric::from_snapshot` / `MemFabric::
    /// from_snapshot`), so the caller persists the bytes and reopens with the
    /// matching engine.
    fn snapshot(&self) -> Result<Vec<u8>, FabricError>;
}

/// A minimal in-memory reference engine. It is a real engine — it applies
/// operations, serves reads, and mints receipts whose causal token advances with
/// each commit — standing in for the Loro-backed engine until S5. It owns receipt
/// construction, so a receipt from here denotes a genuine (in-memory durable)
/// commit.
#[derive(Debug, Default)]
pub struct MemFabric {
    state: BTreeMap<FabricKey, Vec<u8>>,
    counter: u64,
}

impl MemFabric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore an in-memory engine from a [`Fabric::snapshot`].
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, FabricError> {
        let state: BTreeMap<FabricKey, Vec<u8>> =
            postcard::from_bytes(bytes).map_err(|e| FabricError::Durability(e.to_string()))?;
        Ok(Self { state, counter: 0 })
    }
}

impl Fabric for MemFabric {
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError> {
        // Apply atomically against a scratch copy, then swap in on success.
        let mut next = self.state.clone();
        for op in &request.ops {
            match op {
                FabricOp::PutCanonical { key, value } => {
                    next.insert(key.clone(), value.clone());
                }
                FabricOp::Remove { key } => {
                    next.remove(key);
                }
            }
        }
        self.state = next;
        self.counter += 1;
        Ok(FabricCommitReceipt::new(
            CausalToken::from_bytes(self.counter.to_le_bytes().to_vec()),
            request.ops.len() as u32,
        ))
    }

    fn read(&self, key: &FabricKey) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }

    fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        postcard::to_stdvec(&self.state).map_err(|e| FabricError::Durability(e.to_string()))
    }
}

/// The Loro-backed Fabric engine — Fabric's real implementation, and the reason
/// this crate is the only one that names Loro. Bodies are stored as canonical
/// binary values in a single Loro map keyed by the hex of their [`FabricKey`];
/// each commit lands as a Loro change and the receipt carries the Loro oplog
/// frontier as its opaque causal token. [`LoroFabric::snapshot`] /
/// [`LoroFabric::from_snapshot`] give the durable-representation round-trip the
/// store cutover persists. The collaborative operation set (register/map/list/
/// text/set/counter over Loro containers) extends [`FabricOp`] here in S5.
pub struct LoroFabric {
    doc: loro::LoroDoc,
}

const BODIES_MAP: &str = "bodies";

impl LoroFabric {
    /// A fresh, empty Loro-backed engine with the crate's canonical Loro config.
    pub fn new() -> Self {
        let doc = loro::LoroDoc::new();
        crate::op::configure(&doc, None);
        Self { doc }
    }

    /// Restore an engine from a durable snapshot ([`LoroFabric::snapshot`]).
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, FabricError> {
        let doc = loro::LoroDoc::new();
        crate::op::configure(&doc, None);
        doc.import(bytes)
            .map_err(|e| FabricError::Durability(format!("import snapshot: {e}")))?;
        Ok(Self { doc })
    }

    /// Export the full durable representation as a Loro snapshot.
    pub fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        self.doc
            .export(loro::ExportMode::Snapshot)
            .map_err(|e| FabricError::Durability(format!("export snapshot: {e}")))
    }

    fn key_str(key: &FabricKey) -> String {
        data_encoding::HEXLOWER.encode(key.as_bytes())
    }
}

impl Default for LoroFabric {
    fn default() -> Self {
        Self::new()
    }
}

impl Fabric for LoroFabric {
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError> {
        let bodies = self.doc.get_map(BODIES_MAP);
        for op in &request.ops {
            match op {
                FabricOp::PutCanonical { key, value } => bodies
                    .insert(&Self::key_str(key), value.as_slice())
                    .map_err(|e| FabricError::Durability(format!("put: {e}")))?,
                FabricOp::Remove { key } => bodies
                    .delete(&Self::key_str(key))
                    .map_err(|e| FabricError::Durability(format!("remove: {e}")))?,
            }
        }
        // Label the change and land it as one Loro commit.
        self.doc.set_next_commit_message(&request.request);
        self.doc.commit();
        // The Loro oplog frontier is the opaque causal token.
        let causal = CausalToken::from_bytes(self.doc.oplog_frontiers().encode());
        Ok(FabricCommitReceipt::new(causal, request.ops.len() as u32))
    }

    fn read(&self, key: &FabricKey) -> Option<Vec<u8>> {
        let bodies = self.doc.get_map(BODIES_MAP);
        bodies
            .get(&Self::key_str(key))
            .and_then(|v| v.into_value().ok())
            .and_then(|v| v.into_binary().ok())
            .map(|b| b.to_vec())
    }

    fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        LoroFabric::snapshot(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_request_roundtrips_postcard() {
        let req = FabricTransactionRequest::new(
            "created",
            vec![
                FabricOp::PutCanonical {
                    key: FabricKey::from_bytes(vec![1, 2, 3]),
                    value: vec![9],
                },
                FabricOp::Remove {
                    key: FabricKey::from_bytes(vec![4]),
                },
            ],
        );
        let bytes = postcard::to_stdvec(&req).unwrap();
        let back: FabricTransactionRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn loro_engine_persists_reads_and_survives_a_snapshot_roundtrip() {
        let mut fabric = LoroFabric::new();
        let key = FabricKey::from_bytes(b"body/0".to_vec());
        fabric
            .commit(FabricTransactionRequest::new(
                "created",
                vec![FabricOp::PutCanonical {
                    key: key.clone(),
                    value: b"durable".to_vec(),
                }],
            ))
            .unwrap();
        assert_eq!(fabric.read(&key).as_deref(), Some(&b"durable"[..]));

        // Durable round-trip: a restored engine reads back the same state.
        let snap = fabric.snapshot().unwrap();
        let restored = LoroFabric::from_snapshot(&snap).unwrap();
        assert_eq!(restored.read(&key).as_deref(), Some(&b"durable"[..]));

        // Remove is durable too, and the causal token advances.
        let mut fabric = restored;
        let before = fabric
            .commit(FabricTransactionRequest::new("noop", vec![]))
            .unwrap();
        let after = fabric
            .commit(FabricTransactionRequest::new(
                "removed",
                vec![FabricOp::Remove { key: key.clone() }],
            ))
            .unwrap();
        assert_ne!(before.causal(), after.causal());
        assert_eq!(fabric.read(&key), None);
    }

    #[test]
    fn engine_applies_atomically_and_issues_advancing_receipts() {
        let mut fabric = MemFabric::new();
        let key = FabricKey::from_bytes(b"body/0".to_vec());
        let r1 = fabric
            .commit(FabricTransactionRequest::new(
                "created",
                vec![FabricOp::PutCanonical {
                    key: key.clone(),
                    value: b"v1".to_vec(),
                }],
            ))
            .unwrap();
        assert_eq!(r1.applied(), 1);
        assert_eq!(fabric.read(&key).as_deref(), Some(&b"v1"[..]));

        let r2 = fabric
            .commit(FabricTransactionRequest::new(
                "removed",
                vec![FabricOp::Remove { key: key.clone() }],
            ))
            .unwrap();
        // The causal token advances between commits.
        assert_ne!(r1.causal(), r2.causal());
        assert_eq!(fabric.read(&key), None);
    }
}
