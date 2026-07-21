//! [`Replica`] — the committing semantic layer over a Fabric engine.
//!
//! Replica translates a validated set of staged [`BodyOp`]s into semantic
//! [`FabricOp`]s, submits them to a Fabric engine for a durable atomic commit,
//! and advances its semantic frontier **only** from the returned
//! [`FabricCommitReceipt`]. It never authors a Loro delta and never fabricates a
//! receipt — the frontier root is derived from the Fabric-issued causal token,
//! so the frontier cannot advance without a real commit.
//!
//! S5a wires the write path over the in-memory reference engine
//! ([`Replica::in_memory`]); the Loro-backed engine and the collaborative
//! operation set land in the S5 store cutover, behind this same API.

use lait_fabric::{Fabric, FabricKey, FabricOp, FabricTransactionRequest, LoroFabric, MemFabric};
use serde::{Deserialize, Serialize};

use crate::body::BodyOp;
use crate::frontier::ReplicaFrontier;
use crate::ids::BodyKey;

/// Domain separator for deriving a Fabric key from a Body key.
const BODY_KEY_DOMAIN: &[u8] = b"lait/fabric-key/1";
/// Domain separator for advancing the semantic frontier from a commit receipt.
const FRONTIER_DOMAIN: &[u8] = b"lait/replica-frontier/1";

/// Why a Replica commit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaCommitError {
    /// A staged operation is not yet supported by the current engine (the
    /// collaborative algebra lands with the Loro engine in S5).
    UnsupportedOp,
    /// The Fabric engine failed to durably apply the transaction.
    Fabric(String),
}

impl std::fmt::Display for ReplicaCommitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReplicaCommitError {}

/// The Orbit's durable local materialization, over a Fabric engine.
pub struct Replica {
    fabric: Box<dyn Fabric + Send>,
    frontier: ReplicaFrontier,
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
    /// Build a Replica over a given Fabric engine.
    pub fn new(fabric: Box<dyn Fabric + Send>) -> Self {
        Self {
            fabric,
            frontier: ReplicaFrontier::EMPTY,
        }
    }

    /// Build a Replica over the in-memory reference engine.
    pub fn in_memory() -> Self {
        Self::new(Box::new(MemFabric::new()))
    }

    /// Build a durable Replica over the Loro-backed engine.
    pub fn loro() -> Self {
        Self::new(Box::new(LoroFabric::new()))
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
        })
    }

    /// The current semantic frontier.
    pub fn frontier(&self) -> ReplicaFrontier {
        self.frontier
    }

    /// Durably commit a set of staged Body operations, advancing the frontier
    /// from the Fabric receipt. Atomic: on any error the frontier is unchanged.
    pub fn commit(
        &mut self,
        request_label: &str,
        ops: &[(BodyKey, BodyOp)],
    ) -> Result<ReplicaFrontier, ReplicaCommitError> {
        let mut fabric_ops = Vec::with_capacity(ops.len());
        for (key, op) in ops {
            let fkey = fabric_key(key);
            match op {
                BodyOp::ReplaceAtomic { value } => fabric_ops.push(FabricOp::PutCanonical {
                    key: fkey,
                    value: value.clone(),
                }),
                BodyOp::Create => fabric_ops.push(FabricOp::PutCanonical {
                    key: fkey,
                    value: Vec::new(),
                }),
                BodyOp::Tombstone => fabric_ops.push(FabricOp::Remove { key: fkey }),
                // Collaborative ops require the Loro engine (S5).
                _ => return Err(ReplicaCommitError::UnsupportedOp),
            }
        }
        let receipt = self
            .fabric
            .commit(FabricTransactionRequest::new(request_label, fabric_ops))
            .map_err(|e| ReplicaCommitError::Fabric(e.to_string()))?;
        self.frontier = advance(self.frontier, receipt.causal().as_bytes());
        Ok(self.frontier)
    }

    /// Read the committed canonical bytes of a Body, if present.
    pub fn read(&self, key: &BodyKey) -> Option<Vec<u8>> {
        self.fabric.read(&fabric_key(key))
    }
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
    fn collaborative_ops_are_unsupported_until_the_loro_engine() {
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
