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
//! atomic-only reference engine for tests. [`Replica::incorporate_trusted`] is
//! the engine-convergence step of the Convergence pipeline — its callers must
//! first establish legitimacy through mechanics; it is never reachable from a
//! World or an ordinary Session.

use lait_fabric::{
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
    /// The durable store failed integrity validation on open — never repaired
    /// heuristically; recreation guidance is the caller's.
    Integrity(String),
    /// The Fabric engine failed to apply the transaction.
    Fabric(String),
    /// The durable write of the committed state failed. The acknowledged
    /// frontier did not advance, and the Replica is poisoned (fail-stop) so the
    /// diverged in-memory representation can never acknowledge further commits.
    Durability(String),
    /// A previous durability failure poisoned this Replica; reopen from the
    /// durable store.
    Poisoned,
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
    /// When set, every commit runs the journaled store's full commit protocol
    /// **before** it is acknowledged — checkpoint-on-shutdown is not durable
    /// commit semantics.
    durable: Option<JournaledStore>,
    /// Set after a durability failure: the in-memory engine has state the store
    /// does not, so no further commit may be acknowledged.
    poisoned: bool,
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
        })
    }

    /// The current semantic frontier.
    pub fn frontier(&self) -> ReplicaFrontier {
        self.frontier
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
            Err(FabricError::Durability(m)) => {
                // The engine could not restore itself after a failed apply: its
                // in-memory state may have diverged. Fail stop.
                self.poisoned = true;
                return Err(ReplicaCommitError::Durability(m));
            }
        };
        self.persist_and_advance(receipt.causal().as_bytes())
    }

    /// Incorporate **already-validated** remote material by merging another
    /// replica's exported representation. This is the engine-convergence step of
    /// the Convergence pipeline — the caller (Contact incorporation, or an
    /// administrative/test path) must FIRST have established Space legitimacy
    /// and signer authority through mechanics
    /// ([`crate::transaction::BodyTransactionV1::verify_authorized`]); this
    /// method trusts its input and is therefore **never** reachable from a World
    /// or an ordinary Session. Durability before acknowledgment applies exactly
    /// as for a local commit; the frontier advances only from the engine's
    /// merge receipt, and already-known material reports `unchanged`.
    pub fn incorporate_trusted(
        &mut self,
        exported: &[u8],
    ) -> Result<ConvergenceOutcome, ReplicaCommitError> {
        if self.poisoned {
            return Err(ReplicaCommitError::Poisoned);
        }
        let previous = self.frontier;
        let receipt = match self.fabric.merge(exported) {
            Ok(r) => r,
            Err(FabricError::Unsupported) => return Err(ReplicaCommitError::UnsupportedOp),
            Err(FabricError::TypeConflict) => return Err(ReplicaCommitError::TypeConflict),
            Err(FabricError::InvalidOp(m)) => return Err(ReplicaCommitError::InvalidOp(m)),
            Err(FabricError::Integrity(m)) => return Err(ReplicaCommitError::Integrity(m)),
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
            if let Err(e) = store.commit(&[engine], &[], meta) {
                self.poisoned = true;
                return Err(ReplicaCommitError::Durability(e.to_string()));
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

    #[test]
    fn two_replicas_converge_through_trusted_incorporation() {
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

        // A fresh replica incorporates A's material: accepted, frontier advances.
        let mut b = Replica::loro();
        let outcome = b.incorporate_trusted(&a.export_all().unwrap()).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert!(outcome.advanced());
        assert_eq!(b.read_collaborative(&k), a.read_collaborative(&k));

        // B edits concurrently-ish and A incorporates back.
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
        let outcome = a.incorporate_trusted(&b.export_all().unwrap()).unwrap();
        assert_eq!(outcome.accepted, 1);
        assert_eq!(a.read_collaborative(&k).unwrap().counters["votes"], 10);

        // Incorporating material A already holds is `unchanged`: no frontier
        // movement, no acceptance.
        let before = a.frontier();
        let outcome = a.incorporate_trusted(&b.export_all().unwrap()).unwrap();
        assert_eq!(outcome.unchanged, 1);
        assert_eq!(outcome.accepted, 0);
        assert!(!outcome.advanced());
        assert_eq!(a.frontier(), before);
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
        let outcome = b.incorporate_trusted(&a.export_all().unwrap()).unwrap();
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
