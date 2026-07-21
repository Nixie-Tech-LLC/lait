//! The Fabric operation surface — the sealed contract Replica drives.
//!
//! Fabric is LAIT's canonical, sealed Loro component and the only crate that
//! names Loro. It exposes **LAIT-owned** operations and results, never raw
//! documents, containers, or Loro frontier types. Replica validates and
//! constructs a semantic transaction plan, translates it into a
//! [`FabricTransactionRequest`], and advances its semantic frontier only from a
//! durable [`FabricCommitReceipt`]. Fabric never imports Replica.
//!
//! S0 establishes these shapes as the sealed boundary; the journal phases,
//! durable application, and receipt production land in S5. The opaque
//! [`CausalToken`] carries Fabric's Loro frontier as bytes so it can ride inside
//! a receipt without ever surfacing a `loro::*` type across the boundary.

use serde::{Deserialize, Serialize};

/// An opaque commitment to Fabric's internal causal position (Loro frontier),
/// carried as bytes. It rides inside [`FabricCommitReceipt`] and is never
/// interpreted outside Fabric — no `loro::*` type crosses the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CausalToken(Vec<u8>);

impl CausalToken {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
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

/// A single Fabric-level operation. Replica alone translates a semantic `BodyOp`
/// into one or more `FabricOp`s; Fabric maps them canonically onto Loro. This is
/// the sealed S0 shape — the concrete operation set is implemented in S5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FabricOp {
    /// Atomically replace the canonical bytes stored at a key.
    PutCanonical { key: FabricKey, value: Vec<u8> },
    /// Apply an opaque, Fabric-canonical collaborative delta at a key. The delta
    /// encoding is Fabric-private; Replica never authors raw Loro updates.
    ApplyDelta { key: FabricKey, delta: Vec<u8> },
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
/// count of changes applied; the durable store paths and journal accounting stay
/// inside Fabric.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricCommitReceipt {
    pub causal: CausalToken,
    pub applied: u32,
}

impl FabricCommitReceipt {
    pub fn new(causal: CausalToken, applied: u32) -> Self {
        Self { causal, applied }
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
    fn causal_token_is_opaque_bytes() {
        let receipt = FabricCommitReceipt::new(CausalToken::from_bytes(vec![7, 7]), 2);
        assert_eq!(receipt.causal.as_bytes(), &[7, 7]);
        assert_eq!(receipt.applied, 2);
    }
}
