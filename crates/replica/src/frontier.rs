//! Frontiers and transaction identity.
//!
//! [`ReplicaFrontier`] is a technology-neutral commitment to the accepted
//! semantic transaction DAG. It is an **equality/cursor token**, not a scalar
//! ordering claim: ancestry and concurrency are proven by Manifest transaction
//! references during Convergence, which is what avoids an unbounded public
//! vector clock. Fabric's own document frontier stays an opaque token *inside*
//! Fabric commit receipts and never appears in World/runtime wire types.

use serde::{Deserialize, Serialize};

/// A commitment to the accepted semantic transaction DAG: a 32-byte root over
/// the accepted set plus the count of transactions it commits. Equality and
/// cursor comparison only — `transaction_count` orders nothing on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReplicaFrontier {
    pub root: [u8; 32],
    pub transaction_count: u64,
}

impl ReplicaFrontier {
    /// The empty frontier: a zero root committing zero transactions.
    pub const EMPTY: ReplicaFrontier = ReplicaFrontier {
        root: [0u8; 32],
        transaction_count: 0,
    };

    pub fn new(root: [u8; 32], transaction_count: u64) -> Self {
        Self {
            root,
            transaction_count,
        }
    }
}

/// An authority frontier — an opaque, canonical mechanics-owned commitment to
/// the authority material a request was authorized against. Runtime and World
/// code treat it as an equality token: authorization and commit compare-and-swap
/// the *same* authority frontier, and a change returns `AuthorityChanged`
/// without committing. The bytes are produced and validated by mechanics; this
/// newtype only carries them across the Replica boundary without interpretation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct AuthorityFrontier(Vec<u8>);

impl AuthorityFrontier {
    pub fn from_canonical_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_frontier_commits_nothing() {
        assert_eq!(ReplicaFrontier::EMPTY.transaction_count, 0);
        assert_eq!(ReplicaFrontier::EMPTY.root, [0u8; 32]);
    }

    #[test]
    fn frontier_equality_is_over_root_and_count() {
        let a = ReplicaFrontier::new([1u8; 32], 4);
        let b = ReplicaFrontier::new([1u8; 32], 4);
        let c = ReplicaFrontier::new([1u8; 32], 5);
        assert_eq!(a, b);
        assert_ne!(a, c, "count participates in equality");
    }

    #[test]
    fn authority_frontier_is_an_opaque_equality_token() {
        let x = AuthorityFrontier::from_canonical_bytes(vec![9, 9, 9]);
        let y = AuthorityFrontier::from_canonical_bytes(vec![9, 9, 9]);
        assert_eq!(x, y);
        assert_eq!(x.as_bytes(), &[9, 9, 9]);
    }
}
