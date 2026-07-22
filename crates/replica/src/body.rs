//! Body schemas, operations, and descriptors.
//!
//! A Body is a durable addressable World entity. A World declares its
//! [`BodySchema`]s and stages [`BodyOp`]s; Replica validates them, mechanics
//! adjudicates authority, and Fabric makes them durable. The operation algebra
//! is LAIT semantics — **not** a copy of the CRDT engine's API — and is frozen as an S1
//! fixture and implemented through Fabric in S5. This module defines the sealed
//! contract shapes; S0 introduces no production routing.

use serde::{Deserialize, Serialize};

use crate::ids::{EncodingId, SchemaId};

/// Domain separator for the ciphertext-only content commitment.
pub const BODY_CONTENT_DOMAIN: &[u8] = b"lait/body-content/1";

/// A commitment to a Body's protected payload: `BLAKE3(BODY_CONTENT_DOMAIN ||
/// protected_payload)`. It commits to the **ciphertext**, never the plaintext,
/// so it is not an equality oracle over decrypted content.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ContentCommitment([u8; 32]);

impl ContentCommitment {
    /// Compute the commitment over an already-protected (encrypted) payload.
    pub fn over_protected_payload(protected_payload: &[u8]) -> Self {
        let mut h = blake3::Hasher::new();
        h.update(BODY_CONTENT_DOMAIN);
        h.update(protected_payload);
        Self(*h.finalize().as_bytes())
    }

    pub fn from_bytes(raw: [u8; 32]) -> Self {
        Self(raw)
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.0
    }
}

/// How a schema's Bodies mutate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MutationModel {
    /// The Body carries a single canonical value replaced atomically per
    /// transaction.
    Atomic,
    /// The Body uses the versioned LAIT collaborative algebra.
    Collaborative(CollaborativeSchema),
}

/// The collaborative-schema declaration for a Body. The concrete path grammar,
/// stable element identity, concurrency winners, idempotence, type conflicts,
/// limits, and upgrade behavior are frozen as an S1 fixture; S0 reserves the
/// shape so registration and descriptors can name it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborativeSchema {
    /// Maximum encoded size, in bytes, of a single collaborative Body. `0` means
    /// "use the Replica default"; real limits are frozen in S1.
    pub max_encoded_bytes: u64,
}

/// A World's declaration of one Body schema it supports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodySchema {
    pub id: SchemaId,
    pub version: u32,
    pub encoding: EncodingId,
    pub mutation: MutationModel,
    /// Earlier schema versions this version can read (deterministic upgrade
    /// declaration). Runtime rejects contradictory upgrade claims.
    pub readable_predecessors: Vec<u32>,
}

/// The LAIT-owned Body operation algebra. A World stages these; it cannot submit
/// raw CRDT updates or container ids. Stable element ids, paths, concurrency,
/// idempotency, limits, and errors are LAIT semantics. This enum is the sealed
/// S0 shape; the exact path grammar and element-identity rules are frozen as an
/// S1 fixture and implemented through Fabric in S5.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyOp {
    /// Atomic replacement of a Body's canonical value.
    ReplaceAtomic {
        value: Vec<u8>,
    },
    /// Register set / clear.
    RegisterSet {
        path: String,
        value: Vec<u8>,
    },
    RegisterClear {
        path: String,
    },
    /// Map entry set / remove.
    MapSet {
        path: String,
        key: String,
        value: Vec<u8>,
    },
    MapRemove {
        path: String,
        key: String,
    },
    /// Ordered-list insert / remove / move with stable element identity.
    ListInsert {
        path: String,
        index: u64,
        value: Vec<u8>,
    },
    ListRemove {
        path: String,
        element: String,
    },
    ListMove {
        path: String,
        element: String,
        index: u64,
    },
    /// Text splice with declared coordinate semantics.
    TextSplice {
        path: String,
        index: u64,
        delete: u64,
        insert: String,
    },
    /// Set add / remove.
    SetAdd {
        path: String,
        value: Vec<u8>,
    },
    SetRemove {
        path: String,
        value: Vec<u8>,
    },
    /// Counter increment.
    CounterAdd {
        path: String,
        delta: i64,
    },
    /// Body create / tombstone (when the schema allows it).
    Create,
    Tombstone,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_commitment_covers_ciphertext_with_domain() {
        let c1 = ContentCommitment::over_protected_payload(b"cipher-a");
        let c2 = ContentCommitment::over_protected_payload(b"cipher-a");
        let c3 = ContentCommitment::over_protected_payload(b"cipher-b");
        assert_eq!(c1, c2, "deterministic over identical ciphertext");
        assert_ne!(c1, c3);
        // Domain-separated: a bare hash of the payload is not the commitment.
        assert_ne!(c1.as_bytes(), *blake3::hash(b"cipher-a").as_bytes());
    }

    #[test]
    fn body_op_and_schema_roundtrip_postcard() {
        let op = BodyOp::TextSplice {
            path: "body".into(),
            index: 3,
            delete: 1,
            insert: "hi".into(),
        };
        let bytes = postcard::to_stdvec(&op).unwrap();
        let back: BodyOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(op, back);

        let schema = BodySchema {
            id: SchemaId::parse("issue").unwrap(),
            version: 1,
            encoding: EncodingId::parse("lait.body.v1").unwrap(),
            mutation: MutationModel::Collaborative(CollaborativeSchema::default()),
            readable_predecessors: vec![],
        };
        let sb = postcard::to_stdvec(&schema).unwrap();
        let sback: BodySchema = postcard::from_bytes(&sb).unwrap();
        assert_eq!(schema, sback);
    }
}
