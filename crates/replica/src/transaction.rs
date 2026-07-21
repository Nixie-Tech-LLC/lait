//! BodyTransactionV1 — the signed Body-transaction record and its descriptors
//! (`lait/body-transaction/1`), the S5 protection boundary.
//!
//! A device-signed transaction covers an ordered, BodyKey-sorted set of public
//! [`BodyDescriptorV1`]s and their ciphertext commitments. Mechanics validates
//! the signer's authority at the referenced authority frontier before Replica
//! retains or incorporates the material. An opaque Station can therefore validate
//! Space binding, authority, descriptor/transaction integrity, and ciphertext
//! bytes **without** a World implementation or a decryption key.
//!
//! There is no plaintext hash anywhere: the commitment is ciphertext-only
//! ([`crate::body::ContentCommitment`]), which avoids an equality oracle.
//!
//! **Two levels of verification, deliberately separate.**
//! [`BodyTransactionV1::verify`] is the *opaque structural* check any Station can
//! run without membership state: canonical shape, descriptor binding, ordering,
//! and the committing signature. It is **not** an authority check — a
//! structurally-valid transaction may still be signed by a device with no
//! standing. Before a transaction is retained or incorporated, mechanics must
//! also prove the signer had authority at the referenced frontier;
//! [`BodyTransactionV1::verify_authorized`] runs the structural check and then
//! consults a mechanics-provided [`AuthoritySource`]. Retention/Convergence must
//! use `verify_authorized`, never `verify` alone.

use mechanics::ids::SpaceId;
use serde::{Deserialize, Serialize};

use crate::body::ContentCommitment;
use crate::frontier::{AuthorityFrontier, ReplicaFrontier, TransactionId};
use crate::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

/// The signing domain for a Body transaction.
pub const BODY_TRANSACTION_DOMAIN: &[u8] = b"lait/body-transaction/1";
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;
/// Maximum descriptors in one transaction.
pub const MAX_DESCRIPTORS: usize = 4096;
/// Maximum encoded transaction size (1 MiB).
pub const MAX_TRANSACTION: usize = 1024 * 1024;
/// The fixed rendered-SpaceId length.
pub const SPACE_ID_LEN: usize = 29;

/// A public Body descriptor in canonical wire form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyDescriptorV1 {
    pub space: [u8; SPACE_ID_LEN],
    pub world: WorldId,
    pub body: BodyId,
    pub schema: SchemaId,
    pub schema_version: u32,
    pub encoding: EncodingId,
    pub replica_frontier: ReplicaFrontier,
    pub content_commitment: [u8; 32],
    pub transaction: [u8; 16],
    pub signer: [u8; 32],
    pub authority_frontier: AuthorityFrontier,
}

impl BodyDescriptorV1 {
    /// The BodyKey this descriptor addresses (the sort key).
    pub fn key(&self) -> BodyKey {
        BodyKey::new(self.world.clone(), self.body.clone())
    }

    /// Whether a protected payload's ciphertext matches this descriptor's
    /// commitment. This is the ciphertext-only content check an opaque retainer
    /// runs before any decryption is attempted.
    pub fn commits_to(&self, protected_payload: &[u8]) -> bool {
        ContentCommitment::over_protected_payload(protected_payload).as_bytes()
            == self.content_commitment
    }
}

/// A signed Body transaction covering an ordered set of descriptors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyTransactionV1 {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    pub transaction: [u8; 16],
    pub replica_frontier: ReplicaFrontier,
    pub authority_frontier: AuthorityFrontier,
    pub descriptors: Vec<BodyDescriptorV1>,
    pub signer: [u8; 32],
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why a Body transaction failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionError {
    UnsupportedVersion(u8),
    UnsupportedSignatureAlgorithm(u8),
    NonCanonical,
    BadSpaceId,
    /// Empty or over the descriptor-count/size bound.
    BadDescriptorCount,
    /// Descriptors were not strictly BodyKey-sorted (unsorted or duplicated).
    UnsortedOrDuplicate,
    /// A descriptor's Space/transaction/signer/authority did not equal the
    /// enclosing transaction's (a transplanted descriptor).
    Transplanted,
    BadSignature,
    /// The transaction is structurally valid and correctly signed, but the
    /// signer had no authority (membership/standing) at the referenced authority
    /// frontier. Produced only by [`BodyTransactionV1::verify_authorized`].
    AuthorityUnverified,
}

/// A mechanics-provided view of Space authority, consulted before a Body
/// transaction is retained or incorporated. Replica owns no authority state; it
/// asks this seam whether a signer was admitted with standing at a given
/// authority frontier. Mechanics (`mechanics`) implements it over replayed
/// signed history.
pub trait AuthoritySource {
    /// Whether the device key `signer` was an admitted member with authoring
    /// standing at `authority_frontier`.
    fn signer_authorized(&self, signer: &[u8; 32], authority_frontier: &AuthorityFrontier) -> bool;
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransactionError {}

fn length_framed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + 4 + body.len());
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn space_bytes(space: &SpaceId) -> Option<[u8; SPACE_ID_LEN]> {
    <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()
}

impl BodyTransactionV1 {
    /// The signed preimage: length-framed domain over every field through
    /// `signer` (signature fields excluded).
    fn preimage(&self) -> Vec<u8> {
        let body = postcard::to_stdvec(&(
            self.version,
            self.space,
            self.transaction,
            self.replica_frontier,
            &self.authority_frontier,
            &self.descriptors,
            self.signer,
        ))
        .expect("postcard body-transaction preimage");
        length_framed(BODY_TRANSACTION_DOMAIN, &body)
    }

    /// Construct and sign a transaction from the committing device's seed. The
    /// caller is responsible for building descriptors that agree with the
    /// enclosing fields; [`Self::verify`] enforces the binding.
    pub fn sign(
        space: &SpaceId,
        transaction: TransactionId,
        replica_frontier: ReplicaFrontier,
        authority_frontier: AuthorityFrontier,
        descriptors: Vec<BodyDescriptorV1>,
        signer_seed: &[u8; 32],
    ) -> Option<Self> {
        let signer = mechanics::crypto::device_from_seed(signer_seed).key_bytes()?;
        let mut tx = Self {
            version: 1,
            space: space_bytes(space)?,
            transaction: transaction.as_bytes(),
            replica_frontier,
            authority_frontier,
            descriptors,
            signer,
            signature_algorithm: SIG_ALG_ED25519,
            signature: [0u8; 64],
        };
        tx.signature = mechanics::crypto::sign_detached(signer_seed, &tx.preimage());
        Some(tx)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard body-transaction")
    }

    /// Decode canonical bytes: size-bounded, exact decode/re-encode equality.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, TransactionError> {
        if bytes.len() > MAX_TRANSACTION {
            return Err(TransactionError::NonCanonical);
        }
        let tx: Self = postcard::from_bytes(bytes).map_err(|_| TransactionError::NonCanonical)?;
        if tx.encode() != bytes {
            return Err(TransactionError::NonCanonical);
        }
        Ok(tx)
    }

    /// **Structural** verification only: canonical shape, descriptor binding,
    /// ordering, and the committing signature. This does **not** prove authority
    /// — a valid device key with no standing produces a transaction that passes
    /// here. Use [`Self::verify_authorized`] before retaining or incorporating.
    pub fn verify(&self) -> Result<(), TransactionError> {
        if self.version != 1 {
            return Err(TransactionError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(TransactionError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        std::str::from_utf8(&self.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or(TransactionError::BadSpaceId)?;

        if self.descriptors.is_empty() || self.descriptors.len() > MAX_DESCRIPTORS {
            return Err(TransactionError::BadDescriptorCount);
        }

        // Strictly BodyKey-sorted, no duplicates.
        for w in self.descriptors.windows(2) {
            if w[0].key() >= w[1].key() {
                return Err(TransactionError::UnsortedOrDuplicate);
            }
        }

        // Each descriptor is bound to the enclosing transaction.
        for d in &self.descriptors {
            if d.space != self.space
                || d.transaction != self.transaction
                || d.signer != self.signer
                || d.authority_frontier != self.authority_frontier
            {
                return Err(TransactionError::Transplanted);
            }
        }

        if !mechanics::crypto::verify_detached(&self.signer, &self.preimage(), &self.signature) {
            return Err(TransactionError::BadSignature);
        }
        Ok(())
    }

    /// Full verification for retention/incorporation: the structural
    /// [`Self::verify`] **and** the mechanics authority check — the signer must
    /// have been an admitted member with standing at `authority_frontier`. Any
    /// valid device key that lacks that standing fails with
    /// [`TransactionError::AuthorityUnverified`].
    pub fn verify_authorized(
        &self,
        authority: &dyn AuthoritySource,
    ) -> Result<(), TransactionError> {
        self.verify()?;
        if !authority.signer_authorized(&self.signer, &self.authority_frontier) {
            return Err(TransactionError::AuthorityUnverified);
        }
        Ok(())
    }
}
