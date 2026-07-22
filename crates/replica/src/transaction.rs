//! `BodyTransaction` — the signed Body-transaction envelope, its core, and
//! its descriptors (`lait/body-transaction/2`), the protection boundary.
//!
//! A transaction is a device-signed **envelope** over two parts:
//!
//! - the [`BodyTransactionCore`]: Space, parent Manifest root, resulting
//!   Replica frontier, referenced authority frontier, acting principal,
//!   canonical authorization demand, intent/operations digests, and the
//!   ordered BodyKey-sorted set of public [`BodyDescriptor`]s with their
//!   ciphertext commitments;
//! - the mechanics-derived **authorization receipt**
//!   ([`mechanics::demand::AuthorizationReceipt`], canonical bytes), which
//!   binds the core digest, the demand, the evidence, the checkpoint
//!   commitment, and the pinned coordinates.
//!
//! The digest cycle is broken exactly as specified: the **core digest**
//! hashes the complete canonical core (excluding the receipt, the outer
//! signature, and the outer id); Mechanics binds that digest inside the
//! receipt; the device then signs the envelope `{ core, receipt }`; and the
//! **full signed-envelope digest is the transaction id** referenced by
//! Manifest entries and request receipts.
//!
//! There is no plaintext hash anywhere: the commitment is ciphertext-only
//! ([`crate::body::ContentCommitment`]), which avoids an equality oracle.
//!
//! **Two levels of verification, deliberately separate.**
//! [`BodyTransaction::verify`] is the *opaque structural* check any Station
//! can run without membership state: canonical shape, descriptor ordering,
//! demand canonicality, the receipt's byte-exact binding to the core, and the
//! committing signature. It is **not** an authority check. Before a
//! transaction is retained or incorporated, mechanics must also prove the
//! receipt against the referenced historical frontier — **no World callback
//! runs**; [`BodyTransaction::verify_authorized`] runs the structural check
//! and then consults the mechanics-provided [`AuthoritySource`].

use mechanics::demand::AuthorizationReceipt;
use mechanics::ids::SpaceId;
use serde::{Deserialize, Serialize};

use crate::body::ContentCommitment;
use crate::frontier::{AuthorityFrontier, ReplicaFrontier};
use crate::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

/// The signing domain for a Body transaction envelope.
pub const BODY_TRANSACTION_DOMAIN: &[u8] = b"lait/body-transaction/2";
/// BLAKE3 derive-key context for the core digest.
const CORE_DIGEST_CONTEXT: &str = "lait.body-transaction-core.v1";
/// BLAKE3 derive-key context for the transaction id (full envelope digest).
const TRANSACTION_ID_CONTEXT: &str = "lait.body-transaction-id.v1";
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;
/// Maximum descriptors in one transaction.
pub const MAX_DESCRIPTORS: usize = 4096;
/// Maximum encoded transaction size (1 MiB).
pub const MAX_TRANSACTION: usize = 1024 * 1024;
/// The fixed rendered-SpaceId length.
pub const SPACE_ID_LEN: usize = 29;
/// The "no parent" Manifest root (a fresh store's first commit).
pub const NO_PARENT_ROOT: [u8; 32] = [0u8; 32];

/// A public Body descriptor in canonical wire form. Binding to the enclosing
/// transaction is positional: descriptors live inside the signed core, so a
/// descriptor can never be transplanted into another transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyDescriptor {
    pub world: WorldId,
    pub body: BodyId,
    pub schema: SchemaId,
    pub schema_version: u32,
    pub encoding: EncodingId,
    pub content_commitment: [u8; 32],
}

impl BodyDescriptor {
    /// The BodyKey this descriptor addresses (the sort key).
    pub fn key(&self) -> BodyKey {
        BodyKey::new(self.world.clone(), self.body.clone())
    }

    /// Whether a protected payload's ciphertext matches this descriptor's
    /// commitment — the ciphertext-only content check an opaque retainer runs
    /// before any decryption is attempted.
    pub fn commits_to(&self, protected_payload: &[u8]) -> bool {
        ContentCommitment::over_protected_payload(protected_payload).as_bytes()
            == self.content_commitment
    }
}

/// The transaction core: everything the receipt binds, excluding the receipt
/// itself, the outer signature, and the outer transaction id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyTransactionCore {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    /// The committed Manifest root this transaction was authored against
    /// ([`NO_PARENT_ROOT`] for a fresh store's first commit). Local submit
    /// requires it to equal the current committed root; remote work may name
    /// a verified historical or concurrent parent.
    pub parent_manifest_root: [u8; 32],
    /// The resulting Replica frontier this transaction advances its author to.
    pub replica_frontier: ReplicaFrontier,
    /// The authority frontier authorization was evaluated at.
    pub authority_frontier: AuthorityFrontier,
    /// The acting principal (canonical ActorId text).
    pub actor: String,
    /// The signing device's raw key.
    pub signer: [u8; 32],
    /// Digest of the signed intent payload.
    pub intent_digest: [u8; 32],
    /// Digest of the complete canonical staged operation set.
    pub operations_digest: [u8; 32],
    /// The canonical authorization-demand bytes (mandatory, non-empty).
    pub demand: Vec<u8>,
    /// The ordered, BodyKey-sorted descriptors.
    pub descriptors: Vec<BodyDescriptor>,
}

impl BodyTransactionCore {
    /// The canonical core digest — the value the authorization receipt binds.
    pub fn digest(&self) -> [u8; 32] {
        let bytes = postcard::to_stdvec(self).expect("postcard transaction core");
        blake3::derive_key(CORE_DIGEST_CONTEXT, &bytes)
    }
}

/// The signed Body-transaction envelope: core plus authorization receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BodyTransaction {
    pub core: BodyTransactionCore,
    /// Canonical [`AuthorizationReceipt`] bytes (opaque at the frame layer;
    /// structurally bound to the core by [`BodyTransaction::verify`]).
    pub authorization_receipt: Vec<u8>,
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
    /// The demand bytes are absent or non-canonical.
    BadDemand,
    /// The authorization receipt is undecodable or does not bind this exact
    /// core (actor, device, Space, frontier, parent root, digests).
    ReceiptUnbound(&'static str),
    BadSignature,
    /// Structurally valid and correctly signed, but mechanics refused the
    /// receipt against the referenced historical frontier. Produced only by
    /// [`BodyTransaction::verify_authorized`].
    AuthorityUnverified,
    /// The referenced parent Manifest is not locally resolvable; retry once
    /// the exact material arrives. Never fall back to current state.
    ParentManifestUnavailable,
}

impl std::fmt::Display for TransactionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for TransactionError {}

/// A device signing capability the committing layer supplies (runtime's
/// `LocalIdentity` implements it). Replica builds the canonical preimage and
/// hands it here — it never sees seed bytes.
pub trait TransactionSigner: Send + Sync {
    /// The raw ed25519 public key of the signing device.
    fn signer_key(&self) -> [u8; 32];
    /// Sign an already-built canonical preimage.
    fn sign_preimage(&self, preimage: &[u8]) -> [u8; 64];
}

/// A seed-backed signer for tests and seed-holding callers.
pub struct SeedSigner<'a>(pub &'a [u8; 32]);

impl TransactionSigner for SeedSigner<'_> {
    fn signer_key(&self) -> [u8; 32] {
        mechanics::crypto::device_from_seed(self.0)
            .key_bytes()
            .expect("seed-derived device key")
    }
    fn sign_preimage(&self, preimage: &[u8]) -> [u8; 64] {
        mechanics::crypto::sign_detached(self.0, preimage)
    }
}

/// The mechanics-provided view of Space authority, consulted before material
/// is retained or incorporated. Replica owns no authority state; it asks this
/// seam. Mechanics implements it over the durable authority ledger.
pub trait AuthoritySource {
    /// Whether the device key `signer` was an admitted member with authoring
    /// standing at `authority_frontier` — the Manifest-advertisement
    /// legitimacy check.
    fn signer_authorized(&self, signer: &[u8; 32], authority_frontier: &AuthorityFrontier) -> bool;

    /// Verify a transaction's authorization receipt against **historical**
    /// mechanics state at its referenced frontier: actor resolution, demand
    /// evaluation, evidence digest, checkpoint commitment, and implementation
    /// activation. No World callback runs. Missing history is a retryable
    /// refusal.
    ///
    /// The default checks only that the signer had authoring standing at the
    /// referenced frontier — the minimal legitimacy any Station can prove. A
    /// real mechanics implementation MUST override it to verify the full
    /// authorization receipt (the orbital composition does).
    fn verify_transaction(&self, tx: &BodyTransaction) -> Result<(), String> {
        if self.signer_authorized(&tx.core.signer, &tx.core.authority_frontier) {
            Ok(())
        } else {
            Err("signer not authorized at the referenced frontier".into())
        }
    }
}

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

/// The inputs the committing layer supplies to sign a transaction.
pub struct TransactionSignRequest<'a> {
    pub space: &'a SpaceId,
    pub parent_manifest_root: [u8; 32],
    pub replica_frontier: ReplicaFrontier,
    pub authority_frontier: AuthorityFrontier,
    pub actor: &'a str,
    pub intent_digest: [u8; 32],
    pub operations_digest: [u8; 32],
    pub demand: Vec<u8>,
    pub descriptors: Vec<BodyDescriptor>,
}

impl BodyTransaction {
    fn preimage(core: &BodyTransactionCore, receipt: &[u8]) -> Vec<u8> {
        let body = postcard::to_stdvec(&(core, receipt)).expect("postcard envelope preimage");
        length_framed(BODY_TRANSACTION_DOMAIN, &body)
    }

    /// Build the core, hand its digest to `authorize` for the receipt, then
    /// sign the envelope. `authorize` receives the exact core digest the
    /// receipt must bind.
    pub fn sign_with(
        request: TransactionSignRequest<'_>,
        signer: &dyn TransactionSigner,
        authorize: impl FnOnce(&BodyTransactionCore) -> Result<Vec<u8>, String>,
    ) -> Result<Self, String> {
        let core = BodyTransactionCore {
            version: 1,
            space: space_bytes(request.space).ok_or("space id shape")?,
            parent_manifest_root: request.parent_manifest_root,
            replica_frontier: request.replica_frontier,
            authority_frontier: request.authority_frontier,
            actor: request.actor.to_string(),
            signer: signer.signer_key(),
            intent_digest: request.intent_digest,
            operations_digest: request.operations_digest,
            demand: request.demand,
            descriptors: request.descriptors,
        };
        let receipt = authorize(&core)?;
        let mut tx = Self {
            core,
            authorization_receipt: receipt,
            signature_algorithm: SIG_ALG_ED25519,
            signature: [0u8; 64],
        };
        tx.signature = signer.sign_preimage(&Self::preimage(&tx.core, &tx.authorization_receipt));
        Ok(tx)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard body-transaction")
    }

    /// The transaction id: the full signed-envelope digest.
    pub fn id(&self) -> [u8; 32] {
        blake3::derive_key(TRANSACTION_ID_CONTEXT, &self.encode())
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

    /// The decoded, binding-checked authorization receipt.
    pub fn receipt(&self) -> Result<AuthorizationReceipt, TransactionError> {
        AuthorizationReceipt::decode(&self.authorization_receipt)
            .map_err(|_| TransactionError::ReceiptUnbound("undecodable"))
    }

    /// **Structural** verification only: canonical shape, descriptor
    /// ordering, canonical demand, receipt-to-core binding, and the
    /// committing signature. This does **not** prove authority — use
    /// [`Self::verify_authorized`] before retaining or incorporating.
    pub fn verify(&self) -> Result<(), TransactionError> {
        let core = &self.core;
        if core.version != 1 {
            return Err(TransactionError::UnsupportedVersion(core.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(TransactionError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        let space = std::str::from_utf8(&core.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or(TransactionError::BadSpaceId)?;

        if core.descriptors.is_empty() || core.descriptors.len() > MAX_DESCRIPTORS {
            return Err(TransactionError::BadDescriptorCount);
        }
        // Strictly BodyKey-sorted, no duplicates.
        for w in core.descriptors.windows(2) {
            if w[0].key() >= w[1].key() {
                return Err(TransactionError::UnsortedOrDuplicate);
            }
        }
        // The demand must be present and canonical.
        let demand = mechanics::demand::AuthorizationDemand::decode_canonical(&core.demand)
            .map_err(|_| TransactionError::BadDemand)?;

        // The receipt must bind this exact core.
        let receipt = self.receipt()?;
        if receipt.space != space.as_str() {
            return Err(TransactionError::ReceiptUnbound("space"));
        }
        if receipt.actor != core.actor {
            return Err(TransactionError::ReceiptUnbound("actor"));
        }
        if receipt.device != core.signer {
            return Err(TransactionError::ReceiptUnbound("device"));
        }
        if receipt.authority_frontier != core.authority_frontier.as_bytes() {
            return Err(TransactionError::ReceiptUnbound("authority frontier"));
        }
        if receipt.parent_manifest_root != core.parent_manifest_root {
            return Err(TransactionError::ReceiptUnbound("parent manifest root"));
        }
        if receipt.intent_digest != core.intent_digest {
            return Err(TransactionError::ReceiptUnbound("intent digest"));
        }
        if receipt.effect_operations_digest != core.operations_digest {
            return Err(TransactionError::ReceiptUnbound("operations digest"));
        }
        if receipt.demand_digest != demand.digest().map_err(|_| TransactionError::BadDemand)? {
            return Err(TransactionError::ReceiptUnbound("demand digest"));
        }
        if receipt.body_transaction_core_digest != core.digest() {
            return Err(TransactionError::ReceiptUnbound("core digest"));
        }

        if !mechanics::crypto::verify_detached(
            &core.signer,
            &Self::preimage(core, &self.authorization_receipt),
            &self.signature,
        ) {
            return Err(TransactionError::BadSignature);
        }
        Ok(())
    }

    /// Full verification for retention/incorporation: the structural
    /// [`Self::verify`] **and** the mechanics historical-receipt check at the
    /// referenced authority frontier. No World callback runs.
    pub fn verify_authorized(
        &self,
        authority: &dyn AuthoritySource,
    ) -> Result<(), TransactionError> {
        self.verify()?;
        authority
            .verify_transaction(self)
            .map_err(|_| TransactionError::AuthorityUnverified)
    }
}
