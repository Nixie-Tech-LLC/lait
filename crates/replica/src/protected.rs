//! `ProtectedBodyPayload` — the canonical plaintext a protected Body object
//! seals, and the key-source seam Replica consults to seal/open it.
//!
//! The canonical plaintext is a versioned tuple scoped to **exactly one Body**:
//! its mutation model, its canonical payload (an atomic Body's application
//! bytes, or a collaborative Body's canonical per-Body Fabric export — never a
//! whole-engine or cross-Body snapshot), and the base/resulting Replica
//! frontiers of the transaction that produced it. The persisted envelope is
//! exactly `epoch_id[16] || nonce[12] || ciphertext_and_tag` (the existing
//! construction — no new cryptography), produced by
//! [`mechanics::crypto::body_seal`] under an opaque
//! [`mechanics::crypto::AuthorizedBodyKey`] capability that mechanics-side
//! policy mints. Replica selects the capability under Space policy and passes
//! it only to seal/open; nothing here decides epoch legitimacy.

use fabric::BodyExport;
use mechanics::crypto::{AuthorizedBodyKey, BODY_ENVELOPE_OVERHEAD, BODY_EPOCH_ID_LEN};
use serde::{Deserialize, Serialize};

use crate::frontier::ReplicaFrontier;

/// The maximum protected Body envelope size (64 MiB) — the per-Body bound,
/// checked before allocation on both seal and open.
pub const MAX_BODY_BYTES: usize = 64 * 1024 * 1024;

/// The maximum canonical plaintext size: the envelope bound minus the fixed
/// envelope overhead, so a maximal plaintext still seals within
/// [`MAX_BODY_BYTES`].
pub const MAX_PROTECTED_PLAINTEXT: usize = MAX_BODY_BYTES - BODY_ENVELOPE_OVERHEAD;

/// The declared mutation model tags.
pub const MUTATION_ATOMIC: u8 = 1;
pub const MUTATION_COLLABORATIVE: u8 = 2;

/// The canonical protected-Body plaintext. `version` is exactly 1 and
/// `mutation_model` must agree with the payload variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedBodyPayload {
    pub version: u8,
    pub mutation_model: u8,
    pub payload: BodyExport,
    pub base_frontier: ReplicaFrontier,
    pub resulting_frontier: ReplicaFrontier,
}

/// Why a protected payload failed. Commitment and AEAD failures share
/// [`ProtectedError::InvalidProtectedBody`] deliberately — no oracle
/// distinguishes them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtectedError {
    /// Malformed envelope, wrong key, failed authentication, non-canonical
    /// plaintext, or a model/variant disagreement.
    InvalidProtectedBody,
    /// The plaintext or envelope exceeds the Body maximum.
    BodyTooLarge,
    /// Unknown plaintext version.
    UnsupportedVersion(u8),
    /// No authorized key material is available for a local write.
    BodyKeyUnavailable,
}

impl std::fmt::Display for ProtectedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ProtectedError {}

impl ProtectedBodyPayload {
    /// Build the canonical plaintext for one Body's export.
    pub fn new(
        payload: BodyExport,
        base_frontier: ReplicaFrontier,
        resulting_frontier: ReplicaFrontier,
    ) -> Self {
        let mutation_model = match &payload {
            BodyExport::Atomic(_) => MUTATION_ATOMIC,
            BodyExport::Collaborative(_) => MUTATION_COLLABORATIVE,
        };
        Self {
            version: 1,
            mutation_model,
            payload,
            base_frontier,
            resulting_frontier,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard protected payload")
    }

    /// Decode canonical plaintext bytes: size-bounded **before** decode, exact
    /// decode/re-encode equality, version and model/variant agreement.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ProtectedError> {
        if bytes.len() > MAX_PROTECTED_PLAINTEXT {
            return Err(ProtectedError::BodyTooLarge);
        }
        let payload: Self =
            postcard::from_bytes(bytes).map_err(|_| ProtectedError::InvalidProtectedBody)?;
        if payload.encode() != bytes {
            return Err(ProtectedError::InvalidProtectedBody);
        }
        if payload.version != 1 {
            return Err(ProtectedError::UnsupportedVersion(payload.version));
        }
        let model_ok = matches!(
            (&payload.payload, payload.mutation_model),
            (BodyExport::Atomic(_), MUTATION_ATOMIC)
                | (BodyExport::Collaborative(_), MUTATION_COLLABORATIVE)
        );
        if !model_ok {
            return Err(ProtectedError::InvalidProtectedBody);
        }
        Ok(payload)
    }

    /// Seal the canonical plaintext under an authorized key epoch. The result
    /// is the persisted/transferred envelope.
    pub fn seal(&self, key: &AuthorizedBodyKey) -> Result<Vec<u8>, ProtectedError> {
        let plaintext = self.encode();
        if plaintext.len() > MAX_PROTECTED_PLAINTEXT {
            return Err(ProtectedError::BodyTooLarge);
        }
        Ok(mechanics::crypto::body_seal(key, &plaintext))
    }

    /// Open a protected envelope with the capability for its epoch. Bounds are
    /// checked before any allocation; a commitment/authentication failure and a
    /// malformed envelope are indistinguishable.
    pub fn open(key: &AuthorizedBodyKey, envelope: &[u8]) -> Result<Self, ProtectedError> {
        if envelope.len() > MAX_BODY_BYTES {
            return Err(ProtectedError::BodyTooLarge);
        }
        if envelope.len() < BODY_EPOCH_ID_LEN {
            return Err(ProtectedError::InvalidProtectedBody);
        }
        let plaintext = mechanics::crypto::body_open(key, envelope)
            .ok_or(ProtectedError::InvalidProtectedBody)?;
        Self::decode_canonical(&plaintext)
    }
}

/// The mechanics-owned key seam Replica consults. The composition root
/// implements it over the authorized epoch set (signed history); Replica calls
/// it under Space policy and never persists or exposes key material.
pub trait BodyKeySource: Send + Sync {
    /// The capability for sealing **new** local material: the current
    /// authorized epoch's key. `None` when no authorized epoch key is held —
    /// a local write then fails [`ProtectedError::BodyKeyUnavailable`].
    fn sealing_key(&self) -> Option<AuthorizedBodyKey>;

    /// The capability for opening material sealed under `epoch`. `None` when
    /// that epoch's key is not held (the opaque branch) or the epoch is not
    /// authorized (rejected upstream).
    fn opening_key(&self, epoch: &[u8; BODY_EPOCH_ID_LEN]) -> Option<AuthorizedBodyKey>;
}

/// A single static epoch key source for tests and single-epoch deployments.
pub struct StaticBodyKeys {
    key: AuthorizedBodyKey,
}

impl StaticBodyKeys {
    pub fn new(key: AuthorizedBodyKey) -> Self {
        Self { key }
    }
}

impl BodyKeySource for StaticBodyKeys {
    fn sealing_key(&self) -> Option<AuthorizedBodyKey> {
        Some(self.key.clone())
    }
    fn opening_key(&self, epoch: &[u8; BODY_EPOCH_ID_LEN]) -> Option<AuthorizedBodyKey> {
        (self.key.epoch_id() == epoch).then(|| self.key.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> AuthorizedBodyKey {
        AuthorizedBodyKey::for_authorized_epoch([7u8; 16], [9u8; 32])
    }

    fn payload() -> ProtectedBodyPayload {
        ProtectedBodyPayload::new(
            BodyExport::Atomic(b"the canonical application bytes".to_vec()),
            ReplicaFrontier::EMPTY,
            ReplicaFrontier::new([1u8; 32], 1),
        )
    }

    #[test]
    fn seal_open_roundtrips_and_the_envelope_shape_is_exact() {
        let p = payload();
        let envelope = p.seal(&key()).unwrap();
        // epoch_id[16] || nonce[12] || ciphertext_and_tag
        assert_eq!(&envelope[..16], &[7u8; 16]);
        assert_eq!(envelope.len(), p.encode().len() + BODY_ENVELOPE_OVERHEAD);
        assert_eq!(ProtectedBodyPayload::open(&key(), &envelope).unwrap(), p);
    }

    #[test]
    fn at_rest_bytes_contain_no_plaintext() {
        let p = payload();
        let envelope = p.seal(&key()).unwrap();
        let needle = b"canonical application bytes";
        assert!(
            !envelope
                .windows(needle.len())
                .any(|w| w == needle.as_slice()),
            "the sealed envelope must not leak plaintext"
        );
    }

    #[test]
    fn a_wrong_epoch_or_tampered_envelope_is_one_typed_failure() {
        let envelope = payload().seal(&key()).unwrap();
        // Wrong epoch on the capability.
        let other = AuthorizedBodyKey::for_authorized_epoch([8u8; 16], [9u8; 32]);
        assert_eq!(
            ProtectedBodyPayload::open(&other, &envelope),
            Err(ProtectedError::InvalidProtectedBody)
        );
        // Wrong key material under the right epoch.
        let wrong_key = AuthorizedBodyKey::for_authorized_epoch([7u8; 16], [1u8; 32]);
        assert_eq!(
            ProtectedBodyPayload::open(&wrong_key, &envelope),
            Err(ProtectedError::InvalidProtectedBody)
        );
        // A flipped ciphertext byte fails authentication with the SAME error.
        let mut tampered = envelope.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(
            ProtectedBodyPayload::open(&key(), &tampered),
            Err(ProtectedError::InvalidProtectedBody)
        );
    }

    #[test]
    fn model_variant_disagreement_is_non_canonical() {
        let mut p = payload();
        p.mutation_model = MUTATION_COLLABORATIVE; // payload is Atomic
        assert_eq!(
            ProtectedBodyPayload::decode_canonical(&p.encode()),
            Err(ProtectedError::InvalidProtectedBody)
        );
    }

    #[test]
    fn unknown_version_is_rejected_not_negotiated() {
        let mut p = payload();
        p.version = 2;
        assert_eq!(
            ProtectedBodyPayload::decode_canonical(&p.encode()),
            Err(ProtectedError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn bounds_are_checked_before_allocation() {
        // An over-bound input is refused by length alone (no decode attempt).
        let huge = vec![0u8; MAX_PROTECTED_PLAINTEXT + 1];
        assert_eq!(
            ProtectedBodyPayload::decode_canonical(&huge),
            Err(ProtectedError::BodyTooLarge)
        );
        let huge_envelope = vec![0u8; MAX_BODY_BYTES + 1];
        assert_eq!(
            ProtectedBodyPayload::open(&key(), &huge_envelope),
            Err(ProtectedError::BodyTooLarge)
        );
    }

    #[test]
    fn the_static_key_source_serves_exactly_its_epoch() {
        let src = StaticBodyKeys::new(key());
        assert!(src.sealing_key().is_some());
        assert!(src.opening_key(&[7u8; 16]).is_some());
        assert!(src.opening_key(&[8u8; 16]).is_none());
    }
}
