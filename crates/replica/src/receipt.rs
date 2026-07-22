//! `RequestReceiptV1` — the canonical persistent-idempotency receipt.
//!
//! Every semantic transaction committed through the public action API records a
//! receipt under its durable idempotency scope `(Space, World, Device,
//! RequestId)`. An identical replay of the same request returns this receipt's
//! committed result **without reapplying** the operations; reusing the same
//! request id with a different payload is a typed conflict. The receipt carries
//! everything an identical replay must return: the application effect bytes,
//! the Observation scopes, and the committed Replica frontier the transaction
//! advanced to.
//!
//! C0 freezes the canonical bytes, bounds, and lookup semantics. The durable
//! content-addressed representation — the receipt as a store object referenced
//! by the same authoritative manifest as its transaction — lands with the
//! canonical Body/store representation (completion package C1.3); the packet
//! frozen here is that object's exact payload.

use mechanics::ids::{DeviceId, SpaceId};
use serde::{Deserialize, Serialize};

use crate::frontier::ReplicaFrontier;
use crate::ids::{BodyKey, WorldId};

/// The maximum application effect payload a receipt may carry (1 MiB), enforced
/// at commit time — an oversized effect refuses the commit before anything is
/// applied.
pub const MAX_EFFECT_BYTES: usize = 1024 * 1024;

/// The canonical committed-request receipt. `version` is exactly 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestReceiptV1 {
    pub version: u8,
    /// The durable idempotency scope.
    pub space: SpaceId,
    pub world: WorldId,
    pub device: DeviceId,
    pub request: [u8; 16],
    /// BLAKE3 of the canonical request payload — the discriminator between an
    /// identical replay (same hash → return this receipt) and a conflicting
    /// reuse (different hash → `RequestIdConflict`).
    pub payload_hash: [u8; 32],
    /// The application-defined effect bytes the original commit returned.
    pub effect: Vec<u8>,
    /// The Observation scopes the original commit touched.
    pub scopes: Vec<BodyKey>,
    /// The committed Replica frontier the transaction advanced to.
    pub frontier: ReplicaFrontier,
    /// The committed transaction's id (the full signed-envelope digest);
    /// all-zero for an idempotent no-op that committed no transaction.
    pub transaction: [u8; 32],
}

/// Why a receipt failed to decode or validate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReceiptError {
    /// The bytes did not decode, left trailing bytes, or were non-canonical.
    NonCanonical,
    /// `version` was not 1.
    UnsupportedVersion(u8),
    /// The effect exceeded [`MAX_EFFECT_BYTES`].
    EffectTooLarge,
}

impl std::fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ReceiptError {}

impl RequestReceiptV1 {
    /// Encode to canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard receipt")
    }

    /// Decode from canonical bytes, requiring exact decode/re-encode equality
    /// and validating version and effect bound.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ReceiptError> {
        let receipt: Self = postcard::from_bytes(bytes).map_err(|_| ReceiptError::NonCanonical)?;
        let re = postcard::to_stdvec(&receipt).map_err(|_| ReceiptError::NonCanonical)?;
        if re != bytes {
            return Err(ReceiptError::NonCanonical);
        }
        if receipt.version != 1 {
            return Err(ReceiptError::UnsupportedVersion(receipt.version));
        }
        if receipt.effect.len() > MAX_EFFECT_BYTES {
            return Err(ReceiptError::EffectTooLarge);
        }
        Ok(receipt)
    }

    /// The canonical lookup key bytes for this receipt's idempotency scope.
    pub fn scope_key(&self) -> Vec<u8> {
        scope_key(&self.space, &self.world, &self.device, &self.request)
    }
}

/// The canonical idempotency scope key: the postcard of
/// `(space, world, device, request)`.
pub fn scope_key(
    space: &SpaceId,
    world: &WorldId,
    device: &DeviceId,
    request: &[u8; 16],
) -> Vec<u8> {
    postcard::to_stdvec(&(space, world, device, request)).expect("postcard scope key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::BodyId;

    fn receipt() -> RequestReceiptV1 {
        RequestReceiptV1 {
            version: 1,
            space: SpaceId::from_digest([2u8; 16]),
            world: WorldId::parse("com.example.notes").unwrap(),
            device: mechanics::crypto::device_from_seed(&[5u8; 32]),
            request: [7u8; 16],
            payload_hash: [9u8; 32],
            effect: b"created".to_vec(),
            scopes: vec![BodyKey::new(
                WorldId::parse("com.example.notes").unwrap(),
                BodyId::from_bytes([1u8; 16]),
            )],
            frontier: ReplicaFrontier::new([3u8; 32], 4),
            transaction: [8u8; 32],
        }
    }

    #[test]
    fn receipt_roundtrips_canonically() {
        let r = receipt();
        let bytes = r.encode();
        assert_eq!(RequestReceiptV1::decode_canonical(&bytes).unwrap(), r);
    }

    #[test]
    fn trailing_bytes_are_non_canonical() {
        let mut bytes = receipt().encode();
        bytes.push(0);
        assert_eq!(
            RequestReceiptV1::decode_canonical(&bytes),
            Err(ReceiptError::NonCanonical)
        );
    }

    #[test]
    fn unknown_version_is_rejected_not_negotiated() {
        let mut r = receipt();
        r.version = 2;
        assert_eq!(
            RequestReceiptV1::decode_canonical(&r.encode()),
            Err(ReceiptError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn oversized_effect_is_rejected_at_exactly_the_bound() {
        let mut r = receipt();
        r.effect = vec![0u8; MAX_EFFECT_BYTES];
        assert!(RequestReceiptV1::decode_canonical(&r.encode()).is_ok());
        r.effect = vec![0u8; MAX_EFFECT_BYTES + 1];
        assert_eq!(
            RequestReceiptV1::decode_canonical(&r.encode()),
            Err(ReceiptError::EffectTooLarge)
        );
    }

    #[test]
    fn scope_key_distinguishes_every_component() {
        let base = receipt();
        let mut other = base.clone();
        other.request = [8u8; 16];
        assert_ne!(base.scope_key(), other.scope_key());
        let mut other = base.clone();
        other.device = mechanics::crypto::device_from_seed(&[6u8; 32]);
        assert_ne!(base.scope_key(), other.scope_key());
        let mut other = base.clone();
        other.world = WorldId::parse("com.example.other").unwrap();
        assert_ne!(base.scope_key(), other.scope_key());
        let mut other = base.clone();
        other.space = SpaceId::from_digest([3u8; 16]);
        assert_ne!(base.scope_key(), other.scope_key());
    }

    #[test]
    fn golden_encoding_is_byte_stable() {
        // The canonical bytes are frozen: any change to field order, types, or
        // encoding changes this fixture's exact encoding — a version break, not
        // an allowed drift. The version byte leads, then the fixed idempotency
        // scope, so the anchor asserts the exact leading bytes.
        let r = receipt();
        let bytes = r.encode();
        assert_eq!(bytes[0], 1, "version leads");
        let scope = scope_key(&r.space, &r.world, &r.device, &r.request);
        assert_eq!(
            &bytes[1..1 + scope.len()],
            &scope[..],
            "the scope fields follow the version in scope-key order"
        );
        assert_eq!(
            &bytes[1 + scope.len()..1 + scope.len() + 32],
            &[9u8; 32],
            "payload hash follows the scope"
        );
    }
}
