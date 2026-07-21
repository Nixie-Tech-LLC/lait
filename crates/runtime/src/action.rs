//! `SignedWorldActionV1` — the canonical, signed application-action envelope.
//!
//! A World intent that must be authorized and durably committed rides this
//! envelope. Runtime derives [`PrincipalFacts`](crate::world::PrincipalFacts)
//! from the docked identity; a caller cannot assert them. The envelope binds the
//! request to a Space, World, actor/device, authority frontier, and intent
//! schema/version, and commits to the payload by hash.
//!
//! The signature preimage uses the **length-framed** rule (the same rule
//! Coordinates v1 uses in S2) with domain `lait/world-action/1`, covering
//! version, header, payload, and signer. Exact postcard decode/re-encode
//! equality is required — a non-canonical encoding is rejected, not tolerated.
//!
//! The envelope's self-signature, canonical form, payload binding, and version
//! rejection are validated here ([`SignedWorldActionV1::verify_self`]); the
//! mechanics authority proof (the signer is the docked principal, with standing
//! at the header's authority frontier) and the persistent-idempotency scope are
//! enforced by [`Session::submit`](crate::session::Session::submit), which is
//! the only local commit entry. Imported signed actions enter through
//! Contact/Convergence, never a second submit API.

use mechanics::ids::{ActorId, DeviceId, SpaceId};
use replica::frontier::AuthorityFrontier;
use replica::ids::{SchemaId, WorldId};
use serde::{Deserialize, Serialize};

/// The signature domain for a World action.
pub const WORLD_ACTION_DOMAIN: &[u8] = b"lait/world-action/1";

/// The Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;

/// The maximum action payload size (1 MiB).
pub const MAX_PAYLOAD: usize = 1024 * 1024;

/// 128 random caller-supplied bits correlating a request for idempotency. It is
/// a diagnostic/idempotency aid, never Body identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RequestId([u8; 16]);

impl RequestId {
    /// Mint a fresh random request id from the OS CSPRNG. Deterministic
    /// callers may instead supply their own 128 random bits via
    /// [`RequestId::from_bytes`].
    pub fn mint() -> Self {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).expect("OS CSPRNG");
        Self(raw)
    }
    pub fn from_bytes(raw: [u8; 16]) -> Self {
        Self(raw)
    }
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }
}

/// The persistent idempotency key: `(Space, World, Device, Request)`. Identical
/// reuse returns the committed receipt; reuse with another payload is a
/// conflict.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdempotencyKey {
    pub space: SpaceId,
    pub world: WorldId,
    pub device: DeviceId,
    pub request: RequestId,
}

/// The authenticated header of a World action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldActionHeader {
    pub request: RequestId,
    pub space: SpaceId,
    pub world: WorldId,
    pub actor: ActorId,
    pub device: DeviceId,
    pub authority_frontier: AuthorityFrontier,
    pub intent_schema: SchemaId,
    pub intent_version: u32,
    /// BLAKE3 of the payload, binding it into the signed header.
    pub payload_hash: [u8; 32],
}

/// A signed World action. `version` is exactly 1; `signature_algorithm` is 1
/// (Ed25519). The payload is at most 1 MiB.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWorldActionV1 {
    pub version: u8,
    pub header: WorldActionHeader,
    pub payload: Vec<u8>,
    pub signer: DeviceId,
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why a World action failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActionError {
    /// The bytes did not decode, or left trailing bytes, or were non-canonical
    /// (decode then re-encode was not byte-exact).
    NonCanonical,
    /// `version` was not 1.
    UnsupportedVersion(u8),
    /// `signature_algorithm` was not 1 (Ed25519).
    UnsupportedSignatureAlgorithm(u8),
    /// The payload exceeded 1 MiB.
    PayloadTooLarge,
    /// The header's `payload_hash` did not match the payload.
    PayloadHashMismatch,
    /// The signer was not the acting device, or its key bytes were malformed.
    SignerMismatch,
    /// The Ed25519 signature did not verify.
    BadSignature,
}

impl std::fmt::Display for ActionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ActionError {}

/// The payload commitment placed in the header.
pub fn payload_hash(payload: &[u8]) -> [u8; 32] {
    *blake3::hash(payload).as_bytes()
}

/// Build the length-framed signature preimage:
/// `u16be(domain_len) || domain || u32be(body_len) || body`, where `body` is the
/// canonical postcard of `(version, header, payload, signer)`. This is the same
/// framing rule Coordinates v1 (S2) uses.
fn action_preimage(
    version: u8,
    header: &WorldActionHeader,
    payload: &[u8],
    signer: &DeviceId,
) -> Vec<u8> {
    let body =
        postcard::to_stdvec(&(version, header, payload, signer)).expect("postcard action body");
    let mut out = Vec::with_capacity(2 + WORLD_ACTION_DOMAIN.len() + 4 + body.len());
    out.extend_from_slice(&(WORLD_ACTION_DOMAIN.len() as u16).to_be_bytes());
    out.extend_from_slice(WORLD_ACTION_DOMAIN);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(&body);
    out
}

impl SignedWorldActionV1 {
    /// Construct and sign a World action from the acting device's identity seed.
    /// The seed's public key must equal `header.device`.
    pub fn sign(header: WorldActionHeader, payload: Vec<u8>, device_seed: &[u8; 32]) -> Self {
        let signer = mechanics::crypto::device_from_seed(device_seed);
        let preimage = action_preimage(1, &header, &payload, &signer);
        let signature = mechanics::crypto::sign_detached(device_seed, &preimage);
        Self {
            version: 1,
            header,
            payload,
            signer,
            signature_algorithm: SIG_ALG_ED25519,
            signature,
        }
    }

    /// Decode from canonical bytes, requiring exact decode/re-encode equality
    /// (no trailing bytes, minimal encoding).
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ActionError> {
        let action: Self = postcard::from_bytes(bytes).map_err(|_| ActionError::NonCanonical)?;
        let re = postcard::to_stdvec(&action).map_err(|_| ActionError::NonCanonical)?;
        if re != bytes {
            return Err(ActionError::NonCanonical);
        }
        Ok(action)
    }

    /// Encode to canonical bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard action")
    }

    /// Validate everything an opaque verifier can check without mechanics
    /// authority state: version, algorithm, payload bound, payload hash, signer
    /// identity, and the self-signature. Returns the idempotency key on success.
    ///
    /// The mechanics proof that `signer` belongs to `header.actor` and had
    /// standing at `header.authority_frontier` is a separate step wired in S5.
    pub fn verify_self(&self) -> Result<IdempotencyKey, ActionError> {
        if self.version != 1 {
            return Err(ActionError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(ActionError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        if self.payload.len() > MAX_PAYLOAD {
            return Err(ActionError::PayloadTooLarge);
        }
        if self.header.payload_hash != payload_hash(&self.payload) {
            return Err(ActionError::PayloadHashMismatch);
        }
        if self.signer != self.header.device {
            return Err(ActionError::SignerMismatch);
        }
        let key = self.signer.key_bytes().ok_or(ActionError::SignerMismatch)?;
        let preimage = action_preimage(self.version, &self.header, &self.payload, &self.signer);
        if !mechanics::crypto::verify_detached(&key, &preimage, &self.signature) {
            return Err(ActionError::BadSignature);
        }
        Ok(IdempotencyKey {
            space: self.header.space.clone(),
            world: self.header.world.clone(),
            device: self.header.device.clone(),
            request: self.header.request,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(payload: &[u8], device: &DeviceId) -> WorldActionHeader {
        WorldActionHeader {
            request: RequestId::from_bytes([1u8; 16]),
            space: SpaceId::from_digest([2u8; 16]),
            world: WorldId::parse("com.example.issues").unwrap(),
            actor: ActorId::from_incept_hash(&"a".repeat(64)),
            device: device.clone(),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![0xAA, 0xBB]),
            intent_schema: SchemaId::parse("issue").unwrap(),
            intent_version: 1,
            payload_hash: payload_hash(payload),
        }
    }

    fn signed(seed: &[u8; 32]) -> SignedWorldActionV1 {
        let device = mechanics::crypto::device_from_seed(seed);
        let payload = b"an application intent".to_vec();
        SignedWorldActionV1::sign(header(&payload, &device), payload, seed)
    }

    #[test]
    fn signed_action_roundtrips_and_verifies() {
        let action = signed(&[7u8; 32]);
        let bytes = action.encode();
        let back = SignedWorldActionV1::decode_canonical(&bytes).unwrap();
        assert_eq!(action, back);
        let key = back.verify_self().unwrap();
        assert_eq!(key.request, RequestId::from_bytes([1u8; 16]));
    }

    #[test]
    fn tampered_payload_fails_hash_binding() {
        let mut action = signed(&[7u8; 32]);
        action.payload = b"a different intent".to_vec();
        assert_eq!(action.verify_self(), Err(ActionError::PayloadHashMismatch));
    }

    #[test]
    fn tampered_signature_fails_verification() {
        let mut action = signed(&[7u8; 32]);
        action.signature[0] ^= 0xff;
        assert_eq!(action.verify_self(), Err(ActionError::BadSignature));
    }

    #[test]
    fn wrong_signer_is_rejected() {
        // Re-sign the preimage with a different seed but claim the original device.
        let mut action = signed(&[7u8; 32]);
        action.signer = mechanics::crypto::device_from_seed(&[9u8; 32]);
        // signer no longer matches header.device
        assert_eq!(action.verify_self(), Err(ActionError::SignerMismatch));
    }

    #[test]
    fn unsupported_version_is_rejected_not_negotiated() {
        let mut action = signed(&[7u8; 32]);
        action.version = 2;
        assert_eq!(
            action.verify_self(),
            Err(ActionError::UnsupportedVersion(2))
        );
    }

    #[test]
    fn unsupported_signature_algorithm_is_rejected() {
        let mut action = signed(&[7u8; 32]);
        action.signature_algorithm = 2;
        assert_eq!(
            action.verify_self(),
            Err(ActionError::UnsupportedSignatureAlgorithm(2))
        );
    }

    #[test]
    fn trailing_bytes_are_non_canonical() {
        let action = signed(&[7u8; 32]);
        let mut bytes = action.encode();
        bytes.push(0x00);
        assert_eq!(
            SignedWorldActionV1::decode_canonical(&bytes),
            Err(ActionError::NonCanonical)
        );
    }

    #[test]
    fn oversized_payload_is_rejected() {
        let seed = [3u8; 32];
        let device = mechanics::crypto::device_from_seed(&seed);
        let payload = vec![0u8; MAX_PAYLOAD + 1];
        let action = SignedWorldActionV1::sign(header(&payload, &device), payload, &seed);
        assert_eq!(action.verify_self(), Err(ActionError::PayloadTooLarge));
    }

    #[test]
    fn signature_is_deterministic_for_a_fixed_seed() {
        // Ed25519 is deterministic; a fixed seed + fixed header/payload yields a
        // byte-stable signature, so this doubles as a golden anchor.
        let a = signed(&[42u8; 32]);
        let b = signed(&[42u8; 32]);
        assert_eq!(a.signature, b.signature);
        assert_eq!(a.encode(), b.encode());
    }
}
