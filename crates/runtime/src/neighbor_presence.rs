//! Neighbor presence v1 — an authenticated two-message liveness challenge
//! (`lait/neighbor-presence/1`), the S4 replacement for the raw `PRESENCE_ALPN`
//! dial.
//!
//! The exchange proves a Neighbor is reachable *now* without conferring any
//! standing: it carries no frontier, routes, standing, or authority material.
//! Both messages are signed (`.../probe`, `.../ack`); each signature key must
//! match its StationId, and the StationId must equal the negotiated transport
//! identity (in LAIT a peer *is* its device key). Nonces come from the OS
//! CSPRNG; challenges are single-use for one exchange.

use mechanics::ids::StationId;
use serde::{Deserialize, Serialize};

use crate::wire::length_framed;

/// The only presence protocol version this build speaks (never negotiated).
pub const PRESENCE_PROTOCOL: u16 = 1;

/// The Neighbor-presence v1 ALPN.
pub const PRESENCE_ALPN: &[u8] = b"lait/neighbor-presence/1";
/// PresenceProbe signing domain.
pub const PROBE_DOMAIN: &[u8] = b"lait/neighbor-presence/1/probe";
/// PresenceAck signing domain.
pub const ACK_DOMAIN: &[u8] = b"lait/neighbor-presence/1/ack";
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;
/// Maximum encoded message size.
pub const MAX_MESSAGE: usize = 4 * 1024;

/// The probe that opens a presence challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceProbe {
    pub protocol: u16,
    pub space: [u8; 29],
    pub initiator_station: [u8; 32],
    pub responder_station: [u8; 32],
    pub initiator_transport: [u8; 32],
    pub nonce: [u8; 32],
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// The ack that answers a probe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresenceAck {
    /// Commitment to the exact probe being answered.
    pub probe_hash: [u8; 32],
    pub responder_transport: [u8; 32],
    pub nonce: [u8; 32],
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why a presence message failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresenceError {
    /// The signed protocol field names a version this build does not speak.
    UnsupportedProtocol(u16),
    UnsupportedSignatureAlgorithm(u8),
    NonCanonical,
    /// A signer/StationId/transport identity did not agree.
    IdentityMismatch,
    /// The Space did not match the expected exchange Space (cross-Space replay).
    SpaceMismatch,
    /// The ack did not commit to this probe, or reflected the probe's own nonce.
    ChallengeMismatch,
    BadSignature,
}

impl std::fmt::Display for PresenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for PresenceError {}

fn decode_canonical<T>(bytes: &[u8]) -> Result<T, PresenceError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    if bytes.len() > MAX_MESSAGE {
        return Err(PresenceError::NonCanonical);
    }
    let value: T = postcard::from_bytes(bytes).map_err(|_| PresenceError::NonCanonical)?;
    let re = postcard::to_stdvec(&value).map_err(|_| PresenceError::NonCanonical)?;
    if re != bytes {
        return Err(PresenceError::NonCanonical);
    }
    Ok(value)
}

impl PresenceProbe {
    fn preimage(
        protocol: u16,
        space: &[u8; 29],
        initiator_station: &[u8; 32],
        responder_station: &[u8; 32],
        initiator_transport: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let body = postcard::to_stdvec(&(
            protocol,
            space,
            initiator_station,
            responder_station,
            initiator_transport,
            nonce,
        ))
        .expect("postcard probe body");
        length_framed(PROBE_DOMAIN, &body)
    }

    /// Sign a probe from the initiator's device seed. The seed's key becomes
    /// both `initiator_station` and `initiator_transport` (a peer is its key).
    pub fn sign(
        protocol: u16,
        space: [u8; 29],
        responder_station: [u8; 32],
        nonce: [u8; 32],
        initiator_seed: &[u8; 32],
    ) -> Option<Self> {
        let station = mechanics::crypto::device_from_seed(initiator_seed).key_bytes()?;
        let preimage = Self::preimage(
            protocol,
            &space,
            &station,
            &responder_station,
            &station,
            &nonce,
        );
        let signature = mechanics::crypto::sign_detached(initiator_seed, &preimage);
        Some(Self {
            protocol,
            space,
            initiator_station: station,
            responder_station,
            initiator_transport: station,
            nonce,
            signature_algorithm: SIG_ALG_ED25519,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard probe")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PresenceError> {
        decode_canonical(bytes)
    }

    /// A commitment to the canonical probe (everything the initiator signed).
    pub fn hash(&self) -> [u8; 32] {
        *blake3::hash(&Self::preimage(
            self.protocol,
            &self.space,
            &self.initiator_station,
            &self.responder_station,
            &self.initiator_transport,
            &self.nonce,
        ))
        .as_bytes()
    }

    /// Verify the probe: algorithm, the expected exchange Space (rejecting a
    /// cross-Space replay), the initiator's signature, and that its StationId
    /// equals its transport identity and the connection peer.
    pub fn verify(
        &self,
        expected_space: &[u8; 29],
        transport_peer: &StationId,
    ) -> Result<(), PresenceError> {
        if self.protocol != PRESENCE_PROTOCOL {
            return Err(PresenceError::UnsupportedProtocol(self.protocol));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(PresenceError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        if &self.space != expected_space {
            return Err(PresenceError::SpaceMismatch);
        }
        if self.initiator_station != self.initiator_transport
            || self.initiator_transport != transport_peer.key_bytes()
        {
            return Err(PresenceError::IdentityMismatch);
        }
        let preimage = Self::preimage(
            self.protocol,
            &self.space,
            &self.initiator_station,
            &self.responder_station,
            &self.initiator_transport,
            &self.nonce,
        );
        if !mechanics::crypto::verify_detached(&self.initiator_station, &preimage, &self.signature)
        {
            return Err(PresenceError::BadSignature);
        }
        Ok(())
    }
}

impl PresenceAck {
    fn preimage(
        probe_hash: &[u8; 32],
        responder_transport: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Vec<u8> {
        let body = postcard::to_stdvec(&(probe_hash, responder_transport, nonce))
            .expect("postcard ack body");
        length_framed(ACK_DOMAIN, &body)
    }

    /// Sign an ack answering `probe` from the responder's device seed.
    pub fn sign(probe: &PresenceProbe, nonce: [u8; 32], responder_seed: &[u8; 32]) -> Option<Self> {
        let responder = mechanics::crypto::device_from_seed(responder_seed).key_bytes()?;
        let probe_hash = probe.hash();
        let preimage = Self::preimage(&probe_hash, &responder, &nonce);
        let signature = mechanics::crypto::sign_detached(responder_seed, &preimage);
        Some(Self {
            probe_hash,
            responder_transport: responder,
            nonce,
            signature_algorithm: SIG_ALG_ED25519,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard ack")
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PresenceError> {
        decode_canonical(bytes)
    }

    /// Verify the ack against the probe it answers and the responder's
    /// negotiated transport identity. Rejects reflection (echoing the probe's
    /// nonce), commitment mismatch, and identity/signature substitution.
    pub fn verify(
        &self,
        probe: &PresenceProbe,
        transport_peer: &StationId,
    ) -> Result<(), PresenceError> {
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(PresenceError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        // The ack must commit to exactly this probe.
        if self.probe_hash != probe.hash() {
            return Err(PresenceError::ChallengeMismatch);
        }
        // A single-use challenge: the responder must present a fresh nonce, not
        // reflect the initiator's.
        if self.nonce == probe.nonce {
            return Err(PresenceError::ChallengeMismatch);
        }
        // The responder's transport identity must be the probe's responder
        // Station and the negotiated connection peer.
        if self.responder_transport != probe.responder_station
            || self.responder_transport != transport_peer.key_bytes()
        {
            return Err(PresenceError::IdentityMismatch);
        }
        let preimage = Self::preimage(&self.probe_hash, &self.responder_transport, &self.nonce);
        if !mechanics::crypto::verify_detached(&probe.responder_station, &preimage, &self.signature)
        {
            return Err(PresenceError::BadSignature);
        }
        Ok(())
    }
}
