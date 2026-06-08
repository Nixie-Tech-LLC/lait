//! Wire protocol: signed gossip messages, the room ticket, and topic derivation.
//!
//! Messages broadcast on the gossip topic are postcard-encoded `SignedMessage`s
//! carrying an ed25519 signature over a `Payload`. This mirrors the canonical
//! iroh-gossip `chat.rs` example.

use std::{fmt, str::FromStr};

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{EndpointAddr, PublicKey, SecretKey};
use iroh_gossip::proto::TopicId;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;

const SIGNATURE_LENGTH: usize = iroh::Signature::LENGTH;
type SignatureBytes = ByteArray<SIGNATURE_LENGTH>;

/// Derive a stable gossip topic id from a human room name, so everyone who
/// types the same room name lands in the same room.
pub fn topic_for_room(room: &str) -> TopicId {
    let hash = blake3::hash(room.as_bytes());
    TopicId::from_bytes(*hash.as_bytes())
}

/// The application-level payload carried inside a signed gossip message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    /// Announce/refresh our nickname.
    Hello { nick: String },
    /// A normal chat line for the room.
    Chat { text: String },
    /// A request to be added to the chat (surfaces for members to approve).
    JoinRequest { nick: String },
    /// Periodic liveness heartbeat for presence tracking.
    Presence { nick: String },
    /// Announce a shared resource: a base32 BlobTicket plus a human label.
    Resource { label: String, ticket: String },
}

/// A signed, postcard-encoded envelope broadcast over gossip.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    from: PublicKey,
    data: Bytes,
    signature: SignatureBytes,
}

impl SignedMessage {
    /// Verify the signature and decode the inner payload.
    pub fn verify_and_decode(bytes: &[u8]) -> Result<(PublicKey, Payload)> {
        let signed: Self = postcard::from_bytes(bytes).context("decode signed message")?;
        let key = signed.from;
        key.verify(
            &signed.data,
            &iroh::Signature::from_bytes(&signed.signature),
        )
        .map_err(|e| anyhow::anyhow!("invalid signature: {e}"))?;
        let payload: Payload = postcard::from_bytes(&signed.data).context("decode payload")?;
        Ok((signed.from, payload))
    }

    /// Sign and encode a payload for broadcast.
    pub fn sign_and_encode(secret_key: &SecretKey, payload: &Payload) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(payload).context("encode payload")?.into();
        let signature = secret_key.sign(&data);
        let signed = Self {
            from: secret_key.public(),
            data,
            signature: ByteArray::new(signature.to_bytes()),
        };
        let encoded = postcard::to_stdvec(&signed).context("encode signed message")?;
        Ok(encoded.into())
    }
}

/// A base32-encoded invite to join a room: the topic, bootstrap peers, and the
/// minting host's nickname so a joiner can auto-add them as a contact in one
/// step (the host's endpoint id is `peers[0].id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomTicket {
    pub topic: TopicId,
    pub peers: Vec<EndpointAddr>,
    /// Nick of the host who minted this ticket (for one-step `connect`).
    pub host_nick: String,
}

impl RoomTicket {
    /// The endpoint id of the host who minted the ticket, if any bootstrap
    /// peer is present (the first peer is always the minting host).
    pub fn host(&self) -> Option<EndpointAddr> {
        self.peers.first().cloned()
    }
}

impl RoomTicket {
    fn to_bytes(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard::to_stdvec is infallible")
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        postcard::from_bytes(bytes).context("decode room ticket")
    }
}

impl fmt::Display for RoomTicket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.to_bytes());
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

impl FromStr for RoomTicket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let bytes = data_encoding::BASE32_NOPAD
            .decode(s.trim().to_ascii_uppercase().as_bytes())
            .context("decode room ticket base32")?;
        Self::from_bytes(&bytes)
    }
}
