//! Wire protocol: signed gossip messages, the room ticket, and topic derivation.
//!
//! Messages broadcast on the gossip topic are postcard-encoded `SignedMessage`s
//! carrying an ed25519 signature over a `Payload`. This mirrors the canonical
//! iroh-gossip `chat.rs` example.

use std::{fmt, str::FromStr};

use anyhow::{Context, Result};
use bytes::Bytes;
use iroh::{EndpointId, PublicKey, SecretKey};
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

/// Urgency tier of a chat message — the agent-facing analogue of iMessage's
/// notification levels. The receiver's effective tier is lifted to at least
/// `Direct` when the message addresses it (an `@mention` or an entry in `to`).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize, clap::ValueEnum,
)]
#[serde(rename_all = "snake_case")]
#[value(rename_all = "snake_case")]
pub enum Tier {
    /// Ambient room chatter — logged, glanced at, no receipts expected.
    #[default]
    Ambient,
    /// Addressed to you and worth a reply (an `@mention` or an inbound call).
    Direct,
    /// Requires an explicit `ack` within the deadline; the sender is alerted if
    /// none arrives.
    NeedsAck,
    /// "Notify anyway": overrides the receiver's focus/mute and re-broadcasts
    /// until acked. The preemption tier.
    Interrupt,
}

/// State of a delivery/read/ack receipt for a specific message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptState {
    /// The message reached the recipient's daemon.
    Delivered,
    /// The recipient's read cursor passed the message (the agent read it).
    Seen,
    /// The recipient explicitly acknowledged the message.
    Acked,
}

/// The application-level payload carried inside a signed gossip message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    /// Announce/refresh our nickname.
    Hello { nick: String },
    /// A chat line for the room. Carries a sender-assigned `msg_id` (the global
    /// identity is `(from_key, msg_id)`), an urgency `tier`, an optional set of
    /// addressed recipients (`to`; empty = whole room), an optional ack
    /// `deadline_ms`, and a `notify_anyway` override of the receiver's focus.
    Chat {
        text: String,
        msg_id: u64,
        tier: Tier,
        to: Vec<PublicKey>,
        deadline_ms: Option<u64>,
        notify_anyway: bool,
    },
    /// A delivery/read/ack receipt for a message we received, addressed back to
    /// that message's original sender (`ref_from`, `ref_msg_id`).
    Receipt {
        ref_from: PublicKey,
        ref_msg_id: u64,
        state: ReceiptState,
    },
    /// A request to be added to the chat (surfaces for members to approve).
    JoinRequest { nick: String },
    /// Periodic liveness heartbeat for presence tracking.
    Presence { nick: String },
    /// Graceful "going offline" notice, broadcast on shutdown so peers can mark
    /// us offline immediately instead of waiting for the heartbeat to lapse.
    Bye { nick: String },
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

/// A compact, base32-encoded invite to join a room. It carries only what a
/// joiner cannot derive on its own: the room name (the topic is
/// `topic_for_room(room)`), the host's endpoint id, and the host's nick (for
/// one-step `connect`). We deliberately do NOT ship relay/socket addresses —
/// iroh discovery resolves a reachable address from the pubkey — so the ticket
/// stays short enough to survive copy-paste as a single line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoomTicket {
    pub room: String,
    pub host: EndpointId,
    /// Nick of the host who minted this ticket (for one-step `connect`).
    pub host_nick: String,
}

impl RoomTicket {
    /// The gossip topic this ticket joins (derived from the room name).
    pub fn topic(&self) -> TopicId {
        topic_for_room(&self.room)
    }

    /// The `groupchat://` link form of this ticket, for humans/chat apps.
    pub fn link(&self) -> String {
        format!("groupchat://join/{self}")
    }

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
        // Accept a bare token or a `groupchat://join/<token>` link, and tolerate
        // stray whitespace/newlines a terminal may have wrapped in on copy.
        let s = s.trim();
        let token = s.strip_prefix("groupchat://join/").unwrap_or(s);
        let cleaned: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = data_encoding::BASE32_NOPAD
            .decode(cleaned.to_ascii_uppercase().as_bytes())
            .context("decode room ticket base32")?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_key() -> EndpointId {
        SecretKey::from_bytes(&[7u8; 32]).public()
    }

    fn sample() -> RoomTicket {
        RoomTicket {
            room: "demo".into(),
            host: host_key(),
            host_nick: "alice".into(),
        }
    }

    #[test]
    fn ticket_roundtrips_through_base32() {
        let t = sample();
        let back: RoomTicket = t.to_string().parse().unwrap();
        assert_eq!(back.room, "demo");
        assert_eq!(back.host, host_key());
        assert_eq!(back.host_nick, "alice");
        assert_eq!(back.topic(), topic_for_room("demo"));
    }

    #[test]
    fn ticket_is_a_short_one_liner() {
        let s = sample().to_string();
        assert!(
            s.len() < 120,
            "ticket should be a short one-liner, got {} chars",
            s.len()
        );
    }

    #[test]
    fn parses_groupchat_link_form() {
        let t = sample();
        let link = t.link();
        assert!(link.starts_with("groupchat://join/"));
        let back: RoomTicket = link.parse().unwrap();
        assert_eq!(back.host, host_key());
    }

    #[test]
    fn tolerates_whitespace_from_paste() {
        let s = sample().to_string();
        // Simulate a terminal wrapping the token across lines on copy.
        let mangled = format!("  {}\n   {}  ", &s[..s.len() / 2], &s[s.len() / 2..]);
        let back: RoomTicket = mangled.parse().unwrap();
        assert_eq!(back.host, host_key());
    }
}
