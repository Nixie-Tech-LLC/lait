//! Wire protocol: signed gossip messages, the room ticket, and topic derivation.
//!
//! Messages broadcast on the gossip topic are postcard-encoded `SignedMessage`s
//! carrying an ed25519 signature over a `Payload`. This mirrors the canonical
//! iroh-gossip `chat.rs` example.
//!
//! This is the transport skeleton kept from the chat app: signed announce +
//! presence over gossip. The issue-tracker data model (Loro docs, the catalog,
//! per-doc sync) is layered on top of it — see `docs/ARCHITECTURE.md`.

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

/// Length of an invite nonce — a random single-use id (128 bits).
const INVITE_NONCE_LEN: usize = 16;

/// A capability that **pre-authorizes** admission to a workspace (Pattern A). An
/// admin signs it into a [`SignedInvite`]; whoever redeems it on `join` is sealed
/// the workspace key automatically — collapsing the classic
/// request→`members approve` round-trip into a single `join`.
///
/// It is a **bearer** token: authority rides the channel the invite travels over,
/// bounded by an expiry and (by default) a single use. A workspace that wants a
/// human in the loop mints a grant-less ticket instead (`invite --require-approval`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteGrant {
    /// The workspace this grant admits into (binds the capability to one room).
    pub workspace: String,
    /// A random id so a single-use grant is spent exactly once.
    pub nonce: [u8; INVITE_NONCE_LEN],
    /// Unix seconds after which the grant is void.
    pub expires_at: u64,
    /// One redemption (`true`) vs. valid-until-expiry for a whole team (`false`).
    pub single_use: bool,
}

impl InviteGrant {
    /// Mint a fresh grant for `workspace`, valid for `ttl_secs` from `now`.
    pub fn mint(workspace: String, now: u64, ttl_secs: u64, single_use: bool) -> Self {
        let mut nonce = [0u8; INVITE_NONCE_LEN];
        getrandom::fill(&mut nonce).expect("getrandom");
        Self {
            workspace,
            nonce,
            expires_at: now.saturating_add(ttl_secs),
            single_use,
        }
    }

    /// Whether the grant is past its expiry at `now` (unix seconds).
    pub fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// An [`InviteGrant`] signed by its issuer (an admin), so a redeemer can prove the
/// workspace's authority pre-authorized them. Verification here is signature-only;
/// the *authority* (issuer ∈ current admins), *freshness* (not expired), and
/// *single-use* checks are enforced by the redeeming node against live state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInvite {
    issuer: PublicKey,
    grant: Bytes,
    signature: SignatureBytes,
}

impl SignedInvite {
    /// Sign `grant` with the issuer's secret key.
    pub fn sign(secret_key: &SecretKey, grant: &InviteGrant) -> Result<Self> {
        let data: Bytes = postcard::to_stdvec(grant)
            .context("encode invite grant")?
            .into();
        let signature = secret_key.sign(&data);
        Ok(Self {
            issuer: secret_key.public(),
            grant: data,
            signature: ByteArray::new(signature.to_bytes()),
        })
    }

    /// Verify the issuer signature and decode the grant.
    pub fn verify(&self) -> Result<(PublicKey, InviteGrant)> {
        self.issuer
            .verify(&self.grant, &iroh::Signature::from_bytes(&self.signature))
            .map_err(|e| anyhow::anyhow!("invalid invite signature: {e}"))?;
        let grant: InviteGrant =
            postcard::from_bytes(&self.grant).context("decode invite grant")?;
        Ok((self.issuer, grant))
    }
}

/// The application-level payload carried inside a signed gossip message. Scoped
/// to announce + presence; the tracker's data sync rides its own per-doc streams
/// (see `docs/ARCHITECTURE.md` §8), not this gossip payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    /// Announce/refresh our nickname.
    Hello { nick: String },
    /// A request to be added to the room (surfaces for members to see). Carries
    /// an optional pre-authorization capability (Pattern A): when present and
    /// valid, an admin receiver auto-seals the workspace key with no manual step.
    JoinRequest {
        nick: String,
        #[serde(default)]
        invite: Option<SignedInvite>,
    },
    /// Periodic liveness heartbeat for presence tracking. `state` carries the
    /// three-state input-driven presence (online/away, UI.md §4.5); a missing
    /// value from an older peer defaults to online.
    Presence {
        nick: String,
        #[serde(default)]
        state: PresenceState,
    },
    /// Graceful "going offline" notice, broadcast on shutdown so peers can mark
    /// us offline immediately instead of waiting for the heartbeat to lapse.
    Bye { nick: String },
    /// "My catalog head moved" — the P1 sync trigger (A§8). A peer that sees a
    /// head different from what it holds pulls from us over the sync ALPN.
    Announce {
        workspace: String,
        catalog_head: Vec<u8>,
    },
}

/// Three-state presence carried on the wire (UI.md §4.5). Offline is conveyed by
/// `Bye`/heartbeat lapse, not this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    /// Interactive, reply-ready — input within the engagement window.
    #[default]
    Online,
    /// Node up and syncing, human/agent not engaged.
    Away,
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
        let data: Bytes = postcard::to_stdvec(payload)
            .context("encode payload")?
            .into();
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
    /// The workspace id the joiner adopts (the genesis trust anchor, A§6/A§10).
    /// A brand-new client establishes the whole workspace from nothing but this
    /// ticket: it adopts the id, then backfills the catalog + docs over sync.
    #[serde(default)]
    pub workspace: String,
    /// An optional pre-authorization capability (Pattern A). Present ⇒ a joiner is
    /// auto-admitted on `join` (the seal happens without a manual `members
    /// approve`). Absent ⇒ the classic request→approve flow. The joiner echoes it
    /// in its signed `JoinRequest`.
    #[serde(default)]
    pub invite: Option<SignedInvite>,
}

impl RoomTicket {
    /// The gossip topic this ticket joins (derived from the room name).
    pub fn topic(&self) -> TopicId {
        topic_for_room(&self.room)
    }

    /// The `lait://` link form of this ticket, for humans/chat apps.
    pub fn link(&self) -> String {
        format!("lait://join/{self}")
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
        // Accept a bare token or a `lait://join/<token>` link, and tolerate
        // stray whitespace/newlines a terminal may have wrapped in on copy.
        let s = s.trim();
        let token = s.strip_prefix("lait://join/").unwrap_or(s);
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
            workspace: "ws_00000000000000000000000000".into(),
            invite: None,
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
    fn parses_lait_link_form() {
        let t = sample();
        let link = t.link();
        assert!(link.starts_with("lait://join/"));
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

    #[test]
    fn signed_invite_roundtrips_and_detects_tampering() {
        let sk = SecretKey::from_bytes(&[9u8; 32]);
        let grant = InviteGrant::mint("ws_1".into(), 1_000, 3_600, true);
        let signed = SignedInvite::sign(&sk, &grant).unwrap();
        let (issuer, back) = signed.verify().expect("valid signature verifies");
        assert_eq!(issuer, sk.public());
        assert_eq!(back, grant);
        assert!(!back.is_expired(4_599) && back.is_expired(4_600));
        // Flip a byte of the signed grant ⇒ verification must fail.
        let mut tampered = signed;
        let mut bytes = tampered.grant.to_vec();
        bytes[0] ^= 0xff;
        tampered.grant = bytes.into();
        assert!(tampered.verify().is_err(), "tampered grant must not verify");
    }

    #[test]
    fn ticket_carries_an_invite_through_base32() {
        let sk = SecretKey::from_bytes(&[3u8; 32]);
        let grant = InviteGrant::mint("ws_00000000000000000000000000".into(), 0, 604_800, true);
        let mut t = sample();
        t.invite = Some(SignedInvite::sign(&sk, &grant).unwrap());
        let back: RoomTicket = t.to_string().parse().unwrap();
        let (issuer, g) = back
            .invite
            .expect("invite survives roundtrip")
            .verify()
            .unwrap();
        assert_eq!(issuer, sk.public());
        assert_eq!(g, grant);
    }
}
