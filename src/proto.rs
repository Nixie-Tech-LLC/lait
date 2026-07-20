//! Wire protocol: signed gossip messages, the space ticket, and topic derivation.
//!
//! Messages broadcast on the gossip topic are postcard-encoded `SignedMessage`s
//! carrying a **lait** ed25519 signature over a `Payload` — authored, signed, and
//! verified by [`crate::sigdag`], lait's own signing plane — so a message's
//! author is a lait [`DeviceId`] rather than a transport key, and the primitive
//! is the same one the trust planes use.
//!
//! No concrete transport type is named here. A room selector is the transport
//! seam's opaque [`Topic`]; this module owns only the rule that derives one from
//! a space id, and a ticket's host is a lait [`DeviceId`] like every other
//! identity.

use std::{fmt, str::FromStr};

use anyhow::{Context, Result};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use serde_byte_array::ByteArray;

use crate::{ids::DeviceId, transport::Topic};

/// An ed25519 signature is 64 bytes.
const SIGNATURE_LENGTH: usize = 64;
type SignatureBytes = ByteArray<SIGNATURE_LENGTH>;

/// Signing domains (see [`crate::sigdag::sign_message`]). Distinct per use-site so
/// a signature from one context can never verify in another — a gossip message is
/// not liftable into an invite, and vice-versa.
const GOSSIP_DOMAIN: &[u8] = b"lait/gossip/1";
const INVITE_DOMAIN: &[u8] = b"lait/invite/1";

/// Derive the gossip topic id from the space id. The topic is a pure
/// function of the genesis identity — there is no user-settable network name,
/// so it can never drift, be renamed apart, or collide across spaces the
/// way the old folder-seeded "room" string could. Domain-separated so the topic
/// space is disjoint from any other blake3 use; the `lait/topic/v3` tag also
/// serves as the gossip protocol **epoch** — bump it on any breaking change to
/// [`Payload`] *or the message-signing preimage* so old and new nodes partition
/// onto different topics instead of silently failing to decode/verify each
/// other's frames (postcard is not self-describing; that drop is logged in
/// node.rs). v2 carried the domain/space-bound signatures; v3 carries the
/// space-vocabulary flag day, partitioning v0.5.x nodes onto a topic no v0.6
/// node subscribes to.
pub fn topic_for_space(space: &str) -> Topic {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"lait/topic/v3");
    hasher.update(space.as_bytes());
    Topic(*hasher.finalize().as_bytes())
}

/// Serde for a [`DeviceId`] as the raw 32 bytes of the ed25519 key it *is*.
///
/// A ticket is a single copy-paste line, and its host field is the largest fixed
/// cost in it. Spelling the key as its 64 hex characters would double that field
/// and lengthen every invite link ever sent, for an identity that has not
/// changed by one bit.
mod device_id_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    use crate::ids::DeviceId;

    pub fn serialize<S: Serializer>(id: &DeviceId, s: S) -> Result<S::Ok, S::Error> {
        id.key_bytes()
            .ok_or_else(|| serde::ser::Error::custom("host is not a 32-byte device key"))?
            .serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<DeviceId, D::Error> {
        Ok(DeviceId::from_key_bytes(&<[u8; 32]>::deserialize(d)?))
    }
}

/// Length of an invite nonce — a random single-use id (128 bits).
const INVITE_NONCE_LEN: usize = 16;

/// A capability that **pre-authorizes** admission to a space (Pattern A). An
/// admin signs it into a [`SignedInvite`]; whoever redeems it on `join` is sealed
/// the space key automatically — collapsing the classic
/// request→`members approve` round-trip into a single `join`.
///
/// It is a **bearer** token: authority rides the channel the invite travels over,
/// bounded by an expiry and (by default) a single use. A space that wants a
/// human in the loop mints a grant-less ticket instead (`invite --require-approval`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteGrant {
    /// The space this grant admits into (binds the capability to one room).
    pub space: String,
    /// A random id so a single-use grant is spent exactly once.
    pub nonce: [u8; INVITE_NONCE_LEN],
    /// Unix seconds after which the grant is void.
    pub expires_at: u64,
    /// One redemption (`true`) vs. valid-until-expiry for a whole team (`false`).
    pub single_use: bool,
}

impl InviteGrant {
    /// Mint a fresh grant for `space`, valid for `ttl_secs` from `now`.
    pub fn mint(space: String, now: u64, ttl_secs: u64, single_use: bool) -> Self {
        let mut nonce = [0u8; INVITE_NONCE_LEN];
        getrandom::fill(&mut nonce).expect("getrandom");
        Self {
            space,
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
/// space's authority pre-authorized them. Verification here is signature-only;
/// the *authority* (issuer ∈ current admins), *freshness* (not expired), and
/// *single-use* checks are enforced by the redeeming node against live state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedInvite {
    issuer: DeviceId,
    grant: Bytes,
    signature: SignatureBytes,
}

impl SignedInvite {
    /// Sign `grant` with the issuer's identity seed (lait's own signing plane).
    /// Bound to the invite domain and the grant's own space.
    pub fn sign(seed: &[u8; 32], grant: &InviteGrant) -> Result<Self> {
        let data: Bytes = postcard::to_stdvec(grant)
            .context("encode invite grant")?
            .into();
        let (issuer, sig) = crate::sigdag::sign_message(INVITE_DOMAIN, &grant.space, seed, &data);
        Ok(Self {
            issuer,
            grant: data,
            signature: ByteArray::new(sig),
        })
    }

    /// Verify the issuer signature and decode the grant. Returns the issuer's
    /// lait `DeviceId` (what membership is keyed on). The signature is bound to the
    /// invite domain and the grant's space, so it cannot be a lifted gossip
    /// signature nor replayed for a different space.
    pub fn verify(&self) -> Result<(DeviceId, InviteGrant)> {
        let grant: InviteGrant =
            postcard::from_bytes(&self.grant).context("decode invite grant")?;
        if !crate::sigdag::verify_message(
            INVITE_DOMAIN,
            &grant.space,
            &self.issuer,
            &self.grant,
            &self.signature,
        ) {
            anyhow::bail!("invalid invite signature");
        }
        Ok((self.issuer.clone(), grant))
    }
}

/// The application-level payload carried inside a signed gossip message. Scoped
/// to announcements and presence; document synchronization uses separate
/// per-document streams rather than this gossip payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Payload {
    /// Announce/refresh our nickname.
    Hello { nick: String },
    /// A request to be added to the room (surfaces for members to see). Carries
    /// an optional pre-authorization capability (Pattern A): when present and
    /// valid, an admin receiver auto-seals the space key with no manual step.
    JoinRequest {
        nick: String,
        /// The pre-authorization, **sealed to the host** (`ticket.host`) and bound
        /// to the joiner's actor: `seal_to(host, postcard((SignedInvite, redeemer)))`.
        /// Sealing keeps the nonce off the shared gossip topic — a removed member
        /// on the topic sees only ciphertext, so it cannot lift the invite to
        /// hijack the seat. Binding the redeemer means a *copied* blob only ever
        /// admits the original joiner (an eavesdropper cannot re-pair it with its
        /// own inception). Only the host can open it, so the host auto-admits;
        /// other admins fall back to the manual approve of the stashed request.
        #[serde(default)]
        invite: Option<Vec<u8>>,
        /// The joiner's self-certifying actor inception (lait/actor/1), so an
        /// admin can admit its *actor* before doc-sync delivers it. Absent only
        /// from a pre-actor peer (which a v2 daemon will not admit).
        #[serde(default)]
        incept: Option<crate::actor::SignedEvent>,
    },
    /// Periodic liveness heartbeat for presence tracking. `state` carries the
    /// three-state input-driven presence (online or away).
    ///
    /// NOTE: postcard is not self-describing, so `#[serde(default)]` does NOT make
    /// this field forward-compatible on the wire — a pre-`state` peer sends a
    /// shorter frame and a newer peer fails to decode it with
    /// `DeserializeUnexpectedEnd` (the drop is now logged in node.rs). Adding
    /// `state` was a coordinated format bump; the `#[serde(default)]` only helps
    /// the JSON/DTO paths, not the postcard wire. See `docs/PROTOCOL.md`.
    Presence {
        nick: String,
        #[serde(default)]
        state: PresenceState,
    },
    /// Graceful "going offline" notice, broadcast on shutdown so peers can mark
    /// us offline immediately instead of waiting for the heartbeat to lapse.
    Bye { nick: String },
    /// "My catalog head moved": the peer-sync trigger. A peer that sees a
    /// head different from what it holds pulls from us over the sync ALPN.
    Announce {
        space: String,
        catalog_head: Vec<u8>,
    },
}

/// Three-state presence carried on the wire. Offline is conveyed by
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

/// A signed, postcard-encoded envelope broadcast over gossip. The author is a
/// lait [`DeviceId`], signed by [`crate::sigdag`] — the transport never sees a
/// key type of its own here.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignedMessage {
    from: DeviceId,
    data: Bytes,
    signature: SignatureBytes,
}

impl SignedMessage {
    /// Verify the signature and decode the inner payload. `space` is the
    /// receiver's own space: the signature is bound to it, so a message signed
    /// for a different topic fails here — closing cross-space replay of
    /// presence/join gossip. Returns the author's device id, which is also the
    /// peer to dial back — a device *is* its key.
    pub fn verify_and_decode(space: &str, bytes: &[u8]) -> Result<(DeviceId, Payload)> {
        let signed: Self = postcard::from_bytes(bytes).context("decode signed message")?;
        if !crate::sigdag::verify_message(
            GOSSIP_DOMAIN,
            space,
            &signed.from,
            &signed.data,
            &signed.signature,
        ) {
            anyhow::bail!("invalid signature");
        }
        let payload: Payload = postcard::from_bytes(&signed.data).context("decode payload")?;
        Ok((signed.from, payload))
    }

    /// Sign and encode a payload for broadcast on `space`'s topic, using the
    /// sender's identity seed. The signature binds the gossip domain and space.
    pub fn sign_and_encode(space: &str, seed: &[u8; 32], payload: &Payload) -> Result<Bytes> {
        let data: Bytes = postcard::to_stdvec(payload)
            .context("encode payload")?
            .into();
        let (from, sig) = crate::sigdag::sign_message(GOSSIP_DOMAIN, space, seed, &data);
        let signed = Self {
            from,
            data,
            signature: ByteArray::new(sig),
        };
        let encoded = postcard::to_stdvec(&signed).context("encode signed message")?;
        Ok(encoded.into())
    }
}

/// The [`SpaceTicket`] wire format this build mints and accepts. It is the
/// ticket's first byte, checked before any field is decoded, so an invite from a
/// different epoch is refused by name instead of decoding into plausible
/// nonsense. Bump it for any change to the ticket's shape or field meanings.
pub const TICKET_VERSION: u8 = 1;

/// A compact, base32-encoded invite to join a space. It carries only what a
/// joiner cannot derive on its own: the space id (the topic is
/// `topic_for_space(space)` and the genesis trust anchor),
/// the space's display name (so the joiner sees what they're joining before
/// the catalog arrives), the host's endpoint id, and the host's nick (for
/// one-step `connect`). We deliberately do NOT ship relay/socket addresses —
/// the adapter's discovery resolves a reachable address from the pubkey — so the
/// ticket stays short enough to survive copy-paste as a single line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpaceTicket {
    /// The space id the joiner bootstraps from (required — a brand-new
    /// client establishes the whole space from nothing but this ticket: it
    /// roots on the id, then backfills the catalog + docs over sync).
    pub space: String,
    /// The space's display name at mint time (cosmetic; the synced catalog
    /// value is authoritative once it arrives).
    pub name: String,
    /// The host to dial, and the recipient a pre-authorization is sealed to.
    /// Carried as the key's raw 32 bytes; see [`device_id_bytes`].
    #[serde(with = "device_id_bytes")]
    pub host: DeviceId,
    /// Nick of the host who minted this ticket (for one-step `connect`).
    pub host_nick: String,
    /// The salt that, with the founding device, derives `space`
    /// (`lait/space/1`). Ships so the joiner can verify the id commits to the
    /// founder rather than trusting a bare anchor string.
    #[serde(default)]
    pub salt: [u8; 16],
    /// The break-glass recovery commitment folded into `space`. The joiner
    /// checks the id commits to it too, so the recovery authority is pinned at
    /// verification, not trusted from a mutable field.
    #[serde(default)]
    pub recovery_root: [u8; 32],
    /// The founder's signed inception. Together with `salt` it makes the trust
    /// root **verifiable offline**: the joiner checks `space` commits to this
    /// inception's device, that the inception validly incepts for `space`,
    /// and roots genesis on its `ActorId` — so a tampered anchor is detected, not
    /// silently forked (see [`crate::space::verify_founding`]).
    #[serde(default)]
    pub founder_inception: Option<crate::actor::SignedEvent>,
    /// An optional pre-authorization capability (Pattern A). Present ⇒ a joiner is
    /// auto-admitted on `join` (the seal happens without a manual `members
    /// approve`). Absent ⇒ the classic request→approve flow. The joiner echoes it
    /// in its signed `JoinRequest`.
    #[serde(default)]
    pub invite: Option<SignedInvite>,
    /// The host's direct socket addresses, for the **Isolated** network policy
    /// only (no relay, no discovery). Empty in a normal `Public`/`Local` ticket —
    /// there the ticket stays address-free and the relay mesh resolves the host
    /// from its id. Present, the joiner registers `{host, these addrs}` and dials the
    /// host directly on a LAN with no infrastructure.
    #[serde(default)]
    pub host_addrs: Vec<std::net::SocketAddr>,
}

impl SpaceTicket {
    /// The gossip topic this ticket joins (derived from the space id).
    pub fn topic(&self) -> Topic {
        topic_for_space(&self.space)
    }

    /// The `lait://` link form of this ticket, for humans/chat apps.
    pub fn link(&self) -> String {
        format!("lait://join/{self}")
    }

    fn to_bytes(&self) -> Vec<u8> {
        let mut out = vec![TICKET_VERSION];
        out.extend_from_slice(&postcard::to_stdvec(self).expect("a ticket always encodes"));
        out
    }
    fn from_bytes(bytes: &[u8]) -> Result<Self> {
        // The version is read and checked before one other byte is trusted.
        // Postcard is not self-describing, so a ticket from another epoch does
        // not fail to decode — it decodes into fields that look plausible and
        // are wrong. Refusing by version turns that into one legible sentence.
        let (&version, bytes) = bytes.split_first().context("that invite is empty")?;
        if version != TICKET_VERSION {
            anyhow::bail!(
                "that invite is from an older lait and this one cannot read it.\n\
                 ask whoever sent it for a fresh one with `lait invite`."
            );
        }
        // Same reason as the base32 step: postcard's own words ("Hit the end of
        // buffer, expected more data") describe our wire format, not the user's
        // mistake, and used to be printed under the good advice instead of it.
        let t: Self = postcard::from_bytes(bytes).map_err(|_| {
            anyhow::anyhow!(
                "that invite could not be read — it may be incomplete, or from an \
                 older lait.\n\
                 ask for a fresh one with `lait invite`."
            )
        })?;
        // A matching version byte is not proof on its own — one byte in 256
        // agrees by accident — so the space id shape stays as the second check.
        if !t.space.starts_with("ws_") {
            anyhow::bail!(
                "decode space ticket: not a valid space id (this invite may be from an older lait — ask for a fresh one)"
            );
        }
        Ok(t)
    }
}

impl fmt::Display for SpaceTicket {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut text = data_encoding::BASE32_NOPAD.encode(&self.to_bytes());
        text.make_ascii_lowercase();
        write!(f, "{text}")
    }
}

impl FromStr for SpaceTicket {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        // Accept a bare token or a `lait://join/<token>` link, and tolerate
        // stray whitespace/newlines a terminal may have wrapped in on copy.
        let s = s.trim();
        let token = s.strip_prefix("lait://join/").unwrap_or(s);
        let cleaned: String = token.chars().filter(|c| !c.is_whitespace()).collect();
        // Replace the decoder's error rather than wrapping it: `data-encoding`
        // explains itself in its own terms ("non-zero trailing bits at 3",
        // "invalid length at 18"), which says nothing to someone who pasted an
        // invite badly — and this is the first thing a new joiner ever runs. The
        // cause is dropped on purpose; base32 is an implementation detail of the
        // link, and the actionable part is entirely in the advice.
        let bytes = data_encoding::BASE32_NOPAD
            .decode(cleaned.to_ascii_uppercase().as_bytes())
            .map_err(|_| {
                anyhow::anyhow!(
                    "that invite link is not readable — it looks truncated or \
                     mistyped.\n\
                     copy the whole `lait://join/…` line (it is one long token), \
                     or ask for a fresh one with `lait invite`."
                )
            })?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host_key() -> DeviceId {
        crate::crypto::device_from_seed(&[7u8; 32])
    }

    /// A `SpaceTicket` exactly as the build before the transport cutover minted
    /// it: the sample below, postcard-encoded, with the host spelled in the
    /// network's own key type. Two obligations ride on it.
    ///
    /// The host was 32 raw bytes at offset 35 and must stay 32 raw bytes there:
    /// the identity did not change, so the wire must not grow. And the whole
    /// blob must now be *refused* — it carries no version byte, and the byte it
    /// starts with instead is the space id's length.
    const PRE_CUTOVER_TICKET: &str = concat!(
        "1d77735f3030303030303030303030303030303030303030303030303030",
        "0464656d6f",
        "ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c",
        "05616c696365",
        "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
    );
    /// Where the host key starts in that encoding: the space id and the display
    /// name, each with its length prefix.
    const HOST_OFFSET: usize = 35;

    fn pre_cutover_bytes() -> Vec<u8> {
        data_encoding::HEXLOWER
            .decode(PRE_CUTOVER_TICKET.as_bytes())
            .unwrap()
    }

    /// A bad invite is the most likely thing to go wrong on a new joiner's very
    /// first command, so its error is held to a higher bar: it must be about the
    /// invite, never about how we encode one.
    #[test]
    fn a_bad_invite_explains_itself_without_leaking_the_codec() {
        // Real shapes: a truncated link, an unencodable paste, and well-formed
        // base32 whose payload isn't a ticket — these produced, respectively,
        // "non-zero trailing bits at 3", "invalid length at 18", and "Hit the end
        // of buffer, expected more data".
        for bad in ["lait://join/zzzz", "not-a-real-invite!!", "aebagbaf"] {
            let e = bad
                .parse::<SpaceTicket>()
                .expect_err("must not parse")
                .to_string()
                // `{:#}`-style flattening is what the reporter prints, so check the
                // whole chain, not just the top.
                .to_lowercase();
            for leak in [
                "base32",
                "postcard",
                "trailing bits",
                "invalid length",
                "end of buffer",
                "serde",
            ] {
                assert!(
                    !e.contains(leak),
                    "invite error leaks the codec ({leak:?}) for input {bad:?}: {e}",
                );
            }
            assert!(
                e.contains("invite"),
                "invite error must name the invite for input {bad:?}: {e}",
            );
        }
    }

    fn sample() -> SpaceTicket {
        SpaceTicket {
            space: "ws_00000000000000000000000000".into(),
            name: "demo".into(),
            host: host_key(),
            host_nick: "alice".into(),
            salt: [0u8; 16],
            recovery_root: [0u8; 32],
            founder_inception: None,
            invite: None,
            host_addrs: vec![],
        }
    }

    #[test]
    fn ticket_roundtrips_through_base32() {
        let t = sample();
        let back: SpaceTicket = t.to_string().parse().unwrap();
        assert_eq!(back.space, "ws_00000000000000000000000000");
        assert_eq!(back.name, "demo");
        assert_eq!(back.host, host_key());
        assert_eq!(back.host_nick, "alice");
        assert_eq!(
            back.topic(),
            topic_for_space("ws_00000000000000000000000000")
        );
    }

    #[test]
    fn topic_is_a_pure_function_of_the_space_id() {
        // Same id → same topic; different ids → different topics. The display
        // name plays no part (renaming never re-topics).
        assert_eq!(topic_for_space("ws_A"), topic_for_space("ws_A"));
        assert_ne!(topic_for_space("ws_A"), topic_for_space("ws_B"));
        let mut a = sample();
        a.name = "renamed".into();
        assert_eq!(a.topic(), sample().topic());
    }

    #[test]
    fn garbage_ticket_errors_with_the_older_lait_hint() {
        // A structurally-valid base32 blob that isn't a new-format ticket must
        // fail with the "older lait" hint, not decode into garbage fields.
        let blob = data_encoding::BASE32_NOPAD.encode(b"\x04demo\x00\x00\x00");
        let err = blob.parse::<SpaceTicket>().unwrap_err();
        assert!(
            format!("{err:#}").contains("older lait"),
            "error should carry the stale-invite hint, got: {err:#}"
        );
    }

    /// The host field is 32 raw bytes and stays exactly where it was. A round
    /// trip through the current code cannot show this — it would agree with
    /// itself about any encoding — so the comparison is against bytes an
    /// earlier build produced.
    #[test]
    fn the_ticket_host_is_still_thirty_two_raw_bytes() {
        let legacy = pre_cutover_bytes();
        let legacy_host = &legacy[HOST_OFFSET..HOST_OFFSET + 32];
        assert_eq!(
            legacy_host,
            host_key().key_bytes().unwrap(),
            "the fixture's host must be the key the sample names"
        );

        let minted = sample().to_bytes();
        // One version byte ahead of where it used to sit, and not a byte wider.
        assert_eq!(&minted[1 + HOST_OFFSET..1 + HOST_OFFSET + 32], legacy_host);
        assert_eq!(
            minted.len(),
            legacy.len() + 1,
            "the only growth in the ticket is its version byte"
        );
    }

    /// An invite minted before the flag day is refused by version, and says so
    /// in a sentence its holder can act on — never decoded into fields that
    /// happen to parse.
    #[test]
    fn a_pre_flag_day_invite_is_refused_by_version() {
        let mut text = data_encoding::BASE32_NOPAD.encode(&pre_cutover_bytes());
        text.make_ascii_lowercase();
        let err = format!("{:#}", text.parse::<SpaceTicket>().unwrap_err());
        assert!(
            err.contains("older lait"),
            "the refusal must name the cause: {err}"
        );
        assert!(
            err.contains("lait invite"),
            "the refusal must name the way out: {err}"
        );
    }

    #[test]
    fn ticket_is_a_short_one_liner() {
        let s = sample().to_string();
        // Since the lait/actor/1 cutover the ticket also carries the founding
        // *actor* id (a self-certifying identity, ~68 chars) so a joiner roots
        // its genesis on the founder's identity rather than a device key. That
        // is a real size cost, but the ticket stays a single copy-paste line.
        assert!(
            s.len() < 260,
            "ticket should be a short one-liner, got {} chars",
            s.len()
        );
    }

    #[test]
    fn parses_lait_link_form() {
        let t = sample();
        let link = t.link();
        assert!(link.starts_with("lait://join/"));
        let back: SpaceTicket = link.parse().unwrap();
        assert_eq!(back.host, host_key());
    }

    #[test]
    fn tolerates_whitespace_from_paste() {
        let s = sample().to_string();
        // Simulate a terminal wrapping the token across lines on copy.
        let mangled = format!("  {}\n   {}  ", &s[..s.len() / 2], &s[s.len() / 2..]);
        let back: SpaceTicket = mangled.parse().unwrap();
        assert_eq!(back.host, host_key());
    }

    #[test]
    fn signed_invite_roundtrips_and_detects_tampering() {
        let seed = [9u8; 32];
        let grant = InviteGrant::mint("ws_1".into(), 1_000, 3_600, true);
        let signed = SignedInvite::sign(&seed, &grant).unwrap();
        let (issuer, back) = signed.verify().expect("valid signature verifies");
        assert_eq!(issuer, crate::crypto::device_from_seed(&seed));
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
        let seed = [3u8; 32];
        let grant = InviteGrant::mint("ws_00000000000000000000000000".into(), 0, 604_800, true);
        let mut t = sample();
        t.invite = Some(SignedInvite::sign(&seed, &grant).unwrap());
        let back: SpaceTicket = t.to_string().parse().unwrap();
        let (issuer, g) = back
            .invite
            .expect("invite survives roundtrip")
            .verify()
            .unwrap();
        assert_eq!(issuer, crate::crypto::device_from_seed(&seed));
        assert_eq!(g, grant);
    }
}
