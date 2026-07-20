//! Identifiers. Every id is exactly one kind of thing with one
//! stability guarantee. App-minted ids are `<prefix>_<ULID>`: a ULID is a
//! 128-bit, lexicographically-sortable, time-ordered identifier rendered in
//! Crockford base32 (26 chars), so ids sort by creation time and never collide
//! in practice. These are **content-independent** and **not** Loro `PeerId`s:
//! a `DocId` is minted once and is permanent, while a Loro `PeerId`
//! is an internal, per-session `u64`.
//!
//! `DeviceId` is an ed25519 public key — the same bytes as the iroh `EndpointId`.
//! Since the `lait/actor/1` cutover it identifies a **device**, not a person: a
//! member is an [`ActorId`] over a set of device keys, so one human holds many
//! `DeviceId`s and rotates them under a stable identity. Read a `DeviceId` as "which
//! device", an `ActorId` as "who".

use std::fmt;

use serde::{Deserialize, Serialize};

/// A monotonic-ish clock + randomness source for minting ULIDs. Injected so
/// tests are deterministic and never flake on wall-clock/RNG (per the plan's
/// "inject clocks/seeds" rule).
pub trait UlidSource {
    /// Milliseconds since the Unix epoch.
    fn now_ms(&self) -> u64;
    /// 80 bits of randomness for the ULID's entropy section.
    fn rand80(&self) -> u128;
}

/// Production source: real wall clock + `getrandom`.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemUlidSource;

impl UlidSource for SystemUlidSource {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0)
    }
    fn rand80(&self) -> u128 {
        let mut buf = [0u8; 10];
        getrandom::fill(&mut buf).expect("getrandom");
        let mut v: u128 = 0;
        for b in buf {
            v = (v << 8) | b as u128;
        }
        v
    }
}

const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHIJKLMNOPQRSTUV";

/// Render a 128-bit value as a 26-char Crockford base32 ULID string.
fn encode_ulid(value: u128) -> String {
    // 128 bits → 26 base32 chars (the top char encodes only 2 bits).
    let mut out = [0u8; 26];
    let mut v = value;
    for i in (0..26).rev() {
        out[i] = CROCKFORD[(v & 0x1f) as usize];
        v >>= 5;
    }
    String::from_utf8(out.to_vec()).expect("ascii")
}

/// Mint a fresh ULID string from a source: 48-bit ms timestamp + 80-bit random.
pub fn mint_ulid(src: &dyn UlidSource) -> String {
    let ts = (src.now_ms() as u128) & ((1u128 << 48) - 1);
    let rand = src.rand80() & ((1u128 << 80) - 1);
    encode_ulid((ts << 80) | rand)
}

/// Declare a newtype id `$name` with textual prefix `$prefix` (e.g. `iss_`).
macro_rules! prefixed_id {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// The textual prefix these ids carry (including the underscore).
            pub const PREFIX: &'static str = $prefix;

            /// Mint a fresh id: `<prefix><ULID>`.
            pub fn mint(src: &dyn UlidSource) -> Self {
                Self(format!("{}{}", $prefix, mint_ulid(src)))
            }

            /// Wrap an existing string, validating the prefix + ULID shape.
            pub fn parse(s: &str) -> Option<Self> {
                let rest = s.strip_prefix($prefix)?;
                if rest.len() == 26 && rest.bytes().all(|b| CROCKFORD.contains(&b.to_ascii_uppercase())) {
                    Some(Self(s.to_string()))
                } else {
                    None
                }
            }

            /// The full id string, prefix included.
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// A short, git-style prefix of the id (prefix + first `n` ULID
            /// chars) — the canonical human handle. `n` counts
            /// ULID characters after the textual prefix.
            pub fn short(&self, n: usize) -> String {
                let ulid = &self.0[$prefix.len()..];
                let take = n.min(ulid.len());
                format!("{}{}", $prefix, &ulid[..take])
            }

            /// The bare ULID portion (no textual prefix).
            pub fn ulid(&self) -> &str {
                &self.0[$prefix.len()..]
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<$name> for String {
            fn from(v: $name) -> String {
                v.0
            }
        }
    };
}

prefixed_id!(
    /// Space id — minted at `space init` and committed by genesis.
    SpaceId, "ws_"
);

impl SpaceId {
    /// Derive a **self-certifying** space id from a 16-byte digest that
    /// commits to the founding device + salt (`lait/space/1`): `ws_<crockford128>`.
    /// The id is bound to its trust root rather than random, so a joiner can
    /// verify a ticket's founder anchor against the id (see [`crate::space`]).
    pub fn from_digest(digest: [u8; 16]) -> Self {
        Self(format!(
            "{}{}",
            Self::PREFIX,
            encode_ulid(u128::from_be_bytes(digest))
        ))
    }
}
prefixed_id!(
    /// Issue document id — app-minted, content-independent, the key in
    /// `Catalog.docs`, the filename in git, and the routing key on the wire.
    ///
    /// ```
    /// use lait_kernel::ids::{DocId, SystemUlidSource};
    /// let id = DocId::mint(&SystemUlidSource);
    /// assert!(id.as_str().starts_with("iss_"));
    /// // a short, git-style handle is a genuine prefix of the full id
    /// let short = id.short(7);
    /// assert!(id.as_str().starts_with(&short));
    /// // round-trips through parse()
    /// assert_eq!(DocId::parse(id.as_str()), Some(id));
    /// ```
    DocId, "iss_"
);
prefixed_id!(
    /// Project id — key in `Catalog.projects`.
    ProjectId, "prj_"
);
prefixed_id!(
    /// Label id — key in `Catalog.labels`.
    LabelId, "lbl_"
);

/// A **device** id — an ed25519 public key, hex-encoded (64 lowercase hex
/// chars), the same bytes as the iroh `EndpointId`. Kept as a validated string
/// so Layer B can carry it without depending on iroh types.
///
/// Not a member id: membership is keyed on [`ActorId`], and a device speaks
/// *for* an actor only while the actor's key-event log binds it. Use this for
/// transport peers, signature authors, and `committedBy` stamps — never to
/// answer "who did this".
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DeviceId(String);

impl DeviceId {
    /// Parse a 64-char lowercase-hex ed25519 public key.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(Self(s.to_ascii_lowercase()))
        } else {
            None
        }
    }

    /// Wrap a key string that is already known valid (e.g. an iroh
    /// `EndpointId`, 64-hex by construction). **Validates nothing** — the
    /// caller vouches for the shape.
    ///
    /// Only use this where the value's provenance guarantees a device key. It
    /// is not a parser: reaching for it on a string read back out of a document
    /// launders whatever is there into a `DeviceId`, and post-cutover those
    /// strings are often `ActorId`s — a type lie that then mis-attributes
    /// silently downstream. Use [`DeviceId::parse`] there instead.
    pub fn from_key_string(s: String) -> Self {
        Self(s)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A short, display-friendly prefix (first 8 hex chars).
    pub fn short(&self) -> String {
        self.0.chars().take(8).collect()
    }
}

impl fmt::Display for DeviceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An actor id — the **self-certifying** identity of a member (`lait/actor/1`):
/// `act_` + the blake3 content-address of the actor's `Incept` event, 64
/// lowercase hex chars. An actor is a *set of device keys under one
/// self-managed key-event log*; a `DeviceId` (device key) signs, an `ActorId`
/// *is someone*. Not an ed25519 key — it never verifies a signature — and
/// content-independent of any device key, so devices rotate under a stable
/// identity. Minted per-space (the `Incept` payload binds the space id
/// + a nonce), so the same human is unlinkable across spaces by default.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ActorId(String);

impl ActorId {
    /// The textual prefix these ids carry (including the underscore).
    pub const PREFIX: &'static str = "act_";

    /// Parse `act_` + 64 lowercase hex chars.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        let rest = s.strip_prefix(Self::PREFIX)?;
        if rest.len() == 64 && rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            Some(Self(format!(
                "{}{}",
                Self::PREFIX,
                rest.to_ascii_lowercase()
            )))
        } else {
            None
        }
    }

    /// Wrap the content-address of an `Incept` event (a 64-hex blake3 string,
    /// as produced by `SignedNode::hash`). The caller vouches the hash shape.
    pub fn from_incept_hash(hash: &str) -> Self {
        Self(format!("{}{}", Self::PREFIX, hash))
    }

    /// The bare incept-event hash (no textual prefix).
    pub fn incept_hash(&self) -> &str {
        &self.0[Self::PREFIX.len()..]
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// A short, display-friendly handle: `act_` + first 8 hash chars.
    pub fn short(&self) -> String {
        self.0.chars().take(Self::PREFIX.len() + 8).collect()
    }
}

impl fmt::Display for ActorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A fully deterministic source: fixed clock, counter entropy.
    struct FakeSource {
        ms: Cell<u64>,
        ctr: Cell<u128>,
    }
    impl FakeSource {
        fn new(ms: u64) -> Self {
            Self {
                ms: Cell::new(ms),
                ctr: Cell::new(0),
            }
        }
    }
    impl UlidSource for FakeSource {
        fn now_ms(&self) -> u64 {
            self.ms.get()
        }
        fn rand80(&self) -> u128 {
            let v = self.ctr.get();
            self.ctr.set(v + 1);
            v
        }
    }

    #[test]
    fn ulid_is_26_crockford_chars() {
        let s = FakeSource::new(1_700_000_000_000);
        let u = mint_ulid(&s);
        assert_eq!(u.len(), 26, "ULID is 26 chars");
        assert!(
            u.bytes().all(|b| CROCKFORD.contains(&b)),
            "crockford alphabet"
        );
    }

    #[test]
    fn docid_roundtrips_and_validates() {
        let s = FakeSource::new(1_700_000_000_000);
        let id = DocId::mint(&s);
        assert!(id.as_str().starts_with("iss_"));
        assert_eq!(DocId::parse(id.as_str()), Some(id.clone()));
        assert_eq!(DocId::parse("iss_short"), None, "bad ULID length rejected");
        assert_eq!(
            DocId::parse("prj_00000000000000000000000000"),
            None,
            "wrong prefix rejected"
        );
    }

    #[test]
    fn ulids_sort_by_time() {
        // Two ids minted at different times sort by time (ULID property), which
        // is what lets the Done view order by creation without extra state.
        let early = FakeSource::new(1_000);
        let late = FakeSource::new(2_000);
        let a = DocId::mint(&early);
        let b = DocId::mint(&late);
        assert!(a < b, "earlier ULID sorts before later: {a} !< {b}");
    }

    #[test]
    fn short_handle_is_prefix_plus_n() {
        let s = FakeSource::new(1_700_000_000_000);
        let id = DocId::mint(&s);
        let short = id.short(3);
        assert!(short.starts_with("iss_"));
        assert_eq!(short.len(), "iss_".len() + 3);
        assert!(
            id.as_str().starts_with(&short),
            "short is a genuine prefix of the full id"
        );
    }

    #[test]
    fn device_id_validates_ed25519_hex() {
        let key = "a".repeat(64);
        assert!(DeviceId::parse(&key).is_some());
        assert!(DeviceId::parse("tooshort").is_none());
        assert!(
            DeviceId::parse(&"g".repeat(64)).is_none(),
            "non-hex rejected"
        );
        assert_eq!(DeviceId::parse(&key).unwrap().short().len(), 8);
    }
}
