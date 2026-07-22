//! Body-domain identifiers. These are bounded strong newtypes with canonical
//! byte encodings; comparison uses canonical bytes, never display strings or
//! Unicode normalization. They enter persisted/signed material in S5 as the only
//! accepted Body/store format.
//!
//! - [`WorldId`] — 3–63 lowercase ASCII bytes in reverse-domain form.
//! - [`SchemaId`] / [`EncodingId`] — 1–63 lowercase ASCII `[a-z0-9][a-z0-9._-]*`.
//! - [`BodyId`] — 128 CSPRNG bits, lowercase unpadded base32; Runtime mints it,
//!   World code cannot choose the randomness.
//! - [`BodyKey`] — `{ world, body }`, the durable addressable key of a Body.

use serde::{Deserialize, Serialize};

/// Lowercase-only, unpadded RFC 4648 base32 for [`BodyId`] rendering. The
/// standard `data_encoding::BASE32_NOPAD` is uppercase; we lowercase the
/// alphabet so Body ids are all-lowercase like every other LAIT id.
fn base32_nopad_lower() -> data_encoding::Encoding {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.encoding().expect("valid base32 spec")
}

/// A World identity — a stable namespaced identifier in **reverse-domain form**
/// (e.g. `com.example.issues`), 3–63 lowercase ASCII bytes. Reverse-domain form
/// means dot-separated labels, each a nonempty `[a-z0-9-]` run that neither
/// starts nor ends with `-`, and at least two labels (one dot).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct WorldId(String);

impl WorldId {
    /// Validate and wrap a World id in canonical reverse-domain form.
    pub fn parse(s: &str) -> Option<Self> {
        let bytes = s.as_bytes();
        if bytes.len() < 3 || bytes.len() > 63 {
            return None;
        }
        let labels: Vec<&str> = s.split('.').collect();
        if labels.len() < 2 {
            return None;
        }
        for label in &labels {
            if label.is_empty() {
                return None;
            }
            let lb = label.as_bytes();
            if lb[0] == b'-' || lb[lb.len() - 1] == b'-' {
                return None;
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return None;
            }
        }
        Some(Self(s.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The canonical comparison bytes.
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for WorldId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Validate the shared `SchemaId`/`EncodingId` grammar: 1–63 lowercase ASCII
/// bytes matching `[a-z0-9][a-z0-9._-]*`.
fn valid_schema_grammar(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 63 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b.iter().all(|&c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'_' || c == b'-'
    })
}

/// A schema identity — 1–63 lowercase ASCII `[a-z0-9][a-z0-9._-]*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SchemaId(String);

impl SchemaId {
    pub fn parse(s: &str) -> Option<Self> {
        valid_schema_grammar(s).then(|| Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for SchemaId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// An encoding identity — the same grammar as [`SchemaId`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EncodingId(String);

impl EncodingId {
    pub fn parse(s: &str) -> Option<Self> {
        valid_schema_grammar(s).then(|| Self(s.to_string()))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl std::fmt::Display for EncodingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// A Body identity — 128 CSPRNG bits, rendered lowercase unpadded base32 (26
/// chars). Runtime mints it from the OS CSPRNG; **World code cannot choose the
/// randomness**. Stored as the canonical 16 raw bytes so comparison is over
/// bytes, not the display string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BodyId([u8; 16]);

impl BodyId {
    /// Mint a fresh Body id from 128 bits of OS CSPRNG entropy.
    pub fn mint() -> Self {
        let mut raw = [0u8; 16];
        getrandom::fill(&mut raw).expect("getrandom");
        Self(raw)
    }

    /// Wrap the canonical 16 raw bytes.
    pub fn from_bytes(raw: [u8; 16]) -> Self {
        Self(raw)
    }

    /// The canonical 16 raw bytes.
    pub fn as_bytes(&self) -> [u8; 16] {
        self.0
    }

    /// Parse the lowercase unpadded-base32 rendering back to canonical bytes.
    pub fn parse(s: &str) -> Option<Self> {
        let raw = base32_nopad_lower().decode(s.as_bytes()).ok()?;
        <[u8; 16]>::try_from(raw.as_slice()).ok().map(Self)
    }

    /// The lowercase unpadded-base32 rendering (26 chars).
    pub fn render(&self) -> String {
        base32_nopad_lower().encode(&self.0)
    }
}

impl std::fmt::Display for BodyId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// The durable addressable key of a Body: which World, which Body. Ordering is
/// `(world, body)` over canonical bytes — the ordering S5 manifests require.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct BodyKey {
    pub world: WorldId,
    pub body: BodyId,
}

impl BodyKey {
    pub fn new(world: WorldId, body: BodyId) -> Self {
        Self { world, body }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn world_id_accepts_reverse_domain_and_rejects_malformed() {
        assert!(WorldId::parse("com.example.issues").is_some());
        assert!(WorldId::parse("a.b").is_some());
        // too short / no dot / empty label / bad chars / edge hyphen / too long
        assert!(WorldId::parse("ab").is_none(), "no dot");
        assert!(WorldId::parse("noseparator").is_none());
        assert!(WorldId::parse("a..b").is_none(), "empty label");
        assert!(WorldId::parse("A.B").is_none(), "uppercase rejected");
        assert!(WorldId::parse("a.-b").is_none(), "leading hyphen in label");
        assert!(WorldId::parse("a.b-").is_none(), "trailing hyphen in label");
        assert!(WorldId::parse("a.b_c").is_none(), "underscore not allowed");
        assert!(WorldId::parse(&format!("a.{}", "x".repeat(63))).is_none());
    }

    #[test]
    fn schema_and_encoding_grammar() {
        for good in ["issue", "issue.v1", "a", "x-y_z.0", "0abc"] {
            assert!(SchemaId::parse(good).is_some(), "{good} should parse");
            assert!(EncodingId::parse(good).is_some());
        }
        for bad in ["", ".leading", "_leading", "-leading", "UP", "with space"] {
            assert!(SchemaId::parse(bad).is_none(), "{bad} should reject");
            assert!(EncodingId::parse(bad).is_none());
        }
        assert!(SchemaId::parse(&"a".repeat(64)).is_none(), "over 63 bytes");
    }

    #[test]
    fn body_id_is_128_bits_and_roundtrips_lowercase_base32() {
        let id = BodyId::mint();
        let s = id.render();
        assert_eq!(s.len(), 26, "128 bits → 26 base32 chars");
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
            "lowercase base32 alphabet"
        );
        assert_eq!(BodyId::parse(&s), Some(id));
        // Two mints differ with overwhelming probability.
        assert_ne!(BodyId::mint(), BodyId::mint());
    }

    #[test]
    fn body_key_orders_by_world_then_body() {
        let w1 = WorldId::parse("com.a").unwrap();
        let w2 = WorldId::parse("com.b").unwrap();
        let b = BodyId::from_bytes([0u8; 16]);
        let k1 = BodyKey::new(w1, b.clone());
        let k2 = BodyKey::new(w2, b);
        assert!(k1 < k2, "world is the primary sort key");
    }
}
