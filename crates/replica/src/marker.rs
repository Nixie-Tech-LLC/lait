//! The Replica store marker (`lait/replica/1`).
//!
//! The first thing opened in a Replica store. It distinguishes — before any
//! other file is trusted — a foreign directory, an unsupported store version, a
//! corrupt marker, and a valid store, so recreation guidance is exact and never
//! deletes or overwrites automatically. Integrity of the referenced material and
//! the lock are separate, later checks; this is only the 4 KiB header.
//!
//! The on-disk layout front-loads an **independently parseable** fixed prefix —
//! `MAGIC || version` — ahead of the postcard body, so a truncated or corrupt
//! LAIT marker is told apart from a foreign directory: magic mismatch is
//! `NotAReplicaStore`, a wrong version is `UnsupportedStoreVersion`, and a body
//! that will not decode or fails its checksum is `CorruptStoreMarker`.

use lait_kernel::ids::SpaceId;
use serde::{Deserialize, Serialize};

/// The store magic (fixed-length, matched byte-for-byte before anything else).
pub const STORE_MAGIC: &[u8] = b"lait/replica/1";
/// The current store version.
pub const STORE_VERSION: u8 = 1;
/// Maximum marker header size.
pub const MAX_MARKER: usize = 4 * 1024;
/// The fixed rendered-SpaceId length.
pub const SPACE_ID_LEN: usize = 29;

/// The postcard body carried after the `MAGIC || version` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MarkerBody {
    space: [u8; SPACE_ID_LEN],
    checksum: [u8; 32],
}

/// The store marker header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreMarkerV1 {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    /// BLAKE3 over `MAGIC || [version] || space`.
    pub checksum: [u8; 32],
}

/// How a marker failed to identify a valid store. The last two are surfaced by
/// higher store-open logic, not the marker decoder, but share this taxonomy so
/// callers render one consistent recreation message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MarkerError {
    /// The bytes are not a Replica store marker at all (foreign directory): the
    /// fixed magic prefix does not match.
    NotAReplicaStore,
    /// A Replica marker (magic matched) of an unsupported version.
    UnsupportedStoreVersion { found: u8 },
    /// A Replica marker whose body did not decode or failed its checksum.
    CorruptStoreMarker,
    /// The store's referenced material failed full integrity validation.
    ReplicaIntegrityFailure,
    /// The store is locked by a live Station.
    ReplicaLocked,
}

impl std::fmt::Display for MarkerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for MarkerError {}

fn checksum(version: u8, space: &[u8; SPACE_ID_LEN]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(STORE_MAGIC);
    h.update(&[version]);
    h.update(space);
    *h.finalize().as_bytes()
}

impl StoreMarkerV1 {
    /// Build a marker for a Space's store.
    pub fn new(space: &SpaceId) -> Option<Self> {
        let space = <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()?;
        Some(Self {
            version: STORE_VERSION,
            space,
            checksum: checksum(STORE_VERSION, &space),
        })
    }

    /// The canonical on-disk bytes: `MAGIC || version || postcard(body)`.
    pub fn encode(&self) -> Vec<u8> {
        let body = postcard::to_stdvec(&MarkerBody {
            space: self.space,
            checksum: self.checksum,
        })
        .expect("postcard marker body");
        let mut out = Vec::with_capacity(STORE_MAGIC.len() + 1 + body.len());
        out.extend_from_slice(STORE_MAGIC);
        out.push(self.version);
        out.extend_from_slice(&body);
        out
    }

    /// Classify raw marker bytes into an exact cause. The fixed prefix is matched
    /// before the postcard body is trusted, so foreign / unsupported / corrupt
    /// are distinguished.
    pub fn classify(bytes: &[u8]) -> Result<Self, MarkerError> {
        if bytes.len() > MAX_MARKER {
            return Err(MarkerError::CorruptStoreMarker);
        }
        // Magic first: foreign vs ours, from a fixed independently-parsed prefix.
        let prefix_len = STORE_MAGIC.len() + 1;
        if bytes.len() < prefix_len || &bytes[..STORE_MAGIC.len()] != STORE_MAGIC {
            return Err(MarkerError::NotAReplicaStore);
        }
        // Version: ours, but maybe unsupported.
        let version = bytes[STORE_MAGIC.len()];
        if version != STORE_VERSION {
            return Err(MarkerError::UnsupportedStoreVersion { found: version });
        }
        // Body: ours + supported, but maybe corrupt.
        let body: MarkerBody = postcard::from_bytes(&bytes[prefix_len..])
            .map_err(|_| MarkerError::CorruptStoreMarker)?;
        if body.checksum != checksum(version, &body.space) {
            return Err(MarkerError::CorruptStoreMarker);
        }
        Ok(Self {
            version,
            space: body.space,
            checksum: body.checksum,
        })
    }

    /// The Space this store holds, if the marker is valid.
    pub fn space(&self) -> Option<SpaceId> {
        std::str::from_utf8(&self.space)
            .ok()
            .and_then(SpaceId::parse)
    }
}
