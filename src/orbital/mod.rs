//! The product's adoption of the orbital lifecycle — **mechanics only**.
//!
//! It fixes where the product keeps its orbital store, composes a [`Runtime`]
//! from parts supplied by the caller, and (C5) supplies the mechanics
//! composition — authority view/source, key source, and authority
//! incorporation — over the Space's signed membership material
//! ([`mechanics::OrbitalMechanics`]).
//! It defines **no World**: per the program's settled decisions (O13/O23), no
//! consumer-specific World becomes first-party inside LAIT, and the current
//! Issues behavior adopts the public API as an *adapter over the existing
//! product semantics* — not as a new product-owned World schema. The daemon
//! integration supplies that adapter's registration when it routes the control
//! surface onto Sessions; independent Worlds are exercised by the conformance
//! and adoption tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use replica::BodyKeySource;
use runtime::{AuthorityView, Runtime, WorldRegistry};

/// Where the product keeps its orbital stores, under the lait home. Kept beside
/// (not inside) the existing daemon state so neither can corrupt the other.
pub fn orbital_store_root(home: &Path) -> PathBuf {
    home.join("orbital")
}

/// A typed refusal for a pre-orbital home (C5: clean break, no migration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedStoreVersion {
    /// Where the legacy store was detected.
    pub legacy_repo: std::path::PathBuf,
    /// Human recreation guidance.
    pub guidance: String,
}

impl std::fmt::Display for UnsupportedStoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported store version at {}: {}",
            self.legacy_repo.display(),
            self.guidance
        )
    }
}
impl std::error::Error for UnsupportedStoreVersion {}

/// Detect a pre-orbital (v0.x) space store under `home`. The orbital
/// composition root must NEVER create a fresh Orbit beside or over one.
pub fn detect_legacy_home(home: &Path) -> Option<UnsupportedStoreVersion> {
    let repo = home.join("repo");
    let legacy = repo.join("genesis.json").exists()
        || repo.join("catalog.loro").exists()
        || repo.join("membership.loro").exists();
    legacy.then(|| UnsupportedStoreVersion {
        legacy_repo: repo,
        guidance: "this home holds a pre-orbital space store; the orbital                    formats are a clean break with no migration. Export what                    you need with a v0.x binary, then remove the old store                    (or choose a fresh home) and re-create the space."
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    })
}

/// Compose the product's orbital [`Runtime`]: the store root convention plus a
/// caller-supplied World registry, mechanics authority view, and mechanics-
/// owned Body key source. The product holds no privileged path — this is the
/// same `Runtime::open` any consumer calls, at the product's store location.
/// Refuses (typed, with recreation guidance) when `home` holds a pre-orbital
/// store: a fresh Orbit is never created beside or over a legacy home.
pub fn open_orbital_runtime(
    home: &Path,
    registry: WorldRegistry,
    authority: Arc<dyn AuthorityView>,
    keys: Arc<dyn BodyKeySource>,
) -> Result<Runtime, UnsupportedStoreVersion> {
    if let Some(err) = detect_legacy_home(home) {
        return Err(err);
    }
    Ok(Runtime::open(
        orbital_store_root(home),
        registry,
        authority,
        keys,
    ))
}

pub mod mechanics;

pub use mechanics::{AuthorityRecord, OrbitalMechanics};

/// A random 16-byte value (salts, epoch ids, nonces).
pub(crate) fn rand16() -> [u8; 16] {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("getrandom");
    raw
}
