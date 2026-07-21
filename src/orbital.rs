//! The product's adoption of the orbital lifecycle — **mechanics only**.
//!
//! This module is deliberately thin: it fixes where the product keeps its
//! orbital store and composes a [`Runtime`] from parts supplied by the caller.
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

/// Compose the product's orbital [`Runtime`]: the store root convention plus a
/// caller-supplied World registry, mechanics authority view, and mechanics-
/// owned Body key source. The product holds no privileged path — this is the
/// same `Runtime::open` any consumer calls, at the product's store location.
pub fn open_orbital_runtime(
    home: &Path,
    registry: WorldRegistry,
    authority: Arc<dyn AuthorityView>,
    keys: Arc<dyn BodyKeySource>,
) -> Runtime {
    Runtime::open(orbital_store_root(home), registry, authority, keys)
}
