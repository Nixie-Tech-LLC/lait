//! The frozen collaborative-operation algebra (S1a).
//!
//! This module fixes the LAIT Body operation algebra's **declared semantics** and
//! **bounds** so an implementation (S5, through Fabric) and an independent World
//! author agree on behavior. It is LAIT semantics, not a copy of the CRDT engine's API.
//!
//! # Paths
//!
//! A collaborative operation addresses a location by a `path`: a `/`-separated
//! sequence of 1–64 segments, each 1–64 bytes of `[a-z0-9_]`. The empty path
//! addresses the Body root. Paths are compared byte-exact; there is no Unicode
//! normalization and no implicit array indexing in the path (list positions are
//! carried in operation fields, not the path).
//!
//! # Stable element identity
//!
//! Ordered-list and set elements have **stable element ids** assigned by Fabric
//! at insert time and echoed to the World in Projections. `ListRemove`/`ListMove`
//! name an element by that id, never by index, so a concurrent insert cannot
//! shift the target of a remove. `index` in `ListInsert`/`ListMove` is a
//! placement coordinate resolved against the committed order at apply time.
//!
//! # Concurrency winners
//!
//! - Registers and map entries are last-writer-wins by the semantic transaction
//!   order Fabric commits; concurrent sets to the same path both survive as
//!   conflicting versions only until the next observed commit resolves them.
//! - Ordered lists converge by stable-id insertion order (no lost inserts;
//!   concurrent inserts at the same index interleave deterministically).
//! - Sets are add-wins; a concurrent add and remove of the same value keeps it.
//! - Counters sum all increments (commutative).
//! - Text splices converge by the CRDT's per-character identity; overlapping
//!   splices never corrupt, though they may interleave.
//!
//! # Idempotence
//!
//! Applying the *same* committed transaction twice is a no-op (Replica advances
//! its frontier only once per transaction id). Re-submitting an equivalent
//! intent under a **new** request id is a new transaction, not idempotent.
//!
//! # Type conflicts
//!
//! A path bound to one collaborative type (register/map/list/text/set/counter)
//! cannot be reused as another. An operation whose type disagrees with the
//! established type at a path is a `TypeConflict` and commits nothing.
//!
//! # Limits (frozen)
//!
//! See the constants below. Exceeding any bound rejects the whole transaction
//! with a limit error and commits nothing.
//!
//! # Schema upgrades
//!
//! A schema version declares `readable_predecessors` (strictly older, distinct
//! versions). Reading an older Body under a newer supported version is allowed;
//! writing always uses the schema's own version. Downgrade is never implied.

/// Maximum number of `/`-separated segments in a path.
pub const MAX_PATH_SEGMENTS: usize = 64;
/// Maximum bytes in a single path segment.
pub const MAX_PATH_SEGMENT_BYTES: usize = 64;
/// Maximum bytes in a single map entry key.
pub const MAX_MAP_KEY_BYTES: usize = 256;
/// Maximum bytes in a single register/list/set value payload.
pub const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Maximum UTF-8 bytes inserted by one text splice.
pub const MAX_TEXT_INSERT_BYTES: usize = 64 * 1024;
/// Maximum number of operations staged in one Body transaction.
pub const MAX_OPS_PER_TRANSACTION: usize = 4096;

/// Whether a path is well-formed under the frozen grammar. The empty string is
/// the valid root path.
pub fn valid_path(path: &str) -> bool {
    if path.is_empty() {
        return true;
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() > MAX_PATH_SEGMENTS {
        return false;
    }
    segments.iter().all(|seg| {
        !seg.is_empty()
            && seg.len() <= MAX_PATH_SEGMENT_BYTES
            && seg
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_well_formed_paths_accepted() {
        assert!(valid_path(""), "empty path is the root");
        assert!(valid_path("title"));
        assert!(valid_path("comments/c_1/body"));
        assert!(valid_path("a1_b2/c3"));
    }

    #[test]
    fn malformed_paths_rejected() {
        assert!(!valid_path("/leading"), "empty leading segment");
        assert!(!valid_path("trailing/"), "empty trailing segment");
        assert!(!valid_path("a//b"), "empty middle segment");
        assert!(!valid_path("Upper"), "uppercase not allowed");
        assert!(!valid_path("has space"));
        assert!(!valid_path("dot.notation"), "segments split on / only");
        assert!(!valid_path(&"x".repeat(MAX_PATH_SEGMENT_BYTES + 1)));
        let too_many = vec!["a"; MAX_PATH_SEGMENTS + 1].join("/");
        assert!(!valid_path(&too_many));
    }

    #[test]
    fn limits_are_stable() {
        // Pin the frozen bounds so a change is a deliberate, reviewed edit.
        assert_eq!(MAX_PATH_SEGMENTS, 64);
        assert_eq!(MAX_PATH_SEGMENT_BYTES, 64);
        assert_eq!(MAX_MAP_KEY_BYTES, 256);
        assert_eq!(MAX_VALUE_BYTES, 64 * 1024);
        assert_eq!(MAX_TEXT_INSERT_BYTES, 64 * 1024);
        assert_eq!(MAX_OPS_PER_TRANSACTION, 4096);
    }
}
