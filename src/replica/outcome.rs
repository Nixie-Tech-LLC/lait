//! What a replica operation returns: a value, and whatever it made dirty.
//!
//! **The invariant this type exists to hold.** A mutation validates fully before
//! it commits anything, so a failure touches no document and produces no dirty
//! set — nothing rings the doorbell, and an optimistic client's rollback is
//! race-free. Enforced structurally rather than by convention: a dirty set can
//! only be reached through the `Ok` side of a [`Result`], so there is no way to
//! spell "this failed, and here is what changed."
//!
//! The fields are private and the constructors are the only way in, so a caller
//! must say which it means — [`unchanged`](Outcome::unchanged) for reads and
//! no-op writes, [`committed`](Outcome::committed) for a mutation that landed.
//! `Option` is preserved rather than collapsed to an empty set because the
//! daemon distinguishes them: `None` means nothing happened, while an empty
//! `Some` means a commit landed whose effects no subscriber needs.

use super::DirtySet;

/// A successful operation's value plus its dirty set, if it committed one.
#[derive(Debug)]
pub struct Outcome<T> {
    value: T,
    dirty: Option<DirtySet>,
}

impl<T> Outcome<T> {
    /// A result that changed no document: a read, or a write that resolved to a
    /// no-op. No doorbell rings for it.
    pub fn unchanged(value: T) -> Self {
        Self { value, dirty: None }
    }

    /// A result whose commit landed, carrying what it touched.
    pub fn committed(value: T, dirty: DirtySet) -> Self {
        Self {
            value,
            dirty: Some(dirty),
        }
    }

    /// Replace the value, keeping whatever was committed — for adapting an
    /// inner operation's outcome into an outer one's type.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Outcome<U> {
        Outcome {
            value: f(self.value),
            dirty: self.dirty,
        }
    }

    /// The value, discarding the dirty set. For callers that drive an operation
    /// for its result alone and leave the doorbell to whoever owns it.
    pub fn value(self) -> T {
        self.value
    }

    /// Split into value and dirty set. The control adapter's door: it is what
    /// turns an outcome into a wire response plus a doorbell.
    pub fn into_parts(self) -> (T, Option<DirtySet>) {
        (self.value, self.dirty)
    }
}
