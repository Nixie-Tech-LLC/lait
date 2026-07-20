//! What a successful command reports about its persistence effect.
//!
//! **Two invariants, and this type carries one of them.** *Return-state safety*:
//! an error return never carries a dirty set, so nothing rings the doorbell for a
//! rejected write and an optimistic client's rollback is race-free. That one is
//! structural here — a dirty set is reachable only through the `Ok` side of a
//! [`Result`], so "this failed, and here is what changed" cannot be spelled.
//! *Write ordering*: no durable write precedes an error return. That one this
//! type cannot prove and does not claim. A command that commits and then fails is
//! still a correctness defect; it must finish as [`committed`](Change::committed)
//! carrying its dirty set, never as an error.
//!
//! Only commands return this. A read has no persistence effect to classify, so it
//! returns its domain value directly and the adapter supplies the absent dirty set.
//!
//! The state is named rather than spelled `Option<DirtySet>` because `None` is an
//! adapter representation while `Unchanged` and `Committed` are claims a reviewer
//! must check against the code. Private fields keep the constructors the only way
//! in, but they remain assertions by the command's author, not proof.

use super::{DirtySet, ReplicaError};

/// A successful command's value plus the persistence effect it reports.
#[derive(Debug)]
pub struct Change<T> {
    value: T,
    state: ChangeState,
}

#[derive(Debug)]
enum ChangeState {
    Unchanged,
    Committed(DirtySet),
}

impl<T> Change<T> {
    /// An idempotent command that performed no durable write. Use it only on a
    /// branch where the absence of a write is proven, not merely likely.
    pub fn unchanged(value: T) -> Self {
        Self {
            value,
            state: ChangeState::Unchanged,
        }
    }

    /// A command whose durable write landed, carrying what it touched. An empty
    /// dirty set is meaningful and distinct from `Unchanged`: it says a commit
    /// happened whose scope no subscriber needs.
    pub fn committed(value: T, dirty: DirtySet) -> Self {
        Self {
            value,
            state: ChangeState::Committed(dirty),
        }
    }

    /// Adapt an inner command's value into an outer one's type, keeping its
    /// report. Nested commands compose through this rather than by unpacking and
    /// rebuilding the state, which is how a report drifts from what happened.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Change<U> {
        Change {
            value: f(self.value),
            state: self.state,
        }
    }

    /// Split into value and dirty set. The control adapter's door: it is what
    /// turns a change into a wire response plus a doorbell.
    pub fn into_parts(self) -> (T, Option<DirtySet>) {
        let dirty = match self.state {
            ChangeState::Unchanged => None,
            ChangeState::Committed(dirty) => Some(dirty),
        };
        (self.value, dirty)
    }

    /// The report alone, for a caller that drives a command outside dispatch and
    /// owns the notification itself.
    pub fn into_dirty(self) -> Option<DirtySet> {
        self.into_parts().1
    }
}

/// A fallible domain operation: a read that can refuse, or a command's error side.
pub type ReplicaResult<T> = std::result::Result<T, ReplicaError>;

/// A command: on success, a value and its persistence report.
pub type ChangeResult<T> = ReplicaResult<Change<T>>;
