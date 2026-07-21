//! Lifecycle, dormancy, Contact, and World error taxonomies.
//!
//! These are hand-rolled (no `thiserror`) to keep the runtime dependency set at
//! `serde` + `anyhow`. `Display` renders the `Debug` form — the categories carry
//! no remote prose; human-facing callers map the variant to their own text.

use lait_kernel::ids::SpaceId;

/// Implement `Display` (via `Debug`) and `std::error::Error` for a plain enum.
macro_rules! debug_error {
    ($($ty:ty),+ $(,)?) => {$(
        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{self:?}")
            }
        }
        impl std::error::Error for $ty {}
    )+};
}

/// Why an Orbit lifecycle operation failed. Acquisition revalidates integrity,
/// protocol version, custody, and the store lock; observation never grants
/// control.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleError {
    /// No local Orbit exists for the Space.
    OrbitNotFound(SpaceId),
    /// The Orbit's store is already locked by another live Station or handle
    /// (the typed double-lock).
    ReplicaLocked(SpaceId),
    /// The Coordinates presented an unknown/unsupported version.
    UnsupportedCoordinatesVersion,
    /// The store failed integrity or protocol-version validation on acquisition.
    IntegrityFailure(String),
    /// The operation is not yet wired at this stage of the carve. Present only so
    /// S0's sealed lifecycle surface compiles; production never routes through
    /// these paths until the owning stage lands.
    NotYetWired(&'static str),
}

/// Why dormancy failed to cleanly return the Orbit. Dormancy drains tasks,
/// checkpoints, and releases resources; a failure still returns a recoverable
/// Orbit via [`StationExit`], never a leaked lock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DormancyError {
    /// A tracked task did not drain within its deadline.
    DrainTimeout,
    /// The Replica checkpoint failed.
    Checkpoint(String),
    /// The transport did not close cleanly.
    Transport(String),
}

/// The typed reason an activation ended unexpectedly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StationExitReason {
    /// A tracked task panicked or errored.
    TaskFailed(String),
    /// Dormancy itself failed partway.
    Dormancy(DormancyError),
}

/// The result of a Station stopping — cleanly or by unexpected task exit. Either
/// way the durable Orbit is recoverable; the store lock is released last.
#[derive(Debug)]
pub struct StationExit {
    /// The recovered durable Orbit.
    pub orbit: crate::lifecycle::Orbit,
    /// The typed reason the Station stopped, if it was not a clean dormancy.
    pub reason: Option<StationExitReason>,
}

/// Why an administrative/test [`Station::contact`](crate::lifecycle::Station)
/// failed. Ordinary callers never schedule Contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactError {
    /// The named Neighbor is not known.
    UnknownNeighbor,
    /// The Neighbor was not reachable within the deadline.
    Unreachable,
    /// The Contact exchange failed mid-transfer.
    Transfer(String),
}

/// The versioned typed error surface a World implementation and its callers
/// speak. Callers render human prose; these carry no remote text. Frozen against
/// the S1a contract packet; S0 fixes the categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorldError {
    /// The request could not be decoded or was structurally invalid.
    InvalidRequest,
    /// The request named a schema the World does not support.
    UnsupportedSchema,
    /// The request named a schema version the World cannot read.
    UnsupportedSchemaVersion,
    /// The principal lacks standing for the action.
    Denied,
    /// Two Body versions conflicted semantically.
    Conflict,
    /// A resource limit was exceeded.
    LimitExceeded,
    /// The authority frontier changed between authorization and commit; nothing
    /// was committed.
    AuthorityChanged,
    /// A request id was reused with a different payload.
    RequestIdConflict,
    /// The Session's Station has gone dormant or exited.
    StationDormant,
    /// The Replica/Fabric persistence layer failed durably.
    Persistence,
    /// Continuity was lost; the caller must reset/re-query.
    ResetRequired,
}

debug_error!(
    LifecycleError,
    DormancyError,
    StationExitReason,
    ContactError,
    WorldError,
);
