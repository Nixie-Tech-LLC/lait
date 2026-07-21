//! **Replica** — LAIT's durable-material and Convergence semantics.
//!
//! A Replica is an Orbit's durable local materialization of its Space: authority
//! material, World Bodies, semantic frontiers, locally held keys, and enough
//! metadata to distinguish unknown, partial, and corrupt material. Replica is a
//! LAIT semantic type — **not Loro**, and it never exposes Loro. It applies
//! transaction, incorporation, and Convergence policy using [`lait_kernel`]
//! (mechanics) for legitimacy and [`lait_fabric`] (Fabric) for canonical
//! collaborative representation and durability.
//!
//! This crate is prefix-free from birth (the S8 renames do not touch it). It
//! names neither `loro` nor any product/consumer vocabulary — the dependency
//! edge is the seal, and the guard suite proves the vocabulary boundary.
//!
//! S0 establishes the sealed contract surface: Body identity ([`ids`]), Body
//! schemas/operations/descriptors ([`body`]), semantic/authority frontiers
//! ([`frontier`]), and Convergence outcomes ([`convergence`]). The transaction
//! planning and Fabric translation land in later stages (S5); the algebra is
//! frozen as an S1 fixture.

pub mod algebra;
pub mod body;
pub mod convergence;
pub mod frontier;
pub mod ids;
pub mod manifest;
pub mod marker;
pub mod replica;
pub mod transaction;

pub use body::{
    BodyDescriptor, BodyOp, BodySchema, CollaborativeSchema, ContentCommitment, MutationModel,
};
pub use convergence::{ConvergenceOutcome, IncorporationClass};
pub use frontier::{AuthorityFrontier, ReplicaFrontier, TransactionId};
pub use ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
pub use lait_fabric::{CollaborativeView, ListElement};
pub use manifest::{
    ManifestBook, ManifestEntryV1, ManifestError, ManifestPageV1, ManifestRootV1, RootObservation,
};
pub use marker::{MarkerError, StoreMarkerV1};
pub use replica::{Replica, ReplicaCommitError};
pub use transaction::{AuthoritySource, BodyDescriptorV1, BodyTransactionV1, TransactionError};
