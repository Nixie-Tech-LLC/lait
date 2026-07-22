//! **Replica** — LAIT's durable-material and Convergence semantics.
//!
//! A Replica is an Orbit's durable local materialization of its Space: authority
//! material, World Bodies, semantic frontiers, locally held keys, and enough
//! metadata to distinguish unknown, partial, and corrupt material. Replica is a
//! LAIT semantic type — **not the CRDT engine**, which it never exposes. It applies
//! transaction, incorporation, and Convergence policy using [`mechanics`]
//! (mechanics) for legitimacy and [`fabric`] (Fabric) for canonical
//! collaborative representation and durability.
//!
//! This crate is prefix-free from birth (the S8 renames do not touch it). It
//! names neither `loro` nor any product/consumer vocabulary — the dependency
//! edge is the seal, and the guard suite proves the vocabulary boundary.
//!
//! The sealed contract surface: Body identity ([`ids`]), Body schemas/
//! operations/descriptors ([`body`]), semantic/authority frontiers
//! ([`frontier`]), Convergence outcomes ([`convergence`]), signed transactions
//! and manifests ([`transaction`], [`manifest`]), persistent-idempotency
//! receipts ([`receipt`]), and the committing [`replica`] itself, which
//! translates validated Body operations into Fabric operations and advances
//! only from durable Fabric receipts.

pub mod algebra;
pub mod body;
pub mod convergence;
pub mod frontier;
pub mod ids;
pub mod manifest;
pub mod marker;
pub mod protected;
pub mod receipt;
pub mod replica;
pub mod transaction;

pub use body::{BodyOp, BodySchema, CollaborativeSchema, ContentCommitment, MutationModel};
pub use convergence::{
    AuthorityBatchReceipt, AuthorityIncorporator, ConvergenceOutcome, IncorporationClass,
    StagedContactMaterial, ValidatedContactBundle,
};
pub use fabric::{CollaborativeView, ListElement};
pub use frontier::{AuthorityFrontier, ReplicaFrontier};
pub use ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
pub use manifest::{
    AuthorizedRoot, ManifestBook, ManifestEntry, ManifestError, ManifestPage, ManifestRoot,
    RootObservation,
};
pub use marker::{MarkerError, StoreMarker};
pub use protected::{
    BodyKeySource, ProtectedBodyPayload, ProtectedError, StaticBodyKeys, MAX_BODY_BYTES,
    MAX_PROTECTED_PLAINTEXT,
};
pub use receipt::{ReceiptError, RequestReceipt, MAX_EFFECT_BYTES};
pub use replica::{
    operations_digest_of, ActionOutcome, BodyBinding, CommitAuthorization, CommitContext,
    ExportedMaterial, QuotaConfig, Replica, ReplicaCommitError, StaticAuthorizer, SupportedSchemas,
    TransactionAuthorizer, MUTATION_ATOMIC, MUTATION_COLLABORATIVE,
};
pub use transaction::{
    AuthoritySource, BodyDescriptor, BodyTransaction, BodyTransactionCore, SeedSigner,
    TransactionError, TransactionSigner,
};
