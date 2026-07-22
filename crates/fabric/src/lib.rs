//! The fabric maintains the **shared world**: collaborative documents,
//! persistence, history, convergence, and projection.
//!
//! The kernel determines **legitimacy** — identity, authority, custody,
//! recovery, and which transitions are valid given signed history. The fabric
//! and the kernel are separate crates because the dependency edge is a
//! correctness boundary: convergence cannot confer legitimacy. They ship, test,
//! and version together as lait's substrate.
//!
//! This crate is the substrate's Loro boundary. It owns container layouts, CRDT
//! mutations, import/export, and the collaborative-document seam the replica
//! drives ([`fabric::Fabric`]); kernel replay adjudicates signed authority
//! inputs. Raw document handles never cross the boundary — everything outside
//! sees [`fabric::FabricOp`] transactions and typed exports.

pub mod fabric;
mod loro_ext;
mod op;

/// The semantics-free durable commit protocol, extracted into the lower
/// `journal` crate (mechanics commits its authority ledger through the same
/// machinery). Re-exported here so Fabric consumers keep one durability
/// namespace.
pub mod journal {
    pub use ::journal::*;
}

pub use fabric::{
    BodyExport, CausalToken, CollaborativeView, CrdtFabric, Fabric, FabricCommitReceipt,
    FabricError, FabricKey, FabricOp, FabricTransactionRequest, ListElement,
};
pub use journal::{FaultInjector, JournaledStore, ObjectRef, StoreManifest, FAULT_POINTS};
