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
//! mutations, import/export, and projection; kernel replay adjudicates signed
//! authority inputs. Everything outside sees typed wrappers
//! ([`issue::IssueDoc`], [`catalog::CatalogDoc`], [`membership::MembershipDoc`])
//! whose mutating commit path is [`op::OpCtx`]-carrying `apply()`.
//!
//! The wrappers do not expose raw document handles, keeping container details
//! and commit metadata inside the fabric boundary.

// Kernel re-exports give fabric modules one internal namespace for shared types.
pub(crate) use lait_kernel::{acl, actor, dto, genesis, ids, sigdag, space};

pub mod catalog;
pub mod history;
pub mod issue;
mod loro_ext;
pub mod membership;
pub mod op;
pub mod store;
