//! Loro-backed collaborative documents, persistence, history, and projection.
//!
//! This crate is the workspace's Loro boundary. It owns container layouts, CRDT
//! mutations, import/export, and projection; kernel replay adjudicates signed
//! authority inputs. Everything outside sees typed wrappers
//! ([`issue::IssueDoc`], [`catalog::CatalogDoc`], [`membership::MembershipDoc`])
//! whose mutating commit path is [`op::OpCtx`]-carrying `apply()`.
//!
//! The wrappers do not expose raw document handles, keeping container details
//! and commit metadata inside the engine boundary.

// Kernel re-exports give engine modules one internal namespace for shared types.
pub(crate) use lait_kernel::{acl, actor, dto, genesis, ids, sigdag, space};

pub mod catalog;
pub mod history;
pub mod issue;
mod loro_ext;
pub mod membership;
pub mod op;
pub mod store;
