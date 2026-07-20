//! Layer A — the **engine**: lait's data type behind the Layer-A contract
//! (`docs/DATA-CONTRACT.md`).
//!
//! The lait data type is *a convergent data body ⊕ a causal authority envelope*.
//! This crate owns both halves' storage representation and is the **only crate**
//! in the workspace allowed to name the convergence scaffold's types (`loro::*`)
//! — it lists `loro` in its manifest and nothing else does, so the seal is the
//! dependency edge, enforced by rustc. Everything outside sees typed wrappers
//! ([`issue::IssueDoc`], [`catalog::CatalogDoc`], [`membership::MembershipDoc`])
//! whose one mutating commit path is [`op::OpCtx`]-carrying `apply()` — so a
//! commit without request-kind/actor/tier metadata is not expressible outside.
//!
//! Enforcement is structural, not disciplinary: the wrappers expose no raw
//! document handle, so a call site that wanted to skip the contract cannot name
//! the type it would need.

// Path compatibility: the engine modules and the store reach lait's roots by
// their historical `crate::` paths (`crate::ids`, `crate::genesis`, …). The
// kernel is a real dependency; these aliases keep the module bodies unchanged.
pub(crate) use lait_kernel::{acl, actor, dto, genesis, ids, sigdag, space};

pub mod catalog;
pub mod history;
pub mod issue;
mod loro_ext;
pub mod membership;
pub mod op;
pub mod store;
