//! Layer A — the **engine**: lait's data type behind the Layer-A contract
//! (`docs/LAIT-DATA-CONTRACT.md`).
//!
//! The lait data type is *a convergent data body ⊕ a causal authority envelope*.
//! This module owns both halves' storage representation and is the **only**
//! place in the crate allowed to name the convergence engine's types (`loro::*`).
//! Everything outside sees typed wrappers ([`issue::IssueDoc`],
//! [`catalog::CatalogDoc`], [`membership::MembershipDoc`]) whose one mutating
//! commit path is [`op::OpCtx`]-carrying `apply()` — so a commit without
//! request-kind/actor/tier metadata is not expressible outside this module.
//!
//! Enforcement is structural, not disciplinary: the wrappers expose no raw
//! document handle, so a call site that wanted to skip the contract cannot name
//! the type it would need. (This sealed the three `pub fn doc()` leaks that let
//! ~25 bare `.commit()` sites inherit engine defaults — timestampless, fused,
//! message-less changes — which is what made history per-session.)

pub mod catalog;
pub mod history;
pub mod issue;
mod loro_ext;
pub mod membership;
pub mod op;
