//! The product's orbital World adapter (C4): the frozen contract packet, the
//! parsed state/projection layer, and the registered `IssuesWorld`.
//!
//! See `docs/plans/04-product-world-contract.md` for the normative mapping.

pub mod contract;
pub mod issues;
pub mod router;
pub mod views;

pub use contract::{IssueEffect, IssueIntent, IssueQuery, PRODUCT_WORLD};
pub use issues::IssuesWorld;
pub use router::{IssueRouter, RouterFacts};
