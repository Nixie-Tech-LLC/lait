//! **The lait kernel** — lait's roots, in the sense of a seed, not an OS core:
//! the minimal set of commitments everything else is derived from, and against
//! which every scaffold is replaceable.
//!
//! This crate lists **no scaffold** in its manifest — not Loro, not iroh — so a
//! scaffold reference here does not compile. That absence *is* the boundary:
//! "where lait starts and ends" is the dependency edge, enforced by rustc.
//!
//! The kernel determines **legitimacy** — identity, authority, custody,
//! recovery, and which transitions are valid given signed history. `lait-fabric`
//! maintains the **shared world** — documents, persistence, history,
//! convergence, projection. They are separate crates because that dependency
//! edge is a correctness boundary: convergence cannot confer legitimacy. They
//! ship, test, and version together as lait's substrate.
//!
//! What lives here is pure over identity + signed bytes:
//!
//! - [`ids`] — self-certifying identity types (a `DeviceId` *is* an ed25519 key).
//! - [`crypto`] — sealing/identity primitives (pure RustCrypto/dalek).
//! - [`sigdag`] — the signed hash-DAG envelope every trust plane rides.
//! - [`genesis`] — the root of trust that seeds every replay.
//! - [`acl`] / [`actor`] / [`space`] — the trust planes: membership authority,
//!   actor/device identity, and break-glass recovery, each a pure replay over
//!   signed bytes (a scaffold only *moves* those bytes; trust comes from replay).
//! - [`dkg`] — the FROST threshold-recovery ceremony logic.
//! - [`authz`] — authorization decisions over the replayed state.

pub mod acl;
pub mod actor;
pub mod authority;
pub mod authz;
pub mod compile;
pub mod crypto;
pub mod custody;
pub mod dkg;
pub mod dto;
pub mod expand;
pub mod gaccess;
pub mod gdkg;
pub mod genesis;
pub mod handover;
pub mod ids;
pub mod policy;
pub mod refresh;
pub mod reshare;
pub mod sigdag;
pub mod space;
pub mod status;
pub mod transition;
