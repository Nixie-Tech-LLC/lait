//! **The lait kernel** — lait's roots, in the sense of a seed, not an OS core:
//! the minimal set of commitments everything else is derived from, and against
//! which every scaffold is replaceable.
//!
//! This crate lists **no scaffold** in its manifest — not Loro, not iroh — so a
//! scaffold reference here does not compile. That absence *is* the boundary:
//! "where lait starts and ends" is the dependency edge, enforced by rustc rather
//! than remembered by a reviewer. What lives here is pure over identity + signed
//! bytes:
//!
//! - [`ids`] — self-certifying identity types (a `UserId` *is* an ed25519 key).
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
pub mod crypto;
pub mod dkg;
pub mod dto;
pub mod genesis;
pub mod ids;
pub mod sigdag;
pub mod space;
