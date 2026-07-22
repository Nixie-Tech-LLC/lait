//! lait: a local-first, peer-to-peer issue tracker.
//!
//! One binary, four roles:
//!   * `lait daemon` runs the orbital Station: mechanics authority, the Body
//!     replica, comms transport, and the docked Issues World.
//!   * `lait <cmd>` is the CLI client, driving the daemon over a local IPC
//!     control channel.
//!   * `lait serve` binds that same façade to loopback HTTP + SSE so a browser
//!     can be a client too ([`serve`], `docs/UI.md`). The only surface global
//!     to the machine: it supervises one daemon per space.
//!   * `lait mcp` exposes the same Layer-B façade as MCP tools for an agent.
//!
//! The crate is split lib + bin so integration tests, doctests, and the MCP/DTO
//! parity check can exercise the same code the binary runs. See `docs/`.
//!
//! Layering (see `docs/ARCHITECTURE.md` and `docs/DATA-CONTRACT.md`):
//!   * **The substrate** (`mechanics`, `fabric`, `replica`, `comms`,
//!     `runtime`): authority, convergence, the Body graph, transport, and the
//!     orbital lifecycle, each behind its own crate boundary.
//!   * **The product** ([`world`], [`orbital`]): the Issues World contract and
//!     the composition root that docks it.
//!   * **Layer B — control protocol** ([`control`], [`dto`]): a stable,
//!     versioned, hand-maintained projection over the local socket. Never a
//!     dump of storage internals.

pub mod app;
pub mod cli;
pub mod cmdspec;
pub mod config;
pub mod control;
pub mod daemon_spawn;
pub mod diagnose;
/// Layer-B data-transfer objects (the product's external JSON shapes).
pub mod dto;
/// Product identifiers: the generic mechanics ids plus the Issues-owned ids.
pub mod ids;
pub mod install;
pub mod list_picker;
pub mod mcp;
pub mod members_ui;
/// The product's adoption of the orbital lifecycle (hosts a World, drives
/// Sessions through the public `runtime` API).
pub mod orbital;
pub mod registry;
pub mod serve;
pub mod spaces;
/// The product's orbital World adapter (the C4 contract packet + IssuesWorld).
pub mod world;

// The **kernel** (`mechanics`) holds lait's roots — identity, the trust
// planes, derivation rules — in a crate that lists no scaffold, so no CRDT or
// transport reference there can compile. Re-exported here so the app layer
// keeps reaching them by their historical crate-root paths (`crate::acl`,
// `lait::crypto`, …); the boundary is enforced by the kernel crate's manifest,
// not by these aliases.
pub use mechanics::{
    acl, actor, authority, compile, crypto, custody, dkg, expand, genesis, policy, secretfs,
    sigdag, space, transition,
};

// The **fabric** (`fabric`) is the substrate's convergence boundary — the only
// crate whose manifest lists the CRDT engine, so document merge internals are
// unnameable outside it.
pub use fabric::{self as fabric};

// The **net adapter** (`comms`) is how independently held replicas exchange
// their material: lait's own `Transport` seam plus the network policy behind it,
// in a crate that alone lists iroh. `iroh` is absent from THIS manifest, so no
// `iroh::` reference compiles in the app layer. Re-exported so the daemon keeps
// reaching the seam by its historical paths (`crate::transport`, `crate::net`).
pub use comms as transport;
pub use comms::policy as net;
