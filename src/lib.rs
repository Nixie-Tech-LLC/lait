//! lait: a local-first, peer-to-peer issue tracker.
//!
//! One binary, four roles:
//!   * `lait daemon` runs the node (endpoint, gossip room, presence, and —
//!     the replica core — the Loro-CRDT catalog + issue documents, git-backed).
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
//!   * **Layer A — storage/CRDT** ([`catalog`], [`issue`], [`store`], [`ids`]):
//!     Loro documents are the single source of truth for all merge semantics.
//!   * **Layer B — control protocol** ([`control`], [`dto`]): a stable, versioned,
//!     hand-maintained projection of Layer A over the local socket. Never a dump.
//!   * **Peer wire and sync** ([`proto`] and `sync`): opaque Loro bytes plus
//!     the minimum framing to route them over the network adapter.

pub mod app;
pub mod cli;
pub mod cmdspec;
pub mod config;
pub mod control;
pub mod daemon_spawn;
pub mod diagnose;
pub mod inbox;
pub mod index;
pub mod install;
pub mod list_picker;
pub mod mcp;
pub mod members_ui;
pub mod node;
pub mod presence;
pub mod proto;
pub mod registry;
pub mod replica;
pub mod secretfs;
pub mod serve;
pub mod spaces;
pub mod sync;

// The **kernel** (`lait-kernel`) holds lait's roots — identity, the trust
// planes, derivation rules — in a crate that lists no scaffold, so a `loro::`
// or `iroh::` reference there cannot compile. Re-exported here so the app layer
// keeps reaching them by their historical crate-root paths (`crate::acl`,
// `lait::ids`, …); the boundary is enforced by the kernel crate's manifest, not
// by these aliases.
pub use lait_kernel::{
    acl, actor, authority, authz, compile, crypto, custody, dkg, dto, expand, genesis, ids, policy,
    sigdag, space, transition,
};

// The **fabric** (`lait-fabric`) maintains the shared world — documents,
// persistence, history, convergence, projection — and is the only crate that
// names Loro. Re-exported here as the `fabric` module and its wrappers, while
// the app crate's manifest lists no `loro`, so `loro::*` is unnameable outside
// the fabric.
pub use lait_fabric::{self as fabric, catalog, issue, membership, store};

// The **net adapter** (`lait-net`) is how independently held replicas exchange
// their material: lait's own `Transport` seam plus the network policy behind it,
// in a crate that alone lists iroh. `iroh` is absent from THIS manifest, so no
// `iroh::` reference compiles in the app layer. Re-exported so the daemon keeps
// reaching the seam by its historical paths (`crate::transport`, `crate::net`).
pub use lait_net as transport;
pub use lait_net::policy as net;
