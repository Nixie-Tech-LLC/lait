//! lait: a local-first, peer-to-peer issue tracker.
//!
//! One binary, three roles:
//!   * `lait daemon` runs the node (endpoint, gossip room, presence, and —
//!     the tracker core — the Loro-CRDT catalog + issue documents, git-backed).
//!   * `lait <cmd>` / `lait tui` are CLI/TUI clients driving the daemon
//!     over a local IPC control channel.
//!   * `lait mcp` exposes the same Layer-B façade as MCP tools for an agent.
//!
//! The crate is split lib + bin so integration tests, doctests, and the MCP/DTO
//! parity check can exercise the same code the binary runs. See `docs/`.
//!
//! Layering (see `docs/ARCHITECTURE.md` §4, `docs/SCHEMA.md` §1):
//!   * **Layer A — storage/CRDT** ([`catalog`], [`issue`], [`store`], [`ids`]):
//!     Loro documents are the single source of truth for all merge semantics.
//!   * **Layer B — control protocol** ([`control`], [`dto`]): a stable, versioned,
//!     hand-maintained projection of Layer A over the local socket. Never a dump.
//!   * **Layer C — wire/sync** ([`proto`], and P1 `sync`): opaque Loro bytes plus
//!     the minimum framing to route them over iroh.

pub mod acl;
pub mod app;
pub mod catalog;
pub mod cli;
pub mod cmdspec;
pub mod config;
pub mod control;
pub mod crypto;
pub mod daemon_spawn;
pub mod diagnose;
pub mod dto;
pub mod ids;
pub mod inbox;
pub mod index;
pub mod install;
pub mod issue;
pub mod loro_ext;
pub mod mcp;
pub mod members_ui;
pub mod membership;
pub mod node;
pub mod presence;
pub mod proto;
pub mod registry;
pub mod store;
pub mod sync;
pub mod tracker;
pub mod tui;
pub mod workspaces;
