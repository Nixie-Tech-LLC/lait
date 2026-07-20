//! **The transport seam** — lait's own interface to a peer-to-peer network, with
//! the concrete network (iroh today) as a swappable *contractor* behind it.
//!
//! Where [`crate::net`] owns the network *policy* (which relay/discovery), this
//! owns the network *mechanism*: the daemon dials peers, gossips, and accepts
//! connections through [`Transport`] in lait's vocabulary ([`PeerId`], [`Topic`],
//! framed [`Stream`]s, [`GossipEvent`]s) — not through `iroh::Endpoint`/`Gossip`/
//! `Router`/`Connection` directly. iroh becomes one implementation
//! (the planned iroh transport), and a deterministic in-process one
//! ([`mem::MemTransport`]) lets the *real daemon* run hermetically in tests.
//!
//! **The daemon is the consumer, not the transport.** `node.rs` stays the
//! composition of the tracker core + control plane + protocol logic; it holds an
//! `Arc<dyn Transport>` and drives it. Swapping iroh for the in-memory transport
//! swaps *nothing* in the daemon — which is the whole point: the thing under test
//! is the actual daemon, over a network we control.
//!
//! Identity note: [`PeerId`] is a lait [`UserId`] — a peer *is* its ed25519 key,
//! the same bytes iroh calls an `EndpointId` (the T0 identity agreement). The
//! iroh impl converts at its own edge; nothing above this seam names an iroh id.

pub mod mem;

use anyhow::Result;
use async_trait::async_trait;

use crate::ids::UserId;

/// A peer's stable identity — its ed25519 public key. Same 32 bytes iroh calls an
/// `EndpointId`; lait names it a `UserId` everywhere above the transport edge.
pub type PeerId = UserId;

/// A protocol selector for a direct connection (lait's ALPNs: sync, presence).
pub type Alpn = &'static [u8];

/// A gossip room id — a pure function of the workspace id ([`crate::proto`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Topic(pub [u8; 32]);

/// What a gossip subscription yields. The daemon's `recv_loop` is written against
/// exactly this — decode/verify a `Received`, `touch` on `NeighborUp`, mark
/// offline on `NeighborDown`.
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// A signed application frame from `from` (the daemon verifies it — the
    /// transport does not authenticate payloads).
    Received { from: PeerId, bytes: Vec<u8> },
    /// A peer joined our view of the room.
    NeighborUp(PeerId),
    /// A peer left / went unreachable.
    NeighborDown(PeerId),
}

/// A bidirectional, **framed** byte stream — one lait protocol message per frame.
/// Length framing is the transport's job, so `sync.rs` sends/receives whole
/// `Msg`s instead of hand-rolling length prefixes over a raw QUIC stream.
#[async_trait]
pub trait Stream: Send {
    /// Send one frame.
    async fn send(&mut self, frame: &[u8]) -> Result<()>;
    /// Receive the next frame, or `None` at clean end-of-stream.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>>;
    /// Signal we are done sending (the peer sees end-of-stream).
    async fn finish(&mut self) -> Result<()>;
}

/// An accepted inbound connection: who dialed, on which protocol, and the stream.
pub struct Incoming {
    pub from: PeerId,
    pub alpn: Vec<u8>,
    pub stream: Box<dyn Stream>,
}

/// A joined gossip room: broadcast to it, and pull the next event.
#[async_trait]
pub trait GossipRoom: Send {
    /// Broadcast an (already-signed) frame to the room.
    async fn broadcast(&self, bytes: Vec<u8>) -> Result<()>;
    /// The next event, or `None` when the room is gone.
    async fn next(&mut self) -> Option<GossipEvent>;
}

/// lait's network mechanism. The daemon depends on this, not on iroh types.
///
/// This is the narrow waist: dial (direct connections for sync/presence), gossip
/// (announce/presence room), and accept (inbound direct connections routed by
/// ALPN). Reachability lives in [`crate::net::PeerBook`], which the concrete
/// transport owns and the daemon populates.
#[async_trait]
pub trait Transport: Send + Sync {
    /// Our own peer id.
    fn my_id(&self) -> PeerId;

    /// Hint how to reach `peer` so a later bare-id [`connect`](Transport::connect)
    /// resolves. `addrs` empty ⇒ use the policy default (e.g. the configured
    /// relay); non-empty ⇒ those direct addresses (Isolated, carried in a ticket).
    /// The in-memory transport ignores this — it resolves peers by id.
    fn learn(&self, peer: PeerId, addrs: &[std::net::SocketAddr]);

    /// Open a direct, framed connection to `peer` for protocol `alpn`.
    async fn connect(&self, peer: PeerId, alpn: Alpn) -> Result<Box<dyn Stream>>;

    /// Accept the next inbound direct connection (any registered ALPN). The daemon
    /// loops this and dispatches by `alpn` — its `Router` replacement.
    async fn accept(&self) -> Option<Incoming>;

    /// Join a gossip room, bootstrapping from `bootstrap` peers.
    async fn subscribe(&self, topic: Topic, bootstrap: &[PeerId]) -> Result<Box<dyn GossipRoom>>;

    /// Best-effort teardown.
    async fn shutdown(&self);
}
