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
//! composition of the replica core + control plane + protocol logic; it holds an
//! `Arc<dyn Transport>` and drives it. Swapping iroh for the in-memory transport
//! swaps *nothing* in the daemon — which is the whole point: the thing under test
//! is the actual daemon, over a network we control.
//!
//! Identity note: [`PeerId`] is a lait [`DeviceId`] — a peer *is* its ed25519 key,
//! the same bytes iroh calls an `EndpointId` (the T0 identity agreement). The
//! iroh impl converts at its own edge; nothing above this seam names an iroh id.

pub mod iroh;
pub mod mem;

use anyhow::Result;
use async_trait::async_trait;

use crate::ids::DeviceId;

/// A peer's stable identity — its ed25519 public key. Same 32 bytes iroh calls an
/// `EndpointId`; lait names it a `DeviceId` everywhere above the transport edge.
pub type PeerId = DeviceId;

/// A protocol selector for a direct connection (lait's ALPNs: sync, presence).
pub type Alpn = &'static [u8];

/// A gossip room id — a pure function of the space id ([`crate::proto`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Topic(pub [u8; 32]);

/// Max framed message size (64 MiB) — a guard against a malformed length.
/// Framing policy belongs to the transport (the seam that owns the wire), so the
/// constant lives here; `sync.rs` holds a private duplicate until PR-2 re-points
/// it. Enforced read-side by every implementation; send-side only the
/// `u32::try_from` overflow guard applies.
pub const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// What a gossip subscription yields. The daemon's `recv_loop` is written against
/// exactly this — decode/verify a `Received`, `touch` on `NeighborUp`, mark
/// offline on `NeighborDown`.
#[derive(Debug, Clone)]
pub enum GossipEvent {
    /// A signed application frame. `from` is the **delivering neighbor** — the
    /// last hop in the gossip overlay, a routing hint, never an authenticated
    /// author (iroh-gossip relays frames peer-to-peer, so the deliverer is
    /// usually not the signer). The daemon derives authorship from the signed
    /// payload; the transport does not authenticate payloads.
    Received { from: PeerId, bytes: Vec<u8> },
    /// A peer joined our view of the room.
    NeighborUp(PeerId),
    /// A peer left / went unreachable.
    NeighborDown(PeerId),
}

/// A bidirectional, **framed** byte stream — one lait protocol message per frame.
/// Length framing is the transport's job, so `sync.rs` sends/receives whole
/// `Msg`s instead of hand-rolling length prefixes over a raw QUIC stream.
///
/// **Close semantics (dialer side):** dropping a dialer's `Box<dyn Stream>`
/// closes the underlying connection — that IS the dialer's "done" signal (the
/// iroh impl's stream owns the dial-side connection; today's `conn.close(0, …)`
/// reason strings were diagnostics only). Dialers never call
/// [`wait_closed`](Stream::wait_closed).
///
/// **Readiness (accept side):** an accepted stream may not exist on the wire
/// until the dialer opens it and writes — accepters must not assume anything
/// before their first `recv`/`send` (lait's protocols all have the dialer speak
/// first; a presence probe never opens a stream at all).
#[async_trait]
pub trait Stream: Send {
    /// Send one frame. May park indefinitely under the peer's flow control
    /// (real transports have backpressure; the in-memory one buffers
    /// unboundedly) — callers own their timeouts.
    async fn send(&mut self, frame: &[u8]) -> Result<()>;
    /// Receive the next frame. `Ok(None)` at **clean** end-of-stream (the peer
    /// finished at a frame boundary); an end mid-frame or a lost connection is
    /// an `Err` — truncation is loud, never a quiet end.
    async fn recv(&mut self) -> Result<Option<Vec<u8>>>;
    /// Signal we are done sending (the peer sees end-of-stream after draining).
    /// This only **queues** the end marker — it does NOT confirm delivery;
    /// accepters must follow with [`wait_closed`](Stream::wait_closed) before
    /// dropping the stream.
    async fn finish(&mut self) -> Result<()>;
    /// Park until the peer has closed the connection under this stream (or it
    /// is lost). **Accept-side contract:** after the accepter has sent its last
    /// frame and called [`finish`](Stream::finish), it MUST await this before
    /// dropping the stream — `finish` only queues end-of-stream, and dropping
    /// the stream tears the connection down (CONNECTION_CLOSE), truncating any
    /// frames the dialer has not yet drained (the silent-partial-sync bug
    /// guarded at the daemon's sync accepter). Resolves once the dialer has
    /// closed/dropped its side, which it does only after draining. Dialers
    /// never need this — a dialer signals "done" by dropping its stream.
    async fn wait_closed(&mut self);
}

/// An accepted inbound connection: who dialed, on which protocol, and the stream.
pub struct Incoming {
    pub from: PeerId,
    pub alpn: Vec<u8>,
    pub stream: Box<dyn Stream>,
}

/// The send half of a joined gossip room. Split from the receive half so the
/// daemon can share the sender across its heartbeat/announce tasks (behind an
/// `Arc`/`Mutex`) *while* `recv_loop` owns the receiver — one combined object
/// can't serve both at once. `&self` + `Send + Sync` makes sharing natural.
#[async_trait]
pub trait GossipSender: Send + Sync {
    /// Broadcast an (already-signed) frame to the room. Gossip is **lossy** —
    /// delivery is best-effort and unordered; the protocol tolerates misses
    /// (announces piggyback on the heartbeat).
    async fn broadcast(&self, bytes: Vec<u8>) -> Result<()>;
}

/// The receive half of a joined gossip room.
#[async_trait]
pub trait GossipReceiver: Send {
    /// The next event, or `None` when the room is gone. A lossy transport may
    /// silently skip missed messages (there is no Lagged event — gossip is
    /// lossy by contract and the daemon already tolerates loss).
    async fn next(&mut self) -> Option<GossipEvent>;
    /// Resolve once the room is usable — connected to at least one peer (the
    /// ticket-join "connected to the host or fail loudly" path). May consume
    /// the initial `NeighborUp` from the event stream. The in-memory transport
    /// is always joined and resolves immediately. Callers own the timeout, as
    /// the daemon's `join_topic` does today.
    async fn joined(&mut self) -> Result<()>;
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

    /// The direct addresses a minted ticket must carry so a peer can reach us
    /// **when the policy has no relay/discovery** (Isolated). Empty under
    /// Public/Local — those tickets stay address-free (the policy resolves bare
    /// ids), so the policy test lives here, not in the daemon.
    fn advertised_addrs(&self) -> Vec<std::net::SocketAddr>;

    /// Join a gossip room, bootstrapping from `bootstrap` peers (which the
    /// transport also [`learn`](Transport::learn)s, so bare-id dials to them
    /// resolve). Non-waiting — a solo founder must not block; callers wanting a
    /// join-wait use [`GossipReceiver::joined`] under their own timeout.
    async fn subscribe(
        &self,
        topic: Topic,
        bootstrap: &[PeerId],
    ) -> Result<(Box<dyn GossipSender>, Box<dyn GossipReceiver>)>;

    /// Best-effort teardown: unblocks a parked [`accept`](Transport::accept)
    /// (which returns `None` from then on) and closes the network.
    async fn shutdown(&self);
}
