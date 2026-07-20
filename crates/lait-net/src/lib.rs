//! **The network adapter** — how independently held replicas exchange their
//! material, and the only crate that names a concrete network.
//!
//! Kernel determines legitimacy and Fabric maintains the shared world; those two
//! are lait's substrate. This crate is neither: it is the replaceable mechanism
//! that moves their bytes between peers. The application composes all three.
//!
//! Two halves, and the distinction is the point:
//!
//! - [`policy`] owns *where* lait operates — the public relay mesh, a named local
//!   relay, or isolated. lait states its requirement; the contractor fulfils it.
//! - this module owns *how* — dialing, gossiping, and accepting through
//!   [`Transport`] in lait's own vocabulary ([`PeerId`], [`Topic`], framed
//!   [`Stream`]s, [`GossipEvent`]s), never through a vendor's connection types.
//!
//! One policy, N transports: the shipped one over QUIC ([`DefaultFactory`]) and a
//! deterministic in-process one ([`mem::MemTransport`]) that lets the *real
//! daemon* run with no network at all.
//!
//! **The daemon is the consumer, not the transport.** It holds an
//! `Arc<dyn Transport>` and drives it, so swapping the in-memory transport for
//! the shipped one changes *nothing* above this seam — which is what makes the
//! thing under test the actual daemon rather than a stand-in.
//!
//! Identity note: [`PeerId`] is a [`DeviceId`] — a peer *is* its ed25519 key (the
//! T0 identity agreement). The concrete transport converts at its own edge;
//! nothing above this seam names a foreign id type.

mod iroh;
pub mod mem;
pub mod policy;

use anyhow::Result;
use async_trait::async_trait;

use lait_kernel::ids::DeviceId;

/// The transport lait ships with: QUIC over the relay mesh its [`policy`]
/// selects, and the factory that builds it. Exported under their role rather
/// than their vendor, so replacing the contractor is a change here and nowhere
/// else — no consumer names it, and the module behind these is private.
pub use iroh::{IrohFactory as DefaultFactory, IrohTransport as DefaultTransport};

/// A peer's stable identity — its ed25519 public key. Same 32 bytes iroh calls an
/// `EndpointId`; lait names it a `DeviceId` everywhere above the transport edge.
pub type PeerId = DeviceId;

/// A protocol selector for a direct connection (lait's ALPNs: sync, presence).
pub type Alpn = &'static [u8];

/// A gossip room id — a pure function of the space id (derived by the application protocol).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Topic(pub [u8; 32]);

/// Max framed message size (64 MiB) — a guard against a malformed length.
/// Framing policy belongs to the transport (the seam that owns the wire), so the
/// constant lives here and the protocols above it send whole messages. Enforced
/// read-side by every implementation; send-side only the `u32::try_from`
/// overflow guard applies.
pub const MAX_FRAME: u32 = 64 * 1024 * 1024;

/// How a daemon obtains its network.
///
/// A factory rather than a ready-made [`Transport`], because the transport's
/// identity must *be* the daemon's identity, and the daemon only learns its seed
/// after opening its identity file. Handing the seed to the builder is what makes
/// the two agree by construction; the daemon's check afterwards is what makes a
/// factory that disagrees fail loudly instead of running with signed gossip under
/// one key and a dialable peer under another.
#[async_trait]
pub trait TransportFactory: Send + Sync {
    async fn build(
        &self,
        identity_seed: &[u8; 32],
        network: &policy::Network,
        alpns: &[Alpn],
    ) -> Result<std::sync::Arc<dyn Transport>>;
}

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
/// ALPN). Reachability lives in [`policy::PeerBook`], which the concrete
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
