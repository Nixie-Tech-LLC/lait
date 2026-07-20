//! The iroh implementation of the transport seam — the ONLY file besides
//! [`crate::net`] that names iroh connection/gossip types, and the only one
//! anywhere that names `GOSSIP_ALPN` (gossip is transport plumbing here; it
//! never surfaces through [`Transport::accept`]).
//!
//! Division of labour: [`crate::net`] owns network *policy* (which
//! relay/discovery — `RelayMode`, presets, address lookups are spoken only
//! there, inside `build_endpoint`); this module owns the *mechanism* — dialing,
//! accepting, framing, gossip — in lait's vocabulary. Identity converts at this
//! edge and nowhere above it: a [`PeerId`] and an iroh `EndpointId` are the
//! same 32 ed25519 bytes (the T0 identity agreement).
//!
//! Accept design: an internal [`Router`] dispatches inbound connections by
//! ALPN. Each lait ALPN gets a [`ForwardHandler`] that wraps the connection in
//! an accept-side [`IrohStream`] and forwards it out of [`Transport::accept`],
//! returning from the handler immediately — sound because the `IrohStream`'s
//! `Connection` clone keeps the connection alive after the handler returns
//! (iroh drops only its own handle; verified by the R1 regression test).

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::{anyhow, Context as _, Result};
use async_trait::async_trait;
use iroh::{
    endpoint::{Connection, ReadExactError, RecvStream, SendStream},
    protocol::{AcceptError, ProtocolHandler, Router},
    EndpointId, SecretKey,
};
use iroh_gossip::{
    api::{Event, GossipReceiver as ApiReceiver, GossipSender as ApiSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::StreamExt;
use tokio::sync::{mpsc, watch, Mutex as TokioMutex};

use super::{
    Alpn, GossipEvent, GossipReceiver, GossipSender, Incoming, PeerId, Stream, Topic, Transport,
    MAX_FRAME,
};
use crate::ids::DeviceId;

/// Inbound connections buffered between the Router's handlers and a slow
/// [`Transport::accept`] loop before handlers start parking in their forward.
const INCOMING_BUFFER: usize = 16;

// ---- id / topic conversion at the edge (T0: same 32 bytes) ----

/// [`PeerId`] → iroh `EndpointId`: hex-decode the 64-char lowercase key string
/// into the 32 key bytes. (Same decode as `proto::endpoint_of`, which is
/// private to `proto.rs`; duplicated here so PR-1 touches nothing outside the
/// transport — PR-2 can dedupe by promoting that fn to `pub(crate)`.)
fn endpoint_id(peer: &PeerId) -> Result<EndpointId> {
    let raw = data_encoding::HEXLOWER_PERMISSIVE
        .decode(peer.as_str().as_bytes())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
        .context("peer id is not a 32-byte key")?;
    EndpointId::from_bytes(&raw).context("peer id is not a valid endpoint id")
}

/// iroh `EndpointId` → [`PeerId`] — the reverse encoding (same as the daemon's
/// own-identity construction from its endpoint key).
fn peer_id(id: EndpointId) -> PeerId {
    DeviceId::from_key_string(id.to_string())
}

/// [`Topic`] → gossip `TopicId`: the same 32 bytes, renamed at the edge.
fn topic_id(t: Topic) -> TopicId {
    TopicId::from_bytes(t.0)
}

// ---- framing (byte-identical to sync.rs's write_msg/read_msg wire format) ----

/// One wire frame: u32 big-endian body length, then the body verbatim.
fn encode_frame(body: &[u8]) -> Result<Vec<u8>> {
    let len = u32::try_from(body.len()).map_err(|_| anyhow!("frame too large"))?;
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(body);
    Ok(buf)
}

/// The read-side guard against a malformed length.
fn check_frame_len(len: u32) -> Result<()> {
    if len > MAX_FRAME {
        anyhow::bail!("frame length {len} exceeds the {MAX_FRAME}-byte cap");
    }
    Ok(())
}

/// The iroh transport: an endpoint bound under lait's [`Network`] policy, a
/// gossip instance, and an internal [`Router`] forwarding lait's ALPNs out
/// through [`Transport::accept`].
///
/// [`Network`]: crate::net::Network
pub struct IrohTransport {
    endpoint: iroh::Endpoint,
    gossip: Gossip,
    /// Reachability policy — populated via [`Transport::learn`], queried by the
    /// endpoint on every bare-id dial. Policy semantics live in [`crate::net`].
    peers: crate::net::PeerBook,
    /// Owns ALPN dispatch and graceful teardown (internal — never surfaced).
    router: Router,
    /// Fed by the [`ForwardHandler`]s; drained by [`Transport::accept`].
    incoming: TokioMutex<mpsc::Receiver<Incoming>>,
    /// Flipped by [`Transport::shutdown`] so a parked `accept` unblocks even
    /// while it holds the `incoming` lock.
    shutdown: watch::Sender<bool>,
    /// Cached conversion of `endpoint.id()`.
    my_id: PeerId,
}

impl IrohTransport {
    /// Bind an endpoint under lait's [`Network`] policy (via
    /// [`crate::net::build_endpoint`] — the sole relay/discovery vocabulary
    /// site), spawn gossip, register `alpns` plus the internal gossip ALPN on a
    /// [`Router`], and — when the policy provides a relay — wait (bounded, 30s,
    /// warn-and-continue) for the home relay so early dials are routable.
    ///
    /// Takes the raw identity seed so no iroh key type crosses the boundary:
    /// the seed *is* the identity, and the transport keypair is derived here at
    /// the edge, exactly as the daemon does today.
    ///
    /// [`Network`]: crate::net::Network
    pub async fn new(
        identity_seed: &[u8; 32],
        network: &crate::net::Network,
        alpns: &[Alpn],
    ) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(identity_seed);
        let (endpoint, peers) = crate::net::build_endpoint(&secret_key, network).await?;
        let gossip = Gossip::builder().spawn(endpoint.clone());

        let (tx, rx) = mpsc::channel(INCOMING_BUFFER);
        let mut builder = Router::builder(endpoint.clone()).accept(GOSSIP_ALPN, gossip.clone());
        for &alpn in alpns {
            builder = builder.accept(
                alpn,
                ForwardHandler {
                    alpn,
                    tx: tx.clone(),
                },
            );
        }
        // Drop the original sender: only the handlers hold one now, so the
        // channel closes when the Router (and with it the handlers) shuts down.
        drop(tx);
        let router = builder.spawn();

        // Waiting for a home relay only makes sense when the policy provides
        // one. Bounded so a valid-URL-but-unreachable relay can't hang startup
        // forever (iroh's `online()` never times out on its own).
        if network.uses_relay()
            && tokio::time::timeout(Duration::from_secs(30), endpoint.online())
                .await
                .is_err()
        {
            tracing::warn!("no home relay after 30s — continuing; peers may be unreachable");
        }

        let my_id = peer_id(endpoint.id());
        Ok(Self {
            endpoint,
            gossip,
            peers,
            router,
            incoming: TokioMutex::new(rx),
            shutdown: watch::Sender::new(false),
            my_id,
        })
    }
}

/// Router handler for one lait ALPN: wraps the connection in an accept-side
/// [`IrohStream`] and forwards it as an [`Incoming`], returning immediately —
/// the stream's `Connection` clone keeps the connection alive after the handler
/// returns (iroh drops only its own handle on return).
#[derive(Debug, Clone)]
struct ForwardHandler {
    alpn: Alpn,
    tx: mpsc::Sender<Incoming>,
}

impl ProtocolHandler for ForwardHandler {
    async fn accept(&self, conn: Connection) -> std::result::Result<(), AcceptError> {
        let from = peer_id(conn.remote_id());
        // A closed receiver just means the transport is shutting down — drop
        // the connection on the floor (its drop closes it).
        let _ = self
            .tx
            .send(Incoming {
                from,
                alpn: self.alpn.to_vec(),
                stream: Box::new(IrohStream::accepted(conn)),
            })
            .await;
        Ok(())
    }
}

/// One framed lait stream over one QUIC connection. Owns the `Connection`: the
/// dial side drops it to close (the dialer's "done" signal); the accept side
/// parks on it in [`Stream::wait_closed`].
struct IrohStream {
    conn: Connection,
    /// Dial side: opened eagerly in `connect`. Accept side: `None` until the
    /// first send/recv — a lazy `accept_bi`, because a presence probe never
    /// opens a stream at all (an eager accept would park forever).
    bi: Option<(SendStream, RecvStream)>,
    accept_side: bool,
}

impl IrohStream {
    fn dialed(conn: Connection, send: SendStream, recv: RecvStream) -> Self {
        Self {
            conn,
            bi: Some((send, recv)),
            accept_side: false,
        }
    }

    fn accepted(conn: Connection) -> Self {
        Self {
            conn,
            bi: None,
            accept_side: true,
        }
    }

    async fn bi(&mut self) -> Result<&mut (SendStream, RecvStream)> {
        if self.bi.is_none() {
            let pair = if self.accept_side {
                self.conn.accept_bi().await.context("accept stream")?
            } else {
                self.conn.open_bi().await.context("open stream")?
            };
            self.bi = Some(pair);
        }
        Ok(self.bi.as_mut().expect("just set"))
    }
}

#[async_trait]
impl Stream for IrohStream {
    /// u32 BE length prefix + body — byte-identical to the sync protocol's
    /// historical `write_msg` (the frame we are handed IS the encoded body; we
    /// prepend exactly the 4 length bytes).
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        let buf = encode_frame(frame)?;
        let (send, _) = self.bi().await?;
        send.write_all(&buf).await.context("write frame")?;
        Ok(())
    }

    /// A clean FIN before any length byte is `Ok(None)`; a FIN mid-frame or a
    /// lost connection is an `Err` — truncation is loud (deliberately stricter
    /// than the legacy `read_msg`, which mapped every read error to a quiet
    /// end: exactly the silent-partial-sync failure mode).
    async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        let (_, recv) = self.bi().await?;
        let mut len_buf = [0u8; 4];
        match recv.read_exact(&mut len_buf).await {
            Ok(()) => {}
            // The peer finished exactly at a frame boundary: a clean end.
            Err(ReadExactError::FinishedEarly(0)) => return Ok(None),
            Err(e) => return Err(anyhow!(e).context("read frame length")),
        }
        let len = u32::from_be_bytes(len_buf);
        check_frame_len(len)?;
        let mut buf = vec![0u8; len as usize];
        recv.read_exact(&mut buf).await.context("read frame body")?;
        Ok(Some(buf))
    }

    /// Queues the FIN only — does NOT confirm delivery; accepters must follow
    /// with [`wait_closed`](Stream::wait_closed). Idempotent (a second finish,
    /// or finishing a stream the peer already reset, is not an error).
    async fn finish(&mut self) -> Result<()> {
        if let Some((send, _)) = self.bi.as_mut() {
            let _ = send.finish();
        }
        Ok(())
    }

    /// Parks until the peer closes the connection (or it is lost) — the
    /// delivery guarantee `finish` lacks. The `ConnectionError` it resolves
    /// with is discarded: closing is best-effort by contract.
    async fn wait_closed(&mut self) {
        self.conn.closed().await;
    }
}

/// Gossip sender half: a thin wrap of the iroh api sender.
struct IrohGossipSender(ApiSender);

#[async_trait]
impl GossipSender for IrohGossipSender {
    async fn broadcast(&self, bytes: Vec<u8>) -> Result<()> {
        self.0
            .broadcast(bytes.into())
            .await
            .map_err(|e| anyhow!("broadcast failed: {e}"))
    }
}

/// Gossip receiver half: maps iroh events to [`GossipEvent`]s.
struct IrohGossipReceiver(ApiReceiver);

#[async_trait]
impl GossipReceiver for IrohGossipReceiver {
    async fn next(&mut self) -> Option<GossipEvent> {
        loop {
            match self.0.next().await {
                Some(Ok(Event::Received(m))) => {
                    // `from` is the delivering neighbor — a routing hint, never
                    // an authenticated author (the trait's Received contract).
                    return Some(GossipEvent::Received {
                        from: peer_id(m.delivered_from),
                        bytes: m.content.to_vec(),
                    });
                }
                Some(Ok(Event::NeighborUp(id))) => {
                    return Some(GossipEvent::NeighborUp(peer_id(id)))
                }
                Some(Ok(Event::NeighborDown(id))) => {
                    return Some(GossipEvent::NeighborDown(peer_id(id)))
                }
                // Gossip is lossy by contract; a lag is not an event.
                Some(Ok(Event::Lagged)) => {
                    tracing::debug!("gossip receiver lagged; messages were dropped");
                    continue;
                }
                Some(Err(e)) => {
                    tracing::debug!("gossip receiver error: {e:#}");
                    return None;
                }
                None => return None,
            }
        }
    }

    async fn joined(&mut self) -> Result<()> {
        self.0
            .joined()
            .await
            .map_err(|e| anyhow!("gossip join failed: {e}"))
    }
}

#[async_trait]
impl Transport for IrohTransport {
    fn my_id(&self) -> PeerId {
        self.my_id.clone()
    }

    /// Empty `addrs` ⇒ the policy default ([`PeerBook::learn`]: `{id, relay}`
    /// under Local, a no-op under Public where discovery resolves ids);
    /// non-empty ⇒ those direct addresses ([`PeerBook::learn_direct`] — the
    /// Isolated ticket path).
    ///
    /// [`PeerBook::learn`]: crate::net::PeerBook::learn
    /// [`PeerBook::learn_direct`]: crate::net::PeerBook::learn_direct
    fn learn(&self, peer: PeerId, addrs: &[SocketAddr]) {
        let id = match endpoint_id(&peer) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!("cannot learn unparseable peer id: {e:#}");
                return;
            }
        };
        if addrs.is_empty() {
            self.peers.learn(id);
        } else {
            self.peers.learn_direct(id, addrs);
        }
    }

    /// Dials by bare id (resolution goes through the policy: discovery, the
    /// [`PeerBook`], or carried addresses) and opens the stream eagerly. NO
    /// internal timeout — callers own timeouts, as the daemon's pull/probe do.
    ///
    /// [`PeerBook`]: crate::net::PeerBook
    async fn connect(&self, peer: PeerId, alpn: Alpn) -> Result<Box<dyn Stream>> {
        let id = endpoint_id(&peer)?;
        let conn = self
            .endpoint
            .connect(id, alpn)
            .await
            .context("connect to peer")?;
        let (send, recv) = conn.open_bi().await.context("open stream")?;
        Ok(Box::new(IrohStream::dialed(conn, send, recv)))
    }

    /// The Router does the real accepting; this drains what the handlers
    /// forward. Gossip connections are handled internally and never surface.
    /// `None` once [`shutdown`](Transport::shutdown) has run.
    async fn accept(&self) -> Option<Incoming> {
        let mut shutdown = self.shutdown.subscribe();
        if *shutdown.borrow() {
            return None;
        }
        let mut rx = self.incoming.lock().await;
        tokio::select! {
            inc = rx.recv() => inc,
            _ = shutdown.wait_for(|s| *s) => None,
        }
    }

    fn advertised_addrs(&self) -> Vec<SocketAddr> {
        if self.peers.is_isolated() {
            // Isolated: peers reach us only by carried direct addresses, so a
            // minted ticket must ship ours.
            self.endpoint.addr().ip_addrs().copied().collect()
        } else {
            // Public/Local resolve bare ids — tickets stay address-free.
            Vec::new()
        }
    }

    /// Bootstrap ids are converted AND pre-learned (so bare-id dials to them
    /// resolve under Local), then the topic is joined non-waiting.
    async fn subscribe(
        &self,
        topic: Topic,
        bootstrap: &[PeerId],
    ) -> Result<(Box<dyn GossipSender>, Box<dyn GossipReceiver>)> {
        let mut ids = Vec::with_capacity(bootstrap.len());
        for peer in bootstrap {
            let id = endpoint_id(peer)?;
            self.peers.learn(id);
            ids.push(id);
        }
        let sub = self
            .gossip
            .subscribe(topic_id(topic), ids)
            .await
            .map_err(|e| anyhow!("subscribe to room: {e}"))?;
        let (sender, receiver) = sub.split();
        Ok((
            Box::new(IrohGossipSender(sender)),
            Box::new(IrohGossipReceiver(receiver)),
        ))
    }

    /// Teardown order: unblock `accept` (it returns `None` from now on), then
    /// shut the Router down — which stops the handlers (closing the incoming
    /// channel), shuts gossip down, and closes the endpoint. Best-effort; the
    /// daemon keeps its own deadline and Bye-before-shutdown ordering.
    async fn shutdown(&self) {
        let _ = self.shutdown.send(true);
        if let Err(e) = self.router.shutdown().await {
            tracing::debug!("router shutdown: {e:#}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden bytes: the frame encoder writes exactly `u32 BE length + body` —
    /// the sync protocol's historical wire format. Locks the header so PR-2's
    /// cutover cannot silently change the wire.
    #[test]
    fn framing_golden_bytes() {
        assert_eq!(encode_frame(&[0x04]).unwrap(), vec![0, 0, 0, 1, 0x04]);
        assert_eq!(encode_frame(&[]).unwrap(), vec![0, 0, 0, 0]);
        let body = [0xAB; 300];
        let framed = encode_frame(&body).unwrap();
        assert_eq!(&framed[..4], &[0, 0, 1, 0x2C]); // 300 = 0x012C
        assert_eq!(&framed[4..], &body[..]);

        // The read-side cap rejects a malformed length, naming the cap.
        assert!(check_frame_len(MAX_FRAME).is_ok());
        let err = check_frame_len(MAX_FRAME + 1).unwrap_err().to_string();
        assert!(err.contains("exceeds"), "cap error names the cap: {err}");
    }

    /// T0: a peer id and an endpoint id are the same 32 bytes, and the
    /// conversions at this edge are exact inverses.
    #[test]
    fn id_topic_conversions() {
        let device = crate::crypto::device_from_seed(&[7u8; 32]);
        let ep = endpoint_id(&device).expect("a lait device id is a valid endpoint id");
        assert_eq!(peer_id(ep), device, "peer_id ∘ endpoint_id = identity");

        let bytes = [42u8; 32];
        assert_eq!(topic_id(Topic(bytes)).as_bytes(), &bytes);

        // A space topic derived by proto survives the Topic round-trip.
        let derived = crate::proto::topic_for_space("ws-under-test");
        let roundtrip = topic_id(Topic(*derived.as_bytes()));
        assert_eq!(roundtrip, derived);

        // Garbage is a loud error, not a bogus id.
        assert!(endpoint_id(&DeviceId::from_key_string("nope".into())).is_err());
    }
}
