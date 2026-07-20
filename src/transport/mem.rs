//! An **in-process, deterministic** [`Transport`] — the whole network in one
//! process, over channels, with no iroh and no sockets.
//!
//! This is what makes the *real daemon* testable hermetically: build N
//! [`MemTransport`]s off one [`MemNet`] switchboard, hand each to a daemon, and
//! they dial/gossip/accept through the same code paths as production — but the
//! "network" is a `HashMap` and some channels, so it is offline, instant, and
//! reproducible on every OS. It is the seed of the deterministic network
//! simulator (controllable delivery: drop/delay/partition) sketched in the
//! testing scope; this draft is the connectivity core.
//!
//! Contract fidelity notes (the iroh impl is the contract where they diverge):
//! frames travel whole over channels, so mem can never truncate — the
//! *truncation consequence* of skipping [`Stream::wait_closed`] is only
//! observable on iroh, but the *ordering* obligation (the accepter parks until
//! the dialer is done and drops) is modeled faithfully here. `connect` succeeds
//! whenever the peer is *registered* on the switchboard; liveness is
//! membership, so a "down" peer must have been [`Transport::shutdown`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};

use super::{
    Alpn, GossipEvent, GossipReceiver, GossipSender, Incoming, PeerId, Stream, Topic, Transport,
};

/// The shared switchboard every in-memory peer is wired to. Cloneable; all clones
/// share one registry, so peers created from it can reach each other.
#[derive(Clone, Default)]
pub struct MemNet(Arc<StdMutex<Inner>>);

#[derive(Default)]
struct Inner {
    /// Inbound-connection inbox per peer.
    peers: HashMap<PeerId, mpsc::UnboundedSender<Incoming>>,
    /// One broadcast bus per gossip topic.
    topics: HashMap<Topic, broadcast::Sender<TopicMsg>>,
}

#[derive(Clone)]
enum TopicMsg {
    Join(PeerId),
    Data(PeerId, Vec<u8>),
}

impl MemNet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach a new peer `id` to this network and return its transport.
    pub fn peer(&self, id: PeerId) -> MemTransport {
        let (tx, rx) = mpsc::unbounded_channel();
        self.0.lock().unwrap().peers.insert(id.clone(), tx);
        MemTransport {
            id,
            net: self.clone(),
            incoming: TokioMutex::new(rx),
        }
    }

    fn topic_bus(&self, topic: Topic) -> broadcast::Sender<TopicMsg> {
        self.0
            .lock()
            .unwrap()
            .topics
            .entry(topic)
            .or_insert_with(|| broadcast::channel(256).0)
            .clone()
    }
}

/// One peer's view of the in-memory network.
pub struct MemTransport {
    id: PeerId,
    net: MemNet,
    incoming: TokioMutex<mpsc::UnboundedReceiver<Incoming>>,
}

/// A framed duplex stream backed by a pair of channels.
struct MemStream {
    /// `None` after [`Stream::finish`]: dropping the sender is the end-of-stream
    /// marker the peer's `recv` sees as `Ok(None)` once drained — real FIN
    /// semantics, matching the iroh impl.
    tx: Option<mpsc::UnboundedSender<Vec<u8>>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
    /// Held only so its drop marks *this whole handle* gone — the peer's
    /// [`Stream::wait_closed`] parks on it. Distinct from `tx` because `finish`
    /// must drop `tx` without counting as "closed".
    _alive: mpsc::UnboundedReceiver<()>,
    /// Never sent on; its `closed()` resolves exactly when the peer drops its
    /// `_alive` half, i.e. drops its whole stream handle.
    peer_alive: mpsc::UnboundedSender<()>,
}

fn duplex() -> (MemStream, MemStream) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    let (a_alive_tx, a_alive_rx) = mpsc::unbounded_channel();
    let (b_alive_tx, b_alive_rx) = mpsc::unbounded_channel();
    (
        MemStream {
            tx: Some(a_tx),
            rx: b_rx,
            _alive: a_alive_rx,
            peer_alive: b_alive_tx,
        },
        MemStream {
            tx: Some(b_tx),
            rx: a_rx,
            _alive: b_alive_rx,
            peer_alive: a_alive_tx,
        },
    )
}

#[async_trait]
impl Stream for MemStream {
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .as_ref()
            .ok_or_else(|| anyhow!("stream already finished"))?
            .send(frame.to_vec())
            .map_err(|_| anyhow!("peer stream closed"))
    }
    async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        // Whole frames over a channel: an end is always at a frame boundary, so
        // mem never surfaces the mid-frame truncation `Err` the iroh impl can.
        Ok(self.rx.recv().await)
    }
    async fn finish(&mut self) -> Result<()> {
        self.tx = None; // dropping the sender delivers end-of-stream after drain
        Ok(())
    }
    async fn wait_closed(&mut self) {
        // Resolves when the peer drops its `_alive` receiver — which happens
        // only when the peer drops its whole stream handle. The ordering half
        // of the accepter contract (park until the dialer is done and drops).
        self.peer_alive.closed().await;
    }
}

/// The send half of a joined room: a publisher on the topic's broadcast bus.
struct MemGossipSender {
    me: PeerId,
    bus: broadcast::Sender<TopicMsg>,
}

#[async_trait]
impl GossipSender for MemGossipSender {
    async fn broadcast(&self, bytes: Vec<u8>) -> Result<()> {
        // Delivery to zero subscribers is fine (a solo node broadcasting).
        let _ = self.bus.send(TopicMsg::Data(self.me.clone(), bytes));
        Ok(())
    }
}

/// The receive half: a subscriber on the topic's broadcast bus.
struct MemGossipReceiver {
    me: PeerId,
    rx: broadcast::Receiver<TopicMsg>,
}

#[async_trait]
impl GossipReceiver for MemGossipReceiver {
    async fn next(&mut self) -> Option<GossipEvent> {
        loop {
            match self.rx.recv().await {
                Ok(TopicMsg::Data(from, bytes)) if from != self.me => {
                    return Some(GossipEvent::Received { from, bytes })
                }
                Ok(TopicMsg::Join(p)) if p != self.me => return Some(GossipEvent::NeighborUp(p)),
                Ok(_) => continue, // our own frames
                Err(broadcast::error::RecvError::Lagged(_)) => continue, // lossy by contract
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }
    async fn joined(&mut self) -> Result<()> {
        Ok(()) // the switchboard is always joined
    }
}

#[async_trait]
impl Transport for MemTransport {
    fn my_id(&self) -> PeerId {
        self.id.clone()
    }

    fn learn(&self, _peer: PeerId, _addrs: &[SocketAddr]) {
        // No-op: the switchboard resolves every peer by id.
    }

    async fn connect(&self, peer: PeerId, alpn: Alpn) -> Result<Box<dyn Stream>> {
        let inbox = self
            .net
            .0
            .lock()
            .unwrap()
            .peers
            .get(&peer)
            .cloned()
            .ok_or_else(|| anyhow!("no such peer on the in-memory network"))?;
        let (mine, theirs) = duplex();
        inbox
            .send(Incoming {
                from: self.id.clone(),
                alpn: alpn.to_vec(),
                stream: Box::new(theirs),
            })
            .map_err(|_| anyhow!("peer is gone"))?;
        Ok(Box::new(mine))
    }

    async fn accept(&self) -> Option<Incoming> {
        self.incoming.lock().await.recv().await
    }

    fn advertised_addrs(&self) -> Vec<SocketAddr> {
        Vec::new() // the switchboard resolves by id — tickets stay address-free
    }

    async fn subscribe(
        &self,
        topic: Topic,
        _bootstrap: &[PeerId],
    ) -> Result<(Box<dyn GossipSender>, Box<dyn GossipReceiver>)> {
        let bus = self.net.topic_bus(topic);
        let rx = bus.subscribe();
        // Announce ourselves so already-subscribed peers see a NeighborUp.
        let _ = bus.send(TopicMsg::Join(self.id.clone()));
        Ok((
            Box::new(MemGossipSender {
                me: self.id.clone(),
                bus,
            }),
            Box::new(MemGossipReceiver {
                me: self.id.clone(),
                rx,
            }),
        ))
    }

    async fn shutdown(&self) {
        self.net.0.lock().unwrap().peers.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn id(seed: u8) -> PeerId {
        crate::crypto::device_from_seed(&[seed; 32])
    }

    #[tokio::test]
    async fn two_mem_peers_gossip_and_dial() {
        let net = MemNet::new();
        let a = net.peer(id(1));
        let b = net.peer(id(2));
        let topic = Topic([7u8; 32]);

        // B subscribes first, then A — A's Join should reach B as a NeighborUp.
        let (_b_send, mut b_recv) = b.subscribe(topic, &[]).await.unwrap();
        let (a_send, mut a_recv) = a.subscribe(topic, &[]).await.unwrap();
        // joined() resolves immediately — the switchboard is always joined.
        tokio::time::timeout(Duration::from_secs(1), a_recv.joined())
            .await
            .expect("joined must not block on mem")
            .unwrap();
        match b_recv.next().await {
            Some(GossipEvent::NeighborUp(p)) => assert_eq!(p, id(1)),
            other => panic!("expected NeighborUp(a), got {other:?}"),
        }

        // A broadcasts through the split-off sender WHILE its receiver is parked
        // in next() on another task — the concurrency shape the daemon needs
        // (heartbeat broadcasts while recv_loop consumes).
        let a_reader = tokio::spawn(async move { a_recv.next().await });
        a_send.broadcast(b"announce".to_vec()).await.unwrap();
        match b_recv.next().await {
            Some(GossipEvent::Received { from, bytes }) => {
                assert_eq!(from, id(1));
                assert_eq!(bytes, b"announce");
            }
            other => panic!("expected Received, got {other:?}"),
        }
        a_reader.abort(); // A never receives its own frames; stop the parked task.

        // Tickets stay address-free on the switchboard.
        assert!(a.advertised_addrs().is_empty());

        // A dials B directly; B accepts; a frame round-trips both ways.
        let b_accept = tokio::spawn(async move {
            let inc = b.accept().await.expect("incoming");
            assert_eq!(inc.from, id(1));
            assert_eq!(inc.alpn, crate::sync::SYNC_ALPN);
            let mut s = inc.stream;
            assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"ping"[..]));
            s.send(b"pong").await.unwrap();
        });
        let mut s = a.connect(id(2), crate::sync::SYNC_ALPN).await.unwrap();
        s.send(b"ping").await.unwrap();
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"pong"[..]));
        b_accept.await.unwrap();
    }

    /// `finish` delivers a real end-of-stream: the peer drains the queued
    /// frames, then sees `Ok(None)` — and a send after `finish` is an error.
    #[tokio::test]
    async fn finish_delivers_end_of_stream_after_drain() {
        let net = MemNet::new();
        let a = net.peer(id(1));
        let b = net.peer(id(2));

        let b_task = tokio::spawn(async move {
            let mut s = b.accept().await.expect("incoming").stream;
            assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"one"[..]));
            assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"two"[..]));
            assert_eq!(s.recv().await.unwrap(), None, "clean end after drain");
        });
        let mut s = a.connect(id(2), crate::sync::SYNC_ALPN).await.unwrap();
        s.send(b"one").await.unwrap();
        s.send(b"two").await.unwrap();
        s.finish().await.unwrap();
        assert!(s.send(b"late").await.is_err(), "send after finish errors");
        b_task.await.unwrap();
    }

    /// The ordering half of the accepter contract (the part mem CAN model):
    /// `wait_closed` does not resolve while the dialer still holds its stream,
    /// and resolves promptly once the dialer drops it.
    #[tokio::test]
    async fn wait_closed_parks_until_dialer_drops() {
        let net = MemNet::new();
        let a = net.peer(id(1));
        let b = net.peer(id(2));

        let b_task = tokio::spawn(async move {
            let mut s = b.accept().await.expect("incoming").stream;
            s.send(b"payload").await.unwrap();
            s.finish().await.unwrap();
            // Must still be parked: the dialer holds its handle for 200ms.
            let parked = tokio::time::timeout(Duration::from_millis(100), s.wait_closed()).await;
            assert!(
                parked.is_err(),
                "wait_closed resolved while the dialer still held the stream"
            );
            tokio::time::timeout(Duration::from_secs(5), s.wait_closed())
                .await
                .expect("wait_closed must resolve after the dialer drops");
        });

        let mut s = a.connect(id(2), crate::sync::SYNC_ALPN).await.unwrap();
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"payload"[..]));
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(s); // the dialer's "done" signal
        b_task.await.unwrap();
    }

    /// Liveness is switchboard membership: a shutdown peer fails `connect`.
    #[tokio::test]
    async fn connect_fails_after_peer_shutdown() {
        let net = MemNet::new();
        let a = net.peer(id(1));
        let b = net.peer(id(2));
        b.shutdown().await;
        assert!(a.connect(id(2), crate::sync::SYNC_ALPN).await.is_err());
    }
}
