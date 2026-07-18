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

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex as StdMutex};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use tokio::sync::{broadcast, mpsc, Mutex as TokioMutex};

use super::{Alpn, GossipEvent, GossipRoom, Incoming, PeerId, Stream, Topic, Transport};

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
    tx: mpsc::UnboundedSender<Vec<u8>>,
    rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

fn duplex() -> (MemStream, MemStream) {
    let (a_tx, a_rx) = mpsc::unbounded_channel();
    let (b_tx, b_rx) = mpsc::unbounded_channel();
    (
        MemStream { tx: a_tx, rx: b_rx },
        MemStream { tx: b_tx, rx: a_rx },
    )
}

#[async_trait]
impl Stream for MemStream {
    async fn send(&mut self, frame: &[u8]) -> Result<()> {
        self.tx
            .send(frame.to_vec())
            .map_err(|_| anyhow!("peer stream closed"))
    }
    async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        Ok(self.rx.recv().await)
    }
    async fn finish(&mut self) -> Result<()> {
        Ok(()) // dropping `tx` signals end-of-stream to the peer
    }
}

/// A joined room: a subscriber on the topic's broadcast bus.
struct MemRoom {
    me: PeerId,
    bus: broadcast::Sender<TopicMsg>,
    rx: broadcast::Receiver<TopicMsg>,
}

#[async_trait]
impl GossipRoom for MemRoom {
    async fn broadcast(&self, bytes: Vec<u8>) -> Result<()> {
        // Delivery to zero subscribers is fine (a solo node broadcasting).
        let _ = self.bus.send(TopicMsg::Data(self.me.clone(), bytes));
        Ok(())
    }
    async fn next(&mut self) -> Option<GossipEvent> {
        loop {
            match self.rx.recv().await {
                Ok(TopicMsg::Data(from, bytes)) if from != self.me => {
                    return Some(GossipEvent::Received { from, bytes })
                }
                Ok(TopicMsg::Join(p)) if p != self.me => return Some(GossipEvent::NeighborUp(p)),
                Ok(_) => continue, // our own frames
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
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

    async fn subscribe(&self, topic: Topic, _bootstrap: &[PeerId]) -> Result<Box<dyn GossipRoom>> {
        let bus = self.net.topic_bus(topic);
        let rx = bus.subscribe();
        // Announce ourselves so already-subscribed peers see a NeighborUp.
        let _ = bus.send(TopicMsg::Join(self.id.clone()));
        Ok(Box::new(MemRoom {
            me: self.id.clone(),
            bus,
            rx,
        }))
    }

    async fn shutdown(&self) {
        self.net.0.lock().unwrap().peers.remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> PeerId {
        crate::crypto::user_from_seed(&[seed; 32])
    }

    #[tokio::test]
    async fn two_mem_peers_gossip_and_dial() {
        let net = MemNet::new();
        let a = net.peer(id(1));
        let b = net.peer(id(2));
        let topic = Topic([7u8; 32]);

        // B subscribes first, then A — A's Join should reach B as a NeighborUp.
        let mut room_b = b.subscribe(topic, &[]).await.unwrap();
        let room_a = a.subscribe(topic, &[]).await.unwrap();
        match room_b.next().await {
            Some(GossipEvent::NeighborUp(p)) => assert_eq!(p, id(1)),
            other => panic!("expected NeighborUp(a), got {other:?}"),
        }

        // A broadcasts; B receives it (and never its own frames).
        room_a.broadcast(b"announce".to_vec()).await.unwrap();
        match room_b.next().await {
            Some(GossipEvent::Received { from, bytes }) => {
                assert_eq!(from, id(1));
                assert_eq!(bytes, b"announce");
            }
            other => panic!("expected Received, got {other:?}"),
        }

        // A dials B directly; B accepts; a frame round-trips both ways.
        let b_accept = tokio::spawn(async move {
            let inc = b.accept().await.expect("incoming");
            assert_eq!(inc.from, id(1));
            assert_eq!(inc.alpn, b"lait/sync/1");
            let mut s = inc.stream;
            assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"ping"[..]));
            s.send(b"pong").await.unwrap();
        });
        let mut s = a.connect(id(2), b"lait/sync/1").await.unwrap();
        s.send(b"ping").await.unwrap();
        assert_eq!(s.recv().await.unwrap().as_deref(), Some(&b"pong"[..]));
        b_accept.await.unwrap();
    }
}
