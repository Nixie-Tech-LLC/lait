//! The groupchat daemon: owns the iroh endpoint, the gossip room, presence, and
//! the local control server that CLI/MCP clients drive.
//!
//! This is the transport + identity + presence skeleton the issue tracker builds
//! on (see `docs/ARCHITECTURE.md`). The chat/receipts/calls domain has been
//! pruned away; what remains is the iroh foundation: a signed-gossip room for
//! announce/presence, a liveness-probe ALPN, and the daemon/control plumbing.

use std::{
    collections::{HashMap, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream as LocalStream},
    ListenerOptions,
};
use iroh::{
    address_lookup::memory::MemoryLookup,
    endpoint::{presets, Connection},
    protocol::{AcceptError, ProtocolHandler, Router},
    Endpoint, EndpointId, SecretKey,
};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::StreamExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::Notify,
};

use crate::{
    config::{acquire_daemon_lock, load_or_create_identity, Profile},
    control::{
        control_name, Event as LogEvent, EventKind, PresenceEntry, Request, Response, StatusInfo,
    },
    presence::PeerState,
    proto::{topic_for_room, Payload, RoomTicket, SignedMessage},
};

/// ALPN for the lightweight liveness-probe protocol. A completed QUIC handshake
/// is the entire signal — there is no payload.
const PRESENCE_ALPN: &[u8] = b"groupchat/presence/0";
/// How often we broadcast a presence heartbeat. This is only a keepalive for the
/// gossip connection; presence itself is driven by neighbor events + direct
/// probes (see `presence.rs`), not by whether these are delivered.
const HEARTBEAT: Duration = Duration::from_secs(10);
/// How long a direct liveness probe waits for a QUIC handshake before concluding
/// the peer is gone.
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// How often the reaper sweeps for stale peers.
const REAP_INTERVAL: Duration = Duration::from_secs(5);
/// Drop an offline peer from the presence table entirely after this long.
const PRUNE_WINDOW: Duration = Duration::from_secs(600);
/// Default idle window before an unused daemon shuts itself down. Overridable
/// via `GROUPCHAT_IDLE_SECS` (0 disables). Keeps per-session daemons from piling
/// up, while never shutting one that has a client connected.
const IDLE_SHUTDOWN: Duration = Duration::from_secs(30 * 60);
/// How often the idle-shutdown loop checks for inactivity.
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether an idle daemon should shut down: no clients connected AND no activity
/// within the window. A zero window disables idle shutdown entirely.
fn should_idle_shutdown(active_conns: u64, idle_for: Duration, window: Duration) -> bool {
    !window.is_zero() && active_conns == 0 && idle_for >= window
}

/// Idle-shutdown window, overridable via `GROUPCHAT_IDLE_SECS` (0 disables).
fn idle_window_from_env() -> Duration {
    match std::env::var("GROUPCHAT_IDLE_SECS") {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(IDLE_SHUTDOWN),
        Err(_) => IDLE_SHUTDOWN,
    }
}

/// A peer we have heard from on the gossip topic.
#[derive(Debug, Clone)]
pub struct Peer {
    pub nick: String,
    pub last_seen: Instant,
    /// Neighbor-driven, probe-confirmed presence state (see `presence.rs`).
    pub presence: PeerState,
}

/// Accepts liveness probes (see `Node::probe_peer`). The completed QUIC
/// handshake is the entire signal; the handler just lets the connection close.
#[derive(Debug, Clone)]
struct PresencePing;

impl ProtocolHandler for PresencePing {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        connection.closed().await;
        Ok(())
    }
}

/// Append-only-ish ring buffer of presence/system events. Holds a `Notify` that
/// is fired on every push so blocking waiters (`Request::Wait`) wake the instant
/// a new event lands — event-based delivery instead of poll loops.
#[derive(Debug, Default)]
pub struct EventLog {
    seq: u64,
    events: VecDeque<LogEvent>,
    notify: Arc<Notify>,
}

impl EventLog {
    /// A handle to the wake source, fired on every `push`. Cloneable and usable
    /// without holding the log's mutex.
    pub fn notify(&self) -> Arc<Notify> {
        self.notify.clone()
    }

    pub fn push(&mut self, kind: EventKind, id: String, nick: String, text: String) {
        self.seq += 1;
        self.events.push_back(LogEvent {
            seq: self.seq,
            kind,
            id,
            nick,
            text,
            ts: now_secs(),
        });
        while self.events.len() > 1000 {
            self.events.pop_front();
        }
        // Wake everyone blocked in Request::Wait.
        self.notify.notify_waiters();
    }

    pub fn since(&self, since: u64) -> (Vec<LogEvent>, u64) {
        let out: Vec<LogEvent> = self
            .events
            .iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect();
        let last = self.events.back().map(|e| e.seq).unwrap_or(since);
        (out, last)
    }
}

/// Cheaply-cloneable shared state.
#[derive(Debug, Clone)]
pub struct Shared {
    pub nick: String,
    pub room: String,
    pub my_id: EndpointId,
    pub presence: Arc<Mutex<HashMap<EndpointId, Peer>>>,
    pub events: Arc<Mutex<EventLog>>,
}

/// The running node.
pub struct Node {
    endpoint: Endpoint,
    gossip: Gossip,
    sender: Mutex<GossipSender>,
    secret_key: SecretKey,
    router: Router,
    shared: Shared,
    shutdown: Arc<Notify>,
    /// Bumped on every (re)subscribe so stale receive loops exit.
    recv_gen: AtomicU64,
    /// Number of control connections currently open (0 ⇒ idle).
    active_conns: AtomicU64,
    /// Last time a client connected or acted — drives idle-shutdown.
    last_active: Mutex<Instant>,
    /// Idle window before self-shutdown (`Duration::ZERO` disables).
    idle_window: Duration,
}

impl Node {
    /// Update presence for a peer and return the best display nick. Emits a
    /// "is online" notification when a peer transitions from offline to online.
    fn touch(&self, id: EndpointId, nick: Option<String>) -> String {
        let now = Instant::now();
        let came_online = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(&id) {
                Some(entry) => {
                    entry.last_seen = now;
                    let came = entry.presence.seen(now);
                    if let Some(n) = nick {
                        if !n.is_empty() {
                            entry.nick = n;
                        }
                    }
                    came
                }
                None => {
                    let nm = nick
                        .filter(|n| !n.is_empty())
                        .unwrap_or_else(|| id.fmt_short().to_string());
                    p.insert(
                        id,
                        Peer {
                            nick: nm,
                            last_seen: now,
                            presence: PeerState::new_online(now),
                        },
                    );
                    true
                }
            }
        };
        let display = self.display_nick(&id);
        if came_online && id != self.shared.my_id {
            self.shared.events.lock().unwrap().push(
                EventKind::Presence,
                id.to_string(),
                display.clone(),
                format!("{display} is online"),
            );
        }
        display
    }

    /// Mark a peer offline and emit a "went offline"/"left" notification, once.
    fn mark_offline(&self, id: EndpointId, left: bool) {
        let visible = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(&id) {
                Some(peer) => peer.presence.force_offline(),
                None => false,
            }
        };
        if visible {
            self.announce_offline(id, left);
        }
    }

    /// Handle a gossip NeighborDown: drop the peer to Suspect (not offline) and
    /// launch a direct liveness probe to decide whether it actually left. This
    /// is what makes presence robust against Plumtree's tree reshuffling and the
    /// 2-node lazy-push oscillation that used to flap peers offline every ~30s.
    fn on_neighbor_down(self: Arc<Self>, id: EndpointId) {
        let became_suspect = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(&id) {
                Some(peer) => peer.presence.neighbor_down(Instant::now()),
                None => false,
            }
        };
        if became_suspect {
            tokio::spawn(self.probe_peer(id));
        }
    }

    /// Directly dial a suspect peer on the presence ALPN. A completed QUIC
    /// handshake means it is alive and reachable regardless of the gossip tree
    /// state; a failure within the timeout means it is gone.
    async fn probe_peer(self: Arc<Self>, id: EndpointId) {
        let alive =
            match tokio::time::timeout(PROBE_TIMEOUT, self.endpoint.connect(id, PRESENCE_ALPN))
                .await
            {
                Ok(Ok(conn)) => {
                    conn.close(0u32.into(), b"probe");
                    true
                }
                _ => false,
            };
        let transition = {
            let mut p = self.shared.presence.lock().unwrap();
            p.get_mut(&id)
                .and_then(|peer| peer.presence.probe_result(alive, Instant::now()))
        };
        match transition {
            Some(true) => self.announce_online(id),
            Some(false) => self.announce_offline(id, false),
            None => {}
        }
    }

    /// Emit an "is online" presence event. The caller has already transitioned
    /// the peer's state; this only notifies.
    fn announce_online(&self, id: EndpointId) {
        if id == self.shared.my_id {
            return;
        }
        let display = self.display_nick(&id);
        self.shared.events.lock().unwrap().push(
            EventKind::Presence,
            id.to_string(),
            display.clone(),
            format!("{display} is online"),
        );
    }

    /// Emit a "went offline"/"left" presence event. State is already updated.
    fn announce_offline(&self, id: EndpointId, left: bool) {
        let display = self.display_nick(&id);
        let text = if left {
            format!("{display} left")
        } else {
            format!("{display} went offline")
        };
        self.shared
            .events
            .lock()
            .unwrap()
            .push(EventKind::Presence, id.to_string(), display, text);
    }

    /// Periodically mark stale-online peers offline and prune long-dead ones —
    /// presence stays accurate without anyone managing it by hand.
    async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
            // Only reap peers that went Suspect (NeighborDown) and stayed
            // unconfirmed past the grace window. A plain connected peer is never
            // reaped on a timer, no matter how quiet — that was the old bug.
            let stale: Vec<EndpointId> = {
                let p = self.shared.presence.lock().unwrap();
                p.iter()
                    .filter(|(_, peer)| peer.presence.should_reap(now))
                    .map(|(id, _)| *id)
                    .collect()
            };
            for id in stale {
                self.mark_offline(id, false);
            }
            self.shared.presence.lock().unwrap().retain(|_, peer| {
                peer.presence.is_online() || peer.last_seen.elapsed() < PRUNE_WINDOW
            });
        }
    }

    /// Best display name for a peer: last-seen presence nick, else the short id.
    fn display_nick(&self, id: &EndpointId) -> String {
        self.shared
            .presence
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.nick.clone())
            .unwrap_or_else(|| id.fmt_short().to_string())
    }

    async fn handle_payload(&self, from: EndpointId, payload: Payload) {
        match payload {
            Payload::Hello { nick } | Payload::Presence { nick } => {
                self.touch(from, Some(nick));
            }
            Payload::Bye { nick } => {
                self.touch(from, Some(nick));
                self.mark_offline(from, true);
            }
            Payload::JoinRequest { nick } => {
                let display = self.touch(from, Some(nick.clone()));
                self.shared.events.lock().unwrap().push(
                    EventKind::Join,
                    from.to_string(),
                    display.clone(),
                    format!("{display} joined the room"),
                );
            }
        }
    }

    /// Sign and broadcast a payload on the current topic.
    async fn broadcast(&self, payload: Payload) -> Result<()> {
        let bytes = SignedMessage::sign_and_encode(&self.secret_key, &payload)?;
        let sender = self.sender.lock().unwrap().clone();
        sender
            .broadcast(bytes)
            .await
            .map_err(|e| anyhow!("broadcast failed: {e}"))?;
        Ok(())
    }

    /// (Re)subscribe to a topic, replacing the active sender/receiver. Waits
    /// until the gossip mesh has formed (at least one neighbor) so that a
    /// message broadcast right after joining is not dropped.
    async fn join_topic(self: &Arc<Self>, topic: TopicId, peers: Vec<EndpointId>) -> Result<()> {
        // We bootstrap off endpoint ids only; iroh discovery resolves a
        // reachable address from each pubkey, so no explicit addresses needed.
        let gtopic = tokio::time::timeout(
            Duration::from_secs(15),
            self.gossip.subscribe_and_join(topic, peers),
        )
        .await
        .map_err(|_| anyhow!("timed out connecting to the room's peers"))?
        .map_err(|e| anyhow!("subscribe_and_join: {e}"))?;
        let (sender, receiver) = gtopic.split();
        *self.sender.lock().unwrap() = sender;
        let gen = self.recv_gen.fetch_add(1, Ordering::SeqCst) + 1;
        tokio::spawn(self.clone().recv_loop(receiver, gen));
        Ok(())
    }

    async fn recv_loop(self: Arc<Self>, mut receiver: GossipReceiver, gen: u64) {
        loop {
            if self.recv_gen.load(Ordering::SeqCst) != gen {
                break; // a newer subscription replaced us
            }
            match receiver.try_next().await {
                Ok(Some(event)) => match event {
                    Event::Received(msg) => {
                        if let Ok((from, payload)) = SignedMessage::verify_and_decode(&msg.content)
                        {
                            self.handle_payload(from, payload).await;
                        }
                    }
                    Event::NeighborUp(id) => {
                        self.touch(id, None);
                    }
                    // A NeighborDown may mean the peer left, OR (in a larger
                    // mesh) just that it is no longer one of our *direct* gossip
                    // neighbors. Don't trust it outright: drop to Suspect and
                    // confirm with a direct probe before declaring offline.
                    Event::NeighborDown(id) => {
                        self.clone().on_neighbor_down(id);
                    }
                    Event::Lagged => {}
                },
                Ok(None) => break,
                Err(_) => break,
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(HEARTBEAT);
        loop {
            interval.tick().await;
            if let Err(e) = self
                .broadcast(Payload::Presence {
                    nick: self.shared.nick.clone(),
                })
                .await
            {
                tracing::debug!("heartbeat broadcast failed: {e}");
            }
        }
    }

    async fn dispatch(self: Arc<Self>, req: Request) -> Result<Response> {
        match req {
            Request::Status => {
                let online_peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|p| p.presence.is_online())
                    .count();
                Ok(Response::Status(StatusInfo {
                    id: self.shared.my_id.to_string(),
                    nick: self.shared.nick.clone(),
                    room: self.shared.room.clone(),
                    online_peers,
                }))
            }
            Request::Id => Ok(Response::Text {
                text: self.shared.my_id.to_string(),
            }),
            Request::Invite => {
                let ticket = RoomTicket {
                    room: self.shared.room.clone(),
                    host: self.shared.my_id,
                    host_nick: self.shared.nick.clone(),
                };
                // Return the bare token — clean for agents to pass to `connect`.
                // The CLI presents the link form + clipboard for humans.
                Ok(Response::Text {
                    text: ticket.to_string(),
                })
            }
            Request::Join { ticket } => {
                let ticket: RoomTicket = ticket.parse().context("parse room ticket")?;
                self.join_topic(ticket.topic(), vec![ticket.host]).await?;
                self.broadcast(Payload::JoinRequest {
                    nick: self.shared.nick.clone(),
                })
                .await
                .ok();
                Ok(Response::Ok {
                    message: Some("joined room and sent join request".to_string()),
                })
            }
            Request::Connect { ticket } => {
                let ticket: RoomTicket = ticket.parse().context("parse room ticket")?;
                self.join_topic(ticket.topic(), vec![ticket.host]).await?;
                self.broadcast(Payload::JoinRequest {
                    nick: self.shared.nick.clone(),
                })
                .await
                .ok();
                Ok(Response::Ok {
                    message: Some("connected to room \u{2014} you're live".to_string()),
                })
            }
            Request::Log { since } => {
                let (events, last) = self.shared.events.lock().unwrap().since(since);
                Ok(Response::Events { events, last })
            }
            Request::Wait { since, timeout_ms } => {
                // Event-based delivery: block until an event newer than `since`
                // lands (woken by EventLog::push) or the timeout fires. No busy
                // poll — the connection task simply parks until notified.
                let timeout_ms = timeout_ms.clamp(0, 300_000);
                let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
                let notify = self.shared.events.lock().unwrap().notify();
                loop {
                    // Register interest *before* re-checking so a push between
                    // the check and the await can't be lost.
                    let notified = notify.notified();
                    tokio::pin!(notified);
                    notified.as_mut().enable();

                    let (events, last) = self.shared.events.lock().unwrap().since(since);
                    if !events.is_empty() {
                        return Ok(Response::Events { events, last });
                    }

                    tokio::select! {
                        _ = &mut notified => continue,
                        _ = tokio::time::sleep_until(deadline) => {
                            let (events, last) = self.shared.events.lock().unwrap().since(since);
                            return Ok(Response::Events { events, last });
                        }
                    }
                }
            }
            Request::Who => {
                let peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(id, p)| PresenceEntry {
                        id: id.to_string(),
                        nick: p.nick.clone(),
                        online: p.presence.is_online(),
                        last_seen_secs: p.last_seen.elapsed().as_secs(),
                    })
                    .collect();
                Ok(Response::Who { peers })
            }
            Request::Stop => {
                let s = self.shutdown.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    s.notify_one();
                });
                Ok(Response::Ok {
                    message: Some("shutting down".to_string()),
                })
            }
        }
    }

    /// Count the connection for idle-shutdown, then handle it. Keeping the count
    /// accurate is what lets a daemon nap only when truly unused — never while a
    /// client (a `watch`/`wait`, or any in-flight request) is connected.
    async fn handle_conn(self: Arc<Self>, stream: LocalStream) {
        self.active_conns.fetch_add(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
        self.clone().handle_conn_inner(stream).await;
        self.active_conns.fetch_sub(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// Shut the daemon down once it has been idle (no open connections and no
    /// activity) for `idle_window`. Disabled when the window is zero.
    async fn idle_shutdown_loop(self: Arc<Self>) {
        if self.idle_window.is_zero() {
            return;
        }
        let mut interval = tokio::time::interval(IDLE_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            let active = self.active_conns.load(Ordering::SeqCst);
            let idle_for = self.last_active.lock().unwrap().elapsed();
            if should_idle_shutdown(active, idle_for, self.idle_window) {
                tracing::info!("idle {idle_for:?} with no clients — shutting down");
                self.shutdown.notify_one();
                break;
            }
        }
    }

    async fn handle_conn_inner(self: Arc<Self>, stream: LocalStream) {
        let (read_half, mut write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => match self.dispatch(req).await {
                Ok(r) => r,
                Err(e) => Response::Error {
                    message: format!("{e:#}"),
                },
            },
            Err(e) => Response::Error {
                message: format!("bad request: {e}"),
            },
        };
        let mut out = serde_json::to_string(&resp).unwrap_or_else(|_| {
            "{\"status\":\"error\",\"message\":\"encode failure\"}".to_string()
        });
        out.push('\n');
        let _ = write_half.write_all(out.as_bytes()).await;
        let _ = write_half.flush().await;
    }
}

/// Build and run the daemon until a Stop request arrives.
pub async fn run_daemon(home: PathBuf) -> Result<()> {
    // Single-instance guard: at most one daemon per home. Held for the whole
    // daemon lifetime; released by the OS on exit/crash. A duplicate spawned
    // during the startup race fails here and bails instead of clobbering the
    // live daemon's socket.
    let _daemon_lock = acquire_daemon_lock(&home)?;

    let secret_key = load_or_create_identity(&home)?;
    let profile = Profile::load(&home)?;

    let memory_lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .address_lookup(memory_lookup.clone())
        .bind()
        .await?;
    let my_id = endpoint.id();

    let gossip = Gossip::builder().spawn(endpoint.clone());

    let shared = Shared {
        nick: profile.nick.clone(),
        room: profile.room.clone(),
        my_id,
        presence: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(EventLog::default())),
    };

    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(PRESENCE_ALPN, PresencePing)
        .spawn();

    // Wait until we have a home relay so our advertised address is dialable.
    endpoint.online().await;

    // Subscribe to our room topic. Bootstrap is empty here; peers join by
    // ticket (`Join`/`Connect`), which dials the host directly.
    let topic = topic_for_room(&profile.room);
    let gtopic = gossip
        .subscribe(topic, vec![])
        .await
        .map_err(|e| anyhow!("subscribe to room: {e}"))?;
    let (sender, receiver) = gtopic.split();

    let node = Arc::new(Node {
        endpoint,
        gossip,
        sender: Mutex::new(sender),
        secret_key,
        router,
        shared,
        shutdown: Arc::new(Notify::new()),
        recv_gen: AtomicU64::new(1),
        active_conns: AtomicU64::new(0),
        last_active: Mutex::new(Instant::now()),
        idle_window: idle_window_from_env(),
    });

    tokio::spawn(node.clone().recv_loop(receiver, 1));
    tokio::spawn(node.clone().heartbeat_loop());
    tokio::spawn(node.clone().reaper_loop());
    tokio::spawn(node.clone().idle_shutdown_loop());

    // announce ourselves
    node.broadcast(Payload::Hello {
        nick: node.shared.nick.clone(),
    })
    .await
    .ok();

    // control server — a local IPC channel (unix socket / windows named pipe)
    let control = control_name(&home)?;
    // On unix the socket is a filesystem entry; clear any stale one a crashed
    // daemon left behind so bind doesn't fail with AddrInUse. (No-op on Windows,
    // where named pipes are reclaimed by the OS when the last handle closes.)
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::config::socket_path(&home));
    let listener = ListenerOptions::new()
        .name(control)
        .create_tokio()
        .context("bind control channel")?;

    tracing::info!(
        "groupchat daemon online as {my_id} in room '{}'",
        profile.room
    );

    let shutdown = node.shutdown.clone();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accept = listener.accept() => {
                match accept {
                    Ok(stream) => {
                        let n = node.clone();
                        tokio::spawn(async move { n.handle_conn(stream).await; });
                    }
                    Err(e) => tracing::warn!("control accept error: {e}"),
                }
            }
        }
    }

    // Tell the room we're going offline so peers update presence immediately
    // instead of waiting for our heartbeat to lapse. Give gossip a moment to
    // flush the message to neighbors before we tear the router down.
    node.broadcast(Payload::Bye {
        nick: node.shared.nick.clone(),
    })
    .await
    .ok();
    tokio::time::sleep(Duration::from_millis(500)).await;

    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::config::socket_path(&home));
    node.router.shutdown().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn idle_shutdown_only_when_unused_and_past_window() {
        let w = Duration::from_secs(60);
        // idle (no conns) and past the window → shut down
        assert!(should_idle_shutdown(0, Duration::from_secs(61), w));
        // idle but not yet past the window → keep running
        assert!(!should_idle_shutdown(0, Duration::from_secs(30), w));
        // a client is connected → never shut down, however long
        assert!(!should_idle_shutdown(1, Duration::from_secs(600), w));
        // zero window disables idle shutdown
        assert!(!should_idle_shutdown(
            0,
            Duration::from_secs(600),
            Duration::ZERO
        ));
    }
}
