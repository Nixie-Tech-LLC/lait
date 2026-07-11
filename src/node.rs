//! The groupchat daemon: owns the iroh endpoint, the gossip room, presence, the
//! Loro-CRDT tracker core ([`crate::tracker`]), and the local control server that
//! CLI/TUI/MCP clients drive.
//!
//! The iroh transport (signed-gossip room for announce/presence, a liveness
//! probe ALPN, the daemon/control plumbing) is the P1 networking substrate. The
//! P0 tracker rides on top: the daemon is the **only** owner of the Loro docs
//! (UI.md §1), and every surface is a thin Layer-B client of it.
//!
//! **Doorbells (S§7.5, UI.md §4.1–§4.2).** A mutation produces a
//! [`crate::tracker::DirtySet`]; the daemon stamps it with a per-boot `epoch` and
//! a per-session `seq`, pushes it onto a bounded ring, and wakes every parked
//! [`Request::Subscribe`] stream. `seq` is never persisted; the first frame of
//! every Subscribe is a `Reset`, which unifies first-connect / reconnect /
//! restart / ring-overrun into one rebaseline path (UI.md §4.1).

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
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
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::Notify,
};

use crate::{
    config::{acquire_daemon_lock, load_or_create_identity, Profile},
    control::{
        control_name, Doorbell, Event as LogEvent, EventKind, PresenceEntry, Request, Response,
        StatusInfo,
    },
    ids::{SystemUlidSource, UserId},
    presence::PeerState,
    proto::{topic_for_room, Payload, RoomTicket, SignedMessage},
    store::Store,
    tracker::{DirtySet, Tracker},
};

const PRESENCE_ALPN: &[u8] = b"groupchat/presence/0";
const HEARTBEAT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_INTERVAL: Duration = Duration::from_secs(5);
const PRUNE_WINDOW: Duration = Duration::from_secs(600);
const IDLE_SHUTDOWN: Duration = Duration::from_secs(30 * 60);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Bound on the doorbell ring — holds the last ~1000 *batches* (UI.md §4.2).
const DOORBELL_RING: usize = 1000;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Whether the daemon should idle-shut-down now. A node that is serving a mesh
/// (`mesh_member` — it currently sees a peer, or has ever persisted one) stays
/// up regardless of local client activity so peers can always pull its changes
/// (DUR-3); only a solo/ephemeral node — one auto-spawned for a one-off CLI
/// command that never met a peer — idles out after the window with no clients.
/// A zero window disables idle-shutdown entirely (GROUPCHAT_IDLE_SECS=0).
fn should_idle_shutdown(
    active_conns: u64,
    idle_for: Duration,
    window: Duration,
    mesh_member: bool,
) -> bool {
    !window.is_zero() && !mesh_member && active_conns == 0 && idle_for >= window
}

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

fn peers_path(home: &Path) -> PathBuf {
    home.join("peers.json")
}

/// Load the persisted set of previously-seen peer endpoints, to seed the gossip
/// bootstrap on (re)start (DUR-1). iroh discovery resolves a dialable address
/// from each `EndpointId`, so the ids alone are enough to reconnect — a fresh
/// daemon no longer re-enters the mesh with an empty bootstrap set and waits
/// passively to be re-announced to. Our own id is filtered out.
fn load_bootstrap_peers(home: &Path, me: EndpointId) -> Vec<EndpointId> {
    let Ok(data) = std::fs::read_to_string(peers_path(home)) else {
        return Vec::new();
    };
    let ids: Vec<EndpointId> = serde_json::from_str(&data).unwrap_or_default();
    ids.into_iter().filter(|id| *id != me).collect()
}

/// Persist the set of currently-known peer endpoints (best-effort) so the next
/// daemon start can bootstrap from them.
fn save_known_peers(home: &Path, peers: &[EndpointId]) {
    if let Ok(data) = serde_json::to_string(peers) {
        let _ = std::fs::write(peers_path(home), data);
    }
}

/// A pinned always-on **seed** peer — the client-side half of the seed role
/// (ARCHITECTURE §10). Unlike the opportunistic `peers.json` bootstrap set
/// (DUR-1), these pins are **explicit and sticky**: they always seed the gossip
/// bootstrap and are eagerly pulled on startup, so a client converges through
/// its seed even when no other peer is online. A pin grants **no trust** — the
/// seed is a bootstrap/backfill anchor only; every signed op is still validated
/// against the genesis keys carried in the ticket (A§6/A§10).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRecord {
    pub id: EndpointId,
    #[serde(default)]
    pub nick: String,
    #[serde(default)]
    pub workspace: String,
}

fn seeds_path(home: &Path) -> PathBuf {
    home.join("seeds.json")
}

/// Load the pinned seed registry (best-effort; empty when absent or corrupt).
fn load_seeds(home: &Path) -> Vec<SeedRecord> {
    let Ok(data) = std::fs::read_to_string(seeds_path(home)) else {
        return Vec::new();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

/// Persist the pinned seed registry (best-effort).
fn save_seeds(home: &Path, seeds: &[SeedRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(seeds) {
        let _ = std::fs::write(seeds_path(home), data);
    }
}

/// The pinned seeds' endpoint ids, minus our own — the sticky half of the gossip
/// bootstrap set. Our own id is filtered out (dialing ourselves is pointless).
fn seed_ids(home: &Path, me: EndpointId) -> Vec<EndpointId> {
    load_seeds(home)
        .into_iter()
        .map(|s| s.id)
        .filter(|id| *id != me)
        .collect()
}

/// Upsert a seed into the registry keyed by endpoint id (the id is the identity;
/// nick/workspace refresh in place). Returns true when it was newly pinned.
fn upsert_seed(home: &Path, rec: SeedRecord) -> bool {
    let mut seeds = load_seeds(home);
    if let Some(existing) = seeds.iter_mut().find(|s| s.id == rec.id) {
        existing.nick = rec.nick;
        existing.workspace = rec.workspace;
        save_seeds(home, &seeds);
        false
    } else {
        seeds.push(rec);
        save_seeds(home, &seeds);
        true
    }
}

/// Unpin seeds matching `needle` — a full endpoint id, an id prefix, or a nick.
/// Returns how many were removed.
fn remove_seed(home: &Path, needle: &str) -> usize {
    let mut seeds = load_seeds(home);
    let before = seeds.len();
    seeds.retain(|s| {
        let id = s.id.to_string();
        !(id == needle || (needle.len() >= 6 && id.starts_with(needle)) || s.nick == needle)
    });
    let removed = before - seeds.len();
    if removed > 0 {
        save_seeds(home, &seeds);
    }
    removed
}

/// A peer we have heard from on the gossip topic.
#[derive(Debug, Clone)]
pub struct Peer {
    pub nick: String,
    pub last_seen: Instant,
    pub presence: PeerState,
    /// Advertised three-state presence: `true` ⇒ up but AFK (UI.md §4.5). Only
    /// meaningful while `presence.is_online()`.
    pub away: bool,
}

#[derive(Debug, Clone)]
struct PresencePing;

impl ProtocolHandler for PresencePing {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        connection.closed().await;
        Ok(())
    }
}

/// Accepts the P1 sync ALPN and serves a peer's catalog-first **pull**
/// ([`crate::sync::serve`]). A pull never mutates our state, so this is
/// read-only and rings no doorbell.
#[derive(Clone)]
struct SyncHandler {
    tracker: Arc<Mutex<Tracker>>,
}

impl std::fmt::Debug for SyncHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SyncHandler")
    }
}

impl ProtocolHandler for SyncHandler {
    async fn accept(&self, connection: Connection) -> std::result::Result<(), AcceptError> {
        // `serve` finishes its send stream but `send.finish()` only queues the
        // FIN — it does NOT wait for the data to be delivered. If we returned
        // here the `Connection` would drop and send CONNECTION_CLOSE, truncating
        // the trailing `DocUpdate`/`EndDocs` frames before the puller drains them
        // (issue-doc bodies would silently never sync). Keep the connection alive
        // until the puller has read everything and closes it — same as the
        // presence handler above.
        let keepalive = connection.clone();
        if let Err(e) = crate::sync::serve(connection, &self.tracker).await {
            tracing::debug!("sync serve error: {e:#}");
        }
        keepalive.closed().await;
        Ok(())
    }
}

/// Append-only-ish ring buffer of presence/system events (P1 transport surface).
#[derive(Debug, Default)]
pub struct EventLog {
    seq: u64,
    events: VecDeque<LogEvent>,
    notify: Arc<Notify>,
}

impl EventLog {
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

/// The doorbell ring — per-session `seq`, per-boot `epoch`, bounded batches.
#[derive(Debug)]
pub struct DoorbellRing {
    epoch: u64,
    seq: u64,
    ring: VecDeque<Doorbell>,
}

impl DoorbellRing {
    fn new(epoch: u64) -> Self {
        Self {
            epoch,
            seq: 0,
            ring: VecDeque::new(),
        }
    }
    /// The oldest retained seq (for stale-cursor detection).
    fn oldest(&self) -> u64 {
        self.ring.front().map(|f| f.seq).unwrap_or(self.seq)
    }
}

/// Whether a Subscribe stream must emit a `Reset` and rebaseline: the client's
/// `cursor` has fallen off the back of the ring, so the next frame it needs
/// (`cursor + 1`) is older than the oldest one still retained. When
/// `cursor + 1 == oldest` the ring still holds the exact next frame, so no reset
/// (S§7.5, UI.md §4.1). Pure and side-effect-free so the ring-overrun invariant
/// is unit-testable without driving the async socket loop.
fn subscribe_should_reset(cursor: u64, oldest: u64) -> bool {
    cursor + 1 < oldest
}

/// Cheaply-cloneable shared presence state.
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
    recv_gen: AtomicU64,
    active_conns: AtomicU64,
    last_active: Mutex<Instant>,
    idle_window: Duration,
    /// The Loro-CRDT tracker core (P0). The daemon is its only owner.
    tracker: Arc<Mutex<Tracker>>,
    /// The doorbell ring + its wake source (S§7.5).
    doorbell: Arc<Mutex<DoorbellRing>>,
    doorbell_notify: Arc<Notify>,
    /// Peers we currently have an in-flight sync pull to (dedupes announce storms).
    syncing: Arc<Mutex<HashSet<EndpointId>>>,
    /// This node's home dir — used to persist the bootstrap peer set (DUR-1).
    home: PathBuf,
}

impl Node {
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
                            away: false,
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

    async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
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

    fn display_nick(&self, id: &EndpointId) -> String {
        self.shared
            .presence
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.nick.clone())
            .unwrap_or_else(|| id.fmt_short().to_string())
    }

    async fn handle_payload(self: &Arc<Self>, from: EndpointId, payload: Payload) {
        match payload {
            Payload::Hello { nick } => {
                self.touch(from, Some(nick));
                // a peer just showed up — pull to backfill from it (A§10 bootstrap).
                self.clone().trigger_pull(from);
            }
            Payload::Presence { nick, state } => {
                self.touch(from, Some(nick));
                if let Some(p) = self.shared.presence.lock().unwrap().get_mut(&from) {
                    p.away = matches!(state, crate::proto::PresenceState::Away);
                }
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
                // a joiner wants our state — and may have state we lack; pull.
                self.clone().trigger_pull(from);
            }
            Payload::Announce {
                workspace,
                catalog_head,
            } => {
                self.touch(from, None);
                let (our_ws, our_head) = {
                    let t = self.tracker.lock().unwrap();
                    (t.workspace_str(), t.sync_head_bytes())
                };
                // Only pull when the peer's catalog head differs from ours — the
                // A§8 trigger. Same head ⇒ nothing to do (storm suppression).
                if workspace == our_ws && catalog_head != our_head {
                    self.clone().trigger_pull(from);
                }
            }
        }
    }

    /// Spawn a deduped sync pull from a peer (A§8). At most one in-flight pull
    /// per peer; on success (something changed) ring a doorbell and re-announce
    /// so peers that are behind us pull in turn.
    fn trigger_pull(self: Arc<Self>, peer: EndpointId) {
        if peer == self.shared.my_id {
            return;
        }
        tokio::spawn(async move {
            if !self.syncing.lock().unwrap().insert(peer) {
                return; // already syncing this peer
            }
            let result = self.do_pull(peer).await;
            self.syncing.lock().unwrap().remove(&peer);
            match result {
                Ok(dirty) => {
                    if !dirty.is_empty() {
                        self.ring_doorbell(dirty);
                        let _ = self.broadcast_announce().await;
                    }
                    // We successfully reached this peer — persist it immediately so
                    // even a short-lived daemon (up for less than a heartbeat) can
                    // bootstrap from it on the next start (DUR-1).
                    self.persist_known_peers();
                }
                Err(e) => tracing::debug!("pull from {peer} failed: {e:#}"),
            }
        });
    }

    async fn do_pull(&self, peer: EndpointId) -> Result<crate::tracker::DirtySet> {
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            self.endpoint.connect(peer, crate::sync::SYNC_ALPN),
        )
        .await
        .map_err(|_| anyhow!("connect to peer for sync timed out"))??;
        let dirty = crate::sync::pull(&conn, &self.tracker).await?;
        conn.close(0u32.into(), b"sync done");
        Ok(dirty)
    }

    /// Broadcast our current catalog head so peers that are behind pull from us.
    async fn broadcast_announce(&self) -> Result<()> {
        let (workspace, catalog_head) = {
            let t = self.tracker.lock().unwrap();
            (t.workspace_str(), t.sync_head_bytes())
        };
        self.broadcast(Payload::Announce {
            workspace,
            catalog_head,
        })
        .await
    }

    /// Snapshot the peers we currently know (excluding ourselves) and persist
    /// them as the next start's gossip bootstrap set (DUR-1). Best-effort.
    fn persist_known_peers(&self) {
        let peers: Vec<EndpointId> = {
            let p = self.shared.presence.lock().unwrap();
            p.keys()
                .copied()
                .filter(|id| *id != self.shared.my_id)
                .collect()
        };
        if !peers.is_empty() {
            save_known_peers(&self.home, &peers);
        }
    }

    /// Our own presence state (UI.md §4.5): `away` when no client input within
    /// the engagement window, else `online`. Input is tracked via `last_active`.
    fn my_presence_state(&self) -> crate::proto::PresenceState {
        const ENGAGED: Duration = Duration::from_secs(60);
        if self.last_active.lock().unwrap().elapsed() <= ENGAGED {
            crate::proto::PresenceState::Online
        } else {
            crate::proto::PresenceState::Away
        }
    }

    async fn broadcast(&self, payload: Payload) -> Result<()> {
        let bytes = SignedMessage::sign_and_encode(&self.secret_key, &payload)?;
        let sender = self.sender.lock().unwrap().clone();
        sender
            .broadcast(bytes)
            .await
            .map_err(|e| anyhow!("broadcast failed: {e}"))?;
        Ok(())
    }

    async fn join_topic(self: &Arc<Self>, topic: TopicId, peers: Vec<EndpointId>) -> Result<()> {
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

    /// Adopt a ticket's workspace (if we're empty, A§6/A§10), join its gossip
    /// topic, announce, and eagerly pull from the host to backfill.
    async fn adopt_and_join(self: &Arc<Self>, ticket: &RoomTicket) -> Result<()> {
        if !ticket.workspace.is_empty() {
            let founder = ticket.host.to_string();
            let _ = self
                .tracker
                .lock()
                .unwrap()
                .adopt_workspace(&ticket.workspace, &founder);
        }
        self.join_topic(ticket.topic(), vec![ticket.host]).await?;
        self.broadcast(Payload::JoinRequest {
            nick: self.shared.nick.clone(),
        })
        .await
        .ok();
        let _ = self.broadcast_announce().await;
        self.clone().trigger_pull(ticket.host);
        Ok(())
    }

    /// Pin a seed (A§10). Accepts two forms: a full `RoomTicket` (adopt the
    /// workspace, join, and backfill — the primary path), or a bare endpoint id
    /// (pin only, for a peer we already share a workspace with). Either way the
    /// pin is persisted so future restarts always dial and backfill from it.
    async fn seed_add(self: &Arc<Self>, arg: &str) -> Result<Response> {
        // Try the ticket form first; a bare id will not decode as a ticket.
        if let Ok(ticket) = arg.parse::<RoomTicket>() {
            let id = ticket.host;
            if id == self.shared.my_id {
                return Ok(Response::err("that ticket points at this node's own id"));
            }
            self.adopt_and_join(&ticket).await?;
            let newly = upsert_seed(
                &self.home,
                SeedRecord {
                    id,
                    nick: ticket.host_nick.clone(),
                    workspace: ticket.workspace.clone(),
                },
            );
            self.clone().trigger_pull(id);
            return Ok(Response::Ok {
                message: Some(format!(
                    "{} seed {id} \u{2014} adopted workspace, backfilling",
                    if newly { "pinned" } else { "updated" }
                )),
            });
        }
        if let Ok(id) = arg.parse::<EndpointId>() {
            if id == self.shared.my_id {
                return Ok(Response::err("that's this node's own id"));
            }
            let workspace = self.tracker.lock().unwrap().workspace_str();
            let newly = upsert_seed(
                &self.home,
                SeedRecord {
                    id,
                    nick: String::new(),
                    workspace,
                },
            );
            self.clone().trigger_pull(id);
            return Ok(Response::Ok {
                message: Some(format!(
                    "{} seed {id}",
                    if newly { "pinned" } else { "already pinned; refreshed" }
                )),
            });
        }
        Ok(Response::err(
            "expected a room ticket (from `groupchat invite`) or an endpoint id",
        ))
    }

    async fn recv_loop(self: Arc<Self>, mut receiver: GossipReceiver, gen: u64) {
        loop {
            if self.recv_gen.load(Ordering::SeqCst) != gen {
                break;
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
                        // mesh formed with this peer — pull to converge (A§8) and
                        // persist it right away for restart bootstrap (DUR-1).
                        self.clone().trigger_pull(id);
                        self.persist_known_peers();
                    }
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
                    state: self.my_presence_state(),
                })
                .await
            {
                tracing::debug!("heartbeat broadcast failed: {e}");
            }
            // Piggyback a catalog-head announce on the heartbeat so a peer that
            // missed a live announce still converges within a heartbeat (A§8).
            let _ = self.broadcast_announce().await;
            // Persist the peers we currently know so the next start bootstraps
            // from them instead of waiting to be re-announced to (DUR-1).
            self.persist_known_peers();
        }
    }

    /// Stamp a tracker [`DirtySet`] into a doorbell and wake every parked stream.
    fn ring_doorbell(&self, dirty: DirtySet) {
        let mut d = self.doorbell.lock().unwrap();
        d.seq += 1;
        let frame = Doorbell {
            epoch: d.epoch,
            seq: d.seq,
            reset: false,
            dirty_by_project: dirty.dirty_by_project,
            dirty_catalog: dirty.dirty_catalog,
            activity_advanced: dirty.activity_advanced,
        };
        d.ring.push_back(frame);
        while d.ring.len() > DOORBELL_RING {
            d.ring.pop_front();
        }
        drop(d);
        self.doorbell_notify.notify_waiters();
    }

    /// Dispatch a tracker request against the Loro core, ringing a doorbell for
    /// any resulting dirty-set. The lock is held only for the synchronous handle
    /// (never across an await).
    /// Dispatch a tracker request; ring a local doorbell for any dirty-set and
    /// return `(response, did_change)`. A change means our catalog head moved, so
    /// the caller announces it for P2P propagation (A§8).
    fn dispatch_tracker(&self, req: Request) -> (Response, bool) {
        let (resp, dirty) = {
            let mut t = self.tracker.lock().unwrap();
            t.handle(req)
        };
        let changed = dirty.is_some();
        if let Some(dirty) = dirty {
            self.ring_doorbell(dirty);
        }
        (resp, changed)
    }

    async fn dispatch(self: Arc<Self>, req: Request) -> Result<Response> {
        match req {
            // ---- tracker (P0) ----
            Request::IssueNew { .. }
            | Request::IssueEdit { .. }
            | Request::IssueMove { .. }
            | Request::Assign { .. }
            | Request::Label { .. }
            | Request::Comment { .. }
            | Request::IssueDelete { .. }
            | Request::IssueView { .. }
            | Request::List { .. }
            | Request::Board { .. }
            | Request::History { .. }
            | Request::ProjectNew { .. }
            | Request::ProjectList
            | Request::LabelNew { .. }
            | Request::LabelList
            | Request::Activity { .. }
            | Request::MemberAdd { .. }
            | Request::MemberRemove { .. }
            | Request::KeyRotate
            | Request::Members => {
                let (resp, changed) = self.dispatch_tracker(req);
                if changed {
                    // our catalog head moved — announce so peers pull (A§8).
                    let me = self.clone();
                    tokio::spawn(async move { me.broadcast_announce().await.ok() });
                }
                Ok(resp)
            }

            // Subscribe is handled by the streaming path, not here.
            Request::Subscribe { .. } => Ok(Response::err("subscribe is a streaming request")),

            // ---- transport / presence ----
            Request::Status => {
                let online_peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|p| p.presence.is_online())
                    .count();
                let (workspace, issues, projects) = {
                    let t = self.tracker.lock().unwrap();
                    (
                        Some(t.workspace_id().to_string()),
                        t.issue_count(),
                        t.project_count(),
                    )
                };
                Ok(Response::Status(StatusInfo {
                    id: self.shared.my_id.to_string(),
                    nick: self.shared.nick.clone(),
                    room: self.shared.room.clone(),
                    online_peers,
                    workspace,
                    issues,
                    projects,
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
                    workspace: self.tracker.lock().unwrap().workspace_str(),
                };
                Ok(Response::Text {
                    text: ticket.to_string(),
                })
            }
            Request::Join { ticket } => {
                let ticket: RoomTicket = ticket.parse().context("parse room ticket")?;
                self.adopt_and_join(&ticket).await?;
                Ok(Response::Ok {
                    message: Some("joined room and sent join request".to_string()),
                })
            }
            Request::Connect { ticket } => {
                let ticket: RoomTicket = ticket.parse().context("parse room ticket")?;
                self.adopt_and_join(&ticket).await?;
                Ok(Response::Ok {
                    message: Some("connected to room \u{2014} you're live".to_string()),
                })
            }
            Request::SeedAdd { arg } => self.seed_add(arg.trim()).await,
            Request::SeedList => {
                let seeds = load_seeds(&self.home);
                if seeds.is_empty() {
                    return Ok(Response::Text {
                        text: "(no pinned seeds \u{2014} add one with `groupchat seed add <ticket>`)"
                            .to_string(),
                    });
                }
                let presence = self.shared.presence.lock().unwrap();
                let lines: Vec<String> = seeds
                    .iter()
                    .map(|s| {
                        let state = match presence.get(&s.id) {
                            Some(p) if p.presence.is_online() => {
                                if p.away {
                                    "away"
                                } else {
                                    "online"
                                }
                            }
                            _ => "offline",
                        };
                        let nick = if s.nick.is_empty() { "seed" } else { &s.nick };
                        format!("{}  {:<12}  {}", s.id, nick, state)
                    })
                    .collect();
                Ok(Response::Text {
                    text: lines.join("\n"),
                })
            }
            Request::SeedRemove { who } => {
                let n = remove_seed(&self.home, who.trim());
                if n == 0 {
                    Ok(Response::err("no pinned seed matched that id/nick"))
                } else {
                    Ok(Response::Ok {
                        message: Some(format!("unpinned {n} seed(s)")),
                    })
                }
            }
            Request::Log { since } => {
                let (events, last) = self.shared.events.lock().unwrap().since(since);
                Ok(Response::Events { events, last })
            }
            Request::Wait { since, timeout_ms } => {
                let timeout_ms = timeout_ms.clamp(0, 300_000);
                let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
                let notify = self.shared.events.lock().unwrap().notify();
                loop {
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
                    .map(|(id, p)| {
                        let online = p.presence.is_online();
                        // three-state (UI.md §4.5): reachable-and-engaged =
                        // online; reachable-but-AFK = away; unreachable = offline.
                        let state = if !online {
                            "offline"
                        } else if p.away {
                            "away"
                        } else {
                            "online"
                        };
                        PresenceEntry {
                            id: id.to_string(),
                            nick: p.nick.clone(),
                            state: state.to_string(),
                            online,
                            last_seen_secs: p.last_seen.elapsed().as_secs(),
                        }
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

    async fn handle_conn(self: Arc<Self>, stream: LocalStream) {
        self.active_conns.fetch_add(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
        self.clone().handle_conn_inner(stream).await;
        self.active_conns.fetch_sub(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// Whether this node belongs to a shared workspace it should stay online to
    /// serve (DUR-3). True if it currently tracks any peer, or has ever persisted
    /// one (DUR-1 `peers.json`) — i.e. it has meshed with someone at least once.
    /// A node that has never met a peer is solo/ephemeral and may idle out.
    fn is_mesh_member(&self) -> bool {
        if self
            .shared
            .presence
            .lock()
            .unwrap()
            .values()
            .next()
            .is_some()
        {
            return true;
        }
        !load_bootstrap_peers(&self.home, self.shared.my_id).is_empty()
    }

    async fn idle_shutdown_loop(self: Arc<Self>) {
        if self.idle_window.is_zero() {
            return;
        }
        let mut interval = tokio::time::interval(IDLE_CHECK_INTERVAL);
        loop {
            interval.tick().await;
            let active = self.active_conns.load(Ordering::SeqCst);
            let idle_for = self.last_active.lock().unwrap().elapsed();
            if should_idle_shutdown(active, idle_for, self.idle_window, self.is_mesh_member()) {
                tracing::info!("idle {idle_for:?} with no clients — shutting down");
                self.shutdown.notify_one();
                break;
            }
        }
    }

    async fn handle_conn_inner(self: Arc<Self>, stream: LocalStream) {
        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        let req = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                let _ = write_line(write_half, &Response::err(format!("bad request: {e}"))).await;
                return;
            }
        };
        // Subscribe is a streaming request: never returns until disconnect.
        if let Request::Subscribe { since } = req {
            self.stream_subscribe(write_half, since).await;
            return;
        }
        let resp = match self.dispatch(req).await {
            Ok(r) => r,
            Err(e) => Response::err(format!("{e:#}")),
        };
        let _ = write_line(write_half, &resp).await;
    }

    /// The streaming Subscribe loop (S§7.5, UI.md §4.1): emit a `Reset` first
    /// frame that rebaselines the client to the current `seq`, then push every
    /// new doorbell until the client hangs up or the daemon stops. Because the
    /// first frame is always `Reset`, first-connect / reconnect / restart /
    /// ring-overrun all collapse to one rebaseline path — the fix for the
    /// pre-existing wait/watch deafness across the idle-shutdown.
    async fn stream_subscribe(
        self: Arc<Self>,
        mut write_half: tokio::io::WriteHalf<LocalStream>,
        _since: u64,
    ) {
        let (epoch, mut cursor) = {
            let d = self.doorbell.lock().unwrap();
            (d.epoch, d.seq)
        };
        // First frame: Reset — "rebaseline from a fresh snapshot".
        let reset = Doorbell {
            epoch,
            seq: cursor,
            reset: true,
            ..Default::default()
        };
        if write_line_half(&mut write_half, &reset).await.is_err() {
            return;
        }

        let shutdown = self.shutdown.clone();
        loop {
            let notified = self.doorbell_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            // Drain frames newer than the cursor. If the cursor has fallen off
            // the back of the ring, send a Reset and rebaseline.
            let (frames, oldest, latest_seq) = {
                let d = self.doorbell.lock().unwrap();
                let frames: Vec<Doorbell> =
                    d.ring.iter().filter(|f| f.seq > cursor).cloned().collect();
                (frames, d.oldest(), d.seq)
            };
            if subscribe_should_reset(cursor, oldest) {
                let reset = Doorbell {
                    epoch,
                    seq: latest_seq,
                    reset: true,
                    ..Default::default()
                };
                if write_line_half(&mut write_half, &reset).await.is_err() {
                    return;
                }
                cursor = latest_seq;
            } else {
                for f in frames {
                    cursor = f.seq;
                    if write_line_half(&mut write_half, &f).await.is_err() {
                        return;
                    }
                }
            }

            tokio::select! {
                _ = &mut notified => continue,
                _ = shutdown.notified() => return,
            }
        }
    }
}

/// Serialize a response and write it as one newline-delimited frame.
async fn write_line<T: serde::Serialize>(
    mut write_half: tokio::io::WriteHalf<LocalStream>,
    value: &T,
) -> std::io::Result<()> {
    write_line_half(&mut write_half, value).await
}

async fn write_line_half<T: serde::Serialize>(
    write_half: &mut tokio::io::WriteHalf<LocalStream>,
    value: &T,
) -> std::io::Result<()> {
    let mut out = serde_json::to_string(value)
        .unwrap_or_else(|_| "{\"kind\":\"error\",\"message\":\"encode failure\"}".to_string());
    out.push('\n');
    write_half.write_all(out.as_bytes()).await?;
    write_half.flush().await
}

/// Build and run the daemon until a Stop request arrives. When `seed` is set the
/// node runs as an always-on seed and never idle-shuts-down (DUR-4).
pub async fn run_daemon(home: PathBuf, seed: bool) -> Result<()> {
    let _daemon_lock = acquire_daemon_lock(&home)?;

    let secret_key = load_or_create_identity(&home)?;
    let profile = Profile::load(&home)?;

    // Tracker core (P0): open the git-backed store and load/create the workspace.
    let store = Store::open(&home)?;
    let me = UserId::from_key_string(secret_key.public().to_string());
    let identity_seed = secret_key.to_bytes();
    let tracker = Tracker::open(
        store,
        me,
        profile.nick.clone(),
        identity_seed,
        Box::new(SystemUlidSource),
    )?;
    let tracker = Arc::new(Mutex::new(tracker));

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
        .accept(
            crate::sync::SYNC_ALPN,
            SyncHandler {
                tracker: tracker.clone(),
            },
        )
        .spawn();

    endpoint.online().await;

    let topic = topic_for_room(&profile.room);
    // Seed gossip bootstrap from previously-seen peers so a restart actively
    // rejoins the mesh instead of waiting to be re-announced to (DUR-1), unioned
    // with the explicit, sticky seed pins (A§10) so a restart always dials its
    // always-on seeds even when no ordinary peer was seen last run.
    let pinned_seeds = seed_ids(&home, my_id);
    let mut bootstrap = load_bootstrap_peers(&home, my_id);
    for id in &pinned_seeds {
        if !bootstrap.contains(id) {
            bootstrap.push(*id);
        }
    }
    let gtopic = gossip
        .subscribe(topic, bootstrap)
        .await
        .map_err(|e| anyhow!("subscribe to room: {e}"))?;
    let (sender, receiver) = gtopic.split();

    // A seed never idles out (DUR-4): it must stay reachable to serve sync and
    // backfill history even with no local client and no peer currently online.
    // Otherwise honour the configured idle window (GROUPCHAT_IDLE_SECS).
    let idle_window = if seed {
        Duration::ZERO
    } else {
        idle_window_from_env()
    };
    if seed {
        tracing::info!("running as an always-on seed — idle-shutdown disabled");
    }

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
        idle_window,
        tracker,
        doorbell: Arc::new(Mutex::new(DoorbellRing::new(now_secs()))),
        doorbell_notify: Arc::new(Notify::new()),
        syncing: Arc::new(Mutex::new(HashSet::new())),
        home: home.clone(),
    });

    tokio::spawn(node.clone().recv_loop(receiver, 1));
    tokio::spawn(node.clone().heartbeat_loop());
    tokio::spawn(node.clone().reaper_loop());
    tokio::spawn(node.clone().idle_shutdown_loop());

    node.broadcast(Payload::Hello {
        nick: node.shared.nick.clone(),
    })
    .await
    .ok();

    // Eagerly backfill from every pinned seed on startup — don't wait for a
    // gossip NeighborUp. This is what makes a seed a cold-start anchor (A§10): a
    // fresh or long-offline client converges through its seed immediately.
    for id in pinned_seeds {
        node.clone().trigger_pull(id);
    }

    let control = control_name(&home)?;
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

    node.persist_known_peers();
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
        // A solo node (never meshed) idles out only when unused past the window.
        assert!(should_idle_shutdown(0, Duration::from_secs(61), w, false));
        assert!(!should_idle_shutdown(0, Duration::from_secs(30), w, false));
        assert!(!should_idle_shutdown(1, Duration::from_secs(600), w, false));
        assert!(!should_idle_shutdown(
            0,
            Duration::from_secs(600),
            Duration::ZERO,
            false
        ));
        // DUR-3: a mesh member never idles out, even unused well past the window,
        // so peers can always pull its changes.
        assert!(!should_idle_shutdown(0, Duration::from_secs(600), w, true));
    }

    // Doorbell/Reset control-plane invariant (S§7.5, UI.md §4.1): a Subscribe
    // stream rebaselines with a `Reset` exactly when its cursor has fallen off
    // the back of the ring, and never otherwise.
    #[test]
    fn subscribe_resets_only_on_ring_overrun() {
        // Fresh cursor against a fresh/empty ring: `oldest()` collapses to the
        // (zero) seq, so cursor 0 vs oldest 0 → no reset. A brand-new subscriber
        // is rebaselined by the *first-frame* Reset, not by this path.
        let fresh = DoorbellRing::new(7);
        assert_eq!(fresh.oldest(), 0);
        assert!(!subscribe_should_reset(0, fresh.oldest()));

        // Cursor far behind the oldest retained frame → the gap is unrecoverable,
        // so the stream must Reset and rebaseline.
        assert!(subscribe_should_reset(5, 100));

        // Boundary: cursor == oldest - 1 means the ring still holds the exact
        // next frame (`cursor + 1 == oldest`), so no reset — the drain path can
        // deliver every missed frame contiguously.
        let oldest = 42;
        assert!(!subscribe_should_reset(oldest - 1, oldest));
        // One older than the boundary (a genuine one-frame gap) → reset.
        assert!(subscribe_should_reset(oldest - 2, oldest));
    }

    // DUR-1: the bootstrap peer set round-trips through disk and never seeds the
    // node with itself (dialing your own id is pointless and could self-loop).
    #[test]
    fn bootstrap_peers_persist_and_filter_self() {
        let dir = std::env::temp_dir().join(format!("gc-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let me = SecretKey::from_bytes(&[1u8; 32]).public();
        let peer = SecretKey::from_bytes(&[2u8; 32]).public();

        // Nothing persisted yet → empty bootstrap (the old always-empty case).
        assert!(load_bootstrap_peers(&dir, me).is_empty());

        // Persist a set that includes ourselves; reload must drop self and keep
        // the real peer, so a restart bootstraps from the peer.
        save_known_peers(&dir, &[me, peer]);
        assert_eq!(load_bootstrap_peers(&dir, me), vec![peer]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // The pinned-seed registry (A§10 client half): upsert is id-keyed (no
    // duplicates), bootstrap ids drop self, and removal matches id or nick.
    #[test]
    fn seeds_upsert_dedup_and_remove() {
        let dir = std::env::temp_dir().join(format!("gc-seeds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let a = SecretKey::from_bytes(&[2u8; 32]).public();
        let b = SecretKey::from_bytes(&[3u8; 32]).public();

        assert!(load_seeds(&dir).is_empty());

        // First add is new; re-adding the same id updates in place (not a dup).
        assert!(upsert_seed(
            &dir,
            SeedRecord {
                id: a,
                nick: "nas".into(),
                workspace: "ws".into()
            }
        ));
        assert!(!upsert_seed(
            &dir,
            SeedRecord {
                id: a,
                nick: "nas2".into(),
                workspace: "ws".into()
            }
        ));
        assert_eq!(load_seeds(&dir).len(), 1);
        assert_eq!(load_seeds(&dir)[0].nick, "nas2");

        assert!(upsert_seed(
            &dir,
            SeedRecord {
                id: b,
                nick: String::new(),
                workspace: "ws".into()
            }
        ));
        // Bootstrap ids list both, but filter out our own id when we are `a`.
        assert_eq!(seed_ids(&dir, b).len(), 1);
        assert_eq!(seed_ids(&dir, SecretKey::from_bytes(&[9u8; 32]).public()).len(), 2);

        // Remove by nick, then by full id.
        assert_eq!(remove_seed(&dir, "nas2"), 1);
        assert_eq!(remove_seed(&dir, &b.to_string()), 1);
        assert!(load_seeds(&dir).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
