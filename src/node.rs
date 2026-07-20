//! The lait daemon: owns a [`Transport`], the gossip room, presence, the
//! Loro-CRDT replica core ([`crate::replica`]), and the local control server that
//! CLI, web, and MCP clients drive.
//!
//! The daemon is the transport's **consumer**, never its implementation: it
//! dials, gossips and accepts in lait's own vocabulary, so the network it runs
//! over is a constructor argument. The replica rides on top: the daemon is the
//! **only** owner of the Loro docs, and every local interface is a control
//! client.
//!
//! **Doorbells.** A mutation produces a
//! [`crate::replica::DirtySet`]; the daemon stamps it with a per-boot `epoch` and
//! a per-session `seq`, pushes it onto a bounded ring, and wakes every parked
//! [`Request::Subscribe`] stream. `seq` is never persisted; the first frame of
//! every Subscribe is a `Reset`, which unifies first-connect / reconnect /
//! restart or ring overrun into one rebaseline path.

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
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{watch, Notify},
    task::JoinSet,
};

use crate::{
    config::{acquire_daemon_lock, load_or_create_identity, Settings},
    control::{
        control_name, Doorbell, Event as LogEvent, EventKind, PresenceEntry, Request, Response,
        StatusInfo,
    },
    dto::{Candidate, JoinRequestDto, SeedDto},
    ids::{DeviceId, SystemUlidSource},
    index::{resolve_device_dir, DeviceResolution, KnownDevice},
    presence::{PeerState, PRESENCE_ALPN},
    proto::{InviteGrant, Payload, SignedInvite, SignedMessage, SpaceTicket},
    replica::{DirtySet, Replica},
    store::Store,
    transport::{
        DefaultFactory, GossipEvent, GossipSender, Incoming, Topic, Transport, TransportFactory,
    },
};

const HEARTBEAT: Duration = Duration::from_secs(10);
const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const REAP_INTERVAL: Duration = Duration::from_secs(5);

/// How often the daemon coalesces pending durable-store mutations into a single
/// git commit. Git provides inspectability, not durability (every write is
/// fsync'd), so a slow cadence keeps `git add -A` off the edit hot path while
/// still snapshotting history within a few seconds.
const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(5);
const PRUNE_WINDOW: Duration = Duration::from_secs(600);
const IDLE_SHUTDOWN: Duration = Duration::from_secs(30 * 60);
const IDLE_CHECK_INTERVAL: Duration = Duration::from_secs(5);
/// Bound on the doorbell ring: the last ~1000 batches.
const DOORBELL_RING: usize = 1000;
/// How many times a pull that ended before the peer's `EndDocs` is retried
/// promptly. Bounded so a peer that truncates every attempt costs a fixed
/// number of dials; the announce/heartbeat backstop still carries the rest.
const PULL_RETRIES: u32 = 1;
const PULL_RETRY_DELAY: Duration = Duration::from_secs(1);

/// How long teardown may spend cancelling and draining the daemon's tasks. The
/// daemon must not return before its tasks have ended — returning releases the
/// daemon lock and legalizes a same-home restart — but a wedged task must not
/// hold the lock forever either, so anything still running past this deadline is
/// aborted. All state is already durable by the time the deadline starts.
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(3);
/// Grace for a `Bye` to reach the room before the transport closes under it.
const BYE_GRACE: Duration = Duration::from_millis(500);

/// Daemon-wide cancellation. Every long-lived task selects on
/// [`Cancel::cancelled`], so teardown ends them deterministically: the daemon
/// spawns loops (gossip receive, heartbeat, reaper, checkpoint, idle, accept)
/// and per-connection tasks that each hold an `Arc<Node>`, and a detached one
/// would keep broadcasting and checkpointing after the home directory it writes
/// to is gone and another daemon owns the lock.
#[derive(Clone)]
pub struct Cancel(Arc<watch::Sender<bool>>);

impl Cancel {
    fn new() -> Self {
        Self(Arc::new(watch::Sender::new(false)))
    }

    /// Signal every task to wind down. Idempotent.
    fn cancel(&self) {
        let _ = self.0.send(true);
    }

    fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolve once cancellation has been signalled (immediately if it already
    /// has). Holding the sender in the daemon keeps this from ever resolving by
    /// channel closure instead of by an actual cancel.
    async fn cancelled(&self) {
        let mut rx = self.0.subscribe();
        if *rx.borrow() {
            return;
        }
        let _ = rx.wait_for(|c| *c).await;
    }
}

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
/// A zero window disables idle-shutdown entirely (LAIT_IDLE_SECS=0).
fn should_idle_shutdown(
    active_conns: u64,
    idle_for: Duration,
    window: Duration,
    mesh_member: bool,
) -> bool {
    !window.is_zero() && !mesh_member && active_conns == 0 && idle_for >= window
}

/// The presence/announce heartbeat interval. Configurable via `LAIT_HEARTBEAT_SECS`
/// (default [`HEARTBEAT`] = 10s). Convergence is event-driven (a live announce
/// triggers an immediate pull), so the heartbeat is only a catch-up safety net —
/// but *absence* proofs (e.g. lazy-revocation) must wait a full heartbeat, and 10s
/// dominates multi-node test wall-clock. Letting the test pipeline set a 1s clock
/// cuts that without weakening the assertion. A zero/unparseable value falls back
/// to the default; the interval must be non-zero (tokio panics on a 0 period).
fn heartbeat_from_env() -> Duration {
    match std::env::var("LAIT_HEARTBEAT_SECS") {
        Ok(s) => match s.trim().parse::<u64>() {
            Ok(n) if n > 0 => Duration::from_secs(n),
            _ => HEARTBEAT,
        },
        Err(_) => HEARTBEAT,
    }
}

fn idle_window_from_env() -> Duration {
    match std::env::var("LAIT_IDLE_SECS") {
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

/// Load the persisted set of previously-seen peers, to seed the gossip
/// bootstrap on restart. The transport resolves a dialable address from each
/// device key, so the ids alone are enough to reconnect — a fresh
/// daemon no longer re-enters the mesh with an empty bootstrap set and waits
/// passively to be re-announced to. Our own id is filtered out.
fn load_bootstrap_peers(home: &Path, me: &DeviceId) -> Vec<DeviceId> {
    let Ok(data) = std::fs::read_to_string(peers_path(home)) else {
        return Vec::new();
    };
    let ids: Vec<DeviceId> = serde_json::from_str(&data).unwrap_or_default();
    ids.into_iter().filter(|id| id != me).collect()
}

/// Persist the set of currently-known peer endpoints (best-effort) so the next
/// daemon start can bootstrap from them.
fn save_known_peers(home: &Path, peers: &[DeviceId]) {
    if let Ok(data) = serde_json::to_string(peers) {
        let _ = std::fs::write(peers_path(home), data);
    }
}

/// A pinned always-on **seed** peer — the client-side half of the seed role
/// Unlike the opportunistic `peers.json` bootstrap set
/// these learned peers, pins are **explicit and sticky**: they always seed the gossip
/// bootstrap and are eagerly pulled on startup, so a client converges through
/// its seed even when no other peer is online. A pin grants **no trust** — the
/// seed is a bootstrap/backfill anchor only; every signed op is still validated
/// against the genesis keys carried in the ticket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SeedRecord {
    pub id: DeviceId,
    #[serde(default)]
    pub nick: String,
    #[serde(default)]
    pub space: String,
}

fn seeds_path(home: &Path) -> PathBuf {
    home.join("seeds.json")
}

/// Load the pinned seed registry, entry at a time. A pin is deliberately-placed
/// infrastructure — the anchor a cold client converges through — so one
/// unreadable record must not unpin the rest, and a dropped pin must never be
/// silent: every reject is named at warn and the survivors are kept.
///
/// An id that is not a device key is rejected rather than pinned: it would be
/// carried as far as the dial and fail there, with nothing pointing back at the
/// registry entry that caused it.
fn load_seeds(home: &Path) -> Vec<SeedRecord> {
    let Ok(data) = std::fs::read_to_string(seeds_path(home)) else {
        return Vec::new();
    };
    let rows: Vec<serde_json::Value> = match serde_json::from_str(&data) {
        Ok(rows) => rows,
        Err(e) => {
            tracing::warn!("seeds.json is not a list of pinned seeds ({e}); pinning none");
            return Vec::new();
        }
    };
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let rec: SeedRecord = match serde_json::from_value(row.clone()) {
            Ok(rec) => rec,
            Err(e) => {
                tracing::warn!("skipping an unreadable pinned seed ({e}): {row}");
                continue;
            }
        };
        match DeviceId::parse(rec.id.as_str()) {
            // Normalize on the way in so the pin compares equal to the same key
            // seen over the wire.
            Some(id) => out.push(SeedRecord { id, ..rec }),
            None => tracing::warn!(
                "skipping a pinned seed whose id is not a device key: {:?}",
                rec.id.as_str()
            ),
        }
    }
    out
}

/// Persist the pinned seed registry (best-effort).
fn save_seeds(home: &Path, seeds: &[SeedRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(seeds) {
        let _ = std::fs::write(seeds_path(home), data);
    }
}

/// The pinned seeds' endpoint ids, minus our own — the sticky half of the gossip
/// bootstrap set. Our own id is filtered out (dialing ourselves is pointless).
fn seed_ids(home: &Path, me: &DeviceId) -> Vec<DeviceId> {
    load_seeds(home)
        .into_iter()
        .map(|s| s.id)
        .filter(|id| id != me)
        .collect()
}

/// Upsert a seed into the registry keyed by endpoint id (the id is the identity;
/// nick/space refresh in place). Returns true when it was newly pinned.
fn upsert_seed(home: &Path, rec: SeedRecord) -> bool {
    let mut seeds = load_seeds(home);
    if let Some(existing) = seeds.iter_mut().find(|s| s.id == rec.id) {
        existing.nick = rec.nick;
        existing.space = rec.space;
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
        let id = s.id.as_str();
        !(id == needle || (needle.len() >= 6 && id.starts_with(needle)) || s.nick == needle)
    });
    let removed = before - seeds.len();
    if removed > 0 {
        save_seeds(home, &seeds);
    }
    removed
}

/// Path to the local **alias** store — your private key→petname map (the trusted
/// half of the local-petname identity model). Never synced; a name you set here
/// is trusted because *you* set it, unlike the self-asserted wire nick.
fn aliases_path(home: &Path) -> PathBuf {
    home.join("aliases.json")
}

/// A local alias: a petname you attached to an authenticated ed25519 key. Local
/// to this node, never broadcast, never part of the signed ACL.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AliasRecord {
    /// The member's ed25519 key (64-hex) — the authenticated identity.
    key: String,
    /// The petname you assigned.
    name: String,
}

/// Load the local alias store (best-effort; empty when absent or corrupt).
fn load_aliases(home: &Path) -> Vec<AliasRecord> {
    let Ok(data) = std::fs::read_to_string(aliases_path(home)) else {
        return Vec::new();
    };
    serde_json::from_str(&data).unwrap_or_default()
}

/// Persist the local alias store (best-effort).
fn save_aliases(home: &Path, aliases: &[AliasRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(aliases) {
        let _ = std::fs::write(aliases_path(home), data);
    }
}

/// Set (or, with an empty `name`, clear) the local petname for `key`. Keyed by
/// the full ed25519 key — the authenticated identity, never a wire nick.
fn upsert_alias(home: &Path, key: &str, name: &str) {
    let mut aliases = load_aliases(home);
    aliases.retain(|a| a.key != key);
    if !name.is_empty() {
        aliases.push(AliasRecord {
            key: key.to_string(),
            name: name.to_string(),
        });
    }
    save_aliases(home, &aliases);
}

/// Map ambiguous device matches into the shared [`Candidate`] shape so the CLI and
/// `--json` render them through the same disambiguation path as issue refs
/// `reff` is the short key, `key_alias` the optional nickname, and `title` the full
/// key so the caller can copy an unambiguous value.
fn device_candidates(cands: &[KnownDevice]) -> Vec<Candidate> {
    cands
        .iter()
        .map(|c| Candidate {
            reff: c.key.short(),
            key_alias: (!c.nick.is_empty()).then(|| c.nick.clone()),
            title: c.key.as_str().to_string(),
        })
        .collect()
}

/// A peer we have heard from on the gossip topic.
#[derive(Debug, Clone)]
pub struct Peer {
    pub nick: String,
    pub last_seen: Instant,
    pub presence: PeerState,
    /// Advertised three-state presence: `true` means reachable but away. Only
    /// meaningful while `presence.is_online()`.
    pub away: bool,
}

/// Seal a pre-authorization to the host and bind it to the joiner's actor, for
/// `Payload::JoinRequest`. Sealing keeps the invite nonce off the shared gossip
/// topic; binding the redeemer means a *copied* blob can only ever admit that
/// actor, not an eavesdropper re-pairing it with its own inception.
fn seal_bound_invite(
    host: &DeviceId,
    invite: &SignedInvite,
    redeemer: &crate::ids::ActorId,
) -> Option<Vec<u8>> {
    let payload = postcard::to_stdvec(&(invite.clone(), redeemer.clone())).ok()?;
    crate::crypto::seal_to(host, &payload)
}

/// Open a sealed, redeemer-bound pre-authorization. Returns the invite only if it
/// was sealed to `me` (the host) AND the request's `incept` is the actor the seal
/// names — so a blob copied off the topic and re-paired with a different
/// inception is refused. `my_seed` is the host's identity seed.
fn open_bound_invite(
    my_seed: &[u8; 32],
    me: &DeviceId,
    sealed: &[u8],
    incept: &crate::actor::SignedEvent,
) -> Option<SignedInvite> {
    let raw = crate::crypto::open_sealed(my_seed, me, sealed)?;
    let (invite, redeemer): (SignedInvite, crate::ids::ActorId) =
        postcard::from_bytes(&raw).ok()?;
    if crate::ids::ActorId::from_incept_hash(&incept.hash()) != redeemer {
        return None;
    }
    Some(invite)
}

/// Bounded ring buffer of presence and transport events.
#[derive(Debug, Default)]
pub struct EventLog {
    seq: u64,
    events: VecDeque<LogEvent>,
}

impl EventLog {
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
/// Pure and side-effect-free so the ring-overrun invariant
/// is unit-testable without driving the async socket loop.
fn subscribe_should_reset(cursor: u64, oldest: u64) -> bool {
    cursor + 1 < oldest
}

/// Cheaply-cloneable shared presence state.
#[derive(Debug, Clone)]
pub struct Shared {
    /// Our display nick. Mutable so a `ConfigReload` (from `lait config set
    /// user.nick`) applies live instead of waiting for a restart. There is no
    /// room here: the gossip topic is a pure function of the space id.
    pub nick: Arc<Mutex<String>>,
    pub my_id: DeviceId,
    pub presence: Arc<Mutex<HashMap<DeviceId, Peer>>>,
    pub events: Arc<Mutex<EventLog>>,
}

impl Shared {
    fn nick(&self) -> String {
        self.nick.lock().unwrap().clone()
    }
}

/// The running node.
pub struct Node {
    /// The network, in lait's vocabulary. Dialing, gossip, accepting, address
    /// advertisement and teardown all go through here; no concrete network type
    /// is reachable from the daemon.
    transport: Arc<dyn Transport>,
    sender: Mutex<Arc<dyn GossipSender>>,
    /// lait's identity: the seed *is* the key, and the transport derives its own
    /// keypair from the same 32 bytes (checked at construction).
    identity_seed: [u8; 32],
    /// This daemon's space id (constant). Bound into every signed gossip
    /// message so a message cannot be replayed onto another space's topic.
    space: String,
    shared: Shared,
    shutdown: Arc<Notify>,
    /// Teardown signal for every long-lived task (see [`Cancel`]).
    cancel: Cancel,
    /// Every task the daemon spawns, so teardown can join them before the
    /// injectable entry returns and releases the daemon lock. Held behind a
    /// `std::sync::Mutex` that is never locked across an `.await`.
    tasks: Arc<Mutex<JoinSet<()>>>,
    recv_gen: AtomicU64,
    active_conns: AtomicU64,
    last_active: Mutex<Instant>,
    idle_window: Duration,
    /// The Loro-CRDT replica core. The daemon is its only owner.
    replica: Arc<Mutex<Replica>>,
    /// The doorbell ring and its wake source.
    doorbell: Arc<Mutex<DoorbellRing>>,
    doorbell_notify: Arc<Notify>,
    /// Peers we currently have an in-flight sync pull to (dedupes announce storms).
    syncing: Arc<Mutex<HashSet<DeviceId>>>,
    /// Ephemeral join-request actor inceptions, keyed by the requesting device.
    /// Bounded and NEVER persisted here — an inception only enters the synced
    /// membership doc when an admin actually admits (redeem/approve), so an
    /// unauthenticated peer cannot grow the shared container (amplification DoS).
    pending_incepts: Arc<Mutex<HashMap<DeviceId, crate::actor::SignedEvent>>>,
    /// This node's home dir, used to persist the bootstrap peer set across restarts.
    home: PathBuf,
}

impl Node {
    /// Spawn a daemon-owned task. Every `tokio::spawn` in the daemon goes
    /// through here: an untracked task outlives teardown holding an `Arc<Node>`,
    /// which is only invisible in production because the process exits. Finished
    /// tasks are reaped on the way in so the set does not grow with the number
    /// of control connections served.
    fn spawn<F>(&self, fut: F)
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        // Past cancellation the set has already been drained for joining, so a
        // task admitted here would be exactly the untracked straggler this
        // exists to prevent. Teardown is under way; drop the work.
        if self.cancel.is_cancelled() {
            return;
        }
        let mut tasks = self.tasks.lock().unwrap();
        while tasks.try_join_next().is_some() {}
        tasks.spawn(fut);
    }

    fn touch(&self, id: &DeviceId, nick: Option<String>) -> String {
        // A newly-seen peer must be reachable before we dial it back (Local).
        self.transport.learn(id.clone(), &[]);
        let now = Instant::now();
        let came_online = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(id) {
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
                    let nm = nick.filter(|n| !n.is_empty()).unwrap_or_else(|| id.short());
                    p.insert(
                        id.clone(),
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
        let display = self.display_nick(id);
        if came_online && *id != self.shared.my_id {
            self.shared.events.lock().unwrap().push(
                EventKind::Presence,
                id.as_str().to_string(),
                display.clone(),
                format!("{display} is online"),
            );
            self.ring_presence_doorbell();
        }
        display
    }

    fn mark_offline(&self, id: &DeviceId, left: bool) {
        let visible = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(id) {
                Some(peer) => peer.presence.force_offline(),
                None => false,
            }
        };
        if visible {
            self.announce_offline(id, left);
        }
    }

    fn on_neighbor_down(self: Arc<Self>, id: DeviceId) {
        let became_suspect = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(&id) {
                Some(peer) => peer.presence.neighbor_down(Instant::now()),
                None => false,
            }
        };
        if became_suspect {
            self.spawn(self.clone().probe_peer(id));
        }
    }

    async fn probe_peer(self: Arc<Self>, id: DeviceId) {
        // Liveness is whether the dial succeeds; nothing is ever sent. Dropping
        // the returned stream closes the connection, which is the dialer's
        // whole side of the presence protocol — the accepter opens no stream.
        let alive = matches!(
            tokio::time::timeout(
                PROBE_TIMEOUT,
                self.transport.connect(id.clone(), PRESENCE_ALPN)
            )
            .await,
            Ok(Ok(_))
        );
        let transition = {
            let mut p = self.shared.presence.lock().unwrap();
            p.get_mut(&id)
                .and_then(|peer| peer.presence.probe_result(alive, Instant::now()))
        };
        match transition {
            Some(true) => self.announce_online(&id),
            Some(false) => self.announce_offline(&id, false),
            None => {}
        }
    }

    fn announce_online(&self, id: &DeviceId) {
        if *id == self.shared.my_id {
            return;
        }
        let display = self.display_nick(id);
        self.shared.events.lock().unwrap().push(
            EventKind::Presence,
            id.as_str().to_string(),
            display.clone(),
            format!("{display} is online"),
        );
        self.ring_presence_doorbell();
    }

    fn announce_offline(&self, id: &DeviceId, left: bool) {
        let display = self.display_nick(id);
        let text = if left {
            format!("{display} left")
        } else {
            format!("{display} went offline")
        };
        self.shared.events.lock().unwrap().push(
            EventKind::Presence,
            id.as_str().to_string(),
            display,
            text,
        );
        self.ring_presence_doorbell();
    }

    async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.cancel.cancelled() => break,
            }
            let now = Instant::now();
            let stale: Vec<DeviceId> = {
                let p = self.shared.presence.lock().unwrap();
                p.iter()
                    .filter(|(_, peer)| peer.presence.should_reap(now))
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            for id in stale {
                self.mark_offline(&id, false);
            }
            self.shared.presence.lock().unwrap().retain(|_, peer| {
                peer.presence.is_online() || peer.last_seen.elapsed() < PRUNE_WINDOW
            });
        }
    }

    fn display_nick(&self, id: &DeviceId) -> String {
        self.shared
            .presence
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.nick.clone())
            .unwrap_or_else(|| id.short())
    }

    async fn handle_payload(self: &Arc<Self>, from: DeviceId, payload: Payload) {
        match payload {
            Payload::Hello { nick } => {
                self.touch(&from, Some(nick));
                // A newly visible peer may have state we missed; pull to backfill.
                self.clone().trigger_pull(from);
            }
            Payload::Presence { nick, state } => {
                self.touch(&from, Some(nick));
                if let Some(p) = self.shared.presence.lock().unwrap().get_mut(&from) {
                    p.away = matches!(state, crate::proto::PresenceState::Away);
                }
            }
            Payload::Bye { nick } => {
                self.touch(&from, Some(nick));
                self.mark_offline(&from, true);
            }
            Payload::JoinRequest {
                nick,
                invite,
                incept,
            } => {
                let display = self.touch(&from, Some(nick.clone()));
                self.shared.events.lock().unwrap().push(
                    EventKind::Join,
                    from.as_str().to_string(),
                    display.clone(),
                    format!("{display} joined the room"),
                );
                self.ring_presence_doorbell();
                // Stash the joiner's inception EPHEMERALLY (bounded, never synced)
                // so a manual `member add` can admit it later. It only enters the
                // shared membership doc when an admin admits — so an
                // unauthenticated peer cannot grow the container.
                if let Some(incept) = &incept {
                    const MAX_PENDING_INCEPTS: usize = 256;
                    let mut pend = self.pending_incepts.lock().unwrap();
                    if pend.contains_key(&from) || pend.len() < MAX_PENDING_INCEPTS {
                        pend.insert(from.clone(), incept.clone());
                    }
                }
                // Pattern A: if the joiner presented a valid pre-authorization and
                // we're an admin who can seal, admit them now — no manual approve.
                // On any failure we simply leave the request pending (the event
                // above already surfaces it to `members requests`).
                if let Some(invite) = invite {
                    self.clone().try_auto_approve(&from, invite, incept);
                }
                // a joiner wants our state — and may have state we lack; pull.
                self.clone().trigger_pull(from);
            }
            Payload::Announce {
                space,
                catalog_head,
            } => {
                self.touch(&from, None);
                let (our_ws, our_head) = {
                    let t = self.replica.lock().unwrap();
                    (t.space_str(), t.sync_head_bytes())
                };
                // Only pull when the peer's catalog head differs from ours — the
                // An unchanged catalog head suppresses redundant pull storms.
                if space == our_ws && catalog_head != our_head {
                    self.clone().trigger_pull(from);
                }
            }
        }
    }

    /// Spawn a deduplicated sync pull from a peer. At most one in-flight pull
    /// per peer; on success (something changed) ring a doorbell and re-announce
    /// so peers that are behind us pull in turn.
    fn trigger_pull(self: Arc<Self>, peer: DeviceId) {
        self.trigger_pull_within(peer, PULL_RETRIES);
    }

    /// `retries` bounds the prompt re-pull after an *incomplete* transfer, so a
    /// peer that truncates every time costs a fixed number of attempts rather
    /// than an unbounded loop. Convergence still has the announce/heartbeat
    /// backstop underneath it.
    fn trigger_pull_within(self: Arc<Self>, peer: DeviceId, retries: u32) {
        if peer == self.shared.my_id {
            return;
        }
        // Ensure the sync dial can resolve the peer under Local.
        self.transport.learn(peer.clone(), &[]);
        let cancel = self.cancel.clone();
        let tracker = self.clone();
        tracker.spawn(async move {
            if !self.syncing.lock().unwrap().insert(peer.clone()) {
                return; // already syncing this peer
            }
            // A pull has no read deadline of its own (a stalled peer would park
            // the task forever), so teardown is what bounds it.
            let result = tokio::select! {
                r = self.do_pull(&peer) => r,
                _ = cancel.cancelled() => Err(anyhow!("daemon shutting down")),
            };
            self.syncing.lock().unwrap().remove(&peer);
            match result {
                Ok(outcome) => {
                    if !outcome.dirty.is_empty() {
                        self.ring_doorbell(outcome.dirty);
                        let _ = self.broadcast_announce().await;
                    }
                    // We reached this peer — persist it immediately so even a
                    // short-lived daemon (up for less than a heartbeat) can
                    // bootstrap from it on the next start. True whether or not
                    // the transfer finished: reachability is what is being
                    // recorded.
                    self.persist_known_peers();
                    if !outcome.complete && retries > 0 {
                        tokio::time::sleep(PULL_RETRY_DELAY).await;
                        self.clone().trigger_pull_within(peer, retries - 1);
                    }
                }
                Err(e) => tracing::debug!("pull from {peer} failed: {e:#}"),
            }
        });
    }

    async fn do_pull(&self, peer: &DeviceId) -> Result<crate::sync::PullOutcome> {
        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            self.transport.connect(peer.clone(), crate::sync::SYNC_ALPN),
        )
        .await
        .map_err(|_| anyhow!("connect to peer for sync timed out"))??;
        let outcome = crate::sync::pull(&mut *stream, &self.replica).await?;
        // Dropping the dialer's stream closes the connection: the dialer's
        // "done" signal, and what releases the accepter from `wait_closed`.
        Ok(outcome)
    }

    /// The daemon's inbound side: one loop over the transport's accepted
    /// connections, dispatched by ALPN. It replaces a per-protocol handler
    /// registry, and it is why the daemon needs no network type of its own.
    ///
    /// `accept` yields `None` only after the transport has shut down, so this
    /// ends on teardown without a cancellation arm of its own.
    async fn accept_loop(self: Arc<Self>) {
        while let Some(inc) = self.transport.accept().await {
            let me = self.clone();
            self.spawn(async move { me.serve_incoming(inc).await });
        }
    }

    async fn serve_incoming(self: Arc<Self>, inc: Incoming) {
        let mut stream = inc.stream;
        if inc.alpn == crate::sync::SYNC_ALPN {
            if let Err(e) = crate::sync::serve(&mut *stream, &self.replica).await {
                tracing::debug!("sync serve error: {e:#}");
            }
            // Unconditional, including on the error path above. `finish` only
            // queues end-of-stream; dropping the stream tears the connection
            // down and truncates whatever the puller has not yet drained —
            // issue-doc bodies that then silently never sync. Bounded by
            // cancellation so a peer holding its side open cannot park
            // teardown, but with no timeout of its own: a deadline short
            // enough to be useful is short enough to cut a large transfer.
            tokio::select! {
                _ = stream.wait_closed() => {}
                _ = self.cancel.cancelled() => {}
            }
        } else if inc.alpn == PRESENCE_ALPN {
            // A probe sends nothing; it is alive iff the dial landed here.
            tokio::select! {
                _ = stream.wait_closed() => {}
                _ = self.cancel.cancelled() => {}
            }
        } else {
            tracing::debug!("inbound connection on an unregistered alpn: {:?}", inc.alpn);
        }
    }

    /// Broadcast our current catalog head so peers that are behind pull from us.
    async fn broadcast_announce(&self) -> Result<()> {
        let (space, catalog_head) = {
            let t = self.replica.lock().unwrap();
            (t.space_str(), t.sync_head_bytes())
        };
        self.broadcast(Payload::Announce {
            space,
            catalog_head,
        })
        .await
    }

    /// Snapshot the peers we currently know (excluding ourselves) and persist
    /// them as the next start's gossip bootstrap set. Best-effort.
    fn persist_known_peers(&self) {
        let peers: Vec<DeviceId> = {
            let p = self.shared.presence.lock().unwrap();
            p.keys()
                .filter(|id| **id != self.shared.my_id)
                .cloned()
                .collect()
        };
        if !peers.is_empty() {
            save_known_peers(&self.home, &peers);
        }
    }

    /// Our presence state: `away` when no client input arrives within
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
        let bytes = SignedMessage::sign_and_encode(&self.space, &self.identity_seed, &payload)?;
        // Clone the sender out from under the lock: a std mutex guard must never
        // cross an await, and the broadcast below is one.
        let sender = self.sender.lock().unwrap().clone();
        sender
            .broadcast(bytes.to_vec())
            .await
            .map_err(|e| anyhow!("broadcast failed: {e}"))?;
        Ok(())
    }

    async fn join_topic(self: &Arc<Self>, topic: Topic, peers: Vec<DeviceId>) -> Result<()> {
        let (tx, mut rx) = self.transport.subscribe(topic, &peers).await?;
        // Install nothing until the room is actually reachable: a join that
        // times out must leave the node in the room it was already in, rather
        // than swapping in a sender that broadcasts into nowhere.
        tokio::time::timeout(Duration::from_secs(15), rx.joined())
            .await
            .map_err(|_| anyhow!("timed out connecting to the room's peers"))??;
        *self.sender.lock().unwrap() = Arc::from(tx);
        let gen = self.recv_gen.fetch_add(1, Ordering::SeqCst) + 1;
        self.spawn(self.clone().recv_loop(rx, gen));
        Ok(())
    }

    /// Connect to the bound space's mesh through a ticket: join the topic,
    /// broadcast our join request, announce, and eagerly pull from the host to
    /// backfill. The store was already bootstrapped by the CLI
    /// ([`crate::replica::join_space_store`]) — a ticket for a *different*
    /// space is a hard error, never an adoption: a daemon is only ever
    /// subscribed to its own space's topic, so split-brain is structurally
    /// impossible.
    async fn connect_space(self: &Arc<Self>, ticket: &SpaceTicket) -> Result<()> {
        let bound = self.replica.lock().unwrap().space_str();
        if ticket.space != bound {
            anyhow::bail!(
                "this store is bound to space {bound}, but the invite is for {} — \
                 run `lait join` from a directory that isn't already a space",
                ticket.space
            );
        }
        // Under Isolated the host is reachable only at the addresses the ticket
        // carries — register them so the bare-id dial below resolves. A no-op for
        // Public/Local tickets (which carry none and resolve by relay/discovery).
        let host = ticket.host.clone();
        self.transport.learn(host.clone(), &ticket.host_addrs);
        self.join_topic(ticket.topic(), vec![host.clone()]).await?;
        // Mint (or recover) our actor inception so an admin can admit our actor.
        let incept = self.replica.lock().unwrap().self_inception().ok();
        // Seal the pre-authorization to the HOST and bind it to our actor, so the
        // invite nonce never rides the shared topic in the clear (a removed member
        // subscribed to the topic can't lift it), and a copied blob can only ever
        // admit us — not an eavesdropper re-pairing it with their own inception.
        let sealed_invite = match (&ticket.invite, &incept) {
            (Some(inv), Some(ic)) => {
                let redeemer = crate::ids::ActorId::from_incept_hash(&ic.hash());
                seal_bound_invite(&host, inv, &redeemer)
            }
            _ => None,
        };
        self.broadcast(Payload::JoinRequest {
            nick: self.shared.nick(),
            invite: sealed_invite,
            incept,
        })
        .await
        .ok();
        let _ = self.broadcast_announce().await;
        self.clone().trigger_pull(host);
        Ok(())
    }

    /// The honest post-`join` message. A join only *requests* access: until an
    /// an admin approves us, we hold ciphertext and cannot read the board.
    /// So we tell the joiner the truth and point at the one next step, instead of
    /// implying success. If we resolved to an already-member (a re-join), say so.
    fn join_message(&self, ticket: &SpaceTicket) -> String {
        let host = if ticket.host_nick.is_empty() {
            "the space admin".to_string()
        } else {
            ticket.host_nick.clone()
        };
        let already_member = self.replica.lock().unwrap().am_i_member();
        if already_member {
            "joined \u{2014} you're on the board and syncing.".to_string()
        } else if ticket.invite.is_some() {
            // Pattern A: the ticket carried a pre-authorization, so admission is
            // automatic once an admin node processes the request (typically ~a
            // couple seconds). Tell the truth without implying a manual step.
            format!(
                "joining {host}'s space with an invite pass \u{2014} you should be admitted \
                 automatically in a moment, then your board decrypts and syncs.\n\
                 run `lait status` to confirm you're in."
            )
        } else {
            format!(
                "join request sent to {host}.\n\
                 you're not on the board yet \u{2014} {host} still has to approve you, then \
                 your board decrypts and syncs automatically.\n\
                 run `lait status` any time to check whether you've been approved."
            )
        }
    }

    /// Pin a seed. Accepts two forms: a full `SpaceTicket` for the
    /// space this store is bound to (connect + backfill — the primary path),
    /// or a bare endpoint id (pin only, for a peer we already share a space
    /// with). A ticket for a *foreign* space is an error — join it first.
    /// Either way the pin is persisted so restarts always dial and backfill.
    async fn seed_add(self: &Arc<Self>, arg: &str) -> Result<Response> {
        // Try the ticket form first; a bare id will not decode as a ticket.
        if let Ok(ticket) = arg.parse::<SpaceTicket>() {
            let id = ticket.host.clone();
            if id == self.shared.my_id {
                return Ok(Response::err("that ticket points at this node's own id"));
            }
            let bound = self.replica.lock().unwrap().space_str();
            if ticket.space != bound {
                return Ok(Response::err(format!(
                    "that ticket is for a different space ({}) — join it first: `lait join <ticket>`",
                    ticket.space
                )));
            }
            self.connect_space(&ticket).await?;
            let newly = upsert_seed(
                &self.home,
                SeedRecord {
                    id: id.clone(),
                    nick: ticket.host_nick.clone(),
                    space: ticket.space.clone(),
                },
            );
            self.clone().trigger_pull(id.clone());
            return Ok(Response::Ok {
                message: Some(format!(
                    "{} seed {id} \u{2014} backfilling",
                    if newly { "pinned" } else { "updated" }
                )),
            });
        }
        if let Some(id) = DeviceId::parse(arg) {
            if id == self.shared.my_id {
                return Ok(Response::err("that's this node's own id"));
            }
            let space = self.replica.lock().unwrap().space_str();
            let newly = upsert_seed(
                &self.home,
                SeedRecord {
                    id: id.clone(),
                    nick: String::new(),
                    space,
                },
            );
            self.clone().trigger_pull(id.clone());
            return Ok(Response::Ok {
                message: Some(format!(
                    "{} seed {id}",
                    if newly {
                        "pinned"
                    } else {
                        "already pinned; refreshed"
                    }
                )),
            });
        }
        Ok(Response::err(
            "expected a room ticket (from `lait invite`) or a 64-character device id",
        ))
    }

    async fn recv_loop(
        self: Arc<Self>,
        mut receiver: Box<dyn crate::transport::GossipReceiver>,
        gen: u64,
    ) {
        loop {
            if self.recv_gen.load(Ordering::SeqCst) != gen {
                break;
            }
            let event = tokio::select! {
                event = receiver.next() => event,
                _ = self.cancel.cancelled() => break,
            };
            // `None` means the room is gone; there is nothing left to receive.
            let Some(event) = event else { break };
            match event {
                GossipEvent::Received { bytes, .. } => {
                    // The delivering neighbor is a routing hint, never the
                    // author: gossip relays peer to peer, so authorship comes
                    // from the signature and nowhere else.
                    match SignedMessage::verify_and_decode(&self.space, &bytes) {
                        Ok((from, payload)) => self.handle_payload(from, payload).await,
                        // A decode failure here is almost always a version-skewed
                        // peer: postcard is not self-describing, so a payload whose
                        // shape changed across releases fails to deserialize (see
                        // `docs/PROTOCOL.md` — incompatible wire epochs require
                        // all nodes to upgrade together).
                        // Swallowing it silently made mixed-version fleets
                        // undiagnosable; log at debug with the error so the drop is
                        // at least visible under `RUST_LOG=lait=debug`.
                        Err(e) => tracing::debug!(
                            error = %e,
                            "dropped an undecodable gossip payload (likely a \
                             version-skewed or malformed peer)"
                        ),
                    }
                }
                GossipEvent::NeighborUp(id) => {
                    self.touch(&id, None);
                    // The mesh formed with this peer: pull to converge and
                    // persist it immediately for restart bootstrap.
                    self.clone().trigger_pull(id);
                    self.persist_known_peers();
                }
                GossipEvent::NeighborDown(id) => {
                    self.clone().on_neighbor_down(id);
                }
            }
        }
    }

    async fn heartbeat_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(heartbeat_from_env());
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.cancel.cancelled() => break,
            }
            if let Err(e) = self
                .broadcast(Payload::Presence {
                    nick: self.shared.nick(),
                    state: self.my_presence_state(),
                })
                .await
            {
                tracing::debug!("heartbeat broadcast failed: {e}");
            }
            // Piggyback a catalog-head announce on the heartbeat so a peer that
            // A peer that missed a live announcement still converges within a heartbeat.
            let _ = self.broadcast_announce().await;
            // Persist the peers we currently know so the next start bootstraps
            // from them instead of waiting to be re-announced.
            self.persist_known_peers();
        }
    }

    /// Periodically coalesce pending durable-store mutations into a single git
    /// commit, keeping `git add -A` (a subprocess whose cost grows with the
    /// tree) off every edit's hot path. Git is inspectability only:
    /// durability is the per-write fsync — so a late or missed checkpoint never
    /// risks data; at worst the working tree is briefly uncommitted and the next
    /// tick tidies it.
    async fn checkpoint_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(CHECKPOINT_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.cancel.cancelled() => break,
            }
            if self.replica.lock().unwrap().checkpoint() {
                tracing::debug!("store checkpoint committed");
            }
        }
    }

    /// Signal shutdown to **every** waiter. The `shutdown` Notify has multiple
    /// tasks parked on it (the main accept loop *and* each Subscribe stream), so
    /// a bare `notify_one` could hand its single permit to a subscriber and leave
    /// the accept loop running — a daemon that answered "shutting down" and then
    /// didn't (the zombie: its pipe instance keeps accepting connects nobody
    /// serves). `notify_waiters` wakes everyone currently parked; the follow-up
    /// `notify_one` stores a permit for a waiter that hadn't re-parked yet.
    fn signal_shutdown(&self) {
        self.shutdown.notify_waiters();
        self.shutdown.notify_one();
    }

    /// Ring the presence plane — a peer joined or changed presence. Carries no
    /// replica dirty-set: the `EventLog` moved, not a doc. Subscribers re-read
    /// `Log{since}`. This is what lets a stream wake on presence at all; the
    /// replica `DirtySet` paths below never touch the `EventLog`.
    fn ring_presence_doorbell(&self) {
        let mut d = self.doorbell.lock().unwrap();
        d.seq += 1;
        let frame = Doorbell {
            epoch: d.epoch,
            seq: d.seq,
            reset: false,
            presence_advanced: true,
            ..Default::default()
        };
        d.ring.push_back(frame);
        while d.ring.len() > DOORBELL_RING {
            d.ring.pop_front();
        }
        drop(d);
        self.doorbell_notify.notify_waiters();
    }

    /// Stamp a replica [`DirtySet`] into a doorbell and wake every parked stream.
    fn ring_doorbell(&self, dirty: DirtySet) {
        // Project config moved (local edit or sync import) — keep the machine
        // registry's advisory project snapshot fresh. Every ring_doorbell call
        // site has already released the replica lock, so the re-lock inside is
        // safe.
        let projects_moved = dirty
            .dirty_catalog
            .contains(&crate::control::CatalogScope::Projects);
        let mut d = self.doorbell.lock().unwrap();
        d.seq += 1;
        let frame = Doorbell {
            epoch: d.epoch,
            seq: d.seq,
            reset: false,
            dirty_by_project: dirty.dirty_by_project,
            dirty_catalog: dirty.dirty_catalog,
            activity_advanced: dirty.activity_advanced,
            presence_advanced: false,
        };
        d.ring.push_back(frame);
        while d.ring.len() > DOORBELL_RING {
            d.ring.pop_front();
        }
        drop(d);
        self.doorbell_notify.notify_waiters();
        if projects_moved {
            self.refresh_registry_row();
        }
    }

    /// Pattern A: try to auto-admit `joiner` against a presented invite. Verifies
    /// the issuer signature, the space binding, and expiry here (transport
    /// concerns), then hands the state-dependent checks + sealing to the replica's
    /// `redeem_invite`. Best-effort: any failure is a silent fallback to the
    /// classic pending-request flow, so a bad/expired/foreign invite never blocks
    /// a manual approve. On success we ring the doorbell and re-announce so the
    /// freshly-sealed joiner pulls and decrypts.
    fn try_auto_approve(
        self: Arc<Self>,
        _joiner_id: &DeviceId,
        sealed: Vec<u8>,
        incept: Option<crate::actor::SignedEvent>,
    ) {
        // A pre-actor peer carries no inception — a v2 daemon cannot admit it.
        let Some(incept) = incept else { return };
        // Only we (the host) can open the sealed pre-authorization — that is what
        // kept the nonce off the topic — and only for the actor it names, so a
        // blob copied off the wire cannot be re-paired with an eavesdropper's
        // inception.
        let me = self.shared.my_id.clone();
        let Some(invite) = open_bound_invite(&self.identity_seed, &me, &sealed, &incept) else {
            return;
        };
        let (issuer, grant) = match invite.verify() {
            Ok(v) => v,
            Err(_) => return,
        };
        let now = now_secs();
        if grant.is_expired(now) {
            return;
        }
        let (changed, dirty) = {
            let mut t = self.replica.lock().unwrap();
            // Bind the grant to *our* space before doing anything.
            if grant.space != t.space_str() {
                return;
            }
            let (_resp, dirty) = t.redeem_invite(&issuer, &incept, &grant.nonce, grant.single_use);
            (dirty.is_some(), dirty)
        };
        if let Some(dirty) = dirty {
            self.ring_doorbell(dirty);
        }
        if changed {
            let me = self.clone();
            self.spawn(async move {
                me.broadcast_announce().await.ok();
            });
        }
    }

    /// Assemble the who-ref resolution directory. Keys are gathered
    /// from every place we've seen one — our own id, the live presence map, recent
    /// join requests, and the signed ACL members — so any of them resolves by
    /// `@me` / full key / id-prefix. **Names come only from the local alias store**
    /// (a petname you set), never from the self-asserted wire nick: an
    /// unauthenticated name must never resolve to a key. A key with no alias is
    /// still resolvable, just not by name. This is what turns `members add bob`
    /// (after `--as bob`) and `assign ENG-1 c3ab21` into real keys.
    fn device_directory(&self) -> Vec<KnownDevice> {
        let mut keys: HashSet<DeviceId> = HashSet::new();
        keys.insert(self.shared.my_id.clone());
        {
            let presence = self.shared.presence.lock().unwrap();
            for id in presence.keys() {
                keys.insert(id.clone());
            }
        }
        {
            let (events, _) = self.shared.events.lock().unwrap().since(0);
            for e in &events {
                if e.kind == EventKind::Join {
                    keys.insert(DeviceId::from_key_string(e.id.clone()));
                }
            }
        }
        {
            for key in self.replica.lock().unwrap().member_device_keys() {
                keys.insert(key);
            }
        }
        let aliases = load_aliases(&self.home);
        keys.into_iter()
            .map(|key| {
                let nick = aliases
                    .iter()
                    .find(|a| a.key == key.as_str())
                    .map(|a| a.name.clone())
                    .unwrap_or_default();
                KnownDevice { key, nick }
            })
            .collect()
    }

    /// Pending join requests: announced joiners (`EventKind::Join`) who are not
    /// yet ACL members. Newest-first, deduped by key. Ephemeral — bounded by the
    /// event ring and is never persisted.
    fn pending_join_requests(&self) -> Vec<JoinRequestDto> {
        // A joiner's announced id is a *device* key; it is "already a member" if
        // that device speaks for a member actor.
        let members: HashSet<String> = self
            .replica
            .lock()
            .unwrap()
            .member_device_keys()
            .into_iter()
            .map(|k| k.as_str().to_string())
            .collect();
        let (events, _) = self.shared.events.lock().unwrap().since(0);
        let mut seen: HashSet<String> = HashSet::new();
        let mut out = Vec::new();
        for e in events.iter().rev() {
            if e.kind != EventKind::Join {
                continue;
            }
            if members.contains(&e.id) || !seen.insert(e.id.clone()) {
                continue;
            }
            out.push(JoinRequestDto {
                key: e.id.clone(),
                nick: e.nick.clone(),
                ts: e.ts,
            });
        }
        out
    }

    /// Resolve the who-refs carried by a request (local-alias / id-prefix → full
    /// key) against the directory, before the replica sees them. Returns
    /// the rewritten request, or an early `Response` (not-found / ambiguous) to
    /// send back verbatim. Only the ref-bearing requests are touched; everything
    /// else passes through untouched (and without building the directory).
    fn resolve_refs_in(&self, req: Request) -> std::result::Result<Request, Response> {
        if !matches!(
            req,
            Request::MemberAdd { .. }
                | Request::MemberRemove { .. }
                | Request::Assign { .. }
                | Request::IssueNew { .. }
                | Request::SpaceElevate { .. }
        ) {
            return Ok(req);
        }
        let dir = self.device_directory();
        let me = self.shared.my_id.clone();
        let resolve = |who: &str| -> std::result::Result<String, Response> {
            match resolve_device_dir(who, &me, &dir) {
                DeviceResolution::One(u) => Ok(u.as_str().to_string()),
                DeviceResolution::Zero => {
                    Err(Response::not_found(format!("no user matches '{who}'")))
                }
                DeviceResolution::Many(c) => Err(Response::Candidates {
                    candidates: device_candidates(&c),
                    near_miss_for: None,
                }),
            }
        };
        Ok(match req {
            Request::MemberAdd {
                who,
                admin,
                as_name,
            } => Request::MemberAdd {
                who: resolve(&who)?,
                admin,
                as_name,
            },
            Request::MemberRemove { who } => Request::MemberRemove {
                who: resolve(&who)?,
            },
            Request::SpaceElevate { cofounders, k } => {
                let mut out = Vec::with_capacity(cofounders.len());
                for w in &cofounders {
                    out.push(resolve(w)?);
                }
                Request::SpaceElevate { cofounders: out, k }
            }
            Request::Assign { reff, who, add } => {
                let mut out = Vec::with_capacity(who.len());
                for w in &who {
                    out.push(resolve(w)?);
                }
                Request::Assign {
                    reff,
                    who: out,
                    add,
                }
            }
            Request::IssueNew {
                title,
                project,
                project_hint,
                assignees,
                priority,
                labels,
                body,
            } => {
                let mut out = Vec::with_capacity(assignees.len());
                for a in &assignees {
                    out.push(resolve(a)?);
                }
                Request::IssueNew {
                    title,
                    project,
                    project_hint,
                    assignees: out,
                    priority,
                    labels,
                    body,
                }
            }
            other => other,
        })
    }

    /// Dispatch a replica request against the Loro core, ringing a doorbell for
    /// any resulting dirty-set. The lock is held only for the synchronous handle
    /// (never across an await).
    /// Dispatch a replica request; ring a local doorbell for any dirty-set and
    /// return `(response, did_change)`. A change means our catalog head moved, so
    /// the caller announces it for peer propagation.
    fn dispatch_replica(&self, req: Request) -> (Response, bool) {
        let (resp, dirty) = {
            let mut t = self.replica.lock().unwrap();
            t.handle(req)
        };
        let changed = dirty.is_some();
        if let Some(dirty) = dirty {
            self.ring_doorbell(dirty);
        }
        (resp, changed)
    }

    async fn dispatch(self: Arc<Self>, req: Request) -> Result<Response> {
        // Resolve nick / id-prefix who-refs to full keys before the replica sees
        // them; a not-found / ambiguous ref short-circuits with its own response.
        let req = match self.resolve_refs_in(req) {
            Ok(r) => r,
            Err(resp) => return Ok(resp),
        };
        match req {
            // ---- replica ----
            Request::IssueNew { .. }
            | Request::IssueEdit { .. }
            | Request::IssueMove { .. }
            | Request::IssueStart { .. }
            | Request::IssueDone { .. }
            | Request::IssueStop { .. }
            | Request::Assign { .. }
            | Request::Label { .. }
            | Request::Comment { .. }
            | Request::IssueDelete { .. }
            | Request::IssueLink { .. }
            | Request::IssueUnlink { .. }
            | Request::IssueParent { .. }
            | Request::IssueGraph { .. }
            | Request::IssueRestore { .. }
            | Request::IssueView { .. }
            | Request::List { .. }
            | Request::Board { .. }
            | Request::History { .. }
            | Request::ProjectNew { .. }
            | Request::ProjectList
            | Request::LabelNew { .. }
            | Request::LabelList
            | Request::Activity { .. }
            | Request::MemberRemove { .. }
            | Request::MemberLog
            | Request::KeyRotate
            | Request::InviteRevoke { .. }
            | Request::DeviceInvite
            | Request::DeviceAdd { .. }
            | Request::DeviceRevoke { .. }
            | Request::DeviceList
            | Request::Recover
            | Request::SpaceElevate { .. }
            | Request::SpaceRecoverApprove { .. }
            | Request::SpaceElevateApprove { .. }
            | Request::SpaceCustodyExport { .. }
            | Request::SpaceCustodyImport { .. }
            | Request::SpaceRecover => {
                let (resp, changed) = self.dispatch_replica(req);
                if changed {
                    // Announce a changed catalog head so peers pull.
                    let me = self.clone();
                    self.spawn(async move {
                        me.broadcast_announce().await.ok();
                    });
                }
                Ok(resp)
            }

            // Add a member, then attach the optional local petname to the resolved
            // key (`who` is already a full key — `resolve_refs_in` ran first). The
            // alias is set only after the ACL op actually took (`changed`).
            Request::MemberAdd {
                who,
                admin,
                as_name,
            } => {
                // If this device's inception was stashed from a join request,
                // make it known now — admin-gated persistence, only on this
                // explicit approve action (not on the raw request).
                if let Some(dev) = DeviceId::parse(&who) {
                    let pending = self.pending_incepts.lock().unwrap().get(&dev).cloned();
                    if let Some(incept) = pending {
                        let _ = self.replica.lock().unwrap().import_inception(&incept);
                    }
                }
                let (resp, changed) = self.dispatch_replica(Request::MemberAdd {
                    who: who.clone(),
                    admin,
                    as_name: None,
                });
                if changed {
                    if let Some(name) = as_name.as_deref() {
                        upsert_alias(&self.home, &who, name.trim());
                    }
                    let me = self.clone();
                    self.spawn(async move {
                        me.broadcast_announce().await.ok();
                    });
                }
                Ok(resp)
            }

            // Sponsor an agent: import its stashed inception (from the agent's
            // join) so the replica can resolve its actor, then dispatch.
            Request::AgentAdd { key } => {
                if let Some(dev) = DeviceId::parse(&key) {
                    let pending = self.pending_incepts.lock().unwrap().get(&dev).cloned();
                    if let Some(incept) = pending {
                        let _ = self.replica.lock().unwrap().import_inception(&incept);
                    }
                }
                let (resp, changed) = self.dispatch_replica(Request::AgentAdd { key });
                if changed {
                    let me = self.clone();
                    self.spawn(async move {
                        me.broadcast_announce().await.ok();
                    });
                }
                Ok(resp)
            }

            // Members list, with local petnames overlaid onto the projection.
            Request::Members => {
                let (resp, _) = self.dispatch_replica(Request::Members);
                Ok(match resp {
                    Response::Members { mut members } => {
                        let aliases = load_aliases(&self.home);
                        // A member's `key` is now an actor id; a local petname may
                        // have been set on the actor id OR on any of its device
                        // keys (e.g. the device seen in the join request). Resolve
                        // through the actor's device set.
                        let plane = self.replica.lock().unwrap().actor_plane();
                        for m in &mut members {
                            if let Some(a) = aliases.iter().find(|a| a.key == m.key) {
                                m.alias = a.name.clone();
                            } else if let Some(actor) = crate::ids::ActorId::parse(&m.key) {
                                let devs = plane.devices_of(&actor);
                                if let Some(a) = aliases
                                    .iter()
                                    .find(|a| devs.iter().any(|d| d.as_str() == a.key))
                                {
                                    m.alias = a.name.clone();
                                }
                            }
                        }
                        Response::Members { members }
                    }
                    other => other,
                })
            }

            // Set (or clear) a local petname for any known key. Resolves `who`
            // against the full directory (alias / id-prefix / key), then records
            // the name locally — never synced, never a signed op.
            Request::MemberAlias { who, name } => {
                let dir = self.device_directory();
                match resolve_device_dir(who.trim(), &self.shared.my_id.clone(), &dir) {
                    DeviceResolution::One(u) => {
                        let name = name.trim();
                        upsert_alias(&self.home, u.as_str(), name);
                        let msg = if name.is_empty() {
                            format!("cleared alias for {}", u.short())
                        } else {
                            format!("{name} = {}", u.short())
                        };
                        Ok(Response::Ok { message: Some(msg) })
                    }
                    DeviceResolution::Zero => {
                        Ok(Response::not_found(format!("no user matches '{who}'")))
                    }
                    DeviceResolution::Many(c) => Ok(Response::Candidates {
                        candidates: device_candidates(&c),
                        near_miss_for: None,
                    }),
                }
            }

            // ---- join-request approval (built on the ACL member ops) ----
            Request::MemberRequests => Ok(Response::JoinRequests {
                requests: self.pending_join_requests(),
            }),
            Request::MemberApprove { who, as_name } => {
                let pending = self.pending_join_requests();
                if pending.is_empty() {
                    return Ok(Response::err("no pending join requests to approve"));
                }
                // Key-first: resolve strictly by id-prefix / full key against the
                // pending set. Empty nicks here mean the joiner's self-asserted name
                // is NOT a resolution input — an unauthenticated nick must never
                // select who gets sealed the space key. The approver attaches a
                // *trusted* local petname via `as_name`.
                let dir: Vec<KnownDevice> = pending
                    .iter()
                    .map(|r| KnownDevice {
                        key: DeviceId::from_key_string(r.key.clone()),
                        nick: String::new(),
                    })
                    .collect();
                match resolve_device_dir(who.trim(), &self.shared.my_id.clone(), &dir) {
                    DeviceResolution::One(u) => {
                        let key = u.as_str().to_string();
                        // Import the joiner's stashed inception (from its join
                        // request) so the replica can resolve its actor — admin-
                        // gated persistence, only on this explicit approve.
                        if let Some(incept) = self.pending_incepts.lock().unwrap().get(&u).cloned()
                        {
                            let _ = self.replica.lock().unwrap().import_inception(&incept);
                        }
                        let (resp, changed) = self.dispatch_replica(Request::MemberAdd {
                            who: key.clone(),
                            admin: false,
                            as_name: None,
                        });
                        if changed {
                            if let Some(name) = as_name.as_deref() {
                                upsert_alias(&self.home, &key, name.trim());
                            }
                            let me = self.clone();
                            self.spawn(async move {
                                me.broadcast_announce().await.ok();
                            });
                        }
                        Ok(resp)
                    }
                    DeviceResolution::Zero => Ok(Response::not_found(format!(
                        "no pending join request matches '{who}' — approve by key or \
                         id-prefix (see `lait members requests`)"
                    ))),
                    DeviceResolution::Many(c) => Ok(Response::Candidates {
                        candidates: device_candidates(&c),
                        near_miss_for: None,
                    }),
                }
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
                let (space, name, issues, projects, membership) = {
                    let t = self.replica.lock().unwrap();
                    let membership = if t.am_i_admin() {
                        "admin"
                    } else if t.am_i_member() {
                        "member"
                    } else {
                        "pending"
                    };
                    (
                        Some(t.space_id().to_string()),
                        t.space_name(),
                        t.issue_count(),
                        t.project_count(),
                        membership.to_string(),
                    )
                };
                let pending_requests = self.pending_join_requests().len();
                let (degraded_recovery, recovery) = {
                    let t = self.replica.lock().unwrap();
                    (t.degraded_recovery_holders(), Some(t.recovery_status()))
                };
                Ok(Response::Status(Box::new(StatusInfo {
                    id: self.shared.my_id.to_string(),
                    nick: self.shared.nick(),
                    name,
                    online_peers,
                    space,
                    issues,
                    projects,
                    membership,
                    pending_requests,
                    degraded_recovery,
                    recovery,
                })))
            }
            Request::Diagnose { expected_space } => {
                // Gather the same live state `Status` does, then project it into
                // the ordered onboarding gates (pure core, unit-tested separately).
                let online_peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .values()
                    .filter(|p| p.presence.is_online())
                    .count();
                let (space, name, issues, projects, membership) = {
                    let t = self.replica.lock().unwrap();
                    let membership = if t.am_i_admin() {
                        "admin"
                    } else if t.am_i_member() {
                        "member"
                    } else {
                        "pending"
                    };
                    (
                        t.space_id().to_string(),
                        t.space_name(),
                        t.issue_count(),
                        t.project_count(),
                        membership.to_string(),
                    )
                };
                let (degraded_recovery, rekey_pending, local_custody) = {
                    let t = self.replica.lock().unwrap();
                    (
                        t.degraded_recovery_holders(),
                        t.rekey_pending_notice(),
                        t.recovery_status().local_custody,
                    )
                };
                let view = crate::diagnose::diagnose(crate::diagnose::DiagnoseInput {
                    space: Some(space.as_str()),
                    name: name.as_str(),
                    membership: membership.as_str(),
                    online_peers,
                    projects,
                    issues,
                    expected_space: expected_space.as_deref(),
                    degraded_recovery: &degraded_recovery,
                    rekey_pending: rekey_pending.as_deref(),
                    local_custody: Some(&local_custody),
                });
                Ok(Response::Diagnosis(Box::new(view)))
            }
            Request::Id => Ok(Response::Text {
                text: self.shared.my_id.to_string(),
            }),
            Request::Invite {
                require_approval,
                reusable,
                ttl_hours,
            } => {
                let (space, name) = {
                    let t = self.replica.lock().unwrap();
                    // Only an admin can meaningfully onboard: `redeem_invite`
                    // honors a pre-authorization only from an admin device, and a
                    // manual approve is admin-gated too. Refuse up front rather
                    // than hand back a ticket that can never admit anyone.
                    if !t.am_i_admin() {
                        return Ok(Response::err(
                            "only an admin can mint an invite — ask a space admin",
                        ));
                    }
                    (t.space_str(), t.space_name())
                };
                // Default: embed a signed, single-use pre-authorization so the
                // joiner is auto-admitted (Pattern A). `--require-approval` mints a
                // grant-less ticket that falls back to the manual approve flow.
                let invite = if require_approval {
                    None
                } else {
                    const DEFAULT_TTL_HOURS: u64 = 24 * 7;
                    let ttl_secs = ttl_hours.unwrap_or(DEFAULT_TTL_HOURS).saturating_mul(3600);
                    let grant = InviteGrant::mint(space.clone(), now_secs(), ttl_secs, !reusable);
                    SignedInvite::sign(&self.identity_seed, &grant).ok()
                };
                // Carry the verifiable founding proof (salt + founder inception),
                // NOT a bare anchor string. The joiner checks the space id
                // commits to it, so a non-founder's invite still roots the joiner
                // on the TRUE founder and a tampered anchor is rejected — every
                // correctly-joined node holds the same proof (lait/space/1).
                let (salt, recovery_root, founder_inception) =
                    match self.replica.lock().unwrap().founding_proof() {
                        Some(p) => p,
                        None => {
                            return Ok(Response::err(
                                "this space has no founding proof — cannot mint an invite",
                            ))
                        }
                    };
                // Under a policy with no relay and no discovery a ticket must
                // carry the host's direct addresses. Which policies those are is
                // the transport's business, not the daemon's: it returns the
                // addresses a ticket needs, empty when bare ids already resolve.
                let host_addrs = self.transport.advertised_addrs();
                let ticket = SpaceTicket {
                    space,
                    name,
                    host: self.shared.my_id.clone(),
                    host_nick: self.shared.nick(),
                    salt,
                    recovery_root,
                    founder_inception: Some(founder_inception),
                    invite,
                    host_addrs,
                };
                Ok(Response::Text {
                    text: ticket.to_string(),
                })
            }
            Request::Join { ticket } | Request::Connect { ticket } => {
                let ticket: SpaceTicket = ticket.parse().context("parse space ticket")?;
                // The CLI already bootstrapped this store from the ticket
                // (`replica::join_space_store`) and registered it; the
                // daemon's part is transport only — connect, request admission,
                // backfill.
                self.connect_space(&ticket).await?;
                Ok(Response::Ok {
                    message: Some(self.join_message(&ticket)),
                })
            }
            Request::SeedAdd { arg } => self.seed_add(arg.trim()).await,
            Request::SeedList => {
                let seeds = load_seeds(&self.home);
                let presence = self.shared.presence.lock().unwrap();
                let seeds: Vec<SeedDto> = seeds
                    .into_iter()
                    .map(|s| {
                        let (state, online) = match presence.get(&s.id) {
                            Some(p) if p.presence.is_online() => {
                                (if p.away { "away" } else { "online" }, true)
                            }
                            _ => ("offline", false),
                        };
                        SeedDto {
                            id: s.id.as_str().to_string(),
                            nick: s.nick,
                            space: s.space,
                            state: state.to_string(),
                            online,
                        }
                    })
                    .collect();
                Ok(Response::Seeds { seeds })
            }
            Request::SeedRemove { who } => {
                let n = remove_seed(&self.home, who.trim());
                if n == 0 {
                    Ok(Response::not_found("no pinned seed matched that id/nick"))
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
            Request::Who => {
                let peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(id, p)| {
                        let online = p.presence.is_online();
                        // Three-state presence: reachable and engaged means
                        // online; reachable-but-AFK = away; unreachable = offline.
                        let state = if !online {
                            "offline"
                        } else if p.away {
                            "away"
                        } else {
                            "online"
                        };
                        PresenceEntry {
                            id: id.as_str().to_string(),
                            nick: p.nick.clone(),
                            state: state.to_string(),
                            online,
                            last_seen_secs: p.last_seen.elapsed().as_secs(),
                        }
                    })
                    .collect();
                Ok(Response::Who { peers })
            }
            Request::Inbox { clear } => {
                let (mut entries, unread) = crate::inbox::list(&self.home);
                if clear {
                    crate::inbox::mark_read(&self.home, now_secs());
                }
                // Resolve actor keys to display nicks at READ time (never
                // persisted): local petname > live presence nick > short key.
                let aliases = load_aliases(&self.home);
                let presence = self.shared.presence.lock().unwrap();
                for e in entries.iter_mut() {
                    let Some(actor) = e.actor.clone() else {
                        continue;
                    };
                    let pet = aliases
                        .iter()
                        .find(|a| a.key == actor)
                        .map(|a| a.name.clone())
                        .filter(|n| !n.is_empty());
                    let pres = presence
                        .iter()
                        .find(|(id, _)| id.as_str() == actor)
                        .map(|(_, p)| p.nick.clone())
                        .filter(|n| !n.is_empty());
                    let short: String = actor.chars().take(8).collect();
                    e.actor_nick = Some(pet.or(pres).unwrap_or(short));
                }
                drop(presence);
                Ok(Response::Inbox { entries, unread })
            }
            Request::ConfigReload => {
                // Re-read the layered settings so a daemon-read key set via
                // `lait config` applies live (never a silent wait-for-restart).
                let settings = Settings::load(Some(&self.home));
                let nick = settings.nick();
                *self.shared.nick.lock().unwrap() = nick.clone();
                self.replica.lock().unwrap().set_nick(nick.clone());
                // Broadcast the new nick right away so peers don't wait a
                // heartbeat to see it.
                let me = self.clone();
                self.spawn(async move {
                    me.broadcast(Payload::Hello {
                        nick: me.shared.nick(),
                    })
                    .await
                    .ok();
                });
                Ok(Response::Ok {
                    message: Some(format!("config reloaded (nick: {nick})")),
                })
            }
            Request::Stop => {
                let me = self.clone();
                self.spawn(async move {
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    me.signal_shutdown();
                });
                Ok(Response::Ok {
                    message: Some("shutting down".to_string()),
                })
            }
            // Answer with our version and nothing else. The client decides
            // whether it can talk to us (`check_control_protocol`); refusing here
            // would only mean a client that can't understand the refusal. The
            // dialer's `protocol_version` is recorded in the type for a future
            // daemon-side policy — today it needs no reply beyond ours.
            Request::Hello { .. } => Ok(Response::Hello {
                protocol_version: crate::control::CONTROL_PROTOCOL_VERSION,
            }),
        }
    }

    /// Refresh this store's row in the machine-level space registry —
    /// advisory navigation state (name + project keys for `lait spaces`).
    /// Best-effort: registry failure never affects daemon operation. The
    /// registry's merge keeps `origin`/`host_nick` from the init/join upsert.
    fn refresh_registry_row(&self) {
        let (space, name, projects) = {
            let t = self.replica.lock().unwrap();
            (t.space_str(), t.space_name(), t.project_briefs())
        };
        if let Err(e) = crate::spaces::upsert(crate::spaces::SpaceEntry {
            space,
            name,
            path: self.home.display().to_string(),
            origin: crate::spaces::Origin::default(),
            host_nick: String::new(),
            last_opened: now_secs(),
            projects,
        }) {
            tracing::debug!("space registry refresh failed: {e:#}");
        }
    }

    async fn handle_conn(self: Arc<Self>, stream: LocalStream) {
        self.active_conns.fetch_add(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
        self.clone().handle_conn_inner(stream).await;
        self.active_conns.fetch_sub(1, Ordering::SeqCst);
        *self.last_active.lock().unwrap() = Instant::now();
    }

    /// Whether this node belongs to a shared space it should stay online to
    /// serve (DUR-3). True if it currently tracks any peer, or has ever persisted
    /// one in `peers.json`, meaning it has meshed with someone at least once.
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
        !load_bootstrap_peers(&self.home, &self.shared.my_id).is_empty()
    }

    async fn idle_shutdown_loop(self: Arc<Self>) {
        if self.idle_window.is_zero() {
            return;
        }
        let mut interval = tokio::time::interval(IDLE_CHECK_INTERVAL);
        loop {
            tokio::select! {
                _ = interval.tick() => {}
                _ = self.cancel.cancelled() => break,
            }
            let active = self.active_conns.load(Ordering::SeqCst);
            let idle_for = self.last_active.lock().unwrap().elapsed();
            if should_idle_shutdown(active, idle_for, self.idle_window, self.is_mesh_member()) {
                tracing::info!("idle {idle_for:?} with no clients — shutting down");
                self.signal_shutdown();
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

    /// The streaming subscription loop: emit a `Reset` first
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
                // A stream that outlived the stop signal (it parked between the
                // notify and its re-park) still has to end, or teardown waits on
                // a client that will never disconnect.
                _ = self.cancel.cancelled() => return,
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

/// The production daemon entry: run until a Stop request arrives, then exit the
/// process. When `seed` is set the node runs as an always-on seed and never
/// idle-shuts-down (DUR-4).
///
/// Exiting is a hard guarantee of the *process* form of the daemon: "stop" means
/// the process is gone, so nothing left running (a wedged endpoint task, a
/// non-tokio thread) can leave a zombie whose half-dead control channel hangs
/// every later client. It lives here and not in [`run_daemon_with`] because an
/// in-process daemon that exited would take its host down with it.
pub async fn run_daemon(home: PathBuf, seed: bool) -> Result<()> {
    // Identity is global by default (DUR-5); store (repo/lock/socket/config) is
    // this per-repo home. `$LAIT_HOME` collapses both back into `home`.
    run_daemon_with(home, seed, crate::config::identity_dir()?, &DefaultFactory).await?;
    std::process::exit(0);
}

/// The injectable daemon: everything [`run_daemon`] does, but it **returns**
/// after teardown instead of exiting, and takes its identity directory rather
/// than reading the process-global one — so several daemons can run in one
/// process, each with its own identity, without sharing anything but the runtime.
///
/// Returning is a stronger contract than exiting: by the time it returns, every
/// task the daemon spawned has ended or been aborted, because returning drops the
/// daemon lock and legalizes a restart on the same home.
pub async fn run_daemon_with(
    home: PathBuf,
    seed: bool,
    identity_dir: PathBuf,
    factory: &dyn TransportFactory,
) -> Result<()> {
    let _daemon_lock = acquire_daemon_lock(&home)?;

    let identity_seed = load_or_create_identity(&identity_dir)?;
    let settings = Settings::load(Some(&home));
    let nick = settings.nick();

    // Replica core: open the git-backed store. The store must already be
    // initialized (`lait init` / `lait join`) — a daemon never founds a
    // space as a side effect of starting.
    let store = Store::open(&home)?;
    let me = crate::crypto::device_from_seed(&identity_seed);
    let replica = Replica::open(
        store,
        me,
        nick.clone(),
        identity_seed,
        Box::new(SystemUlidSource),
    )?;
    // Register/refresh this store in the machine-level space registry so
    // founders and joiners alike show up in `lait spaces` and resolve via
    // `-w`. Best-effort (navigation state, never a gate); the merge keeps the
    // origin/host_nick recorded by `lait init`/`lait join`.
    if let Err(e) = crate::spaces::upsert(crate::spaces::SpaceEntry {
        space: replica.space_str(),
        name: replica.space_name(),
        path: home.display().to_string(),
        origin: crate::spaces::Origin::default(),
        host_nick: String::new(),
        last_opened: now_secs(),
        projects: replica.project_briefs(),
    }) {
        tracing::warn!("space registry upsert failed: {e:#}");
    }
    let replica = Arc::new(Mutex::new(replica));

    // lait states its network requirement; the transport executes it (crate::net
    // is the sole place relay/discovery vocabulary lives). Defaults to Public.
    let network = crate::net::Network::from_env()?;
    // Public and Local both resolve bare ids. Isolated has neither relay nor
    // discovery and reaches peers only by addresses carried in a ticket — say so
    // rather than fail silently on the first wider dial.
    if matches!(network, crate::net::Network::Isolated) {
        tracing::info!(
            "LAIT_NETWORK=isolated: no relay and no discovery — peers are reached \
             by addresses carried in the ticket (host-star on a LAN); a wider mesh \
             beyond the ticket host is not resolved"
        );
    }
    let transport = factory
        .build(
            &identity_seed,
            &network,
            &[PRESENCE_ALPN, crate::sync::SYNC_ALPN],
        )
        .await?;
    // The transport's identity MUST be the daemon's. Nothing downstream can
    // detect a mismatch: signed gossip would carry one key while the peer
    // dialed back is another, minted tickets would advertise a host nobody can
    // reach, and every symptom would surface far from the cause.
    let expected = crate::crypto::device_from_seed(&identity_seed);
    if transport.my_id() != expected {
        anyhow::bail!("transport identity does not match daemon identity");
    }
    let my_id = transport.my_id();

    let shared = Shared {
        nick: Arc::new(Mutex::new(nick)),
        my_id: my_id.clone(),
        presence: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(EventLog::default())),
    };

    // The topic is a pure function of the space id — no user-settable
    // network name, so a cold boot can never subscribe to the wrong topic.
    let topic = crate::proto::topic_for_space(&replica.lock().unwrap().space_str());
    // Seed gossip bootstrap from previously-seen peers so a restart actively
    // rejoins the mesh instead of waiting to be re-announced, unioned with the
    // explicit, sticky seed pins so a restart always dials its
    // always-on seeds even when no ordinary peer was seen last run.
    let pinned_seeds = seed_ids(&home, &my_id);
    let mut bootstrap = load_bootstrap_peers(&home, &my_id);
    for id in &pinned_seeds {
        if !bootstrap.contains(id) {
            bootstrap.push(id.clone());
        }
    }
    // Subscribing also teaches the transport how to reach each bootstrap peer,
    // so a later bare-id dial to one of them resolves.
    let (sender, receiver) = transport.subscribe(topic, &bootstrap).await?;

    // A seed never idles out (DUR-4): it must stay reachable to serve sync and
    // backfill history even with no local client and no peer currently online.
    // Otherwise honour the configured idle window (LAIT_IDLE_SECS).
    let idle_window = if seed {
        Duration::ZERO
    } else {
        idle_window_from_env()
    };
    if seed {
        tracing::info!("running as an always-on seed — idle-shutdown disabled");
    }

    let space = replica.lock().unwrap().space_str();
    let node = Arc::new(Node {
        transport,
        sender: Mutex::new(Arc::from(sender)),
        identity_seed,
        space,
        shared,
        shutdown: Arc::new(Notify::new()),
        cancel: Cancel::new(),
        tasks: Arc::new(Mutex::new(JoinSet::new())),
        recv_gen: AtomicU64::new(1),
        active_conns: AtomicU64::new(0),
        last_active: Mutex::new(Instant::now()),
        idle_window,
        replica,
        doorbell: Arc::new(Mutex::new(DoorbellRing::new(now_secs()))),
        doorbell_notify: Arc::new(Notify::new()),
        syncing: Arc::new(Mutex::new(HashSet::new())),
        pending_incepts: Arc::new(Mutex::new(HashMap::new())),
        home: home.clone(),
    });

    // The accept loop goes up first: ALPNs were registered when the transport
    // was built, so inbound connections can already be queued behind it.
    node.spawn(node.clone().accept_loop());
    node.spawn(node.clone().recv_loop(receiver, 1));
    node.spawn(node.clone().heartbeat_loop());
    node.spawn(node.clone().reaper_loop());
    node.spawn(node.clone().checkpoint_loop());
    node.spawn(node.clone().idle_shutdown_loop());

    node.broadcast(Payload::Hello {
        nick: node.shared.nick(),
    })
    .await
    .ok();

    // Eagerly backfill from every pinned seed on startup — don't wait for a
    // gossip NeighborUp. This makes a seed a cold-start anchor: a
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

    {
        let t = node.replica.lock().unwrap();
        tracing::info!(
            "lait daemon online as {my_id} in space '{}' ({})",
            t.space_name(),
            t.space_str()
        );
    }

    let shutdown = node.shutdown.clone();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accept = listener.accept() => {
                match accept {
                    Ok(stream) => {
                        let n = node.clone();
                        node.spawn(async move { n.handle_conn(stream).await; });
                    }
                    Err(e) => tracing::warn!("control accept error: {e}"),
                }
            }
        }
    }

    // Stop accepting control connections immediately: the pipe/socket server
    // instance must go away with the loop, or a client that connects during
    // teardown parks forever on a server that will never answer.
    drop(listener);

    node.persist_known_peers();
    // Flush any mutations marked since the last checkpoint tick, so a clean
    // shutdown (e.g. idle-out) leaves the git history current rather than a few
    // seconds behind (the data itself is already fsync-durable regardless).
    node.replica.lock().unwrap().checkpoint();

    // Teardown order is load-bearing: `Bye` must reach the room while gossip is
    // still up, so peers mark us offline immediately instead of waiting out a
    // heartbeat lapse. Only then does cancellation go out, and only then does
    // the network close under the tasks that were using it.
    let _ = tokio::time::timeout(SHUTDOWN_DEADLINE, async {
        node.broadcast(Payload::Bye {
            nick: node.shared.nick(),
        })
        .await
        .ok();
        tokio::time::sleep(BYE_GRACE).await;
    })
    .await;
    node.cancel.cancel();

    // Take the task set out from under its lock: joining is an await, and the
    // lock must never be held across one.
    let mut tasks = std::mem::take(&mut *node.tasks.lock().unwrap());
    let _ = tokio::time::timeout(SHUTDOWN_DEADLINE, async {
        node.transport.shutdown().await;
        while tasks.join_next().await.is_some() {}
    })
    .await;
    // Whatever is still running past the deadline is wedged, not slow. Abort it
    // and reap the handles so nothing is left running behind our return.
    tasks.abort_all();
    let _ = tokio::time::timeout(SHUTDOWN_DEADLINE, async {
        while tasks.join_next().await.is_some() {}
    })
    .await;

    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::config::socket_path(&home));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sealed_invite_binds_to_its_redeemer_and_hides_from_the_topic() {
        use crate::actor::incept_single;
        use crate::ids::{SpaceId, SystemUlidSource};
        use crate::proto::{InviteGrant, SignedInvite};

        let ws = SpaceId::mint(&SystemUlidSource);
        let host_seed = [10u8; 32];
        let host = crate::crypto::device_from_seed(&host_seed);

        // The legit joiner and an eavesdropper, each with their own actor.
        let (j_incept, j_actor) = incept_single(&[11u8; 32], &ws, [1u8; 16], [2u8; 16], None);
        let (atk_incept, _atk_actor) = incept_single(&[12u8; 32], &ws, [3u8; 16], [4u8; 16], None);

        // An admin mints + signs an invite; the joiner seals it bound to itself.
        let grant = InviteGrant::mint(ws.to_string(), 0, 3600, true);
        let invite = SignedInvite::sign(&host_seed, &grant).unwrap();
        let sealed = seal_bound_invite(&host, &invite, &j_actor).unwrap();

        // The host opens it for the bound joiner.
        assert!(
            open_bound_invite(&host_seed, &host, &sealed, &j_incept).is_some(),
            "the host admits the bound joiner"
        );
        // Hijack attempt: an eavesdropper COPIES the opaque blob and re-pairs it
        // with its OWN inception — the redeemer binding refuses it.
        assert!(
            open_bound_invite(&host_seed, &host, &sealed, &atk_incept).is_none(),
            "a copied blob cannot admit a different actor"
        );
        // And a non-host cannot even read the blob — the nonce stays off the topic.
        let atk_device = crate::crypto::device_from_seed(&[12u8; 32]);
        assert!(
            open_bound_invite(&[12u8; 32], &atk_device, &sealed, &j_incept).is_none(),
            "only the host can open the sealed invite"
        );
    }

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

    // Doorbell/reset invariant: a subscription
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

    // The bootstrap peer set round-trips through disk and never seeds the
    // node with itself (dialing your own id is pointless and could self-loop).
    #[test]
    fn bootstrap_peers_persist_and_filter_self() {
        let dir = std::env::temp_dir().join(format!("gc-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let me = crate::crypto::device_from_seed(&[1u8; 32]);
        let peer = crate::crypto::device_from_seed(&[2u8; 32]);

        // Nothing persisted yet → empty bootstrap (the old always-empty case).
        assert!(load_bootstrap_peers(&dir, &me).is_empty());

        // Persist a set that includes ourselves; reload must drop self and keep
        // the real peer, so a restart bootstraps from the peer.
        save_known_peers(&dir, &[me.clone(), peer.clone()]);
        assert_eq!(load_bootstrap_peers(&dir, &me), vec![peer]);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The on-disk peer cache is written by one daemon and read by the next,
    /// possibly across an upgrade, so its encoding is a compatibility surface.
    /// This fixture is a literal `peers.json` written by a pre-cutover build; it
    /// must still load, and must still resolve to the same key the identity seed
    /// derives.
    #[test]
    fn a_legacy_peers_file_still_bootstraps() {
        let dir = std::env::temp_dir().join(format!("gc-legacy-peers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            peers_path(&dir),
            r#"["8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394"]"#,
        )
        .unwrap();

        let me = crate::crypto::device_from_seed(&[9u8; 32]);
        assert_eq!(
            load_bootstrap_peers(&dir, &me),
            vec![crate::crypto::device_from_seed(&[2u8; 32])],
            "a legacy peers.json must still name the same peer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The same obligation for `seeds.json`, plus the one that matters more:
    /// a seed is pinned infrastructure, so a file with one bad record keeps
    /// every good one instead of silently unpinning the lot.
    #[test]
    fn a_legacy_seeds_file_keeps_its_pins_and_rejects_only_the_bad_rows() {
        let dir = std::env::temp_dir().join(format!("gc-legacy-seeds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            seeds_path(&dir),
            r#"[
  {
    "id": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    "nick": "nas",
    "space": "ws_x"
  }
]"#,
        )
        .unwrap();

        let seeds = load_seeds(&dir);
        assert_eq!(seeds.len(), 1, "a legacy seeds.json must still load");
        assert_eq!(seeds[0].id, crate::crypto::device_from_seed(&[2u8; 32]));
        assert_eq!(seeds[0].nick, "nas");
        assert_eq!(seeds[0].space, "ws_x");

        // One good pin, one row missing its id, one row whose id is not a key.
        std::fs::write(
            seeds_path(&dir),
            r#"[
  {"id": "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394", "nick": "nas", "space": "ws_x"},
  {"nick": "no-id", "space": "ws_x"},
  {"id": "not-a-key", "nick": "junk", "space": "ws_x"}
]"#,
        )
        .unwrap();
        let seeds = load_seeds(&dir);
        assert_eq!(
            seeds.len(),
            1,
            "a bad row must cost its own pin and no others"
        );
        assert_eq!(seeds[0].nick, "nas");

        // A file that is not a list at all pins nothing rather than panicking.
        std::fs::write(seeds_path(&dir), "not json at all").unwrap();
        assert!(load_seeds(&dir).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // The pinned-seed registry is ID-keyed (no
    // duplicates), bootstrap ids drop self, and removal matches id or nick.
    #[test]
    fn seeds_upsert_dedup_and_remove() {
        let dir = std::env::temp_dir().join(format!("gc-seeds-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let a = crate::crypto::device_from_seed(&[2u8; 32]);
        let b = crate::crypto::device_from_seed(&[3u8; 32]);

        assert!(load_seeds(&dir).is_empty());

        // First add is new; re-adding the same id updates in place (not a dup).
        assert!(upsert_seed(
            &dir,
            SeedRecord {
                id: a.clone(),
                nick: "nas".into(),
                space: "ws".into()
            }
        ));
        assert!(!upsert_seed(
            &dir,
            SeedRecord {
                id: a.clone(),
                nick: "nas2".into(),
                space: "ws".into()
            }
        ));
        assert_eq!(load_seeds(&dir).len(), 1);
        assert_eq!(load_seeds(&dir)[0].nick, "nas2");

        assert!(upsert_seed(
            &dir,
            SeedRecord {
                id: b.clone(),
                nick: String::new(),
                space: "ws".into()
            }
        ));
        // Bootstrap ids list both, but filter out our own id when we are `a`.
        assert_eq!(seed_ids(&dir, &b).len(), 1);
        assert_eq!(
            seed_ids(&dir, &crate::crypto::device_from_seed(&[9u8; 32])).len(),
            2
        );

        // Remove by nick, then by full id.
        assert_eq!(remove_seed(&dir, "nas2"), 1);
        assert_eq!(remove_seed(&dir, b.as_str()), 1);
        assert!(load_seeds(&dir).is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
