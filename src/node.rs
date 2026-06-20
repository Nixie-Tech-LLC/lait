//! The groupchat daemon: owns the iroh endpoint, the gossip room, the blob
//! store, presence, and the local control server that CLI/MCP clients drive.

use std::{
    collections::{HashMap, HashSet, VecDeque},
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use anyhow::{anyhow, Context, Result};
use iroh::{
    address_lookup::memory::MemoryLookup, endpoint::presets, protocol::Router, Endpoint,
    EndpointAddr, EndpointId, SecretKey,
};
use iroh_blobs::{store::fs::FsStore, ticket::BlobTicket, BlobsProtocol};
use iroh_gossip::{
    api::{Event, GossipReceiver, GossipSender},
    net::{Gossip, GOSSIP_ALPN},
    proto::TopicId,
};
use n0_future::StreamExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::Notify,
};

use crate::{
    call::{place_call, CallHandler, CALL_ALPN},
    config::{
        blob_store_path, load_or_create_identity, socket_path, Contacts, Profile,
    },
    control::{
        Event as LogEvent, EventKind, MessageReceipts, PresenceEntry, RecipientReceipt, Request,
        ResourceEntry, Response, StatusInfo,
    },
    proto::{topic_for_room, Payload, ReceiptState, RoomTicket, SignedMessage, Tier},
};

/// How recently a peer must have been heard from to count as online.
const ONLINE_WINDOW: Duration = Duration::from_secs(30);
/// How often we broadcast a presence heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(10);
/// How often the reaper sweeps for stale peers.
const REAP_INTERVAL: Duration = Duration::from_secs(5);
/// Drop an offline peer from the presence table entirely after this long.
const PRUNE_WINDOW: Duration = Duration::from_secs(600);
/// Default ack window for a needs_ack/interrupt message that gives no explicit
/// deadline.
const ACK_DEADLINE_DEFAULT: Duration = Duration::from_secs(60);
/// How often the ack reaper checks outstanding messages for overdue acks.
const ACK_REAP_INTERVAL: Duration = Duration::from_secs(1);
/// How many times an interrupt-tier message is re-broadcast before giving up.
const MAX_ESCALATIONS: u32 = 3;
/// Base spacing between interrupt re-broadcasts (grows per escalation).
const ESCALATION_BACKOFF: Duration = Duration::from_secs(15);
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

/// Shorten a message for inclusion in a receipt/alert line.
fn truncate(text: &str) -> String {
    const MAX: usize = 48;
    if text.chars().count() <= MAX {
        text.to_string()
    } else {
        let cut: String = text.chars().take(MAX).collect();
        format!("{cut}\u{2026}")
    }
}

/// A peer we have heard from on the gossip topic.
#[derive(Debug, Clone)]
pub struct Peer {
    pub nick: String,
    pub last_seen: Instant,
    /// Last broadcast presence state, so we emit a notification only on the
    /// online<->offline transition rather than on every heartbeat.
    pub online: bool,
}

/// Append-only-ish ring buffer of chat/system events. Holds a `Notify` that is
/// fired on every push so blocking waiters (`Request::Wait`) wake the instant a
/// new event lands — event-based delivery instead of poll loops.
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
        self.push_full(kind, id, nick, text, Tier::Ambient, None);
    }

    /// Push an event marked `direct` — addressed to us, warranting a response
    /// (an @mention or an inbound call).
    pub fn push_direct(&mut self, kind: EventKind, id: String, nick: String, text: String) {
        self.push_full(kind, id, nick, text, Tier::Direct, None);
    }

    /// Push a chat event carrying an explicit tier and the sender's message id
    /// (the handle used to `ack` it).
    pub fn push_chat(
        &mut self,
        id: String,
        nick: String,
        text: String,
        tier: Tier,
        msg_id: u64,
    ) {
        self.push_full(EventKind::Chat, id, nick, text, tier, Some(msg_id));
    }

    /// Push with full control over tier and msg_id. `direct` is derived from the
    /// tier (anything `>= Direct` warrants a response).
    pub fn push_full(
        &mut self,
        kind: EventKind,
        id: String,
        nick: String,
        text: String,
        tier: Tier,
        msg_id: Option<u64>,
    ) {
        self.seq += 1;
        self.events.push_back(LogEvent {
            seq: self.seq,
            kind,
            id,
            nick,
            text,
            ts: now_secs(),
            direct: tier >= Tier::Direct,
            tier,
            msg_id,
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

    /// Resolve a local event `seq` to the chat message it refers to: its
    /// sender's id string and message id. Used to turn a user-facing `ack <seq>`
    /// into a receipt addressed at the original sender.
    pub fn chat_ref(&self, seq: u64) -> Option<(String, u64)> {
        self.events
            .iter()
            .find(|e| e.seq == seq && matches!(e.kind, EventKind::Chat))
            .and_then(|e| e.msg_id.map(|m| (e.id.clone(), m)))
    }
}

/// One message we sent that we're tracking receipts for, reconciled against the
/// expected recipient roster.
#[derive(Debug, Clone)]
struct Pending {
    text: String,
    tier: Tier,
    /// Resolved recipient roster we expect acks from.
    to: Vec<EndpointId>,
    deadline: Option<Instant>,
    deadline_ms: Option<u64>,
    delivered: HashSet<EndpointId>,
    seen: HashSet<EndpointId>,
    acked: HashSet<EndpointId>,
    /// Whether we've already surfaced the overdue-ack alert.
    alerted: bool,
    /// Interrupt-tier re-broadcast bookkeeping.
    escalations: u32,
    next_escalation: Option<Instant>,
}

impl Pending {
    fn all_acked(&self) -> bool {
        self.to.iter().all(|id| self.acked.contains(id))
    }
}

/// Outbox of messages we sent that expect receipts, keyed by msg_id.
#[derive(Debug, Default)]
pub struct Outbox {
    pending: HashMap<u64, Pending>,
}

/// Cheaply-cloneable shared state, also handed to the call handler.
#[derive(Debug, Clone)]
pub struct Shared {
    pub nick: String,
    pub room: String,
    pub my_id: EndpointId,
    pub contacts: Arc<Mutex<Contacts>>,
    pub presence: Arc<Mutex<HashMap<EndpointId, Peer>>>,
    pub events: Arc<Mutex<EventLog>>,
    pub resources: Arc<Mutex<Vec<ResourceEntry>>>,
    /// Messages we've sent that are awaiting delivery/read/ack receipts.
    pub outbox: Arc<Mutex<Outbox>>,
    /// Receiver focus: silence anything below this tier unless it's notify_anyway.
    pub mute_below: Arc<Mutex<Tier>>,
}

/// The running node.
pub struct Node {
    home: PathBuf,
    endpoint: Endpoint,
    gossip: Gossip,
    sender: Mutex<GossipSender>,
    store: FsStore,
    secret_key: SecretKey,
    memory_lookup: MemoryLookup,
    router: Router,
    shared: Shared,
    shutdown: Arc<Notify>,
    /// Bumped on every (re)subscribe so stale receive loops exit.
    recv_gen: AtomicU64,
    /// When set (after minting an invite), inbound join requests are auto-added
    /// as contacts so onboarding is mutual and one-step.
    auto_approve: AtomicBool,
    /// Monotonic source of message ids; the global identity is `(my_id, msg_id)`.
    next_msg_id: AtomicU64,
    /// Local event seqs we've already emitted a Seen receipt for, so following
    /// the log with several clients doesn't re-emit.
    seen_emitted: Mutex<HashSet<u64>>,
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
        let mut came_online = false;
        {
            let mut p = self.shared.presence.lock().unwrap();
            let entry = p.entry(id).or_insert_with(|| Peer {
                nick: id.fmt_short().to_string(),
                last_seen: Instant::now(),
                online: false,
            });
            if !entry.online {
                entry.online = true;
                came_online = true;
            }
            entry.last_seen = Instant::now();
            if let Some(n) = nick {
                if !n.is_empty() {
                    entry.nick = n;
                }
            }
        }
        let display = self
            .shared
            .contacts
            .lock()
            .unwrap()
            .nick_of(&id)
            .or_else(|| {
                self.shared
                    .presence
                    .lock()
                    .unwrap()
                    .get(&id)
                    .map(|p| p.nick.clone())
            })
            .unwrap_or_else(|| id.fmt_short().to_string());
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

    /// Mark a peer offline and emit a "went offline" notification, once.
    fn mark_offline(&self, id: EndpointId, left: bool) {
        let nick = {
            let mut p = self.shared.presence.lock().unwrap();
            match p.get_mut(&id) {
                Some(peer) if peer.online => {
                    peer.online = false;
                    peer.nick.clone()
                }
                _ => return, // unknown or already offline — nothing to announce
            }
        };
        let display = self.shared.contacts.lock().unwrap().nick_of(&id).unwrap_or(nick);
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

    /// Add (or update) a contact, persist it, and log a system event. Returns
    /// the nick used. Idempotent.
    fn add_contact(&self, id: EndpointId, nick: String) -> Result<String> {
        let pruned = {
            let mut c = self.shared.contacts.lock().unwrap();
            // Replace any stale identity that used this nick (e.g. a reinstall).
            let pruned = c.remove_stale_nick(&nick, &id);
            c.add(id, nick.clone());
            c.save(&self.home)?;
            pruned
        };
        for old in &pruned {
            if let Ok(old_id) = old.parse::<EndpointId>() {
                self.shared.presence.lock().unwrap().remove(&old_id);
            }
        }
        self.shared.events.lock().unwrap().push(
            EventKind::System,
            id.to_string(),
            nick.clone(),
            if pruned.is_empty() {
                format!("added {nick} to contacts")
            } else {
                format!("added {nick} to contacts (replaced {} stale identity)", pruned.len())
            },
        );
        Ok(nick)
    }

    /// Periodically mark stale-online peers offline and prune long-dead ones —
    /// presence stays accurate without anyone managing it by hand.
    async fn reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(REAP_INTERVAL);
        loop {
            interval.tick().await;
            let stale: Vec<EndpointId> = {
                let p = self.shared.presence.lock().unwrap();
                p.iter()
                    .filter(|(_, peer)| peer.online && peer.last_seen.elapsed() >= ONLINE_WINDOW)
                    .map(|(id, _)| *id)
                    .collect()
            };
            for id in stale {
                self.mark_offline(id, false);
            }
            self.shared
                .presence
                .lock()
                .unwrap()
                .retain(|_, peer| peer.online || peer.last_seen.elapsed() < PRUNE_WINDOW);
        }
    }

    /// Emit Seen receipts for tracked chat events being handed to a client (via
    /// `wait`/`log`) — the agent reading them is our proxy for "seen". Tracked
    /// inbound messages always surface at `tier >= Direct`; ambient room chatter
    /// generates no receipt traffic. Deduped by local seq.
    async fn emit_seen(&self, events: &[LogEvent]) {
        let mut to_send: Vec<(EndpointId, u64)> = Vec::new();
        {
            let mut em = self.seen_emitted.lock().unwrap();
            for e in events {
                if e.tier < Tier::Direct {
                    continue;
                }
                let Some(mid) = e.msg_id else { continue };
                let Ok(src) = e.id.parse::<EndpointId>() else {
                    continue;
                };
                if src != self.shared.my_id && em.insert(e.seq) {
                    to_send.push((src, mid));
                }
            }
        }
        for (src, mid) in to_send {
            let _ = self
                .broadcast(Payload::Receipt {
                    ref_from: src,
                    ref_msg_id: mid,
                    state: ReceiptState::Seen,
                })
                .await;
        }
    }

    /// Watch the outbox for needs_ack/interrupt messages whose deadline lapsed
    /// without a full set of acks. Surfaces a local (direct) alert so the
    /// sender's agent notices, and re-broadcasts interrupt-tier messages on a
    /// backoff until they're acked or the retry budget is spent.
    async fn ack_reaper_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(ACK_REAP_INTERVAL);
        loop {
            interval.tick().await;
            let now = Instant::now();
            let mut alerts: Vec<(u64, String, String)> = Vec::new();
            let mut rebroadcasts: Vec<Payload> = Vec::new();
            {
                let mut ob = self.shared.outbox.lock().unwrap();
                for (msg_id, p) in ob.pending.iter_mut() {
                    let Some(deadline) = p.deadline else { continue };
                    if p.all_acked() || now < deadline {
                        continue;
                    }
                    if !p.alerted {
                        p.alerted = true;
                        let missing: Vec<String> = p
                            .to
                            .iter()
                            .filter(|id| !p.acked.contains(*id))
                            .map(|id| self.display_nick(id))
                            .collect();
                        alerts.push((*msg_id, truncate(&p.text), missing.join(", ")));
                    }
                    if p.tier == Tier::Interrupt && p.escalations < MAX_ESCALATIONS {
                        let due = p.next_escalation.map(|t| now >= t).unwrap_or(true);
                        if due {
                            p.escalations += 1;
                            p.next_escalation = Some(now + ESCALATION_BACKOFF * p.escalations);
                            // Annotate with the nudge count so each re-broadcast
                            // is byte-distinct — iroh-gossip drops byte-identical
                            // repeats as loop prevention — and the repeat reads as
                            // an escalation to the receiver. The msg_id is
                            // unchanged, so an ack still resolves to it.
                            rebroadcasts.push(Payload::Chat {
                                text: format!("{} \u{23EB}(nudge {})", p.text, p.escalations),
                                msg_id: *msg_id,
                                tier: Tier::Interrupt,
                                to: p.to.clone(),
                                deadline_ms: p.deadline_ms,
                                notify_anyway: true,
                            });
                        }
                    }
                }
            }
            for (msg_id, text, who) in alerts {
                self.shared.events.lock().unwrap().push_full(
                    EventKind::Receipt,
                    self.shared.my_id.to_string(),
                    "system".to_string(),
                    format!("\u{26A0} no ack for msg {msg_id} (\u{201C}{text}\u{201D}) from: {who}"),
                    Tier::Direct,
                    None,
                );
            }
            for payload in rebroadcasts {
                let _ = self.broadcast(payload).await;
            }
        }
    }

    /// Whether a chat line addresses us directly (an `@nick` or a bare mention
    /// of our nick as a word) — worth a response rather than a glance.
    fn mentions_me(&self, text: &str) -> bool {
        let nick = self.shared.nick.to_lowercase();
        if nick.is_empty() {
            return false;
        }
        let t = text.to_lowercase();
        t.contains(&format!("@{nick}"))
            || t.split(|c: char| !c.is_alphanumeric()).any(|w| w == nick)
    }

    /// Best display name for a peer: contact nick, else last-seen presence nick,
    /// else the short id.
    fn display_nick(&self, id: &EndpointId) -> String {
        self.shared
            .contacts
            .lock()
            .unwrap()
            .nick_of(id)
            .or_else(|| {
                self.shared
                    .presence
                    .lock()
                    .unwrap()
                    .get(id)
                    .map(|p| p.nick.clone())
            })
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
            Payload::Chat {
                text,
                msg_id,
                tier,
                to,
                deadline_ms: _,
                notify_anyway,
            } => {
                let nick = self.touch(from, None);
                let me = self.shared.my_id;
                // Addressed to us? An explicit `to` wins; otherwise an @mention.
                let addressed = if to.is_empty() {
                    self.mentions_me(&text)
                } else {
                    to.contains(&me)
                };
                // Effective tier: addressing lifts to at least Direct, then the
                // receiver's focus may silence it (unless notify_anyway).
                let mut eff = tier.max(if addressed { Tier::Direct } else { Tier::Ambient });
                let mute_below = *self.shared.mute_below.lock().unwrap();
                if eff < mute_below && !notify_anyway {
                    eff = Tier::Ambient;
                }
                // The sender tracks receipts for needs_ack/interrupt or any
                // explicitly-addressed message; emit a Delivered receipt for those.
                let tracked = tier >= Tier::NeedsAck || !to.is_empty();
                if tracked && from != me {
                    let _ = self
                        .broadcast(Payload::Receipt {
                            ref_from: from,
                            ref_msg_id: msg_id,
                            state: ReceiptState::Delivered,
                        })
                        .await;
                }
                self.shared
                    .events
                    .lock()
                    .unwrap()
                    .push_chat(from.to_string(), nick, text, eff, msg_id);
            }
            Payload::Receipt {
                ref_from,
                ref_msg_id,
                state,
            } => {
                // Only the original sender acts on a receipt; everyone else on
                // the gossip topic ignores it.
                if ref_from != self.shared.my_id || from == self.shared.my_id {
                    return;
                }
                let display = self.display_nick(&from);
                let mut acked_text: Option<String> = None;
                {
                    let mut ob = self.shared.outbox.lock().unwrap();
                    if let Some(p) = ob.pending.get_mut(&ref_msg_id) {
                        // Make sure this peer is on the tracked roster (a room
                        // needs_ack reaches peers that joined after send).
                        if !p.to.contains(&from) {
                            p.to.push(from);
                        }
                        match state {
                            ReceiptState::Delivered => {
                                p.delivered.insert(from);
                            }
                            ReceiptState::Seen => {
                                p.delivered.insert(from);
                                p.seen.insert(from);
                            }
                            ReceiptState::Acked => {
                                p.delivered.insert(from);
                                p.seen.insert(from);
                                p.acked.insert(from);
                                acked_text = Some(p.text.clone());
                            }
                        }
                    }
                }
                if let Some(text) = acked_text {
                    self.shared.events.lock().unwrap().push_full(
                        EventKind::Receipt,
                        from.to_string(),
                        display.clone(),
                        format!("{display} acked: \u{201C}{}\u{201D}", truncate(&text)),
                        Tier::Ambient,
                        None,
                    );
                }
            }
            Payload::JoinRequest { nick } => {
                let display = self.touch(from, Some(nick.clone()));
                let already = self.shared.contacts.lock().unwrap().contains(&from);
                if already {
                    self.shared.events.lock().unwrap().push(
                        EventKind::Join,
                        from.to_string(),
                        display.clone(),
                        format!("{display} (already a contact) joined the room"),
                    );
                } else if self.auto_approve.load(Ordering::SeqCst) {
                    // They joined via an invite we minted: auto-approve so the
                    // contact link is mutual without a manual step.
                    let _ = self.add_contact(from, nick.clone());
                    self.shared.events.lock().unwrap().push(
                        EventKind::Join,
                        from.to_string(),
                        nick.clone(),
                        format!("{nick} joined via your invite \u{2014} auto-approved as a contact"),
                    );
                } else {
                    self.shared.events.lock().unwrap().push(
                        EventKind::Join,
                        from.to_string(),
                        display,
                        format!(
                            "{nick} wants to join \u{2014} approve with: groupchat contacts add {from} {nick}"
                        ),
                    );
                }
            }
            Payload::Resource { label, ticket } => {
                let nick = self.touch(from, None);
                self.shared.resources.lock().unwrap().push(ResourceEntry {
                    label: label.clone(),
                    ticket: ticket.clone(),
                    from: nick.clone(),
                });
                self.shared.events.lock().unwrap().push(
                    EventKind::Resource,
                    from.to_string(),
                    nick,
                    format!("shared resource '{label}' \u{2014} get it with: groupchat get {label}"),
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
    async fn join_topic(self: &Arc<Self>, topic: TopicId, peers: Vec<EndpointAddr>) -> Result<()> {
        let peer_ids: Vec<EndpointId> = peers.iter().map(|p| p.id).collect();
        for p in peers {
            self.memory_lookup.add_endpoint_info(p);
        }
        let gtopic = tokio::time::timeout(
            Duration::from_secs(15),
            self.gossip.subscribe_and_join(topic, peer_ids),
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
                        if let Ok((from, payload)) = SignedMessage::verify_and_decode(&msg.content) {
                            self.handle_payload(from, payload).await;
                        }
                    }
                    Event::NeighborUp(id) => {
                        self.touch(id, None);
                    }
                    // NeighborDown only means this peer is no longer one of our
                    // *direct* gossip neighbors — the mesh reshuffles neighbors
                    // constantly without anyone actually leaving. Treating it as
                    // "offline" causes online/offline flapping. Presence is driven
                    // by heartbeats instead: a peer goes offline when its
                    // heartbeats lapse (the reaper) or it sends a graceful Bye.
                    Event::NeighborDown(_) | Event::Lagged => {}
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
            if self.recv_gen.load(Ordering::SeqCst) == 0 {
                // not subscribed yet; skip
            }
            let _ = self
                .broadcast(Payload::Presence {
                    nick: self.shared.nick.clone(),
                })
                .await;
        }
    }

    /// Resolve a "who" string (endpoint id or contact/presence nick) to an id.
    fn resolve_target(&self, who: &str) -> Option<EndpointId> {
        if let Ok(id) = who.parse::<EndpointId>() {
            return Some(id);
        }
        // by contact nick
        for c in self.shared.contacts.lock().unwrap().list() {
            if c.nick == who {
                if let Ok(id) = c.id.parse::<EndpointId>() {
                    return Some(id);
                }
            }
        }
        // by presence nick
        for (id, p) in self.shared.presence.lock().unwrap().iter() {
            if p.nick == who {
                return Some(*id);
            }
        }
        None
    }

    fn is_online(&self, id: &EndpointId) -> bool {
        self.shared
            .presence
            .lock()
            .unwrap()
            .get(id)
            .map(|p| p.online)
            .unwrap_or(false)
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
                    .filter(|p| p.online)
                    .count();
                Ok(Response::Status(StatusInfo {
                    id: self.shared.my_id.to_string(),
                    nick: self.shared.nick.clone(),
                    room: self.shared.room.clone(),
                    online_peers,
                    contacts: self.shared.contacts.lock().unwrap().list().len(),
                    resources: self.shared.resources.lock().unwrap().len(),
                }))
            }
            Request::Id => Ok(Response::Text {
                text: self.shared.my_id.to_string(),
            }),
            Request::Invite => {
                // Minting an invite is an explicit "let this person in", so
                // auto-approve their inbound join request for one-step onboarding.
                // Persist it so a reused ticket still auto-approves after a restart.
                if !self.auto_approve.swap(true, Ordering::SeqCst) {
                    if let Ok(mut p) = Profile::load(&self.home) {
                        p.auto_approve = true;
                        let _ = p.save(&self.home);
                    }
                }
                let ticket = RoomTicket {
                    topic: topic_for_room(&self.shared.room),
                    peers: vec![self.endpoint.addr()],
                    host_nick: self.shared.nick.clone(),
                };
                Ok(Response::Text {
                    text: ticket.to_string(),
                })
            }
            Request::Join { ticket } => {
                let ticket: RoomTicket = ticket.parse().context("parse room ticket")?;
                self.join_topic(ticket.topic, ticket.peers).await?;
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
                let host = ticket.host();
                self.join_topic(ticket.topic, ticket.peers).await?;
                // Auto-add the host as a contact (their id is the first peer).
                let host_msg = if let Some(addr) = host {
                    if addr.id != self.shared.my_id {
                        let nick = if ticket.host_nick.is_empty() {
                            addr.id.fmt_short().to_string()
                        } else {
                            ticket.host_nick.clone()
                        };
                        self.add_contact(addr.id, nick.clone())?;
                        format!(" and added {nick} as a contact")
                    } else {
                        String::new()
                    }
                } else {
                    String::new()
                };
                self.broadcast(Payload::JoinRequest {
                    nick: self.shared.nick.clone(),
                })
                .await
                .ok();
                Ok(Response::Ok {
                    message: Some(format!("connected to room{host_msg} \u{2014} you're live")),
                })
            }
            Request::Send {
                text,
                to,
                tier,
                deadline_ms,
                notify_anyway,
            } => {
                let msg_id = self.next_msg_id.fetch_add(1, Ordering::SeqCst);
                // Resolve the addressed recipients (nick or id) to endpoint ids.
                let mut to_ids: Vec<EndpointId> = Vec::new();
                let mut unknown: Vec<String> = Vec::new();
                for w in &to {
                    match self.resolve_target(w) {
                        Some(id) => to_ids.push(id),
                        None => unknown.push(w.clone()),
                    }
                }
                if !unknown.is_empty() {
                    return Err(anyhow!("unknown recipient(s): {}", unknown.join(", ")));
                }
                // We track receipts when the sender wants them: needs_ack /
                // interrupt, or any explicitly-addressed message.
                let tracked = tier >= Tier::NeedsAck || !to_ids.is_empty();
                if tracked {
                    let expected: Vec<EndpointId> = if !to_ids.is_empty() {
                        to_ids.clone()
                    } else {
                        // Room-wide needs_ack: expect acks from everyone online.
                        self.shared
                            .presence
                            .lock()
                            .unwrap()
                            .iter()
                            .filter(|(id, p)| p.online && **id != self.shared.my_id)
                            .map(|(id, _)| *id)
                            .collect()
                    };
                    let deadline = match deadline_ms {
                        Some(ms) => Some(Instant::now() + Duration::from_millis(ms)),
                        None if tier >= Tier::NeedsAck => Some(Instant::now() + ACK_DEADLINE_DEFAULT),
                        None => None,
                    };
                    self.shared.outbox.lock().unwrap().pending.insert(
                        msg_id,
                        Pending {
                            text: text.clone(),
                            tier,
                            to: expected,
                            deadline,
                            deadline_ms,
                            delivered: HashSet::new(),
                            seen: HashSet::new(),
                            acked: HashSet::new(),
                            alerted: false,
                            escalations: 0,
                            next_escalation: None,
                        },
                    );
                }
                self.broadcast(Payload::Chat {
                    text: text.clone(),
                    msg_id,
                    tier,
                    to: to_ids,
                    deadline_ms,
                    notify_anyway,
                })
                .await?;
                // echo into our own log so the sender sees it too
                self.shared.events.lock().unwrap().push_chat(
                    self.shared.my_id.to_string(),
                    format!("{} (me)", self.shared.nick),
                    text,
                    tier,
                    msg_id,
                );
                Ok(Response::Text {
                    text: if tracked {
                        format!("sent (msg {msg_id}); ack/receipts track it")
                    } else {
                        format!("sent (msg {msg_id})")
                    },
                })
            }
            Request::Log { since } => {
                let (events, last) = self.shared.events.lock().unwrap().since(since);
                self.emit_seen(&events).await;
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
                        self.emit_seen(&events).await;
                        return Ok(Response::Events { events, last });
                    }

                    tokio::select! {
                        _ = &mut notified => continue,
                        _ = tokio::time::sleep_until(deadline) => {
                            let (events, last) = self.shared.events.lock().unwrap().since(since);
                            self.emit_seen(&events).await;
                            return Ok(Response::Events { events, last });
                        }
                    }
                }
            }
            Request::Who => {
                let contacts = self.shared.contacts.lock().unwrap();
                let peers = self
                    .shared
                    .presence
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|(id, p)| {
                        let is_contact = contacts.contains(id);
                        let nick = contacts.nick_of(id).unwrap_or_else(|| p.nick.clone());
                        PresenceEntry {
                            id: id.to_string(),
                            nick,
                            online: p.online,
                            is_contact,
                            last_seen_secs: p.last_seen.elapsed().as_secs(),
                        }
                    })
                    .collect();
                Ok(Response::Who { peers })
            }
            Request::ContactsList => Ok(Response::Contacts {
                contacts: self.shared.contacts.lock().unwrap().list(),
            }),
            Request::ContactsAdd { id, nick } => {
                let eid: EndpointId = id.parse().map_err(|e| anyhow!("parse endpoint id: {e}"))?;
                let nick = nick.unwrap_or_else(|| {
                    self.shared
                        .presence
                        .lock()
                        .unwrap()
                        .get(&eid)
                        .map(|p| p.nick.clone())
                        .unwrap_or_else(|| eid.fmt_short().to_string())
                });
                self.add_contact(eid, nick.clone())?;
                Ok(Response::Ok {
                    message: Some(format!("added contact {nick}")),
                })
            }
            Request::ContactsRemove { id } => {
                let eid: EndpointId = id.parse().map_err(|e| anyhow!("parse endpoint id: {e}"))?;
                let removed = {
                    let mut c = self.shared.contacts.lock().unwrap();
                    let r = c.remove(&eid);
                    c.save(&self.home)?;
                    r
                };
                Ok(Response::Ok {
                    message: Some(if removed {
                        "contact removed".to_string()
                    } else {
                        "no such contact".to_string()
                    }),
                })
            }
            Request::Call { who, text } => {
                let target = self
                    .resolve_target(&who)
                    .ok_or_else(|| anyhow!("unknown peer: {who}"))?;
                if !self.shared.contacts.lock().unwrap().contains(&target) {
                    return Err(anyhow!("{who} is not in your contacts \u{2014} add them first"));
                }
                if !self.is_online(&target) {
                    return Err(anyhow!("{who} is not online"));
                }
                let text = text.unwrap_or_else(|| "\u{1F44B} (ring)".to_string());
                let ack = place_call(&self.endpoint, target, &self.shared.nick, &text).await?;
                Ok(Response::Text {
                    text: format!("call connected; they said: {ack}"),
                })
            }
            Request::Share { path, label } => {
                let abs = std::path::absolute(&path).context("resolve path")?;
                let label = label.unwrap_or_else(|| {
                    abs.file_name()
                        .map(|s| s.to_string_lossy().to_string())
                        .unwrap_or_else(|| "resource".to_string())
                });
                let tag = self
                    .store
                    .blobs()
                    .add_path(abs)
                    .await
                    .map_err(|e| anyhow!("add file to blob store: {e}"))?;
                let ticket = BlobTicket::new(self.endpoint.addr(), tag.hash, tag.format);
                let ticket_str = ticket.to_string();
                self.shared.resources.lock().unwrap().push(ResourceEntry {
                    label: label.clone(),
                    ticket: ticket_str.clone(),
                    from: format!("{} (me)", self.shared.nick),
                });
                self.broadcast(Payload::Resource {
                    label: label.clone(),
                    ticket: ticket_str.clone(),
                })
                .await
                .ok();
                Ok(Response::Text { text: ticket_str })
            }
            Request::Get { resource, out } => {
                let ticket: BlobTicket = match resource.parse::<BlobTicket>() {
                    Ok(t) => t,
                    Err(_) => {
                        let found = self
                            .shared
                            .resources
                            .lock()
                            .unwrap()
                            .iter()
                            .find(|r| r.label == resource)
                            .map(|r| r.ticket.clone());
                        let s = found
                            .ok_or_else(|| anyhow!("no resource or ticket matching '{resource}'"))?;
                        s.parse::<BlobTicket>()
                            .map_err(|e| anyhow!("parse stored ticket: {e}"))?
                    }
                };
                let downloader = self.store.downloader(&self.endpoint);
                downloader
                    .download(ticket.hash(), Some(ticket.addr().id))
                    .await
                    .map_err(|e| anyhow!("download: {e}"))?;
                let out_path = std::path::absolute(&out).context("resolve out path")?;
                self.store
                    .blobs()
                    .export(ticket.hash(), out_path.clone())
                    .await
                    .map_err(|e| anyhow!("export: {e}"))?;
                Ok(Response::Text {
                    text: format!("downloaded to {}", out_path.display()),
                })
            }
            Request::Resources => Ok(Response::Resources {
                resources: self.shared.resources.lock().unwrap().clone(),
            }),
            Request::Ack { seq } => {
                let (sender_id, msg_id) = self
                    .shared
                    .events
                    .lock()
                    .unwrap()
                    .chat_ref(seq)
                    .ok_or_else(|| anyhow!("no chat message at seq {seq}"))?;
                let ref_from: EndpointId = sender_id
                    .parse()
                    .map_err(|e| anyhow!("parse sender id: {e}"))?;
                if ref_from == self.shared.my_id {
                    return Err(anyhow!("that's your own message"));
                }
                self.broadcast(Payload::Receipt {
                    ref_from,
                    ref_msg_id: msg_id,
                    state: ReceiptState::Acked,
                })
                .await?;
                Ok(Response::Ok {
                    message: Some(format!("acked msg {msg_id}")),
                })
            }
            Request::Receipts { seq } => {
                // Optionally scope to one message identified by a local seq.
                let only = match seq {
                    Some(s) => Some(
                        self.shared
                            .events
                            .lock()
                            .unwrap()
                            .chat_ref(s)
                            .ok_or_else(|| anyhow!("no chat message at seq {s}"))?
                            .1,
                    ),
                    None => None,
                };
                let now = Instant::now();
                let ob = self.shared.outbox.lock().unwrap();
                let mut messages: Vec<MessageReceipts> = ob
                    .pending
                    .iter()
                    .filter(|(mid, _)| only.map(|o| **mid == o).unwrap_or(true))
                    .map(|(mid, p)| {
                        let overdue = p.deadline.map(|d| now >= d).unwrap_or(false) && !p.all_acked();
                        let recipients = p
                            .to
                            .iter()
                            .map(|id| RecipientReceipt {
                                id: id.to_string(),
                                nick: self.display_nick(id),
                                delivered: p.delivered.contains(id),
                                seen: p.seen.contains(id),
                                acked: p.acked.contains(id),
                            })
                            .collect();
                        MessageReceipts {
                            msg_id: *mid,
                            text: p.text.clone(),
                            tier: p.tier,
                            overdue,
                            recipients,
                        }
                    })
                    .collect();
                messages.sort_by_key(|m| m.msg_id);
                Ok(Response::Receipts { messages })
            }
            Request::Focus { mute_below, clear } => {
                let new = if clear {
                    Tier::Ambient
                } else {
                    mute_below.unwrap_or(*self.shared.mute_below.lock().unwrap())
                };
                *self.shared.mute_below.lock().unwrap() = new;
                if let Ok(mut p) = Profile::load(&self.home) {
                    p.mute_below = new;
                    let _ = p.save(&self.home);
                }
                Ok(Response::Ok {
                    message: Some(match new {
                        Tier::Ambient => "focus cleared \u{2014} nothing muted".to_string(),
                        t => format!("focus on \u{2014} muting below {t:?} (notify_anyway overrides)"),
                    }),
                })
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
    async fn handle_conn(self: Arc<Self>, stream: UnixStream) {
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

    async fn handle_conn_inner(self: Arc<Self>, stream: UnixStream) {
        let (read_half, mut write_half) = stream.into_split();
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
        let mut out = serde_json::to_string(&resp)
            .unwrap_or_else(|_| "{\"status\":\"error\",\"message\":\"encode failure\"}".to_string());
        out.push('\n');
        let _ = write_half.write_all(out.as_bytes()).await;
        let _ = write_half.flush().await;
    }
}

/// Build and run the daemon until a Stop request arrives.
pub async fn run_daemon(home: PathBuf) -> Result<()> {
    let secret_key = load_or_create_identity(&home)?;
    let profile = Profile::load(&home)?;
    let contacts = Contacts::load(&home)?;

    let memory_lookup = MemoryLookup::new();
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key.clone())
        .address_lookup(memory_lookup.clone())
        .bind()
        .await?;
    let my_id = endpoint.id();

    let store = FsStore::load(blob_store_path(&home))
        .await
        .map_err(|e| anyhow!("open blob store: {e}"))?;
    let blobs = BlobsProtocol::new(&store, None);
    let gossip = Gossip::builder().spawn(endpoint.clone());

    let shared = Shared {
        nick: profile.nick.clone(),
        room: profile.room.clone(),
        my_id,
        contacts: Arc::new(Mutex::new(contacts)),
        presence: Arc::new(Mutex::new(HashMap::new())),
        events: Arc::new(Mutex::new(EventLog::default())),
        resources: Arc::new(Mutex::new(Vec::new())),
        outbox: Arc::new(Mutex::new(Outbox::default())),
        mute_below: Arc::new(Mutex::new(profile.mute_below)),
    };

    let call_handler = CallHandler::new(shared.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .accept(CALL_ALPN, call_handler)
        .spawn();

    // Wait until we have a home relay so our advertised address is dialable.
    endpoint.online().await;

    // Subscribe to our room topic, bootstrapping off known contacts so that
    // restarting the daemon reconnects us to the people we already know (dialed
    // by endpoint id via discovery) instead of waiting to be re-invited.
    let topic = topic_for_room(&profile.room);
    let bootstrap: Vec<EndpointId> = shared
        .contacts
        .lock()
        .unwrap()
        .list()
        .iter()
        .filter_map(|c| c.id.parse::<EndpointId>().ok())
        .collect();
    if !bootstrap.is_empty() {
        tracing::info!("bootstrapping room off {} contact(s)", bootstrap.len());
    }
    let gtopic = gossip
        .subscribe(topic, bootstrap)
        .await
        .map_err(|e| anyhow!("subscribe to room: {e}"))?;
    let (sender, receiver) = gtopic.split();

    let node = Arc::new(Node {
        home: home.clone(),
        endpoint,
        gossip,
        sender: Mutex::new(sender),
        store,
        secret_key,
        memory_lookup,
        router,
        shared,
        shutdown: Arc::new(Notify::new()),
        recv_gen: AtomicU64::new(1),
        auto_approve: AtomicBool::new(profile.auto_approve),
        next_msg_id: AtomicU64::new(now_secs().saturating_mul(1000)),
        seen_emitted: Mutex::new(HashSet::new()),
        active_conns: AtomicU64::new(0),
        last_active: Mutex::new(Instant::now()),
        idle_window: idle_window_from_env(),
    });

    tokio::spawn(node.clone().recv_loop(receiver, 1));
    tokio::spawn(node.clone().heartbeat_loop());
    tokio::spawn(node.clone().reaper_loop());
    tokio::spawn(node.clone().ack_reaper_loop());
    tokio::spawn(node.clone().idle_shutdown_loop());

    // announce ourselves
    node.broadcast(Payload::Hello {
        nick: node.shared.nick.clone(),
    })
    .await
    .ok();

    // control server
    let socket = socket_path(&home);
    let _ = std::fs::remove_file(&socket);
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("bind control socket {}", socket.display()))?;

    tracing::info!("groupchat daemon online as {my_id} in room '{}'", profile.room);

    let shutdown = node.shutdown.clone();
    loop {
        tokio::select! {
            _ = shutdown.notified() => break,
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _)) => {
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

    let _ = std::fs::remove_file(&socket);
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
        assert!(!should_idle_shutdown(0, Duration::from_secs(600), Duration::ZERO));
    }
}
