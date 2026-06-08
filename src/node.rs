//! The groupchat daemon: owns the iroh endpoint, the gossip room, the blob
//! store, presence, and the local control server that CLI/MCP clients drive.

use std::{
    collections::{HashMap, VecDeque},
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
        Event as LogEvent, EventKind, PresenceEntry, Request, ResourceEntry, Response, StatusInfo,
    },
    proto::{topic_for_room, Payload, RoomTicket, SignedMessage},
};

/// How recently a peer must have been heard from to count as online.
const ONLINE_WINDOW: Duration = Duration::from_secs(30);
/// How often we broadcast a presence heartbeat.
const HEARTBEAT: Duration = Duration::from_secs(10);

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A peer we have heard from on the gossip topic.
#[derive(Debug, Clone)]
pub struct Peer {
    pub nick: String,
    pub last_seen: Instant,
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
}

impl Node {
    /// Update presence for a peer and return the best display nick.
    fn touch(&self, id: EndpointId, nick: Option<String>) -> String {
        {
            let mut p = self.shared.presence.lock().unwrap();
            let entry = p.entry(id).or_insert_with(|| Peer {
                nick: id.fmt_short().to_string(),
                last_seen: Instant::now(),
            });
            entry.last_seen = Instant::now();
            if let Some(n) = nick {
                if !n.is_empty() {
                    entry.nick = n;
                }
            }
        }
        if let Some(cn) = self.shared.contacts.lock().unwrap().nick_of(&id) {
            return cn;
        }
        self.shared
            .presence
            .lock()
            .unwrap()
            .get(&id)
            .map(|p| p.nick.clone())
            .unwrap_or_else(|| id.fmt_short().to_string())
    }

    /// Add (or update) a contact, persist it, and log a system event. Returns
    /// the nick used. Idempotent.
    fn add_contact(&self, id: EndpointId, nick: String) -> Result<String> {
        {
            let mut c = self.shared.contacts.lock().unwrap();
            c.add(id, nick.clone());
            c.save(&self.home)?;
        }
        self.shared.events.lock().unwrap().push(
            EventKind::System,
            id.to_string(),
            nick.clone(),
            format!("added {nick} to contacts"),
        );
        Ok(nick)
    }

    fn handle_payload(&self, from: EndpointId, payload: Payload) {
        match payload {
            Payload::Hello { nick } | Payload::Presence { nick } => {
                self.touch(from, Some(nick));
            }
            Payload::Chat { text } => {
                let nick = self.touch(from, None);
                self.shared
                    .events
                    .lock()
                    .unwrap()
                    .push(EventKind::Chat, from.to_string(), nick, text);
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
                            self.handle_payload(from, payload);
                        }
                    }
                    Event::NeighborUp(id) => {
                        self.touch(id, None);
                    }
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
            .map(|p| p.last_seen.elapsed() < ONLINE_WINDOW)
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
                    .filter(|p| p.last_seen.elapsed() < ONLINE_WINDOW)
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
                self.auto_approve.store(true, Ordering::SeqCst);
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
            Request::Send { text } => {
                self.broadcast(Payload::Chat { text: text.clone() }).await?;
                // echo into our own log so the sender sees it too
                self.shared.events.lock().unwrap().push(
                    EventKind::Chat,
                    self.shared.my_id.to_string(),
                    format!("{} (me)", self.shared.nick),
                    text,
                );
                Ok(Response::Ok { message: None })
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
                            online: p.last_seen.elapsed() < ONLINE_WINDOW,
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

    async fn handle_conn(self: Arc<Self>, stream: UnixStream) {
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
    };

    let call_handler = CallHandler::new(shared.clone());
    let router = Router::builder(endpoint.clone())
        .accept(GOSSIP_ALPN, gossip.clone())
        .accept(iroh_blobs::ALPN, blobs)
        .accept(CALL_ALPN, call_handler)
        .spawn();

    // Wait until we have a home relay so our advertised address is dialable.
    endpoint.online().await;

    // Subscribe to our room topic immediately (no bootstrap peers yet).
    let topic = topic_for_room(&profile.room);
    let gtopic = gossip
        .subscribe(topic, vec![])
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
        auto_approve: AtomicBool::new(false),
    });

    tokio::spawn(node.clone().recv_loop(receiver, 1));
    tokio::spawn(node.clone().heartbeat_loop());

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

    let _ = std::fs::remove_file(&socket);
    node.router.shutdown().await.ok();
    Ok(())
}
