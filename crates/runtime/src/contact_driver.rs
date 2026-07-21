//! The Station's Contact plane — C2.2/C2.3.
//!
//! One tracked driver thread runs a current-thread tokio runtime hosting:
//!
//! - the **accept loop**: inbound `lait/contact/1` connections are answered by
//!   serving a snapshot of the Replica's retained material (signed Hello/Ack
//!   handshake binding Space, Stations, transport identity, and nonces; then
//!   the canonical frame sequence; then the `TransferAck`, `finish`,
//!   `wait_closed` discipline). Inbound `lait/neighbor-presence/1` probes are
//!   answered with a signed ack. The transport peer is bound to the signed
//!   Station identity **before** any staging is allocated.
//! - the **scheduler**: at most four Contacts in flight globally and one per
//!   Neighbor; eligibility comes from the persistent registry (pending mark,
//!   exponential 1 s–5 min backoff with jitter, unexpired route lease); fair
//!   round-robin by due time; success resets backoff; dormancy cancels
//!   everything and rejects newly queued work.
//! - optional **gossip**: periodic signed Beacon emission on the Space's room
//!   and ingestion of received Beacons into the registry (verified, forward-
//!   only, coalescing).
//!
//! A completed inbound transfer is staged as untrusted bytes, validated into
//! the sealed bundle (authority batch first, durably), incorporated under the
//! Station writer, and only then acknowledged to the caller. `TransferAck`
//! means transcript receipt, never durable convergence.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use mechanics::ids::{SpaceId, StationId};
use replica::{AuthorityIncorporator, AuthoritySource, StagedContactMaterial};

use crate::beacon::{RouteHint, SignedBeaconV1, BEACON_PROTOCOL};
use crate::contact::{
    build_transfer_frames, AccepterEvent, AccepterValidator, ContactFrame, ContactHelloAckV1,
    ContactHelloV1, ContactId, InitiatorReceiver, OutboundTransfer, Progress, ReceivedMaterial,
    CONTACT_ALPN, CONTACT_PROTOCOL, MAX_FRAME,
};
use crate::error::ContactError;
use crate::lifecycle::CancelToken;
use crate::lifecycle::ContactOutcome;
use crate::neighbor_presence::{AckV1, ProbeV1, PRESENCE_ALPN_V1};
use crate::neighbors::NeighborRegistry;
use crate::session::StationCore;

/// The Contact scheduler's global in-flight bound.
pub const MAX_CONTACTS_IN_FLIGHT: usize = 4;

/// Milliseconds since the unix epoch (receiver-local wall clock).
pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The mechanics seam the Contact plane needs, supplied at activation by the
/// composition root. Everything here is mechanics-owned policy; the Station
/// only orchestrates.
pub struct ContactMechanics {
    /// Validates signer standing at referenced authority frontiers.
    pub source: Arc<dyn AuthoritySource + Send + Sync>,
    /// Durably, idempotently commits received authority batches (the explicit
    /// first Convergence phase).
    pub incorporator: Arc<Mutex<dyn AuthorityIncorporator + Send>>,
    /// The canonical authority batch this Station serves to peers.
    pub export: Arc<dyn Fn() -> Vec<Vec<u8>> + Send + Sync>,
    /// The current local authority frontier (for signing manifests and
    /// attributing incorporation).
    pub frontier: Arc<dyn Fn() -> replica::AuthorityFrontier + Send + Sync>,
}

/// Gossip participation for Beacon emission/ingestion.
#[derive(Clone)]
pub struct GossipOptions {
    pub bootstrap: Vec<comms::PeerId>,
    /// The route hints this Station advertises in its Beacons.
    pub advertise: Vec<RouteHint>,
    pub beacon_interval: Duration,
}

/// The comms configuration a Station activates with.
pub struct CommsOptions {
    pub transport: Arc<dyn comms::Transport>,
    /// The Station's own device seed: signs Hello/Ack, Beacons, manifests,
    /// and attributes incorporations.
    pub station_seed: [u8; 32],
    pub mechanics: ContactMechanics,
    pub gossip: Option<GossipOptions>,
    /// The whole-contact deadline.
    pub whole_deadline: Duration,
    /// The per-frame progress deadline.
    pub progress_deadline: Duration,
    /// Receiver-local route lease.
    pub route_lease: Duration,
}

impl std::fmt::Debug for CommsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommsOptions").finish_non_exhaustive()
    }
}

/// A command into the driver.
pub(crate) enum DriverCmd {
    /// Administrative/test Contact to a Neighbor, bypassing the backoff (but
    /// not the in-flight bounds).
    Contact {
        station: StationId,
        reply: std::sync::mpsc::SyncSender<Result<ContactOutcome, ContactError>>,
    },
    /// Ingest raw (gossip-received) Beacon bytes.
    Beacon(Vec<u8>),
}

/// Everything the driver thread owns.
pub(crate) struct DriverContext {
    pub space: SpaceId,
    pub space_bytes: [u8; 29],
    pub station_key: [u8; 32],
    pub epoch: u64,
    pub core: Arc<StationCore>,
    pub registry: Arc<Mutex<NeighborRegistry>>,
    pub options: CommsOptions,
    pub commands: std::sync::mpsc::Receiver<DriverCmd>,
    pub cancel: CancelToken,
}

/// Run the driver until cancellation. Called on a tracked Station thread.
pub(crate) fn run_driver(ctx: DriverContext) {
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return,
    };
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, drive(ctx));
}

async fn drive(ctx: DriverContext) {
    let ctx = std::rc::Rc::new(ctx);
    let beacon_seq = std::rc::Rc::new(AtomicU64::new(0));

    // Gossip: subscribe, emit, ingest.
    let mut gossip_sender: Option<Box<dyn comms::GossipSender>> = None;
    if let Some(gossip) = &ctx.options.gossip {
        let topic = beacon_topic(&ctx.space);
        if let Ok((sender, mut receiver)) = ctx
            .options
            .transport
            .subscribe(topic, &gossip.bootstrap)
            .await
        {
            gossip_sender = Some(sender);
            let ctx2 = ctx.clone();
            tokio::task::spawn_local(async move {
                while let Some(event) = receiver.next().await {
                    if ctx2.cancel.is_cancelled() {
                        break;
                    }
                    if let comms::GossipEvent::Received { bytes, .. } = event {
                        ingest_beacon(&ctx2, &bytes);
                    }
                }
            });
        }
    }

    // Accept loop: serve inbound Contacts and presence probes.
    {
        let ctx2 = ctx.clone();
        tokio::task::spawn_local(async move {
            loop {
                if ctx2.cancel.is_cancelled() {
                    break;
                }
                let Some(incoming) = ctx2.options.transport.accept().await else {
                    break;
                };
                if ctx2.cancel.is_cancelled() {
                    break;
                }
                let ctx3 = ctx2.clone();
                tokio::task::spawn_local(async move {
                    let comms::Incoming { from, alpn, stream } = incoming;
                    if alpn == CONTACT_ALPN {
                        let _ = serve_contact(&ctx3, from, stream).await;
                    } else if alpn == PRESENCE_ALPN_V1 {
                        let _ = serve_presence(&ctx3, from, stream).await;
                    }
                });
            }
        });
    }

    // The scheduler tick: service commands, emit beacons, dial eligible
    // Neighbors under the in-flight bounds.
    let in_flight: std::rc::Rc<std::cell::RefCell<std::collections::BTreeSet<StationId>>> =
        Default::default();
    let mut last_beacon = Instant::now() - Duration::from_secs(3600);
    loop {
        if ctx.cancel.is_cancelled() {
            break;
        }
        // Commands (administrative contacts + beacon ingestion).
        while let Ok(cmd) = ctx.commands.try_recv() {
            match cmd {
                DriverCmd::Beacon(bytes) => ingest_beacon(&ctx, &bytes),
                DriverCmd::Contact { station, reply } => {
                    if in_flight.borrow().contains(&station)
                        || in_flight.borrow().len() >= MAX_CONTACTS_IN_FLIGHT
                    {
                        let _ = reply.send(Err(ContactError::Transfer(
                            "contact slots exhausted".into(),
                        )));
                        continue;
                    }
                    in_flight.borrow_mut().insert(station.clone());
                    let ctx2 = ctx.clone();
                    let in_flight2 = in_flight.clone();
                    tokio::task::spawn_local(async move {
                        let result = contact_neighbor(&ctx2, &station).await;
                        record_result(&ctx2, &station, &result);
                        in_flight2.borrow_mut().remove(&station);
                        let _ = reply.send(result);
                    });
                }
            }
        }
        // Periodic Beacon emission.
        if let (Some(sender), Some(gossip)) = (&gossip_sender, &ctx.options.gossip) {
            if last_beacon.elapsed() >= gossip.beacon_interval {
                last_beacon = Instant::now();
                let sequence = beacon_seq.fetch_add(1, Ordering::SeqCst) + 1;
                let frontier = ctx.core.frontier();
                if let Some(beacon) = SignedBeaconV1::emit(
                    BEACON_PROTOCOL,
                    &ctx.space,
                    mechanics::ids::StationEpoch::from_u64(ctx.epoch),
                    sequence,
                    frontier.root,
                    frontier.transaction_count,
                    gossip.advertise.clone(),
                    &ctx.options.station_seed,
                ) {
                    let _ = sender.broadcast(beacon.encode()).await;
                }
            }
        }
        // Scheduler: dial eligible Neighbors, fair order, bounded fan-out.
        let eligible = {
            let registry = ctx.registry.lock().unwrap_or_else(|p| p.into_inner());
            registry.eligible(now_ms())
        };
        for station in eligible {
            if ctx.cancel.is_cancelled() {
                break;
            }
            {
                let mut flying = in_flight.borrow_mut();
                if flying.contains(&station) || flying.len() >= MAX_CONTACTS_IN_FLIGHT {
                    continue;
                }
                flying.insert(station.clone());
            }
            let ctx2 = ctx.clone();
            let in_flight2 = in_flight.clone();
            tokio::task::spawn_local(async move {
                let result = contact_neighbor(&ctx2, &station).await;
                record_result(&ctx2, &station, &result);
                in_flight2.borrow_mut().remove(&station);
            });
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    ctx.options.transport.shutdown().await;
}

fn beacon_topic(space: &SpaceId) -> comms::Topic {
    let mut h = blake3::Hasher::new();
    h.update(b"lait/beacon-room/1");
    h.update(space.as_str().as_bytes());
    comms::Topic(*h.finalize().as_bytes())
}

fn ingest_beacon(ctx: &DriverContext, bytes: &[u8]) {
    let Ok(signed) = SignedBeaconV1::decode_canonical(bytes) else {
        return;
    };
    let Ok(verified) = signed.verify() else {
        return;
    };
    // Never register ourselves.
    if verified.station().key_bytes() == ctx.station_key {
        return;
    }
    // Teach the transport the advertised routes (scheme 1: UTF-8 socket addr).
    for hint in verified.routes() {
        if hint.scheme == 1 {
            if let Ok(text) = std::str::from_utf8(&hint.bytes) {
                if let Ok(addr) = text.parse() {
                    ctx.options
                        .transport
                        .learn(verified.station().as_device(), &[addr]);
                }
            }
        }
    }
    let frontier = ctx.core.frontier();
    let mut registry = ctx.registry.lock().unwrap_or_else(|p| p.into_inner());
    let _ = registry.observe_beacon(
        &verified,
        (&frontier.root, frontier.transaction_count),
        now_ms(),
        ctx.options.route_lease.as_millis() as u64,
    );
}

fn record_result(
    ctx: &DriverContext,
    station: &StationId,
    result: &Result<ContactOutcome, ContactError>,
) {
    let mut registry = ctx.registry.lock().unwrap_or_else(|p| p.into_inner());
    match result {
        Ok(_) => {
            let _ = registry.record_success(station, now_ms());
        }
        Err(_) => {
            let _ = registry.record_failure(station, now_ms());
        }
    }
}

/// Dial a Neighbor, run the initiator side, validate, and incorporate.
async fn contact_neighbor(
    ctx: &DriverContext,
    station: &StationId,
) -> Result<ContactOutcome, ContactError> {
    let peer = station.as_device();
    let deadline = Instant::now() + ctx.options.whole_deadline;
    let mut stream = step(
        deadline,
        ctx.options.progress_deadline,
        ctx.options.transport.connect(peer, CONTACT_ALPN),
    )
    .await
    .map_err(|_| ContactError::Unreachable)?
    .map_err(|_| ContactError::Unreachable)?;

    let (received, bytes_moved) = initiate(ctx, &mut *stream, station, deadline).await?;
    drop(stream); // dialer close: we have the transcript

    // Stage → validate (authority first, durable) → incorporate under the
    // Station writer. TransferAck already went out — it acknowledged the
    // transcript, not convergence.
    let staged = StagedContactMaterial {
        authority_records: received.authority_records,
        manifest_root_bytes: received.manifest_root_bytes,
        manifest_pages: received.manifest_pages.into_values().collect(),
        bodies: received
            .bodies
            .into_iter()
            .map(|((tx, key), bytes)| (tx, key, bytes))
            .collect(),
    };
    let signer = crate::world::LocalIdentity::from_seed(&ctx.options.station_seed);
    let frontier = (ctx.options.mechanics.frontier)();
    let convergence = {
        let mut incorporator = ctx
            .options
            .mechanics
            .incorporator
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        ctx.core
            .with_replica(|replica| {
                let commit_ctx = replica::CommitContext {
                    space: &ctx.space,
                    signer: &signer,
                    authority_frontier: frontier.clone(),
                };
                let bundle = replica.validate_contact(
                    &staged,
                    ctx.options.mechanics.source.as_ref(),
                    &mut *incorporator,
                )?;
                replica.incorporate_bundle(
                    &commit_ctx,
                    bundle,
                    ctx.options.mechanics.source.as_ref(),
                )
            })
            .map_err(|e| ContactError::Transfer(e.to_string()))?
    };
    // Publish Observations only AFTER durable incorporation, grouped per
    // World (remote changes share the local commits' delivery path).
    if convergence.advanced() {
        let mut by_world: std::collections::BTreeMap<replica::WorldId, Vec<replica::BodyKey>> =
            Default::default();
        for key in &convergence.scopes {
            by_world
                .entry(key.world.clone())
                .or_default()
                .push(key.clone());
        }
        for (world, scopes) in by_world {
            ctx.core
                .broadcaster
                .publish(world, scopes, convergence.current);
        }
    }
    Ok(ContactOutcome {
        bytes_moved,
        convergence,
    })
}

/// A step under both the whole-contact deadline and the progress deadline.
async fn step<F: std::future::Future>(
    whole_deadline: Instant,
    progress: Duration,
    fut: F,
) -> Result<F::Output, ()> {
    let now = Instant::now();
    if now >= whole_deadline {
        return Err(());
    }
    let budget = progress.min(whole_deadline - now);
    tokio::time::timeout(budget, fut).await.map_err(|_| ())
}

/// The initiator side over an open stream: Hello/Ack handshake, receive every
/// frame through the pure machine, send the ack.
async fn initiate(
    ctx: &DriverContext,
    stream: &mut dyn comms::Stream,
    responder: &StationId,
    deadline: Instant,
) -> Result<(ReceivedMaterial, u64), ContactError> {
    let progress = ctx.options.progress_deadline;
    let contact = ContactId::mint();
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| ContactError::Transfer(e.to_string()))?;
    let hello = ContactHelloV1::sign(
        CONTACT_PROTOCOL,
        ctx.space_bytes,
        responder.key_bytes(),
        nonce,
        contact,
        &ctx.options.station_seed,
    )
    .ok_or_else(|| ContactError::Transfer("sign hello".into()))?;
    step(deadline, progress, stream.send(&hello.encode()))
        .await
        .map_err(|_| ContactError::Unreachable)?
        .map_err(|e| ContactError::Transfer(e.to_string()))?;

    let ack_bytes = step(deadline, progress, stream.recv())
        .await
        .map_err(|_| ContactError::Unreachable)?
        .map_err(|e| ContactError::Transfer(e.to_string()))?
        .ok_or(ContactError::Unreachable)?;
    let ack =
        ContactHelloAckV1::decode(&ack_bytes).map_err(|e| ContactError::Transfer(e.to_string()))?;
    // Bind the negotiated transport peer to the signed Station identity
    // BEFORE any staging is allocated.
    ack.verify(&hello, responder)
        .map_err(|e| ContactError::Transfer(e.to_string()))?;

    let mut receiver = InitiatorReceiver::new(contact);
    let mut bytes_moved = (hello.encode().len() + ack_bytes.len()) as u64;
    loop {
        let frame = step(deadline, progress, stream.recv())
            .await
            .map_err(|_| ContactError::Transfer("contact deadline".into()))?
            .map_err(|e| ContactError::Transfer(e.to_string()))?
            .ok_or_else(|| ContactError::Transfer("stream ended mid-transfer".into()))?;
        if frame.len() > MAX_FRAME {
            return Err(ContactError::Transfer("frame over limit".into()));
        }
        bytes_moved += frame.len() as u64;
        match receiver.on_frame(&frame) {
            Ok(Progress::Continue) => {}
            Ok(Progress::SendAck(ack_frame)) => {
                let raw = ack_frame.encode(&contact);
                bytes_moved += raw.len() as u64;
                step(deadline, progress, stream.send(&raw))
                    .await
                    .map_err(|_| ContactError::Transfer("contact deadline".into()))?
                    .map_err(|e| ContactError::Transfer(e.to_string()))?;
                let _ = step(deadline, progress, stream.finish()).await;
                break;
            }
            Ok(Progress::PeerAborted(code)) | Err(code) => {
                return Err(ContactError::Transfer(format!("aborted: code {code}")));
            }
        }
    }
    let received = receiver
        .into_received()
        .ok_or_else(|| ContactError::Transfer("incomplete transfer".into()))?;
    Ok((received, bytes_moved))
}

/// The accepter side: verify the Hello, answer, snapshot the Replica's
/// retained material, serve the canonical frames, await the ack, then
/// `finish` + `wait_closed` before dropping.
async fn serve_contact(
    ctx: &DriverContext,
    from: comms::PeerId,
    mut stream: Box<dyn comms::Stream>,
) -> Result<(), ContactError> {
    let deadline = Instant::now() + ctx.options.whole_deadline;
    let progress = ctx.options.progress_deadline;
    let hello_bytes = step(deadline, progress, stream.recv())
        .await
        .map_err(|_| ContactError::Unreachable)?
        .map_err(|e| ContactError::Transfer(e.to_string()))?
        .ok_or(ContactError::Unreachable)?;
    let hello =
        ContactHelloV1::decode(&hello_bytes).map_err(|e| ContactError::Transfer(e.to_string()))?;
    // Bind the transport peer to the signed initiator identity BEFORE
    // allocating anything.
    let transport_peer = StationId::from_device(&from).ok_or(ContactError::UnknownNeighbor)?;
    hello
        .verify(&ctx.space_bytes, &transport_peer)
        .map_err(|e| ContactError::Transfer(e.to_string()))?;
    if hello.responder_station != ctx.station_key {
        return Err(ContactError::Transfer("hello for another Station".into()));
    }
    // Arm a reciprocal dial to the initiator: the responder only SERVES material
    // here, so a pull back is what redeems a joiner's admission and converges us.
    // First-contact gated (see `note_reciprocable`) so converged peers do not
    // ping-pong.
    {
        let lease_ms = ctx.options.route_lease.as_millis() as u64;
        let mut registry = ctx.registry.lock().unwrap_or_else(|p| p.into_inner());
        let _ = registry.note_reciprocable(&transport_peer, now_ms(), lease_ms);
    }
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| ContactError::Transfer(e.to_string()))?;
    let ack = ContactHelloAckV1::sign(&hello, nonce, &ctx.options.station_seed)
        .ok_or_else(|| ContactError::Transfer("sign ack".into()))?;
    step(deadline, progress, stream.send(&ack.encode()))
        .await
        .map_err(|_| ContactError::Unreachable)?
        .map_err(|e| ContactError::Transfer(e.to_string()))?;

    // Snapshot the served material under the writer lock.
    let signer = crate::world::LocalIdentity::from_seed(&ctx.options.station_seed);
    let frontier = (ctx.options.mechanics.frontier)();
    let (material, manifest) = ctx
        .core
        .with_replica(|replica| {
            let commit_ctx = replica::CommitContext {
                space: &ctx.space,
                signer: &signer,
                authority_frontier: frontier.clone(),
            };
            let material = replica.export_material()?;
            let manifest = replica.export_manifest(&commit_ctx)?;
            Ok((material, manifest))
        })
        .map_err(|e: replica::ReplicaCommitError| ContactError::Transfer(e.to_string()))?;
    let mut authority_records = (ctx.options.mechanics.export)();
    let mut bodies = Vec::new();
    for (tx, payloads) in &material {
        authority_records.push(tx.encode());
        for (key, envelope) in payloads {
            bodies.push((tx.transaction, key.clone(), envelope.clone()));
        }
    }
    let transfer = OutboundTransfer {
        authority_frontier: frontier.as_bytes().to_vec(),
        authority_records,
        manifest_root_bytes: manifest.0,
        manifest_pages: manifest.1,
        bodies,
    };
    let contact = hello.contact;
    let frames = build_transfer_frames(&contact, &transfer);
    let mut validator = AccepterValidator::new(contact);
    for frame in &frames {
        if ctx.cancel.is_cancelled() {
            return Err(ContactError::Transfer("station dormant".into()));
        }
        validator.record_sent(frame);
        step(deadline, progress, stream.send(frame))
            .await
            .map_err(|_| ContactError::Transfer("contact deadline".into()))?
            .map_err(|e| ContactError::Transfer(e.to_string()))?;
    }
    // Await the TransferAck through the validator, then finish + wait_closed.
    loop {
        let frame = step(deadline, progress, stream.recv())
            .await
            .map_err(|_| ContactError::Transfer("contact deadline".into()))?
            .map_err(|e| ContactError::Transfer(e.to_string()))?
            .ok_or_else(|| ContactError::Transfer("closed before ack".into()))?;
        match validator.on_frame(&frame) {
            Ok(AccepterEvent::Acked { .. }) => break,
            Ok(AccepterEvent::PeerAborted(code)) => {
                return Err(ContactError::Transfer(format!("peer aborted: {code}")))
            }
            Ok(_) => {}
            Err(code) => {
                let _ = stream
                    .send(&ContactFrame::Abort { code }.encode(&contact))
                    .await;
                return Err(ContactError::Transfer(format!("abort: {code}")));
            }
        }
    }
    let _ = step(deadline, progress, stream.finish()).await;
    let _ = step(deadline, progress, stream.wait_closed()).await;
    Ok(())
}

/// Answer a Neighbor-presence probe with a signed ack.
async fn serve_presence(
    ctx: &DriverContext,
    from: comms::PeerId,
    mut stream: Box<dyn comms::Stream>,
) -> Result<(), ContactError> {
    let deadline = Instant::now() + ctx.options.progress_deadline;
    let probe_bytes = step(deadline, ctx.options.progress_deadline, stream.recv())
        .await
        .map_err(|_| ContactError::Unreachable)?
        .map_err(|e| ContactError::Transfer(e.to_string()))?
        .ok_or(ContactError::Unreachable)?;
    let probe = ProbeV1::decode(&probe_bytes).map_err(|e| ContactError::Transfer(e.to_string()))?;
    let prober = StationId::from_device(&from).ok_or(ContactError::UnknownNeighbor)?;
    probe
        .verify(&ctx.space_bytes, &prober)
        .map_err(|e| ContactError::Transfer(e.to_string()))?;
    if probe.responder_station != ctx.station_key {
        return Err(ContactError::Transfer("probe for another Station".into()));
    }
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|e| ContactError::Transfer(e.to_string()))?;
    let ack = AckV1::sign(&probe, nonce, &ctx.options.station_seed)
        .ok_or_else(|| ContactError::Transfer("sign presence ack".into()))?;
    let _ = step(
        deadline,
        ctx.options.progress_deadline,
        stream.send(&ack.encode()),
    )
    .await;
    let _ = step(deadline, ctx.options.progress_deadline, stream.finish()).await;
    let _ = step(
        deadline,
        ctx.options.progress_deadline,
        stream.wait_closed(),
    )
    .await;
    Ok(())
}
