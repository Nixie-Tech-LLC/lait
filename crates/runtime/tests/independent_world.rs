//! C6.2 — the Issues-free independent-World conformance target (the named
//! `orbital-independent-world` gate).
//!
//! One product-free World (`dev.example.multi`: an atomic `entry` schema and a
//! collaborative `pad` schema) exercises through PUBLIC APIs only: atomic and
//! collaborative Bodies, multi-Body atomic failure (old-or-new), local
//! authorization and authority change, offline restart/query, Observation
//! reset/backpressure, Beacon ingestion into the Neighbor registry with
//! automatic Contact/Convergence through `comms`, opaque retention with
//! byte-identical forwarding across a third Station, cancellation/dormancy,
//! and idempotent retry after a crash.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::{ActorId, DeviceId, SpaceId, StationId};
use replica::body::{BodyOp, BodySchema, CollaborativeSchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};
use runtime::coordinates::{ApproachRoute, CoordinatesAdmission, CoordinatesPayload};

#[allow(dead_code)]
fn any_demand() -> Vec<u8> {
    mechanics::demand::AuthorizationDemand::require(
        mechanics::demand::PolicyCapability::new("w", "c"),
        mechanics::demand::PolicyResource::space("w"),
    )
    .encode_canonical()
    .expect("canonical demand")
}
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, EnterOptions, LocalIdentity,
    ObservationCursor, ObservationStreamError, RequestId, Runtime, RuntimeBuilder, Session,
    SignedCoordinates, World, WorldContext, WorldEffect, WorldError, WorldIntent, WorldLimits,
    WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};

const FOUNDER_SEED: [u8; 32] = [7u8; 32];
const RECOVERY_SEED: [u8; 32] = [20u8; 32];
const STATION_A_SEED: [u8; 32] = [91u8; 32];
const STATION_B_SEED: [u8; 32] = [92u8; 32];
const STATION_C_SEED: [u8; 32] = [93u8; 32];
const WRITER_SEED: [u8; 32] = [94u8; 32];
const READER_SEED: [u8; 32] = [95u8; 32];
const SALT: [u8; 16] = [9u8; 16];
const EPOCH: [u8; 16] = [23u8; 16];
const EPOCH_KEY: [u8; 32] = [24u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root(tag: &str) -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-indep-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn coordinates() -> (SpaceId, SignedCoordinates) {
    let rc = mechanics::space::recovery_commit(&mechanics::space::recovery_pub_of(&RECOVERY_SEED))
        .unwrap();
    let device = mechanics::space::recovery_pub_of(&FOUNDER_SEED);
    let ws = mechanics::space::derive_space_id(&device, &SALT, &rc);
    let (incept, _actor) =
        mechanics::actor::incept_single(&FOUNDER_SEED, &ws, [1u8; 16], [2u8; 16], None);
    let payload = CoordinatesPayload {
        space: <[u8; 29]>::try_from(ws.as_str().as_bytes()).unwrap(),
        salt: SALT,
        recovery_root: rc,
        founder_inception: postcard::to_stdvec(&incept).unwrap(),
        display_name_hint: "Independent".into(),
        approach_station: mechanics::crypto::device_from_seed(&STATION_A_SEED)
            .key_bytes()
            .unwrap(),
        approach_nick_hint: "a".into(),
        approach_routes: vec![ApproachRoute::DirectV4 {
            ip: [127, 0, 0, 1],
            port: 4242,
        }],
        admission: CoordinatesAdmission::None,
    };
    (ws, SignedCoordinates::sign(payload, &STATION_A_SEED))
}

/// The multi-schema independent World.
struct MultiWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl MultiWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("dev.example.multi").unwrap(),
            schemas: vec![
                BodySchema {
                    id: SchemaId::parse("entry").unwrap(),
                    version: 1,
                    encoding: EncodingId::parse("bytes").unwrap(),
                    mutation: MutationModel::Atomic,
                    readable_predecessors: vec![],
                },
                BodySchema {
                    id: SchemaId::parse("pad").unwrap(),
                    version: 1,
                    encoding: EncodingId::parse("collab").unwrap(),
                    mutation: MutationModel::Collaborative(CollaborativeSchema::default()),
                    readable_predecessors: vec![],
                },
            ],
        }
    }
    fn entry_key(&self, k: &str) -> BodyKey {
        let mut raw = [0u8; 16];
        let kb = k.as_bytes();
        raw[..kb.len().min(16)].copy_from_slice(&kb[..kb.len().min(16)]);
        BodyKey::new(self.id.clone(), BodyId::from_bytes(raw))
    }
    fn pad_key(&self) -> BodyKey {
        BodyKey::new(self.id.clone(), BodyId::from_bytes([0xEE; 16]))
    }
}

impl World for MultiWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }
    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }
    fn submit(
        &self,
        ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        let v: serde_json::Value =
            serde_json::from_slice(&intent.payload).map_err(|_| WorldError::InvalidRequest)?;
        let op = v["op"].as_str().ok_or(WorldError::InvalidRequest)?;
        let mut operations = Vec::new();
        let mut declarations = Vec::new();
        let mut scopes = Vec::new();
        let mut declare = |key: &BodyKey, schema: &str, ops: &mut Vec<_>, op: BodyOp| {
            declarations.push(runtime::BodyDeclaration {
                key: key.clone(),
                schema: SchemaId::parse(schema).unwrap(),
                schema_version: 1,
            });
            scopes.push(key.clone());
            ops.push((key.clone(), op));
        };
        match op {
            "set" => {
                let key = self.entry_key(v["k"].as_str().ok_or(WorldError::InvalidRequest)?);
                declare(
                    &key,
                    "entry",
                    &mut operations,
                    BodyOp::ReplaceAtomic {
                        value: v["v"].as_str().unwrap_or_default().as_bytes().to_vec(),
                    },
                );
            }
            "pad" => {
                let key = self.pad_key();
                let text = v["text"].as_str().unwrap_or_default();
                let at = ctx
                    .read_collaborative(&key)
                    .and_then(|p| p.texts.get("body").map(|t| t.chars().count() as u64))
                    .unwrap_or(0);
                declare(
                    &key,
                    "pad",
                    &mut operations,
                    BodyOp::TextSplice {
                        path: "body".into(),
                        index: at,
                        delete: 0,
                        insert: text.to_string(),
                    },
                );
            }
            "both" => {
                let key = self.entry_key(v["k"].as_str().ok_or(WorldError::InvalidRequest)?);
                declare(
                    &key,
                    "entry",
                    &mut operations,
                    BodyOp::ReplaceAtomic {
                        value: v["v"].as_str().unwrap_or_default().as_bytes().to_vec(),
                    },
                );
                let pad = self.pad_key();
                declare(
                    &pad,
                    "pad",
                    &mut operations,
                    BodyOp::TextSplice {
                        path: "body".into(),
                        index: 0,
                        delete: 0,
                        insert: v["text"].as_str().unwrap_or_default().to_string(),
                    },
                );
            }
            "bad_both" => {
                // A valid atomic op plus an INVALID collaborative op: the
                // whole multi-Body transaction must be old-or-new.
                let key = self.entry_key("poisoned");
                declare(
                    &key,
                    "entry",
                    &mut operations,
                    BodyOp::ReplaceAtomic {
                        value: b"must not survive".to_vec(),
                    },
                );
                let pad = self.pad_key();
                declare(
                    &pad,
                    "pad",
                    &mut operations,
                    BodyOp::ListRemove {
                        path: "items".into(),
                        element: "0".repeat(32),
                    },
                );
            }
            _ => return Err(WorldError::InvalidRequest),
        }
        Ok(WorldEffect {
            demand: any_demand(),
            operations,
            scopes,
            effect: vec![],
            declarations,
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let v: serde_json::Value =
            serde_json::from_slice(&query.payload).map_err(|_| WorldError::InvalidRequest)?;
        let bytes = match v["q"].as_str() {
            Some("entry") => ctx
                .read_body(&self.entry_key(v["k"].as_str().unwrap_or_default()))
                .unwrap_or_default(),
            Some("pad") => ctx
                .read_collaborative(&self.pad_key())
                .and_then(|p| p.texts.get("body").cloned())
                .unwrap_or_default()
                .into_bytes(),
            _ => return Err(WorldError::InvalidRequest),
        };
        Ok(WorldProjection {
            demand: any_demand(),
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            bytes,
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

/// A flippable authority for the authority-change case.
struct FlipAuthority {
    frontier: Mutex<Vec<u8>>,
}

/// A view whose default `authorize_mutation` builds a structurally-valid
/// receipt — the permissive delegate for the writer-only view's allow path.
struct PermissiveAuthority;

impl runtime::AuthorityView for PermissiveAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        None
    }
}

impl runtime::AuthorityView for FlipAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        Some(runtime::PrincipalResolution {
            actor: ActorId::from_incept_hash(&"a".repeat(64)),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(
                self.frontier.lock().unwrap().clone(),
            ),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn authorize_mutation(
        &self,
        space: &mechanics::ids::SpaceId,
        world: &WorldId,
        actor: &ActorId,
        device: &DeviceId,
        authority_frontier: &AuthorityFrontier,
        parent_manifest_root: [u8; 32],
        implementation_id: [u8; 32],
        intent_digest: [u8; 32],
        demand: &[u8],
        operations_digest: [u8; 32],
        core_digest: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        // The coarse per-device write gate lives in the view, as the orbital
        // composition's demand evaluation does — never in the World callback.
        let writer = mechanics::crypto::device_from_seed(&WRITER_SEED);
        if device != &writer {
            return Err("device holds no write authority".into());
        }
        PermissiveAuthority.authorize_mutation(
            space,
            world,
            actor,
            device,
            authority_frontier,
            parent_manifest_root,
            implementation_id,
            intent_digest,
            demand,
            operations_digest,
            core_digest,
        )
    }
}

struct AnyKnownSigner;
impl replica::AuthoritySource for AnyKnownSigner {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AuthorityFrontier) -> bool {
        [WRITER_SEED, STATION_A_SEED, STATION_B_SEED, STATION_C_SEED]
            .iter()
            .any(|seed| mechanics::crypto::device_from_seed(seed).key_bytes() == Some(*signer))
    }
}

struct AcceptingIncorporator;
impl replica::AuthorityIncorporator for AcceptingIncorporator {
    fn incorporate_authority(
        &mut self,
        _records: &[Vec<u8>],
    ) -> Result<replica::AuthorityBatchReceipt, String> {
        Ok(replica::AuthorityBatchReceipt {
            space: coordinates().0,
            prior_frontier: replica::frontier::AuthorityFrontier::from_canonical_bytes(vec![]),
            resulting_frontier: AuthorityFrontier::from_canonical_bytes(vec![6]),
            batch_digest: *blake3::hash(&_records.concat()).as_bytes(),
        })
    }
}

fn test_keys() -> Arc<dyn replica::BodyKeySource> {
    Arc::new(replica::StaticBodyKeys::new(
        AuthorizedBodyKey::for_authorized_epoch(EPOCH, EPOCH_KEY),
    ))
}

fn registry(with_world: bool) -> runtime::WorldRegistry {
    let mut builder = RuntimeBuilder::new();
    if with_world {
        let world = MultiWorld::new();
        let reg = WorldRegistration {
            id: world.id(),
            implementation_version: WorldVersion(1),
            schemas: world.schemas().to_vec(),
            limits: WorldLimits::default(),
        };
        builder = builder.register(reg, Arc::new(world));
    }
    builder.build().unwrap()
}

fn authority() -> Arc<FlipAuthority> {
    Arc::new(FlipAuthority {
        frontier: Mutex::new(vec![6]),
    })
}

fn comms_options(transport: Arc<dyn comms::Transport>, seed: [u8; 32]) -> CommsOptions {
    CommsOptions {
        transport,
        station_seed: seed,
        mechanics: ContactMechanics {
            source: Arc::new(AnyKnownSigner),
            incorporator: Arc::new(Mutex::new(AcceptingIncorporator)),
            export: Arc::new(Vec::new),
            frontier: Arc::new(|| AuthorityFrontier::from_canonical_bytes(vec![6])),
        },
        gossip: None,
        whole_deadline: Duration::from_secs(20),
        progress_deadline: Duration::from_secs(5),
        route_lease: Duration::from_secs(60),
    }
}

fn writer() -> LocalIdentity {
    Runtime::identity_from_seed(&WRITER_SEED)
}

fn world_id() -> WorldId {
    WorldId::parse("dev.example.multi").unwrap()
}

fn submit_json(
    session: &Session,
    identity: &LocalIdentity,
    request: RequestId,
    schema: &str,
    value: serde_json::Value,
) -> Result<runtime::CommittedEffect, WorldError> {
    let action = identity.sign_action(
        session,
        request,
        WorldIntent {
            schema: SchemaId::parse(schema).unwrap(),
            schema_version: 1,
            payload: serde_json::to_vec(&value).unwrap(),
        },
    )?;
    session.submit(action)
}

fn query_json(session: &Session, value: serde_json::Value) -> Vec<u8> {
    session
        .query(WorldQuery {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: serde_json::to_vec(&value).unwrap(),
        })
        .unwrap()
        .bytes
}

#[test]
fn bodies_authority_restart_idempotency_and_observation() {
    let root = temp_root("core");
    let auth = authority();
    let rt = Runtime::open(root.clone(), registry(true), auth.clone(), test_keys());
    let station = rt
        .form_space(runtime::SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: None,
            observation_capacity: 1, // force overruns for the backpressure case
        })
        .unwrap();
    let space = station.space_id().clone();
    let session = station.dock(&world_id(), &writer()).unwrap();
    let mut stream = session.observe(None);
    assert!(stream.try_next().unwrap().unwrap().reset);

    // Atomic + collaborative Bodies in one multi-Body transaction.
    submit_json(
        &session,
        &writer(),
        RequestId::mint(),
        "entry",
        serde_json::json!({"op":"both","k":"greeting","v":"hello","text":"pad!"}),
    )
    .unwrap();
    assert_eq!(
        query_json(&session, serde_json::json!({"q":"entry","k":"greeting"})),
        b"hello"
    );
    assert_eq!(
        query_json(&session, serde_json::json!({"q":"pad"})),
        b"pad!"
    );

    // Multi-Body atomic FAILURE: the valid atomic op must not survive its
    // failed sibling — old-or-new, nothing partial.
    let before = station.frontier();
    let err = submit_json(
        &session,
        &writer(),
        RequestId::mint(),
        "entry",
        serde_json::json!({"op":"bad_both"}),
    )
    .unwrap_err();
    assert_eq!(err, WorldError::InvalidRequest);
    assert_eq!(station.frontier(), before);
    assert_eq!(
        query_json(&session, serde_json::json!({"q":"entry","k":"poisoned"})),
        b"",
        "the valid half of the failed transaction did not survive"
    );

    // Local authorization: a granted-nothing principal is denied.
    let reader = Runtime::identity_from_seed(&READER_SEED);
    let reader_session = station.dock(&world_id(), &reader).unwrap();
    assert_eq!(
        submit_json(
            &reader_session,
            &reader,
            RequestId::mint(),
            "entry",
            serde_json::json!({"op":"set","k":"x","v":"y"}),
        ),
        Err(WorldError::Denied)
    );

    // Authority change between signing and submit commits nothing.
    let stale = writer()
        .sign_action(
            &session,
            RequestId::mint(),
            WorldIntent {
                schema: SchemaId::parse("entry").unwrap(),
                schema_version: 1,
                payload: serde_json::to_vec(&serde_json::json!({"op":"set","k":"stale","v":"no"}))
                    .unwrap(),
            },
        )
        .unwrap();
    *auth.frontier.lock().unwrap() = vec![7, 7];
    assert_eq!(session.submit(stale), Err(WorldError::AuthorityChanged));
    *auth.frontier.lock().unwrap() = vec![6];

    // Observation backpressure: capacity 1, three commits — an old cursor
    // gets exactly one reset, the gap discarded, memory bounded.
    for i in 0..3 {
        submit_json(
            &session,
            &writer(),
            RequestId::mint(),
            "entry",
            serde_json::json!({"op":"set","k":format!("k{i}"),"v":"v"}),
        )
        .unwrap();
    }
    let mut lagged = session.observe(Some(ObservationCursor {
        epoch: session.epoch(),
        sequence: 1,
    }));
    assert!(lagged.try_next().unwrap().unwrap().reset, "overrun resets");

    // Idempotent retry after a crash: the SAME signed action replays after a
    // cold reactivation without reapplying its (non-idempotent) text splice.
    let request = RequestId::from_bytes([44u8; 16]);
    let replayable = writer()
        .sign_action(
            &session,
            request,
            WorldIntent {
                schema: SchemaId::parse("pad").unwrap(),
                schema_version: 1,
                payload: serde_json::to_vec(&serde_json::json!({"op":"pad","text":"-again"}))
                    .unwrap(),
            },
        )
        .unwrap();
    let first = session.submit(replayable.clone()).unwrap();
    // Crash: drop without dormancy.
    drop(stream);
    drop(session);
    drop(reader_session);
    drop(station);

    // Offline restart: acknowledged state is immediately queryable, streams
    // rebaseline, and the identical retry replays.
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    let session = station.dock(&world_id(), &writer()).unwrap();
    assert_eq!(
        query_json(&session, serde_json::json!({"q":"pad"})),
        b"pad!-again"
    );
    let replay = session.submit(replayable).unwrap();
    assert_eq!(replay.effect, first.effect);
    assert_eq!(replay.frontier, first.frontier, "nothing reapplied");
    assert_eq!(
        query_json(&session, serde_json::json!({"q":"pad"})),
        b"pad!-again",
        "the non-idempotent splice applied exactly once across the crash"
    );

    // Dormancy terminates streams typed and refuses new work.
    let mut stream = session.observe(None);
    let _ = stream.try_next();
    let _ = station.go_dormant().unwrap();
    assert_eq!(
        stream.next_timeout(Duration::from_millis(200)),
        Err(ObservationStreamError::StationDormant)
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn beacons_contact_and_opaque_forwarding_across_three_stations() {
    let (_space, coords) = coordinates();
    let net = comms::mem::MemNet::new();
    let ta: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_A_SEED)));
    let tb: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_B_SEED)));
    let tc: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_C_SEED)));

    // A holds the World and commits; B is World-FREE (an unavailable World
    // deployment); C holds the World again.
    let root_a = temp_root("fw-a");
    let root_b = temp_root("fw-b");
    let root_c = temp_root("fw-c");
    let rt_a = Runtime::open(root_a.clone(), registry(true), authority(), test_keys());
    let rt_b = Runtime::open(root_b.clone(), registry(false), authority(), test_keys());
    let rt_c = Runtime::open(root_c.clone(), registry(true), authority(), test_keys());

    let station_a = rt_a
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(ta, STATION_A_SEED)),
            observation_capacity: 0,
        })
        .unwrap();
    let session = station_a.dock(&world_id(), &writer()).unwrap();
    submit_json(
        &session,
        &writer(),
        RequestId::mint(),
        "entry",
        serde_json::json!({"op":"set","k":"routed","v":"through-b"}),
    )
    .unwrap();

    let station_b = rt_b
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(tb, STATION_B_SEED)),
            observation_capacity: 0,
        })
        .unwrap();
    // B pulls A: the material is legitimate but its World is unavailable —
    // retained opaquely, never interpreted.
    let outcome = station_b
        .contact(
            &StationId::from_device(&mechanics::crypto::device_from_seed(&STATION_A_SEED)).unwrap(),
            ContactOptions,
        )
        .unwrap();
    assert!(outcome.convergence.unsupported_retained >= 1);
    assert_eq!(outcome.convergence.accepted, 0);

    // A Beacon from B queues C's scheduler: fully automatic convergence of
    // the forwarded (still-opaque-at-B) material into C, which CAN interpret.
    let station_c = rt_c
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(tc, STATION_C_SEED)),
            observation_capacity: 0,
        })
        .unwrap();
    let beacon = runtime::SignedBeacon::emit(
        runtime::beacon::BEACON_PROTOCOL,
        station_b.space_id(),
        station_b.epoch(),
        1,
        [0xAB; 32], // a frontier C does not hold → newsworthy
        1,
        0,
        vec![],
        &STATION_B_SEED,
    )
    .unwrap();
    station_c.observe_beacon(&beacon.encode());
    // Beacon ingestion rides the Station driver: poll (bounded) for the
    // registry to reflect it.
    let b_station =
        StationId::from_device(&mechanics::crypto::device_from_seed(&STATION_B_SEED)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if station_c.neighbors().iter().any(|n| n.station == b_station) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the verified Beacon never reached the registry"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // A fresh verified Beacon renews the bare-id dial lease (W0), so C's
    // scheduler pulls B on its own — the forwarded (opaque-at-B) material
    // converges into C with no explicit dial at all.
    let session_c = station_c.dock(&world_id(), &writer()).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if query_json(&session_c, serde_json::json!({"q":"entry","k":"routed"})) == b"through-b" {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "C never auto-converged the material B could only forward"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    let _ = station_a.go_dormant();
    let _ = station_b.go_dormant();
    let _ = station_c.go_dormant();
    let _ = std::fs::remove_dir_all(&root_a);
    let _ = std::fs::remove_dir_all(&root_b);
    let _ = std::fs::remove_dir_all(&root_c);
}

#[test]
fn the_eclipse_fence_quarantines_unadmitted_beacon_emitters() {
    // W0-S2: a validly SIGNED beacon from a station with no standing at our
    // authority frontier must not create durable registry state or teach
    // routes — a self-signed beacon proves control of a key, not admission.
    let (_space, coords) = coordinates();
    let net = comms::mem::MemNet::new();
    let tc: Arc<dyn comms::Transport> =
        Arc::new(net.peer(mechanics::crypto::device_from_seed(&STATION_C_SEED)));
    let root_c = temp_root("fence-c");
    let rt_c = Runtime::open(root_c.clone(), registry(true), authority(), test_keys());
    let station_c = rt_c
        .enter_orbit(&coords, EnterOptions)
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: Some(comms_options(tc, STATION_C_SEED)),
            observation_capacity: 0,
        })
        .unwrap();

    // A stranger key AnyKnownSigner does not authorize.
    const STRANGER_SEED: [u8; 32] = [99u8; 32];
    let stranger_beacon = runtime::SignedBeacon::emit(
        runtime::beacon::BEACON_PROTOCOL,
        station_c.space_id(),
        station_c.epoch(),
        1,
        [0xCD; 32],
        1,
        0,
        vec![],
        &STRANGER_SEED,
    )
    .unwrap();
    station_c.observe_beacon(&stranger_beacon.encode());

    // Prove the ingestion pipeline is live with an ADMITTED emitter, then
    // check the stranger stayed out — absence is meaningful, not a race.
    let admitted_beacon = runtime::SignedBeacon::emit(
        runtime::beacon::BEACON_PROTOCOL,
        station_c.space_id(),
        station_c.epoch(),
        1,
        [0xAB; 32],
        1,
        0,
        vec![],
        &STATION_B_SEED,
    )
    .unwrap();
    station_c.observe_beacon(&admitted_beacon.encode());
    let b_station =
        StationId::from_device(&mechanics::crypto::device_from_seed(&STATION_B_SEED)).unwrap();
    let stranger_station =
        StationId::from_device(&mechanics::crypto::device_from_seed(&STRANGER_SEED)).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let neighbors = station_c.neighbors();
        assert!(
            !neighbors.iter().any(|n| n.station == stranger_station),
            "an unadmitted emitter reached the durable registry"
        );
        if neighbors.iter().any(|n| n.station == b_station) {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the admitted beacon never landed — the pipeline was not live"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    // One more look after the admitted one landed: still fenced out.
    assert!(
        !station_c
            .neighbors()
            .iter()
            .any(|n| n.station == stranger_station),
        "the stranger appeared after the admitted beacon"
    );

    let _ = station_c.go_dormant();
    let _ = std::fs::remove_dir_all(&root_c);
}
