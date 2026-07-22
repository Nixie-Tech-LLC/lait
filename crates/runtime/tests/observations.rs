//! C3 / G7 — the bounded Observation stream, through the public API.
//!
//! Frozen v1 semantics: exclusive `(epoch, sequence)` cursors; `observe(None)`
//! or a cursor from another epoch yields exactly one reset record then live
//! delivery; an in-window cursor replays retained records; an overrun yields
//! one reset and discards the gap; publications happen once per durable
//! commit (never before durability, never for a refused request or an
//! idempotent replay); sequences are monotonic within an activation epoch;
//! dormancy ends streams with a typed `StationDormant`.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mechanics::acl::Grant;
use mechanics::crypto::AuthorizedBodyKey;
use mechanics::ids::{ActorId, DeviceId};
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

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
    ActivationOptions, LocalIdentity, ObservationCursor, ObservationStreamError, RequestId,
    Runtime, RuntimeBuilder, Session, SpaceFormationOptions, Station, World, WorldContext,
    WorldEffect, WorldError, WorldIntent, WorldLimits, WorldProjection, WorldQuery,
    WorldRegistration, WorldVersion,
};

const WRITER_SEED: [u8; 32] = [55u8; 32];
const READER_SEED: [u8; 32] = [56u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> std::path::PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-obs-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct KvWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl KvWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("dev.example.kv").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("entry").unwrap(),
                version: 1,
                encoding: EncodingId::parse("bytes").unwrap(),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }
    fn body(&self, key: &str) -> BodyKey {
        let mut raw = [0u8; 16];
        let k = key.as_bytes();
        raw[..k.len().min(16)].copy_from_slice(&k[..k.len().min(16)]);
        BodyKey::new(self.id.clone(), BodyId::from_bytes(raw))
    }
}

impl World for KvWorld {
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
        if !ctx.principal().standing.has(&Grant::Write) {
            return Err(WorldError::Denied);
        }
        let text = String::from_utf8(intent.payload).map_err(|_| WorldError::InvalidRequest)?;
        let (key, value) = text.split_once('=').ok_or(WorldError::InvalidRequest)?;
        let body = self.body(key);
        Ok(WorldEffect {
            demand: any_demand(),
            operations: vec![(
                body.clone(),
                BodyOp::ReplaceAtomic {
                    value: value.as_bytes().to_vec(),
                },
            )],
            scopes: vec![body],
            effect: vec![],
            declarations: vec![],
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let key = String::from_utf8(query.payload).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldProjection {
            demand: any_demand(),
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            bytes: ctx.read_body(&self.body(&key)).unwrap_or_default(),
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

struct WriterOnly;
impl runtime::AuthorityView for WriterOnly {
    fn resolve(&self, device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        let writer = mechanics::crypto::device_from_seed(&WRITER_SEED);
        let grants = if device == &writer {
            vec![Grant::Write]
        } else {
            vec![]
        };
        Some(runtime::PrincipalResolution {
            actor: ActorId::from_incept_hash(&"e".repeat(64)),
            standing: runtime::Standing::new(grants),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![5]),
        })
    }
}

fn runtime_at(root: &std::path::Path) -> Runtime {
    let world = KvWorld::new();
    let reg = WorldRegistration {
        id: world.id(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let registry = RuntimeBuilder::new()
        .register(reg, Arc::new(world))
        .build()
        .unwrap();
    Runtime::open(
        root.to_path_buf(),
        registry,
        Arc::new(WriterOnly),
        Arc::new(replica::StaticBodyKeys::new(
            AuthorizedBodyKey::for_authorized_epoch([17u8; 16], [18u8; 32]),
        )),
    )
}

fn station_with_capacity(root: &std::path::Path, capacity: usize) -> Station {
    runtime_at(root)
        .form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions {
            drain_deadline: Duration::from_secs(5),
            comms: None,
            observation_capacity: capacity,
        })
        .unwrap()
}

fn dock(station: &Station) -> (Session, LocalIdentity) {
    let world_id = WorldId::parse("dev.example.kv").unwrap();
    let writer = Runtime::identity_from_seed(&WRITER_SEED);
    let session = station.dock(&world_id, &writer).unwrap();
    (session, writer)
}

fn action(
    session: &Session,
    identity: &LocalIdentity,
    request: RequestId,
    entry: &str,
) -> runtime::SignedWorldAction {
    identity
        .sign_action(
            session,
            request,
            WorldIntent {
                schema: SchemaId::parse("entry").unwrap(),
                schema_version: 1,
                payload: entry.as_bytes().to_vec(),
            },
        )
        .unwrap()
}

#[test]
fn first_use_resets_then_each_durable_commit_publishes_exactly_once() {
    let root = temp_root();
    let station = station_with_capacity(&root, 0);
    let (session, writer) = dock(&station);

    let mut stream = session.observe(None);
    let first = stream.try_next().unwrap().unwrap();
    assert!(first.reset, "first use rebaselines");
    assert!(stream.try_next().unwrap().is_none(), "exactly one reset");

    // A durable commit publishes exactly one record with its scopes.
    session
        .submit(action(&session, &writer, RequestId::mint(), "a=1"))
        .unwrap();
    let record = stream.try_next().unwrap().unwrap();
    assert!(!record.reset);
    assert_eq!(record.scopes.len(), 1);
    assert!(record.sequence > first.sequence, "monotonic");
    assert!(stream.try_next().unwrap().is_none(), "published ONCE");

    // A refused request publishes nothing.
    let reader = Runtime::identity_from_seed(&READER_SEED);
    let world_id = WorldId::parse("dev.example.kv").unwrap();
    let denied_session = station.dock(&world_id, &reader).unwrap();
    let denied = denied_session.submit(action(&denied_session, &reader, RequestId::mint(), "x=y"));
    assert_eq!(denied, Err(WorldError::Denied));
    assert!(stream.try_next().unwrap().is_none());

    // An idempotent replay publishes nothing either.
    let request = RequestId::from_bytes([9u8; 16]);
    let signed = action(&session, &writer, request, "b=2");
    session.submit(signed.clone()).unwrap();
    let _ = stream.try_next().unwrap().unwrap();
    session.submit(signed).unwrap();
    assert!(
        stream.try_next().unwrap().is_none(),
        "a replay commits nothing and publishes nothing"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_in_window_cursor_replays_then_follows_live() {
    let root = temp_root();
    let station = station_with_capacity(&root, 0);
    let (session, writer) = dock(&station);
    session
        .submit(action(&session, &writer, RequestId::mint(), "a=1"))
        .unwrap();
    session
        .submit(action(&session, &writer, RequestId::mint(), "b=2"))
        .unwrap();

    // A fresh stream resets at the current sequence; its cursor then REPLAYS
    // nothing (exclusive) until new commits arrive.
    let mut stream = session.observe(None);
    let reset = stream.try_next().unwrap().unwrap();
    assert!(reset.reset);
    assert!(stream.try_next().unwrap().is_none());

    // A cursor from sequence 0 of THIS epoch replays both retained records.
    let mut replay = session.observe(Some(ObservationCursor {
        epoch: session.epoch(),
        sequence: 0,
    }));
    let r1 = replay.try_next().unwrap().unwrap();
    let r2 = replay.try_next().unwrap().unwrap();
    assert!(!r1.reset && !r2.reset);
    assert!(r1.sequence < r2.sequence);
    assert!(replay.try_next().unwrap().is_none());

    // …then follows live delivery.
    session
        .submit(action(&session, &writer, RequestId::mint(), "c=3"))
        .unwrap();
    let live = replay
        .next_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    assert_eq!(live.sequence, r2.sequence + 1);
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn an_overrun_yields_one_reset_and_discards_the_gap() {
    let root = temp_root();
    // Capacity 1: only the newest record is retained.
    let station = station_with_capacity(&root, 1);
    let (session, writer) = dock(&station);
    for i in 0..3 {
        session
            .submit(action(
                &session,
                &writer,
                RequestId::mint(),
                &format!("k{i}=v"),
            ))
            .unwrap();
    }
    // A cursor pointing into the discarded gap gets exactly one reset, then
    // the retained tail.
    let mut stream = session.observe(Some(ObservationCursor {
        epoch: session.epoch(),
        sequence: 0,
    }));
    let reset = stream.try_next().unwrap().unwrap();
    assert!(reset.reset, "overrun rebaselines");
    assert!(
        stream.try_next().unwrap().is_none(),
        "the gap is discarded, not replayed"
    );
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn restart_and_cross_epoch_cursors_reset() {
    let root = temp_root();
    let rt = runtime_at(&root);
    let station = rt
        .form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    let space = station.space_id().clone();
    let (session, writer) = dock(&station);
    session
        .submit(action(&session, &writer, RequestId::mint(), "a=1"))
        .unwrap();
    let old_epoch = session.epoch();

    // Crash after durability, before any consumer observed: recovery is reset
    // + re-query, never a durable outbox.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    let (session, _) = dock(&station);
    let mut stream = session.observe(Some(ObservationCursor {
        epoch: old_epoch,
        sequence: 1,
    }));
    let record = stream.try_next().unwrap().unwrap();
    assert!(record.reset, "a cursor from another epoch resets");
    // The committed state is re-queried, not replayed.
    let projection = session
        .query(WorldQuery {
            schema: SchemaId::parse("entry").unwrap(),
            schema_version: 1,
            payload: b"a".to_vec(),
        })
        .unwrap();
    assert_eq!(projection.bytes, b"1");
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn dormancy_terminates_streams_typed_and_concurrent_sessions_both_receive() {
    let root = temp_root();
    let station = station_with_capacity(&root, 0);
    let (s1, writer) = dock(&station);
    let (s2, _) = dock(&station);
    let mut stream1 = s1.observe(None);
    let mut stream2 = s2.observe(None);
    let _ = stream1.try_next().unwrap();
    let _ = stream2.try_next().unwrap();

    s1.submit(action(&s1, &writer, RequestId::mint(), "a=1"))
        .unwrap();
    assert!(stream1.try_next().unwrap().unwrap().sequence >= 1);
    assert!(stream2.try_next().unwrap().unwrap().sequence >= 1);

    let _ = station.go_dormant().unwrap();
    assert_eq!(
        stream1.next_timeout(Duration::from_secs(1)),
        Err(ObservationStreamError::StationDormant)
    );
    assert_eq!(
        stream2.try_next(),
        Err(ObservationStreamError::StationDormant)
    );
    let _ = std::fs::remove_dir_all(&root);
}
