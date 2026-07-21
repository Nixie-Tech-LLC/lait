//! S1 dispatch proof: a test-only World submits and queries through the generic
//! Session dispatch — no product types anywhere. This exercises the
//! envelope → dock → World → Effect/Projection seam the product adopts in S5.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lait_kernel::acl::Grant;
use lait_kernel::ids::{ActorId, DeviceId};

use crate::error::WorldError;
use crate::lifecycle::{ActivationOptions, Runtime, SpaceFormationOptions};
use crate::registry::RuntimeBuilder;
use crate::session::ObservationCursor;
use crate::world::{
    AuthorityView, LocalIdentity, PrincipalResolution, Standing, World, WorldContext, WorldEffect,
    WorldIntent, WorldLimits, WorldProjection, WorldQuery, WorldRegistration, WorldVersion,
};
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, EncodingId, SchemaId, WorldId};

/// The writing test device (granted Write by [`SeedAuthority`]).
const WRITER_SEED: [u8; 32] = [41u8; 32];
/// A second device with no grants (resolves, but has empty standing).
const READER_SEED: [u8; 32] = [42u8; 32];

/// A test mechanics view: the writer device gets Write standing, any other
/// known-shaped device resolves with empty standing.
struct SeedAuthority;

impl AuthorityView for SeedAuthority {
    fn resolve(&self, device: &DeviceId) -> Option<PrincipalResolution> {
        let writer = lait_kernel::crypto::device_from_seed(&WRITER_SEED);
        let grants = if device == &writer {
            vec![Grant::Write]
        } else {
            vec![]
        };
        Some(PrincipalResolution {
            actor: ActorId::from_incept_hash(&"a".repeat(64)),
            standing: Standing::new(grants),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![1]),
        })
    }
}

fn writer() -> LocalIdentity {
    Runtime::identity_from_seed(&WRITER_SEED)
}

fn reader() -> LocalIdentity {
    Runtime::identity_from_seed(&READER_SEED)
}

/// A minimal note World: intents carry UTF-8 text; `submit` stages an atomic
/// replacement and reports the touched scope; `query` echoes a deterministic
/// projection derived only from its inputs.
struct NoteWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl NoteWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("com.example.notes").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("note").unwrap(),
                version: 1,
                encoding: EncodingId::parse("text.utf8").unwrap(),
                mutation: MutationModel::Atomic,
                readable_predecessors: vec![],
            }],
        }
    }
}

impl World for NoteWorld {
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
        // Authorization is per request: the note World needs Write standing.
        if !ctx.principal().standing.has(&Grant::Write) {
            return Err(WorldError::Denied);
        }
        if intent.schema.as_str() != "note" {
            return Err(WorldError::UnsupportedSchema);
        }
        // Deterministic body key: same World, a fixed body for this test.
        let key = BodyKey::new(self.id.clone(), BodyId::from_bytes([0u8; 16]));
        Ok(WorldEffect {
            operations: vec![(
                key.clone(),
                BodyOp::ReplaceAtomic {
                    value: intent.payload.clone(),
                },
            )],
            scopes: vec![key],
            effect: intent.payload,
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        if query.schema.as_str() != "note" {
            return Err(WorldError::UnsupportedSchema);
        }
        // Read the committed Body from the stable snapshot and uppercase it. An
        // absent Body reads as empty.
        let key = BodyKey::new(self.id.clone(), BodyId::from_bytes([0u8; 16]));
        let committed = ctx.read_body(&key).unwrap_or_default();
        let text = String::from_utf8(committed).map_err(|_| WorldError::InvalidRequest)?;
        Ok(WorldProjection {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            bytes: text.to_uppercase().into_bytes(),
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

fn note_registration() -> (WorldRegistration, Arc<dyn World>) {
    let world = NoteWorld::new();
    let reg = WorldRegistration {
        id: world.id(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    (reg, Arc::new(world))
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_root() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-dispatch-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn station_with(reg: WorldRegistration, world: Arc<dyn World>) -> crate::lifecycle::Station {
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry, Arc::new(SeedAuthority));
    rt.form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap()
}

fn station() -> crate::lifecycle::Station {
    let (reg, world) = note_registration();
    station_with(reg, world)
}

#[test]
fn test_world_submits_and_queries_through_dispatch() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();

    // A query before any submit reads the empty committed snapshot.
    let empty = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(empty.bytes, b"");

    // Submit an intent: it is durably committed and advances the frontier.
    let committed = session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"hello".to_vec(),
        })
        .unwrap();
    assert_eq!(committed.effect, b"hello");
    assert_eq!(committed.frontier.transaction_count, 1);
    assert_eq!(committed.observation.sequence, 1);
    assert_eq!(committed.observation.scopes.len(), 1);
    assert_ne!(committed.frontier, ReplicaFrontier::EMPTY);

    // The query now reads back the committed Body.
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.bytes, b"HELLO");
}

#[test]
fn authorization_is_checked_per_request() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    // A principal with no Write standing is denied at submit, not at dock.
    let session = station.dock(&world_id, &reader()).unwrap();
    let denied = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"x".to_vec(),
    });
    assert_eq!(denied, Err(WorldError::Denied));
}

#[test]
fn many_sessions_dock_independently_without_owning_the_station() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let s1 = station.dock(&world_id, &writer()).unwrap();
    let s2 = station.dock(&world_id, &writer()).unwrap();
    assert_eq!(s1.epoch(), s2.epoch());
    // Undocking one Session leaves the Station and the other Session intact.
    s1.undock();
    assert!(s2
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"ok".to_vec(),
        })
        .is_ok());
    // The Station survives its Sessions and can still go dormant.
    assert!(station.go_dormant().is_ok());
}

#[test]
fn dormancy_terminates_sessions() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    // Going dormant terminates the Session: further requests fail closed.
    let _orbit = station.go_dormant().unwrap();
    assert_eq!(
        session.query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::StationDormant)
    );
}

#[test]
fn a_session_cannot_stop_the_station() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    // Dock a Session and drop it (undock) — the Station is unaffected and can
    // still serve new Sessions.
    let s = station.dock(&world_id, &writer()).unwrap();
    s.undock();
    let s2 = station.dock(&world_id, &writer()).unwrap();
    assert!(s2
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"ok".to_vec(),
        })
        .is_ok());
    // A tracked task panicking does not stop the Station's ability to go dormant.
    station.spawn_tracked(|_c| panic!("boom")).unwrap();
    let exit = station.wait();
    assert!(matches!(
        exit.reason,
        Some(crate::error::StationExitReason::TaskFailed(_))
    ));
}

/// A World whose `submit` panics — to prove Runtime contains it.
struct PanicWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}
impl World for PanicWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }
    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }
    fn submit(
        &self,
        _ctx: &mut WorldContext<'_>,
        _intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        panic!("world callback panics")
    }
    fn query(
        &self,
        _ctx: &WorldContext<'_>,
        _query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        Err(WorldError::InvalidRequest)
    }
}

#[test]
fn a_world_panic_is_contained_and_does_not_end_the_station() {
    let id = WorldId::parse("com.example.panic").unwrap();
    let schemas = vec![BodySchema {
        id: SchemaId::parse("note").unwrap(),
        version: 1,
        encoding: EncodingId::parse("text.utf8").unwrap(),
        mutation: MutationModel::Atomic,
        readable_predecessors: vec![],
    }];
    let reg = WorldRegistration {
        id: id.clone(),
        implementation_version: WorldVersion(1),
        schemas: schemas.clone(),
        limits: WorldLimits::default(),
    };
    let world: Arc<dyn World> = Arc::new(PanicWorld {
        id: id.clone(),
        schemas,
    });
    let station = station_with(reg, world);
    let session = station.dock(&id, &writer()).unwrap();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"x".to_vec(),
    });
    assert_eq!(r, Err(WorldError::WorldImplementationFailed));
    // The Station survives the panic and can still go dormant cleanly.
    assert!(station.go_dormant().is_ok());
}

#[test]
fn payload_over_the_declared_limit_is_rejected_before_the_callback() {
    let (mut reg, world) = note_registration();
    reg.limits = WorldLimits {
        max_payload_bytes: 4,
    };
    let station = station_with(reg, world);
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"toolong".to_vec(),
    });
    assert_eq!(r, Err(WorldError::LimitExceeded));
}

#[test]
fn unregistered_schema_and_version_are_rejected() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    // Unknown schema.
    assert_eq!(
        session.submit(WorldIntent {
            schema: SchemaId::parse("other").unwrap(),
            schema_version: 1,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::UnsupportedSchema)
    );
    // Known schema, unknown version.
    assert_eq!(
        session.submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 9,
            payload: b"x".to_vec(),
        }),
        Err(WorldError::UnsupportedSchemaVersion)
    );
}

#[test]
fn an_acknowledged_commit_survives_a_crash_without_dormancy() {
    // Finding #1's scenario: submit returns success, then the process dies with
    // NO go_dormant and NO checkpoint call. Dropping the Station without
    // dormancy models the kill (the OS releases the lock either way). The
    // acknowledged commit must still be there on the next activation, because
    // durability happened AT COMMIT, not at shutdown.
    let (reg, world) = note_registration();
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry, Arc::new(SeedAuthority));
    let world_id = WorldId::parse("com.example.notes").unwrap();

    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"ack'd then crash".to_vec(),
        })
        .unwrap();
    // Crash: no dormancy, no checkpoint.
    drop(session);
    drop(station);

    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.bytes, b"ACK'D THEN CRASH");
}

#[test]
fn commits_made_during_an_activation_survive_wait_exit() {
    // Finding #1's second scenario: Station::wait returns without a checkpoint.
    // Per-commit durability means nothing made during the activation is lost.
    let (reg, world) = note_registration();
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry, Arc::new(SeedAuthority));
    let world_id = WorldId::parse("com.example.notes").unwrap();

    let station = rt
        .form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let space = station.space_id().clone();
    let session = station.dock(&world_id, &writer()).unwrap();
    session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"survives wait".to_vec(),
        })
        .unwrap();
    // Exit via wait (no dormancy checkpoint path).
    let exit = station.wait();
    drop(exit);

    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.bytes, b"SURVIVES WAIT");
}

#[test]
fn committed_bodies_survive_dormancy_and_reactivation() {
    // The full durable loop: form → activate → submit → go_dormant (checkpoint)
    // → re-acquire → activate → the committed Body is read back.
    let (reg, world) = note_registration();
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry, Arc::new(SeedAuthority));
    let world_id = WorldId::parse("com.example.notes").unwrap();

    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"durable".to_vec(),
        })
        .unwrap();
    // Go dormant: this checkpoints the Replica to the store.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);

    // Re-acquire and reactivate: the committed Body is restored.
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.bytes, b"DURABLE");
}

/// A hostile World that stages an operation against ANOTHER World's namespace.
struct RogueWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}
impl World for RogueWorld {
    fn id(&self) -> WorldId {
        self.id.clone()
    }
    fn schemas(&self) -> &[BodySchema] {
        &self.schemas
    }
    fn submit(
        &self,
        _ctx: &mut WorldContext<'_>,
        intent: WorldIntent,
    ) -> Result<WorldEffect, WorldError> {
        // Attempt to overwrite a Body belonging to com.example.notes.
        let foreign = BodyKey::new(
            WorldId::parse("com.example.notes").unwrap(),
            BodyId::from_bytes([0u8; 16]),
        );
        Ok(WorldEffect {
            operations: vec![(
                foreign.clone(),
                BodyOp::ReplaceAtomic {
                    value: intent.payload,
                },
            )],
            scopes: vec![foreign],
            effect: vec![],
        })
    }
    fn query(
        &self,
        _ctx: &WorldContext<'_>,
        _query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        Err(WorldError::InvalidRequest)
    }
}

#[test]
fn a_world_cannot_write_outside_its_namespace() {
    let id = WorldId::parse("com.example.rogue").unwrap();
    let schemas = vec![BodySchema {
        id: SchemaId::parse("note").unwrap(),
        version: 1,
        encoding: EncodingId::parse("text.utf8").unwrap(),
        mutation: MutationModel::Atomic,
        readable_predecessors: vec![],
    }];
    let reg = WorldRegistration {
        id: id.clone(),
        implementation_version: WorldVersion(1),
        schemas: schemas.clone(),
        limits: WorldLimits::default(),
    };
    let world: Arc<dyn World> = Arc::new(RogueWorld {
        id: id.clone(),
        schemas,
    });
    let station = station_with(reg, world);
    let session = station.dock(&id, &writer()).unwrap();
    let before = station.frontier();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"overwrite you".to_vec(),
    });
    assert_eq!(r, Err(WorldError::ContractViolation));
    // Nothing was committed.
    assert_eq!(station.frontier(), before);
}

/// An authority view whose frontier can be flipped mid-flight — for the CAS test.
struct FlippingAuthority {
    frontier: std::sync::Mutex<Vec<u8>>,
}
impl AuthorityView for FlippingAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<PrincipalResolution> {
        Some(PrincipalResolution {
            actor: ActorId::from_incept_hash(&"a".repeat(64)),
            standing: Standing::new(vec![Grant::Write]),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(
                self.frontier.lock().unwrap().clone(),
            ),
        })
    }
}

#[test]
fn a_changed_authority_frontier_refuses_the_commit() {
    // A World that flips the shared authority frontier DURING its callback —
    // modelling a concurrent membership change landing between authorization
    // and commit. The commit-side CAS must catch it.
    struct FlipDuringSubmit {
        inner: NoteWorld,
        authority: Arc<FlippingAuthority>,
    }
    impl World for FlipDuringSubmit {
        fn id(&self) -> WorldId {
            self.inner.id()
        }
        fn schemas(&self) -> &[BodySchema] {
            self.inner.schemas()
        }
        fn submit(
            &self,
            ctx: &mut WorldContext<'_>,
            intent: WorldIntent,
        ) -> Result<WorldEffect, WorldError> {
            *self.authority.frontier.lock().unwrap() = vec![9, 9];
            self.inner.submit(ctx, intent)
        }
        fn query(
            &self,
            ctx: &WorldContext<'_>,
            query: WorldQuery,
        ) -> Result<WorldProjection, WorldError> {
            self.inner.query(ctx, query)
        }
    }

    let authority = Arc::new(FlippingAuthority {
        frontier: std::sync::Mutex::new(vec![1]),
    });
    let inner = NoteWorld::new();
    let id = inner.id();
    let reg = WorldRegistration {
        id: id.clone(),
        implementation_version: WorldVersion(1),
        schemas: inner.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let world: Arc<dyn World> = Arc::new(FlipDuringSubmit {
        inner,
        authority: authority.clone(),
    });
    let registry = RuntimeBuilder::new().register(reg, world).build().unwrap();
    let rt = Runtime::open(temp_root(), registry, authority);
    let station = rt
        .form_space(SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&id, &writer()).unwrap();
    let before = station.frontier();
    let r = session.submit(WorldIntent {
        schema: SchemaId::parse("note").unwrap(),
        schema_version: 1,
        payload: b"x".to_vec(),
    });
    assert_eq!(r, Err(WorldError::AuthorityChanged));
    assert_eq!(station.frontier(), before, "nothing committed");
}

#[test]
fn runtime_stamps_the_projection_frontier() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let committed = session
        .submit(WorldIntent {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: b"x".to_vec(),
        })
        .unwrap();
    // The NoteWorld returns ReplicaFrontier::EMPTY from query; Runtime must
    // overwrite it with the real committed frontier of the held snapshot.
    let proj = session
        .query(WorldQuery {
            schema: SchemaId::parse("note").unwrap(),
            schema_version: 1,
            payload: vec![],
        })
        .unwrap();
    assert_eq!(proj.frontier, committed.frontier);
    assert_ne!(proj.frontier, ReplicaFrontier::EMPTY);
}

/// A collaborative World: intents append a comment (list) and bump a counter;
/// queries project the collaborative view.
struct BoardWorld {
    id: WorldId,
    schemas: Vec<BodySchema>,
}

impl BoardWorld {
    fn new() -> Self {
        Self {
            id: WorldId::parse("com.example.board").unwrap(),
            schemas: vec![BodySchema {
                id: SchemaId::parse("card").unwrap(),
                version: 1,
                encoding: EncodingId::parse("collab").unwrap(),
                mutation: MutationModel::Collaborative(
                    replica::body::CollaborativeSchema::default(),
                ),
                readable_predecessors: vec![],
            }],
        }
    }
    fn body(&self) -> BodyKey {
        BodyKey::new(self.id.clone(), BodyId::from_bytes([7u8; 16]))
    }
}

impl World for BoardWorld {
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
        let key = self.body();
        Ok(WorldEffect {
            operations: vec![
                (
                    key.clone(),
                    BodyOp::ListInsert {
                        path: "comments".into(),
                        index: ctx
                            .read_collaborative(&key)
                            .map(|v| v.lists.get("comments").map(|l| l.len()).unwrap_or(0))
                            .unwrap_or(0) as u64,
                        value: intent.payload,
                    },
                ),
                (
                    key.clone(),
                    BodyOp::CounterAdd {
                        path: "activity".into(),
                        delta: 1,
                    },
                ),
            ],
            scopes: vec![key],
            effect: vec![],
        })
    }
    fn query(
        &self,
        ctx: &WorldContext<'_>,
        _query: WorldQuery,
    ) -> Result<WorldProjection, WorldError> {
        let view = ctx.read_collaborative(&self.body()).unwrap_or_default();
        let comments: Vec<String> = view
            .lists
            .get("comments")
            .map(|l| {
                l.iter()
                    .map(|e| String::from_utf8_lossy(&e.value).into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let activity = view.counters.get("activity").copied().unwrap_or(0);
        Ok(WorldProjection {
            schema: SchemaId::parse("card").unwrap(),
            schema_version: 1,
            bytes: format!("{activity}:{}", comments.join(",")).into_bytes(),
            frontier: ReplicaFrontier::EMPTY,
        })
    }
}

#[test]
fn a_collaborative_world_commits_and_reads_through_the_session() {
    let world = BoardWorld::new();
    let id = world.id();
    let reg = WorldRegistration {
        id: id.clone(),
        implementation_version: WorldVersion(1),
        schemas: world.schemas().to_vec(),
        limits: WorldLimits::default(),
    };
    let registry = RuntimeBuilder::new()
        .register(reg, Arc::new(world))
        .build()
        .unwrap();
    let rt = Runtime::open(temp_root(), registry, Arc::new(SeedAuthority));
    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();
    let session = station.dock(&id, &writer()).unwrap();

    let query = || WorldQuery {
        schema: SchemaId::parse("card").unwrap(),
        schema_version: 1,
        payload: vec![],
    };
    let intent = |text: &str| WorldIntent {
        schema: SchemaId::parse("card").unwrap(),
        schema_version: 1,
        payload: text.as_bytes().to_vec(),
    };

    session.submit(intent("first comment")).unwrap();
    session.submit(intent("second comment")).unwrap();
    let proj = session.query(query()).unwrap();
    assert_eq!(proj.bytes, b"2:first comment,second comment");

    // Collaborative Bodies survive dormancy + reactivation like atomic ones.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&id, &writer()).unwrap();
    let proj = session.query(query()).unwrap();
    assert_eq!(proj.bytes, b"2:first comment,second comment");
}

#[test]
fn observation_cursor_starts_at_a_reset_boundary() {
    let station = station();
    let world_id = WorldId::parse("com.example.notes").unwrap();
    let session = station.dock(&world_id, &writer()).unwrap();
    let cursor = ObservationCursor::start(session.epoch());
    assert_eq!(cursor.sequence, 0);
    assert_eq!(session.observe(cursor), cursor);
}
