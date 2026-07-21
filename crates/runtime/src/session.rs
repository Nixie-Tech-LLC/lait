//! [`Session`] — a local caller docked to a hosted World.
//!
//! A Session is bound to one World, principal, and Station activation epoch.
//! Sessions are many-to-one, independently closeable, and **cannot** stop the
//! Station. Authorization is checked per request, not only at Dock.
//!
//! The dispatch seam: `submit`/`query` **validate the request against the
//! World's registration, contain a World panic, and build a bounded**
//! [`WorldContext`](crate::world::WorldContext) over the principal before routing
//! to the World implementation. Before the World is called the Session
//! enforces: the Station is live; the payload is within
//! [`WorldLimits`](crate::world::WorldLimits); the intent/query names a declared
//! schema+version (a query may also read a declared readable predecessor); and
//! the principal's standing is **re-resolved through the mechanics
//! [`AuthorityView`](crate::world::AuthorityView)** for this request. A panic in
//! the callback is caught as [`WorldError::WorldImplementationFailed`] and never
//! ends the Station.
//!
//! After the World stages its effect, the Session **contains** it — every staged
//! operation and scope must address the Session's own World namespace with an
//! operation kind that World's registered mutation models allow — then performs
//! the authority-frontier compare-and-swap under the writer lock, and durably
//! commits. Success means recoverable, not merely applied in memory.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use lait_kernel::ids::StationEpoch;
use replica::body::{BodyOp, BodySchema, MutationModel};
use replica::frontier::ReplicaFrontier;
use replica::ids::{BodyKey, SchemaId, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::WorldError;
use crate::world::{
    AuthorityView, PrincipalFacts, World, WorldContext, WorldEffect, WorldIntent, WorldLimits,
    WorldProjection, WorldQuery,
};

/// A resumable Observation position. First observation, restart, cursor overrun,
/// schema migration, or lost continuity forces a reset/rebaseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservationCursor {
    pub epoch: StationEpoch,
    pub sequence: u64,
}

impl ObservationCursor {
    /// The starting cursor — its first delivery always resets.
    pub fn start(epoch: StationEpoch) -> Self {
        Self { epoch, sequence: 0 }
    }
}

/// A bounded invalidation/advancement signal published after a durable commit.
/// It carries no replicated state — consumers re-query. A slow consumer
/// rebaselines rather than buffering without bound.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Observation {
    pub epoch: StationEpoch,
    pub sequence: u64,
    /// Set on first observation, restart, cursor overrun, migration, or lost
    /// continuity — the consumer must rebaseline.
    pub reset: bool,
    pub world: WorldId,
    pub scopes: Vec<BodyKey>,
    pub frontier: ReplicaFrontier,
}

/// The result of a durable [`Session::submit`]: the application-defined effect
/// bytes, the **committed** Replica frontier the change advanced to, and the
/// Observation Runtime published. A `CommittedEffect` is proof of durability —
/// it is returned only after the Replica advanced from a real Fabric receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEffect {
    pub effect: Vec<u8>,
    pub frontier: ReplicaFrontier,
    pub observation: Observation,
}

/// The single mutex-guarded committing state: the Replica writer plus the
/// closed flag. `closed` lives **inside** the same mutex as the writer so that
/// commit admission and Station shutdown are one serialized state transition —
/// a submit admitted before dormancy either commits before the close (and is
/// durable + checkpointed) or observes `closed` and is refused. There is no
/// window where a commit lands after the shutdown checkpoint.
struct CoreInner {
    replica: replica::Replica,
    closed: bool,
}

/// The Station's exclusive committing state, shared with its Sessions. Held
/// behind an `Arc` by the Station and every Session; a Session can commit
/// through it but never stop the Station.
pub(crate) struct StationCore {
    inner: std::sync::Mutex<CoreInner>,
    obs_seq: std::sync::atomic::AtomicU64,
    epoch: StationEpoch,
}

impl StationCore {
    pub(crate) fn new(epoch: StationEpoch, replica: replica::Replica) -> Self {
        Self {
            inner: std::sync::Mutex::new(CoreInner {
                replica,
                closed: false,
            }),
            obs_seq: std::sync::atomic::AtomicU64::new(0),
            epoch,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, CoreInner> {
        self.inner.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub(crate) fn frontier(&self) -> ReplicaFrontier {
        self.lock().replica.frontier()
    }

    /// Close the core to further commits, as one transition under the writer
    /// mutex: an in-flight submit either completed its journaled durable commit
    /// before the close or observes it and is refused. Every acknowledged
    /// commit is already on disk, so closing needs no checkpoint.
    pub(crate) fn close(&self) {
        self.lock().closed = true;
    }
}

/// A [`BodyReader`] over a locked Replica, handed to a World during a query.
struct ReplicaReader<'a>(&'a replica::Replica);

impl crate::world::BodyReader for ReplicaReader<'_> {
    fn read_body(&self, key: &BodyKey) -> Option<Vec<u8>> {
        self.0.read(key)
    }
    fn read_collaborative_body(&self, key: &BodyKey) -> Option<replica::CollaborativeView> {
        self.0.read_collaborative(key)
    }
}

/// A local caller's handle to a hosted World.
pub struct Session {
    world_id: WorldId,
    world: Arc<dyn World>,
    principal: PrincipalFacts,
    epoch: StationEpoch,
    /// The World's declared limits, enforced before the callback runs.
    limits: WorldLimits,
    /// The World's declared schemas, checked against each request.
    schemas: Vec<BodySchema>,
    /// A shared flag: `false` once the Station is going dormant or has exited.
    /// A Session only *reads* it — it can never stop the Station.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// The Station's exclusive committing state.
    core: Arc<StationCore>,
    /// The mechanics authority view: standing is re-resolved per request and the
    /// authority frontier is compare-and-swapped at commit.
    authority: Arc<dyn AuthorityView>,
}

impl Session {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        world_id: WorldId,
        world: Arc<dyn World>,
        principal: PrincipalFacts,
        epoch: StationEpoch,
        limits: WorldLimits,
        schemas: Vec<BodySchema>,
        alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
        core: Arc<StationCore>,
        authority: Arc<dyn AuthorityView>,
    ) -> Self {
        Self {
            world_id,
            world,
            principal,
            epoch,
            limits,
            schemas,
            alive,
            core,
            authority,
        }
    }

    /// Fresh principal facts for THIS request: standing and the authority
    /// frontier are re-resolved through the mechanics view, so dock-time facts
    /// never outlive the authority state. Denied when the device no longer
    /// resolves.
    fn fresh_principal(&self) -> Result<PrincipalFacts, WorldError> {
        let resolution = self
            .authority
            .resolve(&self.principal.device)
            .ok_or(WorldError::Denied)?;
        Ok(PrincipalFacts {
            actor: resolution.actor,
            device: self.principal.device.clone(),
            station: self.principal.station.clone(),
            standing: resolution.standing,
            authority_frontier: resolution.authority_frontier,
        })
    }

    /// Contain a World's staged effect inside its own namespace and registered
    /// mutation models. A buggy or hostile World must not be able to write
    /// another World's Bodies or exceed the transaction bound.
    fn contain_effect(&self, effect: &WorldEffect) -> Result<(), WorldError> {
        if effect.operations.len() > replica::algebra::MAX_OPS_PER_TRANSACTION {
            return Err(WorldError::ContractViolation);
        }
        let allows_atomic = self
            .schemas
            .iter()
            .any(|s| matches!(s.mutation, MutationModel::Atomic));
        let allows_collab = self
            .schemas
            .iter()
            .any(|s| matches!(s.mutation, MutationModel::Collaborative(_)));
        for (key, op) in &effect.operations {
            if key.world != self.world_id {
                return Err(WorldError::ContractViolation);
            }
            let permitted = match op {
                BodyOp::ReplaceAtomic { .. } => allows_atomic,
                // Create/tombstone are legal under either registered model.
                BodyOp::Create | BodyOp::Tombstone => allows_atomic || allows_collab,
                _ => allows_collab,
            };
            if !permitted {
                return Err(WorldError::ContractViolation);
            }
        }
        for scope in &effect.scopes {
            if scope.world != self.world_id {
                return Err(WorldError::ContractViolation);
            }
        }
        Ok(())
    }

    fn ensure_live(&self) -> Result<(), WorldError> {
        if self.alive.load(std::sync::atomic::Ordering::SeqCst) {
            Ok(())
        } else {
            Err(WorldError::StationDormant)
        }
    }

    /// Enforce the declared payload limit (a limit of `0` means "Runtime
    /// default", currently unbounded — S1 freezes the real default).
    fn ensure_within_limit(&self, payload_len: usize) -> Result<(), WorldError> {
        let max = self.limits.max_payload_bytes;
        if max != 0 && payload_len > max as usize {
            return Err(WorldError::LimitExceeded);
        }
        Ok(())
    }

    /// The exact `(schema, version)` must be a declared, writable schema.
    fn ensure_writable_schema(&self, schema: &SchemaId, version: u32) -> Result<(), WorldError> {
        let known = self.schemas.iter().find(|s| &s.id == schema);
        match known {
            None => Err(WorldError::UnsupportedSchema),
            Some(s) if s.version == version => Ok(()),
            Some(_) => Err(WorldError::UnsupportedSchemaVersion),
        }
    }

    /// A query may read the declared version or any of its readable predecessors.
    fn ensure_readable_schema(&self, schema: &SchemaId, version: u32) -> Result<(), WorldError> {
        let mut saw_schema = false;
        for s in &self.schemas {
            if &s.id != schema {
                continue;
            }
            saw_schema = true;
            if s.version == version || s.readable_predecessors.contains(&version) {
                return Ok(());
            }
        }
        if saw_schema {
            Err(WorldError::UnsupportedSchemaVersion)
        } else {
            Err(WorldError::UnsupportedSchema)
        }
    }

    /// The World this Session is docked to.
    pub fn world_id(&self) -> &WorldId {
        &self.world_id
    }

    /// The Station activation epoch this Session is bound to.
    pub fn epoch(&self) -> StationEpoch {
        self.epoch
    }

    /// Submit an application intent and **durably commit** its effect. Runtime
    /// derives the principal facts (the caller cannot assert them), validates the
    /// request, runs the World to stage Body operations, then commits them
    /// through the Station's exclusive Replica writer and publishes an
    /// Observation. The returned [`CommittedEffect`] is proof of durability: it
    /// exists only after the committed state was durably written (the Replica's
    /// per-commit durability sink). A refused request commits nothing.
    pub fn submit(&self, intent: WorldIntent) -> Result<CommittedEffect, WorldError> {
        self.ensure_live()?;
        self.ensure_within_limit(intent.payload.len())?;
        self.ensure_writable_schema(&intent.schema, intent.schema_version)?;
        // Per-request authorization: derive fresh facts from the mechanics view.
        let principal = self.fresh_principal()?;
        let world = &self.world;
        let label = intent.schema.as_str().to_string();
        // Hold the exclusive writer across the whole transaction: the World reads
        // the stable committed snapshot, stages operations against it, and the
        // commit lands atomically — a read-modify-write with no interleaving.
        // The closed flag is checked INSIDE this critical section, so commit
        // admission and Station shutdown are one serialized transition: no
        // commit can land after the dormancy checkpoint.
        let mut inner = self.core.lock();
        if inner.closed {
            return Err(WorldError::StationDormant);
        }
        let effect: WorldEffect = {
            let reader = ReplicaReader(&inner.replica);
            let principal = &principal;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                let mut ctx = WorldContext::with_reads(principal, &reader);
                world.submit(&mut ctx, intent)
            }))
            .unwrap_or(Err(WorldError::WorldImplementationFailed))?
        };
        // Contain the staged effect inside this World's namespace and models.
        self.contain_effect(&effect)?;
        // Authority-frontier compare-and-swap: the frontier the request was
        // authorized at must still be current at commit. A change refuses the
        // commit with AuthorityChanged and commits nothing.
        let current = self
            .authority
            .resolve(&principal.device)
            .ok_or(WorldError::Denied)?;
        if current.authority_frontier != principal.authority_frontier {
            return Err(WorldError::AuthorityChanged);
        }
        let frontier = inner
            .replica
            .commit(&label, &effect.operations)
            .map_err(|e| match e {
                // A staged op the engine cannot express is a World bug.
                replica::ReplicaCommitError::UnsupportedOp => WorldError::ContractViolation,
                replica::ReplicaCommitError::PathInvalid
                | replica::ReplicaCommitError::InvalidOp(_) => WorldError::InvalidRequest,
                replica::ReplicaCommitError::OpLimit => WorldError::LimitExceeded,
                replica::ReplicaCommitError::TypeConflict => WorldError::Conflict,
                replica::ReplicaCommitError::Fabric(_)
                | replica::ReplicaCommitError::Integrity(_)
                | replica::ReplicaCommitError::Durability(_)
                | replica::ReplicaCommitError::OutcomeUnknown
                | replica::ReplicaCommitError::Poisoned => WorldError::Persistence,
            })?;
        drop(inner);

        // Publish the Observation for the committed change.
        let sequence = self
            .core
            .obs_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            + 1;
        Ok(CommittedEffect {
            effect: effect.effect,
            frontier,
            observation: Observation {
                epoch: self.core.epoch,
                sequence,
                reset: false,
                world: self.world_id.clone(),
                scopes: effect.scopes,
                frontier,
            },
        })
    }

    /// Query the World over the stable committed snapshot. The World reads
    /// committed Bodies through the bounded context; the snapshot is held for the
    /// duration of the call so the projection is derived from one consistent
    /// frontier.
    pub fn query(&self, query: WorldQuery) -> Result<WorldProjection, WorldError> {
        self.ensure_live()?;
        self.ensure_within_limit(query.payload.len())?;
        self.ensure_readable_schema(&query.schema, query.schema_version)?;
        // Per-request authorization for reads as well.
        let principal = self.fresh_principal()?;
        let world = &self.world;
        let inner = self.core.lock();
        if inner.closed {
            return Err(WorldError::StationDormant);
        }
        let reader = ReplicaReader(&inner.replica);
        let mut projection = {
            let principal = &principal;
            std::panic::catch_unwind(AssertUnwindSafe(|| {
                let ctx = WorldContext::with_reads(principal, &reader);
                world.query(&ctx, query)
            }))
            .unwrap_or(Err(WorldError::WorldImplementationFailed))?
        };
        // Runtime — not the World — stamps the projection's source frontier: the
        // snapshot it was derived from is the one held for this call.
        projection.frontier = inner.replica.frontier();
        Ok(projection)
    }

    /// Begin observing from a cursor. The streaming surface lands in S5; S0
    /// returns the reset-bearing starting Observation position.
    pub fn observe(&self, cursor: ObservationCursor) -> ObservationCursor {
        cursor
    }

    /// Close this Session, consuming it. Never affects the Station.
    pub fn undock(self) {}
}
