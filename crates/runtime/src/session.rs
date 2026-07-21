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

use mechanics::ids::StationEpoch;
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
/// Observation scopes it touched. A `CommittedEffect` is proof of durability —
/// it is returned only after the Replica advanced from a real Fabric receipt.
/// An identical replay of the same request returns the identical
/// `CommittedEffect` without reapplying anything; invalidation delivery is the
/// job of [`Session::observe`], not of this return value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommittedEffect {
    pub effect: Vec<u8>,
    pub frontier: ReplicaFrontier,
    pub scopes: Vec<BodyKey>,
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
}

impl StationCore {
    pub(crate) fn new(replica: replica::Replica) -> Self {
        Self {
            inner: std::sync::Mutex::new(CoreInner {
                replica,
                closed: false,
            }),
            obs_seq: std::sync::atomic::AtomicU64::new(0),
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
    space: mechanics::ids::SpaceId,
    world_id: WorldId,
    world: Arc<dyn World>,
    /// The docked identity: signs this Session's durable Body transactions.
    identity: crate::world::LocalIdentity,
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
        space: mechanics::ids::SpaceId,
        world_id: WorldId,
        world: Arc<dyn World>,
        identity: crate::world::LocalIdentity,
        principal: PrincipalFacts,
        epoch: StationEpoch,
        limits: WorldLimits,
        schemas: Vec<BodySchema>,
        alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
        core: Arc<StationCore>,
        authority: Arc<dyn AuthorityView>,
    ) -> Self {
        Self {
            space,
            world_id,
            world,
            identity,
            principal,
            epoch,
            limits,
            schemas,
            alive,
            core,
            authority,
        }
    }

    /// The Space this Session's Station serves.
    pub fn space_id(&self) -> &mechanics::ids::SpaceId {
        &self.space
    }

    /// Resolve fresh mechanics facts for `sign_action` — only the docked
    /// device resolves through this Session's authority view.
    pub(crate) fn resolve_for_signing(
        &self,
        device: &mechanics::ids::DeviceId,
    ) -> Option<crate::world::PrincipalResolution> {
        if device != &self.principal.device {
            return None;
        }
        self.authority.resolve(device)
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

    /// Contain a World's staged effect inside its own namespace and each
    /// staged Body's **exact schema binding** — not merely "any model the
    /// World registered". Every operation resolves a binding: an existing
    /// Body's recorded (immutable) binding, an explicit create declaration, or
    /// — for a new Body with no declaration — the intent's schema. The binding
    /// must be a registered, writable schema of this World, and the operation
    /// family must match its mutation model. Returns the per-Body bindings the
    /// commit is made under.
    fn contain_effect(
        &self,
        replica: &replica::Replica,
        effect: &WorldEffect,
        intent_schema: &SchemaId,
    ) -> Result<Vec<(BodyKey, replica::BodyBinding)>, WorldError> {
        if effect.operations.len() > replica::algebra::MAX_OPS_PER_TRANSACTION {
            return Err(WorldError::ContractViolation);
        }
        let mut bindings: Vec<(BodyKey, replica::BodyBinding)> = Vec::new();
        for (key, op) in &effect.operations {
            if key.world != self.world_id {
                return Err(WorldError::ContractViolation);
            }
            // Resolve the Body's schema binding.
            let (schema_id, version) = if let Some(existing) = replica.binding(key) {
                // Existing Body: its binding is immutable; a declaration that
                // disagrees is a violation.
                if let Some(d) = effect.declarations.iter().find(|d| &d.key == key) {
                    if d.schema != existing.schema || d.schema_version != existing.schema_version {
                        return Err(WorldError::ContractViolation);
                    }
                }
                (existing.schema.clone(), existing.schema_version)
            } else if let Some(d) = effect.declarations.iter().find(|d| &d.key == key) {
                (d.schema.clone(), d.schema_version)
            } else {
                (intent_schema.clone(), self.intent_version(intent_schema)?)
            };
            let schema = self
                .schemas
                .iter()
                .find(|s| s.id == schema_id && s.version == version)
                .ok_or(WorldError::ContractViolation)?;
            let collaborative = matches!(schema.mutation, MutationModel::Collaborative(_));
            let permitted = match op {
                BodyOp::ReplaceAtomic { .. } => !collaborative,
                BodyOp::Create => collaborative,
                BodyOp::Tombstone => true,
                _ => collaborative,
            };
            if !permitted {
                return Err(WorldError::ContractViolation);
            }
            if !bindings.iter().any(|(k, _)| k == key) {
                bindings.push((
                    key.clone(),
                    replica::BodyBinding {
                        schema: schema.id.clone(),
                        schema_version: schema.version,
                        encoding: schema.encoding.clone(),
                        mutation_model: if collaborative {
                            replica::MUTATION_COLLABORATIVE
                        } else {
                            replica::MUTATION_ATOMIC
                        },
                    },
                ));
            }
        }
        for scope in &effect.scopes {
            if scope.world != self.world_id {
                return Err(WorldError::ContractViolation);
            }
        }
        Ok(bindings)
    }

    /// The registered version of the intent schema (validated writable before
    /// the callback ran).
    fn intent_version(&self, schema: &SchemaId) -> Result<u32, WorldError> {
        self.schemas
            .iter()
            .find(|s| &s.id == schema)
            .map(|s| s.version)
            .ok_or(WorldError::ContractViolation)
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

    /// Submit a canonical signed action and **durably commit** its effect under
    /// the persistent-idempotency scope `(Space, World, Device, RequestId)`.
    ///
    /// The action is verified (canonical form, payload binding, signer
    /// self-signature) and must name this Session's Space and World; the signer
    /// must be the docked principal, re-resolved through mechanics for this
    /// request; and the header's authority frontier must still be current at
    /// commit (a change refuses with [`WorldError::AuthorityChanged`]). An
    /// identical replay returns the original [`CommittedEffect`] without
    /// reapplying any operation; reusing the request id with a different
    /// payload is [`WorldError::RequestIdConflict`]. A refused request commits
    /// nothing. The returned [`CommittedEffect`] is proof of durability: it
    /// exists only after the journaled store committed the transaction.
    pub fn submit(
        &self,
        action: crate::action::SignedWorldActionV1,
    ) -> Result<CommittedEffect, WorldError> {
        self.ensure_live()?;
        // Opaque verification first: version, algorithm, bounds, payload hash,
        // signer identity, self-signature.
        action.verify_self().map_err(|e| match e {
            crate::action::ActionError::PayloadTooLarge => WorldError::LimitExceeded,
            _ => WorldError::InvalidRequest,
        })?;
        // The action must address exactly this Session.
        if action.header.space != self.space || action.header.world != self.world_id {
            return Err(WorldError::InvalidRequest);
        }
        let intent = WorldIntent {
            schema: action.header.intent_schema.clone(),
            schema_version: action.header.intent_version,
            payload: action.payload,
        };
        self.ensure_within_limit(intent.payload.len())?;
        self.ensure_writable_schema(&intent.schema, intent.schema_version)?;
        let world = &self.world;
        let label = intent.schema.as_str().to_string();
        let intent_schema = intent.schema.clone();
        let request = action.header.request.as_bytes();
        let payload_hash = action.header.payload_hash;
        // Hold the exclusive writer across the WHOLE transaction — including
        // both authority resolutions. Authorization, the idempotency lookup,
        // the World callback, the frontier compare-and-swap, and the durable
        // commit all run inside one critical section, so any authority
        // mutation that itself serializes through this Station's writer (as
        // orbital authority mutations do — membership changes are Replica
        // commits) cannot interleave between the comparison and the commit.
        // External `AuthorityView` implementations owe the linearizable-read
        // contract documented on the trait.
        let mut inner = self.core.lock();
        if inner.closed {
            return Err(WorldError::StationDormant);
        }
        // Per-request authorization, resolved under the writer lock. The
        // signer must BE the docked principal.
        let principal = self.fresh_principal()?;
        if action.header.actor != principal.actor || action.header.device != principal.device {
            return Err(WorldError::Denied);
        }
        // Idempotency: an identical replay returns the original committed
        // result before the World runs again; a conflicting reuse is refused.
        match inner.replica.lookup_action(
            &self.space,
            &self.world_id,
            &principal.device,
            &request,
            &payload_hash,
        ) {
            Ok(None) => {}
            Ok(Some(receipt)) => {
                return Ok(CommittedEffect {
                    effect: receipt.effect,
                    frontier: receipt.frontier,
                    scopes: receipt.scopes,
                });
            }
            Err(replica::ReplicaCommitError::RequestIdConflict) => {
                return Err(WorldError::RequestIdConflict)
            }
            Err(_) => return Err(WorldError::Persistence),
        }
        // The frontier the action was signed against must still be current —
        // the same compare the commit-side CAS re-checks after the callback.
        if action.header.authority_frontier != principal.authority_frontier {
            return Err(WorldError::AuthorityChanged);
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
        // Contain the staged effect inside this World's namespace and each
        // Body's exact schema binding, resolving the bindings the commit is
        // made under.
        let bindings = self.contain_effect(&inner.replica, &effect, &intent_schema)?;
        // Authority-frontier compare-and-swap, still under the writer lock:
        // the frontier the request was authorized at must still be current at
        // commit. A change refuses the commit with AuthorityChanged and
        // commits nothing.
        let current = self
            .authority
            .resolve(&principal.device)
            .ok_or(WorldError::Denied)?;
        if current.authority_frontier != action.header.authority_frontier {
            return Err(WorldError::AuthorityChanged);
        }
        let ctx = replica::CommitContext {
            space: &self.space,
            signer: &self.identity,
            authority_frontier: action.header.authority_frontier.clone(),
        };
        let outcome = inner
            .replica
            .commit_action(
                &ctx,
                &self.world_id,
                &principal.device,
                &request,
                &payload_hash,
                effect.effect,
                effect.scopes,
                &label,
                &effect.operations,
                &bindings,
            )
            .map_err(|e| match e {
                // A staged op the engine cannot express is a World bug.
                replica::ReplicaCommitError::UnsupportedOp => WorldError::ContractViolation,
                replica::ReplicaCommitError::PathInvalid
                | replica::ReplicaCommitError::InvalidOp(_) => WorldError::InvalidRequest,
                replica::ReplicaCommitError::OpLimit => WorldError::LimitExceeded,
                replica::ReplicaCommitError::EffectTooLarge => WorldError::LimitExceeded,
                replica::ReplicaCommitError::TypeConflict => WorldError::Conflict,
                replica::ReplicaCommitError::SchemaMismatch => WorldError::ContractViolation,
                replica::ReplicaCommitError::RequestIdConflict => WorldError::RequestIdConflict,
                // Illegitimate is an incorporation-path error; a local commit
                // never produces it, but the match stays exhaustive.
                replica::ReplicaCommitError::Illegitimate(_)
                | replica::ReplicaCommitError::Fabric(_)
                | replica::ReplicaCommitError::Integrity(_)
                | replica::ReplicaCommitError::BodyKeyUnavailable
                | replica::ReplicaCommitError::Durability(_)
                | replica::ReplicaCommitError::OutcomeUnknown
                | replica::ReplicaCommitError::Poisoned => WorldError::Persistence,
            })?;
        drop(inner);
        let receipt = match outcome {
            replica::ActionOutcome::Committed(r) | replica::ActionOutcome::Replayed(r) => r,
        };
        // Count the committed change for the Observation sequence (the C3
        // stream surface publishes from this counter).
        self.core
            .obs_seq
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(CommittedEffect {
            effect: receipt.effect,
            frontier: receipt.frontier,
            scopes: receipt.scopes,
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

    /// Begin observing from a cursor. **Incomplete surface**: the bounded
    /// Observation stream (ring buffer, reset semantics, backpressure) is
    /// completion package C3 of `docs/plans/02-runtime-world-carve.md`; until
    /// it lands this echoes the input cursor and delivers nothing, and the
    /// public lifecycle is not claimed complete.
    pub fn observe(&self, cursor: ObservationCursor) -> ObservationCursor {
        cursor
    }

    /// Close this Session, consuming it. Never affects the Station.
    pub fn undock(self) {}
}
