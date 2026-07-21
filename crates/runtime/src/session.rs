//! [`Session`] — a local caller docked to a hosted World.
//!
//! A Session is bound to one World, principal, and Station activation epoch.
//! Sessions are many-to-one, independently closeable, and **cannot** stop the
//! Station. Authorization is checked per request, not only at Dock.
//!
//! The dispatch seam: `submit`/`query` **validate the request against the
//! World's registration, contain a World panic, and build a bounded**
//! [`WorldContext`](crate::world::WorldContext) over the principal before routing
//! to the World implementation. Specifically, before the World is called the
//! Session enforces: the Station is live; the payload is within
//! [`WorldLimits`](crate::world::WorldLimits); and the intent/query names a
//! schema+version the World declared (a query may also read a declared readable
//! predecessor). A panic in the callback is caught as
//! [`WorldError::WorldImplementationFailed`] and never ends the Station.
//!
//! Durable persistence of the returned [`WorldEffect`] through Replica/Fabric and
//! Observation publication are wired by the store cutover (S5): until then
//! `submit` returns the staged effect and does **not** claim durability.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;

use lait_kernel::ids::StationEpoch;
use replica::body::BodySchema;
use replica::frontier::ReplicaFrontier;
use replica::ids::{BodyKey, SchemaId, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::WorldError;
use crate::world::{
    PrincipalFacts, World, WorldContext, WorldEffect, WorldIntent, WorldLimits, WorldProjection,
    WorldQuery,
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
    ) -> Self {
        Self {
            world_id,
            world,
            principal,
            epoch,
            limits,
            schemas,
            alive,
        }
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

    /// Submit an application intent. Runtime derives the principal facts; the
    /// caller cannot assert them. The World stages Body operations; durable
    /// commit and Observation publication land in S5.
    pub fn submit(&self, intent: WorldIntent) -> Result<WorldEffect, WorldError> {
        self.ensure_live()?;
        self.ensure_within_limit(intent.payload.len())?;
        self.ensure_writable_schema(&intent.schema, intent.schema_version)?;
        let world = &self.world;
        let principal = &self.principal;
        // Contain a World panic as a typed error — it never ends the Station.
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut ctx = WorldContext::new(principal);
            world.submit(&mut ctx, intent)
        }))
        .unwrap_or(Err(WorldError::WorldImplementationFailed))
    }

    /// Query the World over the stable committed snapshot.
    pub fn query(&self, query: WorldQuery) -> Result<WorldProjection, WorldError> {
        self.ensure_live()?;
        self.ensure_within_limit(query.payload.len())?;
        self.ensure_readable_schema(&query.schema, query.schema_version)?;
        let world = &self.world;
        let principal = &self.principal;
        std::panic::catch_unwind(AssertUnwindSafe(|| {
            let ctx = WorldContext::new(principal);
            world.query(&ctx, query)
        }))
        .unwrap_or(Err(WorldError::WorldImplementationFailed))
    }

    /// Begin observing from a cursor. The streaming surface lands in S5; S0
    /// returns the reset-bearing starting Observation position.
    pub fn observe(&self, cursor: ObservationCursor) -> ObservationCursor {
        cursor
    }

    /// Close this Session, consuming it. Never affects the Station.
    pub fn undock(self) {}
}
