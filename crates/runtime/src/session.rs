//! [`Session`] — a local caller docked to a hosted World.
//!
//! A Session is bound to one World, principal, and Station activation epoch.
//! Sessions are many-to-one, independently closeable, and **cannot** stop the
//! Station. Authorization is checked per request, not only at Dock.
//!
//! S0 wires the dispatch seam: `submit`/`query` build a bounded
//! [`WorldContext`](crate::world::WorldContext) over the principal and route to
//! the World implementation. Durable persistence, the committed-snapshot read
//! surface, and Observation publication land in S5; S0 returns the World's own
//! result without persisting, so this seam is the contract S1 dispatch builds on.

use std::sync::Arc;

use lait_kernel::ids::StationEpoch;
use replica::frontier::ReplicaFrontier;
use replica::ids::{BodyKey, WorldId};
use serde::{Deserialize, Serialize};

use crate::error::WorldError;
use crate::world::{
    PrincipalFacts, World, WorldContext, WorldEffect, WorldIntent, WorldProjection, WorldQuery,
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
    /// A shared flag: `false` once the Station is going dormant or has exited.
    /// A Session only *reads* it — it can never stop the Station.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Session {
    pub(crate) fn new(
        world_id: WorldId,
        world: Arc<dyn World>,
        principal: PrincipalFacts,
        epoch: StationEpoch,
        alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            world_id,
            world,
            principal,
            epoch,
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
        let mut ctx = WorldContext::new(&self.principal);
        self.world.submit(&mut ctx, intent)
    }

    /// Query the World over the stable committed snapshot.
    pub fn query(&self, query: WorldQuery) -> Result<WorldProjection, WorldError> {
        self.ensure_live()?;
        let ctx = WorldContext::new(&self.principal);
        self.world.query(&ctx, query)
    }

    /// Begin observing from a cursor. The streaming surface lands in S5; S0
    /// returns the reset-bearing starting Observation position.
    pub fn observe(&self, cursor: ObservationCursor) -> ObservationCursor {
        cursor
    }

    /// Close this Session, consuming it. Never affects the Station.
    pub fn undock(self) {}
}
