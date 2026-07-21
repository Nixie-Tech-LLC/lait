//! The orbital lifecycle handles: [`Runtime`], [`Orbit`], and [`Station`].
//!
//! Orbit and Station are the same durable relationship in mutually exclusive
//! states. [`Orbit::activate`] consumes the Orbit and returns a [`Station`];
//! [`Station::go_dormant`] consumes the Station and returns the Orbit. Runtime is
//! cloneable and owns configuration + registrations; it owns no active Space
//! state. Orbit and Station are **not** cloneable.
//!
//! S3 makes the durable footprint real: an Orbit is backed by an on-disk store
//! ([`crate::store`]) and holds the exclusive store lock (operational
//! ownership). Activation durably increments the store epoch and moves the lock
//! into the Station, which owns a cancellation token and a tracked task set.
//! Dormancy drains those tasks in a fixed order and releases the lock **last**.
//! Replica content materialization, transports, and Contact land in S5; the
//! lifecycle, lock, epoch, task drain, and Session isolation here are real.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use lait_kernel::ids::{SpaceId, StationEpoch, StationId};

use crate::error::{ContactError, DormancyError, LifecycleError, StationExit, StationExitReason};
use crate::registry::{RuntimeBuilder, WorldRegistry};
use crate::session::Session;
use crate::store::{OrbitStore, StoreLock};
use crate::world::{AuthorityView, LocalIdentity, PrincipalFacts};
use replica::ids::WorldId;
use replica::ConvergenceOutcome;

/// The authority view a Runtime without one falls back to: nobody resolves, so
/// nothing can dock. Standing exists only when the deployment supplies a real
/// mechanics view.
struct DenyAllAuthority;

impl AuthorityView for DenyAllAuthority {
    fn resolve(
        &self,
        _device: &lait_kernel::ids::DeviceId,
    ) -> Option<crate::world::PrincipalResolution> {
        None
    }
}

/// The default deadline for draining tracked tasks during dormancy.
pub const DEFAULT_DRAIN_DEADLINE: Duration = Duration::from_secs(10);

/// A cooperative cancellation signal shared by a Station and its tracked tasks.
/// A task polls [`CancelToken::is_cancelled`] and exits promptly when set. The
/// API cannot preempt a task that ignores it — such a task is drained on a
/// deadline and, if it will not stop, leaked (never holding the store lock).
#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    /// Request cancellation.
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

/// Options for forming a new Space.
#[derive(Debug, Clone, Default)]
pub struct SpaceFormationOptions {
    /// A display-name hint (committed into the Space's Coordinates in S5).
    pub display_name_hint: Option<String>,
}

/// Options for entering (materializing) an Orbit.
#[derive(Debug, Clone, Default)]
pub struct EnterOptions;

/// Options for activating an Orbit into a Station.
#[derive(Debug, Clone)]
pub struct ActivationOptions {
    /// The deadline for draining tracked tasks at dormancy.
    pub drain_deadline: Duration,
}

impl Default for ActivationOptions {
    fn default() -> Self {
        Self {
            drain_deadline: DEFAULT_DRAIN_DEADLINE,
        }
    }
}

/// Options for an administrative/test Contact. Reserved shape; S5.
#[derive(Debug, Clone, Default)]
pub struct ContactOptions;

/// An explicit, non-defaultable confirmation that a destructive deorbit is
/// intended. Constructing it names the exact Space being removed, so a stray
/// call cannot destroy the wrong Orbit.
#[derive(Debug, Clone)]
pub struct DeorbitConfirmation {
    space: SpaceId,
}

impl DeorbitConfirmation {
    /// Confirm destructive removal of a specific Space's local Orbit.
    pub fn for_space(space: SpaceId) -> Self {
        Self { space }
    }
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
}

/// The cloneable entry point. Owns configuration (the store root) and the
/// immutable World registry; owns no active Space state. Local Orbit discovery
/// is Runtime's; acquisition/activation live on the returned [`Orbit`]/
/// [`Station`].
#[derive(Clone)]
pub struct Runtime {
    registry: WorldRegistry,
    root: Option<PathBuf>,
    /// The mechanics authority view principals are derived from. Sessions and
    /// Worlds cannot replace it; only the composition root supplies it.
    authority: Arc<dyn AuthorityView>,
}

impl Runtime {
    /// Begin building a Runtime by registering Worlds.
    pub fn builder() -> RuntimeBuilder {
        RuntimeBuilder::new()
    }

    /// Wrap a frozen registry into a Runtime with **no** store root and a
    /// deny-all authority. Such a Runtime can host Worlds but cannot form or
    /// acquire a durable Orbit, and nothing can dock.
    pub fn from_registry(registry: WorldRegistry) -> Self {
        Self {
            registry,
            root: None,
            authority: Arc::new(DenyAllAuthority),
        }
    }

    /// Open a Runtime rooted at a store directory, with the mechanics authority
    /// view that principals are derived from. Orbits live under
    /// `<root>/<space-id>/`.
    pub fn open(
        root: impl Into<PathBuf>,
        registry: WorldRegistry,
        authority: Arc<dyn AuthorityView>,
    ) -> Self {
        Self {
            registry,
            root: Some(root.into()),
            authority,
        }
    }

    /// Authenticate a local caller by possession of its device seed. The device
    /// key is **derived** from the seed — an identity cannot be asserted from a
    /// bare device id, and standing is resolved by the [`AuthorityView`] at dock
    /// and again at every submit, never carried by the identity.
    pub fn identity_from_seed(seed: &[u8; 32]) -> LocalIdentity {
        LocalIdentity::from_seed(seed)
    }

    /// The immutable World registry this Runtime hosts.
    pub fn registry(&self) -> &WorldRegistry {
        &self.registry
    }

    fn root(&self) -> Result<&PathBuf, LifecycleError> {
        self.root.as_ref().ok_or(LifecycleError::NoStoreRoot)
    }

    /// Form a new Space and its founding Orbit: mint a fresh SpaceId, create the
    /// store (marker + zero epoch), and acquire the exclusive lock. The full
    /// founding proof and Coordinates minting land in S5; the durable Orbit and
    /// its lock are real here.
    pub fn form_space(&self, _options: SpaceFormationOptions) -> Result<Orbit, LifecycleError> {
        let root = self.root()?;
        let mut digest = [0u8; 16];
        getrandom::fill(&mut digest).map_err(|e| LifecycleError::StoreIo(e.to_string()))?;
        let space = SpaceId::from_digest(digest);
        let store = OrbitStore::create(root, &space)?;
        let lock = store.acquire_lock()?;
        let epoch = StationEpoch::from_u64(store.read_epoch()?);
        Ok(Orbit::new(
            store,
            self.registry.clone(),
            self.authority.clone(),
            epoch,
            lock,
        ))
    }

    /// Materialize this device's Orbit from Coordinates. The Coordinates are
    /// fully verified (version, founding self-proof, approach-Station signature,
    /// admission structure); a pre-carve `SpaceTicket` fails with
    /// [`LifecycleError::UnsupportedCoordinatesVersion`]. The store is created if
    /// absent and locked. Replica **content** import lands in S5.
    pub fn enter_orbit(
        &self,
        coordinates: &crate::coordinates::SignedCoordinatesV1,
        _options: EnterOptions,
    ) -> Result<Orbit, LifecycleError> {
        let root = self.root()?;
        let verified = coordinates.verify().map_err(|e| match e {
            crate::coordinates::CoordinatesError::UnsupportedVersion(_) => {
                LifecycleError::UnsupportedCoordinatesVersion
            }
            other => LifecycleError::IntegrityFailure(other.to_string()),
        })?;
        let store = match OrbitStore::open(root, &verified.space) {
            Ok(store) => store,
            Err(LifecycleError::OrbitNotFound(_)) => OrbitStore::create(root, &verified.space)?,
            Err(e) => return Err(e),
        };
        let lock = store.acquire_lock()?;
        let epoch = StationEpoch::from_u64(store.read_epoch()?);
        Ok(Orbit::new(
            store,
            self.registry.clone(),
            self.authority.clone(),
            epoch,
            lock,
        ))
    }

    /// Acquire an existing local Orbit for operational ownership. Revalidates the
    /// store marker/version and takes the exclusive lock (a second acquisition
    /// while a live Station holds it fails with
    /// [`LifecycleError::ReplicaLocked`]).
    pub fn orbit(&self, space: &SpaceId) -> Result<Orbit, LifecycleError> {
        let root = self.root()?;
        let store = OrbitStore::open(root, space)?;
        let lock = store.acquire_lock()?;
        let epoch = StationEpoch::from_u64(store.read_epoch()?);
        Ok(Orbit::new(
            store,
            self.registry.clone(),
            self.authority.clone(),
            epoch,
            lock,
        ))
    }

    /// Advisory, read-only observation of a local Orbit. Never takes the lock and
    /// never grants control.
    pub fn observe_orbit(&self, space: &SpaceId) -> Result<OrbitObservation, LifecycleError> {
        let root = self.root()?;
        let store = OrbitStore::open(root, space)?;
        Ok(OrbitObservation {
            space: space.clone(),
            locked: store.is_locked(),
        })
    }

    /// Advisory observation of every discoverable local Orbit.
    pub fn observe_orbits(&self) -> Vec<OrbitObservation> {
        let Ok(root) = self.root() else {
            return Vec::new();
        };
        OrbitStore::list(root)
            .into_iter()
            .filter_map(|space| self.observe_orbit(&space).ok())
            .collect()
    }
}

/// One device's durable relationship to a Space, acquired for operational
/// ownership (it holds the store lock). **Not** cloneable: [`Orbit::activate`]
/// consumes it.
pub struct Orbit {
    store: OrbitStore,
    registry: WorldRegistry,
    authority: Arc<dyn AuthorityView>,
    epoch: StationEpoch,
    lock: StoreLock,
}

impl std::fmt::Debug for Orbit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Orbit")
            .field("space", self.store.space())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Orbit {
    pub(crate) fn new(
        store: OrbitStore,
        registry: WorldRegistry,
        authority: Arc<dyn AuthorityView>,
        epoch: StationEpoch,
        lock: StoreLock,
    ) -> Self {
        Self {
            store,
            registry,
            authority,
            epoch,
            lock,
        }
    }

    /// The Space this Orbit relates to.
    pub fn space_id(&self) -> &SpaceId {
        self.store.space()
    }

    /// The current durable activation epoch.
    pub fn epoch(&self) -> StationEpoch {
        self.epoch
    }

    /// Activate this Orbit into a [`Station`], consuming it. Activation first
    /// durably increments and fsyncs the store epoch (failing closed on
    /// overflow), then transfers the store lock into the live Station. Valid
    /// offline; grants no new Space authority.
    pub fn activate(self, options: ActivationOptions) -> Result<Station, LifecycleError> {
        let epoch = StationEpoch::from_u64(self.store.bump_epoch()?);
        // Open the durable Replica at the Orbit store's journaled Fabric store:
        // crash recovery runs here (exposing the complete old or complete new
        // state), and from then on every acknowledged commit has completed the
        // full journal protocol before `submit` returns. A crash, kill, or
        // `wait` exit after an acknowledged commit loses nothing.
        let replica = replica::Replica::open_journaled(self.store.dir()).map_err(|e| match e {
            replica::ReplicaCommitError::Integrity(m) => LifecycleError::IntegrityFailure(m),
            other => LifecycleError::StoreIo(other.to_string()),
        })?;
        Ok(Station {
            store: self.store,
            registry: self.registry,
            authority: self.authority,
            epoch,
            lock: Some(self.lock),
            alive: Arc::new(AtomicBool::new(true)),
            cancel: CancelToken::new(),
            handles: Mutex::new(Vec::new()),
            drain_deadline: options.drain_deadline,
            core: Arc::new(crate::session::StationCore::new(epoch, replica)),
        })
    }

    /// Destructively remove this local Orbit, consuming it (and its lock). The
    /// confirmation must name this exact Space.
    pub fn deorbit(self, confirmation: DeorbitConfirmation) -> Result<(), LifecycleError> {
        if confirmation.space() != self.store.space() {
            return Err(LifecycleError::IntegrityFailure(
                "deorbit confirmation names a different Space".into(),
            ));
        }
        self.store.remove()?;
        // The lock file is gone with the directory; drop the guard.
        drop(self.lock);
        Ok(())
    }
}

/// An advisory, read-only snapshot of a local Orbit. Cannot activate or deorbit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OrbitObservation {
    pub space: SpaceId,
    /// Whether the Orbit's store is currently locked by an operational owner.
    pub locked: bool,
}

/// An activated Orbit: the exclusive Replica writer, live task graph, hosted
/// Worlds, docks, and shutdown. **Not** cloneable; [`Station::go_dormant`] and
/// [`Station::wait`] consume it.
pub struct Station {
    store: OrbitStore,
    registry: WorldRegistry,
    authority: Arc<dyn AuthorityView>,
    epoch: StationEpoch,
    /// The exclusive store lock. `Some` while live; taken out (and either moved
    /// into the returned Orbit or dropped) exactly once at dormancy/exit, so it
    /// is always released last.
    lock: Option<StoreLock>,
    /// Set to `false` to reject new docks and terminate Sessions.
    alive: Arc<AtomicBool>,
    /// Signals tracked tasks to stop.
    cancel: CancelToken,
    /// The one tracked task set.
    handles: Mutex<Vec<JoinHandle<()>>>,
    drain_deadline: Duration,
    /// The exclusive committing state (Replica writer + Observation sequence),
    /// shared with docked Sessions so their commits serialize through the one
    /// Replica. Sessions hold a clone but can never stop the Station.
    core: Arc<crate::session::StationCore>,
}

impl std::fmt::Debug for Station {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Station")
            .field("space", self.store.space())
            .field("epoch", &self.epoch)
            .finish_non_exhaustive()
    }
}

impl Station {
    /// This activation's epoch.
    pub fn epoch(&self) -> StationEpoch {
        self.epoch
    }

    /// The Space this Station serves.
    pub fn space_id(&self) -> &SpaceId {
        self.store.space()
    }

    /// The Station's cancellation token (for spawning tracked tasks).
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }

    /// Spawn a tracked task. The task receives the [`CancelToken`] and must exit
    /// promptly once it is cancelled. Dormancy drains every tracked task within
    /// the activation's deadline. Refused (with the closure returned) if the
    /// Station is already going dormant.
    pub fn spawn_tracked<F>(&self, f: F) -> Result<(), LifecycleError>
    where
        F: FnOnce(CancelToken) + Send + 'static,
    {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(LifecycleError::StationDormant);
        }
        let token = self.cancel.clone();
        let handle = std::thread::spawn(move || f(token));
        self.handles.lock().expect("task set").push(handle);
        Ok(())
    }

    /// Attach a local caller to a hosted World and return a [`Session`] bound to
    /// this activation epoch. The caller supplies only a [`LocalIdentity`]
    /// (possession of a device seed) — Runtime **derives** the principal facts by
    /// resolving the device through the mechanics [`AuthorityView`]; a caller
    /// cannot assert actor, standing, or authority frontier. Standing is
    /// re-resolved at every submit, so dock-time facts never outlive the
    /// authority state. Many Sessions may dock; none can stop the Station.
    /// Refused once the Station is going dormant.
    ///
    /// The `station` fact is currently the docking device viewed as a Station id
    /// (local in-process sessions); plumbing the Station's own device identity
    /// through activation arrives with the daemon integration.
    pub fn dock(
        &self,
        world_id: &WorldId,
        identity: &LocalIdentity,
    ) -> Result<Session, LifecycleError> {
        if !self.alive.load(Ordering::SeqCst) {
            return Err(LifecycleError::StationDormant);
        }
        let resolution = self
            .authority
            .resolve(identity.device())
            .ok_or(LifecycleError::PrincipalDenied)?;
        let station =
            StationId::from_device(identity.device()).ok_or(LifecycleError::PrincipalDenied)?;
        let principal = PrincipalFacts {
            actor: resolution.actor,
            device: identity.device().clone(),
            station,
            standing: resolution.standing,
            authority_frontier: resolution.authority_frontier,
        };
        let world = self
            .registry
            .world(world_id)
            .ok_or(LifecycleError::NotYetWired("unknown world at dock"))?;
        let registration = self
            .registry
            .registration(world_id)
            .ok_or(LifecycleError::NotYetWired("unknown world at dock"))?;
        Ok(Session::new(
            world_id.clone(),
            world,
            principal,
            self.epoch,
            registration.limits,
            registration.schemas.clone(),
            self.alive.clone(),
            self.core.clone(),
            self.authority.clone(),
        ))
    }

    /// The current committed Replica frontier (advances as Sessions submit).
    pub fn frontier(&self) -> replica::frontier::ReplicaFrontier {
        self.core.frontier()
    }

    /// Known/discoverable Neighbors. Reachability is advisory. Populated in S4/S5.
    pub fn neighbors(&self) -> Vec<Neighbor> {
        Vec::new()
    }

    /// An explicitly privileged administrative/test Contact. Not exposed on
    /// ordinary Session handles. Wired in S5.
    pub fn contact(
        &self,
        _neighbor: &StationId,
        _options: ContactOptions,
    ) -> Result<ContactOutcome, ContactError> {
        Err(ContactError::Unreachable)
    }

    /// Drain the tracked task set within `deadline`. Returns the join results of
    /// finished tasks and whether any task failed to finish in time.
    fn drain_tasks(&mut self, deadline: Instant) -> (bool, bool) {
        let handles = std::mem::take(&mut *self.handles.lock().expect("task set"));
        loop {
            if handles.iter().all(|h| h.is_finished()) {
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let timed_out = handles.iter().any(|h| !h.is_finished());
        let mut any_panicked = false;
        // Reap the finished tasks; never block on an unfinished (rogue) task —
        // it is leaked, and it holds no lock.
        for h in handles {
            if h.is_finished() && h.join().is_err() {
                any_panicked = true;
            }
        }
        (timed_out, any_panicked)
    }

    /// Go dormant, consuming the Station and returning the Orbit. The drain order
    /// is: reject new docks, terminate Sessions, stop scheduling, cancel and
    /// drain tracked tasks within the deadline, checkpoint, and release the store
    /// lock **last**. On a drain timeout the lock is still released and the
    /// durable Orbit remains recoverable via [`Runtime::orbit`].
    pub fn go_dormant(mut self) -> Result<Orbit, DormancyError> {
        // 1) reject new docks + terminate Sessions.
        self.alive.store(false, Ordering::SeqCst);
        // 2) stop scheduling / signal cancellation.
        self.cancel.cancel();
        // 3) cancel and drain tracked tasks within the deadline.
        let deadline = Instant::now() + self.drain_deadline;
        let (timed_out, _panicked) = self.drain_tasks(deadline);
        // 4) close the committing core under the writer mutex — an in-flight
        //    submit either completed its journaled durable commit before the
        //    close or observes it and is refused. Every acknowledged commit is
        //    already on disk (the journal protocol ran at commit time), so
        //    dormancy needs no separate checkpoint.
        self.core.close();
        // 5) build the recovered Orbit and release the lock last.
        let lock = self.lock.take().expect("station holds its lock");
        if timed_out {
            // The lock releases here; the store persists and is re-acquirable.
            drop(lock);
            return Err(DormancyError::DrainTimeout);
        }
        Ok(Orbit::new(
            self.store,
            self.registry,
            self.authority,
            self.epoch,
            lock,
        ))
    }

    /// Park until every tracked task exits, consuming the Station and returning a
    /// recoverable [`StationExit`]. A task panic is reported as the exit reason;
    /// the durable Orbit is recovered either way and the lock is released last.
    /// No commit is lost on this path: every acknowledged commit was already
    /// durably written by the per-commit sink, and the core is closed (under the
    /// writer mutex) before the Orbit is returned.
    pub fn wait(mut self) -> StationExit {
        let handles = std::mem::take(&mut *self.handles.lock().expect("task set"));
        let mut reason = None;
        for h in handles {
            if h.join().is_err() {
                reason = Some(StationExitReason::TaskFailed(
                    "a tracked task panicked".into(),
                ));
            }
        }
        self.alive.store(false, Ordering::SeqCst);
        self.core.close();
        let lock = self.lock.take().expect("station holds its lock");
        StationExit {
            orbit: Orbit::new(self.store, self.registry, self.authority, self.epoch, lock),
            reason,
        }
    }
}

/// Another known or discoverable Station. Neighbor state is keyed by verified
/// [`StationId`]; reachability is advisory and never standing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neighbor {
    pub station: StationId,
    pub reachability: Reachability,
}

/// Advisory reachability of a Neighbor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    Unknown,
    Reachable,
    Unreachable,
}

/// The outcome of a Contact: bytes moved reported **separately** from the
/// Convergence classification of the material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContactOutcome {
    pub bytes_moved: u64,
    pub convergence: ConvergenceOutcome,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU64;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("lait-runtime-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn runtime(root: &PathBuf) -> Runtime {
        // These lifecycle tests never dock, so the deny-all authority suffices.
        Runtime::open(
            root.clone(),
            RuntimeBuilder::new().build().unwrap(),
            Arc::new(DenyAllAuthority),
        )
    }

    #[test]
    fn form_drop_and_reacquire_an_existing_orbit() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        // Dropping the Orbit releases the lock.
        drop(orbit);
        // The durable Orbit is re-acquirable.
        let again = rt.orbit(&space).unwrap();
        assert_eq!(again.space_id(), &space);
    }

    #[test]
    fn observation_is_advisory_and_cannot_operate() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        let station = orbit.activate(ActivationOptions::default()).unwrap();
        // Observation sees the Orbit and reports it locked, but yields no handle
        // that can activate or deorbit (it is a plain data snapshot).
        let obs = rt.observe_orbit(&space).unwrap();
        assert_eq!(obs.space, space);
        assert!(obs.locked, "an active Station holds the lock");
        drop(station);
    }

    #[test]
    fn activation_consumes_orbit_bumps_epoch_and_dormancy_returns_it() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        assert_eq!(orbit.epoch(), StationEpoch::ZERO);

        let station = orbit.activate(ActivationOptions::default()).unwrap();
        assert_eq!(station.epoch(), StationEpoch::from_u64(1));

        let orbit = station.go_dormant().unwrap();
        assert_eq!(orbit.space_id(), &space);
        // A second activation advances the durable epoch again.
        let station = orbit.activate(ActivationOptions::default()).unwrap();
        assert_eq!(station.epoch(), StationEpoch::from_u64(2));
        drop(station);
    }

    #[test]
    fn a_second_acquisition_is_a_typed_double_lock() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        let station = orbit.activate(ActivationOptions::default()).unwrap();
        // While the Station holds the lock, a second acquisition is refused.
        assert!(matches!(
            rt.orbit(&space),
            Err(LifecycleError::ReplicaLocked(_))
        ));
        drop(station);
    }

    #[test]
    fn no_task_or_handle_retains_the_lock_after_exit() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        let station = orbit.activate(ActivationOptions::default()).unwrap();
        // A cooperative tracked task that finishes on cancellation.
        station
            .spawn_tracked(|cancel| {
                while !cancel.is_cancelled() {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .unwrap();
        let orbit = station.go_dormant().unwrap();
        drop(orbit);
        // The lock is free again.
        assert!(rt.orbit(&space).is_ok());
    }

    #[test]
    fn a_rogue_task_times_out_but_still_releases_the_lock() {
        let root = temp_root();
        let rt = runtime(&root);
        let stop = Arc::new(AtomicBool::new(false));
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        let mut opts = ActivationOptions::default();
        opts.drain_deadline = Duration::from_millis(20);
        let station = orbit.activate(opts).unwrap();
        let stop2 = stop.clone();
        // A task that ignores cancellation until we let it go.
        station
            .spawn_tracked(move |_cancel| {
                while !stop2.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
            })
            .unwrap();
        assert!(matches!(
            station.go_dormant(),
            Err(DormancyError::DrainTimeout)
        ));
        // Despite the timeout, the store lock was released and the Orbit is
        // recoverable.
        assert!(rt.orbit(&space).is_ok());
        stop.store(true, Ordering::SeqCst);
    }

    #[test]
    fn deorbit_removes_the_store() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        orbit
            .deorbit(DeorbitConfirmation::for_space(space.clone()))
            .unwrap();
        assert!(matches!(
            rt.orbit(&space),
            Err(LifecycleError::OrbitNotFound(_))
        ));
    }

    #[test]
    fn deorbit_confirmation_must_name_the_same_space() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        // A confirmation for a *different* Space is refused, and the store is
        // left intact (the confirmation binds removal to an exact Space).
        let wrong = DeorbitConfirmation::for_space(SpaceId::from_digest([0xEE; 16]));
        assert!(matches!(
            orbit.deorbit(wrong),
            Err(LifecycleError::IntegrityFailure(_))
        ));
        assert!(
            rt.orbit(&space).is_ok(),
            "store survived the refused deorbit"
        );
    }

    #[test]
    fn wait_returns_a_recoverable_orbit() {
        let root = temp_root();
        let rt = runtime(&root);
        let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
        let space = orbit.space_id().clone();
        let station = orbit.activate(ActivationOptions::default()).unwrap();
        // A task that exits on its own.
        station.spawn_tracked(|_cancel| {}).unwrap();
        let exit = station.wait();
        assert_eq!(exit.orbit.space_id(), &space);
        assert!(exit.reason.is_none());
    }

    #[test]
    fn a_runtime_without_a_root_cannot_form() {
        let rt = Runtime::from_registry(RuntimeBuilder::new().build().unwrap());
        assert!(matches!(
            rt.form_space(SpaceFormationOptions::default()),
            Err(LifecycleError::NoStoreRoot)
        ));
        assert!(rt.observe_orbits().is_empty());
    }
}
