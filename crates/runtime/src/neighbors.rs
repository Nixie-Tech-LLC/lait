//! The persistent Neighbor registry (v1) — C2.1.
//!
//! Keyed by `(SpaceId, StationId)`: verified Beacon high-water
//! `(epoch, sequence)` persisted across restart, verified route hints with
//! receiver-local lease expiry, advisory reachability, and Orbit-local Contact
//! retry state. Reachability is advisory and never standing. The registry file
//! lives in the Orbit store directory (`neighbors`), atomically replaced on
//! every mutation; a corrupt or version-unknown file is a typed error and is
//! **never** deleted automatically.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use mechanics::ids::{SpaceId, StationId};
use serde::{Deserialize, Serialize};

use crate::beacon::VerifiedBeacon;
use crate::lifecycle::{Neighbor, Reachability};

const NEIGHBORS_FILE: &str = "neighbors";
const REGISTRY_VERSION: u8 = 1;

/// The minimum Contact retry backoff (1 second).
pub const RETRY_MIN_MS: u64 = 1_000;
/// The maximum Contact retry backoff (5 minutes).
pub const RETRY_MAX_MS: u64 = 300_000;

/// Why the registry failed to load. Corrupt state is surfaced, never deleted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryError {
    /// The registry file exists but does not decode canonically.
    CorruptRegistry,
    /// The registry names a version this build does not speak.
    UnsupportedRegistryVersion(u8),
    /// The registry belongs to a different Space.
    ForeignRegistry,
    /// An I/O failure reading or writing the registry.
    Io(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RegistryError {}

/// A verified route hint with its receiver-local lease expiry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredRoute {
    pub hint: crate::beacon::RouteHint,
    /// Receiver-local wall-clock lease expiry (ms since the unix epoch). An
    /// expired route suppresses dialing until a fresh Beacon renews it.
    pub expires_at_ms: u64,
}

/// One Neighbor's persistent record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NeighborRecord {
    pub station: StationId,
    /// Verified Beacon high-water: forward-only per Station, fails closed on
    /// u64 overflow.
    pub epoch: u64,
    pub sequence: u64,
    /// The advertised Replica frontier from the freshest verified Beacon.
    pub frontier_root: [u8; 32],
    pub frontier_count: u64,
    pub routes: Vec<StoredRoute>,
    /// Advisory reachability (never standing).
    pub reachability: u8,
    /// Orbit-local Contact retry state.
    pub failures: u32,
    /// Next Contact attempt not before (ms since the unix epoch). Persisted so
    /// a restart restores retry state instead of causing a dial storm.
    pub next_attempt_ms: u64,
    /// Whether a verified Beacon advertised a frontier we have not yet
    /// converged with (queues Contact; duplicates coalesce here).
    pub pending: bool,
}

const REACH_UNKNOWN: u8 = 0;
const REACH_REACHABLE: u8 = 1;
const REACH_UNREACHABLE: u8 = 2;

#[derive(Debug, Serialize, Deserialize)]
struct RegistryFile {
    version: u8,
    space: SpaceId,
    entries: Vec<NeighborRecord>,
}

/// The persistent registry. All mutation methods persist atomically before
/// returning.
#[derive(Debug)]
pub struct NeighborRegistry {
    path: PathBuf,
    space: SpaceId,
    entries: BTreeMap<StationId, NeighborRecord>,
}

impl NeighborRegistry {
    /// Load (or initialize empty) the registry for a Space from the Orbit
    /// store directory. Corrupt or foreign state is a typed error, untouched.
    pub fn load(store_dir: &Path, space: &SpaceId) -> Result<Self, RegistryError> {
        let path = store_dir.join(NEIGHBORS_FILE);
        let entries = match std::fs::read(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(RegistryError::Io(e.to_string())),
            Ok(bytes) => {
                let file: RegistryFile =
                    postcard::from_bytes(&bytes).map_err(|_| RegistryError::CorruptRegistry)?;
                if file.version != REGISTRY_VERSION {
                    return Err(RegistryError::UnsupportedRegistryVersion(file.version));
                }
                if &file.space != space {
                    return Err(RegistryError::ForeignRegistry);
                }
                file.entries
                    .into_iter()
                    .map(|e| (e.station.clone(), e))
                    .collect()
            }
        };
        Ok(Self {
            path,
            space: space.clone(),
            entries,
        })
    }

    fn persist(&self) -> Result<(), RegistryError> {
        let file = RegistryFile {
            version: REGISTRY_VERSION,
            space: self.space.clone(),
            entries: self.entries.values().cloned().collect(),
        };
        let bytes = postcard::to_stdvec(&file).map_err(|e| RegistryError::Io(e.to_string()))?;
        let tmp = self.path.with_extension("tmp");
        std::fs::write(&tmp, &bytes).map_err(|e| RegistryError::Io(e.to_string()))?;
        std::fs::rename(&tmp, &self.path).map_err(|e| RegistryError::Io(e.to_string()))?;
        Ok(())
    }

    /// Offer a **verified** Beacon (only [`VerifiedBeacon`] is accepted — a
    /// forged structure cannot reach this state). Forward-only per Station:
    /// stale or replayed coordinates are ignored; a fresh one updates the
    /// high-water, renews route leases, and — when the advertised frontier is
    /// not the local one — marks the Neighbor pending Contact (duplicates
    /// coalesce; a malicious repeat of the same coordinate cannot re-queue).
    pub fn observe_beacon(
        &mut self,
        beacon: &VerifiedBeacon,
        local_frontier: (&[u8; 32], u64),
        now_ms: u64,
        route_lease_ms: u64,
    ) -> Result<bool, RegistryError> {
        if beacon.space() != &self.space {
            return Ok(false);
        }
        let station = beacon.station().clone();
        let (epoch, sequence) = beacon.coordinate();
        let entry = self
            .entries
            .entry(station.clone())
            .or_insert_with(|| NeighborRecord {
                station,
                epoch: 0,
                sequence: 0,
                frontier_root: [0u8; 32],
                frontier_count: 0,
                routes: Vec::new(),
                reachability: REACH_UNKNOWN,
                failures: 0,
                next_attempt_ms: 0,
                pending: false,
            });
        // Forward-only: an old or equal coordinate is a replay, ignored. A
        // brand-new entry (0,0) accepts any coordinate.
        let fresh = (epoch, sequence) > (entry.epoch, entry.sequence)
            || (entry.epoch == 0 && entry.sequence == 0 && entry.frontier_count == 0);
        if !fresh {
            return Ok(false);
        }
        entry.epoch = epoch;
        entry.sequence = sequence;
        let (root, count) = beacon.frontier();
        entry.frontier_root = root;
        entry.frontier_count = count;
        entry.routes = beacon
            .routes()
            .iter()
            .map(|r| StoredRoute {
                hint: r.clone(),
                expires_at_ms: now_ms.saturating_add(route_lease_ms),
            })
            .collect();
        // Queue Contact only when the advertised frontier is news.
        let newsworthy = &entry.frontier_root != local_frontier.0;
        if newsworthy {
            entry.pending = true;
        }
        self.persist()?;
        Ok(newsworthy)
    }

    /// Note a Station we just accepted an inbound Contact from, so the scheduler
    /// dials it **back** to complete the bidirectional exchange (the responder
    /// side only served material; a reciprocal pull is what redeems a joiner's
    /// admission and converges the responder). Marks the entry pending with a
    /// direct, leased route toward the peer — dialing resolves by StationId, so
    /// the route only needs to be present and unexpired to pass eligibility.
    /// Never overwrites a fresher Beacon-derived frontier/coordinate.
    pub fn note_reciprocable(
        &mut self,
        station: &StationId,
        now_ms: u64,
        route_lease_ms: u64,
    ) -> Result<(), RegistryError> {
        // Gate to first-contact: arm a reciprocal dial only for a peer we have
        // not yet successfully pulled (unknown reachability). Once the reciprocal
        // exchange succeeds (`record_success` → reachable), later inbound
        // Contacts do not re-arm — so two Stations do not ping-pong forever after
        // they have converged. Steady-state reconciliation is the Beacon's job.
        if let Some(existing) = self.entries.get(station) {
            if existing.reachability != REACH_UNKNOWN {
                return Ok(());
            }
        }
        let entry = self
            .entries
            .entry(station.clone())
            .or_insert_with(|| NeighborRecord {
                station: station.clone(),
                epoch: 0,
                sequence: 0,
                frontier_root: [0u8; 32],
                frontier_count: 0,
                routes: Vec::new(),
                reachability: REACH_UNKNOWN,
                failures: 0,
                next_attempt_ms: 0,
                pending: false,
            });
        entry.pending = true;
        // A direct route toward the inbound peer (scheme 0, no address bytes):
        // the transport dials by StationId, so this only keeps eligibility open.
        let expires_at_ms = now_ms.saturating_add(route_lease_ms);
        let direct = crate::beacon::RouteHint {
            scheme: 0,
            bytes: Vec::new(),
        };
        if let Some(r) = entry.routes.iter_mut().find(|r| r.hint == direct) {
            r.expires_at_ms = r.expires_at_ms.max(expires_at_ms);
        } else {
            entry.routes.push(StoredRoute {
                hint: direct,
                expires_at_ms,
            });
        }
        self.persist()
    }

    /// The Neighbors eligible for a Contact attempt now: pending, past their
    /// backoff, and holding an unexpired route lease (route expiry suppresses
    /// dialing). Fair order: sorted by `next_attempt_ms` then StationId.
    pub fn eligible(&self, now_ms: u64) -> Vec<StationId> {
        let mut due: Vec<(&NeighborRecord, &StationId)> = self
            .entries
            .iter()
            .filter(|(_, e)| {
                e.pending
                    && e.next_attempt_ms <= now_ms
                    && e.routes.iter().any(|r| r.expires_at_ms > now_ms)
            })
            .map(|(k, e)| (e, k))
            .collect();
        due.sort_by(|a, b| {
            a.0.next_attempt_ms
                .cmp(&b.0.next_attempt_ms)
                .then_with(|| a.1.cmp(b.1))
        });
        due.into_iter().map(|(_, k)| k.clone()).collect()
    }

    /// Record a successful Contact: backoff resets, the pending mark clears,
    /// reachability turns advisory-reachable.
    pub fn record_success(
        &mut self,
        station: &StationId,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        if let Some(e) = self.entries.get_mut(station) {
            e.failures = 0;
            e.pending = false;
            e.reachability = REACH_REACHABLE;
            e.next_attempt_ms = now_ms;
            self.persist()?;
        }
        Ok(())
    }

    /// Record a failed Contact attempt: exponential backoff from 1 s to 5 min
    /// with deterministic per-Station jitter; the Neighbor stays pending.
    pub fn record_failure(
        &mut self,
        station: &StationId,
        now_ms: u64,
    ) -> Result<(), RegistryError> {
        if let Some(e) = self.entries.get_mut(station) {
            e.failures = e.failures.saturating_add(1);
            e.reachability = REACH_UNREACHABLE;
            let base = RETRY_MIN_MS.saturating_mul(1u64 << e.failures.min(16));
            let capped = base.min(RETRY_MAX_MS);
            // Deterministic jitter (±12.5%) from the station key + failures so
            // tests are reproducible and herds still spread.
            let seed = blake3::hash(
                &[
                    e.station.key_bytes().as_slice(),
                    &e.failures.to_le_bytes()[..],
                ]
                .concat(),
            );
            let jitter =
                u64::from_le_bytes(seed.as_bytes()[..8].try_into().unwrap()) % (capped / 8).max(1);
            e.next_attempt_ms = now_ms.saturating_add(capped.saturating_sub(jitter));
            self.persist()?;
        }
        Ok(())
    }

    /// Whether a Neighbor is currently marked pending.
    pub fn is_pending(&self, station: &StationId) -> bool {
        self.entries.get(station).is_some_and(|e| e.pending)
    }

    /// The persisted high-water for a Station (`None` if unknown).
    pub fn high_water(&self, station: &StationId) -> Option<(u64, u64)> {
        self.entries.get(station).map(|e| (e.epoch, e.sequence))
    }

    /// A consistent advisory snapshot for [`crate::lifecycle::Station::neighbors`].
    pub fn snapshot(&self) -> Vec<Neighbor> {
        self.entries
            .values()
            .map(|e| Neighbor {
                station: e.station.clone(),
                reachability: match e.reachability {
                    REACH_REACHABLE => Reachability::Reachable,
                    REACH_UNREACHABLE => Reachability::Unreachable,
                    _ => Reachability::Unknown,
                },
            })
            .collect()
    }

    /// The freshest route hints for a Station (unexpired only).
    pub fn routes(&self, station: &StationId, now_ms: u64) -> Vec<crate::beacon::RouteHint> {
        self.entries
            .get(station)
            .map(|e| {
                e.routes
                    .iter()
                    .filter(|r| r.expires_at_ms > now_ms)
                    .map(|r| r.hint.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::beacon::SignedBeacon;
    use mechanics::ids::StationEpoch;

    const SEED: [u8; 32] = [77u8; 32];

    fn space() -> SpaceId {
        SpaceId::from_digest([51u8; 16])
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("lait-registry-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn beacon(epoch: u64, sequence: u64, root: [u8; 32]) -> VerifiedBeacon {
        SignedBeacon::emit(
            crate::beacon::BEACON_PROTOCOL,
            &space(),
            StationEpoch::from_u64(epoch),
            sequence,
            root,
            1,
            vec![crate::beacon::RouteHint {
                scheme: 1,
                bytes: b"127.0.0.1:9000".to_vec(),
            }],
            &SEED,
        )
        .unwrap()
        .verify()
        .unwrap()
    }

    #[test]
    fn high_water_is_forward_only_and_persists_across_restart() {
        let dir = temp_dir("hw");
        let mut reg = NeighborRegistry::load(&dir, &space()).unwrap();
        let local = [0u8; 32];
        assert!(reg
            .observe_beacon(&beacon(2, 5, [9u8; 32]), (&local, 0), 1_000, 60_000)
            .unwrap());
        // A replay or stale coordinate is ignored.
        assert!(!reg
            .observe_beacon(&beacon(2, 5, [9u8; 32]), (&local, 0), 1_100, 60_000)
            .unwrap());
        assert!(!reg
            .observe_beacon(&beacon(1, 9, [9u8; 32]), (&local, 0), 1_200, 60_000)
            .unwrap());
        // Restart: the high-water survives, so the stale coordinate is STILL
        // ignored.
        drop(reg);
        let mut reg = NeighborRegistry::load(&dir, &space()).unwrap();
        let station = mechanics::crypto::device_from_seed(&SEED);
        let station = StationId::from_device(&station).unwrap();
        assert_eq!(reg.high_water(&station), Some((2, 5)));
        assert!(!reg
            .observe_beacon(&beacon(2, 4, [9u8; 32]), (&local, 0), 2_000, 60_000)
            .unwrap());
        assert!(reg
            .observe_beacon(&beacon(2, 6, [10u8; 32]), (&local, 0), 2_100, 60_000)
            .unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_known_frontier_does_not_queue_and_duplicates_coalesce() {
        let dir = temp_dir("coalesce");
        let mut reg = NeighborRegistry::load(&dir, &space()).unwrap();
        // The advertised frontier equals ours: no Contact queued.
        let ours = [9u8; 32];
        reg.observe_beacon(&beacon(1, 1, ours), (&ours, 1), 1_000, 60_000)
            .unwrap();
        assert!(reg.eligible(1_000).is_empty());
        // A new frontier queues once; repeated beacons coalesce into the same
        // pending mark rather than stacking work.
        reg.observe_beacon(&beacon(1, 2, [8u8; 32]), (&ours, 1), 1_100, 60_000)
            .unwrap();
        reg.observe_beacon(&beacon(1, 3, [8u8; 32]), (&ours, 1), 1_200, 60_000)
            .unwrap();
        assert_eq!(reg.eligible(1_300).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn backoff_grows_persists_and_route_expiry_suppresses_dialing() {
        let dir = temp_dir("backoff");
        let mut reg = NeighborRegistry::load(&dir, &space()).unwrap();
        let local = [0u8; 32];
        reg.observe_beacon(&beacon(1, 1, [7u8; 32]), (&local, 0), 1_000, 10_000)
            .unwrap();
        let station = reg.eligible(1_001)[0].clone();
        // Failures push the next attempt out (bounded by 5 minutes).
        reg.record_failure(&station, 1_001).unwrap();
        let first = reg.entries[&station].next_attempt_ms;
        assert!(first > 1_001 && first <= 1_001 + RETRY_MAX_MS);
        assert!(reg.eligible(1_002).is_empty(), "backoff suppresses");
        reg.record_failure(&station, first).unwrap();
        let second = reg.entries[&station].next_attempt_ms;
        assert!(second > first);
        // Restart restores the retry state — no dial storm.
        drop(reg);
        let mut reg = NeighborRegistry::load(&dir, &space()).unwrap();
        assert!(reg.eligible(second - 1).is_empty());
        // Route lease expiry suppresses dialing even when the backoff is due.
        assert!(
            reg.eligible(1_000 + 10_000 + RETRY_MAX_MS).is_empty(),
            "expired route lease suppresses dialing"
        );
        // A fresh beacon renews the lease and the Neighbor dials again.
        reg.observe_beacon(&beacon(1, 2, [7u8; 32]), (&local, 0), second + 1, 60_000)
            .unwrap();
        assert_eq!(reg.eligible(second + 2).len(), 1);
        // Success resets backoff and clears pending.
        reg.record_success(&station, second + 3).unwrap();
        assert!(reg.eligible(second + 4).is_empty());
        assert_eq!(reg.entries[&station].failures, 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corrupt_and_foreign_registries_are_typed_errors_never_deleted() {
        let dir = temp_dir("corrupt");
        std::fs::write(dir.join(NEIGHBORS_FILE), b"garbage").unwrap();
        assert_eq!(
            NeighborRegistry::load(&dir, &space()).unwrap_err(),
            RegistryError::CorruptRegistry
        );
        assert!(dir.join(NEIGHBORS_FILE).exists(), "never deleted");

        // An unsupported version is ITS error, not corruption.
        let file = RegistryFile {
            version: 9,
            space: space(),
            entries: vec![],
        };
        std::fs::write(
            dir.join(NEIGHBORS_FILE),
            postcard::to_stdvec(&file).unwrap(),
        )
        .unwrap();
        assert_eq!(
            NeighborRegistry::load(&dir, &space()).unwrap_err(),
            RegistryError::UnsupportedRegistryVersion(9)
        );

        // A registry for another Space is refused.
        let file = RegistryFile {
            version: REGISTRY_VERSION,
            space: SpaceId::from_digest([99u8; 16]),
            entries: vec![],
        };
        std::fs::write(
            dir.join(NEIGHBORS_FILE),
            postcard::to_stdvec(&file).unwrap(),
        )
        .unwrap();
        assert_eq!(
            NeighborRegistry::load(&dir, &space()).unwrap_err(),
            RegistryError::ForeignRegistry
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
