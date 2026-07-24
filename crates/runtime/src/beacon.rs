//! Beacon v1 — a small signed lossy announcement (`lait/beacon/1`).
//!
//! A Station emits Beacons over the gossip overlay (the S4 replacement for the
//! raw gossip presence payload). A Beacon binds protocol, Space, Station, a
//! durable activation epoch, a monotonic sequence, a Replica frontier summary,
//! and sorted/deduplicated route hints, all under the emitting Station's
//! signature. Receivers persist the highest `(epoch, sequence)` per
//! `(Space, Station)`, reject lower/duplicate values, and fail closed on
//! counter overflow. Route hints never override verified transport/Station
//! identity; they are advisory and receiver-leased.

use mechanics::ids::{SpaceId, StationEpoch, StationId};
use serde::{Deserialize, Serialize};

use crate::wire::length_framed;

/// The Beacon signing domain.
pub const BEACON_DOMAIN: &[u8] = b"lait/beacon/1";
/// The only Beacon protocol version this build speaks (never negotiated).
pub const BEACON_PROTOCOL: u16 = 1;
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;
/// Maximum encoded Beacon size.
pub const MAX_BEACON: usize = 16 * 1024;
/// Maximum number of route hints.
pub const MAX_ROUTE_HINTS: usize = 8;
/// Maximum total encoded route-hint bytes.
pub const MAX_ROUTE_HINT_BYTES: usize = 1024;
/// The receiver-local lease cap for a route hint (seconds).
pub const ROUTE_HINT_LEASE_SECS: u64 = 60;
/// Beacon flag bit: the emitting Station announces planned dormancy. Signed
/// quiescence — a station that de-orbits announced, versus one presumed lost.
pub const BEACON_FLAG_DORMANT: u8 = 1;

/// A typed route hint. `scheme` names the address family/mechanism; `bytes` is
/// its scheme-specific encoding. Advisory only.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct RouteHint {
    pub scheme: u8,
    pub bytes: Vec<u8>,
}

/// The signed body of a Beacon (field order is canonical).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBody {
    pub protocol: u16,
    pub space: [u8; 29],
    pub station: [u8; 32],
    pub epoch: u64,
    pub sequence: u64,
    /// A commitment to the accepted semantic transaction DAG (a Replica frontier
    /// summary), carried opaquely at this layer.
    pub frontier_root: [u8; 32],
    pub frontier_count: u64,
    /// Signed announcement bits ([`BEACON_FLAG_DORMANT`]); unknown bits are
    /// tolerated (advisory news, never authority).
    pub flags: u8,
    pub routes: Vec<RouteHint>,
}

/// A signed Beacon. `version` is exactly 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBeacon {
    pub version: u8,
    pub body: BeaconBody,
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why a Beacon failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconError {
    /// The signed protocol field names a version this build does not speak.
    UnsupportedProtocol(u16),
    UnsupportedVersion(u8),
    UnsupportedSignatureAlgorithm(u8),
    NonCanonical,
    BadSpaceId,
    TooManyRoutes,
    RoutesTooLarge,
    UnsortedOrDuplicateRoutes,
    BadSignature,
}

impl std::fmt::Display for BeaconError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for BeaconError {}

fn space_bytes(space: &SpaceId) -> Option<[u8; 29]> {
    <[u8; 29]>::try_from(space.as_str().as_bytes()).ok()
}

impl SignedBeacon {
    fn preimage(body: &BeaconBody) -> Vec<u8> {
        let b = postcard::to_stdvec(body).expect("postcard beacon body");
        length_framed(BEACON_DOMAIN, &b)
    }

    /// Emit a signed Beacon from the emitting Station's device seed.
    #[allow(clippy::too_many_arguments)]
    pub fn emit(
        protocol: u16,
        space: &SpaceId,
        epoch: StationEpoch,
        sequence: u64,
        frontier_root: [u8; 32],
        frontier_count: u64,
        flags: u8,
        routes: Vec<RouteHint>,
        station_seed: &[u8; 32],
    ) -> Option<Self> {
        let station = mechanics::crypto::device_from_seed(station_seed).key_bytes()?;
        let body = BeaconBody {
            protocol,
            space: space_bytes(space)?,
            station,
            epoch: epoch.as_u64(),
            sequence,
            frontier_root,
            frontier_count,
            flags,
            routes,
        };
        let signature = mechanics::crypto::sign_detached(station_seed, &Self::preimage(&body));
        Some(Self {
            version: 1,
            body,
            signature_algorithm: SIG_ALG_ED25519,
            signature,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard beacon")
    }

    /// Decode canonical bytes: size-bounded, exact decode/re-encode equality.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, BeaconError> {
        if bytes.len() > MAX_BEACON {
            return Err(BeaconError::NonCanonical);
        }
        let beacon: Self = postcard::from_bytes(bytes).map_err(|_| BeaconError::NonCanonical)?;
        if beacon.encode() != bytes {
            return Err(BeaconError::NonCanonical);
        }
        Ok(beacon)
    }

    /// Verify structure + emitting-Station signature, yielding a
    /// [`VerifiedBeacon`]. This is the **only** way to obtain one, so freshness
    /// state can only ever be advanced by a beacon whose signature was checked.
    pub fn verify(&self) -> Result<VerifiedBeacon, BeaconError> {
        if self.version != 1 {
            return Err(BeaconError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(BeaconError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        if self.body.protocol != BEACON_PROTOCOL {
            return Err(BeaconError::UnsupportedProtocol(self.body.protocol));
        }
        let space = std::str::from_utf8(&self.body.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or(BeaconError::BadSpaceId)?;
        if self.body.routes.len() > MAX_ROUTE_HINTS {
            return Err(BeaconError::TooManyRoutes);
        }
        let encoded_routes: usize = self.body.routes.iter().map(|r| 1 + r.bytes.len()).sum();
        if encoded_routes > MAX_ROUTE_HINT_BYTES {
            return Err(BeaconError::RoutesTooLarge);
        }
        for w in self.body.routes.windows(2) {
            if w[0] >= w[1] {
                return Err(BeaconError::UnsortedOrDuplicateRoutes);
            }
        }
        if !mechanics::crypto::verify_detached(
            &self.body.station,
            &Self::preimage(&self.body),
            &self.signature,
        ) {
            return Err(BeaconError::BadSignature);
        }
        Ok(VerifiedBeacon {
            space,
            station: StationId::from_key_bytes(self.body.station),
            epoch: self.body.epoch,
            sequence: self.body.sequence,
            frontier_root: self.body.frontier_root,
            frontier_count: self.body.frontier_count,
            flags: self.body.flags,
            routes: self.body.routes.clone(),
        })
    }
}

/// A beacon whose signature and structure have been verified. It cannot be
/// constructed except by [`SignedBeacon::verify`], so a forged signed
/// structure can never reach freshness state (the Neighbor registry only
/// advances its high-water from a [`VerifiedBeacon`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBeacon {
    space: SpaceId,
    station: StationId,
    epoch: u64,
    sequence: u64,
    frontier_root: [u8; 32],
    frontier_count: u64,
    flags: u8,
    routes: Vec<RouteHint>,
}

impl VerifiedBeacon {
    pub fn space(&self) -> &SpaceId {
        &self.space
    }
    pub fn station(&self) -> &StationId {
        &self.station
    }
    /// The freshness coordinate `(epoch, sequence)`.
    pub fn coordinate(&self) -> (u64, u64) {
        (self.epoch, self.sequence)
    }
    /// The advertised Replica frontier summary.
    pub fn frontier(&self) -> ([u8; 32], u64) {
        (self.frontier_root, self.frontier_count)
    }
    /// The verified route hints (advisory).
    pub fn routes(&self) -> &[RouteHint] {
        &self.routes
    }
    /// Whether the emitter announced planned dormancy (signed quiescence).
    pub fn dormant(&self) -> bool {
        self.flags & BEACON_FLAG_DORMANT != 0
    }
}
