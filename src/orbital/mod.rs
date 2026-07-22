//! The product's adoption of the orbital lifecycle — **mechanics only**.
//!
//! It fixes where the product keeps its orbital store, composes a [`Runtime`]
//! from parts supplied by the caller, and (C5) supplies the mechanics
//! composition — authority view/source, key source, and authority
//! incorporation — over the Space's signed membership material
//! ([`mechanics::OrbitalMechanics`]).
//! It defines **no World**: per the program's settled decisions (O13/O23), no
//! consumer-specific World becomes first-party inside LAIT, and the current
//! Issues behavior adopts the public API as an *adapter over the existing
//! product semantics* — not as a new product-owned World schema. The daemon
//! integration supplies that adapter's registration when it routes the control
//! surface onto Sessions; independent Worlds are exercised by the conformance
//! and adoption tests.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use replica::BodyKeySource;
use runtime::{AuthorityView, Runtime, WorldRegistry};

/// Where the product keeps its orbital stores, under the lait home. Kept beside
/// (not inside) the existing daemon state so neither can corrupt the other.
pub fn orbital_store_root(home: &Path) -> PathBuf {
    home.join("orbital")
}

/// A typed refusal for a pre-orbital home (C5: clean break, no migration).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedStoreVersion {
    /// Where the legacy store was detected.
    pub legacy_repo: std::path::PathBuf,
    /// Human recreation guidance.
    pub guidance: String,
}

impl std::fmt::Display for UnsupportedStoreVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "unsupported store version at {}: {}",
            self.legacy_repo.display(),
            self.guidance
        )
    }
}
impl std::error::Error for UnsupportedStoreVersion {}

/// Whether `home` holds a formed/entered **orbital** Space store — a `ws_*`
/// directory under the orbital store root. The product's "is there a space
/// here?" predicate for the orbital era, alongside the legacy
/// `store::initialized_at`. Cheap (a single directory scan) and side-effect free.
pub fn is_orbital_home(home: &Path) -> bool {
    discover_space_id(home).is_some()
}

/// The single orbital Space id under `home`, if any. `None` for a non-orbital
/// home or (defensively) if more than one `ws_*` store is present.
pub fn discover_space_id(home: &Path) -> Option<crate::ids::SpaceId> {
    let root = orbital_store_root(home);
    let mut found = None;
    for entry in std::fs::read_dir(&root).ok()?.flatten() {
        if !entry.path().is_dir() {
            continue;
        }
        if let Some(space) = entry
            .file_name()
            .to_str()
            .filter(|n| n.starts_with("ws_"))
            .and_then(crate::ids::SpaceId::parse)
        {
            if found.replace(space).is_some() {
                return None;
            }
        }
    }
    found
}

/// Detect a pre-orbital (v0.x) space store under `home`. The orbital
/// composition root must NEVER create a fresh Orbit beside or over one.
pub fn detect_legacy_home(home: &Path) -> Option<UnsupportedStoreVersion> {
    let repo = home.join("repo");
    let legacy = repo.join("genesis.json").exists()
        || repo.join("catalog.loro").exists()
        || repo.join("membership.loro").exists();
    legacy.then(|| UnsupportedStoreVersion {
        legacy_repo: repo,
        guidance: "this home holds a pre-orbital space store; the orbital                    formats are a clean break with no migration. Export what                    you need with a v0.x binary, then remove the old store                    (or choose a fresh home) and re-create the space."
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" "),
    })
}

/// Compose the product's orbital [`Runtime`]: the store root convention plus a
/// caller-supplied World registry, mechanics authority view, and mechanics-
/// owned Body key source. The product holds no privileged path — this is the
/// same `Runtime::open` any consumer calls, at the product's store location.
/// Refuses (typed, with recreation guidance) when `home` holds a pre-orbital
/// store: a fresh Orbit is never created beside or over a legacy home.
pub fn open_orbital_runtime(
    home: &Path,
    registry: WorldRegistry,
    authority: Arc<dyn AuthorityView>,
    keys: Arc<dyn BodyKeySource>,
) -> Result<Runtime, UnsupportedStoreVersion> {
    if let Some(err) = detect_legacy_home(home) {
        return Err(err);
    }
    Ok(Runtime::open(
        orbital_store_root(home),
        registry,
        authority,
        keys,
    ))
}

pub mod ceremony;
pub mod daemon;
pub mod mechanics;

pub use daemon::{run_orbital_daemon, run_orbital_daemon_with, OrbitalDaemon};
pub use mechanics::{AuthorityRecord, OrbitalMechanics};

use crate::world::IssuesWorld;
use anyhow::Result;
use runtime::{ActivationOptions, EnterOptions, RuntimeBuilder, SpaceFormationOptions};

/// The issues Runtime registry the product hosts (one [`IssuesWorld`]).
fn issues_registry() -> Result<WorldRegistry> {
    RuntimeBuilder::new()
        .register(IssuesWorld::registration(), Arc::new(IssuesWorld::new()))
        .build()
        .map_err(|e| anyhow::anyhow!("world registry: {e:?}"))
}

/// The reviewed IssuesWorld implementation id this build ships — the authority
/// identity the founder activates and every product transaction pins.
pub fn issues_implementation_id() -> [u8; 32] {
    IssuesWorld::implementation_descriptor()
        .id()
        .expect("canonical IssuesWorld descriptor")
}

/// The founder product-authority bootstrap: activate the IssuesWorld
/// implementation and grant the founder the Space capabilities. Idempotent —
/// an exact replay changes nothing (both the activation and each grant are
/// idempotent through the authority ledger). Public so a caller forming a
/// Space directly through [`OrbitalMechanics::form`] can run the same
/// deterministic bootstrap the CLI composition root does.
pub fn seed_founder_policy(mechanics: &OrbitalMechanics) -> Result<()> {
    mechanics.activate_implementation(
        crate::world::contract::PRODUCT_WORLD,
        issues_implementation_id(),
    )?;
    for (i, (capability, resource)) in crate::world::contract::founder_capabilities()
        .into_iter()
        .enumerate()
    {
        mechanics.grant_self_capability(capability, resource, [i as u8; 16])?;
    }
    Ok(())
}

/// Found a fresh Space's full orbital footprint under `home` — the `lait init`
/// heir. Mints the mechanics material ([`OrbitalMechanics::form`]: genesis,
/// founding inception, epoch-0), then materializes the Runtime Orbit store
/// (marker, epoch, journaled Fabric store) at the SAME mechanics-derived Space
/// by entering the founder's own Coordinates, and seeds the catalog Body.
/// Returns the mechanics handle and the founder-signed Coordinates.
pub fn form_space(
    home: &Path,
    device_seed: &[u8; 32],
    display_name: &str,
) -> Result<(OrbitalMechanics, runtime::SignedCoordinatesV1)> {
    if let Some(err) = detect_legacy_home(home) {
        return Err(anyhow::anyhow!("{err}"));
    }
    let root = orbital_store_root(home);
    let (mechanics, coords) = OrbitalMechanics::form(&root, device_seed, display_name, vec![])?;
    // The LAIT composition root's product-authority bootstrap: activate the
    // reviewed IssuesWorld implementation id and grant the founder the Space
    // capabilities its own submits require, as one deterministic idempotent
    // step under the founder's genesis policy-admin standing. This precedes any
    // product submit, so the founder's SpaceInit/ProjectNew are authorized.
    seed_founder_policy(&mechanics)?;
    // Materialize the Runtime Orbit store at the mechanics Space by entering
    // the founder's own Coordinates (creates the store if absent), then seed
    // the catalog Body so the space is usable immediately.
    let rt = Runtime::open(
        root,
        issues_registry()?,
        Arc::new(mechanics.clone()),
        Arc::new(mechanics.clone()),
    );
    let orbit = rt
        .enter_orbit(&coords, EnterOptions)
        .map_err(|e| anyhow::anyhow!("materialize orbit: {e:?}"))?;
    let station = orbit
        .activate(ActivationOptions::offline())
        .map_err(|e| anyhow::anyhow!("activate: {e:?}"))?;
    let identity = Runtime::identity_from_seed(device_seed);
    let session = station
        .dock(&crate::world::contract::world_id(), &identity)
        .map_err(|e| anyhow::anyhow!("dock: {e:?}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let action = identity
        .sign_action(
            &session,
            runtime::RequestId::mint(),
            runtime::WorldIntent {
                schema: crate::world::contract::issue_schema(),
                schema_version: crate::world::contract::ISSUE_SCHEMA_VERSION,
                payload: crate::world::contract::IssueIntent::SpaceInit {
                    name: display_name.to_string(),
                    ts: now,
                }
                .to_json(),
            },
        )
        .map_err(|e| anyhow::anyhow!("sign space-init: {e:?}"))?;
    session
        .submit(action)
        .map_err(|e| anyhow::anyhow!("space-init: {e:?}"))?;
    let _ = station.go_dormant();
    let _ = SpaceFormationOptions::default(); // keep the type referenced
    Ok((mechanics, coords))
}

/// The `lait init` heir with first-run UX parity: [`form_space`] plus a seeded
/// default project (named after the space, key derived) so `lait new` works on
/// the very next command — the founder never faces an empty, project-less space.
/// Returns the founded Space id and the default project's brief.
pub fn found_space_cli(
    home: &Path,
    device_seed: &[u8; 32],
    display_name: &str,
) -> Result<(crate::ids::SpaceId, crate::spaces::ProjectBrief)> {
    let (mechanics, _coords) = form_space(home, device_seed, display_name)?;
    let space = mechanics.space();

    // Re-open the now-materialized Orbit offline and file the default project.
    let rt = Runtime::open(
        orbital_store_root(home),
        issues_registry()?,
        Arc::new(mechanics.clone()),
        Arc::new(mechanics.clone()),
    );
    let station = rt
        .orbit(&space)
        .map_err(|e| anyhow::anyhow!("acquire orbit: {e:?}"))?
        .activate(runtime::ActivationOptions::offline())
        .map_err(|e| anyhow::anyhow!("activate: {e:?}"))?;
    let identity = Runtime::identity_from_seed(device_seed);
    let session = station
        .dock(&crate::world::contract::world_id(), &identity)
        .map_err(|e| anyhow::anyhow!("dock: {e:?}"))?;

    let project_name = if display_name.trim().is_empty() {
        "Main".to_string()
    } else {
        display_name.trim().to_string()
    };
    let project_key = crate::replica::derive_project_key(&project_name);
    let project_id = crate::ids::ProjectId::mint(&crate::ids::SystemUlidSource)
        .as_str()
        .to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let action = identity
        .sign_action(
            &session,
            runtime::RequestId::mint(),
            runtime::WorldIntent {
                schema: crate::world::contract::issue_schema(),
                schema_version: crate::world::contract::ISSUE_SCHEMA_VERSION,
                payload: crate::world::contract::IssueIntent::ProjectNew {
                    id: project_id,
                    name: project_name.clone(),
                    key: project_key.clone(),
                    device: crate::crypto::device_from_seed(device_seed)
                        .as_str()
                        .to_string(),
                    ts: now,
                }
                .to_json(),
            },
        )
        .map_err(|e| anyhow::anyhow!("sign project-new: {e:?}"))?;
    session
        .submit(action)
        .map_err(|e| anyhow::anyhow!("project-new: {e:?}"))?;
    let _ = station.go_dormant();

    Ok((
        space,
        crate::spaces::ProjectBrief {
            key: project_key,
            name: project_name,
        },
    ))
}

/// Bootstrap a joiner's full orbital footprint under `home` from an invite
/// link — the `lait join` store heir. Parses the founder-signed Coordinates,
/// mints the joiner's mechanics store ([`OrbitalMechanics::enter`]: genesis
/// adoption, self-inception held pending, admission stashed), then materializes
/// the Runtime Orbit store at the SAME Space by entering those Coordinates.
/// Returns the mechanics handle and the entered Space id. Admission itself is
/// redeemed later, over Contact, once the daemon is serving.
pub fn enter_space(
    home: &Path,
    device_seed: &[u8; 32],
    invite_link: &str,
) -> Result<(OrbitalMechanics, runtime::SignedCoordinatesV1)> {
    if let Some(err) = detect_legacy_home(home) {
        return Err(anyhow::anyhow!("{err}"));
    }
    let coords = runtime::SignedCoordinatesV1::parse_link(invite_link.trim())
        .map_err(|e| anyhow::anyhow!("invalid invite link: {e}"))?;
    let root = orbital_store_root(home);
    let mechanics = OrbitalMechanics::enter(&root, device_seed, &coords)?;
    // Materialize the Runtime Orbit store at the entered Space so the daemon can
    // acquire the Orbit and drive Contact/admission.
    let rt = Runtime::open(
        root,
        issues_registry()?,
        Arc::new(mechanics.clone()),
        Arc::new(mechanics.clone()),
    );
    rt.enter_orbit(&coords, EnterOptions)
        .map_err(|e| anyhow::anyhow!("materialize orbit: {e:?}"))?;
    Ok((mechanics, coords))
}

/// A random 16-byte value (salts, epoch ids, nonces).
pub(crate) fn rand16() -> [u8; 16] {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("getrandom");
    raw
}
