//! The orbital daemon (C5 step 5) — the product's control surface served over
//! the orbital `Runtime`, replacing the legacy `Replica`/sync/gossip node.
//!
//! It composes [`OrbitalMechanics`] (authority/keys/membership over signed
//! material), an issues [`Runtime`] hosting [`IssuesWorld`], and a [`Station`]
//! with the comms Contact plane, then serves the **same** newline-delimited
//! `control::Request`/`Response` IPC the CLI/serve/MCP speak — so those clients
//! are unchanged. Application requests route through [`IssueRouter`] Sessions;
//! peer exchange is Contact/Convergence over `comms`; invitation is Coordinates
//! v1; `Subscribe` streams the Station's `ObservationStream` as `Doorbell`
//! frames.
//!
//! Every control request has an explicit terminal owner (see
//! `tests/control_classification.rs`): product intents/queries route to the
//! World Session; membership, admission, device, key and the FROST
//! recovery/elevation/custody ceremonies are served by [`OrbitalMechanics`]
//! over the mechanics primitives; seeds, diagnose, inbox and log are node-local
//! lifecycle concerns. There is no catch-all refusal.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream as LocalStream},
    ListenerOptions,
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use mechanics::ids::{SpaceId, StationId};
use replica::AuthorityIncorporator;
use runtime::{
    ActivationOptions, CommsOptions, ContactMechanics, ContactOptions, GossipOptions,
    LocalIdentity, Runtime, RuntimeBuilder, Session, Station,
};

use crate::config::{acquire_daemon_lock, load_or_create_identity};
use crate::control::{control_name, Doorbell, Request, Response, StatusInfo};
use crate::ids::SystemUlidSource;
use crate::orbital::{orbital_store_root, unsupported_store_at, OrbitalMechanics};
use crate::transport::{Transport, TransportFactory};
use crate::world::{IssueRouter, IssuesWorld, RouterFacts};

/// Discover the single Space id under a home's orbital store root.
fn discover_space(home: &Path) -> Result<SpaceId> {
    let root = orbital_store_root(home);
    let mut found = None;
    for entry in std::fs::read_dir(&root)
        .with_context(|| format!("no orbital store at {} — run `lait init`", root.display()))?
        .flatten()
    {
        if let Some(name) = entry.file_name().to_str() {
            if name.starts_with("ws_") {
                if let Some(space) = SpaceId::parse(name) {
                    if found.replace(space).is_some() {
                        return Err(anyhow!("more than one Space under {}", root.display()));
                    }
                }
            }
        }
    }
    found.ok_or_else(|| anyhow!("no Space under {} — run `lait init`", root.display()))
}

/// The orbital daemon: the composed stack plus a lazily-docked routing Session.
pub struct OrbitalDaemon {
    mechanics: OrbitalMechanics,
    station: Station,
    /// The canonical [`ApproachRoute`]s this Station advertises, resolved from
    /// the retained transport handle at activation (an Isolated endpoint's own
    /// bound direct addresses) — the composition root's route source, kept
    /// beside the Station (which never exposes its own transport). Invite
    /// creation signs exactly these into Coordinates.
    advertised_routes: Vec<runtime::coordinates::ApproachRoute>,
    /// A retained transport handle (the Station never exposes its own): lets
    /// the manual `connect` nudge teach routes from a pasted Coordinates link
    /// before dialing.
    transport: Arc<dyn Transport>,
    /// The routing Session. `None` until this device holds standing — an
    /// un-admitted joiner serves control (Status/Connect/Members) and drives
    /// Contact before it can dock, then docks lazily once admission lands.
    session: Mutex<Option<Session>>,
    identity: LocalIdentity,
    device_seed: [u8; 32],
    home: PathBuf,
    /// Signalled by a `Stop` request so `serve` returns (the injectable
    /// contract: return, don't `exit`).
    shutdown: Arc<tokio::sync::Notify>,
    /// Latched when teardown begins (Stop or idle-shutdown). Subscription
    /// worker threads check it between bounded waits; the async side watches
    /// [`Self::stop_tx`] for the prompt wakeup.
    stopping: std::sync::atomic::AtomicBool,
    /// The teardown broadcast: `true` once Stop/idle-shutdown latched. Every
    /// live `Subscribe` connection selects on this, so teardown is prompt and
    /// bounded instead of waiting out a poll interval per subscriber.
    stop_tx: tokio::sync::watch::Sender<bool>,
    /// Control connections currently being served (idle-shutdown suppressor).
    active_conns: std::sync::atomic::AtomicU64,
    /// When the last control connection was accepted or completed — the idle
    /// clock's reference point.
    last_activity: Mutex<std::time::Instant>,
}

impl OrbitalDaemon {
    /// Open and activate the orbital stack for a home, then dock the routing
    /// Session. Refuses a pre-orbital home.
    pub async fn open(
        home: &Path,
        device_seed: [u8; 32],
        factory: &dyn TransportFactory,
    ) -> Result<Self> {
        if let Some(err) = unsupported_store_at(home) {
            return Err(anyhow!("{err}"));
        }
        let space = discover_space(home)?;
        let mechanics = OrbitalMechanics::open(&orbital_store_root(home), &space, &device_seed)?;

        let registry = RuntimeBuilder::new()
            .register(IssuesWorld::registration(), Arc::new(IssuesWorld::new()))
            .build()
            .map_err(|e| anyhow!("world registry: {e:?}"))?;
        let rt = Runtime::open(
            orbital_store_root(home),
            registry,
            Arc::new(mechanics.clone()),
            Arc::new(mechanics.clone()),
        );

        let network = crate::net::Network::from_env()?;
        let transport = factory
            .build(
                &device_seed,
                &network,
                &[runtime::contact::CONTACT_ALPN, runtime::PRESENCE_ALPN],
            )
            .await?;
        // Retain a transport clone for invite route advertisement (and the
        // manual `connect` nudge) before the Station consumes one into its
        // Comms.
        let retained_transport = transport.clone();
        // Resolve the routes this Station will advertise — in invites AND in
        // its Beacons: the transport's currently-dialable direct addresses
        // (bounded wait for a fresh iroh endpoint), canonicalized. A
        // relay/discovery transport returns none — its invites are
        // address-free (bare ids resolve).
        let advertised_addrs = retained_transport
            .advertised_routes(Duration::from_secs(3))
            .await
            .unwrap_or_default();
        let advertised_routes = runtime::coordinates::canonical_routes(&advertised_addrs);
        // W0-S1: the gossip bootstrap union — pinned seeds, the verified
        // invite ticket's approach Station, and persisted Neighbor registry
        // entries holding an unexpired route lease. Identities only; the
        // eclipse fence governs everything learned after this.
        let my_id = retained_transport.my_id();
        let mut bootstrap: Vec<crate::ids::DeviceId> =
            load_seeds(home).into_iter().map(|s| s.id).collect();
        // The ticket's approach Station: teach the transport its signed direct
        // routes so the first dial resolves (Coordinates-only, no shared
        // registry), and bootstrap the swarm from it.
        if let Some(coords) = mechanics.pending_coordinates() {
            if let Ok(verified) = coords.verify() {
                if !verified.approach_routes.is_empty() {
                    // PeerId is a DeviceId — the approach Station's key is
                    // its dialable peer id.
                    retained_transport
                        .learn(verified.approach_station.clone(), &verified.approach_routes);
                }
                bootstrap.push(verified.approach_station.clone());
            }
        }
        // Persisted Neighbors with live route leases (S1(c)): dead-hub
        // recovery — surviving peers keep finding each other without the
        // approach Station.
        if let Ok(registry) =
            runtime::NeighborRegistry::load(&orbital_store_root(home).join(space.as_str()), &space)
        {
            for (station, routes) in registry.bootstrap_candidates(now_secs() * 1_000) {
                let device = station.as_device();
                let addrs: Vec<std::net::SocketAddr> = routes
                    .iter()
                    .filter(|h| h.scheme == 1)
                    .filter_map(|h| {
                        std::str::from_utf8(&h.bytes)
                            .ok()
                            .and_then(|t| t.parse().ok())
                    })
                    .collect();
                if !addrs.is_empty() {
                    retained_transport.learn(device.clone(), &addrs);
                }
                bootstrap.push(device);
            }
        }
        bootstrap.sort();
        bootstrap.dedup();
        bootstrap.retain(|p| p != &my_id);
        // The Beacon advertisement (scheme 1: UTF-8 socket address) — the same
        // routes invites carry, in route-hint form, canonically sorted.
        let mut advertise: Vec<runtime::beacon::RouteHint> = advertised_routes
            .iter()
            .map(|r| runtime::beacon::RouteHint {
                scheme: 1,
                bytes: r.to_socket().to_string().into_bytes(),
            })
            .collect();
        advertise.sort();
        advertise.dedup();
        advertise.truncate(runtime::beacon::MAX_ROUTE_HINTS);
        let station = rt
            .orbit(&space)
            .map_err(|e| anyhow!("acquire orbit: {e:?}"))?
            .activate(ActivationOptions {
                drain_deadline: Duration::from_secs(5),
                comms: Some(comms_options(
                    transport,
                    device_seed,
                    &mechanics,
                    bootstrap,
                    advertise,
                )),
                observation_capacity: 0,
            })
            .map_err(|e| anyhow!("activate: {e:?}"))?;
        let identity = Runtime::identity_from_seed(&device_seed);
        // Dock now if we already hold standing (founder / re-opened member);
        // otherwise defer until admission lands (an un-admitted joiner cannot
        // dock, but must still serve control to drive its own Contact).
        let session = station
            .dock(&crate::world::contract::world_id(), &identity)
            .ok();

        // The implementation self-check. Receipts pin whichever implementation
        // id is ACTIVE in the ledger — not this build's — so a build whose
        // descriptor has moved on would silently attest an implementation it
        // is not. Say so at open; `lait world-upgrade` (admin) activates this
        // build's id.
        {
            use runtime::AuthorityView;
            let device = crate::crypto::device_from_seed(&device_seed);
            if let Some(principal) = mechanics.resolve(&device) {
                let ours = crate::orbital::issues_implementation_id();
                let active = mechanics.active_implementation(
                    &crate::world::contract::world_id(),
                    &principal.authority_frontier,
                );
                if active != Some(ours) {
                    tracing::warn!(
                        "this build's IssuesWorld implementation ({}) is not the space's \
                         active one ({}) — writes will attest the active implementation; \
                         an admin should run `lait world-upgrade`",
                        data_encoding::HEXLOWER.encode(&ours[..8]),
                        active
                            .map(|a| data_encoding::HEXLOWER.encode(&a[..8]))
                            .unwrap_or_else(|| "none".into()),
                    );
                }
            }
        }

        Ok(Self {
            mechanics,
            station,
            advertised_routes,
            transport: retained_transport,
            session: Mutex::new(session),
            identity,
            device_seed,
            home: home.to_path_buf(),
            shutdown: Arc::new(tokio::sync::Notify::new()),
            stopping: std::sync::atomic::AtomicBool::new(false),
            stop_tx: tokio::sync::watch::channel(false).0,
            active_conns: std::sync::atomic::AtomicU64::new(0),
            last_activity: Mutex::new(std::time::Instant::now()),
        })
    }

    /// Ensure a routing Session exists, docking lazily once standing is held.
    /// Returns whether a Session is available after the attempt.
    fn ensure_session(&self) -> bool {
        let mut guard = self.session.lock().expect("session lock");
        if guard.is_none() && self.mechanics.am_i_member() {
            *guard = self
                .station
                .dock(&crate::world::contract::world_id(), &self.identity)
                .ok();
        }
        guard.is_some()
    }

    /// Route an issue-family request through the docked Session, or refuse with a
    /// typed "not admitted yet" when this device holds no standing.
    fn route_issue(&self, req: Request) -> Response {
        if !self.ensure_session() {
            return Response::err(
                "not admitted to this space yet — run `lait connect` to reach an \
                 admin and complete admission before filing issues",
            );
        }
        let guard = self.session.lock().expect("session lock");
        let session = guard.as_ref().expect("session present after ensure");
        let router = IssueRouter::new(
            session,
            &self.identity,
            CLOCK.get_or_init(|| SystemUlidSource),
        );
        // A background Contact can advance the authority frontier between a
        // submit's resolve and its commit; that typed refusal committed
        // nothing and is safe to retry. Absorb the transient here so the
        // ambient convergence plane never turns a user's write into an error.
        let mut resp = router.route(req.clone(), &self.facts()).0;
        for _ in 0..3 {
            match &resp {
                Response::Error { message, .. } if message == "membership changed — retry" => {
                    std::thread::sleep(std::time::Duration::from_millis(15));
                    resp = router.route(req.clone(), &self.facts()).0;
                }
                _ => break,
            }
        }
        resp
    }

    fn facts(&self) -> RouterFacts {
        use runtime::AuthorityView;
        let device = crate::crypto::device_from_seed(&self.device_seed);
        let actor = self
            .mechanics
            .resolve(&device)
            .map(|r| r.actor.as_str().to_string())
            .unwrap_or_default();
        RouterFacts {
            device: device.as_str().to_string(),
            actor,
            project_hint: std::env::var("LAIT_PROJECT_HINT").ok(),
            default_project: None,
            now: now_secs(),
        }
    }

    /// Route one control request to its terminal owner — the value the
    /// PRODUCTION classifier returns. Tests and the generated routing table
    /// consume the same `control::classify`; there is no second table and no
    /// wildcard terminal owner.
    fn dispatch(&self, req: Request) -> Response {
        use crate::control::{classify, RequestOwner};
        match classify(&req) {
            RequestOwner::Session => self.route_issue(req),
            RequestOwner::Mechanics => self.dispatch_mechanics(req),
            RequestOwner::Station => self.dispatch_station(req),
            RequestOwner::Observation => self.dispatch_observation(req),
            RequestOwner::Lifecycle => self.dispatch_lifecycle(req),
        }
    }

    /// Membership, admission, device, key, ceremony and custody requests —
    /// served by [`OrbitalMechanics`] over the mechanics primitives.
    fn dispatch_mechanics(&self, req: Request) -> Response {
        match req {
            Request::Members => self.members(),
            Request::MemberAdd { who, admin, .. } => match self.mechanics.member_add(&who, admin) {
                Ok(()) => Response::Ok {
                    message: Some(format!("added {who}")),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::MemberRemove { who } => match self.mechanics.member_remove(&who) {
                Ok(()) => Response::Ok {
                    message: Some(format!("removed {who}")),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::MemberSetRole { who, admin } => {
                match self.mechanics.member_set_role(&who, admin) {
                    Ok(actor) => Response::Ok {
                        message: Some(if admin {
                            format!("promoted {} to admin", actor.short())
                        } else {
                            format!("{} is now a plain member", actor.short())
                        }),
                    },
                    Err(e) => Response::err(format!("{e}")),
                }
            }
            Request::MemberLog => Response::MemberLog {
                entries: self.mechanics.member_log(),
            },
            Request::DeviceInvite => match self.mechanics.device_invite() {
                Ok((actor, space)) => Response::Text {
                    text: format!("{actor} {space}"),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::DeviceAdd { consent } => self.device_add(&consent),
            Request::DeviceRevoke { device } => match self.mechanics.device_revoke(&device) {
                Ok(true) => Response::Ok {
                    message: Some(format!("revoked device {device} and rotated the key")),
                },
                Ok(false) => Response::Ok {
                    message: Some(format!(
                        "revoked device {device} from your identity — ask an admin to \
                         rotate the space key to fence its access to existing content"
                    )),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::DeviceList => Response::Text {
                text: self.device_list_text(),
            },
            Request::Recover => match self.mechanics.recover() {
                Ok(actor) => Response::Ok {
                    message: Some(format!(
                        "recovered actor {} — device set reset to this device; content \
                         access re-seals once a peer syncs",
                        actor.short()
                    )),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::KeyRotate => match self.mechanics.key_rotate() {
                Ok(gen) => Response::Ok {
                    message: Some(format!("rotated the space key to generation {gen}")),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::InviteRevoke { invite } => match self.mechanics.invite_revoke(&invite) {
                Ok(already_spent) => Response::Ok {
                    message: Some(if already_spent {
                        "revoked the invite — note it had already admitted at least one member; \
                         revocation stops further admissions but does not remove them"
                            .to_string()
                    } else {
                        "revoked the invite — it can no longer admit anyone".to_string()
                    }),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::AgentAdd { key } => match self.mechanics.agent_add(&key) {
                Ok(actor) => Response::Ok {
                    message: Some(format!("sponsored agent {}", actor.short())),
                },
                Err(e) => Response::err(format!("{e}")),
            },
            Request::WorldUpgrade => {
                let ours = crate::orbital::issues_implementation_id();
                match self
                    .mechanics
                    .activate_implementation(crate::world::contract::PRODUCT_WORLD, ours)
                {
                    Ok(()) => Response::Ok {
                        message: Some(format!(
                            "implementation {} is active for {} (no-op if it already was)",
                            data_encoding::HEXLOWER.encode(&ours[..8]),
                            crate::world::contract::PRODUCT_WORLD,
                        )),
                    },
                    Err(e) => Response::err(format!("{e}")),
                }
            }
            Request::Id => {
                // First line: the device id (the stable, parseable form).
                // Second line, when the actor plane resolves this device (a
                // pending joiner's inception counts): the actor id — the
                // handle admission and role verbs take (GOV-11).
                let device = crate::crypto::device_from_seed(&self.device_seed).to_string();
                Response::Ok {
                    message: Some(match self.mechanics.my_actor() {
                        Some(actor) => format!("{device}\nactor {}", actor.as_str()),
                        None => device,
                    }),
                }
            }
            Request::Invite {
                role,
                reusable,
                ttl_hours,
            } => self.invite(role.as_deref(), reusable, ttl_hours),
            Request::Join { ticket } => self.connect(&ticket),
            Request::SpaceRecover => self.space_recover(),
            Request::SpaceRecoverApprove { session, expect } => {
                self.space_recover_approve(session, expect)
            }
            Request::SpaceElevate { cofounders, k } => self.space_elevate(cofounders, k),
            Request::SpaceElevateApprove { session, proposal } => {
                self.space_elevate_approve(session, proposal)
            }
            Request::SpaceReshare { participants, k } => self.space_reshare(participants, k),
            Request::SpaceCustodyExport { path, passphrase } => {
                self.space_custody_export(path, passphrase)
            }
            Request::SpaceCustodyImport {
                path,
                passphrase,
                force,
            } => self.space_custody_import(path, passphrase, force),
            Request::AccessList { actor } => {
                let subject = match actor.as_deref() {
                    None => None,
                    Some(who) => match self.mechanics.resolve_actor_ref(who) {
                        Some(a) => Some(a),
                        None => return Response::not_found(format!("no actor matches '{who}'")),
                    },
                };
                Response::Assignments {
                    rows: self.mechanics.assignment_rows(subject.as_ref()),
                }
            }
            Request::AccessGrant {
                actor,
                role,
                project,
            } => self.access_grant(&actor, &role, project.as_deref()),
            Request::AccessRevoke { grant_id } => {
                let raw = match data_encoding::HEXLOWER_PERMISSIVE
                    .decode(grant_id.trim().as_bytes())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                {
                    Some(id) => id,
                    None => return Response::err("expected a 64-hex grant id"),
                };
                match self.mechanics.revoke_assignment(raw) {
                    Ok(()) => Response::Ok {
                        message: Some("revoked the assignment".into()),
                    },
                    Err(e) => Response::err(format!("{e}")),
                }
            }
            // The production classifier routed this here; any other variant
            // reaching this arm is a routing invariant violation, not a
            // servable request.
            other => unreachable!("misclassified mechanics request: {other:?}"),
        }
    }

    /// Connect/neighbor/Contact requests — served by the Station.
    fn dispatch_station(&self, req: Request) -> Response {
        match req {
            Request::Connect { ticket } => self.connect(&ticket),
            Request::Who => Response::Who { peers: self.who() },
            other => unreachable!("misclassified station request: {other:?}"),
        }
    }

    /// The reconciled presence assembly: the persistent Neighbor registry's
    /// advisory reachability (fed by verified Beacons, swarm membership
    /// events, and Contact outcomes) projected into presence rows. The same
    /// truth `status.online_peers` counts — the two surfaces cannot disagree.
    fn who(&self) -> Vec<crate::control::PresenceEntry> {
        let aliases = read_aliases(&self.home);
        let now = now_secs();
        self.station
            .neighbors()
            .into_iter()
            .map(|n| {
                let id = n.station.as_device().to_string();
                let online = n.reachability == runtime::Reachability::Reachable;
                let state = match n.reachability {
                    runtime::Reachability::Reachable => "online",
                    runtime::Reachability::Unreachable => "offline",
                    runtime::Reachability::Unknown => "away",
                };
                let last_seen_secs = if n.last_seen_ms == 0 {
                    0
                } else {
                    now.saturating_sub(n.last_seen_ms / 1_000)
                };
                crate::control::PresenceEntry {
                    nick: aliases.get(&id).cloned().unwrap_or_default(),
                    id,
                    state: state.to_string(),
                    online,
                    last_seen_secs,
                }
            })
            .collect()
    }

    /// The one number both `status` and `who` report as "online".
    fn online_peers(&self) -> usize {
        self.station
            .neighbors()
            .iter()
            .filter(|n| n.reachability == runtime::Reachability::Reachable)
            .count()
    }

    /// Status, subscription, and locally derived projection surfaces.
    fn dispatch_observation(&self, req: Request) -> Response {
        match req {
            Request::Status => self.status(),
            Request::Inbox { clear } => {
                let (entries, unread) = self.inbox_projection();
                if clear {
                    self.write_inbox_watermark(now_secs());
                }
                Response::Inbox { entries, unread }
            }
            // Subscribe is handled by the streaming connection path before
            // dispatch; a one-shot Subscribe cannot be answered on this plane.
            Request::Subscribe { .. } => Response::err("subscribe is a streaming request"),
            other => unreachable!("misclassified observation request: {other:?}"),
        }
    }

    /// Daemon lifecycle and node-local configuration adapters.
    fn dispatch_lifecycle(&self, req: Request) -> Response {
        match req {
            Request::Hello { .. } => Response::Hello {
                protocol_version: crate::control::CONTROL_PROTOCOL_VERSION,
            },
            Request::ConfigReload => Response::Ok { message: None },
            Request::Stop => Response::Ok {
                message: Some("stopping".into()),
            },
            // The orbital daemon has no legacy in-memory event ring — live
            // clients observe the Station's doorbell stream (`Subscribe`)
            // instead — so the polling log is empty by construction.
            Request::Log { since } => Response::Events {
                events: vec![],
                last: since,
            },
            Request::Diagnose { expected_space } => self.diagnose(expected_space),
            Request::SeedAdd { arg } => self.seed_add(arg.trim()),
            Request::SeedList => self.seed_list(),
            Request::SeedRemove { who } => self.seed_remove(who.trim()),
            Request::MemberAlias { who, name } => self.set_alias(&who, &name),
            other => unreachable!("misclassified lifecycle request: {other:?}"),
        }
    }

    /// The (issues, projects) counts from the docked Session's catalog
    /// snapshot — `None` when the projection is UNAVAILABLE (undocked, or a
    /// query failed). Status reports the truth; it never converts an
    /// unavailable projection into false zeros.
    fn counts(&self) -> Option<(usize, usize, String, String)> {
        use crate::world::contract::{self, IssueQuery};
        if !self.ensure_session() {
            return None;
        }
        let guard = self.session.lock().expect("session lock");
        let session = guard.as_ref()?;
        let query = |q: IssueQuery| -> Option<serde_json::Value> {
            let bytes = session
                .query(runtime::WorldQuery {
                    schema: contract::issue_schema(),
                    schema_version: contract::ISSUE_SCHEMA_VERSION,
                    payload: q.to_json(),
                })
                .ok()?
                .bytes;
            serde_json::from_slice(&bytes).ok()
        };
        let snapshot = query(IssueQuery::Snapshot)?;
        let catalog = snapshot.get("catalog")?;
        let projects = catalog.get("projects")?.as_object().map(|m| m.len())?;
        // The catalog `name` register is the space's mutable display label
        // (`SpaceRename` writes it); surface it so the rename is visible.
        let name = catalog
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let description = catalog
            .get("description")
            .and_then(|n| n.as_str())
            .unwrap_or("")
            .to_string();
        let issues = query(IssueQuery::List {
            project: None,
            label: None,
            status: None,
            mine: None,
            all: true,
            me: None,
        })
        .and_then(|v| v.as_array().map(|a| a.len()))?;
        Some((issues, projects, name, description))
    }

    fn status(&self) -> Response {
        let counts = self.counts();
        let (issues, projects, name, description) =
            counts
                .clone()
                .unwrap_or((0, 0, String::new(), String::new()));
        Response::Status(Box::new(StatusInfo {
            id: crate::crypto::device_from_seed(&self.device_seed).to_string(),
            nick: String::new(),
            name,
            description,
            online_peers: self.online_peers(),
            space: Some(self.station.space_id().as_str().to_string()),
            counts_unavailable: counts.is_none(),
            issues,
            projects,
            membership: if self.mechanics.am_i_member() {
                "member".into()
            } else {
                "pending".into()
            },
            degraded_recovery: self.mechanics.degraded_recovery(),
            recovery: Some(self.mechanics.recovery_status()),
        }))
    }

    fn members(&self) -> Response {
        Response::Members {
            members: self.mechanics.members(),
        }
    }

    /// Add a device to this actor from its hex-encoded consent blob (produced
    /// by the joining machine's `device accept`).
    fn device_add(&self, consent_hex: &str) -> Response {
        let binding: crate::actor::DeviceBinding = match data_encoding::HEXLOWER_PERMISSIVE
            .decode(consent_hex.trim().as_bytes())
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
        {
            Some(b) => b,
            None => return Response::err("device consent blob did not decode"),
        };
        match self.mechanics.device_add(binding) {
            Ok(device) => Response::Ok {
                message: Some(format!("added device {}", device.short())),
            },
            Err(e) => Response::err(format!("{e}")),
        }
    }

    /// This actor's device set, one per line, marking the active local device.
    fn device_list_text(&self) -> String {
        let me = crate::crypto::device_from_seed(&self.device_seed);
        let devices = self.mechanics.device_list();
        if devices.is_empty() {
            return "no devices".to_string();
        }
        devices
            .into_iter()
            .map(|d| {
                let tag = if d == me { " (this device)" } else { "" };
                format!("{}{}", d.as_str(), tag)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// Set (or clear, with an empty name) a local petname for a key. Local to
    /// this node, never broadcast, never part of the signed authority.
    fn set_alias(&self, who: &str, name: &str) -> Response {
        match write_alias(&self.home, who, name) {
            Ok(()) if name.trim().is_empty() => Response::Ok {
                message: Some(format!("cleared the local name for {who}")),
            },
            Ok(()) => Response::Ok {
                message: Some(format!("{who} is now locally known as {name}")),
            },
            Err(e) => Response::err(format!("set alias: {e}")),
        }
    }

    /// The guided-join verifier: project live daemon state into the ordered
    /// onboarding gate list (`docs/UI.md`). Pure over the snapshot the daemon
    /// already computes — the same core the legacy node used.
    fn diagnose(&self, expected_space: Option<String>) -> Response {
        let (issues, projects, _name, _description) =
            self.counts()
                .unwrap_or((0, 0, String::new(), String::new()));
        let space = self.station.space_id().as_str().to_string();
        let membership = if self.mechanics.am_i_member() {
            "member"
        } else {
            "pending"
        };
        let degraded = self.mechanics.degraded_recovery();
        let recovery = self.mechanics.recovery_status();
        let view = crate::diagnose::diagnose(crate::diagnose::DiagnoseInput {
            space: Some(space.as_str()),
            name: "",
            membership,
            online_peers: self.online_peers(),
            projects,
            issues,
            expected_space: expected_space.as_deref(),
            degraded_recovery: &degraded,
            rekey_pending: None,
            local_custody: Some(&recovery.local_custody),
        });
        Response::Diagnosis(Box::new(view))
    }

    /// Pin a bootstrap seed by device id (or an orbital Coordinates link's
    /// approach Station) into the node-local registry.
    fn seed_add(&self, arg: &str) -> Response {
        let (id, space) = match crate::ids::DeviceId::parse(arg.trim()) {
            Some(id) => (id, String::new()),
            None => match runtime::SignedCoordinates::parse_link(arg.trim())
                .ok()
                .and_then(|c| c.verify().ok())
            {
                Some(v) => (v.approach_station.clone(), v.space.as_str().to_string()),
                None => return Response::err("expected a device id or a Coordinates link to pin"),
            },
        };
        let newly = upsert_seed(
            &self.home,
            SeedRecord {
                id: id.clone(),
                nick: String::new(),
                space,
            },
        );
        Response::Ok {
            message: Some(if newly {
                format!("pinned seed {}", id.as_str())
            } else {
                format!("seed {} was already pinned (refreshed)", id.as_str())
            }),
        }
    }

    /// The pinned seed registry with live reachability from the Station's
    /// current neighbor set.
    fn seed_list(&self) -> Response {
        let online: std::collections::BTreeSet<[u8; 32]> = self
            .station
            .neighbors()
            .iter()
            .map(|n| n.station.key_bytes())
            .collect();
        let seeds = load_seeds(&self.home)
            .into_iter()
            .map(|s| {
                // A seed is pinned by device id; a Neighbor is a Station id —
                // both are the same 32-byte key, so reachability compares those.
                let is_online =
                    s.id.key_bytes()
                        .map(|k| online.contains(&k))
                        .unwrap_or(false);
                crate::dto::SeedDto {
                    id: s.id.as_str().to_string(),
                    nick: s.nick,
                    space: s.space,
                    state: if is_online { "online" } else { "offline" }.to_string(),
                    online: is_online,
                }
            })
            .collect();
        Response::Seeds { seeds }
    }

    /// Unpin seeds matching a full id, id-prefix, or nick.
    fn seed_remove(&self, needle: &str) -> Response {
        match remove_seed(&self.home, needle) {
            0 => Response::err("no pinned seed matched that id/nick"),
            n => Response::Ok {
                message: Some(format!("unpinned {n} seed(s)")),
            },
        }
    }

    // ---- membership ceremonies (formatting mirrors the product adapters) -----

    fn space_recover(&self) -> Response {
        use mechanics::ceremony::{SpaceRecovered, SpaceRecovery};
        match self.mechanics.space_recover() {
            Ok(SpaceRecovery::Installed(SpaceRecovered { root, rekey_failed })) => {
                let head = format!("recovered the space — root reset to {}", root.short());
                Response::Ok {
                    message: Some(match rekey_failed {
                        None => format!("{head} and re-keyed"),
                        Some(e) => format!(
                            "{head}, but re-keying failed ({e:#}) — the space is still readable \
                             under the old key until an admin rotates it"
                        ),
                    }),
                }
            }
            Ok(SpaceRecovery::Pending {
                session,
                incomplete,
            }) => {
                let hex = session.to_hex();
                let head = format!(
                    "group recovery under way (session {hex}) — each other holder must approve \
                     it with `space recover-approve {hex}` until the threshold co-signs"
                );
                Response::Ok {
                    message: Some(match incomplete {
                        None => head,
                        Some(e) => format!(
                            "{head}. This device could not add its own share ({e:#}); the request \
                             stands and the other holders can still complete it"
                        ),
                    }),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_recover_approve(&self, session: String, expect: Vec<String>) -> Response {
        match self.mechanics.space_recover_approve(session, expect) {
            Ok(a) => {
                let roots = a
                    .roots
                    .iter()
                    .map(|r| r.short())
                    .collect::<Vec<_>>()
                    .join(", ");
                Response::Ok {
                    message: Some(match a.incomplete {
                        None => format!(
                            "co-signed the recovery re-rooting the space to {roots} — it installs \
                             once the threshold has co-signed"
                        ),
                        Some(e) => format!(
                            "co-signed the recovery re-rooting the space to {roots}, and that \
                             completed the threshold — but re-keying failed ({e:#}), so the space \
                             is still readable under the old key until an admin rotates it"
                        ),
                    }),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_elevate(&self, cofounders: Vec<String>, k: u16) -> Response {
        match self.mechanics.space_elevate(cofounders, k) {
            Ok(e) => {
                let message = match (e.grant_request, e.incomplete) {
                    (_, Some(why)) => format!(
                        "proposed a {}-of-{} recovery arrangement (proposal {}) — but this device \
                         could not carry it further ({why:#}); the proposal stands and can still \
                         be authorized",
                        e.k,
                        e.n,
                        e.proposal.to_hex()
                    ),
                    (None, None) => format!(
                        "started {}-of-{} recovery elevation — the DKG completes automatically as \
                         the co-founders' nodes sync; the group key installs once every share is in",
                        e.k, e.n
                    ),
                    (Some(signing), None) => format!(
                        "proposed a {}-of-{} recovery arrangement (proposal {}) — the current \
                         group must authorize it: each holder runs `space elevate-approve {} \
                         --proposal {}`",
                        e.k,
                        e.n,
                        e.proposal.to_hex(),
                        signing.to_hex(),
                        e.proposal.to_hex(),
                    ),
                };
                Response::Ok {
                    message: Some(message),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_elevate_approve(&self, session: String, proposal: String) -> Response {
        match self.mechanics.space_elevate_approve(session, proposal) {
            Ok(a) => Response::Ok {
                message: Some(format!(
                    "co-signed the authorization for a {}-of-{} arrangement — it takes effect \
                     once the threshold has signed",
                    a.k, a.n
                )),
            },
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_reshare(&self, participants: Vec<String>, k: u16) -> Response {
        match self.mechanics.space_reshare(participants, k) {
            Ok(e) => {
                let message = match (e.grant_request, e.incomplete) {
                    (_, Some(why)) => format!(
                        "proposed resharing the recovery key onto a {}-of-{} arrangement \
                         (proposal {}) — but this device could not carry it further ({why:#}); \
                         the proposal stands and can still be authorized",
                        e.k,
                        e.n,
                        e.proposal.to_hex()
                    ),
                    (Some(signing), None) => format!(
                        "proposed resharing the recovery key onto a {}-of-{} arrangement \
                         (proposal {}) — the current group must authorize it: each holder runs \
                         `space elevate-approve {} --proposal {}`. The key itself does not change.",
                        e.k,
                        e.n,
                        e.proposal.to_hex(),
                        signing.to_hex(),
                        e.proposal.to_hex(),
                    ),
                    (None, None) => format!(
                        "started resharing the recovery key onto a {}-of-{} arrangement — the \
                         redistribution completes automatically as the holders' nodes sync",
                        e.k, e.n
                    ),
                };
                Response::Ok {
                    message: Some(message),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_custody_export(&self, path: String, passphrase: String) -> Response {
        match self.mechanics.space_custody_export(path, passphrase) {
            Ok(e) => {
                let note = if !e.indispensable {
                    "this arrangement tolerates a lost holder, so no attestation is required to \
                     install it"
                        .to_string()
                } else if e.outstanding == 0 {
                    "every custodian has attested — the arrangement can now install".to_string()
                } else {
                    format!("still waiting on {} custodian(s)", e.outstanding)
                };
                Response::Ok {
                    message: Some(format!(
                        "exported and verified your share package to {} — {note}. Keep it \
                         somewhere the passphrase alone cannot be found.",
                        e.path
                    )),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn space_custody_import(&self, path: String, passphrase: String, force: bool) -> Response {
        match self.mechanics.space_custody_import(path, passphrase, force) {
            Ok(i) => {
                let head = format!(
                    "restored and verified your share for ceremony {} — this device can take part \
                     in recovery again",
                    i.ceremony.to_hex()
                );
                Response::Ok {
                    message: Some(match i.incomplete {
                        None => head,
                        Some(e) => format!(
                            "{head}. The ceremony did not advance here ({e:#}); it will retry on \
                             the next sync"
                        ),
                    }),
                }
            }
            Err(e) => Response::err(format!("{e}")),
        }
    }

    /// The addressed-to-you inbox — ONE World query over the derived read
    /// model (plan 04: activity/inbox rebuild from query and are never a
    /// second source of truth). The read watermark is a small local file;
    /// deleting it merely resets "unread".
    fn inbox_projection(&self) -> (Vec<crate::dto::InboxEntry>, u64) {
        use crate::world::contract::IssueQuery;
        let me_actor = self.facts().actor;
        let me_device = crate::crypto::device_from_seed(&self.device_seed)
            .as_str()
            .to_string();
        let Some(rows) = self.session_query_json(IssueQuery::Inbox {
            actor: me_actor.as_str().to_string(),
            exclude_device: Some(me_device),
        }) else {
            return (Vec::new(), 0);
        };
        let watermark = self.read_inbox_watermark();
        let mut entries: Vec<crate::dto::InboxEntry> = Vec::new();
        for e in rows.as_array().map(|a| a.as_slice()).unwrap_or_default() {
            entries.push(crate::dto::InboxEntry {
                ts: e["ts"].as_u64().unwrap_or(0),
                kind: e["kind"].as_str().unwrap_or_default().to_string(),
                reff: e["reff"].as_str().unwrap_or_default().to_string(),
                doc_id: e["doc_id"].as_str().unwrap_or_default().to_string(),
                title: e["title"].as_str().unwrap_or_default().to_string(),
                detail: e["detail"].as_str().unwrap_or_default().to_string(),
                actor: e["actor"].as_str().map(String::from),
                actor_nick: None,
            });
        }
        entries.truncate(200);
        let unread = entries.iter().filter(|e| e.ts > watermark).count() as u64;
        (entries, unread)
    }

    fn inbox_watermark_path(&self) -> PathBuf {
        self.home.join("inbox-read.json")
    }

    fn read_inbox_watermark(&self) -> u64 {
        std::fs::read_to_string(self.inbox_watermark_path())
            .ok()
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or(0)
    }

    fn write_inbox_watermark(&self, ts: u64) {
        let _ = std::fs::write(self.inbox_watermark_path(), ts.to_string());
    }

    /// Query the docked Session for a JSON projection (role/workflow views).
    fn session_query_json(
        &self,
        query: crate::world::contract::IssueQuery,
    ) -> Option<serde_json::Value> {
        if !self.ensure_session() {
            return None;
        }
        let guard = self.session.lock().expect("session lock");
        let session = guard.as_ref()?;
        let bytes = session
            .query(runtime::WorldQuery {
                schema: crate::world::contract::issue_schema(),
                schema_version: crate::world::contract::ISSUE_SCHEMA_VERSION,
                payload: query.to_json(),
            })
            .ok()?
            .bytes;
        serde_json::from_slice(&bytes).ok()
    }

    /// Expand a role's pinned definition (read from the Manifest-pinned
    /// Catalog through the Session) and install the exact assignments as one
    /// Mechanics authority batch. IssuesWorld plans the expansion; Runtime
    /// validates; Mechanics commits authority-first.
    fn access_grant(&self, actor: &str, role: &str, project: Option<&str>) -> Response {
        let Some(subject) = self.mechanics.resolve_actor_ref(actor) else {
            return Response::not_found(format!("no actor matches '{actor}'"));
        };
        let Some(view) = self.session_query_json(crate::world::contract::IssueQuery::RoleShow {
            role: role.to_string(),
        }) else {
            return Response::not_found(format!("no role `{role}` in this space"));
        };
        let conflicts = view["conflict_heads"]
            .as_array()
            .cloned()
            .unwrap_or_default();
        if !conflicts.is_empty() {
            return Response::err(format!(
                "role `{role}` has {} concurrent revision heads — resolve them with                  `role resolve` before assigning",
                conflicts.len()
            ));
        }
        let Some(revision) = view.get("revision").filter(|r| !r.is_null()) else {
            return Response::not_found(format!("role `{role}` has no usable revision"));
        };
        let body = &revision["body"];
        if body["tombstone"].as_bool() == Some(true) {
            return Response::err(format!("role `{role}` is tombstoned"));
        }
        let scope_kind = body["scope_kind"].as_str().unwrap_or("space");
        let world = crate::world::contract::PRODUCT_WORLD;
        let resource = match (scope_kind, project) {
            ("space", None) => mechanics::demand::PolicyResource::space(world),
            ("space", Some(_)) => {
                return Response::err("that is a Space role — it takes no --project")
            }
            ("project", Some(sel)) => {
                let Some(snapshot) =
                    self.session_query_json(crate::world::contract::IssueQuery::Snapshot)
                else {
                    return Response::err("the catalog is unavailable");
                };
                let projects = snapshot["catalog"]["projects"].as_object().cloned();
                let resolved = projects.and_then(|m| {
                    let upper = sel.to_ascii_uppercase();
                    if m.contains_key(sel) {
                        return Some(sel.to_string());
                    }
                    m.iter()
                        .find(|(_, meta)| meta["key"].as_str() == Some(upper.as_str()))
                        .map(|(id, _)| id.clone())
                });
                match resolved {
                    Some(id) => mechanics::demand::PolicyResource::project(world, &id),
                    None => return Response::not_found(format!("no project matches '{sel}'")),
                }
            }
            ("project", None) => {
                return Response::err("that is a Project role — pass -p <project>")
            }
            _ => return Response::err("unrecognized role scope"),
        };
        let assignments: Vec<(
            mechanics::demand::PolicyCapability,
            mechanics::demand::PolicyResource,
        )> = body["capabilities"]
            .as_array()
            .map(|caps| {
                caps.iter()
                    .filter_map(|c| c.as_str())
                    .map(|c| {
                        (
                            mechanics::demand::PolicyCapability::new(world, c),
                            resource.clone(),
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        if assignments.is_empty() {
            return Response::err(format!("role `{role}` expands to no capabilities"));
        }
        match self.mechanics.grant_assignments(&subject, &assignments) {
            Ok(granted) => Response::Ok {
                message: Some(format!(
                    "granted {} capability assignment(s) from role `{role}` to {}",
                    granted.len(),
                    subject.short()
                )),
            },
            Err(e) => Response::err(format!("{e}")),
        }
    }

    fn invite(&self, role: Option<&str>, reusable: bool, ttl_hours: Option<u64>) -> Response {
        // Mint an admission-bearing Coordinates link. Accepting the invite is
        // the approval: the capability carries the selected role's exact
        // expanded assignments (default contributor), and redemption is
        // automatic on Contact. `reusable` admits a team (up to the redemption
        // cap) instead of one person.
        let ttl_secs = ttl_hours.unwrap_or(168).max(1).saturating_mul(3600);
        let parent_root = self.station.frontier().root;
        let admission = match self.mechanics.mint_admission(
            &self.device_seed,
            ttl_secs,
            reusable,
            now_secs(),
            role.unwrap_or("contributor"),
            parent_root,
        ) {
            Ok(a) => a,
            Err(e) => return Response::err(format!("mint admission: {e}")),
        };
        match self.mechanics.mint_coordinates(
            &self.device_seed,
            "",
            self.advertised_routes.clone(),
            Some(admission),
        ) {
            Ok(coords) => Response::Ref {
                reff: coords.render(),
            },
            Err(e) => Response::err(format!("mint coordinates: {e}")),
        }
    }

    fn connect(&self, link: &str) -> Response {
        // The manual nudge (W0-S5): a running daemon "connecting" triggers an
        // administrative Contact now, bypassing backoff. Accepts a station id
        // to dial, or a Coordinates link — whose signed approach routes are
        // taught to the transport first, so the dial resolves even after the
        // peer's addresses changed. Coordinates *entry* (store bootstrap)
        // stays `lait join`'s job.
        let link = link.trim();
        let station =
            match crate::ids::DeviceId::parse(link).and_then(|d| StationId::from_device(&d)) {
                Some(station) => Some(station),
                None => runtime::SignedCoordinates::parse_link(link)
                    .ok()
                    .and_then(|c| c.verify().ok())
                    .and_then(|v| {
                        if !v.approach_routes.is_empty() {
                            self.transport
                                .learn(v.approach_station.clone(), &v.approach_routes);
                        }
                        StationId::from_device(&v.approach_station)
                    }),
            };
        match station {
            Some(station) => match self.station.contact(&station, ContactOptions) {
                Ok(outcome) => Response::Ok {
                    message: Some(format!(
                        "contacted — {} bytes moved{}",
                        outcome.bytes_moved,
                        if outcome.convergence.advanced() {
                            ", new material incorporated"
                        } else {
                            ", already converged"
                        }
                    )),
                },
                Err(e) => Response::err(format!("contact: {e:?}")),
            },
            None => Response::err("connect expects a station id or an invite link"),
        }
    }

    /// Serve the control IPC loop until shutdown.
    pub async fn serve(self: Arc<Self>) -> Result<()> {
        let control = control_name(&self.home)?;
        #[cfg(unix)]
        let _ = std::fs::remove_file(crate::config::socket_path(&self.home));
        let listener = ListenerOptions::new()
            .name(control)
            .create_tokio()
            .context("bind control channel")?;
        tracing::info!(
            "orbital daemon online in space {}",
            self.station.space_id().as_str()
        );
        let idle_window = idle_window_from_env();
        let mut idle_tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
                _ = idle_tick.tick() => {
                    // The store watchdog (LOCAL-9): a daemon must never
                    // outlive its store. With the directory gone, this
                    // process can only serve stale memory while blocking its
                    // own clients (presence is a directory scan) — stop
                    // loudly instead.
                    if !self.store_dir().is_dir() {
                        tracing::error!(
                            "orbital store at {} is gone — the daemon will not \
                             outlive its store; stopping",
                            self.store_dir().display()
                        );
                        self.begin_stop();
                        break;
                    }
                    if self.should_idle_shutdown(idle_window) {
                        tracing::info!("orbital daemon idle-shutdown after {idle_window:?}");
                        self.begin_stop();
                        break;
                    }
                }
                accept = listener.accept() => match accept {
                    Ok(stream) => {
                        let me = self.clone();
                        tokio::spawn(async move { me.handle_conn(stream).await });
                    }
                    Err(e) => {
                        tracing::warn!("control accept error: {e}");
                        break;
                    }
                }
            }
        }
        // Cleanly stop the Station (releases the store lock, ends tasks).
        let _ = self.station.frontier();
        Ok(())
    }

    /// This Space's on-disk store directory (the watchdog's liveness probe).
    fn store_dir(&self) -> PathBuf {
        orbital_store_root(&self.home).join(self.station.space_id().as_str())
    }

    /// Whether the idle window has elapsed with nothing to keep us alive: a
    /// non-zero window, no in-flight connections, no neighbors to converge with,
    /// and no activity for at least the window. Mirrors the legacy node's rule.
    fn should_idle_shutdown(&self, window: Duration) -> bool {
        use std::sync::atomic::Ordering;
        if window.is_zero() {
            return false;
        }
        if self.active_conns.load(Ordering::SeqCst) != 0 {
            return false;
        }
        if !self.station.neighbors().is_empty() {
            return false;
        }
        let idle_for = self
            .last_activity
            .lock()
            .map(|t| t.elapsed())
            .unwrap_or_default();
        idle_for >= window
    }

    async fn handle_conn(self: Arc<Self>, stream: LocalStream) {
        use std::sync::atomic::Ordering;
        self.active_conns.fetch_add(1, Ordering::SeqCst);
        // Decrement + stamp activity on every exit path (guard on drop).
        struct ConnGuard<'a>(&'a OrbitalDaemon);
        impl Drop for ConnGuard<'_> {
            fn drop(&mut self) {
                self.0.active_conns.fetch_sub(1, Ordering::SeqCst);
                if let Ok(mut t) = self.0.last_activity.lock() {
                    *t = std::time::Instant::now();
                }
            }
        }
        let _guard = ConnGuard(&self);

        let (read_half, write_half) = tokio::io::split(stream);
        let mut reader = BufReader::new(read_half);
        let mut line = String::new();
        if reader.read_line(&mut line).await.is_err() {
            return;
        }
        let req = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => req,
            Err(e) => {
                let _ = write_line(write_half, &Response::err(format!("bad request: {e}"))).await;
                return;
            }
        };
        if let Request::Subscribe { .. } = req {
            self.stream_subscribe(write_half).await;
            return;
        }
        // Stop is a real teardown request: answer, then signal the serve loop
        // to return (the caller decides whether to exit the process).
        let stop = matches!(req, Request::Stop);
        let resp = self.dispatch(req);
        let _ = write_line(write_half, &resp).await;
        if stop {
            self.begin_stop();
        }
    }

    async fn stream_subscribe(&self, mut write_half: tokio::io::WriteHalf<LocalStream>) {
        // A fresh stream from the current cursor: first frame is always a reset.
        // Without standing there is no Session to observe yet — emit the reset
        // and return; the client re-subscribes after admission.
        let (mut stream, epoch) = {
            if !self.ensure_session() {
                let reset = Doorbell {
                    reset: true,
                    ..Default::default()
                };
                let _ = write_line_half(&mut write_half, &reset).await;
                return;
            }
            let guard = self.session.lock().expect("session lock");
            let session = guard.as_ref().expect("session present after ensure");
            (session.observe(None), session.epoch().as_u64())
        };
        let reset = Doorbell {
            epoch,
            seq: 0,
            reset: true,
            ..Default::default()
        };
        if write_line_half(&mut write_half, &reset).await.is_err() {
            return;
        }
        // Drain the initial reset record so subsequent records are live.
        let _ = stream.try_next();

        // Bridge the blocking observation iterator through a TRACKED blocking
        // task and an async channel. The worker owns the stream and blocks in
        // bounded windows, re-checking the cancellation flag between them; the
        // async side selects on the channel and the teardown watch, so a Stop
        // wakes it immediately and the worker exits within one window. The
        // JoinHandle is awaited — the thread is tracked, never leaked.
        let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (tx, mut rx) = tokio::sync::mpsc::channel::<runtime::Observation>(64);
        let worker = tokio::task::spawn_blocking(move || {
            loop {
                if worker_cancel.load(std::sync::atomic::Ordering::SeqCst) {
                    return;
                }
                match stream.next_timeout(Duration::from_millis(250)) {
                    Ok(Some(record)) => {
                        if tx.blocking_send(record).is_err() {
                            return; // subscriber went away
                        }
                    }
                    Ok(None) => continue, // idle window: re-check cancellation
                    Err(_) => return,     // station dormant: stream closed
                }
            }
        });
        let mut stop_rx = self.stop_tx.subscribe();
        loop {
            tokio::select! {
                changed = stop_rx.changed() => {
                    if changed.is_err() || *stop_rx.borrow() {
                        break;
                    }
                }
                record = rx.recv() => {
                    let Some(record) = record else { break }; // worker ended
                    let frame = Doorbell {
                        epoch: record.epoch.as_u64(),
                        seq: record.sequence,
                        reset: record.reset,
                        activity_advanced: true,
                        ..Default::default()
                    };
                    if write_line_half(&mut write_half, &frame).await.is_err() {
                        break;
                    }
                }
            }
        }
        // Bounded shutdown: signal the worker and await it (it exits within
        // one 250 ms window, or immediately on the closed channel).
        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
        drop(rx);
        let _ = worker.await;
    }

    /// Latch teardown: the atomic (for worker threads), the watch (for live
    /// subscriptions), and the serve loop's notify.
    fn begin_stop(&self) {
        self.stopping
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = self.stop_tx.send(true);
        self.shutdown.notify_one();
    }
}

static CLOCK: std::sync::OnceLock<SystemUlidSource> = std::sync::OnceLock::new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The idle-shutdown window, from `LAIT_IDLE_SECS` (0 disables), else 30 min —
/// the same contract the legacy node honors.
fn idle_window_from_env() -> Duration {
    const DEFAULT: Duration = Duration::from_secs(30 * 60);
    match std::env::var("LAIT_IDLE_SECS") {
        Ok(s) => s
            .trim()
            .parse::<u64>()
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT),
        Err(_) => DEFAULT,
    }
}

fn comms_options(
    transport: Arc<dyn Transport>,
    seed: [u8; 32],
    mechanics: &OrbitalMechanics,
    bootstrap: Vec<crate::ids::DeviceId>,
    advertise: Vec<runtime::beacon::RouteHint>,
) -> CommsOptions {
    let export = mechanics.clone();
    let frontier = mechanics.clone();
    CommsOptions {
        transport,
        station_seed: seed,
        mechanics: ContactMechanics {
            source: Arc::new(mechanics.clone()),
            incorporator: Arc::new(Mutex::new(mechanics.clone()))
                as Arc<Mutex<dyn AuthorityIncorporator + Send>>,
            export: Arc::new(move || export.export_records()),
            frontier: Arc::new(move || frontier.current_frontier()),
        },
        gossip: Some(GossipOptions {
            bootstrap,
            advertise,
            // The heartbeat floor's base; emission is edge-triggered
            // (contact_driver §4.1) and this only bounds staleness.
            beacon_interval: Duration::from_secs(10),
        }),
        whole_deadline: Duration::from_secs(30),
        progress_deadline: Duration::from_secs(10),
        route_lease: Duration::from_secs(120),
    }
}

async fn write_line<T: serde::Serialize>(
    mut write_half: tokio::io::WriteHalf<LocalStream>,
    value: &T,
) -> std::io::Result<()> {
    write_line_half(&mut write_half, value).await
}

async fn write_line_half<T: serde::Serialize>(
    write_half: &mut tokio::io::WriteHalf<LocalStream>,
    value: &T,
) -> std::io::Result<()> {
    let mut out = serde_json::to_string(value)
        .unwrap_or_else(|_| "{\"kind\":\"error\",\"message\":\"encode failure\"}".to_string());
    out.push('\n');
    write_half.write_all(out.as_bytes()).await?;
    write_half.flush().await
}

/// One pinned bootstrap seed — a deliberately-placed anchor a cold client
/// converges through. The id is the identity; nick/space are advisory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SeedRecord {
    id: crate::ids::DeviceId,
    #[serde(default)]
    nick: String,
    #[serde(default)]
    space: String,
}

fn seeds_path(home: &Path) -> PathBuf {
    home.join("seeds.json")
}

/// Load the pinned seed registry, dropping (at warn) any record whose id is not
/// a device key so one bad row never unpins the rest.
fn load_seeds(home: &Path) -> Vec<SeedRecord> {
    let Ok(data) = std::fs::read_to_string(seeds_path(home)) else {
        return Vec::new();
    };
    let rows: Vec<SeedRecord> = serde_json::from_str(&data).unwrap_or_default();
    rows.into_iter()
        .filter(|r| crate::ids::DeviceId::parse(r.id.as_str()).is_some())
        .collect()
}

fn save_seeds(home: &Path, seeds: &[SeedRecord]) {
    if let Ok(data) = serde_json::to_string_pretty(seeds) {
        let _ = std::fs::write(seeds_path(home), data);
    }
}

/// Upsert a seed keyed by id (nick/space refresh in place). Returns whether it
/// was newly pinned.
fn upsert_seed(home: &Path, rec: SeedRecord) -> bool {
    let mut seeds = load_seeds(home);
    if let Some(existing) = seeds.iter_mut().find(|s| s.id == rec.id) {
        existing.nick = rec.nick;
        existing.space = rec.space;
        save_seeds(home, &seeds);
        false
    } else {
        seeds.push(rec);
        save_seeds(home, &seeds);
        true
    }
}

/// Unpin seeds matching a full id, a ≥6-char id prefix, or a nick. Returns the
/// count removed.
fn remove_seed(home: &Path, needle: &str) -> usize {
    let mut seeds = load_seeds(home);
    let before = seeds.len();
    seeds.retain(|s| {
        let id = s.id.as_str();
        !(id == needle || (needle.len() >= 6 && id.starts_with(needle)) || s.nick == needle)
    });
    let removed = before - seeds.len();
    if removed > 0 {
        save_seeds(home, &seeds);
    }
    removed
}

/// The local petname map (`aliases.json` beside the home).
fn read_aliases(home: &Path) -> std::collections::BTreeMap<String, String> {
    std::fs::read(home.join("aliases.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Set or clear a **local** petname for a key in `aliases.json` beside the
/// home. Local to this node, never synced; an empty `name` clears the entry.
fn write_alias(home: &Path, who: &str, name: &str) -> Result<()> {
    let path = home.join("aliases.json");
    let mut map: std::collections::BTreeMap<String, String> = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    let who = who.trim().to_string();
    if name.trim().is_empty() {
        map.remove(&who);
    } else {
        map.insert(who, name.trim().to_string());
    }
    std::fs::write(&path, serde_json::to_vec_pretty(&map)?)?;
    Ok(())
}

/// Run the orbital daemon on `home` with the default transport, holding the
/// daemon lock for its lifetime. Identity is the process-global one.
pub async fn run_orbital_daemon(home: PathBuf, factory: &dyn TransportFactory) -> Result<()> {
    let device_seed = load_or_create_identity(&crate::config::identity_dir()?)?;
    run_orbital_daemon_with(home, device_seed, factory).await
}

/// The injectable orbital daemon: everything [`run_orbital_daemon`] does, but it
/// takes an explicit device seed rather than reading the process-global identity
/// — so several orbital daemons can run in one process, each its own device,
/// sharing nothing but the runtime (the multi-node test contract).
pub async fn run_orbital_daemon_with(
    home: PathBuf,
    device_seed: [u8; 32],
    factory: &dyn TransportFactory,
) -> Result<()> {
    let _lock = acquire_daemon_lock(&home)?;
    let daemon = Arc::new(OrbitalDaemon::open(&home, device_seed, factory).await?);
    daemon.serve().await?;
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::config::socket_path(&home));
    Ok(())
}
