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
//! Ceremony requests (recovery, elevation, custody, device enrollment, reshare)
//! are not yet driven on the orbital plane; the daemon answers them with a
//! typed "not available on the orbital daemon yet" rather than silently
//! mis-serving them — the honest cutover boundary until that surface is ported.

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
use crate::orbital::{detect_legacy_home, orbital_store_root, OrbitalMechanics};
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

/// The orbital daemon: the composed stack plus the docked routing Session.
pub struct OrbitalDaemon {
    mechanics: OrbitalMechanics,
    station: Station,
    session: Session,
    identity: LocalIdentity,
    device_seed: [u8; 32],
    home: PathBuf,
    /// The Observation broadcaster epoch, for Subscribe reset framing.
    doorbell_epoch: u64,
    /// Signalled by a `Stop` request so `serve` returns (the injectable
    /// contract: return, don't `exit`).
    shutdown: Arc<tokio::sync::Notify>,
}

impl OrbitalDaemon {
    /// Open and activate the orbital stack for a home, then dock the routing
    /// Session. Refuses a pre-orbital home.
    pub async fn open(
        home: &Path,
        device_seed: [u8; 32],
        factory: &dyn TransportFactory,
    ) -> Result<Self> {
        if let Some(err) = detect_legacy_home(home) {
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
                &[runtime::contact::CONTACT_ALPN, runtime::PRESENCE_ALPN_V1],
            )
            .await?;
        let station = rt
            .orbit(&space)
            .map_err(|e| anyhow!("acquire orbit: {e:?}"))?
            .activate(ActivationOptions {
                drain_deadline: Duration::from_secs(5),
                comms: Some(comms_options(transport, device_seed, &mechanics)),
                observation_capacity: 0,
            })
            .map_err(|e| anyhow!("activate: {e:?}"))?;
        let identity = Runtime::identity_from_seed(&device_seed);
        let session = station
            .dock(&crate::world::contract::world_id(), &identity)
            .map_err(|e| anyhow!("dock: {e:?}"))?;
        let doorbell_epoch = session.epoch().as_u64();

        Ok(Self {
            mechanics,
            station,
            session,
            identity,
            device_seed,
            home: home.to_path_buf(),
            doorbell_epoch,
            shutdown: Arc::new(tokio::sync::Notify::new()),
        })
    }

    fn router(&self) -> IssueRouter<'_> {
        // The clock is a fresh ULID source each call (stateless).
        IssueRouter::new(
            &self.session,
            &self.identity,
            CLOCK.get_or_init(|| SystemUlidSource),
        )
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

    /// Route one control request to its plane.
    fn dispatch(&self, req: Request) -> Response {
        if IssueRouter::handles(&req) {
            return self.router().route(req, &self.facts()).0;
        }
        match req {
            // ---- transport / status ----
            Request::Status => self.status(),
            Request::Id => Response::Ok {
                message: Some(crate::crypto::device_from_seed(&self.device_seed).to_string()),
            },
            Request::Who => Response::Who { peers: vec![] },
            Request::Invite {
                require_approval, ..
            } => self.invite(require_approval),
            Request::Connect { ticket } | Request::Join { ticket } => self.connect(&ticket),
            Request::ConfigReload => Response::Ok { message: None },
            Request::Stop => Response::Ok {
                message: Some("stopping".into()),
            },

            // ---- membership plane (over the signed ACL DAG) ----
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
            Request::MemberLog => Response::MemberLog {
                entries: self.mechanics.member_log(),
            },
            // No pending-join announcements are tracked on the orbital plane yet:
            // admission is redeemed inline during Contact incorporation, so the
            // truthful answer is an empty pending set (not a mis-served refusal).
            Request::MemberRequests => Response::JoinRequests { requests: vec![] },

            // ---- not yet on the orbital plane (honest boundary) ----
            other => Response::err(format!(
                "'{}' is not yet available on the orbital daemon (membership \
                 ceremonies, recovery, custody, and device enrollment are pending \
                 their orbital port)",
                request_name(&other)
            )),
        }
    }

    fn status(&self) -> Response {
        Response::Status(Box::new(StatusInfo {
            id: crate::crypto::device_from_seed(&self.device_seed).to_string(),
            nick: String::new(),
            name: String::new(),
            online_peers: self.station.neighbors().len(),
            space: Some(self.station.space_id().as_str().to_string()),
            issues: 0,
            projects: 0,
            membership: if self.mechanics.am_i_member() {
                "member".into()
            } else {
                "pending".into()
            },
            pending_requests: 0,
            degraded_recovery: vec![],
            recovery: None,
        }))
    }

    fn members(&self) -> Response {
        Response::Members {
            members: self.mechanics.members(),
        }
    }

    fn invite(&self, require_approval: bool) -> Response {
        // Mint a single-use admission-bearing Coordinates link. `require_approval`
        // inverts the capability's auto-admit bit: an approval-gated invite carries
        // the joiner's material but does not self-admit on redemption.
        let admission = match self.mechanics.mint_admission(
            &self.device_seed,
            24 * 3600,
            !require_approval,
            now_secs(),
        ) {
            Ok(a) => a,
            Err(e) => return Response::err(format!("mint admission: {e}")),
        };
        match self
            .mechanics
            .mint_coordinates(&self.device_seed, "", vec![], Some(admission))
        {
            Ok(coords) => Response::Ref {
                reff: coords.render(),
            },
            Err(e) => Response::err(format!("mint coordinates: {e}")),
        }
    }

    fn connect(&self, link: &str) -> Response {
        // A running daemon "connecting" to a peer id triggers an administrative
        // Contact if we know the Neighbor. Coordinates entry itself happens at
        // `lait join` (store bootstrap); here we accept a station id to dial.
        let station =
            crate::ids::DeviceId::parse(link.trim()).and_then(|d| StationId::from_device(&d));
        match station {
            Some(station) => match self.station.contact(&station, ContactOptions) {
                Ok(_) => Response::Ok {
                    message: Some("contacted".into()),
                },
                Err(e) => Response::err(format!("contact: {e:?}")),
            },
            None => Response::err("connect expects a station id"),
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
        loop {
            tokio::select! {
                _ = self.shutdown.notified() => break,
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

    async fn handle_conn(self: Arc<Self>, stream: LocalStream) {
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
            self.shutdown.notify_one();
        }
    }

    async fn stream_subscribe(&self, mut write_half: tokio::io::WriteHalf<LocalStream>) {
        // A fresh stream from the current cursor: first frame is always a reset.
        let mut stream = self.session.observe(None);
        let reset = Doorbell {
            epoch: self.doorbell_epoch,
            seq: 0,
            reset: true,
            ..Default::default()
        };
        if write_line_half(&mut write_half, &reset).await.is_err() {
            return;
        }
        // Drain the initial reset record so subsequent records are live.
        let _ = stream.try_next();
        loop {
            match stream.next_timeout(Duration::from_secs(30)) {
                Ok(Some(record)) => {
                    let frame = Doorbell {
                        epoch: record.epoch.as_u64(),
                        seq: record.sequence,
                        reset: record.reset,
                        activity_advanced: true,
                        ..Default::default()
                    };
                    if write_line_half(&mut write_half, &frame).await.is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    // Keepalive: nothing changed within the window.
                    if write_half.flush().await.is_err() {
                        return;
                    }
                }
                Err(_) => return, // station dormant
            }
        }
    }
}

static CLOCK: std::sync::OnceLock<SystemUlidSource> = std::sync::OnceLock::new();

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn comms_options(
    transport: Arc<dyn Transport>,
    seed: [u8; 32],
    mechanics: &OrbitalMechanics,
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
            bootstrap: vec![],
            advertise: vec![],
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

fn request_name(req: &Request) -> String {
    serde_json::to_value(req)
        .ok()
        .and_then(|v| v.get("cmd").and_then(|c| c.as_str()).map(String::from))
        .unwrap_or_else(|| "request".into())
}

/// Run the orbital daemon on `home` with the default transport, holding the
/// daemon lock for its lifetime.
pub async fn run_orbital_daemon(home: PathBuf, factory: &dyn TransportFactory) -> Result<()> {
    let _lock = acquire_daemon_lock(&home)?;
    let device_seed = load_or_create_identity(&crate::config::identity_dir()?)?;
    let daemon = Arc::new(OrbitalDaemon::open(&home, device_seed, factory).await?);
    daemon.serve().await?;
    #[cfg(unix)]
    let _ = std::fs::remove_file(crate::config::socket_path(&home));
    Ok(())
}
