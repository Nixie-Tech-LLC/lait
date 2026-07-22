//! Seed-registry end-to-end over the **orbital daemon** (in-process, in-memory
//! transport). A node pins an always-on bootstrap seed — by device id or by an
//! orbital Coordinates link — into its node-local `seeds.json`, and that pin
//! (1) surfaces in a structured `Seeds` DTO with live reachability, and
//! (2) survives a cold daemon restart, redialed purely from the sticky
//! `seeds.json` registry.
//!
//! The orbital `SeedAdd` accepts a device id or a Coordinates link (its approach
//! Station is the pinned id, the link's space is recorded advisory); there is no
//! SpaceTicket anymore, so the legacy "foreign-space ticket is an error" branch
//! is gone with it.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [141u8; 32];
const OTHER_SEED: [u8; 32] = [142u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct MemFactory(MemNet);

#[async_trait]
impl TransportFactory for MemFactory {
    async fn build(
        &self,
        identity_seed: &[u8; 32],
        _network: &Network,
        _alpns: &[Alpn],
    ) -> Result<Arc<dyn Transport>> {
        Ok(Arc::new(
            self.0.peer(lait::crypto::device_from_seed(identity_seed)),
        ))
    }
}

fn temp_home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-seed-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn req(rt: &tokio::runtime::Runtime, home: &Path, r: Request) -> Response {
    rt.block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn spawn_daemon(home: PathBuf, seed: [u8; 32], net: MemNet) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = run_orbital_daemon_with(home, seed, &MemFactory(net)).await {
                eprintln!("DAEMON ERR: {e:#}");
            }
        });
    })
}

fn wait_online(rt: &tokio::runtime::Runtime, home: &Path) {
    let online = poll_until(Duration::from_secs(20), || {
        matches!(req(rt, home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(
        online.is_some(),
        "orbital daemon at {} never came online",
        home.display()
    );
}

fn space_of(rt: &tokio::runtime::Runtime, home: &Path) -> String {
    match req(rt, home, Request::Status) {
        Response::Status(s) => s.space.expect("founder has a space"),
        other => panic!("status returned {other:?}"),
    }
}

/// Pin a seed from a Coordinates link, prove it lists as a structured DTO
/// (carrying the link's device id + space), and prove it survives a cold daemon
/// restart — reloaded from the sticky `seeds.json` alone.
#[test]
fn seed_pin_lists_structured_and_survives_restart() {
    let net = MemNet::new();
    let home = temp_home("pin");
    lait::orbital::found_space_cli(&home, &FOUNDER_SEED, "Seed Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);
    let space = space_of(&rt, &home);

    // The seed/remote list is a structured DTO even when empty (not a text blob).
    match req(&rt, &home, Request::SeedList) {
        Response::Seeds { seeds } => assert!(seeds.is_empty(), "no seeds pinned yet"),
        other => panic!("seed ls must return the structured Seeds DTO, got {other:?}"),
    }

    // A Coordinates link carries an approach Station (a device id) and the space;
    // pinning it records both. The founder's own invite is a convenient link.
    let Response::Ref { reff: link } = req(
        &rt,
        &home,
        Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };
    assert!(
        matches!(
            req(&rt, &home, Request::SeedAdd { arg: link }),
            Response::Ok { .. }
        ),
        "pinning a Coordinates link must succeed"
    );

    // The link's approach Station is the founder's own device.
    let founder_id = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();

    // It lists as one structured seed, carrying the id and the advertised space.
    match req(&rt, &home, Request::SeedList) {
        Response::Seeds { seeds } => {
            assert_eq!(seeds.len(), 1, "exactly one seed pinned: {seeds:?}");
            assert_eq!(seeds[0].id, founder_id, "seed carries the link's device id");
            assert_eq!(seeds[0].space, space, "seed records the link's space");
        }
        other => panic!("seed ls returned {other:?}"),
    }

    // The pin is persisted for restart.
    assert!(
        poll_until(Duration::from_secs(10), || {
            std::fs::read_to_string(home.join("seeds.json"))
                .unwrap_or_default()
                .contains(&founder_id)
                .then_some(())
        })
        .is_some(),
        "the seed must be persisted in seeds.json"
    );

    // Cold restart: stop the daemon and bring a fresh one up on the SAME home.
    let _ = req(&rt, &home, Request::Stop);
    let _ = handle.join();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());
    wait_online(&rt, &home);

    // The pin is reloaded from seeds.json alone — the registry is sticky.
    match req(&rt, &home, Request::SeedList) {
        Response::Seeds { seeds } => {
            assert_eq!(seeds.len(), 1, "the pin survived the restart: {seeds:?}");
            assert_eq!(seeds[0].id, founder_id);
        }
        other => panic!("post-restart seed ls returned {other:?}"),
    }

    let _ = req(&rt, &home, Request::Stop);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}

/// `seed add`/`seed rm` by raw device id: a bare device id is a valid pin, and
/// removal by that id unpins it (both node-local, no space required).
#[test]
fn seed_add_and_remove_by_device_id() {
    let net = MemNet::new();
    let home = temp_home("byid");
    lait::orbital::found_space_cli(&home, &FOUNDER_SEED, "Seed Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    let other_id = lait::crypto::device_from_seed(&OTHER_SEED).to_string();
    assert!(
        matches!(
            req(
                &rt,
                &home,
                Request::SeedAdd {
                    arg: other_id.clone()
                }
            ),
            Response::Ok { .. }
        ),
        "pinning a bare device id must succeed"
    );
    match req(&rt, &home, Request::SeedList) {
        Response::Seeds { seeds } => {
            assert!(
                seeds.iter().any(|s| s.id == other_id),
                "id pinned: {seeds:?}"
            )
        }
        other => panic!("seed ls returned {other:?}"),
    }

    assert!(
        matches!(
            req(
                &rt,
                &home,
                Request::SeedRemove {
                    who: other_id.clone()
                }
            ),
            Response::Ok { .. }
        ),
        "unpinning by id must succeed"
    );
    match req(&rt, &home, Request::SeedList) {
        Response::Seeds { seeds } => assert!(seeds.is_empty(), "seed was unpinned: {seeds:?}"),
        other => panic!("seed ls returned {other:?}"),
    }

    let _ = req(&rt, &home, Request::Stop);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}
