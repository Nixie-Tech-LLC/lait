//! W4 — the Beacon initiative's acceptance harness (docket 06).
//!
//! Real orbital daemons over their control sockets on an in-memory transport,
//! proving the plane the initiative exists for:
//!
//! 1. **Steady-state convergence without re-join** (exit criterion 1 /
//!    LOCAL-11): once admitted, a fresh write moves between idle nodes with no
//!    `Connect` and no re-join — edge-triggered beacon → pending mark →
//!    scheduler Contact.
//! 2. **Dead-hub survival** (exit criterion 2 / LOCAL-8): with the approach
//!    Station's daemon stopped, the surviving members keep converging through
//!    each other.
//! 3. **Presence agreement** (exit criterion 3 / BEACON-10): `who` and
//!    `status.online_peers` project the same reconciled truth, non-empty when
//!    peers exist.
//!
//! Flood/churn bounds (criterion 4) are covered at the unit seam:
//! `neighbors.rs` (registry cap, eviction, coalesced persistence) and
//! `independent_world.rs` (the eclipse fence's quarantine).

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

const FOUNDER_SEED: [u8; 32] = [221u8; 32];
const MEMBER_A_SEED: [u8; 32] = [222u8; 32];
const MEMBER_B_SEED: [u8; 32] = [223u8; 32];

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
    let dir = std::env::temp_dir().join(format!("lait-beacon-{tag}-{}-{n}", std::process::id()));
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
        "daemon at {} never came online",
        home.display()
    );
}

/// Mint a single-use invite at the founder and bootstrap `home`'s store from
/// it (the `lait join` store entry; the caller spawns the daemon after).
fn admit(client: &tokio::runtime::Runtime, home: &Path, seed: &[u8; 32], founder_home: &Path) {
    let Response::Ref { reff: invite } = req(
        client,
        founder_home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };
    lait::orbital::enter_space(home, seed, &invite).unwrap();
}

fn drive_admission(client: &tokio::runtime::Runtime, joiner_home: &Path, founder_device: &str) {
    let admitted = poll_until(Duration::from_secs(25), || {
        req(
            client,
            joiner_home,
            Request::Connect {
                ticket: founder_device.to_string(),
            },
        );
        match req(client, joiner_home, Request::Status) {
            Response::Status(info) if info.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(admitted.is_some(), "the joiner was never admitted");
}

#[test]
fn a_fresh_write_converges_with_no_rejoin_and_presence_surfaces_agree() {
    let net = MemNet::new();
    let founder_home = temp_home("f");
    lait::orbital::form_space(&founder_home, &FOUNDER_SEED, "Beacon Space").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), FOUNDER_SEED, net.clone());
    let client = tokio::runtime::Runtime::new().unwrap();
    wait_online(&client, &founder_home);

    let member_home = temp_home("m");
    admit(&client, &member_home, &MEMBER_A_SEED, &founder_home);
    let member_handle = spawn_daemon(member_home.clone(), MEMBER_A_SEED, net.clone());
    wait_online(&client, &member_home);
    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();
    drive_admission(&client, &member_home, &founder_device);

    // ---- Exit criterion 1: steady-state convergence, hands off. ----
    // The founder files a project + issue. NO Connect is issued from here on;
    // the write must reach the member through the plane alone (edge beacon →
    // pending mark → scheduler Contact).
    let resp = req(
        &client,
        &founder_home,
        Request::ProjectNew {
            name: "Beacon".into(),
            key: "bcn".into(),
            color: None,
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "BCN"),
        "{resp:?}"
    );
    let resp = req(
        &client,
        &founder_home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: "Ambient news".into(),
            project: Some("bcn".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: Some("arrived without a re-join".into()),
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "BCN-1"),
        "{resp:?}"
    );

    let started = Instant::now();
    let converged = poll_until(Duration::from_secs(10), || {
        match req(
            &client,
            &member_home,
            Request::IssueView {
                reff: "BCN-1".into(),
            },
        ) {
            Response::Issue(v) if v.title == "Ambient news" => Some(()),
            _ => None,
        }
    });
    assert!(
        converged.is_some(),
        "the founder's write never reached the member without a re-join"
    );
    // Edge-triggered, not interval-bound: well inside one 10 s beacon floor.
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "convergence took a full floor interval — the edge trigger did not fire"
    );

    // And the reverse direction, still hands off.
    req(
        &client,
        &member_home,
        Request::Comment {
            reply_to: None,
            reff: "BCN-1".into(),
            body: "heard you ambiently".into(),
        },
    );
    let back = poll_until(Duration::from_secs(10), || {
        match req(
            &client,
            &founder_home,
            Request::IssueView {
                reff: "BCN-1".into(),
            },
        ) {
            Response::Issue(v) if v.comments.iter().any(|c| c.body == "heard you ambiently") => {
                Some(())
            }
            _ => None,
        }
    });
    assert!(
        back.is_some(),
        "the member's comment never converged back without a re-join"
    );

    // ---- Exit criterion 3: `who` and `status` agree, non-empty. ----
    for home in [&founder_home, &member_home] {
        let Response::Who { peers } = req(&client, home, Request::Who) else {
            panic!("expected Who");
        };
        let Response::Status(info) = req(&client, home, Request::Status) else {
            panic!("expected Status");
        };
        let who_online = peers.iter().filter(|p| p.online).count();
        assert_eq!(
            who_online,
            info.online_peers,
            "who ({peers:?}) and status disagree at {}",
            home.display()
        );
        assert!(
            who_online >= 1,
            "peers exist but presence is empty at {}",
            home.display()
        );
    }

    let _ = req(&client, &member_home, Request::Stop);
    let _ = req(&client, &founder_home, Request::Stop);
    let _ = member_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&member_home);
}

#[test]
fn surviving_members_converge_after_the_approach_station_dies() {
    let net = MemNet::new();
    let founder_home = temp_home("hub");
    lait::orbital::form_space(&founder_home, &FOUNDER_SEED, "Dead Hub Space").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), FOUNDER_SEED, net.clone());
    let client = tokio::runtime::Runtime::new().unwrap();
    wait_online(&client, &founder_home);
    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();

    // Two members, admitted one after the other through the founder.
    let a_home = temp_home("a");
    admit(&client, &a_home, &MEMBER_A_SEED, &founder_home);
    let a_handle = spawn_daemon(a_home.clone(), MEMBER_A_SEED, net.clone());
    wait_online(&client, &a_home);
    drive_admission(&client, &a_home, &founder_device);

    let b_home = temp_home("b");
    admit(&client, &b_home, &MEMBER_B_SEED, &founder_home);
    let b_handle = spawn_daemon(b_home.clone(), MEMBER_B_SEED, net.clone());
    wait_online(&client, &b_home);
    drive_admission(&client, &b_home, &founder_device);

    // A must learn B's membership (authority news travels the same plane)
    // before the hub dies, so B's beacons pass A's eclipse fence.
    let a_knows_b = poll_until(Duration::from_secs(15), || {
        match req(&client, &a_home, Request::Members) {
            Response::Members { members } if members.len() >= 3 => Some(()),
            _ => None,
        }
    });
    assert!(
        a_knows_b.is_some(),
        "A never learned B's admission over the plane"
    );

    // ---- Exit criterion 2: kill the hub; survivors keep converging. ----
    let _ = req(&client, &founder_home, Request::Stop);
    let _ = founder_handle.join();

    let resp = req(
        &client,
        &b_home,
        Request::ProjectNew {
            name: "Orphaned".into(),
            key: "orp".into(),
            color: None,
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "ORP"),
        "{resp:?}"
    );
    let resp = req(
        &client,
        &b_home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: "The hub is gone".into(),
            project: Some("orp".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "ORP-1"),
        "{resp:?}"
    );

    let survived = poll_until(Duration::from_secs(15), || {
        match req(
            &client,
            &a_home,
            Request::IssueView {
                reff: "ORP-1".into(),
            },
        ) {
            Response::Issue(v) if v.title == "The hub is gone" => Some(()),
            _ => None,
        }
    });
    assert!(
        survived.is_some(),
        "B's write never reached A once the approach station died — the space partitioned"
    );

    let _ = req(&client, &a_home, Request::Stop);
    let _ = req(&client, &b_home, Request::Stop);
    let _ = a_handle.join();
    let _ = b_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&b_home);
}
