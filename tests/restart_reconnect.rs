//! Restart durability over the **orbital daemon** (in-process, in-memory
//! transport): a joiner that is admitted and converged, then has its daemon
//! killed and restarted on the SAME home, must come back holding its persisted
//! membership and reconverge with a peer that files new content while it was
//! down.
//!
//! `orbital_two_node.rs` proves the cold form → invite → enter → admit →
//! converge arc. This adds the restart in the middle: after admission, the
//! joiner daemon is dropped, the founder files a new issue, and the joiner
//! daemon is respawned on its persisted store. It must re-dock from persisted
//! membership and, once Contact is re-driven, converge to the post-restart
//! issue — proving the orbital store survives a crash and rejoins.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Filter, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [151u8; 32];
const JOINER_SEED: [u8; 32] = [152u8; 32];

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
    let dir = std::env::temp_dir().join(format!("lait-restart-{tag}-{}-{n}", std::process::id()));
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

fn list_titles(rt: &tokio::runtime::Runtime, home: &Path) -> Vec<String> {
    match req(
        rt,
        home,
        Request::List {
            project: None,
            filter: Filter::default(),
        },
    ) {
        Response::List { rows } => rows.into_iter().map(|r| r.title).collect(),
        _ => Vec::new(),
    }
}

fn new_issue(rt: &tokio::runtime::Runtime, home: &Path, title: &str) -> Response {
    req(
        rt,
        home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: title.into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    )
}

#[test]
fn restarted_joiner_daemon_reconverges_from_its_persisted_store() {
    let net = MemNet::new();

    // Founder: form, seed a project + first issue, mint an auto-approving invite.
    let founder_home = temp_home("founder");
    lait::orbital::found_space_cli(&founder_home, &FOUNDER_SEED, "Restart Space").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &founder_home);

    assert!(
        matches!(
            req(
                &rt,
                &founder_home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                    color: None,
                }
            ),
            Response::Ref { .. }
        ),
        "founder: projects new"
    );
    assert!(
        matches!(
            new_issue(&rt, &founder_home, "before restart"),
            Response::Ref { .. }
        ),
        "founder: first issue"
    );

    let Response::Ref { reff: invite } = req(
        &rt,
        &founder_home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };

    // Joiner: bootstrap the store from the invite, serve, drive admission.
    let joiner_home = temp_home("joiner");
    lait::orbital::enter_space(&joiner_home, &JOINER_SEED, &invite).unwrap();
    let mut joiner_handle = Some(spawn_daemon(joiner_home.clone(), JOINER_SEED, net.clone()));
    wait_online(&rt, &joiner_home);

    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();
    let joiner_device = lait::crypto::device_from_seed(&JOINER_SEED).to_string();

    let drive_contact = |rt: &tokio::runtime::Runtime| {
        req(
            rt,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
        req(
            rt,
            &founder_home,
            Request::Connect {
                ticket: joiner_device.clone(),
            },
        );
        req(
            rt,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
    };

    let admitted = poll_until(Duration::from_secs(20), || {
        drive_contact(&rt);
        match req(&rt, &joiner_home, Request::Status) {
            Response::Status(info) if info.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(admitted.is_some(), "the joiner was never admitted");

    // The joiner converges the founder's pre-restart issue.
    assert!(
        poll_until(Duration::from_secs(20), || {
            drive_contact(&rt);
            list_titles(&rt, &joiner_home)
                .iter()
                .any(|t| t == "before restart")
                .then_some(())
        })
        .is_some(),
        "pre-restart: the joiner did not converge to the founder's first issue"
    );

    // Crash the joiner (kill its daemon thread) — its home/store survive.
    let _ = req(&rt, &joiner_home, Request::Stop);
    let _ = joiner_handle.take().unwrap().join();

    // While the joiner is down, the founder files a new issue under the same key.
    assert!(
        matches!(
            new_issue(&rt, &founder_home, "after restart"),
            Response::Ref { .. }
        ),
        "founder: post-restart issue"
    );

    // Restart the joiner on the SAME home. It re-docks from its persisted
    // membership (no re-admission) and, once Contact is re-driven, reconverges.
    let joiner_handle = spawn_daemon(joiner_home.clone(), JOINER_SEED, net.clone());
    wait_online(&rt, &joiner_home);

    // It comes back already a member — membership is persisted, not re-earned.
    match req(&rt, &joiner_home, Request::Status) {
        Response::Status(info) => assert_eq!(
            info.membership, "member",
            "the restarted joiner must reload its membership from the persisted store"
        ),
        other => panic!("status returned {other:?}"),
    }

    assert!(
        poll_until(Duration::from_secs(25), || {
            drive_contact(&rt);
            list_titles(&rt, &joiner_home)
                .iter()
                .any(|t| t == "after restart")
                .then_some(())
        })
        .is_some(),
        "post-restart: the joiner did not rejoin and converge to the founder's new issue"
    );

    let _ = req(&rt, &joiner_home, Request::Stop);
    let _ = req(&rt, &founder_home, Request::Stop);
    let _ = joiner_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&joiner_home);
}
