//! End-to-end tests for control-plane dirty notifications and `Reset`
//! recovery, driven through the **orbital daemon** over its real IPC control
//! socket with an in-memory transport (no network sockets). See
//! `docs/PROTOCOL.md`.
//!
//! Formation is `orbital::form_space` (the `lait init` heir); the orbital daemon
//! then serves `control::Request`/`Response` — including the `Subscribe`
//! doorbell stream sourced from the Station's `ObservationStream` — exactly as
//! the CLI/serve/MCP clients speak it. Two behaviors are proven: a wildly stale
//! `since` still rebaselines with a `Reset` first frame and a later live edit
//! rings a real (non-reset) doorbell; and a rejected write (validate-then-commit)
//! rings nothing at all.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, subscribe, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [113u8; 32];

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
    let dir = std::env::temp_dir().join(format!("lait-ctrl-{tag}-{}-{n}", std::process::id()));
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

/// Seed a project + one issue and return the issue's canonical ref (e.g.
/// `ENG-1`). Exercises the World submit path that feeds the doorbell.
fn seed_project_and_issue(rt: &tokio::runtime::Runtime, home: &Path) -> String {
    let resp = req(
        rt,
        home,
        Request::ProjectNew {
            name: "Eng".into(),
            key: "ENG".into(),
            color: None,
        },
    );
    assert!(
        matches!(resp, Response::Ref { .. }),
        "projects new should echo a Ref, got {resp:?}"
    );
    let resp = req(
        rt,
        home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: "t1".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    );
    match resp {
        Response::Ref { reff } => reff,
        other => panic!("issue new should echo a Ref, got {other:?}"),
    }
}

/// A deliberately-stale `since` must not cause silent deafness: the daemon
/// always rebaselines a new Subscribe with a `Reset` first frame at the current
/// sequence, and a subsequent live edit then rings a real, non-reset doorbell.
#[test]
fn stale_since_after_restart_yields_reset() {
    let net = MemNet::new();
    let home = temp_home("stale");
    lait::orbital::form_space(&home, &FOUNDER_SEED, "Ctrl Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    let reff = seed_project_and_issue(&rt, &home);

    rt.block_on(async {
        // A wildly stale `since` — this must NOT make the stream deaf.
        let mut sub = subscribe(&home, 999_999)
            .await
            .expect("open subscribe stream");

        // First frame is ALWAYS a Reset (rebaseline from a fresh snapshot).
        let first = sub
            .next()
            .await
            .expect("read first frame")
            .expect("first frame present");
        assert!(
            first.reset,
            "first Subscribe frame must be a Reset even for a stale since, got {first:?}"
        );

        // A live edit rings a real doorbell: non-reset, advancing activity.
        let resp = request(
            &home,
            &Request::IssueEdit {
                due: None,
                estimate: None,
                reff: reff.clone(),
                title: None,
                status: Some("in_progress".into()),
                priority: None,
                description: None,
            },
        )
        .await
        .expect("issue edit");
        assert!(
            matches!(resp, Response::Ref { .. }),
            "valid edit should echo a Ref, got {resp:?}"
        );

        let ring = sub
            .next()
            .await
            .expect("read edit doorbell")
            .expect("edit doorbell present");
        assert!(
            !ring.reset,
            "a live edit should ring a normal (non-reset) doorbell, got {ring:?}"
        );
        assert!(
            ring.activity_advanced,
            "the edit doorbell must advance activity, got {ring:?}"
        );

        let _ = request(&home, &Request::Stop).await;
    });

    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}

/// A rejected write rings nothing: validate-then-commit means an invalid
/// `IssueEdit` returns an `Error` having touched nothing and produced no
/// dirty-set, so no doorbell arrives. We drain the initial Reset, send a bad
/// status, and assert the stream stays silent for a grace window.
#[test]
fn validate_then_commit_rings_no_doorbell() {
    let net = MemNet::new();
    let home = temp_home("reject");
    lait::orbital::form_space(&home, &FOUNDER_SEED, "Ctrl Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    let reff = seed_project_and_issue(&rt, &home);

    rt.block_on(async {
        let mut sub = subscribe(&home, 0).await.expect("open subscribe stream");

        // Drain the initial Reset frame.
        let first = sub
            .next()
            .await
            .expect("read first frame")
            .expect("first frame present");
        assert!(first.reset, "first Subscribe frame must be a Reset");

        // An invalid status is rejected pre-commit.
        let resp = request(
            &home,
            &Request::IssueEdit {
                due: None,
                estimate: None,
                reff: reff.clone(),
                title: None,
                status: Some("definitely-not-a-status".into()),
                priority: None,
                description: None,
            },
        )
        .await
        .expect("issue edit request round-trips");
        assert!(
            matches!(resp, Response::Error { .. }),
            "an invalid status must be rejected, got {resp:?}"
        );

        // No doorbell must arrive for the rejected write. The only acceptable
        // outcome is the read timing out (nothing rang).
        match tokio::time::timeout(Duration::from_millis(400), sub.next()).await {
            Err(_elapsed) => { /* good: the stream stayed silent */ }
            Ok(Ok(Some(db))) => panic!("a rejected write rang a doorbell: {db:?}"),
            Ok(Ok(None)) => panic!("subscription closed unexpectedly (daemon gone?)"),
            Ok(Err(e)) => panic!("subscription read errored: {e:#}"),
        }

        let _ = request(&home, &Request::Stop).await;
    });

    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}
