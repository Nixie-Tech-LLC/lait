//! End-to-end tests for control-plane dirty notifications and `Reset`
//! recovery. See `docs/PROTOCOL.md`.
//!
//! These drive the **real** daemon binary (`CARGO_BIN_EXE_lait daemon`)
//! over the actual local IPC control channel — a Unix-domain socket on unix, a
//! named pipe on Windows — using the crate's own [`lait::control`] client.
//! Each test gets a fresh `LAIT_HOME` and `LAIT_IDLE_SECS=0`, so the
//! daemon never naps out from under the subscription.
//!
//! The daemon binds an iroh endpoint and waits for a relay to come online before
//! it serves the control channel (`endpoint.online().await`). In a network-
//! isolated sandbox that never completes, so [`Daemon::spawn`] gives up after a
//! bounded wait and the test fails loudly rather than hanging — see the module
//! header note if you need to `#[ignore]` these in such an environment. The pure
//! ring-overrun decision (`node::subscribe_should_reset`) is unit-tested
//! separately (`cargo test --lib node::`) and needs no network.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use lait::control::{request, subscribe, Request, Response};

/// A throwaway `LAIT_HOME` that deletes itself on drop.
struct TempHome {
    path: PathBuf,
}

impl TempHome {
    fn new() -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let uniq = format!(
            "gc-e2e-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0),
            COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        let path = std::env::temp_dir().join(uniq);
        std::fs::create_dir_all(&path).expect("create temp home");
        TempHome { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A running daemon process, killed on drop as a safety net (tests also send a
/// graceful `Stop`).
struct Daemon {
    child: Child,
}

impl Daemon {
    /// Spawn the real daemon binary against `home` and wait until it serves the
    /// control channel. Errors if it never comes online within the budget (e.g.
    /// no network for the iroh relay handshake).
    async fn spawn(home: &Path) -> anyhow::Result<Self> {
        let exe = env!("CARGO_BIN_EXE_lait");
        let child = Command::new(exe)
            .arg("daemon")
            .env("LAIT_HOME", home)
            // Isolate the workspace registry per node: the daemon-boot upsert must land
            // in a scratch config root, never the developer's real workspaces.json.
            .env("LAIT_CONFIG_ROOT", home.join("cfgroot"))
            .env("LAIT_IDLE_SECS", "0")
            // Fast heartbeat: keep presence/announce catch-up snappy in tests.
            .env("LAIT_HEARTBEAT_SECS", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        let mut daemon = Daemon { child };

        // Up to ~30s: the daemon binds an iroh endpoint + waits for a relay
        // before it begins serving the control socket.
        for _ in 0..150 {
            if let Some(status) = daemon.child.try_wait()? {
                anyhow::bail!("daemon exited early with status {status}");
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
            if request(home, &Request::Status).await.is_ok() {
                return Ok(daemon);
            }
        }
        anyhow::bail!("daemon did not come online in time (no network for the iroh relay?)");
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Found a workspace in `home` in-process, using the SAME identity the daemon
/// will load (`<home>/secret.key`, since the daemon runs with `LAIT_HOME=home`).
/// Workspaces are never minted lazily anymore — a daemon errors on an
/// uninitialized store — so every home is founded before its daemon spawns.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::crypto::user_from_seed(&key);
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::found_workspace(&store, &me, &key, "test", &lait::ids::SystemUlidSource)
        .expect("found workspace");
}

/// Seed a project + one issue and return the issue's canonical ref (e.g.
/// `ENG-1`). Exercises the tracker mutation path that feeds the doorbell.
async fn seed_project_and_issue(home: &Path) -> String {
    let resp = request(
        home,
        &Request::ProjectNew {
            name: "Eng".into(),
            key: "ENG".into(),
        },
    )
    .await
    .expect("projects new");
    assert!(
        matches!(resp, Response::Ref { .. }),
        "projects new should echo a Ref, got {resp:?}"
    );

    let resp = request(
        home,
        &Request::IssueNew {
            title: "t1".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    )
    .await
    .expect("issue new");
    match resp {
        Response::Ref { reff } => reff,
        other => panic!("issue new should echo a Ref, got {other:?}"),
    }
}

/// A deliberately-stale `since` must not cause silent deafness: the daemon
/// always rebaselines a new Subscribe with a `Reset` first frame at the current
/// sequence, and a subsequent live edit then rings a real, non-reset
/// doorbell whose dirty-set names the touched project.
#[tokio::test]
async fn stale_since_after_restart_yields_reset() {
    let home = TempHome::new();
    found_home(home.path());
    let _daemon = Daemon::spawn(home.path())
        .await
        .expect("daemon should come online");

    let reff = seed_project_and_issue(home.path()).await;

    // A wildly stale `since` — this must NOT make the stream deaf.
    let mut sub = subscribe(home.path(), 999_999)
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

    // A live edit rings a real doorbell: non-reset, with a non-empty project
    // dirty-set naming the edited issue's project.
    let resp = request(
        home.path(),
        &Request::IssueEdit {
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
        !ring.dirty_by_project.is_empty(),
        "the edit doorbell must carry a non-empty dirty-by-project set, got {ring:?}"
    );

    let _ = request(home.path(), &Request::Stop).await;
}

/// A rejected write rings nothing: validate-then-commit means an
/// invalid `IssueEdit` returns an `Error` having touched nothing and produced no
/// dirty-set, so no doorbell arrives. We drain the initial Reset, send a bad
/// status, and assert the stream stays silent for a grace window.
#[tokio::test]
async fn validate_then_commit_rings_no_doorbell() {
    let home = TempHome::new();
    found_home(home.path());
    let _daemon = Daemon::spawn(home.path())
        .await
        .expect("daemon should come online");

    let reff = seed_project_and_issue(home.path()).await;

    let mut sub = subscribe(home.path(), 0)
        .await
        .expect("open subscribe stream");

    // Drain the initial Reset frame.
    let first = sub
        .next()
        .await
        .expect("read first frame")
        .expect("first frame present");
    assert!(first.reset, "first Subscribe frame must be a Reset");

    // An invalid status is rejected pre-commit.
    let resp = request(
        home.path(),
        &Request::IssueEdit {
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
    match tokio::time::timeout(Duration::from_millis(300), sub.next()).await {
        Err(_elapsed) => { /* good: the stream stayed silent */ }
        Ok(Ok(Some(db))) => panic!("a rejected write rang a doorbell: {db:?}"),
        Ok(Ok(None)) => panic!("subscription closed unexpectedly (daemon gone?)"),
        Ok(Err(e)) => panic!("subscription read errored: {e:#}"),
    }

    let _ = request(home.path(), &Request::Stop).await;
}
