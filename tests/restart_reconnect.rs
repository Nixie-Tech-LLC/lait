//! DUR-1 end-to-end: a daemon that is killed and restarted must actively rejoin
//! the gossip mesh from its persisted peer set (`peers.json`) instead of sitting
//! idle waiting to be re-announced to, and reconverge with a peer that kept
//! running the whole time.
//!
//! Before DUR-1, `run_daemon` re-subscribed to the room topic with an EMPTY
//! bootstrap list and presence was in-memory only, so a restarted node could
//! only rejoin if a still-live peer happened to redial it. This test kills B,
//! files a new issue on A while B is down, restarts B on the SAME home, and
//! asserts B — using only the peers it persisted before the crash — reconnects
//! and converges to the post-restart issue.
//!
//! Like `two_node_sync.rs` this drives the real iroh stack over the Layer-B
//! control channel; convergence timing over discovery/relay is variable, so the
//! polls are generous. If the sandbox blocks iroh the daemons never come online
//! and the test fails at setup with a clear message rather than passing silently.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lait::control::{request, Filter, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

/// A current-thread runtime: each `req` is a single control-channel round trip, so
/// building the default multi-thread runtime (worker-thread pool) per call — often
/// hundreds of times over a tight poll — is pure churn. Far cheaper to build.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Poll `check` immediately, then every 50 ms, until it yields `Some` or `timeout`
/// elapses (returns `None`). Returning the instant the condition holds keeps a
/// fast-converging case in the millisecond range instead of burning whole ticks.
fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tmp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "gc-restart-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A running daemon whose process is killed on drop, so a failed assert (panic)
/// still reaps the child instead of leaking it — a leaked daemon keeps the test
/// harness's stdout pipe open and looks like a hang. `stop()` kills it early
/// without wiping the home, so the same store can be respawned (the restart).
struct Proc(Option<Child>);

impl Proc {
    fn stop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

impl Drop for Proc {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Spawn a daemon on `home` and wait until its control channel answers.
#[allow(clippy::zombie_processes)] // Proc kills+waits on drop
fn spawn(home: &Path) -> Proc {
    let child = Command::new(bin())
        .arg("daemon")
        .env("LAIT_HOME", home)
        // Isolate the workspace registry per node: the daemon-boot upsert must land
        // in a scratch config root, never the developer's real workspaces.json.
        .env("LAIT_CONFIG_ROOT", home.join("cfgroot"))
        // Disable idle shutdown so the restart, not a timer, is what we test.
        .env("LAIT_IDLE_SECS", "0")
        // Run the protocol on a fast heartbeat so catch-up/absence windows are
        // seconds, not the 10s production default — the pipeline's biggest lever.
        .env("LAIT_HEARTBEAT_SECS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let rt = rt();
    let online = poll_until(Duration::from_secs(30), || {
        rt.block_on(async { request(home, &Request::Status).await })
            .ok()
    });
    if online.is_some() {
        return Proc(Some(child));
    }
    let mut c = child;
    let _ = c.kill();
    let _ = c.wait();
    panic!("daemon for {} never came online", home.display());
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn id_of(home: &Path) -> String {
    match req(home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("id returned {other:?}"),
    }
}

fn list_titles(home: &Path) -> Vec<String> {
    match req(
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

fn poll_title(home: &Path, needle: &str, timeout: Duration) -> bool {
    poll_until(timeout, || {
        list_titles(home).iter().any(|t| t == needle).then_some(())
    })
    .is_some()
}

/// Poll until `peers.json` under `home` records `id` (written when the mesh forms
/// / on the first successful pull — DUR-1).
fn poll_peer_persisted(home: &Path, id: &str, timeout: Duration) -> bool {
    poll_until(timeout, || {
        std::fs::read_to_string(home.join("peers.json"))
            .unwrap_or_default()
            .contains(id)
            .then_some(())
    })
    .is_some()
}

/// Found a workspace in `home` in-process, using the SAME identity the daemon
/// will load (`<home>/secret.key`, since the daemon runs with `LAIT_HOME=home`).
/// Workspaces are never minted lazily anymore — a daemon errors on an
/// uninitialized store — so every founder home goes through this first.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::ids::UserId::from_key_string(key.public().to_string());
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::found_workspace(&store, &me, "test", &lait::ids::SystemUlidSource)
        .expect("found workspace");
}

/// Bootstrap a joiner store from a ticket (the client half of `lait join`), so
/// its daemon boots already bound to the host's workspace — the daemon-side
/// Connect/Join no longer adopts a foreign workspace. Restarts are unaffected:
/// the store stays initialized.
fn join_home(home: &Path, ticket: &str) {
    let t: lait::proto::WorkspaceTicket = ticket.parse().expect("parse ticket");
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::join_workspace_store(&store, &t.workspace, &t.host.to_string())
        .expect("bootstrap joiner store");
}

fn new_issue(home: &Path, title: &str) -> Response {
    req(
        home,
        Request::IssueNew {
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
fn restarted_daemon_rejoins_from_persisted_peers() {
    let a_home = tmp_home("a");
    let b_home = tmp_home("b");
    found_home(&a_home);
    let a = spawn(&a_home);

    // A (the founder) adds a project and files the first issue.
    assert!(
        matches!(
            req(
                &a_home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                }
            ),
            Response::Ref { .. }
        ),
        "A: projects new"
    );
    assert!(
        matches!(new_issue(&a_home, "before restart"), Response::Ref { .. }),
        "A: first issue"
    );

    // B bootstraps its store from A's ticket BEFORE its daemon first starts,
    // then connects, and A grants B membership so B can decrypt.
    let ticket = match req(
        &a_home,
        Request::Invite {
            require_approval: true,
            reusable: false,
            ttl_hours: None,
        },
    ) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
    join_home(&b_home, &ticket);
    let mut b = spawn(&b_home);
    assert!(
        matches!(
            req(&b_home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: connect"
    );
    let b_id = id_of(&b_home);
    assert!(
        matches!(
            req(
                &a_home,
                Request::MemberAdd {
                    who: b_id,
                    admin: false,
                    as_name: None
                }
            ),
            Response::Ok { .. }
        ),
        "A: member add B"
    );

    // Prove the mesh formed and B synced A's first issue.
    assert!(
        poll_title(&b_home, "before restart", Duration::from_secs(80)),
        "pre-restart: B did not converge to A's first issue"
    );

    // DUR-1 precondition: B persisted A's endpoint as a bootstrap peer.
    let a_id = id_of(&a_home);
    assert!(
        poll_peer_persisted(&b_home, &a_id, Duration::from_secs(20)),
        "B should persist A ({a_id}) in peers.json for restart bootstrap"
    );

    // Crash B (kill, not a graceful stop) — its home/store survive.
    b.stop();

    // While B is down, A files a new issue under the same epoch key.
    assert!(
        matches!(new_issue(&a_home, "after B restart"), Response::Ref { .. }),
        "A: post-restart issue"
    );

    // Restart B on the SAME home. With DUR-1 it bootstraps gossip from peers.json
    // (A's id) and actively redials A; without it, B would wait to be re-announced
    // to and never converge here.
    b = spawn(&b_home);
    assert!(
        poll_title(&b_home, "after B restart", Duration::from_secs(90)),
        "post-restart: B did not rejoin the mesh from persisted peers and converge"
    );

    // Explicit teardown (Drop would also handle it on panic).
    b.stop();
    drop(a);
    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&b_home);
}
