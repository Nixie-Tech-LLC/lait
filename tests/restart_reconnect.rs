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
use std::time::Duration;

use groupchat::control::{request, Filter, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_groupchat")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
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
        .env("GROUPCHAT_HOME", home)
        // Disable idle shutdown so the restart, not a timer, is what we test.
        .env("GROUPCHAT_IDLE_SECS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let rt = rt();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        if rt
            .block_on(async { request(home, &Request::Status).await })
            .is_ok()
        {
            return Proc(Some(child));
        }
    }
    let mut c = child;
    let _ = c.kill();
    let _ = c.wait();
    panic!("daemon for {} never came online", home.display());
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::Error {
            message: format!("{e:#}"),
        })
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

fn poll_title(home: &Path, needle: &str, tries: u32) -> bool {
    for _ in 0..tries {
        std::thread::sleep(Duration::from_secs(2));
        if list_titles(home).iter().any(|t| t == needle) {
            return true;
        }
    }
    false
}

/// Poll until `peers.json` under `home` records `id` (written when the mesh forms
/// / on the first successful pull — DUR-1).
fn poll_peer_persisted(home: &Path, id: &str, tries: u32) -> bool {
    for _ in 0..tries {
        let j = std::fs::read_to_string(home.join("peers.json")).unwrap_or_default();
        if j.contains(id) {
            return true;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    false
}

fn new_issue(home: &Path, title: &str) -> Response {
    req(
        home,
        Request::IssueNew {
            title: title.into(),
            project: Some("ENG".into()),
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
    let a = spawn(&a_home);
    let mut b = spawn(&b_home);

    // A founds the workspace and files the first issue.
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

    // B connects via A's ticket, and A grants B membership so B can decrypt.
    let ticket = match req(&a_home, Request::Invite) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
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
                    admin: false
                }
            ),
            Response::Ok { .. }
        ),
        "A: member add B"
    );

    // Prove the mesh formed and B synced A's first issue.
    assert!(
        poll_title(&b_home, "before restart", 40),
        "pre-restart: B did not converge to A's first issue"
    );

    // DUR-1 precondition: B persisted A's endpoint as a bootstrap peer.
    let a_id = id_of(&a_home);
    assert!(
        poll_peer_persisted(&b_home, &a_id, 20),
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
        poll_title(&b_home, "after B restart", 45),
        "post-restart: B did not rejoin the mesh from persisted peers and converge"
    );

    // Explicit teardown (Drop would also handle it on panic).
    b.stop();
    drop(a);
    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&b_home);
}
