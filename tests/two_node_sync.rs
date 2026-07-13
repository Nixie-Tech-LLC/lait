//! P1 end-to-end: two real nodes converge live over iroh P2P (A§8), no central
//! server. Pre-spawns two `lait` daemons on distinct `LAIT_HOME`s and
//! drives them **directly over the Layer-B control channel** (`control::request`)
//! — never shelling out to the CLI, so a captured child process can't inherit a
//! pipe and block. An issue created on one node must appear on the other, both
//! directions, via the catalog-first sync protocol.
//!
//! This exercises the real network stack; convergence timing over iroh is
//! variable (discovery/relay), so the polls are generous. If the sandbox blocks
//! iroh the daemons never bind their control channel and the test fails at setup
//! with a clear message rather than silently passing.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lait::control::{request, Filter, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

/// The heartbeat the spawned daemons run on (via `LAIT_HEARTBEAT_SECS`). Absence-
/// proof settling windows are expressed as multiples of this, so they stay sound
/// if the test clock changes. The single source of truth for both.
const TEST_HEARTBEAT: Duration = Duration::from_secs(1);

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
        "gc-2node-{}-{}-{}",
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

/// A running daemon, killed on drop so a failed assert still cleans up.
struct Daemon {
    child: Child,
    home: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[allow(clippy::zombie_processes)] // the returned Daemon kills+waits on drop
fn spawn_daemon(home: &Path) -> Daemon {
    let mut child = Command::new(bin())
        .arg("daemon")
        .env("LAIT_HOME", home)
        .env("LAIT_IDLE_SECS", "0")
        // Run the protocol on a fast heartbeat so catch-up/absence windows are
        // seconds, not the 10s production default — the pipeline's biggest lever.
        .env("LAIT_HEARTBEAT_SECS", TEST_HEARTBEAT.as_secs().to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    // wait up to ~30s for the daemon to bind its control channel + come online.
    let rt = rt();
    let online = poll_until(Duration::from_secs(30), || {
        rt.block_on(async { request(home, &Request::Status).await })
            .ok()
    });
    if online.is_some() {
        return Daemon {
            child,
            home: home.to_path_buf(),
        };
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon for {} never came online", home.display());
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
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

/// Resolve the canonical ref for the row with `title` on this node.
fn row_ref(home: &Path, title: &str) -> Option<String> {
    match req(
        home,
        Request::List {
            project: None,
            filter: Filter::default(),
        },
    ) {
        Response::List { rows } => rows.into_iter().find(|r| r.title == title).map(|r| r.reff),
        _ => None,
    }
}

/// Poll until the issue DOC (not just the catalog row) has synced — i.e. its
/// `description`/body is present and the view is no longer provisional. This is
/// the assertion the catalog-only `list_titles` check cannot make: the body
/// lives ONLY in the issue doc, so it proves the doc transferred.
fn poll_body(home: &Path, reff: &str, needle: &str, timeout: Duration) -> bool {
    poll_until(timeout, || {
        match req(
            home,
            Request::IssueView {
                reff: reff.to_string(),
            },
        ) {
            Response::Issue(v) if !v.provisional && v.description.contains(needle) => Some(()),
            _ => None,
        }
    })
    .is_some()
}

#[test]
fn two_nodes_converge_over_iroh() {
    let a_home = tmp_home("a");
    let b_home = tmp_home("b");
    let a = spawn_daemon(&a_home);
    let b = spawn_daemon(&b_home);

    // Node A founds the workspace and files an issue.
    assert!(
        matches!(
            req(
                &a.home,
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
        matches!(
            req(
                &a.home,
                Request::IssueNew {
                    title: "shared from A".into(),
                    project: Some("ENG".into()),
                    assignees: vec![],
                    priority: Some("high".into()),
                    labels: vec![],
                    // A body lives ONLY in the issue doc (never in the catalog
                    // row) — so asserting B receives it proves the issue DOCUMENT
                    // synced, not just the catalog cache.
                    body: Some("BODY_A: only-in-the-issue-doc contents".into()),
                }
            ),
            Response::Ref { .. }
        ),
        "A: new"
    );

    // A mints a ticket (carrying its workspace id) and B connects.
    let ticket = match req(&a.home, Request::Invite) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
    assert!(!ticket.is_empty(), "ticket should be non-empty");
    assert!(
        matches!(
            req(&b.home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: connect"
    );

    // Workspace data is E2EE (P3): B can't read until A adds it to the ACL and
    // seals it the workspace key. Rather than blind-sleep, wait until B has
    // actually connected to A (a real sync opportunity) — a positive proxy that's
    // both faster and more rigorous than a fixed pause — plus a small settling
    // margin for the pull to complete, then confirm B still sees only ciphertext.
    let connected = poll_until(Duration::from_secs(30), || {
        match req(&b.home, Request::Status) {
            Response::Status(s) if s.online_peers >= 1 => Some(()),
            _ => None,
        }
    });
    assert!(
        connected.is_some(),
        "B never connected to A — cannot make a meaningful pre-add E2EE assertion"
    );
    std::thread::sleep(Duration::from_secs(2));
    assert!(
        list_titles(&b.home).is_empty(),
        "a non-member must see only ciphertext (no readable issues) before being added"
    );

    // Grant B membership by its endpoint id.
    let b_id = match req(&b.home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("B: id returned {other:?}"),
    };
    assert!(
        matches!(
            req(
                &a.home,
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

    // A -> B: B backfills the membership (unseals the key), then decrypts A's
    // issue over the encrypted sync.
    assert!(
        poll_title(&b.home, "shared from A", Duration::from_secs(80)),
        "A→B: B did not converge to A's issue over encrypted P2P sync"
    );

    // Regression (validation-found): the catalog row above can converge from the
    // catalog cache alone while the issue DOCUMENT never transfers. Assert B also
    // receives the issue doc BODY — this fails if the sync connection is torn down
    // before the trailing DocUpdate/EndDocs frames drain (see node.rs SyncHandler).
    let a_ref = row_ref(&b.home, "shared from A").expect("B has a row for A's issue");
    assert!(
        poll_body(&b.home, &a_ref, "BODY_A", Duration::from_secs(60)),
        "A→B: catalog row converged but the issue-doc BODY never synced (doc-frame truncation)"
    );

    // B -> A: a fresh issue on B propagates back to A.
    assert!(
        matches!(
            req(
                &b.home,
                Request::IssueNew {
                    title: "reply from B".into(),
                    project: Some("ENG".into()),
                    assignees: vec![],
                    priority: None,
                    labels: vec![],
                    body: None,
                }
            ),
            Response::Ref { .. }
        ),
        "B: new"
    );
    assert!(
        poll_title(&a.home, "reply from B", Duration::from_secs(60)),
        "B→A: A did not converge to B's issue over P2P sync"
    );

    // Lazy revocation (P3): A removes B (rotating the key), then files new
    // content. B keeps what it already synced but must NOT be able to read the
    // post-removal issue (encrypted under an epoch key B never receives).
    let b_id2 = match req(&b.home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        _ => String::new(),
    };
    assert!(
        matches!(
            req(&a.home, Request::MemberRemove { who: b_id2 }),
            Response::Ok { .. }
        ),
        "A: member remove B"
    );
    assert!(
        matches!(
            req(
                &a.home,
                Request::IssueNew {
                    title: "post-removal secret".into(),
                    project: Some("ENG".into()),
                    assignees: vec![],
                    priority: None,
                    labels: vec![],
                    body: None,
                }
            ),
            Response::Ref { .. }
        ),
        "A: post-removal issue"
    );
    // Intentional settling window (not a pollable condition): this is an
    // *absence* proof — a removed member must never read post-removal content — so
    // there is no positive signal to wait on. A already announced the write live
    // (event-driven), so B has had its immediate chance; wait several fast-heartbeat
    // catch-up cycles (LAIT_HEARTBEAT_SECS=1) as belt-and-suspenders, then assert B
    // still cannot see it. Scales with the heartbeat, so it stays sound if the clock
    // changes.
    std::thread::sleep(3 * TEST_HEARTBEAT);
    assert!(
        !list_titles(&b.home)
            .iter()
            .any(|t| t == "post-removal secret"),
        "lazy revocation: a removed member must not read post-removal content"
    );

    drop(a);
    drop(b);
}
