//! P1 end-to-end: two real nodes converge live over iroh P2P (A§8), no central
//! server. Pre-spawns two `groupchat` daemons on distinct `GROUPCHAT_HOME`s and
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
        .env("GROUPCHAT_HOME", home)
        .env("GROUPCHAT_IDLE_SECS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    // wait up to ~30s for the daemon to bind its control channel + come online.
    let rt = rt();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        if rt
            .block_on(async { request(home, &Request::Status).await })
            .is_ok()
        {
            return Daemon {
                child,
                home: home.to_path_buf(),
            };
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon for {} never came online", home.display());
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::Error {
            message: format!("{e:#}"),
        })
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
fn poll_body(home: &Path, reff: &str, needle: &str, tries: u32) -> bool {
    for _ in 0..tries {
        std::thread::sleep(Duration::from_secs(2));
        if let Response::Issue(v) = req(
            home,
            Request::IssueView {
                reff: reff.to_string(),
            },
        ) {
            if !v.provisional && v.description.contains(needle) {
                return true;
            }
        }
    }
    false
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
    // seals it the workspace key. Give the membership a moment to sync, then
    // confirm B sees only ciphertext (no decryptable issues) — the E2EE outcome.
    std::thread::sleep(Duration::from_secs(6));
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
                    admin: false
                }
            ),
            Response::Ok { .. }
        ),
        "A: member add B"
    );

    // A -> B: B backfills the membership (unseals the key), then decrypts A's
    // issue over the encrypted sync.
    assert!(
        poll_title(&b.home, "shared from A", 40),
        "A→B: B did not converge to A's issue over encrypted P2P sync"
    );

    // Regression (validation-found): the catalog row above can converge from the
    // catalog cache alone while the issue DOCUMENT never transfers. Assert B also
    // receives the issue doc BODY — this fails if the sync connection is torn down
    // before the trailing DocUpdate/EndDocs frames drain (see node.rs SyncHandler).
    let a_ref = row_ref(&b.home, "shared from A").expect("B has a row for A's issue");
    assert!(
        poll_body(&b.home, &a_ref, "BODY_A", 30),
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
        poll_title(&a.home, "reply from B", 30),
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
    // give sync ample time; B must still not see it.
    std::thread::sleep(Duration::from_secs(10));
    assert!(
        !list_titles(&b.home)
            .iter()
            .any(|t| t == "post-removal secret"),
        "lazy revocation: a removed member must not read post-removal content"
    );

    drop(a);
    drop(b);
}
