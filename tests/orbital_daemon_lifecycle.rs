//! C5 step 5 — the orbital daemon serves the product control surface over the
//! real IPC control socket, through the orbital Runtime.
//!
//! Formation happens via `OrbitalMechanics::form` (the `lait init` heir); the
//! orbital daemon then serves `control::Request`/`Response` exactly as the CLI/
//! serve/MCP clients speak it. This drives the issue family end to end
//! (project/new/view/list/board/comment) plus status and invite over the wire,
//! with an in-memory transport (no network sockets) — proving the daemon path
//! works without touching the legacy node.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Filter, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [101u8; 32];

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

fn temp_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-odaemon-{}-{n}", std::process::id()));
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

#[test]
fn the_orbital_daemon_serves_the_issue_surface_over_the_control_socket() {
    // The daemon runs on a dedicated OS thread with its own runtime (it holds a
    // blocking control accept loop); the test drives it with a separate client
    // runtime, exactly as the real CLI/daemon split works.
    let home = temp_home();
    let net = MemNet::new();

    // Formation: the `lait init` heir. Also seed the orbital identity file the
    // daemon reads, so the daemon and formation share one device seed.
    std::fs::create_dir_all(&home).unwrap();
    write_identity(&home, &FOUNDER_SEED);
    lait::orbital::form_space(&home, &FOUNDER_SEED, "Orbital Daemon Space").unwrap();

    // Run the daemon on its own thread.
    let daemon_home = home.clone();
    let daemon_net = net.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = run_orbital_daemon(daemon_home, &MemFactory(daemon_net)).await {
                eprintln!("DAEMON ERR: {e:#}");
            }
        });
    });

    let client_rt = tokio::runtime::Runtime::new().unwrap();

    // Wait for the daemon to answer control requests.
    let online = poll_until(Duration::from_secs(20), || {
        matches!(req(&client_rt, &home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(online.is_some(), "the orbital daemon never answered Status");

    // Status reports the founder as a member of the formed Space.
    let status = req(&client_rt, &home, Request::Status);
    let Response::Status(info) = status else {
        panic!("expected Status");
    };
    assert!(info.space.is_some());
    assert_eq!(info.membership, "member");

    // Create a project.
    let resp = req(
        &client_rt,
        &home,
        Request::ProjectNew {
            name: "Engineering".into(),
            key: "eng".into(),
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "ENG"),
        "{resp:?}"
    );

    // File an issue; it routes through the World and returns the canonical reff.
    let resp = req(
        &client_rt,
        &home,
        Request::IssueNew {
            title: "Served over the socket".into(),
            // Formation seeded the default project, so the space has two —
            // pick the explicit one.
            project: Some("eng".into()),
            project_hint: None,
            assignees: vec![],
            priority: Some("high".into()),
            labels: vec![],
            body: Some("through the orbital daemon".into()),
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "ENG-1"),
        "{resp:?}"
    );

    // View it back.
    let resp = req(
        &client_rt,
        &home,
        Request::IssueView {
            reff: "ENG-1".into(),
        },
    );
    let Response::Issue(view) = resp else {
        panic!("expected Issue, got {resp:?}");
    };
    assert_eq!(view.title, "Served over the socket");
    assert_eq!(view.description, "through the orbital daemon");
    assert_eq!(view.priority, lait::dto::Priority::High);

    // Comment routes too.
    req(
        &client_rt,
        &home,
        Request::Comment {
            reff: "ENG-1".into(),
            body: "a socket comment".into(),
        },
    );
    let resp = req(
        &client_rt,
        &home,
        Request::IssueView {
            reff: "ENG-1".into(),
        },
    );
    let Response::Issue(view) = resp else {
        panic!("expected Issue");
    };
    assert_eq!(view.comments.len(), 1);
    assert_eq!(view.comments[0].body, "a socket comment");

    // The space-wide activity feed serves through daemon dispatch (this pins
    // the classification/routing defect where `lait activity` was refused with
    // "request not routed to the issues world"): the created issue and the
    // comment appear as feed rows, and re-pulling from the returned cursor
    // yields nothing new.
    let resp = req(&client_rt, &home, Request::Activity { since: 0 });
    let Response::Activity { events, last } = resp else {
        panic!("expected Activity, got {resp:?}");
    };
    assert!(last >= 2, "created + comment rows expected, last={last}");
    assert!(events.iter().any(|e| e.kind == "created"));
    assert!(events
        .iter()
        .any(|e| e.kind == "commented" && e.text == "a socket comment"));
    let resp = req(&client_rt, &home, Request::Activity { since: last });
    let Response::Activity { events, last: l2 } = resp else {
        panic!("expected Activity, got {resp:?}");
    };
    assert!(events.is_empty(), "cursor resume must yield no repeats");
    assert_eq!(l2, last);

    // List reflects it.
    let resp = req(
        &client_rt,
        &home,
        Request::List {
            project: None,
            filter: Filter::default(),
        },
    );
    let Response::List { rows } = resp else {
        panic!("expected List");
    };
    assert!(rows.iter().any(|r| r.title == "Served over the socket"));

    // Board renders columns.
    let resp = req(
        &client_rt,
        &home,
        Request::Board {
            project: Some("eng".into()),
            project_hint: None,
        },
    );
    assert!(matches!(resp, Response::Board(_)), "{resp:?}");

    // Members reports the founder as an admin over the signed ACL roster.
    let resp = req(&client_rt, &home, Request::Members);
    let Response::Members { members } = resp else {
        panic!("expected Members, got {resp:?}");
    };
    assert_eq!(members.len(), 1, "just the founder");
    assert_eq!(members[0].role, "admin");
    assert!(members[0].me, "the founder is this device's actor");

    // The membership audit log replays the signed ACL DAG. A freshly formed
    // Space founds membership by Genesis and mints epoch-0, so the log carries
    // the founder-authored mint (not an AddMember), and every op is recognized.
    let resp = req(&client_rt, &home, Request::MemberLog);
    let Response::MemberLog { entries } = resp else {
        panic!("expected MemberLog, got {resp:?}");
    };
    assert!(!entries.is_empty(), "the audit log is non-empty");
    assert!(
        entries.iter().all(|e| e.authorized),
        "every founding op is authorized: {entries:?}"
    );
    assert!(
        entries
            .iter()
            .any(|e| e.kind == "mint_epoch" && !e.actor.is_empty()),
        "the founder-authored epoch-0 mint is present: {entries:?}"
    );

    // Adding a well-formed but unknown actor is refused (its inception is not
    // known locally — no Contact has imported it).
    let unknown = format!("act_{}", "ab".repeat(32));
    let resp = req(
        &client_rt,
        &home,
        Request::MemberAdd {
            who: unknown,
            admin: false,
            as_name: None,
        },
    );
    assert!(
        matches!(resp, Response::Error { .. }),
        "adding an unknown actor is refused, got {resp:?}"
    );

    // Invite mints a Coordinates link (not a SpaceTicket).
    let resp = req(
        &client_rt,
        &home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    );
    let Response::Ref { reff: link } = resp else {
        panic!("expected an invite Ref, got {resp:?}");
    };
    assert!(!link.is_empty());
    // It parses back as Coordinates v1.
    assert!(runtime::SignedCoordinates::parse_link(&link).is_ok());

    // A ceremony request is served by mechanics, not refused: the founder
    // holds the solo space-recovery key, so break-glass recovery re-roots the
    // space to it and re-keys (M3 — no catch-all "not yet available").
    let resp = req(&client_rt, &home, Request::SpaceRecover);
    assert!(
        matches!(resp, Response::Ok { ref message } if message.as_deref().unwrap_or_default().contains("recovered the space")),
        "{resp:?}"
    );

    // Stop the daemon.
    let _ = req(&client_rt, &home, Request::Stop);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}

/// Write the orbital identity seed where the daemon's `load_or_create_identity`
/// expects it (the same file the real `lait init` provisions).
fn write_identity(home: &Path, seed: &[u8; 32]) {
    // The daemon reads config::identity_dir(); a $LAIT_HOME-scoped run collapses
    // it onto `home`, so the seed file lives at `home/secret.key`.
    std::env::set_var("LAIT_HOME", home);
    std::fs::write(
        home.join("secret.key"),
        data_encoding::HEXLOWER.encode(seed),
    )
    .unwrap();
}
