//! Pattern A end-to-end: a **default invite auto-admits the joiner** with no
//! manual `members approve`. Two real daemons over iroh — the host mints a ticket
//! carrying a signed, single-use pass; the joiner `join`s once and must transition
//! `pending → member` and decrypt the board on its own, driven only by the pass.
//!
//! This is the friction the whole change targets: the classic flow needed a
//! host-side approve between the joiner's `join` and their admission. Here there
//! is no such call — if this test needs one, the collapse regressed.
//!
//! Mirrors the harness style of `two_node_sync.rs` (direct control-channel round
//! trips, generous polls for variable iroh discovery/relay timing).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lait::control::{request, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

const TEST_HEARTBEAT: Duration = Duration::from_secs(1);

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
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
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn tmp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "gc-autoapprove-{}-{}-{}",
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

#[allow(clippy::zombie_processes)]
fn spawn_daemon(home: &Path) -> Daemon {
    let mut child = Command::new(bin())
        .arg("daemon")
        .env("LAIT_HOME", home)
        // Isolate the workspace registry per node: the daemon-boot upsert must land
        // in a scratch config root, never the developer's real workspaces.json.
        .env("LAIT_CONFIG_ROOT", home.join("cfgroot"))
        .env("LAIT_IDLE_SECS", "0")
        .env("LAIT_HEARTBEAT_SECS", TEST_HEARTBEAT.as_secs().to_string())
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

fn membership(home: &Path) -> Option<String> {
    match req(home, Request::Status) {
        Response::Status(s) => Some(s.membership),
        _ => None,
    }
}

/// Found a workspace in `home` in-process, using the SAME identity the daemon
/// will load (`<home>/secret.key`, since the daemon runs with `LAIT_HOME=home`).
/// Workspaces are never minted lazily anymore — a daemon errors on an
/// uninitialized store — so every founder home goes through this first.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::crypto::user_from_seed(&key);
    let store = lait::store::Store::open(home).expect("store");
    lait::replica::found_workspace(&store, &me, &key, "test", &lait::ids::SystemUlidSource)
        .expect("found workspace");
}

/// Bootstrap a joiner store from a ticket (the client half of `lait join`), so
/// its daemon boots already bound to the host's workspace — the daemon-side
/// Connect/Join no longer adopts a foreign workspace.
fn join_home(home: &Path, ticket: &str) {
    let t: lait::proto::WorkspaceTicket = ticket.parse().expect("parse ticket");
    let store = lait::store::Store::open(home).expect("store");
    lait::replica::join_workspace_store(
        &store,
        &t.workspace,
        &t.salt,
        &t.recovery_root,
        t.founder_inception
            .as_ref()
            .expect("ticket carries a founding proof"),
    )
    .expect("bootstrap joiner store");
}

#[test]
fn default_invite_auto_admits_the_joiner() {
    let a_home = tmp_home("host");
    let b_home = tmp_home("joiner");
    found_home(&a_home);
    let a = spawn_daemon(&a_home);

    // Host (the founder) adds a project and files an issue with a body (body lives ONLY in
    // the issue doc, so reading it back on B proves the key was sealed + the
    // ciphertext decrypted — not just a catalog row synced).
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
        "host: projects new"
    );
    assert!(
        matches!(
            req(
                &a.home,
                Request::IssueNew {
                    title: "secret work".into(),
                    project: Some("ENG".into()),
                    project_hint: None,
                    assignees: vec![],
                    priority: Some("high".into()),
                    labels: vec![],
                    body: Some("BODY: gated behind the workspace key".into()),
                }
            ),
            Response::Ref { .. }
        ),
        "host: new"
    );

    // Host mints a DEFAULT ticket — carries a signed, single-use auto-approve pass.
    let ticket = match req(
        &a.home,
        Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: None,
        },
    ) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("host: invite returned {other:?}"),
    };
    assert!(!ticket.is_empty(), "ticket should be non-empty");

    // Joiner bootstraps its store from the ticket BEFORE its daemon first
    // starts, then joins ONCE. No `members approve` anywhere in this test.
    join_home(&b_home, &ticket);
    let b = spawn_daemon(&b_home);
    assert!(
        matches!(req(&b.home, Request::Join { ticket }), Response::Ok { .. }),
        "joiner: join"
    );

    // The joiner must reach `member` on its own, driven only by the pass.
    let became_member = poll_until(Duration::from_secs(60), || {
        (membership(&b.home).as_deref() == Some("member")).then_some(())
    });
    assert!(
        became_member.is_some(),
        "joiner never auto-transitioned to member (last: {:?}) — Pattern A auto-approval regressed",
        membership(&b.home)
    );

    // And it can actually read the E2EE body — the seal really landed.
    let read_body = poll_until(Duration::from_secs(30), || {
        match req(
            &b.home,
            Request::IssueView {
                reff: "ENG-1".into(),
            },
        ) {
            Response::Issue(v) if !v.provisional && v.description.contains("gated behind") => {
                Some(())
            }
            _ => None,
        }
    });
    assert!(
        read_body.is_some(),
        "joiner is a member but cannot decrypt the issue body — key seal did not take"
    );

    // Host should no longer see a lingering pending request for the joiner.
    if let Response::Status(s) = req(&a.home, Request::Status) {
        assert_eq!(
            s.pending_requests, 0,
            "auto-approved joiner should not remain a pending request on the host"
        );
    }
}
