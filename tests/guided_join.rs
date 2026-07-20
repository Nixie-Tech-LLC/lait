//! Guided-join verifier + directory-trap fix, end-to-end (see
//! `docs/UI.md`, joining). Two real nodes exercise the `Diagnose` control verb
//! across the onboarding lifecycle, and a CLI-level test proves the read-command
//! decoy-store guard. Drives daemons over the Layer-B control channel like
//! `invite_ergonomics.rs`; the CLI guard test shells the binary because it is
//! specifically about the pre-daemon store-resolution path.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lait::control::{request, Request, Response};
use lait::diagnose::GateState;
use lait::workspaces::{Origin, WorkspaceEntry};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn unique(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "gc-gj-{}-{}-{}",
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
    /// The isolated config root for this node (holds its workspaces.json).
    config_root: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
        let _ = std::fs::remove_dir_all(&self.config_root);
    }
}

#[allow(clippy::zombie_processes)] // Daemon kills+waits on drop
fn spawn_daemon(home: &Path, config_root: &Path) -> Daemon {
    let mut child = Command::new(bin())
        .arg("daemon")
        .env("LAIT_HOME", home)
        // Isolate the joined-workspace registry per node so one test's registry
        // never bleeds into another's (it lives under config_root).
        .env("LAIT_CONFIG_ROOT", config_root)
        .env("LAIT_IDLE_SECS", "0")
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
        return Daemon {
            child,
            home: home.to_path_buf(),
            config_root: config_root.to_path_buf(),
        };
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon for {} never came online", home.display());
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

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn diagnose(home: &Path, expected_workspace: Option<String>) -> lait::diagnose::DiagnosisView {
    match req(home, Request::Diagnose { expected_workspace }) {
        Response::Diagnosis(v) => *v,
        other => panic!("expected Diagnosis, got {other:?}"),
    }
}

fn gate_state(v: &lait::diagnose::DiagnosisView, id: &str) -> GateState {
    v.gates
        .iter()
        .find(|g| g.id == id)
        .expect("gate present")
        .state
}

/// Found a workspace in `home` in-process, using the SAME identity the daemon
/// will load (`<home>/secret.key`, since the daemon runs with `LAIT_HOME=home`).
/// Workspaces are never minted lazily anymore — a daemon errors on an
/// uninitialized store — so every founder home goes through this first.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::crypto::user_from_seed(&key);
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::found_workspace(&store, &me, &key, "test", &lait::ids::SystemUlidSource)
        .expect("found workspace");
}

/// Bootstrap a joiner store from a ticket (the client half of `lait join`), so
/// its daemon boots already bound to the host's workspace — the daemon-side
/// Connect/Join no longer adopts a foreign workspace.
fn join_home(home: &Path, ticket: &str) {
    let t: lait::proto::WorkspaceTicket = ticket.parse().expect("parse ticket");
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::join_workspace_store(
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

fn ticket_for(home: &Path, require_approval: bool) -> String {
    match req(
        home,
        Request::Invite {
            require_approval,
            reusable: false,
            ttl_hours: None,
        },
    ) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("invite returned {other:?}"),
    }
}

/// The full onboarding lifecycle through the verifier: a `require-approval` joiner
/// is blocked on `membership` until an admin approves them, then every gate passes
/// once the board converges. This is the "empty board → legible blocker → get to
/// work" arc the whole change exists to make honest.
#[test]
fn diagnose_tracks_join_lifecycle_from_pending_to_all_pass() {
    // A founds a workspace (in-process, same identity as its daemon), then its
    // daemon adds a project (so the synced gate has something to converge once
    // B is in).
    let a_home = unique("life-a");
    found_home(&a_home);
    let a = spawn_daemon(&a_home, &unique("life-cfg-a"));
    assert!(matches!(
        req(
            &a.home,
            Request::ProjectNew {
                name: "Engineering".into(),
                key: "ENG".into(),
            }
        ),
        Response::Ref { .. }
    ));

    // B bootstraps its store from a require-approval ticket BEFORE its daemon
    // first starts, then connects → lands pending.
    let ticket = ticket_for(&a.home, true);
    let b_home = unique("life-b");
    join_home(&b_home, &ticket);
    let b = spawn_daemon(&b_home, &unique("life-cfg-b"));
    assert!(matches!(
        req(&b.home, Request::Connect { ticket }),
        Response::Ok { .. }
    ));

    // B's diagnosis: the membership gate is the actionable blocker (not a blank
    // board), and sync is Skip because the board is still encrypted.
    let waited = poll_until(Duration::from_secs(30), || {
        let v = diagnose(&b.home, None);
        (v.blocked_on.as_deref() == Some("membership")).then_some(v)
    });
    let v = waited.expect("B should block on membership while pending");
    assert_eq!(gate_state(&v, "membership"), GateState::Wait);
    assert_eq!(
        gate_state(&v, "synced"),
        GateState::Skip,
        "sync is not a second blocker while pending — the board is encrypted"
    );

    // A approves B by authenticated id.
    let b_id = match req(&b.home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("B id returned {other:?}"),
    };
    let approved = poll_until(Duration::from_secs(30), || {
        // The pending request has to reach A before it can approve.
        match req(&a.home, Request::MemberRequests) {
            Response::JoinRequests { requests } if requests.iter().any(|r| r.key == b_id) => {
                Some(())
            }
            _ => None,
        }
    });
    assert!(approved.is_some(), "A never saw B's join request");
    assert!(matches!(
        req(
            &a.home,
            Request::MemberApprove {
                who: b_id,
                as_name: None,
            }
        ),
        Response::Ok { .. }
    ));

    // After approval + convergence, B's diagnosis flips to all-pass: member,
    // peer online, board synced. blocked_on clears.
    let cleared = poll_until(Duration::from_secs(30), || {
        let v = diagnose(&b.home, None);
        v.blocked_on.is_none().then_some(v)
    });
    let v = cleared.expect("B should reach all-pass after approval + sync");
    assert_eq!(gate_state(&v, "membership"), GateState::Pass);
    assert_eq!(gate_state(&v, "peer"), GateState::Pass);
    assert_eq!(gate_state(&v, "synced"), GateState::Pass);
    assert!(v.summary.contains("get to work"));

    drop(a);
    drop(b);
}

/// The directory trap, made legible: `Diagnose { expected_workspace }` with a
/// workspace that isn't the one this store is bound to fails the `workspace` gate,
/// and that mismatch wins over every downstream gate — exactly the "you ran the
/// command in the wrong folder" case the `join` tail catches.
#[test]
fn diagnose_flags_expected_workspace_mismatch() {
    let a_home = unique("mm-a");
    found_home(&a_home);
    let a = spawn_daemon(&a_home, &unique("mm-cfg-a"));

    // A real workspace exists (A is admin), but we assert we expected a different
    // one — as the join tail would if the cwd bound the wrong store.
    let v = diagnose(&a.home, Some("ws_not_the_one_you_joined".into()));
    assert_eq!(
        gate_state(&v, "workspace"),
        GateState::Fail,
        "a wrong expected workspace must fail the workspace gate"
    );
    assert_eq!(
        v.blocked_on.as_deref(),
        Some("workspace"),
        "the store mismatch must be the first/actionable blocker"
    );
    assert!(v.summary.contains("wrong directory"));

    // Sanity: with the *correct* workspace the gate passes.
    let ws = match req(&a.home, Request::Status) {
        Response::Status(s) => s.workspace.expect("A has a workspace"),
        other => panic!("status returned {other:?}"),
    };
    let ok = diagnose(&a.home, Some(ws));
    assert_eq!(gate_state(&ok, "workspace"), GateState::Pass);

    drop(a);
}

/// A successful join records the workspace in the registry (store path → workspace)
/// so the CLI can later route a lost joiner back to the right directory.
#[test]
fn join_records_the_workspace_registry_entry() {
    let a_home = unique("reg-a");
    found_home(&a_home);
    let a = spawn_daemon(&a_home, &unique("reg-cfg-a"));

    let ticket = ticket_for(&a.home, false); // default Pattern A (auto-approve)
    let b_home = unique("reg-b");
    join_home(&b_home, &ticket);
    let b_cfg = unique("reg-cfg-b");
    let b = spawn_daemon(&b_home, &b_cfg);
    assert!(matches!(
        req(&b.home, Request::Connect { ticket }),
        Response::Ok { .. }
    ));

    // Every daemon boot upserts its store into workspaces.json under its config
    // root — so B's row exists as soon as its daemon is up (origin defaults to
    // joined; the CLI-side `lait join` would have stamped host_nick too).
    let reg_file = b_cfg.join("workspaces.json");
    let found = poll_until(Duration::from_secs(10), || {
        let txt = std::fs::read_to_string(&reg_file).ok()?;
        let entries: Vec<WorkspaceEntry> = serde_json::from_str(&txt).ok()?;
        entries
            .into_iter()
            .find(|e| e.path == b_home.display().to_string())
    });
    let entry = found.expect("join must record a registry entry pointing at B's store");
    assert!(
        entry.workspace.starts_with("ws_"),
        "entry carries the workspace id"
    );
    assert_eq!(
        entry.origin,
        Origin::Joined,
        "a bootstrapped joiner registers as joined, not founded"
    );

    drop(a);
    drop(b);
}

/// The decoy-store guard: a read-only command run in a directory with no `.lait/`,
/// when the registry knows of joined workspaces, must refuse to create an empty
/// store and instead point the user at the real one — exit non-zero, no `.lait/`
/// left behind. This is the direct fix for "joined, but `lait projects` shows
/// nothing" caused by running from the wrong folder.
#[test]
fn read_command_in_empty_dir_refuses_to_create_a_decoy_store() {
    let cfg = unique("guard-cfg");
    let cwd = unique("guard-cwd");

    // Seed the registry with a workspace the user "joined" elsewhere.
    let entry = WorkspaceEntry {
        workspace: "ws_01JGUARDTESTWORKSPACEID".into(),
        name: "guardws".into(),
        path: "/some/other/place/.lait".into(),
        origin: Origin::Joined,
        host_nick: "alice".into(),
        last_opened: 42,
        projects: vec![],
    };
    std::fs::write(
        cfg.join("workspaces.json"),
        serde_json::to_string(&vec![entry]).unwrap(),
    )
    .unwrap();

    let out = Command::new(bin())
        .arg("projects")
        .current_dir(&cwd)
        .env("LAIT_CONFIG_ROOT", &cfg)
        // Deliberately NO LAIT_HOME: force the git-style discovery path where the
        // decoy would otherwise be born.
        .env_remove("LAIT_HOME")
        .env_remove("LAIT_STORE")
        .output()
        .expect("spawn `lait projects`");

    assert!(
        !out.status.success(),
        "a read command with no local workspace must exit non-zero, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no lait space in this directory"),
        "guard must explain why, got stderr: {stderr}"
    );
    // The listing is human navigation state: the workspace NAME and its path
    // (not the raw ws id).
    assert!(
        stderr.contains("guardws"),
        "guard must list the registered workspace by name, got stderr: {stderr}"
    );
    assert!(
        stderr.contains("/some/other/place/.lait"),
        "guard must point at the registered store path, got stderr: {stderr}"
    );
    assert!(
        !cwd.join(".lait").exists(),
        "the guard must NOT leave a decoy .lait/ behind"
    );

    let _ = std::fs::remove_dir_all(&cfg);
    let _ = std::fs::remove_dir_all(&cwd);
}

/// The same refusal holds with an EMPTY registry: a store-needing command in a
/// bare directory never creates anything — it exits non-zero and points the user
/// at the creation verbs (`lait init` / `lait join`).
#[test]
fn read_command_with_empty_registry_still_refuses_and_suggests_creation_verbs() {
    let cfg = unique("guard0-cfg");
    let cwd = unique("guard0-cwd");

    let out = Command::new(bin())
        .arg("projects")
        .current_dir(&cwd)
        .env("LAIT_CONFIG_ROOT", &cfg)
        .env_remove("LAIT_HOME")
        .env_remove("LAIT_STORE")
        .output()
        .expect("spawn `lait projects`");

    assert!(
        !out.status.success(),
        "a read command with no workspace anywhere must exit non-zero, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no lait space in this directory"),
        "guard must explain why, got stderr: {stderr}"
    );
    assert!(
        stderr.contains("lait init") && stderr.contains("lait join"),
        "with nothing registered, the guard must suggest init/join, got stderr: {stderr}"
    );
    assert!(
        !cwd.join(".lait").exists(),
        "the guard must NOT leave a decoy .lait/ behind"
    );

    let _ = std::fs::remove_dir_all(&cfg);
    let _ = std::fs::remove_dir_all(&cwd);
}

/// `lait join` in a directory already bound to a DIFFERENT workspace is a hard
/// error (exit 2) — never adopt, never wipe. This shells the real binary because
/// it is the pre-daemon store-resolution path.
#[test]
fn join_binary_refuses_a_directory_bound_to_another_workspace() {
    // A real host to mint a ticket for workspace A…
    let a_home = unique("bind-a");
    found_home(&a_home);
    let a = spawn_daemon(&a_home, &unique("bind-cfg-a"));
    let ticket = ticket_for(&a.home, false);

    // …and a directory already bound to a different workspace C.
    let c_home = unique("bind-c");
    found_home(&c_home);

    let join_cfg = unique("bind-cfg-join");
    let out = Command::new(bin())
        .args(["join", &ticket])
        .env("LAIT_HOME", &c_home)
        .env("LAIT_CONFIG_ROOT", &join_cfg)
        .output()
        .expect("spawn `lait join`");

    assert_eq!(
        out.status.code(),
        Some(2),
        "joining into a store bound to another workspace must exit 2, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("the invite is for"),
        "the refusal must name the mismatch, got stderr: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&c_home);
    let _ = std::fs::remove_dir_all(&join_cfg);
    drop(a);
}

/// `stop` must terminate the daemon even while a Subscribe stream is parked on
/// the shutdown Notify. The zombie regression: `notify_one` could hand its
/// single permit to the parked subscriber instead of the accept loop, leaving a
/// daemon that answered "shutting down" running forever with a half-dead
/// control channel that hangs every later client.
#[test]
fn stop_kills_the_daemon_even_with_a_live_subscriber() {
    let d_home = unique("stop-a");
    found_home(&d_home);
    let mut d = spawn_daemon(&d_home, &unique("stop-cfg-a"));

    // Park a real subscriber server-side: read the first (Reset) frame so the
    // daemon's stream task is provably inside its shutdown/doorbell select.
    let rt = rt();
    let _sub = rt.block_on(async {
        let mut sub = lait::control::subscribe(&d.home, 0)
            .await
            .expect("subscribe");
        sub.next().await.expect("first frame").expect("reset frame");
        sub
    });

    assert!(matches!(req(&d.home, Request::Stop), Response::Ok { .. }));
    let exited = poll_until(Duration::from_secs(10), || {
        d.child.try_wait().ok().flatten()
    });
    assert!(
        exited.is_some(),
        "daemon must exit after stop even with a live subscriber"
    );
}
