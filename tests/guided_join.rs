//! Guided-join verifier + directory-trap fix, end to end (see `docs/UI.md`,
//! joining) — over the **orbital daemon**.
//!
//! The `Diagnose` verb is a keystone onboarding feature: it projects live daemon
//! state into the ordered gate list so a stalled joiner gets one legible blocker
//! instead of a blank board. Here two in-process orbital daemons (in-memory
//! transport) walk the join lifecycle: a fresh joiner blocks on `membership`
//! while un-admitted, then — driven only by accepting the invite and Contact
//! (orbital's automatic admission, no manual approve) — flips to all-pass. A
//! single-node daemon proves the expected-space directory trap, and the Stop
//! path is proven to reap the daemon even with a parked subscriber. The CLI
//! decoy-store / wrong-directory guards shell the real binary because they are
//! specifically about the pre-daemon store-resolution path.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Request, Response};
use lait::diagnose::{DiagnosisView, GateState};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::spaces::{Origin, SpaceEntry};
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [161u8; 32];
const JOINER_SEED: [u8; 32] = [162u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

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

fn unique(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let d = std::env::temp_dir().join(format!(
        "gc-gj-{}-{}-{}-{}",
        tag,
        std::process::id(),
        n,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
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

fn diagnose(
    rt: &tokio::runtime::Runtime,
    home: &Path,
    expected_space: Option<String>,
) -> DiagnosisView {
    match req(rt, home, Request::Diagnose { expected_space }) {
        Response::Diagnosis(v) => *v,
        other => panic!("expected Diagnosis, got {other:?}"),
    }
}

fn gate_state(v: &DiagnosisView, id: &str) -> GateState {
    v.gates
        .iter()
        .find(|g| g.id == id)
        .expect("gate present")
        .state
}

/// The full onboarding lifecycle through the verifier: a fresh joiner is blocked
/// on `membership` until it is admitted, then every gate passes once the board
/// converges. Orbital admission is automatic on Contact (accepting the invite is
/// the approval) — no manual `members approve`. This is the "empty board →
/// legible blocker → get to work" arc the whole change exists to make honest.
#[test]
fn diagnose_tracks_join_lifecycle_from_pending_to_all_pass() {
    let net = MemNet::new();

    // Founder forms a space (found_space_cli seeds a default project, so the
    // synced gate has something to converge once the joiner is in).
    let founder_home = unique("life-a");
    lait::orbital::found_space_cli(&founder_home, &FOUNDER_SEED, "Engineering").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &founder_home);

    // Founder mints an auto-approving invite; joiner bootstraps from it and serves.
    let Response::Ref { reff: invite } = req(
        &rt,
        &founder_home,
        Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };
    let joiner_home = unique("life-b");
    lait::orbital::enter_space(&joiner_home, &JOINER_SEED, &invite).unwrap();
    let joiner_handle = spawn_daemon(joiner_home.clone(), JOINER_SEED, net.clone());
    wait_online(&rt, &joiner_home);

    // Before Contact the joiner is un-admitted: the membership gate is the
    // actionable blocker (not a blank board), and sync is Skip because the board
    // is still encrypted.
    let v = diagnose(&rt, &joiner_home, None);
    assert_eq!(
        v.blocked_on.as_deref(),
        Some("membership"),
        "an un-admitted joiner blocks on membership: {v:?}"
    );
    assert_eq!(gate_state(&v, "membership"), GateState::Wait);
    assert_eq!(
        gate_state(&v, "synced"),
        GateState::Skip,
        "sync is not a second blocker while pending — the board is encrypted"
    );

    // Drive Contact (the orbital admission handshake). Accepting the invite is
    // the approval — no manual admin step.
    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();
    let joiner_device = lait::crypto::device_from_seed(&JOINER_SEED).to_string();

    // After admission + convergence, the joiner's diagnosis flips to all-pass:
    // member, peer online, board synced. blocked_on clears.
    let cleared = poll_until(Duration::from_secs(30), || {
        req(
            &rt,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
        req(
            &rt,
            &founder_home,
            Request::Connect {
                ticket: joiner_device.clone(),
            },
        );
        req(
            &rt,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
        let v = diagnose(&rt, &joiner_home, None);
        v.blocked_on.is_none().then_some(v)
    });
    let v = cleared.expect("the joiner should reach all-pass after admission + sync");
    assert_eq!(gate_state(&v, "membership"), GateState::Pass);
    assert_eq!(gate_state(&v, "peer"), GateState::Pass);
    assert_eq!(gate_state(&v, "synced"), GateState::Pass);
    assert!(v.summary.contains("get to work"), "summary: {}", v.summary);

    let _ = req(&rt, &joiner_home, Request::Stop);
    let _ = req(&rt, &founder_home, Request::Stop);
    let _ = joiner_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&joiner_home);
}

/// The directory trap, made legible: `Diagnose { expected_space }` with a space
/// that isn't the one this store is bound to fails the `space` gate, and that
/// mismatch wins over every downstream gate — exactly the "you ran the command
/// in the wrong folder" case the `join` tail catches.
#[test]
fn diagnose_flags_expected_space_mismatch() {
    let net = MemNet::new();
    let home = unique("mm-a");
    lait::orbital::found_space_cli(&home, &FOUNDER_SEED, "Mismatch Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    // A real space exists (this device is admin), but we assert we expected a
    // different one — as the join tail would if the cwd bound the wrong store.
    let v = diagnose(&rt, &home, Some("ws_not_the_one_you_joined".into()));
    assert_eq!(
        gate_state(&v, "space"),
        GateState::Fail,
        "a wrong expected space must fail the space gate"
    );
    assert_eq!(
        v.blocked_on.as_deref(),
        Some("space"),
        "the store mismatch must be the first/actionable blocker"
    );
    assert!(
        v.summary.contains("wrong directory"),
        "summary: {}",
        v.summary
    );

    // Sanity: with the *correct* space the gate passes.
    let ws = match req(&rt, &home, Request::Status) {
        Response::Status(s) => s.space.expect("this device has a space"),
        other => panic!("status returned {other:?}"),
    };
    let ok = diagnose(&rt, &home, Some(ws));
    assert_eq!(gate_state(&ok, "space"), GateState::Pass);

    let _ = req(&rt, &home, Request::Stop);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}

/// `stop` must terminate the daemon even while a Subscribe stream is parked on
/// the shutdown Notify. The zombie regression: `notify_one` could hand its
/// single permit to the parked subscriber instead of the accept loop, leaving a
/// daemon that answered "shutting down" running forever with a half-dead control
/// channel that hangs every later client.
#[test]
fn stop_kills_the_daemon_even_with_a_live_subscriber() {
    let net = MemNet::new();
    let home = unique("stop-a");
    lait::orbital::found_space_cli(&home, &FOUNDER_SEED, "Stop Space").unwrap();
    let handle = spawn_daemon(home.clone(), FOUNDER_SEED, net.clone());

    let rt = tokio::runtime::Runtime::new().unwrap();
    wait_online(&rt, &home);

    // Park a real subscriber server-side: read the first (Reset) frame so the
    // daemon's stream task is provably inside its shutdown/doorbell select.
    let _sub = rt.block_on(async {
        let mut sub = lait::control::subscribe(&home, 0).await.expect("subscribe");
        sub.next().await.expect("first frame").expect("reset frame");
        sub
    });

    assert!(matches!(
        req(&rt, &home, Request::Stop),
        Response::Ok { .. }
    ));
    let exited = poll_until(Duration::from_secs(10), || {
        handle.is_finished().then_some(())
    });
    assert!(
        exited.is_some(),
        "the daemon must exit after stop even with a live subscriber"
    );
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}

/// The decoy-store guard: a read-only command run in a directory with no `.lait/`,
/// when the registry knows of joined spaces, must refuse to create an empty store
/// and instead point the user at the real one — exit non-zero, no `.lait/` left
/// behind. This is the direct fix for "joined, but `lait projects` shows nothing"
/// caused by running from the wrong folder.
#[test]
fn read_command_in_empty_dir_refuses_to_create_a_decoy_store() {
    let cfg = unique("guard-cfg");
    let cwd = unique("guard-cwd");

    // Seed the registry with a space the user "joined" elsewhere.
    let entry = SpaceEntry {
        space: "ws_01JGUARDTESTSPACEIDXXX".into(),
        name: "guardws".into(),
        path: "/some/other/place/.lait".into(),
        origin: Origin::Joined,
        host_nick: "alice".into(),
        last_opened: 42,
        projects: vec![],
    };
    std::fs::write(
        cfg.join("spaces.json"),
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
        "a read command with no local space must exit non-zero, got {:?}",
        out.status.code()
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("no lait space in this directory"),
        "guard must explain why, got stderr: {stderr}"
    );
    // The listing is human navigation state: the space NAME and its path
    // (not the raw ws id).
    assert!(
        stderr.contains("guardws"),
        "guard must list the registered space by name, got stderr: {stderr}"
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
        "a read command with no space anywhere must exit non-zero, got {:?}",
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

/// `lait join` in a directory already bound to a DIFFERENT space is a hard error
/// (exit 2) — never adopt, never wipe. This shells the real (orbital) binary
/// because it is the pre-daemon store-resolution path. The invite is a real
/// orbital Coordinates link for another space.
#[test]
fn join_binary_refuses_a_directory_bound_to_another_space() {
    // A real orbital space A, whose founder-signed Coordinates link we mint
    // in-process (no daemon needed — the guard fires before any Contact).
    let a_home = unique("bind-a");
    let (_mech_a, coords_a) = lait::orbital::form_space(&a_home, &FOUNDER_SEED, "Space A").unwrap();
    let link = coords_a.render();

    // …and a directory already bound to a different orbital space C.
    let c_home = unique("bind-c");
    std::fs::write(
        c_home.join("secret.key"),
        data_encoding::HEXLOWER.encode(&JOINER_SEED),
    )
    .unwrap();
    lait::orbital::found_space_cli(&c_home, &JOINER_SEED, "Space C").unwrap();

    let join_cfg = unique("bind-cfg-join");
    let out = Command::new(bin())
        .args(["join", &link])
        .env("LAIT_HOME", &c_home)
        .env("LAIT_CONFIG_ROOT", &join_cfg)
        .output()
        .expect("spawn `lait join`");

    assert_eq!(
        out.status.code(),
        Some(2),
        "joining into a store bound to another space must exit 2, stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("the invite is for"),
        "the refusal must name the mismatch, got stderr: {stderr}"
    );

    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&c_home);
    let _ = std::fs::remove_dir_all(&join_cfg);
}
