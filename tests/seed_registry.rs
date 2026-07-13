//! Seed registry end-to-end (ARCHITECTURE §10, client half): a node that pins an
//! always-on seed with `seed add <ticket>` must (1) adopt the seed's workspace
//! and backfill its history from nothing but the ticket, and (2) on a later cold
//! restart — with the opportunistic `peers.json` bootstrap set wiped — redial the
//! seed purely from the sticky `seeds.json` pin and reconverge.
//!
//! This is the property that distinguishes an explicit seed pin from the DUR-1
//! opportunistic peer cache: deleting `peers.json` before the restart removes the
//! DUR-1 path, so if B still converges it can only be via its seed pin.
//!
//! Like `restart_reconnect.rs` this drives the real iroh stack over the Layer-B
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
        "gc-seed-{}-{}-{}",
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

/// A running daemon, killed on drop so a failed assert still reaps the child.
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

/// Spawn a daemon on `home` and wait until its control channel answers. `seed`
/// adds `--seed` (always-on run-mode); idle shutdown is disabled either way so
/// the test, not a timer, controls lifetime.
#[allow(clippy::zombie_processes)] // Proc kills+waits on drop
fn spawn(home: &Path, seed: bool) -> Proc {
    let mut cmd = Command::new(bin());
    cmd.arg("daemon");
    if seed {
        cmd.arg("--seed");
    }
    let child = cmd
        .env("LAIT_HOME", home)
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

/// Poll until `seeds.json` under `home` records `id` (written when the pin lands).
fn poll_seed_persisted(home: &Path, id: &str, timeout: Duration) -> bool {
    poll_until(timeout, || {
        std::fs::read_to_string(home.join("seeds.json"))
            .unwrap_or_default()
            .contains(id)
            .then_some(())
    })
    .is_some()
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
fn seed_pin_adopts_then_survives_restart() {
    let seed_home = tmp_home("seed");
    let b_home = tmp_home("b");
    let seed = spawn(&seed_home, true); // always-on seed
    let mut b = spawn(&b_home, false);

    // The seed founds the workspace and files the first issue.
    assert!(
        matches!(
            req(
                &seed_home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                }
            ),
            Response::Ref { .. }
        ),
        "seed: projects new"
    );
    assert!(
        matches!(new_issue(&seed_home, "before pin"), Response::Ref { .. }),
        "seed: first issue"
    );

    // B pins the seed from its ticket — this should adopt the workspace AND
    // backfill, so B converges to the pre-existing issue with no other peer and
    // no prior peers.json.
    let ticket = match req(&seed_home, Request::Invite) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("seed: invite returned {other:?}"),
    };
    assert!(
        matches!(
            req(&b_home, Request::SeedAdd { arg: ticket }),
            Response::Ok { .. }
        ),
        "B: seed add"
    );

    // Grant B membership (mirrors the P1 sync path in restart_reconnect).
    let b_id = id_of(&b_home);
    assert!(
        matches!(
            req(
                &seed_home,
                Request::MemberAdd {
                    who: b_id,
                    admin: false,
                    as_name: None
                }
            ),
            Response::Ok { .. }
        ),
        "seed: member add B"
    );

    assert!(
        poll_title(&b_home, "before pin", Duration::from_secs(80)),
        "adopt+backfill: B did not converge to the seed's existing issue via the pin"
    );

    // The pin is persisted for restart.
    let seed_id = id_of(&seed_home);
    assert!(
        poll_seed_persisted(&b_home, &seed_id, Duration::from_secs(20)),
        "B should persist the seed ({seed_id}) in seeds.json"
    );

    // Crash B, then wipe its opportunistic peer cache so ONLY the seed pin can
    // bootstrap it on restart — this is what isolates the pin as load-bearing.
    b.stop();
    let _ = std::fs::remove_file(b_home.join("peers.json"));

    // While B is down, the seed files a new issue.
    assert!(
        matches!(new_issue(&seed_home, "after restart"), Response::Ref { .. }),
        "seed: post-restart issue"
    );

    // Restart B on the SAME home with no peers.json. It must redial the seed from
    // seeds.json alone and reconverge.
    b = spawn(&b_home, false);
    assert!(
        poll_title(&b_home, "after restart", Duration::from_secs(90)),
        "restart: B did not redial its pinned seed from seeds.json and converge"
    );

    b.stop();
    drop(seed);
    let _ = std::fs::remove_dir_all(&seed_home);
    let _ = std::fs::remove_dir_all(&b_home);
}
