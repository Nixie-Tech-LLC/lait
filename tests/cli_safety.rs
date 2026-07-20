//! Guards for the two promises the CLI makes before it does something you can't
//! undo, and before it blames the wrong component.
//!
//! 1. **Ask before destroying.** `delete` takes its ref from the git branch when
//!    you omit it, so it is the one verb that can tombstone something you never
//!    named. It must refuse rather than guess — and, with no terminal to ask on
//!    (CI, an agent, a pipe), it must refuse *without blocking* and name `--yes`.
//!    A prompt that hangs a CI job is worse than no prompt at all.
//!
//! 2. **Tell a foreign daemon from an absent one.** A daemon that is listening but
//!    speaks a different wire shape (an older lait still running after an upgrade)
//!    used to be reported as "no daemon" — which spawned a doomed second daemon
//!    over the held lock and waited out a 20s timeout before blaming the timeout.
//!    Detection is at the transport level, so this stays true across wire changes.
//!
//! 3. **Report failures in one voice.** Every client-side error goes through the
//!    top-level reporter: one lowercase `error:` line, the versioned DTO under
//!    `--json`, and the documented exit code. `main` returning `Result` used to
//!    hand these to anyhow's `Termination`, which broke all three.
//!
//! 4. **Never hold your stdout hostage.** A command that auto-spawns a daemon must
//!    still hit EOF when it exits: whoever captured it (`$(lait new …)`, a test
//!    harness, an MCP client) reads until EOF, so a daemon left holding the write
//!    end hangs the *caller*, not the daemon. Windows-only in practice — see
//!    `disinherit_stdio` in `app.rs` — but the promise is platform-independent.

use std::io::Read;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

/// A short-lived home. Kept short on purpose: the control socket lives inside it
/// on unix and `sun_path` caps at 104 bytes (100 here), so a long temp path would
/// silently push the socket to the hashed temp-dir fallback.
fn tmp_home(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("lt-{}-{}", tag, std::process::id()));
    std::fs::remove_dir_all(&d).ok();
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The per-test config root. `$LAIT_HOME` isolates the *store*, but the spaces
/// registry lives under the config root — so without this every `init` here files
/// itself in the developer's real `lait spaces` list and never leaves.
fn config_root(home: &std::path::Path) -> std::path::PathBuf {
    home.join("cfg")
}

fn lait(home: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(bin())
        .env("LAIT_CONFIG_ROOT", config_root(home))
        // Every other integration suite pins this, and so does the CI smoke: a
        // daemon auto-spawned for a one-off command otherwise lingers for the
        // 30-minute idle window, and a client that connects while one is tearing
        // down can park (see `node::run_daemon`). Tests must not race that.
        .env("LAIT_IDLE_SECS", "0")
        .arg("--home")
        .arg(home)
        .args(args)
        .output()
        .expect("spawn lait")
}

fn init(home: &std::path::Path) {
    let out = lait(home, &["init", "--name", "t", "--nick", "t"]);
    assert!(out.status.success(), "init failed: {out:?}");
}

fn shutdown(home: &std::path::Path) {
    lait(home, &["shutdown"]);
}

#[test]
fn delete_without_yes_refuses_and_keeps_the_issue() {
    let home = tmp_home("del");
    init(&home);

    let out = lait(&home, &["new", "keep me"]);
    assert!(out.status.success(), "new failed: {out:?}");

    // `cargo test` gives the child no terminal — the CI/agent shape exactly.
    let started = Instant::now();
    let out = lait(&home, &["delete", "T-1"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "delete blocked waiting for input with no terminal to read from",
    );
    assert!(!out.status.success(), "delete must not proceed unconfirmed");
    assert!(
        stderr.contains("--yes"),
        "refusing is only half the job — it must name the flag that works \
         non-interactively; got: {stderr}",
    );
    // Naming the title is the point: on an inferred ref, "delete T-1?" is
    // unanswerable if you don't recall which issue T-1 is.
    assert!(
        stderr.contains("keep me"),
        "the prompt must name what it would destroy; got: {stderr}",
    );

    let out = lait(&home, &["ls"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("keep me"),
        "the issue must survive an unconfirmed delete",
    );

    // ...and `--yes` is the way through.
    let out = lait(&home, &["--yes", "delete", "T-1"]);
    assert!(out.status.success(), "--yes must confirm: {out:?}");
    let out = lait(&home, &["ls"]);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("keep me"),
        "--yes must actually delete",
    );

    shutdown(&home);
    std::fs::remove_dir_all(&home).ok();
}

/// The daemon a command spawns must not outlive it *holding its stdout*.
///
/// `new` is the shape that bites: it auto-spawns a daemon, and the daemon is
/// still running when `new` exits. On Windows `CreateProcess` inherits every
/// inheritable handle, not just the ones in `STARTUPINFO`, so the daemon came up
/// owning a write-end of the captured stdout of `new` — its own `Stdio::null()`
/// notwithstanding. `new` exited, the pipe never closed, and the caller blocked
/// on an EOF that could not arrive.
///
/// Waits on the *read*, not the exit: the process exiting was never the broken
/// part. Reading on a thread keeps a regression a 15s failure that says why,
/// rather than a wedged test the runner shoots at 90s with no diagnosis.
#[test]
fn a_spawned_daemon_does_not_hold_our_stdout_open() {
    let home = tmp_home("hold");
    init(&home);

    let mut child = Command::new(bin())
        .env("LAIT_CONFIG_ROOT", config_root(&home))
        // 0 disables idle-shutdown, so the daemon is *guaranteed* to still be up
        // when `new` exits — the race this test needs to be deterministic.
        .env("LAIT_IDLE_SECS", "0")
        .arg("--home")
        .arg(&home)
        .args(["new", "hold my stdout"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn lait");

    let status = child.wait().expect("wait for `new`");
    let mut stdout = child.stdout.take().expect("piped stdout");
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        tx.send(stdout.read_to_string(&mut s).map(|_| s)).ok();
    });
    let read = rx.recv_timeout(Duration::from_secs(15));

    // Before any assert: a live daemon is what wedges the reader, and on failure
    // it would otherwise outlive the test and hold the *runner's* pipe too.
    shutdown(&home);
    std::fs::remove_dir_all(&home).ok();

    assert!(status.success(), "new failed: {status}");
    let read = read.expect(
        "`new` exited but its stdout never reached EOF — the daemon it spawned \
         inherited the write end and is holding it open. Whoever captures a lait \
         command (a shell's `$(…)`, a test harness, an MCP client) hangs here.",
    );
    assert!(read.is_ok(), "reading stdout failed: {read:?}");
}

/// `try_wait` must answer *both* ways: a daemon that died is reported dead, and
/// one that is running is not reported dead.
///
/// This is the sensor the spawn wait leans on — "a daemon that has already exited
/// is never going to answer", which is what turns a lock conflict into its own
/// message instead of a 20s timeout blaming the transport. On Windows it is not
/// `std::process::Child::try_wait` but a hand-rolled equivalent (the daemon is
/// spawned through `CreateProcessW` to bound what it inherits), so both answers
/// are pinned here: a false "still running" costs the fast path, and a false
/// "exited" would blame a daemon that is coming up fine.
#[test]
fn a_dead_daemon_is_reported_dead_and_a_live_one_is_not() {
    let exe = std::path::PathBuf::from(bin());

    // Dead: no store to open, so the daemon exits ~immediately and non-zero.
    let empty = tmp_home("dead");
    let log_path = empty.join("daemon.log");
    let log = std::fs::File::create(&log_path).expect("create log");
    let mut child = lait::daemon_spawn::spawn(&exe, &empty, Some(log), None).expect("spawn daemon");
    let deadline = Instant::now() + Duration::from_secs(15);
    let status = loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => break s,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            None => panic!(
                "a daemon that could not open a store was never reported as exited — \
                 the spawn wait would blame a 20s timeout instead of saying why",
            ),
        }
    };
    assert!(
        !status.success(),
        "a daemon that cannot open its store must exit non-zero, got {status}",
    );
    // The log is the daemon's stderr: `daemon_exited_error` quotes it back as the
    // "it said:" diagnosis, so a mis-wired stderr costs the entire explanation and
    // leaves only an exit code.
    let said = std::fs::read_to_string(&log_path).unwrap_or_default();
    assert!(
        said.contains("store not initialized"),
        "the daemon's stderr must reach its log — that text is the whole \
         diagnosis when a spawn dies; got: {said:?}",
    );
    std::fs::remove_dir_all(&empty).ok();

    // Live: a real store, so it comes up — and must not be declared dead.
    //
    // It reaps itself on a short idle window rather than being told to stop: a
    // `shutdown` races the daemon's control-channel bind, and losing that race
    // strands a live `lait.exe`. On Windows that is not a stray process but a
    // broken build — the linker cannot replace a running binary, so the next
    // `cargo run` fails with "Access is denied" in some later step that has
    // nothing to do with this test. Self-reaping means no assertion below can
    // leak one.
    std::env::set_var("LAIT_IDLE_SECS", "2");
    let home = tmp_home("live");
    init(&home);
    let mut child = lait::daemon_spawn::spawn(&exe, &home, None, None).expect("spawn daemon");
    let alive = child.try_wait().expect("try_wait");
    assert!(
        alive.is_none(),
        "a daemon that had just started was reported as exited ({alive:?}) — the \
         spawn wait would abandon a daemon that was coming up fine",
    );

    // ...and when that same daemon idles out, the sensor must notice: proof the
    // `None` above was a live reading rather than a stuck one.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_) => break,
            None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            None => panic!("a daemon that idled out was never reported as exited"),
        }
    }
    std::fs::remove_dir_all(&home).ok();
}

/// A selector that matches nothing is a not-found, and must answer like one on
/// every channel: prose shape, `--json` DTO, and exit code.
#[test]
fn a_client_side_error_keeps_the_cli_contract() {
    let home = tmp_home("err");
    init(&home);

    // `-w` and `--home` are declared conflicting, so the home rides the env here
    // (the same channel `--home` sets internally).
    let run = |args: &[&str]| {
        Command::new(bin())
            .env("LAIT_HOME", &home)
            .env("LAIT_CONFIG_ROOT", config_root(&home))
            .env("LAIT_IDLE_SECS", "0")
            .args(args)
            .output()
            .expect("spawn lait")
    };

    let out = run(&["-w", "nosuchspace", "ls"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    // anyhow's Termination printed `Error:` (capitalised, Debug) while the daemon
    // path printed `error:` — two voices in one binary.
    assert!(
        stderr.starts_with("error:"),
        "errors must use the lowercase `error:` voice; got: {stderr}",
    );
    assert!(
        !stderr.contains("Caused by:"),
        "the cause chain is anyhow's Debug output, not a CLI contract; got: {stderr}",
    );
    // Not-found and ambiguous selectors exit 2; generic termination flattened this to 1.
    assert_eq!(
        out.status.code(),
        Some(2),
        "a selector matching nothing must exit 2; stderr: {stderr}",
    );

    // `--json` is a contract: a consumer must get the DTO on stdout, not prose on
    // stderr and an empty stdout it can't distinguish from an empty result.
    let out = run(&["--json", "-w", "nosuchspace", "ls"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .unwrap_or_else(|e| panic!("stdout not JSON ({e}): {stdout:?}"));
    assert_eq!(v["kind"], "error");
    assert_eq!(
        v["error_kind"], "not_found",
        "the DTO must carry the typed kind, not just prose: {v}",
    );
    assert_eq!(out.status.code(), Some(2));

    shutdown(&home);
    std::fs::remove_dir_all(&home).ok();
}

/// Stand a fake daemon on `home`'s control socket, replying `reply` to every
/// request, and run `lait <args>` against it. Returns (stderr, exit code).
#[cfg(unix)]
fn against_fake_daemon(
    tag: &str,
    reply: &'static [u8],
    args: &[&str],
) -> (String, Option<i32>, Duration) {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;

    let home = tmp_home(tag);
    init(&home);
    shutdown(&home);
    std::thread::sleep(Duration::from_millis(500));

    let sock = lait::config::socket_path(&home);
    std::fs::remove_file(&sock).ok();
    let listener = UnixListener::bind(&sock).expect("bind fake daemon");
    let fake = std::thread::spawn(move || {
        for stream in listener.incoming().take(8) {
            let Ok(mut s) = stream else { continue };
            let mut line = String::new();
            BufReader::new(s.try_clone().unwrap())
                .read_line(&mut line)
                .ok();
            s.write_all(reply).ok();
            s.write_all(b"\n").ok();
        }
    });

    let started = Instant::now();
    let out = lait(&home, args);
    let elapsed = started.elapsed();

    drop(fake);
    std::fs::remove_file(&sock).ok();
    std::fs::remove_dir_all(&home).ok();
    (
        String::from_utf8_lossy(&out.stderr).into_owned(),
        out.status.code(),
        elapsed,
    )
}

/// A daemon this build can't talk to must be reported as *present and foreign* —
/// promptly — not as absent.
#[cfg(unix)]
#[test]
fn a_foreign_daemon_is_named_not_timed_out() {
    // A pre-handshake daemon (v0.4.8): it has no `hello`, so serde rejects the
    // request as an unknown variant. That rejection is the identification.
    let (stderr, code, elapsed) = against_fake_daemon(
        "foreign",
        br#"{"kind":"error","message":"bad request: unknown variant `hello`","error_kind":"error"}"#,
        &["status"],
    );

    // The old path spawned a doomed daemon and polled for a full 20s first.
    assert!(
        elapsed < Duration::from_secs(10),
        "a foreign daemon must be diagnosed promptly, took {elapsed:?}",
    );
    assert_ne!(code, Some(0), "must not report success; stderr: {stderr}");
    assert!(
        stderr.contains("already running"),
        "must say a daemon is there, not imply none is; got: {stderr}",
    );
    assert!(
        !stderr.contains("did not come online"),
        "must not blame a timeout for a daemon that answered instantly; got: {stderr}",
    );
}

/// The asymmetry, end to end: a daemon *ahead* of this build must never be
/// stopped — not even under `--yes`, which is exactly when a blunt "clean it up"
/// would fire. Replacing it downgrades the node, and a store already written at a
/// newer `SCHEMA_VERSION` would then refuse to open at all.
#[cfg(unix)]
#[test]
fn a_newer_daemon_is_never_replaced_even_with_yes() {
    let (stderr, code, _) = against_fake_daemon(
        "newer",
        br#"{"kind":"hello","protocol_version":9000}"#,
        &["--yes", "status"],
    );

    assert_ne!(code, Some(0), "must not proceed; stderr: {stderr}");
    assert!(
        stderr.contains("lait update"),
        "the way out of being behind is to upgrade, not to kill it; got: {stderr}",
    );
    assert!(
        !stderr.contains("stopped it"),
        "must never stop a daemon newer than this build; got: {stderr}",
    );
}

/// A leaf whose name collides with another's must not read the other's args.
///
/// `leaf.name` is only the **last** path segment, so `labels new` answers to
/// `"new"` exactly as the top-level verb does. `app::dispatch` special-cases
/// `new --start`, and asking clap for an arg the matched leaf never declared is a
/// **panic**, not a `false` — so `lait labels new <name>` aborted with "Mismatch
/// between definition and access of `start`" before it reached the daemon.
/// Shipped, and invisible until someone created a label from a surface that
/// wasn't a hand-typed CLI.
///
/// This needs a real store, which is the whole reason it lives here and not in
/// the parse tests: `parse_to_request` is perfectly happy, and dispatch aborts on
/// "no space in this directory" *before* reaching the fault — so the cheap version
/// of this test passes against the bug.
#[test]
fn colliding_leaf_names_do_not_read_each_others_args() {
    let home = tmp_home("leafname");
    init(&home);

    let out = lait(&home, &["labels", "new", "bug", "--color", "red"]);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !stderr.contains("panicked"),
        "`lait labels new` panicked:\n{stderr}",
    );
    assert!(out.status.success(), "`lait labels new` failed: {stderr}",);

    // And it actually made the label, rather than merely not crashing.
    let listed = lait(&home, &["--json", "labels", "ls"]);
    let stdout = String::from_utf8_lossy(&listed.stdout);
    assert!(
        stdout.contains("\"bug\""),
        "the label was not created: {stdout}",
    );

    // NOT tested here: `new --start`. It chains into the work loop and **creates
    // and checks out a git branch in the process's cwd** — and `lait()` doesn't
    // pin one, so it runs in whatever directory the test harness sits in. Asserting
    // it here once left this very repo checked out on a branch named after the test
    // fixture. A `--start` test needs its own throwaway git repo as cwd; until it
    // has one, it does not belong in a suite about not destroying things.
    shutdown(&home);
}
