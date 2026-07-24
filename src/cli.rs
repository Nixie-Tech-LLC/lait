//! CLI client: builds control requests, auto-spawns the daemon, prints results.
//!
//! CLI and MCP are Layer-B clients of the daemon (`docs/UI.md`); the web
//! application uses the same contract through its loopback adapter. This module
//! renders `Response` snapshots for a human shell, or the versioned
//! `--json` DTO for scripts/agents. Exit codes: `0` ok · `1`
//! usage/error · `2` ref not found / ambiguous · `3` daemon unreachable.

use std::{
    io::Write,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use anyhow::{anyhow, Context, Result};

use crate::{
    control::{self, request, ErrorKind, Event, EventKind, Request, Response},
    diagnose::{DiagnosisView, GateState},
    dto::{BoardView, IssueView, Priority, Row},
    spaces::{self, SpaceEntry, StorePresence},
};

/// Output mode threaded from the global `--json` / `--no-color` / `--yes` flags.
#[derive(Debug, Clone, Copy)]
pub struct Out {
    pub json: bool,
    pub color: bool,
    /// `--yes`: assume yes at every confirmation prompt. See [`confirm`].
    pub yes: bool,
}

impl Default for Out {
    fn default() -> Self {
        Out {
            json: false,
            color: true,
            yes: false,
        }
    }
}

/// A client-side failure that carries its own exit code.
///
/// Daemon-side failures already travel with a typed [`ErrorKind`], and
/// `exit_code_for_kind` derives their code "from the typed kind, not the message
/// text". This extends the same rule to failures that never reach the daemon —
/// the alternative is a top-level reporter pattern-matching prose, which is
/// exactly what that rule exists to prevent. Plain `anyhow` errors stay code `1`,
/// so classifying is opt-in and nothing has to be reclassified at once.
#[derive(Debug)]
pub struct CliError {
    /// The documented exit code for this failure.
    pub code: i32,
    pub message: String,
}

impl CliError {
    /// `2` — a selector resolved to nothing. Matches what the daemon already
    /// returns for a missing ref, user, or label, so a missing *space* doesn't
    /// answer differently to the same kind of mistake.
    pub fn not_found(message: impl Into<String>) -> Self {
        CliError {
            code: 2,
            message: message.into(),
        }
    }

    /// `3` — the daemon could not be reached, or could not be understood.
    pub fn unreachable(message: impl Into<String>) -> Self {
        CliError {
            code: 3,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// The exit code represented by a client-side error. Split from
/// [`report_error`] so the mapping is testable without a process to exit —
/// `ExitCode` is deliberately opaque and can't be read back.
///
/// An unclassified error is `1`, so the classification is additive: a plain
/// `anyhow!` keeps behaving exactly as it did.
fn exit_code_for_error(e: &anyhow::Error) -> i32 {
    if let Some(c) = e.downcast_ref::<CliError>() {
        return c.code;
    }
    // Something is listening and no request will ever get through to it: `3`,
    // daemon unreachable, in the sense that matters.
    if e.downcast_ref::<ForeignDaemon>().is_some() {
        return 3;
    }
    1
}

/// Report a failure and return the process exit code — the one place a
/// client-side error becomes output.
///
/// `main` used to be `async fn main() -> Result<()>`, which handed every such
/// error to anyhow's `Termination` impl. That broke four contracts at once, all
/// of which this fixes:
///
/// * **One voice.** `Error:` (anyhow's `Debug`) and `error:` (the daemon path)
///   both shipped in one binary. Now everything is the lowercase form.
/// * **No internals.** `Debug` prints the `Caused by:` chain, which surfaced raw
///   `data-encoding` and `postcard` text ("non-zero trailing bits at 3") on a
///   truncated invite. `{e:#}` is the single-line `context: cause` form.
/// * **`--json` is a contract.** A consumer got prose on stderr and *nothing* on
///   stdout, unable to tell failure from an empty result.
/// * **Exit codes are typed.** `Termination` exits `1` for everything, so a
///   not-found answered `1` while the documented code is `2`.
pub fn report_error(e: &anyhow::Error, out: Out) -> std::process::ExitCode {
    let code = exit_code_for_error(e);
    // The single-line form: "context: cause", never the multi-line chain.
    let message = format!("{e:#}");
    if out.json {
        // Same DTO shape the daemon path emits, so a script parses one thing.
        let resp = if code == 2 {
            Response::not_found(message)
        } else {
            Response::err(message)
        };
        println!(
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        eprintln!("error: {message}");
    }
    std::process::ExitCode::from(code as u8)
}

/// What a confirmation prompt decided, and why — so the caller can tell "the
/// user said no" (a clean exit) from "we couldn't ask" (an error that must
/// name the flag that would have worked).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Confirmed {
    /// Go ahead: the user typed `y`, or `--yes` was passed.
    Yes,
    /// The user answered, and the answer was no.
    No,
    /// We could not ask — no TTY (CI, a pipe, the MCP server), or `--json`.
    /// Never block in these; the caller must fail and print the `--yes` form.
    CannotAsk,
}

/// Ask a yes/no question, defaulting to **no**.
///
/// The one place lait prompts, so every destructive verb and every repair offer
/// degrades identically:
///
/// * `--yes` → [`Confirmed::Yes`] without asking (scripts, CI, agents).
/// * `--json` or no TTY on **stdin or stdout** → [`Confirmed::CannotAsk`]. A
///   prompt written into a pipe is invisible, and reading a reply from a
///   redirected stdin would eat data meant for the command (`lait comment`
///   reads stdin) or block forever with no visible question. Both checks matter:
///   stdout carries the question, stdin carries the answer.
/// * otherwise → ask on **stderr** (stdout is the data channel; a prompt must
///   never land in `lait ls | cat`), read one line, `y`/`yes` is yes and
///   everything else — including a bare Enter or EOF — is no.
pub fn confirm(question: &str, out: Out) -> Confirmed {
    if out.yes {
        return Confirmed::Yes;
    }
    use std::io::IsTerminal;
    if out.json || !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return Confirmed::CannotAsk;
    }
    eprint!("{question} [y/N] ");
    std::io::stderr().flush().ok();
    let mut reply = String::new();
    if std::io::stdin().read_line(&mut reply).is_err() {
        return Confirmed::No;
    }
    match reply.trim().to_ascii_lowercase().as_str() {
        "y" | "yes" => Confirmed::Yes,
        _ => Confirmed::No,
    }
}

/// Minimal ANSI styling. Every helper is gated on `Out.color`, which already
/// folds in `--no-color`, `$NO_COLOR`, `--json`, and TTY detection (computed once
/// in `app::run`), so a renderer just passes `out.color` and never re-checks.
mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const DIM: &str = "\x1b[2m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RED: &str = "\x1b[31m";
    pub const GREEN: &str = "\x1b[32m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const CYAN: &str = "\x1b[36m";
}

/// Wrap `s` in an ANSI code when `on`, else return it unstyled.
fn paint(on: bool, code: &str, s: &str) -> String {
    if on {
        format!("{code}{s}{}", ansi::RESET)
    } else {
        s.to_string()
    }
}

/// The confirmation question for a request that destroys something, or `None`
/// for the ones that don't.
///
/// Deliberately keyed on the `Request` rather than the command name: this is the
/// single list of what lait asks before doing, so adding a destructive verb means
/// adding it here, not remembering to prompt at a call site.
/// The question a destructive verb must answer before it runs, or `None` if the
/// verb destroys nothing.
///
/// Keyed on the `Request` so the list lives in exactly one place, whatever asks
/// it. The CLI asks on a TTY (`confirm_destructive`); `lait serve` hands the same
/// string to the browser to put in a modal. A second copy of this list, phrased
/// slightly differently, is how two surfaces end up disagreeing about what is
/// dangerous.
pub(crate) fn destructive_question(req: &Request) -> Option<String> {
    match req {
        // The ref is inferred from the git branch when omitted, so this is the
        // one verb that can destroy something you never named.
        Request::IssueDelete { reff } => Some(format!("delete {reff}?")),
        Request::MemberRemove { who } => Some(format!(
            "remove {who} from this space and rotate the space key?"
        )),
        Request::KeyRotate => Some("rotate the space key?".to_string()),
        _ => None,
    }
}

/// Best-effort title lookup for a ref, to name what a prompt is about to destroy.
/// A failure just returns `None` — the prompt falls back to the bare ref rather
/// than blocking on a lookup that isn't essential.
async fn peek_title(home: &Path, reff: &str) -> Option<String> {
    match client(
        home,
        Request::IssueView {
            reff: reff.to_string(),
        },
    )
    .await
    {
        Ok(Response::Issue(v)) => Some(v.title),
        _ => None,
    }
}

/// Gate a destructive request behind a confirmation. `true` = go ahead.
///
/// Non-destructive requests pass straight through, so this can sit on the uniform
/// dispatch path without every verb paying for it.
pub async fn confirm_destructive(home: &Path, req: &Request, out: Out) -> bool {
    let Some(question) = destructive_question(req) else {
        return true;
    };
    // Name the thing, not just its handle: `lait delete` on a `eng-142-…` branch
    // takes its ref from the branch, so "delete ENG-142?" is unanswerable if you
    // don't remember which issue that is — which is exactly the case where a
    // stale checkout deletes the wrong one.
    let question = match req {
        Request::IssueDelete { reff } => match peek_title(home, reff).await {
            Some(t) => format!("delete {reff} “{t}”? this tombstones it for every peer"),
            None => question,
        },
        _ => question,
    };
    match confirm(&question, out) {
        Confirmed::Yes => true,
        Confirmed::No => {
            eprintln!("aborted.");
            false
        }
        Confirmed::CannotAsk => {
            eprintln!(
                "error: {question}\n       \
                 this needs confirmation and there is no terminal to ask on — \
                 re-run with `--yes` to confirm."
            );
            false
        }
    }
}

/// Where a spawned daemon's stderr goes. Truncated per spawn (we only spawn when
/// none is running, so it holds exactly the current daemon's life), and inside
/// `home`, which is `*`-gitignored.
pub fn daemon_log_path(home: &Path) -> std::path::PathBuf {
    home.join("daemon.log")
}

/// The last few lines of the daemon log — a dying daemon's own account of why,
/// which is otherwise thrown away.
fn daemon_log_tail(path: &Path, lines: usize) -> Option<String> {
    let text = std::fs::read_to_string(path).ok()?;
    let tail: Vec<&str> = text
        .lines()
        .filter(|l| !l.trim().is_empty())
        .rev()
        .take(lines)
        .collect();
    if tail.is_empty() {
        return None;
    }
    Some(
        tail.into_iter()
            .rev()
            .map(|l| format!("  {l}"))
            .collect::<Vec<_>>()
            .join("\n"),
    )
}

/// Homes whose daemon this process has already verified.
///
/// One CLI invocation can reach [`client`] several times — `delete` peeks the
/// issue's title before asking about it — and each [`control::probe`] is a fresh
/// connect. That is not free: on Windows the control channel is a named pipe
/// serving one client per accepted instance, and a client that connects while no
/// instance is free can park (see the teardown note in `node::run_daemon`). Verify
/// once per home, then stay out of the way.
type VerifiedSet = std::sync::Mutex<std::collections::HashSet<PathBuf>>;
static VERIFIED_DAEMONS: std::sync::OnceLock<VerifiedSet> = std::sync::OnceLock::new();

fn already_verified(home: &Path) -> bool {
    VERIFIED_DAEMONS
        .get_or_init(VerifiedSet::default)
        .lock()
        .map(|s| s.contains(home))
        .unwrap_or(false)
}

fn mark_verified(home: &Path) {
    if let Ok(mut s) = VERIFIED_DAEMONS.get_or_init(VerifiedSet::default).lock() {
        s.insert(home.to_path_buf());
    }
}

/// Forget that `home`'s daemon was verified, so the next [`ensure_daemon`] probes
/// again instead of trusting the memo.
///
/// The memo is only sound because a CLI process resolves one store and exits: it
/// cannot outlive the daemon it verified, so re-probing would be pure cost. A
/// long-lived supervisor breaks that assumption — `lait serve` can watch a daemon
/// stop and then be asked for it again, and a stale entry there does not mean
/// "already fine", it means **"never respawn this"**, which is exactly wrong. The
/// symptom is a connect error that no retry can clear.
///
/// So the one caller that can outlive a daemon says so when it notices.
pub(crate) fn forget_verified(home: &Path) {
    if let Ok(mut s) = VERIFIED_DAEMONS.get_or_init(VerifiedSet::default).lock() {
        s.remove(home);
    }
}

/// Ensure a daemon is running for this home dir, spawning one if needed.
///
/// Uses whatever identity this process would use — i.e. `$LAIT_HOME` if set,
/// else the global `secret.key`. That is right for every caller that resolved
/// its own store, which is every CLI invocation. A caller that supervises
/// *several* homes at once cannot rely on its own env and must say which
/// identity it means: see [`ensure_daemon_as`].
pub async fn ensure_daemon(home: &Path) -> Result<()> {
    ensure_daemon_as(home, None).await
}

/// Ensure a daemon is running for `home`, pinning the identity it runs as.
///
/// `identity: Some(dir)` spawns the daemon with `LAIT_HOME=dir`, which makes
/// [`crate::config::identity_dir`] resolve there and the daemon sign with
/// *that* home's `secret.key`.
///
/// This exists because identity does not follow the store. `identity_dir` reads
/// `$LAIT_HOME` and nothing else — never `$LAIT_STORE` — so pointing a spawn at a
/// self-contained home's store while `LAIT_HOME` is unset opens that store under
/// the *global* key, silently ignoring the `secret.key` sitting inside it. For a
/// named agent's home that is not a subtle mismatch: the space key is sealed
/// to the agent's X25519 key, so the daemon cannot unwrap it, and it would
/// announce the wrong identity as a peer in the agent's space.
///
/// One process resolving one store never notices, because its own env already
/// says which identity it is. `lait serve` holds N homes across *two* identity
/// kinds at once and cannot express that through a process-global env var, so
/// the choice becomes an argument.
pub async fn ensure_daemon_as(home: &Path, identity: Option<&Path>) -> Result<()> {
    if already_verified(home) {
        return Ok(());
    }
    match control::probe(home).await {
        control::Probe::Healthy => {
            mark_verified(home);
            return Ok(());
        }
        control::Probe::Foreign { why, replaceable } => {
            return Err(ForeignDaemon {
                home: home.to_path_buf(),
                why,
                replaceable,
            }
            .into())
        }
        control::Probe::Absent => {}
    }
    // A daemon can only open an initialized store — fail fast with guidance
    // instead of spawning a doomed process and timing out 20s later. This is a
    // missing store, not an unreachable daemon: `1`, not `3`.
    if !crate::orbital::space_store_present(home) {
        return Err(anyhow!(
            "no space at {} — found one with `lait init`, or join one with `lait join <link>`",
            home.display()
        ));
    }
    let exe = std::env::current_exe().context("locate own executable")?;
    // Keep the daemon's stderr instead of discarding it: when a spawn fails, its
    // own message ("another lait daemon is already running for this home …") is
    // the whole diagnosis, and `Stdio::null()` used to throw exactly that away.
    let log_path = daemon_log_path(home);
    let log = std::fs::File::create(&log_path).ok();
    // The daemon outlives us, so it must come up holding *only* what we hand it:
    // on Windows a plain spawn would also give it every other inheritable handle
    // we own — including a captured caller's stdout pipe, which then never sees
    // EOF. See `daemon_spawn`.
    //
    // `identity` rides as an argv (`--home`), not an env var. On Windows the
    // spawn deliberately hands the child our *own* env block so the OS keeps it
    // correctly sorted — which means an env override there would be a
    // process-wide `set_var`. That is fine for `LAIT_STORE` in a CLI that
    // resolves one store and exits, and wrong for `lait serve`, which holds N
    // homes across two identity kinds at once and would race itself. An argument
    // is scoped to the child by construction.
    let mut child =
        crate::daemon_spawn::spawn(&exe, home, log, identity).context("spawn daemon")?;
    for _ in 0..100 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        if request(home, &Request::Status).await.is_ok() {
            return Ok(());
        }
        // A daemon that has already exited is never going to answer. Without this
        // the common failures (lock held, bind failure) each cost the full 20s
        // and then blame a timeout.
        if let Ok(Some(status)) = child.try_wait() {
            // But *our* child dying is not the same as no daemon. Two processes
            // can race to spawn one for the same home: the loser exits saying
            // "another lait daemon is already running" while the winner's is up
            // and answering. Losing that race is success — the home has the daemon
            // it needs, it just isn't ours — so ask before blaming. Rare between
            // two CLI invocations; routine once `lait serve` is in the mix, since
            // it holds several homes and reacts to doorbells while you type.
            //
            // Ask for a moment, not once: the winner is starting at the same
            // instant our loser gives up, so a single immediate probe usually
            // arrives too early and blames a daemon that is seconds from
            // answering. A lost race resolves in milliseconds; a genuinely broken
            // spawn (bind failure, held lock) still fails in about a second rather
            // than the full 20 this check exists to avoid.
            for _ in 0..12 {
                if request(home, &Request::Status).await.is_ok() {
                    mark_verified(home);
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            return Err(daemon_exited_error(status, &log_path));
        }
    }
    Err(CliError::unreachable(format!(
        "daemon did not come online within 20s — it is running but not answering.\n\
         see {log}, or run `lait daemon` in the foreground to watch it start.",
        log = log_path.display(),
    ))
    .into())
}

/// Detect a daemon this build can't talk to and offer to clear it.
///
/// The house pattern for a recoverable bad state: **detect** it precisely,
/// **inform** in the user's terms, **offer** the fix, **verify** it worked, and
/// **degrade** without blocking when there's nobody to ask. Informing alone would
/// leave every verb dead until the user hand-runs a command we already know the
/// name of.
///
/// Detection is at the transport level (see [`control::probe`]) because that is
/// the one thing a wire-shape change cannot break — which matters here, since the
/// whole condition *is* a wire-shape change.
/// `true` if `e` is a foreign daemon this build may replace — i.e. worth offering
/// [`heal_from_error`] and retrying.
pub fn is_replaceable_foreign(e: &anyhow::Error) -> bool {
    e.downcast_ref::<ForeignDaemon>()
        .is_some_and(|f| f.replaceable)
}

/// Offer to clear a daemon this build can't talk to. `Ok(())` = repaired; the
/// caller may retry what failed.
///
/// Driven from the **error path**, never a probe up front: the happy path (a
/// healthy daemon, or none) must not pay a connect for a repair it will never
/// need. Errors are the only place this condition exists, so that is where the
/// offer belongs.
pub async fn heal_from_error(e: &anyhow::Error, out: Out) -> Result<()> {
    let Some(f) = e.downcast_ref::<ForeignDaemon>() else {
        return Err(anyhow!("{e:#}"));
    };
    // Only offer the repair when *we* are the newer side. Offering to stop a
    // daemon that is ahead of this build would be offering to break the node:
    // a downgrade at best, and an unopenable store at worst. There, the only
    // honest answer is the one the handshake already gives — upgrade.
    if !f.replaceable {
        return Err(anyhow!("{e:#}"));
    }
    let pid = crate::config::daemon_pid(&f.home)
        .map(|p| format!(" (pid {p})"))
        .unwrap_or_default();
    // `why` comes from the version handshake, so it names the actual mismatch
    // ("speaks control protocol v1, this build speaks v2") rather than whichever
    // field happened to fail to decode.
    eprintln!(
        "a daemon is already running for this space{pid}: {why}",
        why = f.why
    );
    match confirm("stop it and continue?", out) {
        Confirmed::Yes => {
            stop_daemon_verified(&f.home).await?;
            eprintln!("stopped it — continuing.");
            Ok(())
        }
        Confirmed::No => Err(anyhow!(
            "left it running — `lait shutdown` stops it when you're ready"
        )),
        Confirmed::CannotAsk => Err(anyhow!(
            "run `lait shutdown` to stop it, or re-run with `--yes` to stop it \
             automatically"
        )),
    }
}

/// Poll until nothing is listening on this home, or `within` elapses.
/// `true` = the daemon is really gone.
async fn wait_until_absent(home: &Path, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    loop {
        if matches!(control::probe(home).await, control::Probe::Absent) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Stop the daemon for `home` and **verify** it actually stopped.
///
/// Never trusts the acknowledgement. A v0.4.8-era daemon answers `stop` with
/// "shutting down" and then keeps running — its `notify_one` could hand the lone
/// permit to a subscriber instead of the accept loop (fixed in
/// `node::signal_shutdown`, but the daemons that need stopping are precisely the
/// ones that predate the fix). So: ask, watch, and escalate if it lied.
pub async fn stop_daemon_verified(home: &Path) -> Result<()> {
    // Read the pid before asking — a daemon that honours `stop` takes its lock
    // file with it, and we'd rather have the signal target than race for it.
    let pid = crate::config::daemon_pid(home);
    let _ = control::request(home, &Request::Stop).await;
    if wait_until_absent(home, Duration::from_secs(3)).await {
        return Ok(());
    }
    let Some(pid) = pid else {
        return Err(anyhow!(
            "the daemon ignored `stop` and its lock file names no pid (it predates \
             the pid stamp) — find it with `ps aux | grep 'lait daemon'` and kill it"
        ));
    };
    #[cfg(unix)]
    {
        for sig in [libc::SIGTERM, libc::SIGKILL] {
            // SAFETY: kill(2) with a pid read from this home's lock file, sending
            // a standard termination signal. An already-dead pid just returns
            // ESRCH, which the wait below treats as gone.
            unsafe { libc::kill(pid as libc::pid_t, sig) };
            if wait_until_absent(home, Duration::from_secs(3)).await {
                return Ok(());
            }
        }
    }
    Err(anyhow!(
        "could not stop the daemon (pid {pid}) — kill it by hand and re-run"
    ))
}

/// A daemon is listening on this home that this build cannot talk to — in
/// practice a version skew (the binary was upgraded, the daemon wasn't restarted).
///
/// Typed rather than a message, so the repair can be offered from the error path
/// (see [`heal_from_error`]) instead of probing eagerly on every command that
/// will never need it. Exit code `3`: unreachable in the sense that matters —
/// something is there, and no request will ever get through to it.
#[derive(Debug)]
pub struct ForeignDaemon {
    pub home: PathBuf,
    /// The handshake's own diagnosis; already carries the way out.
    pub why: String,
    /// Whether replacing it is the right repair — false when it is ahead of us.
    pub replaceable: bool,
}

impl std::fmt::Display for ForeignDaemon {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a daemon is already running for this space, but {why}  (home: {home})",
            why = self.why,
            home = self.home.display(),
        )
    }
}

impl std::error::Error for ForeignDaemon {}

/// The spawned daemon exited before answering — report its own last words rather
/// than a timeout.
fn daemon_exited_error(status: std::process::ExitStatus, log_path: &Path) -> anyhow::Error {
    match daemon_log_tail(log_path, 5) {
        Some(tail) => anyhow!(
            "the daemon exited immediately ({status}). it said:\n{tail}\n\
             full log: {log}",
            log = log_path.display(),
        ),
        None => anyhow!(
            "the daemon exited immediately ({status}) without saying why (see {log})",
            log = log_path.display(),
        ),
    }
}

/// Ensure the daemon is up, then send one request.
pub async fn client(home: &Path, req: Request) -> Result<Response> {
    ensure_daemon(home).await?;
    // The daemon answered the probe a moment ago, so a failure here is the
    // transport giving out mid-exchange: `3`, daemon unreachable.
    request(home, &req)
        .await
        .map_err(|e| CliError::unreachable(format!("{e:#}")).into())
}

/// Run a request, print the response, and exit with the corresponding code.
pub async fn run(home: &Path, req: Request, out: Out) -> Result<()> {
    match client(home, req).await {
        Ok(resp) => {
            let code = print_response(&resp, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
        // Propagate rather than reporting here: `client` errors are already
        // classified (`CliError::unreachable`), and the top-level reporter is what
        // honours `--json`. This arm used to print and `exit(3)` itself, which
        // hardcoded "daemon unreachable" onto conditions that weren't — including
        // `ensure_daemon`'s "no space at …", a missing store.
        Err(e) => Err(e),
    }
}

/// Emit a bare text value while honoring the `--json` contract: the
/// `Response::Text` DTO under `--json`, else the raw string. For client-side
/// commands (`id`, `invite`) that don't round-trip a daemon `Response` but must
/// still emit a parseable DTO under `--json` instead of leaking plain text.
pub fn emit_text(text: &str, out: Out) {
    if out.json {
        let resp = Response::Text {
            text: text.to_string(),
        };
        println!(
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("{text}");
    }
}

/// Emit an acknowledgement honouring `--json`: the `Response::Ok` DTO under
/// `--json`, else the human message (`init`, `install-mcp`, `resume`).
pub fn emit_ok(message: &str, out: Out) {
    if out.json {
        let resp = Response::Ok {
            message: Some(message.to_string()),
        };
        println!(
            "{}",
            serde_json::to_string(&resp).unwrap_or_else(|_| "{}".into())
        );
    } else {
        println!("{message}");
    }
}

/// Render the guided-join verifier's gate list (human output). Each gate is a
/// coloured glyph + label + detail, followed by the one-line summary keyed off the
/// blocking gate. Under `--json` the caller emits the DTO instead (handled in
/// `print_response`), so this is the human path only.
fn print_diagnosis(v: &DiagnosisView, out: Out) {
    for g in &v.gates {
        let code = match g.state {
            GateState::Pass => ansi::GREEN,
            GateState::Wait => ansi::YELLOW,
            GateState::Warn => ansi::YELLOW,
            GateState::Fail => ansi::RED,
            GateState::Skip => ansi::DIM,
        };
        let glyph = paint(out.color, code, g.state.glyph());
        println!("{} {:<11} {}", glyph, g.label, g.detail);
    }
    println!();
    let code = if v.blocked_on.is_some() {
        ansi::YELLOW
    } else {
        ansi::GREEN
    };
    println!("{}", paint(out.color, code, &v.summary));
}

/// `join` display: send the join, echo the daemon's ack, then run the guided-join
/// verifier as a tail — passing the ticket's space as `expected_space`, so
/// a directory/store mismatch (the joiner ran `join` in the wrong folder) is caught
/// and named immediately instead of surfacing later as a blank board. Under
/// `--json` we emit only the join DTO (no verifier chrome), mirroring `run_invite`.
pub async fn run_join(home: &Path, ticket: String, out: Out) -> Result<()> {
    // Parse client-side to recover the intended space before the link is
    // moved into the request. A malformed link simply yields no expectation;
    // the daemon returns the real parse error.
    let parsed = runtime::SignedCoordinates::parse_link(ticket.trim())
        .ok()
        .and_then(|c| c.verify().ok());
    // An admission-carrying link admits automatically within seconds, so a
    // pending membership is worth polling out.
    let has_pass = parsed.as_ref().is_some_and(|v| v.admission.is_some());
    let expected = parsed.map(|v| v.space.as_str().to_string());
    let resp = client(home, Request::Join { ticket }).await?;
    match &resp {
        Response::Ok { message } => {
            if out.json {
                emit_ok(message.as_deref().unwrap_or("ok"), out);
                return Ok(());
            }
            println!("{}", message.as_deref().unwrap_or("ok"));
        }
        // A join error (bad ticket, unreachable host) is terminal — print and stop.
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            return Ok(());
        }
    }
    // Human tail: the gate readout. Best-effort — a verifier hiccup must not make a
    // successful join look failed, so we degrade to a hint rather than erroring.
    //
    // Polled, not one-shot: right after `join` returns, admission (Pattern A's
    // auto-seal) and the gossip handshake are still in flight, so a t=0 snapshot
    // reads "waiting on a peer" moments before everything passes — the verifier
    // itself becoming the unreliable reporter. We re-diagnose until the gates
    // settle (all pass, or a Fail-state blocker that time won't clear) or a
    // deadline, and report the settled truth.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut last: Option<Response> = None;
    loop {
        match client(
            home,
            Request::Diagnose {
                expected_space: expected.clone(),
            },
        )
        .await
        {
            Ok(diag) => {
                let settled = match &diag {
                    Response::Diagnosis(v) => match v.blocked_on.as_deref() {
                        None => true,
                        // `space` is the one Fail-state blocker (wrong
                        // directory/store) — waiting can't clear it.
                        Some("space") => true,
                        // Pending membership clears itself only under a pass
                        // (Pattern A auto-seal); pass-less waits on a human.
                        Some("membership") => !has_pass,
                        // peer / synced — convergence in flight; keep polling.
                        Some(_) => false,
                    },
                    // Not a diagnosis (daemon error) — nothing to wait out.
                    _ => true,
                };
                let expired = tokio::time::Instant::now() >= deadline;
                if settled || expired {
                    print_diagnosis_or(&diag, out);
                    break;
                }
                last = Some(diag);
            }
            Err(e) => {
                // Degrade to the freshest readout we have, or a hint.
                match &last {
                    Some(diag) => print_diagnosis_or(diag, out),
                    None => eprintln!("(joined; run `lait doctor` for status — {e:#})"),
                }
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

/// One-line issue summary for the work-state verbs: `MP-3  fix login  in_progress`.
/// Prefers the friendly `KEY-n` handle; the collision-free short id is `--json`'s.
fn workstate_line(v: &crate::dto::IssueView) -> String {
    let handle = v.key_alias.as_deref().unwrap_or(&v.reff);
    format!("{handle}  {}  {}", v.title, v.status)
}

/// A git branch name for an issue: lowercased `KEY-n` + a hyphenated title slug
/// (≤40 chars of slug). Predictable by design — `done`/`show` infer the issue
/// back out of it, and so do agents.
fn branch_name_for(v: &crate::dto::IssueView) -> String {
    let handle = v
        .key_alias
        .clone()
        .unwrap_or_else(|| v.reff.clone())
        .to_ascii_lowercase();
    let mut slug = String::new();
    for c in v.title.to_ascii_lowercase().chars() {
        if slug.len() >= 40 {
            break;
        }
        if c.is_ascii_alphanumeric() {
            slug.push(c);
        } else if !slug.ends_with('-') && !slug.is_empty() {
            slug.push('-');
        }
    }
    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        handle
    } else {
        format!("{handle}-{slug}")
    }
}

/// Create + checkout the issue's branch, best-effort: outside a git work-tree
/// this silently does nothing; inside one, an existing branch is switched to and
/// any failure is a warning — a branch hiccup must never fail the `start`.
fn checkout_issue_branch(v: &crate::dto::IssueView, out: Out) {
    let in_repo = std::process::Command::new("git")
        .args(["rev-parse", "--is-inside-work-tree"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !in_repo {
        return;
    }
    let name = branch_name_for(v);
    // `switch -c` for a fresh branch; if it already exists, plain `switch`.
    let created = std::process::Command::new("git")
        .args(["switch", "-c", &name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    let ok = created
        || std::process::Command::new("git")
            .args(["switch", &name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
    if !out.json {
        if ok {
            println!(
                "{}",
                paint(
                    out.color,
                    ansi::DIM,
                    &format!(
                        "{} branch '{name}'",
                        if created {
                            "switched to new"
                        } else {
                            "switched to"
                        }
                    )
                )
            );
        } else {
            eprintln!("(could not create/switch branch '{name}' — continue manually)");
        }
    }
}

/// `lait start`: claim + activate + branch. The daemon does the atomic
/// state move; the branch is client-side sugar on top (skippable, best-effort).
pub async fn run_start(home: &Path, reff: String, no_branch: bool, out: Out) -> Result<()> {
    let resp = client(home, Request::IssueStart { reff }).await?;
    match &resp {
        Response::Issue(v) => {
            if out.json {
                print_response(&resp, out);
            } else {
                println!("{}  · you", workstate_line(v));
            }
            if !no_branch {
                checkout_issue_branch(v, out);
            }
            Ok(())
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// `lait done` / `lait stop`: the branchless work-state verbs.
pub async fn run_workstate(home: &Path, req: Request, out: Out) -> Result<()> {
    let resp = client(home, req).await?;
    match &resp {
        Response::Issue(v) => {
            if out.json {
                print_response(&resp, out);
            } else {
                println!("{}", workstate_line(v));
            }
            Ok(())
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// `lait new --start`: file the issue, then claim it (two honest commits).
pub async fn run_new_start(home: &Path, new_req: Request, out: Out) -> Result<()> {
    let resp = client(home, new_req).await?;
    match &resp {
        Response::Ref { reff } => {
            if !out.json {
                println!("{reff}");
            }
            run_start(home, reff.clone(), false, out).await
        }
        other => {
            let code = print_response(other, out);
            if code != 0 {
                std::process::exit(code);
            }
            Ok(())
        }
    }
}

/// Bare `lait` — the FOCUS view: unread inbox summary + your open issues.
/// Must answer "what's addressed to me / what am I on" faster than a browser
/// tab could open, and its empty states name the next command.
pub async fn run_focus(home: &Path, out: Out) -> Result<()> {
    let inbox = client(home, Request::Inbox { clear: false }).await?;
    let mine = request(
        home,
        &Request::List {
            project: None,
            filter: crate::control::Filter {
                mine: true,
                status: None,
                label: None,
                all: false,
            },
        },
    )
    .await?;
    if out.json {
        // Machine focus = the two DTOs on two lines (each independently stable).
        print_response(&inbox, out);
        print_response(&mine, out);
        return Ok(());
    }
    if let Response::Inbox { entries, unread } = &inbox {
        if *unread > 0 {
            let heads: Vec<String> = entries
                .iter()
                .take(3)
                .map(|e| format!("{} {}", inbox_line_verb(e), e.reff))
                .collect();
            println!(
                "{} {}",
                paint(out.color, ansi::CYAN, &format!("Inbox ({unread}):")),
                heads.join(" · ")
            );
        }
    }
    match &mine {
        Response::List { rows } if rows.is_empty() => {
            println!("nothing assigned to you — grab something: `lait ls`, or file one: `lait new \"...\"`");
        }
        Response::List { rows } => {
            for r in rows {
                println!("  {}  {:<10}  {}", r.reff, r.status, r.title);
            }
        }
        other => {
            print_response(other, out);
        }
    }
    Ok(())
}

/// The inbox verb phrase for a summary line ("assigned you", "commented on"…).
fn inbox_line_verb(e: &crate::dto::InboxEntry) -> String {
    let who = e.actor_nick.clone().unwrap_or_else(|| "someone".into());
    match e.kind.as_str() {
        "assigned" => format!("{who} assigned you"),
        "comment" => format!("{who} commented on"),
        _ => format!("{who} moved"),
    }
}

/// Render a `Diagnosis` response, or fall back gracefully if the daemon returned
/// some other variant (e.g. an error) to the tail request.
fn print_diagnosis_or(resp: &Response, out: Out) {
    match resp {
        Response::Diagnosis(v) => print_diagnosis(v, out),
        other => {
            print_response(other, out);
        }
    }
}

/// Live status of one registry entry: `missing` (store gone from disk), `up`
/// (a daemon answers on its control channel), or `idle` (store present, no
/// daemon). The probe is a short-deadline `Status` round-trip — never a spawn.
async fn space_status(e: &SpaceEntry) -> &'static str {
    if spaces::presence(e) == StorePresence::Missing {
        return "missing";
    }
    let up = tokio::time::timeout(
        Duration::from_millis(300),
        request(Path::new(&e.path), &Request::Status),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if up {
        "up"
    } else {
        "idle"
    }
}

/// `lait spaces`: every space on this machine (founded and joined),
/// with live status. Honours `--json`.
pub async fn print_spaces(out: Out) {
    let entries = spaces::list();
    let mut statuses = Vec::with_capacity(entries.len());
    for e in &entries {
        statuses.push(space_status(e).await);
    }
    if out.json {
        let rows: Vec<serde_json::Value> = entries
            .iter()
            .zip(&statuses)
            .map(|(e, s)| {
                let mut v = serde_json::to_value(e).unwrap_or_default();
                if let Some(o) = v.as_object_mut() {
                    o.insert("status".into(), serde_json::json!(s));
                }
                v
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({ "spaces": rows }))
                .unwrap_or_else(|_| "{}".into())
        );
        return;
    }
    if entries.is_empty() {
        println!("(no spaces yet — `lait init` to found one, or `lait join <link>`)");
        return;
    }
    for (e, status) in entries.iter().zip(&statuses) {
        let short: String = e.space.chars().take(12).collect();
        let code = match *status {
            "up" => ansi::GREEN,
            "idle" => ansi::DIM,
            _ => ansi::RED,
        };
        let name = if e.name.is_empty() {
            "(unnamed)"
        } else {
            &e.name
        };
        let projects = if e.projects.is_empty() {
            String::new()
        } else {
            let keys: Vec<&str> = e.projects.iter().map(|p| p.key.as_str()).collect();
            format!("  [{}]", keys.join(", "))
        };
        let nick = if e.host_nick.is_empty() {
            String::new()
        } else {
            format!("  (from {})", e.host_nick)
        };
        println!(
            "{name}  {short}  {}  {}{projects}{nick}",
            e.origin,
            paint(out.color, code, status),
        );
        println!("  {}", paint(out.color, ansi::DIM, &e.path));
    }
}

/// The universal "no space here" error: any store-needing command run in a
/// directory with no discoverable `.lait/` gets this instead of a silently
/// minted decoy store. Points at the creation verbs and every known space.
pub fn err_no_store_here(out: Out) {
    eprintln!("no lait space in this directory (nothing is created implicitly).");
    let known = spaces::list();
    if !known.is_empty() {
        eprintln!();
        eprintln!("spaces on this machine:");
        for e in &known {
            let name = if e.name.is_empty() {
                "(unnamed)"
            } else {
                &e.name
            };
            eprintln!(
                "  {} {name}  \u{2192}  {}",
                paint(out.color, ansi::DIM, "\u{2022}"),
                e.path
            );
        }
        eprintln!();
        eprintln!(
            "cd into one, target one from here with `-w <name>`, or `lait spaces` for details."
        );
    } else {
        eprintln!();
        eprintln!("found a space here with `lait init`, or join one with `lait join <link>`.");
    }
}

/// Render the issue-graph neighborhood (`lait graph <ref>`).
fn print_graph(g: &crate::dto::GraphView, out: Out) {
    let row_line = |r: &crate::dto::Row| {
        let handle = r.key_alias.as_deref().unwrap_or(&r.reff);
        format!("{handle}  {}  ({})", r.title, r.status)
    };
    println!("{}", paint(out.color, ansi::BOLD, &g.reff));
    if let Some(p) = &g.parent {
        println!("  parent    {}", row_line(p));
    }
    for c in &g.children {
        println!("  child     {}", row_line(c));
    }
    for l in &g.links {
        let arrow = if l.direction == "out" { "→" } else { "←" };
        println!("  {} {arrow}  {}", l.kind, row_line(&l.row));
    }
    if !g.blocked_by.is_empty() {
        println!(
            "{}",
            paint(out.color, ansi::YELLOW, "  blocked by (open, transitive):")
        );
        for b in &g.blocked_by {
            println!("    ⚠ {}", row_line(b));
        }
    }
    if g.parent.is_none() && g.children.is_empty() && g.links.is_empty() {
        println!("  (no relations — `lait link <ref> blocks <ref>` or `lait parent <ref> <epic>`)");
    }
}

/// Print a response; return the process exit code it implies.
/// Render unix seconds as the UTC `YYYY-MM-DD` day (the inverse of the
/// router's `parse_due`; same civil-date arithmetic).
fn fmt_day(ts: u64) -> String {
    let days = (ts / 86_400) as i64;
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}")
}

pub fn print_response(resp: &Response, out: Out) -> i32 {
    if out.json {
        let json = serde_json::to_string(resp).unwrap_or_else(|_| "{}".into());
        println!("{json}");
        return match resp {
            Response::Error { error_kind, .. } => exit_code_for_kind(*error_kind),
            Response::Candidates { .. } => 2,
            _ => 0,
        };
    }
    match resp {
        // Not a user-facing outcome: the handshake belongs to `control::probe`,
        // which reads it as raw JSON before anything is typed. Rendered plainly
        // rather than `unreachable!()` — a panic here would turn a diagnostic
        // into a crash on exactly the mismatched-daemon path this exists for.
        Response::Hello { protocol_version } => {
            println!("control protocol v{protocol_version}");
            0
        }
        Response::Ok { message } => {
            println!("{}", message.as_deref().unwrap_or("ok"));
            0
        }
        Response::Ref { reff } => {
            println!("{reff}");
            0
        }
        Response::Issue(v) => {
            print_issue(v, out);
            0
        }
        Response::List { rows } => {
            print_rows(rows, out);
            0
        }
        Response::Board(b) => {
            print_board(b, out);
            0
        }
        Response::Graph(g) => {
            print_graph(g, out);
            0
        }
        Response::Inbox { entries, unread } => {
            if entries.is_empty() {
                println!("inbox zero — nothing addressed to you. the backlog is `lait ls`.");
                return 0;
            }
            // Newest-first + a ts watermark ⇒ exactly the first `unread` are unread.
            for (i, e) in entries.iter().enumerate() {
                let mark = if (i as u64) < *unread { "•" } else { " " };
                let detail = if e.detail.is_empty() {
                    String::new()
                } else {
                    format!("  — {}", e.detail)
                };
                println!(
                    "{} {}  {}  {}{}",
                    paint(out.color, ansi::CYAN, mark),
                    e.reff,
                    inbox_line_verb(e),
                    e.title,
                    detail
                );
            }
            println!(
                "{}",
                paint(
                    out.color,
                    ansi::DIM,
                    &format!("({unread} unread — `lait inbox --clear` to mark read)")
                )
            );
            0
        }
        Response::Activity { events, .. } => {
            if events.is_empty() {
                println!("(no activity yet — it fills as the space moves: `lait new \"...\"`)");
            }
            for e in events {
                let changes = if e.changes.is_empty() {
                    String::new()
                } else {
                    let cs: Vec<String> = e
                        .changes
                        .iter()
                        .map(|c| {
                            format!(
                                "{} {}→{}",
                                c.field,
                                c.from.as_deref().unwrap_or("∅"),
                                c.to.as_deref().unwrap_or("∅")
                            )
                        })
                        .collect();
                    format!("  {}", cs.join(", "))
                };
                let warn = if e.collision { " ⚠" } else { "" };
                println!("{} {} {}{}{}", e.reff, e.actor_nick, e.kind, changes, warn);
            }
            0
        }
        Response::Projects { projects } => {
            if projects.is_empty() {
                println!("(no projects — create one: `lait projects add KEY`)");
                // A just-joined peer sees this too, but should wait for sync, not
                // create — point them at the verifier so an empty board is legible.
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::DIM,
                        "  just joined? run `lait doctor` to check sync status"
                    )
                );
            }
            for p in projects {
                println!("{:<6} {}  ({})", p.key, p.name, p.id);
            }
            0
        }
        Response::Updates { updates } => {
            if updates.is_empty() {
                println!("(no updates yet — post one: `lait projects update KEY \"…\"`)");
            }
            for u in updates {
                let health = if u.health.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", u.health.replace('_', " "))
                };
                println!("{}{health}  {}", u.ts, u.body);
                let _ = &u.author;
            }
            0
        }
        Response::Milestones { milestones } => {
            if milestones.is_empty() {
                println!("(no milestones — add one: `lait milestone new KEY \"…\"`)");
            }
            for m in milestones {
                let target = m
                    .target_date
                    .map(|t| format!("  → {}", fmt_day(t)))
                    .unwrap_or_default();
                println!("{:<24} {}/{}{target}  ({})", m.name, m.done, m.total, m.id);
            }
            0
        }
        Response::Cycles { cycles } => {
            if cycles.is_empty() {
                println!("(no cycles — add one: `lait cycle new KEY \"…\"`)");
            }
            for c in cycles {
                let window = match (c.start, c.end) {
                    (0, 0) => String::new(),
                    (s, 0) => format!("  {} →", fmt_day(s)),
                    (0, e) => format!("  → {}", fmt_day(e)),
                    (s, e) => format!("  {} → {}", fmt_day(s), fmt_day(e)),
                };
                println!("{:<24} {}/{}{window}  ({})", c.name, c.done, c.total, c.id);
            }
            0
        }
        Response::Initiatives { initiatives } => {
            if initiatives.is_empty() {
                println!("(no initiatives — add one: `lait initiative new \"…\"`)");
            }
            for i in initiatives {
                let health = if i.health.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", i.health.replace('_', " "))
                };
                let projects = if i.projects.is_empty() {
                    "(no projects)".to_string()
                } else {
                    i.projects.join(", ")
                };
                println!(
                    "{:<24} {}/{}{health}  {}  ({})",
                    i.name, i.done, i.total, projects, i.id
                );
            }
            0
        }
        Response::Teams { teams } => {
            if teams.is_empty() {
                println!("(no teams — add one: `lait team new \"…\" --key T`)");
            }
            for t in teams {
                let projects = if t.projects.is_empty() {
                    String::new()
                } else {
                    format!("  → {}", t.projects.join(", "))
                };
                println!(
                    "{:<8} {:<20} {} member(s){projects}  ({})",
                    t.key,
                    t.name,
                    t.members.len(),
                    t.id
                );
            }
            0
        }
        Response::TriageItems { items } => {
            if items.is_empty() {
                println!("(triage queue is empty — report with `lait triage submit \"…\"`)");
            }
            for t in items {
                let state = if t.outcome.is_empty() {
                    "pending".to_string()
                } else if t.reff.is_empty() {
                    t.outcome.clone()
                } else {
                    format!("{} → {}", t.outcome, t.reff)
                };
                println!("{}  {:<10} {}", t.id, state, t.title);
            }
            0
        }
        Response::Attachment { name, mime, .. } => {
            // Reaching stdout with a payload would splat base64; the CLI's
            // `attachment get` writes the file itself and never prints this.
            println!("attachment {name} ({mime}) — use `lait attachment get` to save it");
            0
        }
        Response::Labels { labels } => {
            if labels.is_empty() {
                println!("(no labels)");
            }
            for l in labels {
                println!("{:<16} {}  ({})", l.name, l.color, l.id);
            }
            0
        }
        Response::Assignments { rows } => {
            if rows.is_empty() {
                println!("(no effective assignments)");
            }
            for r in rows.iter() {
                let scope = if r.resource.is_empty() {
                    "space".to_string()
                } else {
                    r.resource.join("/")
                };
                println!(
                    "{}  {:<24} {:<28} {}",
                    &r.grant_id[..12.min(r.grant_id.len())],
                    r.capability,
                    scope,
                    r.actor
                );
            }
            0
        }
        Response::Members { members } => {
            if members.is_empty() {
                println!("(no members)");
            }
            for m in members {
                let you = if m.me { "  (you)" } else { "" };
                let name = if m.alias.is_empty() {
                    String::new()
                } else {
                    format!("  {}", m.alias)
                };
                // Agents render their sponsor so the delegation chain is visible.
                let sponsor = m
                    .sponsor
                    .as_deref()
                    .map(|s| format!("  via {}", s.chars().take(8).collect::<String>()))
                    .unwrap_or_default();
                let short: String = m.key.chars().take(12).collect();
                println!("{:<7} {}{}{}{}", m.role, short, name, sponsor, you);
            }
            0
        }
        Response::MemberLog { entries } => {
            if entries.is_empty() {
                println!("(no membership ops yet)");
            }
            for e in entries {
                let mark = if e.authorized {
                    paint(out.color, ansi::GREEN, "\u{2713}")
                } else {
                    paint(out.color, ansi::YELLOW, "\u{2717}")
                };
                let actor: String = e.actor.chars().take(8).collect();
                let subject = e
                    .subject
                    .as_deref()
                    .map(|s| s.chars().take(8).collect::<String>())
                    .unwrap_or_default();
                let role = e
                    .role
                    .as_deref()
                    .map(|r| format!(" {r}"))
                    .unwrap_or_default();
                println!("{mark} {actor}  {:<13} {subject}{role}", e.kind);
            }
            0
        }
        Response::Seeds { seeds } => {
            if seeds.is_empty() {
                println!("(no pinned remotes — add one: `lait remote add <ticket>`)");
            }
            for s in seeds {
                let nick = if s.nick.is_empty() { "remote" } else { &s.nick };
                let short: String = s.id.chars().take(12).collect();
                println!("{}  {:<12}  {}", short, nick, s.state);
            }
            0
        }
        Response::Candidates {
            candidates,
            near_miss_for,
        } => {
            match near_miss_for {
                Some(input) => eprintln!("no issue matches '{input}' — did you mean:"),
                None => eprintln!("ambiguous ref — {} candidates:", candidates.len()),
            }
            for c in candidates {
                let alias = c
                    .key_alias
                    .as_deref()
                    .map(|a| format!(" [{a}]"))
                    .unwrap_or_default();
                eprintln!("  {}{}  {}", c.reff, alias, c.title);
            }
            2
        }
        Response::Status(s) => {
            println!("id:        {}", s.id);
            println!("nick:      {}", s.nick);
            let ws_line = match (s.name.is_empty(), s.space.as_deref()) {
                (false, Some(ws)) => format!("{} ({ws})", s.name),
                (true, Some(ws)) => ws.to_string(),
                (false, None) => s.name.clone(),
                (true, None) => "(none)".to_string(),
            };
            println!("space:     {ws_line}");
            if !s.membership.is_empty() {
                let code = if s.membership == "pending" {
                    ansi::YELLOW
                } else {
                    ansi::GREEN
                };
                println!("you:       {}", paint(out.color, code, &s.membership));
            }
            if s.counts_unavailable {
                // Never render an unavailable projection as an empty space.
                println!("issues:    (unavailable)");
                println!("projects:  (unavailable)");
            } else {
                println!("issues:    {}", s.issues);
                println!("projects:  {}", s.projects);
            }
            println!("online:    {} peer(s)", s.online_peers);
            // Directional nudges so neither side of a join stalls silently.
            if s.membership == "pending" {
                println!();
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::CYAN,
                        "⌛ admission in progress — it completes automatically on the next contact with a member."
                    )
                );
                println!("   the board stays encrypted until then; it syncs automatically once you're in.");
            }
            // A degraded recovery holder is reported on every status, not only
            // when break-glass is attempted: by then it is too late to fix.
            for h in &s.degraded_recovery {
                let why = match &h.reason {
                    mechanics::ceremony::RecoveryArtifactFailure::Undecryptable(_) => {
                        "it was protected under another Windows account or machine"
                    }
                    mechanics::ceremony::RecoveryArtifactFailure::Io(_) => {
                        "it is present but could not be read"
                    }
                };
                let scope = match h.is_current_authority {
                    Some(true) => "the space recovery key",
                    _ => "a recovery key (group unidentified)",
                };
                println!();
                println!(
                    "{}",
                    paint(
                        out.color,
                        ansi::YELLOW,
                        &format!("⚠ your share of {scope} is unusable — {why}.")
                    )
                );
                println!("   transcript: {}", h.transcript);
                println!("   you cannot take part in recovery from this device; other threshold holders still can.");
            }
            0
        }
        Response::Diagnosis(v) => {
            print_diagnosis(v, out);
            0
        }
        Response::Text { text } => {
            println!("{text}");
            0
        }
        Response::Events { events, .. } => {
            if events.is_empty() {
                println!("(no new events)");
            }
            for e in events {
                print_event(e);
            }
            0
        }
        Response::Who { peers } => {
            let mut peers = peers.clone();
            if peers.is_empty() {
                println!("(no peers seen yet)");
            }
            peers.sort_by_key(|p| (!p.online, p.nick.clone()));
            for p in peers {
                let (glyph, code) = match p.state.as_str() {
                    "online" => ("\u{25CF}", ansi::GREEN),
                    "away" => ("\u{25D0}", ansi::YELLOW),
                    _ => ("\u{25CB}", ansi::DIM),
                };
                println!("{} {}  ({})", paint(out.color, code, glyph), p.nick, p.id);
            }
            0
        }
        Response::Error {
            message,
            error_kind,
        } => {
            eprintln!("error: {message}");
            exit_code_for_kind(*error_kind)
        }
    }
}

/// Exit code from the typed error kind, not from the message text.
fn exit_code_for_kind(kind: ErrorKind) -> i32 {
    match kind {
        ErrorKind::NotFound => 2,
        ErrorKind::Error => 1,
    }
}

fn prio_badge(p: Priority, color: bool) -> String {
    let badge = format!("·{}·", p.badge());
    let code = match p {
        Priority::Urgent => ansi::RED,
        Priority::High => ansi::YELLOW,
        Priority::Medium => ansi::CYAN,
        Priority::Low => ansi::DIM,
        Priority::None => ansi::DIM,
    };
    paint(color, code, &badge)
}

fn print_rows(rows: &[Row], out: Out) {
    if rows.is_empty() {
        println!(
            "(no issues here — file one: `lait new \"...\"`, or `lait ls --all` to include done)"
        );
        return;
    }
    for r in rows {
        let alias = r.key_alias.as_deref().unwrap_or(&r.reff);
        let asg = if r.assignee_summary.is_empty() {
            String::new()
        } else {
            format!("  {}", r.assignee_summary)
        };
        let dim = if r.provisional {
            paint(out.color, ansi::DIM, " (provisional)")
        } else {
            String::new()
        };
        println!(
            "{} {} {:<12} {}{}{}",
            paint(out.color, ansi::BOLD, &format!("{alias:<10}")),
            prio_badge(r.priority, out.color),
            r.status,
            r.title,
            asg,
            dim
        );
    }
}

fn print_board(b: &BoardView, out: Out) {
    println!(
        "{} · {}",
        paint(out.color, ansi::BOLD, &b.project.key),
        b.project.name
    );
    for col in &b.columns {
        let header = format!("┌ {} ({}) ", col.state.name, col.rows.len());
        println!("\n{}", paint(out.color, ansi::CYAN, &header));
        for r in &col.rows {
            let alias = r.key_alias.as_deref().unwrap_or(&r.reff);
            let asg = if r.assignee_summary.is_empty() {
                String::new()
            } else {
                format!("  {}", r.assignee_summary)
            };
            println!(
                "│ {:<10} {} {}{}",
                alias,
                prio_badge(r.priority, out.color),
                r.title,
                asg
            );
        }
    }
}

fn print_issue(v: &IssueView, out: Out) {
    let alias = v.key_alias.as_deref().unwrap_or(&v.reff);
    println!(
        "{}  {}",
        paint(out.color, ansi::BOLD, alias),
        paint(out.color, ansi::BOLD, &v.title)
    );
    println!("{}", paint(out.color, ansi::DIM, &"─".repeat(60)));
    println!("id:       {}", v.reff);
    println!("project:  {}", v.project_key.as_deref().unwrap_or("?"));
    println!("status:   {}", v.status);
    println!("priority: {}", v.priority.as_str());
    if !v.assignees.is_empty() {
        let names: Vec<String> = v.assignees.iter().map(|u| u.short()).collect();
        println!("assignees: {}", names.join(", "));
    }
    if !v.label_names.is_empty() {
        println!("labels:   {}", v.label_names.join(", "));
    }
    if v.provisional {
        println!("(provisional — issue body not yet synced)");
    }
    if !v.description.is_empty() {
        println!("\n{}", v.description);
    }
    if !v.comments.is_empty() {
        println!("\n## Comments ({})", v.comments.len());
        for c in &v.comments {
            let who = c.author_nick.clone().unwrap_or_else(|| c.author.short());
            println!("{} · {}  {}", who, c.ts, c.body);
        }
    }
    // Corruption is reported, never rendered as content: a malformed record gets
    // a diagnostic line under its own heading, so it can't be mistaken for
    // something a person actually wrote.
    if !v.corrupt_records.is_empty() {
        println!("\n## Corrupt records ({})", v.corrupt_records.len());
        for r in &v.corrupt_records {
            println!("{} · {}", r.locus, r.reason);
        }
        println!("(these are stored records that do not conform to the schema; run with --json for the raw values)");
    }
}

/// `invite` display: bare token + link + a scannable terminal QR of the link,
/// best-effort clipboard, and the optional `--email <addr>` (open the OS mail
/// client with a prefilled invite). The QR always renders in human output; it is
/// suppressed only under `--json` so scripts get clean, parseable output.
pub async fn run_invite(
    home: &Path,
    email: Option<String>,
    role: Option<String>,
    reusable: bool,
    ttl_hours: Option<u64>,
    out: Out,
) -> Result<()> {
    let resp = client(
        home,
        Request::Invite {
            role,
            reusable,
            ttl_hours,
        },
    )
    .await?;
    let token = match resp {
        Response::Ref { reff } => reff.trim().to_string(),
        other => {
            print_response(&other, out);
            return Ok(());
        }
    };
    // Under --json, emit the ticket as the versioned DTO and stop — no bare
    // lines, no QR/clipboard/mail chrome (the link is derivable from the ticket).
    if out.json {
        emit_text(&token, out);
        return Ok(());
    }
    let link = format!("lait://join/{token}");
    println!("{token}");
    println!("{link}");
    let copied = copy_to_clipboard(&token);
    // The QR is a scan-on-your-phone convenience; an invite ticket is long, so the
    // matrix can be taller/wider than the terminal. Render it only when it fits —
    // otherwise it explodes the scrollback for no gain (the link is right above and
    // on the clipboard). Suppress with $LAIT_NO_QR for a clean, QR-free invite.
    if std::env::var_os("LAIT_NO_QR").is_none() {
        match render_qr(&link) {
            Ok(q) => {
                let (cols, rows) = crossterm::terminal::size().unwrap_or((80, 24));
                let qw = q.lines().map(|l| l.chars().count()).max().unwrap_or(0);
                let qh = q.lines().count();
                if qw <= cols as usize && qh + 3 <= rows as usize {
                    println!("\n{q}");
                } else {
                    println!("(QR omitted — too large for this terminal; use the link above)");
                }
            }
            Err(e) => eprintln!("(qr unavailable: {e:#})"),
        }
    }
    if copied {
        println!("(copied to clipboard)");
    }
    // Tell the host what this link actually does, so the mental model matches
    // the flow: accepting the invite IS the approval.
    let hint = if reusable {
        "anyone who runs `lait join <link>` is admitted automatically until it expires"
    } else {
        "your teammate runs `lait join <link>` and is admitted automatically — no approve step"
    };
    println!("→ {hint}");
    if let Some(addr) = email {
        match open_mail_invite(&addr, &link) {
            Ok(()) => {
                if !out.json {
                    println!("(opening your mail client to {addr}…)");
                }
            }
            Err(e) => eprintln!("(could not open mail client: {e:#})"),
        }
    }
    Ok(())
}

/// Copy `s` to the system clipboard, best-effort, using the platform's native
/// tool: `clip` (Windows), `pbcopy` (macOS), or `wl-copy`/`xclip` (Linux).
/// `pub(crate)` so the interactive members picker can copy a fresh invite link.
pub(crate) fn copy_to_clipboard(s: &str) -> bool {
    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[
        ("clip", &[]),
        (
            "powershell",
            &["-NoProfile", "-Command", "$input | Set-Clipboard"],
        ),
    ];
    #[cfg(target_os = "macos")]
    let candidates: &[(&str, &[&str])] = &[("pbcopy", &[])];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates: &[(&str, &[&str])] =
        &[("wl-copy", &[]), ("xclip", &["-selection", "clipboard"])];

    for (cmd, args) in candidates {
        let Ok(mut child) = std::process::Command::new(cmd)
            .args(*args)
            .stdin(Stdio::piped())
            .spawn()
        else {
            continue;
        };
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(s.as_bytes());
        }
        if child.wait().map(|st| st.success()).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Render a scannable QR of the invite link as terminal half-block glyphs. Uses
/// the lowest error-correction level (`L`) so a long invite ticket yields the
/// smallest module count — the QR still scans, but takes far fewer lines than the
/// default level. `pub(crate)` so other local presentation code can reuse it.
pub(crate) fn render_qr(data: &str) -> Result<String> {
    use qrcode::{render::unicode, EcLevel, QrCode};
    let code = QrCode::with_error_correction_level(data.as_bytes(), EcLevel::L)
        .context("build QR code")?;
    Ok(code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Light)
        .light_color(unicode::Dense1x2::Dark)
        .quiet_zone(true)
        .build())
}

/// Open the OS default mail client with a prefilled invite (mailto). lait sends
/// nothing itself — it just hands the URL to the platform handler.
fn open_mail_invite(addr: &str, link: &str) -> Result<()> {
    let subject = "Invitation to my lait space";
    let body = format!(
        "You're invited to my lait space.\n\n\
         1. Install lait\n   \
         macOS/Linux:  curl --proto '=https' --tlsv1.2 -LsSf \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.sh | sh\n   \
         Windows:      powershell -c \"irm \
         https://github.com/Nixie-Tech-LLC/lait/releases/latest/download/lait-installer.ps1 | iex\"\n\n\
         2. Join the space\n   lait join {link}\n\n\
         The link carries a one-time pass, so that admits you automatically and \
         your device gets the space key (run `lait status` to see when you're \
         in). lait is local-first and end-to-end encrypted.\n"
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        addr,
        percent_encode(subject),
        percent_encode(&body)
    );
    open_url(&mailto)
}

/// Minimal RFC-3986 percent-encoding for mailto query components (unreserved set
/// passes through; everything else is `%XX`). Avoids a url-crate dependency.
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Hand a URL to the OS default handler. Uses `rundll32 …FileProtocolHandler` on
/// Windows (robust with `&` in mailto query strings, unlike `cmd start`).
fn open_url(url: &str) -> Result<()> {
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("rundll32");
        c.args(["url.dll,FileProtocolHandler", url]);
        c
    };
    #[cfg(target_os = "macos")]
    let mut cmd = {
        let mut c = std::process::Command::new("open");
        c.arg(url);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = {
        let mut c = std::process::Command::new("xdg-open");
        c.arg(url);
        c
    };
    cmd.stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("launch OS url handler")?;
    Ok(())
}

fn kind_str(k: &EventKind) -> &'static str {
    match k {
        EventKind::Join => "join",
        EventKind::Presence => "presence",
        EventKind::System => "system",
    }
}

fn print_event(e: &Event) {
    match e.kind {
        // Surface the joiner's short key so an admin can recognize them straight
        // from the log, not just `--json`.
        EventKind::Join => {
            let short: String = e.id.chars().take(8).collect();
            println!("[join] {} ({}): {}", e.nick, short, e.text);
        }
        EventKind::Presence => println!("[presence] {}: {}", e.nick, e.text),
        EventKind::System => println!("[system] {}: {}", e.nick, e.text),
    }
}

/// Build the per-OS shell invocation for a `watch --exec` hook. `sh -c` doesn't
/// exist on stock Windows, so a hook there silently failed to start; use the
/// native `cmd /C` instead (mirrors how `copy_to_clipboard`/`open_url` split).
fn hook_command(cmd: &str) -> std::process::Command {
    #[cfg(windows)]
    {
        let mut c = std::process::Command::new("cmd");
        c.arg("/C").arg(cmd);
        c
    }
    #[cfg(not(windows))]
    {
        let mut c = std::process::Command::new("sh");
        c.arg("-c").arg(cmd);
        c
    }
}

fn run_hook(cmd: &str, e: &Event) {
    let json = serde_json::to_string(e).unwrap_or_default();
    let mut command = hook_command(cmd);
    let child = command
        .env("LAIT_EVENT_SEQ", e.seq.to_string())
        .env("LAIT_EVENT_KIND", kind_str(&e.kind))
        .env("LAIT_EVENT_NICK", &e.nick)
        .env("LAIT_EVENT_ID", &e.id)
        .env("LAIT_EVENT_TEXT", &e.text)
        .env("LAIT_EVENT_TS", e.ts.to_string())
        .stdin(Stdio::piped())
        .spawn();
    match child {
        Ok(mut child) => {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(json.as_bytes());
            }
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
        Err(err) => eprintln!("watch: hook failed to start: {err}"),
    }
}

/// Wrap `s` as a single-quoted PowerShell string literal (doubling embedded
/// quotes) so an event nick/text can't break out of the notify command.
#[cfg(target_os = "windows")]
fn ps_single_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

fn desktop_notify(e: &Event) {
    let title = format!("lait: {}", e.nick);
    #[cfg(target_os = "macos")]
    {
        let script = format!("display notification {:?} with title {:?}", e.text, title);
        let _ = std::process::Command::new("osascript")
            .arg("-e")
            .arg(script)
            .spawn();
    }
    #[cfg(target_os = "windows")]
    {
        // Best-effort tray balloon via PowerShell NotifyIcon — no external module
        // (BurntToast etc.) required, works on stock Windows 10/11.
        let script = format!(
            "Add-Type -AssemblyName System.Windows.Forms; \
             $n = New-Object System.Windows.Forms.NotifyIcon; \
             $n.Icon = [System.Drawing.SystemIcons]::Information; \
             $n.Visible = $true; \
             $n.ShowBalloonTip(5000, {}, {}, 'Info'); \
             Start-Sleep -Milliseconds 6000; $n.Dispose()",
            ps_single_quote(&title),
            ps_single_quote(&e.text),
        );
        let _ = std::process::Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &script])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("notify-send")
            .arg(&title)
            .arg(&e.text)
            .spawn();
    }
}

/// Foreground presence-notification runner (the `watch` command).
///
/// Parks on a streaming [`Request::Subscribe`] and treats the doorbell purely as
/// a **wake signal**: a frame carries a dirty *flag*, never the events, so each
/// `presence_advanced` ring is followed by a `Log{since}` re-read for the
/// authoritative rows.
///
/// Two cursors are in play and they are **not** interchangeable: `cursor` is an
/// `EventLog` seq (what `Log{since}` filters on), while the doorbell carries its
/// own per-session `seq`. We never compare them. The doorbell's `epoch` is the
/// one field that matters here — a change means the daemon restarted, which
/// resets the `EventLog` sequence to 0, voiding our cursor. Rebaselining to 0
/// on an epoch change is what keeps `watch` from going deaf across a restart:
/// the old `Wait` poll loop held its stale high-water and silently matched
/// nothing forever.
pub async fn watch(
    home: &Path,
    since: Option<u64>,
    exec: Option<String>,
    notify: bool,
) -> Result<()> {
    ensure_daemon(home).await?;
    // Default to the current high-water: `watch` follows from now, not from the
    // start of the daemon's history.
    let mut cursor = match since {
        Some(n) => n,
        None => match request(home, &Request::Log { since: 0 }).await? {
            Response::Events { last, .. } => last,
            _ => 0,
        },
    };
    eprintln!("watching from seq {cursor} (Ctrl-C to stop)\u{2026}");

    let mut epoch: Option<u64> = None;
    loop {
        let mut sub = match control::subscribe(home, 0).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("watch: {e}; reconnecting\u{2026}");
                tokio::time::sleep(Duration::from_millis(500)).await;
                let _ = ensure_daemon(home).await;
                continue;
            }
        };
        loop {
            let frame = match sub.next().await {
                Ok(Some(f)) => f,
                // EOF or a broken stream: the daemon stopped or restarted. Drop
                // to the outer loop, which respawns it and re-subscribes.
                Ok(None) => break,
                Err(e) => {
                    eprintln!("watch: {e}; reconnecting\u{2026}");
                    break;
                }
            };
            // A new epoch ⇒ a new daemon ⇒ the EventLog seq restarted at 0, so
            // anything we remember is from a log that no longer exists.
            if epoch.is_some_and(|prev| prev != frame.epoch) {
                eprintln!("watch: daemon restarted; rebaselining\u{2026}");
                cursor = 0;
            }
            epoch = Some(frame.epoch);
            // `reset` covers first-frame + doorbell ring-overrun. Our EventLog
            // cursor survives both (only an epoch change voids it), so a reset
            // is just another reason to re-read.
            if !(frame.presence_advanced || frame.reset) {
                continue;
            }
            match request(home, &Request::Log { since: cursor }).await {
                Ok(Response::Events { events, last }) => {
                    for e in &events {
                        print_event(e);
                        if let Some(cmd) = &exec {
                            run_hook(cmd, e);
                        }
                        if notify {
                            desktop_notify(e);
                        }
                    }
                    cursor = last.max(cursor);
                }
                Ok(_) => {}
                Err(e) => eprintln!("watch: {e}"),
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
        let _ = ensure_daemon(home).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Priority;

    #[test]
    fn client_side_exit_codes_come_from_the_type_not_the_prose() {
        // Classified errors carry their documented code.
        assert_eq!(
            exit_code_for_error(&CliError::not_found("no space matches 'x'").into()),
            2,
        );
        assert_eq!(
            exit_code_for_error(&CliError::unreachable("daemon is deaf").into()),
            3,
        );
        // ...and anything unclassified stays 1, so this is additive rather than a
        // reclassification of every existing `anyhow!`.
        assert_eq!(exit_code_for_error(&anyhow!("something went wrong")), 1);
        // The code must survive `.context()`: callers add context freely, and a
        // wrapped not-found is still a not-found. (This is the whole reason the
        // class is a type and not a prefix on the message.)
        let wrapped = Err::<(), _>(anyhow::Error::from(CliError::not_found("gone")))
            .context("while resolving -w")
            .unwrap_err();
        assert_eq!(exit_code_for_error(&wrapped), 2);
    }

    #[test]
    fn destructive_verbs_ask_and_the_rest_do_not() {
        // The three that destroy something ask. This list IS the policy, so a new
        // destructive verb that forgets to register here fails this test rather
        // than silently shipping without a prompt.
        for req in [
            Request::IssueDelete {
                reff: "ENG-1".into(),
            },
            Request::MemberRemove { who: "ada".into() },
            Request::KeyRotate,
        ] {
            assert!(
                destructive_question(&req).is_some(),
                "{req:?} destroys something and must be confirmed",
            );
        }
        // Reads and ordinary writes must never prompt — prompting on these would
        // break every script that files or lists issues.
        for req in [
            Request::List {
                project: None,
                filter: Default::default(),
            },
            Request::IssueView {
                reff: "ENG-1".into(),
            },
            Request::IssueNew {
                title: "t".into(),
                project: None,
                project_hint: None,
                body: None,
                due: None,
                estimate: None,
                assignees: vec![],
                priority: None,
                labels: vec![],
            },
        ] {
            assert!(
                destructive_question(&req).is_none(),
                "{req:?} is not destructive and must not prompt",
            );
        }
    }

    #[test]
    fn confirm_never_blocks_without_a_way_to_ask() {
        // `--yes` is the scripted path: yes, without touching the terminal.
        assert_eq!(
            confirm(
                "x?",
                Out {
                    yes: true,
                    ..Out::default()
                }
            ),
            Confirmed::Yes,
        );
        // `--json` is a machine contract — a prompt would corrupt the stream, so
        // it reports CannotAsk instead of asking. The caller turns that into an
        // error naming `--yes`; it must never wait on stdin.
        assert_eq!(
            confirm(
                "x?",
                Out {
                    json: true,
                    ..Out::default()
                }
            ),
            Confirmed::CannotAsk,
        );
        // Under `cargo test` stdin/stdout are not terminals, which is exactly the
        // CI/agent shape: no TTY → CannotAsk, never a silent hang.
        assert_eq!(confirm("x?", Out::default()), Confirmed::CannotAsk);
    }

    #[test]
    fn paint_is_gated_on_color() {
        // Color off → the string passes through untouched (pipes/`--no-color`/
        // `$NO_COLOR`/non-tty stay clean); color on → wrapped in the code + reset.
        assert_eq!(paint(false, ansi::RED, "hi"), "hi");
        let on = paint(true, ansi::RED, "hi");
        assert!(on.starts_with(ansi::RED) && on.ends_with(ansi::RESET) && on.contains("hi"));
    }

    #[test]
    fn exit_code_is_derived_from_typed_kind_not_prose() {
        // A resolution miss → exit 2, regardless of the (rewordable) message.
        assert_eq!(exit_code_for_kind(ErrorKind::NotFound), 2);
        assert_eq!(exit_code_for_kind(ErrorKind::Error), 1);
        // The constructors carry the kind, and it survives a DTO round-trip so a
        // --json consumer / MCP agent sees the same classification.
        let nf = Response::not_found("no issue matches 'ENG-9x'");
        let json = serde_json::to_string(&nf).unwrap();
        assert!(json.contains("\"error_kind\":\"not_found\""));
        match serde_json::from_str::<Response>(&json).unwrap() {
            Response::Error { error_kind, .. } => assert_eq!(error_kind, ErrorKind::NotFound),
            other => panic!("round-trip changed variant: {other:?}"),
        }
        // A legacy error object with no error_kind field defaults to Error (exit 1).
        let legacy: Response =
            serde_json::from_str(r#"{"kind":"error","message":"boom"}"#).unwrap();
        assert!(matches!(
            legacy,
            Response::Error {
                error_kind: ErrorKind::Error,
                ..
            }
        ));
    }

    #[test]
    fn prio_badge_colorless_is_plain() {
        assert_eq!(prio_badge(Priority::Urgent, false), "·U·");
        // Colored urgent badge carries an ANSI escape but the same visible text.
        let c = prio_badge(Priority::Urgent, true);
        assert!(c.contains("·U·") && c.contains('\u{1b}'));
    }
}
