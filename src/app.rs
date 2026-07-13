//! Binary entry point logic: parse the CLI and dispatch. Lives in the lib (not
//! `main.rs`) so integration tests and doctests can drive the same command
//! surface the binary exposes. `main.rs` is a thin shim over [`run`].
//!
//! The command surface follows UI.md §2: flat verbs act on **issues**, plural
//! nouns manage **registries** (`label <ref> +bug` vs `labels new`), and every
//! `<ref>` is resolved daemon-side (UI.md §3). Each verb maps to exactly one
//! Layer-B `Request` (S§7), which keeps one command = one commit = one activity
//! row (S§7.1).

use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};

use crate::{
    cli::Out,
    config::{self, load_or_create_identity, Profile},
    control::{BoardPos, Filter, Request},
    install::{self, Client, Scope},
    mcp, node,
};

#[derive(Parser, Debug)]
#[command(
    name = "lait",
    // `LAIT_VERSION_LONG` is stamped by build.rs: a clean semver for releases, or
    // a `-dev+<sha> (<date>)` suffix for dev-channel/nightly builds.
    version = env!("LAIT_VERSION_LONG"),
    about = "A local-first, peer-to-peer issue tracker"
)]
pub struct Cli {
    /// Select the node's home directory (overrides $LAIT_HOME).
    #[arg(long, global = true)]
    home: Option<String>,
    /// Emit the versioned JSON DTO instead of human output (UI.md §2.3).
    #[arg(long, global = true)]
    json: bool,
    /// Disable ANSI colours.
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Initialize identity and workspace settings (nickname, room/workspace).
    Init {
        #[arg(long)]
        nick: Option<String>,
        #[arg(long)]
        room: Option<String>,
    },
    /// Create an issue; echoes the resolved handle.
    New {
        title: String,
        #[arg(short = 'p', long)]
        project: Option<String>,
        #[arg(short = 'a', long = "assign")]
        assignees: Vec<String>,
        #[arg(short = 'P', long)]
        priority: Option<String>,
        #[arg(short = 'l', long = "label")]
        labels: Vec<String>,
        #[arg(short = 'b', long)]
        body: Option<String>,
    },
    /// List issue rows from the Catalog cache (no issue-doc loads).
    Ls {
        #[arg(short = 'p', long)]
        project: Option<String>,
        #[arg(long)]
        mine: bool,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        label: Option<String>,
        #[arg(long)]
        all: bool,
    },
    /// Render a project's board (workflow columns × ordered rows).
    Board { project: String },
    /// Show a full issue — lazily loads the issue doc. The ref is optional: on a
    /// branch like `eng-142-fix`, `lait show` infers `ENG-142`.
    Show { reff: Option<String> },
    /// Patch an issue's LWW fields (one commit = one activity row). The ref is
    /// optional — inferred from the git branch (e.g. `eng-142-…` → `ENG-142`).
    Edit {
        reff: Option<String>,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        priority: Option<String>,
    },
    /// Set project (truth) and/or board position (order). The ref is optional —
    /// inferred from the git branch when omitted.
    Move {
        reff: Option<String>,
        #[arg(short = 'p', long)]
        project: Option<String>,
        #[arg(long)]
        top: bool,
        #[arg(long)]
        bottom: bool,
        #[arg(long)]
        before: Option<String>,
        #[arg(long)]
        after: Option<String>,
    },
    /// Add/remove assignees (present-key set).
    Assign {
        reff: String,
        who: Vec<String>,
        #[arg(long)]
        remove: bool,
    },
    /// Add (`+LABEL`) / remove (`-LABEL`) labels on an issue.
    Label {
        reff: String,
        /// Tokens like `+bug` (add) or `-wip` (remove).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        tokens: Vec<String>,
    },
    /// Append a comment (immutable body). No BODY → read stdin.
    Comment { reff: String, body: Option<String> },
    /// Delete (tombstone) an issue. The ref is optional — inferred from the git
    /// branch when omitted.
    Delete { reff: Option<String> },
    /// The issue's derived activity/time-travel feed. The ref is optional —
    /// inferred from the git branch when omitted.
    History { reff: Option<String> },
    /// Manage the project registry.
    Projects {
        #[command(subcommand)]
        cmd: Option<ProjectsCmd>,
    },
    /// Manage the label registry.
    Labels {
        #[command(subcommand)]
        cmd: Option<LabelsCmd>,
    },
    /// Manage workspace membership (the signed ACL, P3). `members` lists.
    Members {
        #[command(subcommand)]
        cmd: Option<MembersCmd>,
    },
    /// Workspace-wide recent transitions.
    Activity {
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Launch the full-screen TUI board.
    Tui,
    /// Guided-join verifier: diagnose why you can't "get to work" yet — an ordered
    /// readout of the onboarding gates (workspace, daemon, membership, peer, sync)
    /// naming the one thing that's blocking you. Runs automatically as the tail of
    /// `join`. (Alias: `verify`.)
    #[command(alias = "verify")]
    Doctor,
    /// List the workspaces you've joined and where each one lives on this machine
    /// — the breadcrumb for "which directory holds the board I joined?".
    Workspaces,
    /// Print our endpoint id (the handle others use to reach us).
    Id,
    /// Run the node daemon in the foreground.
    Daemon {
        /// Run as an always-on seed: never idle-shut-down, so the node stays
        /// reachable to serve sync and backfill history to peers even with no
        /// local client attached and no peer currently online (DUR-4). Add it to
        /// the workspace with `members add <its-id>` so it can decrypt and hold
        /// the full history peers pull from.
        #[arg(long)]
        seed: bool,
    },
    /// Run the MCP server over stdio (for agents).
    Mcp,
    /// Register lait's MCP server with an agent's config.
    InstallMcp {
        #[arg(long, value_enum, default_value_t = Client::Claude)]
        client: Client,
        #[arg(long, value_enum)]
        scope: Option<Scope>,
        #[arg(long, default_value = "lait")]
        name: String,
        #[arg(long)]
        print: bool,
    },
    /// Show node and workspace status.
    Status,
    /// Print a base32 ticket (+ a scannable QR of the invite link) others use to
    /// join your workspace. By default the ticket carries a signed, single-use
    /// pass so your teammate is admitted automatically on `join` — no separate
    /// approve step.
    Invite {
        /// Open your mail client with a prefilled invite to this address (uses the
        /// OS default mailto handler; lait sends nothing itself).
        #[arg(long)]
        email: Option<String>,
        /// Mint a pass-less ticket: the joiner lands as a pending request you must
        /// `members approve` by key — the classic, human-in-the-loop flow. Mutually
        /// exclusive with the pass-tuning flags below (there is no pass to tune).
        #[arg(long, conflicts_with_all = ["reusable", "ttl_hours"])]
        require_approval: bool,
        /// Let one ticket admit your whole team (valid until it expires) instead of
        /// a single person.
        #[arg(long)]
        reusable: bool,
        /// Hours until the pass expires (default 168 = 7 days). Must be ≥ 1.
        #[arg(long, value_name = "HOURS", value_parser = clap::value_parser!(u64).range(1..))]
        ttl_hours: Option<u64>,
    },
    /// Join a workspace from an invite link. A default link admits you
    /// automatically; a `--require-approval` link instead sends a request an admin
    /// must approve. Either way your board decrypts and syncs once you're in —
    /// check progress with `lait status`. (Alias: `connect`.)
    #[command(alias = "connect")]
    Join {
        /// The invite link / ticket from `lait invite`.
        ticket: String,
        /// Set your display name as you join — what the admin sees on your
        /// pending request (a self-asserted claim; they approve you by key).
        #[arg(long)]
        nick: Option<String>,
    },
    /// Manage pinned **remotes** — always-on peers your node always dials for
    /// bootstrap + backfill, so you converge even when no laptop peer is online.
    /// A remote is not a trust authority (genesis/ACL still gate every op, A§10);
    /// stand one up with `daemon --seed` on an always-on box. (Alias: `seed`.)
    #[command(alias = "seed")]
    Remote {
        #[command(subcommand)]
        cmd: SeedCmd,
    },
    /// Print presence/system events (optionally only after --since).
    Log {
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Block until a new presence event arrives, then print it.
    Wait {
        #[arg(long, default_value_t = 0)]
        since: u64,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Follow presence events like a notification stream.
    Watch {
        #[arg(long)]
        since: Option<u64>,
        #[arg(long)]
        exec: Option<String>,
        #[arg(long)]
        notify: bool,
        #[arg(long, default_value_t = 60_000)]
        timeout_ms: u64,
    },
    /// List peers and their online status.
    Who,
    /// List your profiles — each is a separate private identity with its own key
    /// and store (e.g. one per agent/session). (Alias: `agents`.)
    #[command(alias = "agents")]
    Profiles,
    /// Switch to (or create) a named profile for this session.
    Resume { name: String },
    /// Update lait in place from the latest GitHub release (native self-update).
    Update,
    /// Stop the running daemon.
    Stop,
    /// Print shell completions to stdout for the given shell (bash, zsh, fish,
    /// powershell, elvish). E.g. `lait completions bash > ~/.local/share/bash-completion/completions/lait`.
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
    /// Render the lait(1) man page (roff) to stdout.
    Man,
}

#[derive(Subcommand, Debug)]
pub enum ProjectsCmd {
    New {
        name: String,
        #[arg(long)]
        key: String,
    },
    Ls,
}

#[derive(Subcommand, Debug)]
pub enum LabelsCmd {
    New {
        name: String,
        #[arg(long)]
        color: Option<String>,
    },
    Ls,
}

#[derive(Subcommand, Debug)]
pub enum SeedCmd {
    /// Pin a remote and adopt its workspace. Accepts an invite link (from
    /// `lait invite` on the remote — adopts + backfills) or a bare endpoint id
    /// (pin only, for a workspace you already share).
    Add {
        /// An invite link or an endpoint id.
        target: String,
    },
    /// List pinned remotes and whether each is currently reachable.
    Ls,
    /// Unpin a remote by endpoint id (or id-prefix) or name.
    Rm {
        /// Endpoint id (or prefix) or name to unpin.
        who: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum MembersCmd {
    /// Add a member (admin-only). Seals the workspace key to them.
    Add {
        /// A user ref: @me, a local name you've set, a key id-prefix, or a full
        /// 64-hex key. (A self-asserted wire name is NOT accepted — name people
        /// yourself with `--as` / `members name`.)
        who: String,
        #[arg(long)]
        admin: bool,
        /// Attach a local name to this key as you add them (never synced).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
    /// Remove a member (admin-only) and rotate the workspace key.
    Remove {
        /// A user ref: @me, a local name, a key id-prefix, or a full 64-hex key.
        who: String,
    },
    /// List pending join requests (people who ran `join`, not yet added).
    Requests,
    /// Approve a pending join request **by id-prefix / key** (admin-only). The
    /// joiner's advertised name is shown only as an unverified hint — confirm the
    /// short key out-of-band, then approve it and name them with `--as`.
    Approve {
        /// A pending requester: a key id-prefix or a full 64-hex key.
        who: String,
        /// Attach a local name to this key as you approve them (never synced).
        #[arg(long = "as", value_name = "NAME")]
        as_name: Option<String>,
    },
    /// Set (or clear, with an empty name) a local **name** for a member/key —
    /// your private label, never broadcast, never part of the signed ACL.
    /// (Alias: `alias`.)
    #[command(alias = "alias")]
    Name {
        /// A user ref: a key id-prefix, a full key, or an existing name.
        who: String,
        /// The name to assign (omit or pass "" to clear).
        #[arg(default_value = "")]
        name: String,
    },
    /// Rotate the workspace key (admin-only).
    RotateKey,
    Ls,
}

/// Parse arguments and run.
/// Restore the default `SIGPIPE` disposition on unix. Rust ignores `SIGPIPE` by
/// default, which turns a closed downstream pipe (`lait board | head`,
/// `| grep -q`, `| less` then quit) into a panic on the next stdout write
/// (`failed printing to stdout: Broken pipe`) instead of a clean exit. Resetting
/// to `SIG_DFL` makes the process terminate normally when the reader goes away —
/// the expected CLI behavior. No-op on Windows (no `SIGPIPE`).
///
/// **Only for short-lived, output-printing CLI commands.** The `daemon` and the
/// `mcp` stdio server must NOT reset it: they are long-running and do network /
/// socket I/O (iroh, tokio), which relies on `SIGPIPE` staying ignored so a write
/// to a closed socket returns `EPIPE` instead of *killing the process*. Resetting
/// it there makes a dropped relay/socket write terminate the daemon.
#[cfg(unix)]
fn reset_sigpipe() {
    // SAFETY: setting a signal handler to the default disposition is async-signal
    // -safe and is the standard fix for Rust CLIs (see rust-lang/rust#46016).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
}
#[cfg(not(unix))]
fn reset_sigpipe() {}

/// Long-running service commands that must keep Rust's default (SIGPIPE ignored)
/// so networked/stdio I/O returns EPIPE instead of dying on a signal.
fn is_service_command(cmd: &Command) -> bool {
    matches!(cmd, Command::Daemon { .. } | Command::Mcp)
}

/// Read-only commands that only *view* a workspace and so must never silently
/// create a decoy store when run in a directory with none (the directory trap,
/// docs/GUIDED-JOIN.md §B). Writes (`new`/`edit`/…), `init`, and `join`
/// legitimately create and are deliberately excluded. `tui` is included: opening
/// the board in a stray directory is exactly the original-bug symptom (an empty
/// decoy board), and the guard only fires when you already have joined workspaces
/// — so a genuine first-time founder (empty registry) is unaffected, while the
/// store-free `lait workspaces` selector remains reachable from anywhere.
fn is_read_only(cmd: &Command) -> bool {
    matches!(
        cmd,
        Command::Ls { .. }
            | Command::Board { .. }
            | Command::Show { .. }
            | Command::History { .. }
            | Command::Activity { .. }
            | Command::Who
            | Command::Status
            | Command::Doctor
            | Command::Tui
            | Command::Projects { cmd: None }
            | Command::Labels { cmd: None }
            | Command::Members { cmd: None }
    )
}

/// `lait update`: update the installed binary in place from the latest GitHub
/// release — natively, in-process, with no external updater binary. Best-effort
/// stops a running daemon first, so it isn't left on stale code and — on Windows —
/// isn't holding the executable open while it is swapped. Then it queries the
/// `Nixie-Tech-LLC/lait` releases, downloads this platform's asset, verifies it,
/// and self-replaces the running executable (all pure-Rust: `ureq` + rustls,
/// gzip/zip extraction, atomic self-replace).
async fn run_update() -> Result<()> {
    if let Some(home) = config::existing_home() {
        if crate::control::request(&home, &Request::Stop).await.is_ok() {
            println!("stopped the running daemon");
            // let the OS release the file handle before the binary is swapped
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
        }
    }

    // The update is blocking (HTTP + archive extract + file swap); run it off the
    // async runtime so it doesn't stall the reactor.
    let status = tokio::task::spawn_blocking(move || {
        self_update::backends::github::Update::configure()
            .repo_owner("Nixie-Tech-LLC")
            .repo_name("lait")
            .bin_name("lait")
            .bin_path_in_archive(update_bin_path_in_archive())
            .current_version(env!("CARGO_PKG_VERSION"))
            .show_download_progress(true)
            .no_confirm(true)
            .build()
            .and_then(|updater| updater.update())
    })
    .await
    .map_err(|e| anyhow!("update task panicked: {e}"))?
    .map_err(|e| anyhow!("self-update failed: {e}"))?;

    if status.updated() {
        println!(
            "updated {} -> v{}. run any lait command to start the daemon on the new version.",
            env!("CARGO_PKG_VERSION"),
            status.version()
        );
    } else {
        println!("already up to date (v{})", status.version());
    }
    Ok(())
}

/// The in-archive path to the `lait` binary for `self_update`, matching
/// cargo-dist's **per-OS** release layout (verified against the published
/// assets): the unix `.tar.gz` archives nest the binary under a
/// `lait-<target-triple>/` directory, while the Windows `.zip` is flat with
/// `lait.exe` at the archive root. `{{ target }}`/`{{ bin }}` are expanded by
/// self_update; the Windows path needs the explicit `.exe` that `{{ bin }}`
/// does not add. Getting this wrong fails extraction with "specified file not
/// found in archive" — which is exactly what a single nested template did on
/// Windows (it only worked on unix, where it was tested).
fn update_bin_path_in_archive() -> &'static str {
    #[cfg(windows)]
    {
        "{{ bin }}.exe"
    }
    #[cfg(not(windows))]
    {
        "lait-{{ target }}/{{ bin }}"
    }
}

/// Pull the first `KEY-n` token (letters `-` digits) out of a string and
/// normalize the key to uppercase: `eng-142-fix-login` → `ENG-142`,
/// `feature/ENG-7` → `ENG-7`. Returns `None` if there's no such token. No regex
/// dependency — a small forward scan.
fn parse_key_n(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i].is_ascii_alphabetic() {
            let start = i;
            while i < b.len() && b[i].is_ascii_alphabetic() {
                i += 1;
            }
            if i < b.len() && b[i] == b'-' {
                let mut j = i + 1;
                while j < b.len() && b[j].is_ascii_digit() {
                    j += 1;
                }
                if j > i + 1 {
                    return Some(format!(
                        "{}-{}",
                        s[start..i].to_ascii_uppercase(),
                        &s[i + 1..j]
                    ));
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

/// Infer an issue ref from the current git branch (VCS-native ergonomics, à la
/// linear-cli): a branch like `eng-142-fix-login` resolves to `ENG-142`, so
/// `lait show` / `edit` / `history` are argument-free while you work the branch.
/// `None` if not in a git repo, detached HEAD, or the branch carries no `KEY-n`.
fn infer_ref_from_git_branch() -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    parse_key_n(String::from_utf8_lossy(&out.stdout).trim())
}

/// Resolve an optional issue-ref argument: the explicit value if given, else the
/// ref inferred from the git branch (with a clear error when neither is available).
fn resolve_reff_arg(reff: Option<String>) -> Result<String> {
    match reff {
        Some(r) => Ok(r),
        None => infer_ref_from_git_branch().ok_or_else(|| {
            anyhow!(
                "no issue given, and none could be inferred from the current git branch \
                 (name it like `eng-142-short-desc`). Pass a ref explicitly, e.g. `lait show ENG-142`."
            )
        }),
    }
}

pub async fn run() -> Result<()> {
    // `try_parse` (not `parse`) so a usage/parse error exits `1` — the documented
    // code (UI.md §2.3) — instead of clap's default `2`, which collides with
    // `2 = ref not found / ambiguous`. `--help`/`--version` still exit `0`.
    let args = match Cli::try_parse() {
        Ok(a) => a,
        Err(e) => {
            e.print().ok();
            let code = match e.kind() {
                clap::error::ErrorKind::DisplayHelp
                | clap::error::ErrorKind::DisplayVersion
                | clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => 0,
                _ => 1,
            };
            std::process::exit(code);
        }
    };
    if !is_service_command(&args.command) {
        reset_sigpipe();
    }
    // Effective color, computed once: honour --no-color, the $NO_COLOR
    // convention, --json (machine output is never styled), and whether stdout is
    // an interactive terminal (so `lait ls | cat` / redirects stay clean).
    use std::io::IsTerminal;
    let out = Out {
        json: args.json,
        color: !args.no_color
            && !args.json
            && std::env::var_os("NO_COLOR").is_none()
            && std::io::stdout().is_terminal(),
    };

    // Stateless commands that need neither an identity nor a workspace store:
    // emit generated shell completions / a man page and exit.
    match &args.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            let name = cmd.get_name().to_string();
            generate(*shell, &mut cmd, name, &mut std::io::stdout());
            return Ok(());
        }
        Command::Man => {
            clap_mangen::Man::new(Cli::command()).render(&mut std::io::stdout())?;
            return Ok(());
        }
        _ => {}
    }

    // Registry-level commands that operate across identities.
    match &args.command {
        Command::Profiles => {
            let names = config::list_identities()?;
            if out.json {
                println!(
                    "{}",
                    serde_json::to_string(&serde_json::json!({ "identities": names }))
                        .unwrap_or_else(|_| "{}".into())
                );
            } else if names.is_empty() {
                println!("no identities yet — one is created on first use");
            } else {
                for n in names {
                    println!("{n}");
                }
            }
            return Ok(());
        }
        Command::Resume { name } => {
            let home = config::bind_session(name)?;
            // A named identity is a self-contained home: pin it as LAIT_HOME
            // so the daemon we spawn uses it for both identity and store, not the
            // global identity + repo-discovered store (DUR-5).
            std::env::set_var("LAIT_HOME", &home);
            load_or_create_identity(&home)?;
            // Under --json only the Status DTO (below) is emitted — no human line
            // leaking ahead of it.
            if !out.json {
                println!("resumed identity '{name}'");
            }
            return crate::cli::run(&home, Request::Status, out).await;
        }
        // The joined-workspace registry: pure navigation state, no store/daemon.
        Command::Workspaces => {
            crate::cli::print_workspaces(out);
            return Ok(());
        }
        _ => {}
    }

    // Home resolution honours an explicit --home over the session registry.
    if let Some(h) = &args.home {
        std::env::set_var("LAIT_HOME", h);
    }
    // `update` swaps the binary; it must not resolve/create a workspace store.
    if matches!(args.command, Command::Update) {
        return run_update().await;
    }
    // Directory-trap guard (docs/GUIDED-JOIN.md §B): a *read-only* command run in a
    // directory with no discoverable `.lait/` must NOT silently create a decoy
    // store — that's exactly how a joiner ends up staring at an empty board in the
    // wrong place. When we know of workspaces they've joined, point them there and
    // exit instead of manufacturing an empty one. `init`/`join` (and writes) still
    // create; an explicit `--home`/`$LAIT_HOME` opts out (existing_home resolves it).
    if is_read_only(&args.command) && config::existing_home().is_none() {
        let known = crate::workspaces::list();
        if !known.is_empty() {
            crate::cli::warn_no_workspace_here(&known, out);
            std::process::exit(2);
        }
    }
    let home = config::resolve_home(None)?;

    match args.command {
        Command::Init { nick, room } => {
            let key = load_or_create_identity(&config::identity_dir()?)?;
            let mut profile = Profile::load(&home)?;
            if let Some(n) = nick {
                profile.nick = n;
            }
            if let Some(r) = room {
                profile.room = r;
            }
            profile.save(&home)?;
            if out.json {
                crate::cli::emit_ok(
                    &format!(
                        "initialized id={} nick={} room={}",
                        key.public(),
                        profile.nick,
                        profile.room
                    ),
                    out,
                );
            } else {
                println!("initialized.");
                println!("id:   {}", key.public());
                println!("nick: {}", profile.nick);
                println!("room: {}", profile.room);
                println!("home: {}", home.display());
            }
        }
        Command::New {
            title,
            project,
            assignees,
            priority,
            labels,
            body,
        } => {
            crate::cli::run(
                &home,
                Request::IssueNew {
                    title,
                    project,
                    assignees,
                    priority,
                    labels,
                    body,
                },
                out,
            )
            .await?
        }
        Command::Ls {
            project,
            mine,
            status,
            label,
            all,
        } => {
            crate::cli::run(
                &home,
                Request::List {
                    project,
                    filter: Filter {
                        mine,
                        status,
                        label,
                        all,
                    },
                },
                out,
            )
            .await?
        }
        Command::Board { project } => {
            crate::cli::run(&home, Request::Board { project }, out).await?
        }
        Command::Show { reff } => {
            let reff = resolve_reff_arg(reff)?;
            crate::cli::run(&home, Request::IssueView { reff }, out).await?
        }
        Command::Edit {
            reff,
            title,
            status,
            priority,
        } => {
            let reff = resolve_reff_arg(reff)?;
            crate::cli::run(
                &home,
                Request::IssueEdit {
                    reff,
                    title,
                    status,
                    priority,
                },
                out,
            )
            .await?
        }
        Command::Move {
            reff,
            project,
            top,
            bottom,
            before,
            after,
        } => {
            let reff = resolve_reff_arg(reff)?;
            let pos = if top {
                Some(BoardPos::Top)
            } else if bottom {
                Some(BoardPos::Bottom)
            } else if let Some(r) = before {
                Some(BoardPos::Before { reff: r })
            } else {
                after.map(|r| BoardPos::After { reff: r })
            };
            crate::cli::run(&home, Request::IssueMove { reff, project, pos }, out).await?
        }
        Command::Assign { reff, who, remove } => {
            crate::cli::run(
                &home,
                Request::Assign {
                    reff,
                    who,
                    add: !remove,
                },
                out,
            )
            .await?
        }
        Command::Label { reff, tokens } => {
            let mut add = Vec::new();
            let mut remove = Vec::new();
            for t in tokens {
                if let Some(l) = t.strip_prefix('+') {
                    add.push(l.to_string());
                } else if let Some(l) = t.strip_prefix('-') {
                    remove.push(l.to_string());
                } else {
                    add.push(t);
                }
            }
            crate::cli::run(&home, Request::Label { reff, add, remove }, out).await?
        }
        Command::Comment { reff, body } => {
            let body = match body {
                Some(b) => b,
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin().read_to_string(&mut s).ok();
                    s.trim_end().to_string()
                }
            };
            crate::cli::run(&home, Request::Comment { reff, body }, out).await?
        }
        Command::Delete { reff } => {
            let reff = resolve_reff_arg(reff)?;
            crate::cli::run(&home, Request::IssueDelete { reff }, out).await?
        }
        Command::History { reff } => {
            let reff = resolve_reff_arg(reff)?;
            crate::cli::run(&home, Request::History { reff }, out).await?
        }
        Command::Projects { cmd } => match cmd {
            Some(ProjectsCmd::New { name, key }) => {
                crate::cli::run(&home, Request::ProjectNew { name, key }, out).await?
            }
            _ => crate::cli::run(&home, Request::ProjectList, out).await?,
        },
        Command::Labels { cmd } => match cmd {
            Some(LabelsCmd::New { name, color }) => {
                crate::cli::run(&home, Request::LabelNew { name, color }, out).await?
            }
            _ => crate::cli::run(&home, Request::LabelList, out).await?,
        },
        Command::Members { cmd } => match cmd {
            Some(MembersCmd::Add {
                who,
                admin,
                as_name,
            }) => {
                crate::cli::run(
                    &home,
                    Request::MemberAdd {
                        who,
                        admin,
                        as_name,
                    },
                    out,
                )
                .await?
            }
            Some(MembersCmd::Remove { who }) => {
                crate::cli::run(&home, Request::MemberRemove { who }, out).await?
            }
            Some(MembersCmd::Requests) => {
                crate::cli::run(&home, Request::MemberRequests, out).await?
            }
            Some(MembersCmd::Approve { who, as_name }) => {
                crate::cli::run(&home, Request::MemberApprove { who, as_name }, out).await?
            }
            Some(MembersCmd::Name { who, name }) => {
                crate::cli::run(&home, Request::MemberAlias { who, name }, out).await?
            }
            Some(MembersCmd::RotateKey) => crate::cli::run(&home, Request::KeyRotate, out).await?,
            _ => crate::cli::run(&home, Request::Members, out).await?,
        },
        Command::Activity { since } => {
            crate::cli::run(&home, Request::Activity { since }, out).await?
        }
        Command::Tui => crate::tui::run(&home).await?,
        Command::Id => {
            let key = load_or_create_identity(&config::identity_dir()?)?;
            crate::cli::emit_text(&key.public().to_string(), out);
        }
        Command::Daemon { seed } => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "lait=info,warn".into()),
                )
                .init();
            node::run_daemon(home, seed).await?;
        }
        Command::Mcp => {
            mcp::run_mcp(&home).await?;
        }
        Command::InstallMcp {
            client,
            scope,
            name,
            print,
        } => {
            let out = install::install_mcp(client, scope, &name, print)?;
            println!("{out}");
        }
        Command::Status => crate::cli::run(&home, Request::Status, out).await?,
        Command::Doctor => {
            crate::cli::run(
                &home,
                Request::Diagnose {
                    expected_workspace: None,
                },
                out,
            )
            .await?
        }
        Command::Invite {
            email,
            require_approval,
            reusable,
            ttl_hours,
        } => {
            crate::cli::run_invite(&home, email, require_approval, reusable, ttl_hours, out).await?
        }
        Command::Join { ticket, nick } => {
            // Set the display name before the daemon is auto-spawned (below, via
            // ensure_daemon) so a cold joiner announces the right name on its
            // join request. It stays a self-asserted claim — the admin approves
            // by key, never by this nick (UI.md §8).
            if let Some(n) = nick {
                let mut profile = Profile::load(&home)?;
                profile.nick = n;
                profile.save(&home)?;
            }
            // `join` runs the guided-join verifier as its tail (passing the ticket's
            // workspace as `expected_workspace`) so the joiner immediately sees the
            // gate readout — including a directory/store mismatch — instead of a
            // bare "ok" that leaves them guessing.
            crate::cli::run_join(&home, ticket, out).await?
        }
        Command::Remote { cmd } => match cmd {
            SeedCmd::Add { target } => {
                crate::cli::run(&home, Request::SeedAdd { arg: target }, out).await?
            }
            SeedCmd::Ls => crate::cli::run(&home, Request::SeedList, out).await?,
            SeedCmd::Rm { who } => crate::cli::run(&home, Request::SeedRemove { who }, out).await?,
        },
        Command::Log { since } => crate::cli::run(&home, Request::Log { since }, out).await?,
        Command::Wait { since, timeout_ms } => {
            crate::cli::run(&home, Request::Wait { since, timeout_ms }, out).await?
        }
        Command::Watch {
            since,
            exec,
            notify,
            timeout_ms,
        } => crate::cli::watch(&home, since, exec, notify, timeout_ms).await?,
        Command::Who => crate::cli::run(&home, Request::Who, out).await?,
        Command::Profiles
        | Command::Workspaces
        | Command::Resume { .. }
        | Command::Update
        | Command::Completions { .. }
        | Command::Man => {
            unreachable!("handled before resolution")
        }
        Command::Stop => crate::cli::run(&home, Request::Stop, out).await?,
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{parse_key_n, update_bin_path_in_archive};

    #[test]
    fn update_bin_path_matches_cargo_dist_per_os_layout() {
        // Regression guard: cargo-dist nests the binary under `lait-<target>/` in
        // the unix tarballs but ships a FLAT Windows zip with `lait.exe` at the
        // root. A single nested template silently broke every Windows self-update
        // ("specified file not found in archive"). Pin the per-OS contract.
        let path = update_bin_path_in_archive();
        if cfg!(windows) {
            // flat + explicit `.exe`; never nested under a target dir on Windows.
            assert_eq!(path, "{{ bin }}.exe");
            assert!(!path.contains('/'), "Windows zip is flat: {path}");
        } else {
            // nested under the per-target directory cargo-dist emits.
            assert_eq!(path, "lait-{{ target }}/{{ bin }}");
            assert!(
                path.contains("{{ target }}"),
                "unix archive is nested: {path}"
            );
        }
    }

    #[test]
    fn key_n_inference_from_branch_names() {
        // Common branch shapes → KEY-n (key upper-cased).
        assert_eq!(parse_key_n("eng-142-fix-login").as_deref(), Some("ENG-142"));
        assert_eq!(parse_key_n("ENG-7").as_deref(), Some("ENG-7"));
        assert_eq!(parse_key_n("feature/eng-142-x").as_deref(), Some("ENG-142"));
        assert_eq!(parse_key_n("bob/PROJ-3-thing").as_deref(), Some("PROJ-3"));
        // No KEY-n present → nothing inferred (fall back to explicit ref).
        assert_eq!(parse_key_n("main"), None);
        assert_eq!(parse_key_n("142-eng"), None);
        assert_eq!(parse_key_n("release/v0.4.5"), None);
        assert_eq!(parse_key_n("feat/onboarding-dx-bridge"), None);
    }
}
