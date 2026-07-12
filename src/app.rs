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
    version,
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
    /// Show a full issue — lazily loads the issue doc.
    Show { reff: String },
    /// Patch an issue's LWW fields (one commit = one activity row).
    Edit {
        reff: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        status: Option<String>,
        #[arg(long)]
        priority: Option<String>,
    },
    /// Set project (truth) and/or board position (order).
    Move {
        reff: String,
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
    /// Delete (tombstone) an issue.
    Delete { reff: String },
    /// The issue's derived activity/time-travel feed.
    History { reff: String },
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
    /// Print a base32 ticket others use to join your workspace.
    Invite,
    /// Join a workspace from a ticket and announce a join request.
    Join { ticket: String },
    /// Manage pinned always-on **seed** peers — the P2P "remote". A seed is a
    /// sticky bootstrap + backfill anchor your node always dials, so you converge
    /// even when no laptop peer is online. It is not a trust authority (genesis/
    /// ACL still gate every op, A§10). Set one up with `daemon --seed` on the box.
    Seed {
        #[command(subcommand)]
        cmd: SeedCmd,
    },
    /// One-step onboarding: connect to a workspace from a ticket.
    Connect {
        ticket: String,
        #[arg(long)]
        nick: Option<String>,
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
    /// List your identities (each agent/session is its own private identity).
    Agents,
    /// Resume (or create) a named identity for this session.
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
    /// Pin a seed and adopt its workspace. Accepts a room ticket (from
    /// `lait invite` on the seed — adopts + backfills) or a bare endpoint id
    /// (pin only, for a workspace you already share).
    Add {
        /// A room ticket or an endpoint id.
        target: String,
    },
    /// List pinned seeds and whether each is currently reachable.
    Ls,
    /// Unpin a seed by endpoint id (or id-prefix) or nick.
    Rm {
        /// Endpoint id (or prefix) or nick to unpin.
        who: String,
    },
}

#[derive(Subcommand, Debug)]
pub enum MembersCmd {
    /// Add a member (admin-only). Seals the workspace key to them.
    Add {
        /// A user ref: @me or a 64-hex ed25519 key.
        who: String,
        #[arg(long)]
        admin: bool,
    },
    /// Remove a member (admin-only) and rotate the workspace key.
    Remove {
        who: String,
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
    let status = tokio::task::spawn_blocking(|| {
        self_update::backends::github::Update::configure()
            .repo_owner("Nixie-Tech-LLC")
            .repo_name("lait")
            .bin_name("lait")
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

pub async fn run() -> Result<()> {
    let args = Cli::parse();
    if !is_service_command(&args.command) {
        reset_sigpipe();
    }
    let out = Out {
        json: args.json,
        color: !args.no_color,
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
        Command::Agents => {
            let names = config::list_identities()?;
            if names.is_empty() {
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
            println!("resumed identity '{name}'");
            return crate::cli::run(&home, Request::Status, out).await;
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
            println!("initialized.");
            println!("id:   {}", key.public());
            println!("nick: {}", profile.nick);
            println!("room: {}", profile.room);
            println!("home: {}", home.display());
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
        Command::Show { reff } => crate::cli::run(&home, Request::IssueView { reff }, out).await?,
        Command::Edit {
            reff,
            title,
            status,
            priority,
        } => {
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
            crate::cli::run(&home, Request::IssueDelete { reff }, out).await?
        }
        Command::History { reff } => crate::cli::run(&home, Request::History { reff }, out).await?,
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
            Some(MembersCmd::Add { who, admin }) => {
                crate::cli::run(&home, Request::MemberAdd { who, admin }, out).await?
            }
            Some(MembersCmd::Remove { who }) => {
                crate::cli::run(&home, Request::MemberRemove { who }, out).await?
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
            println!("{}", key.public());
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
        Command::Invite => crate::cli::run_invite(&home, out).await?,
        Command::Join { ticket } => crate::cli::run(&home, Request::Join { ticket }, out).await?,
        Command::Seed { cmd } => match cmd {
            SeedCmd::Add { target } => {
                crate::cli::run(&home, Request::SeedAdd { arg: target }, out).await?
            }
            SeedCmd::Ls => crate::cli::run(&home, Request::SeedList, out).await?,
            SeedCmd::Rm { who } => crate::cli::run(&home, Request::SeedRemove { who }, out).await?,
        },
        Command::Connect { ticket, nick } => {
            if let Some(n) = nick {
                let mut profile = Profile::load(&home)?;
                profile.nick = n;
                profile.save(&home)?;
            }
            crate::cli::run(&home, Request::Connect { ticket }, out).await?
        }
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
        Command::Agents
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
