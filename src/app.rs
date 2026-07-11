//! Binary entry point logic: parse the CLI and dispatch. Lives in the lib (not
//! `main.rs`) so integration tests and doctests can drive the same command
//! surface the binary exposes. `main.rs` is a thin shim over [`run`].
//!
//! The command surface follows UI.md §2: flat verbs act on **issues**, plural
//! nouns manage **registries** (`label <ref> +bug` vs `labels new`), and every
//! `<ref>` is resolved daemon-side (UI.md §3). Each verb maps to exactly one
//! Layer-B `Request` (S§7), which keeps one command = one commit = one activity
//! row (S§7.1).

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    cli::Out,
    config::{self, load_or_create_identity, Profile},
    control::{BoardPos, Filter, Request},
    install::{self, Client, Scope},
    mcp, node,
};

#[derive(Parser, Debug)]
#[command(
    name = "groupchat",
    version,
    about = "A local-first, peer-to-peer issue tracker"
)]
pub struct Cli {
    /// Select the node's home directory (overrides $GROUPCHAT_HOME).
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
    Daemon,
    /// Run the MCP server over stdio (for agents).
    Mcp,
    /// Register groupchat's MCP server with an agent's config.
    InstallMcp {
        #[arg(long, value_enum, default_value_t = Client::Claude)]
        client: Client,
        #[arg(long, value_enum)]
        scope: Option<Scope>,
        #[arg(long, default_value = "groupchat")]
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
    /// Stop the running daemon.
    Stop,
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
/// default, which turns a closed downstream pipe (`groupchat board | head`,
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
    matches!(cmd, Command::Daemon | Command::Mcp)
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
            load_or_create_identity(&home)?;
            println!("resumed identity '{name}'");
            return crate::cli::run(&home, Request::Status, out).await;
        }
        _ => {}
    }

    // Home resolution honours an explicit --home over the session registry.
    if let Some(h) = &args.home {
        std::env::set_var("GROUPCHAT_HOME", h);
    }
    let home = config::resolve_home(None)?;

    match args.command {
        Command::Init { nick, room } => {
            let key = load_or_create_identity(&home)?;
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
            let key = load_or_create_identity(&home)?;
            println!("{}", key.public());
        }
        Command::Daemon => {
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "groupchat=info,warn".into()),
                )
                .init();
            node::run_daemon(home).await?;
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
        Command::Agents | Command::Resume { .. } => unreachable!("handled before resolution"),
        Command::Stop => crate::cli::run(&home, Request::Stop, out).await?,
    }

    Ok(())
}
