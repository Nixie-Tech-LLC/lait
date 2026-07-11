//! groupchat: a peer-to-peer node built on iroh.
//!
//! One binary, three roles:
//!   * `groupchat daemon` runs the node (endpoint, gossip room, presence).
//!   * `groupchat <cmd>` is a CLI client that drives the daemon over a socket.
//!   * `groupchat mcp` exposes the same actions as MCP tools for an agent.
//!
//! This is the transport/identity/daemon skeleton the P2P issue tracker is built
//! on — see `docs/ARCHITECTURE.md`.

mod cli;
mod config;
mod control;
mod install;
mod mcp;
mod node;
mod presence;
mod proto;
mod registry;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    config::{load_or_create_identity, Profile},
    control::Request,
    install::{Client, Scope},
};

#[derive(Parser, Debug)]
#[command(
    name = "groupchat",
    version,
    about = "A peer-to-peer node built on iroh"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Initialize identity and settings (nickname, room).
    Init {
        #[arg(long)]
        nick: Option<String>,
        #[arg(long)]
        room: Option<String>,
    },
    /// Print our endpoint id (the handle others use to reach us).
    Id,
    /// Run the node daemon in the foreground.
    Daemon,
    /// Run the MCP server over stdio (for agents).
    Mcp,
    /// Register groupchat's MCP server with an agent's config (one explicit
    /// step — merges into the client's mcpServers without touching other servers).
    InstallMcp {
        /// Target agent: claude | cursor | windsurf | generic.
        #[arg(long, value_enum, default_value_t = Client::Claude)]
        client: Client,
        /// Where to write: user (machine-wide) or project (cwd). Defaults per client.
        #[arg(long, value_enum)]
        scope: Option<Scope>,
        /// Name for the MCP server entry.
        #[arg(long, default_value = "groupchat")]
        name: String,
        /// Print the resulting config instead of writing it.
        #[arg(long)]
        print: bool,
    },
    /// Show node and room status.
    Status,
    /// Print a base32 ticket others use to join your room.
    Invite,
    /// Join a room from a ticket and announce a join request.
    Join { ticket: String },
    /// One-step onboarding: connect to a room from a ticket (joins and goes
    /// live). Optionally set your nick first.
    Connect {
        ticket: String,
        #[arg(long)]
        nick: Option<String>,
    },
    /// Print presence/system events (optionally only entries after --since).
    Log {
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Block until a new event arrives (event-based), then print it. Loops
    /// cleanly to follow presence without busy-polling.
    Wait {
        #[arg(long, default_value_t = 0)]
        since: u64,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Follow events like a notification stream: block on events and, for each
    /// one, optionally run a hook command and/or raise a desktop notification.
    /// Runs until interrupted.
    Watch {
        /// Start from this seq instead of "now" (replays history from here).
        #[arg(long)]
        since: Option<u64>,
        /// Shell command to run per event. Event fields arrive as GROUPCHAT_EVENT_*
        /// env vars and the full event JSON on stdin.
        #[arg(long)]
        exec: Option<String>,
        /// Raise a native desktop notification per event (macOS/Linux).
        #[arg(long)]
        notify: bool,
        #[arg(long, default_value_t = 60_000)]
        timeout_ms: u64,
    },
    /// List peers and their online status.
    Who,
    /// List your identities (each agent/session is its own private identity).
    Agents,
    /// Resume (or create) a named identity for this session, so future resumes
    /// of this session come back as it.
    Resume { name: String },
    /// Stop the running daemon.
    Stop,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Cli::parse();

    // Registry-level commands that operate across identities, not on one
    // resolved home — handle them before resolution so they never mint.
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
            return cli::run(&home, Request::Status).await;
        }
        _ => {}
    }

    // Every other command acts as one identity: resolve which (model B —
    // recall a mapped session, else mint a fresh per-session identity).
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
        Command::Status => cli::run(&home, Request::Status).await?,
        Command::Invite => cli::run_invite(&home).await?,
        Command::Join { ticket } => cli::run(&home, Request::Join { ticket }).await?,
        Command::Connect { ticket, nick } => {
            // For a cold machine, set the nick before the daemon spawns so it
            // advertises the right name. (If the daemon is already up, this
            // applies on its next restart.)
            if let Some(n) = nick {
                let mut profile = Profile::load(&home)?;
                profile.nick = n;
                profile.save(&home)?;
            }
            cli::run(&home, Request::Connect { ticket }).await?
        }
        Command::Log { since } => cli::run(&home, Request::Log { since }).await?,
        Command::Wait { since, timeout_ms } => {
            cli::run(&home, Request::Wait { since, timeout_ms }).await?
        }
        Command::Watch {
            since,
            exec,
            notify,
            timeout_ms,
        } => cli::watch(&home, since, exec, notify, timeout_ms).await?,
        Command::Who => cli::run(&home, Request::Who).await?,
        Command::Agents | Command::Resume { .. } => unreachable!("handled before resolution"),
        Command::Stop => cli::run(&home, Request::Stop).await?,
    }

    Ok(())
}
