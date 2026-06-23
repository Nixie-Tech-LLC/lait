//! groupchat: an agent-to-agent group chat over iroh.
//!
//! One binary, three roles:
//!   * `groupchat daemon` runs the node (endpoint, gossip room, blobs, calls).
//!   * `groupchat <cmd>` is a CLI client that drives the daemon over a socket.
//!   * `groupchat mcp` exposes the same actions as MCP tools for an agent.

mod call;
mod cli;
mod config;
mod control;
mod doctor;
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
    proto::Tier,
};

#[derive(Parser, Debug)]
#[command(name = "groupchat", version, about = "Agent-to-agent group chat over iroh")]
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
    /// Print our endpoint id (the handle others add as a contact).
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
    /// Join a room from a ticket and ask to be added.
    Join { ticket: String },
    /// One-step onboarding: connect to a room from a ticket (joins, auto-adds
    /// the host as a contact, goes live). Optionally set your nick first.
    Connect {
        ticket: String,
        #[arg(long)]
        nick: Option<String>,
    },
    /// Send a chat message to the room.
    Send {
        text: Vec<String>,
        /// Address specific recipients by nick or id (repeatable). Empty = whole
        /// room. Addressed recipients always get receipts.
        #[arg(long)]
        to: Vec<String>,
        /// Urgency: ambient | direct | needs_ack | interrupt. needs_ack and
        /// interrupt track delivery/read/ack and alert you if unacked.
        #[arg(long, value_enum, default_value_t = Tier::Ambient)]
        tier: Tier,
        /// Ack window in milliseconds for needs_ack/interrupt (defaults to 60s).
        #[arg(long)]
        deadline_ms: Option<u64>,
        /// Override the receiver's focus/mute (iMessage "Notify Anyway").
        #[arg(long)]
        notify_anyway: bool,
    },
    /// Acknowledge a received message by its log seq (sends a read/ack receipt
    /// back to the sender).
    Ack { seq: u64 },
    /// Show delivery/read/ack status for messages you sent that expect receipts.
    Receipts {
        /// Scope to a single message by its log seq.
        #[arg(long)]
        seq: Option<u64>,
    },
    /// Set or clear your receiver focus: mute anything below a tier unless it's
    /// sent with --notify-anyway.
    Focus {
        /// Mute anything below this tier (ambient | direct | needs_ack | interrupt).
        #[arg(long, value_enum)]
        mute_below: Option<Tier>,
        /// Clear focus (mute nothing).
        #[arg(long)]
        clear: bool,
    },
    /// Print chat/system log (optionally only entries after --since).
    Log {
        #[arg(long, default_value_t = 0)]
        since: u64,
    },
    /// Block until a new event arrives (event-based), then print it. Loops
    /// cleanly to follow a conversation without busy-polling.
    Wait {
        #[arg(long, default_value_t = 0)]
        since: u64,
        #[arg(long, default_value_t = 30_000)]
        timeout_ms: u64,
    },
    /// Follow the room like a notification stream: block on events and, for each
    /// one, optionally run a hook command and/or raise a desktop notification.
    /// Runs until interrupted.
    Watch {
        /// Start from this seq instead of "now" (replays history from here).
        #[arg(long)]
        since: Option<u64>,
        /// Only act on direct events (@mentions and incoming calls).
        #[arg(long)]
        direct_only: bool,
        /// Only act on events at or above this tier (ambient | direct | needs_ack | interrupt).
        #[arg(long, value_enum)]
        min_tier: Option<Tier>,
        /// Shell command to run per event. Event fields arrive as GROUPCHAT_EVENT_*
        /// env vars and the full event JSON on stdin.
        #[arg(long)]
        exec: Option<String>,
        /// Preemption hook: a command run ONLY for interrupt-tier ("notify
        /// anyway") events — the channel that reaches a heads-down agent.
        #[arg(long)]
        on_interrupt: Option<String>,
        /// Raise a native desktop notification per event (macOS/Linux).
        #[arg(long)]
        notify: bool,
        #[arg(long, default_value_t = 60_000)]
        timeout_ms: u64,
    },
    /// List peers and their online/contact status.
    Who,
    /// Manage contacts.
    Contacts {
        #[command(subcommand)]
        action: ContactsCmd,
    },
    /// Place a 1:1 call to an online contact (by nick or id).
    Call {
        who: String,
        #[arg(long)]
        message: Option<String>,
    },
    /// Share a file as a resource and announce it to the room.
    Share {
        path: String,
        #[arg(long)]
        label: Option<String>,
    },
    /// Download a shared resource by label or ticket.
    Get {
        resource: String,
        #[arg(long, default_value = "./")]
        out: String,
    },
    /// List announced resources.
    Resources,
    /// List your identities (each agent/session is its own private identity).
    Agents,
    /// Resume (or create) a named identity for this session, so future resumes
    /// of this session come back as it.
    Resume { name: String },
    /// Stop the running daemon.
    Stop,
    /// Converge to a single clean install: remove duplicate/old groupchat
    /// binaries, diagnose PATH, and stop stale daemons. Never touches identity.
    Doctor {
        /// Report what would change without removing anything.
        #[arg(long)]
        dry_run: bool,
        /// Don't prompt before removing (used by installers).
        #[arg(long, short = 'y')]
        yes: bool,
        /// Keep this binary instead of the currently-running one.
        #[arg(long)]
        keep: Option<std::path::PathBuf>,
        /// Don't stop running daemons.
        #[arg(long)]
        no_stop_daemon: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ContactsCmd {
    /// Approve/add a contact by endpoint id.
    Add { id: String, nick: Option<String> },
    /// List saved contacts.
    List,
    /// Remove a contact by endpoint id.
    Remove { id: String },
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
        Command::Doctor {
            dry_run,
            yes,
            keep,
            no_stop_daemon,
        } => {
            return doctor::run_doctor(*dry_run, *yes, keep.clone(), !*no_stop_daemon).await;
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
        Command::Send {
            text,
            to,
            tier,
            deadline_ms,
            notify_anyway,
        } => {
            cli::run(
                &home,
                Request::Send {
                    text: text.join(" "),
                    to,
                    tier,
                    deadline_ms,
                    notify_anyway,
                },
            )
            .await?
        }
        Command::Ack { seq } => cli::run(&home, Request::Ack { seq }).await?,
        Command::Receipts { seq } => cli::run(&home, Request::Receipts { seq }).await?,
        Command::Focus { mute_below, clear } => {
            cli::run(&home, Request::Focus { mute_below, clear }).await?
        }
        Command::Log { since } => cli::run(&home, Request::Log { since }).await?,
        Command::Wait { since, timeout_ms } => {
            cli::run(&home, Request::Wait { since, timeout_ms }).await?
        }
        Command::Watch {
            since,
            direct_only,
            min_tier,
            exec,
            on_interrupt,
            notify,
            timeout_ms,
        } => {
            cli::watch(
                &home,
                since,
                direct_only,
                min_tier,
                exec,
                on_interrupt,
                notify,
                timeout_ms,
            )
            .await?
        }
        Command::Who => cli::run(&home, Request::Who).await?,
        Command::Contacts { action } => {
            let req = match action {
                ContactsCmd::Add { id, nick } => Request::ContactsAdd { id, nick },
                ContactsCmd::List => Request::ContactsList,
                ContactsCmd::Remove { id } => Request::ContactsRemove { id },
            };
            cli::run(&home, req).await?
        }
        Command::Call { who, message } => {
            cli::run(&home, Request::Call { who, text: message }).await?
        }
        Command::Share { path, label } => cli::run(&home, Request::Share { path, label }).await?,
        Command::Get { resource, out } => cli::run(&home, Request::Get { resource, out }).await?,
        Command::Resources => cli::run(&home, Request::Resources).await?,
        Command::Agents | Command::Resume { .. } | Command::Doctor { .. } => {
            unreachable!("handled before resolution")
        }
        Command::Stop => cli::run(&home, Request::Stop).await?,
    }

    Ok(())
}
