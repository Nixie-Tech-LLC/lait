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
mod mcp;
mod node;
mod proto;

use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::{
    config::{home_dir, load_or_create_identity, Profile},
    control::Request,
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
    Send { text: Vec<String> },
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
    /// Stop the running daemon.
    Stop,
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
    let home = home_dir()?;

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
        Command::Status => cli::run(&home, Request::Status).await?,
        Command::Invite => cli::run(&home, Request::Invite).await?,
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
        Command::Send { text } => {
            cli::run(
                &home,
                Request::Send {
                    text: text.join(" "),
                },
            )
            .await?
        }
        Command::Log { since } => cli::run(&home, Request::Log { since }).await?,
        Command::Wait { since, timeout_ms } => {
            cli::run(&home, Request::Wait { since, timeout_ms }).await?
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
        Command::Stop => cli::run(&home, Request::Stop).await?,
    }

    Ok(())
}
