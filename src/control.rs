//! Local control protocol between the daemon and its clients (CLI + MCP).
//!
//! Transport is a local IPC channel — a Unix-domain socket on unix, a named pipe
//! on Windows (see `control_name`) — carrying one newline-delimited JSON request,
//! answered by one newline-delimited JSON response.

use std::path::Path;

use anyhow::{Context, Result};
use interprocess::local_socket::{
    tokio::{prelude::*, Stream},
    Name,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// The OS name of the control channel for a home: a filesystem Unix-domain
/// socket on unix, a named pipe on Windows. Daemon and clients derive it from
/// the same home so they always agree on where to bind/connect.
pub fn control_name(home: &Path) -> Result<Name<'static>> {
    #[cfg(unix)]
    {
        use interprocess::local_socket::GenericFilePath;
        crate::config::socket_path(home)
            .to_fs_name::<GenericFilePath>()
            .context("build control socket name")
    }
    #[cfg(windows)]
    {
        use interprocess::local_socket::GenericNamespaced;
        // Named pipes don't live in the filesystem; name one per home so
        // several `$GROUPCHAT_HOME` nodes on one machine stay distinct.
        format!("groupchat-{}.sock", crate::config::home_hash(home))
            .to_ns_name::<GenericNamespaced>()
            .context("build control pipe name")
    }
}

/// A request from a client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Node + room status.
    Status,
    /// Our endpoint id.
    Id,
    /// Produce a base32 room ticket others can join with.
    Invite,
    /// Join a room from a ticket and announce a join request.
    Join { ticket: String },
    /// One-step onboarding: join a room from a ticket and go live.
    Connect { ticket: String },
    /// Fetch presence/system events with seq greater than `since`.
    Log { since: u64 },
    /// Block until an event with seq greater than `since` arrives (event-based
    /// delivery), or until `timeout_ms` elapses. Returns whatever is available.
    Wait { since: u64, timeout_ms: u64 },
    /// List known peers and their online status.
    Who,
    /// Shut the daemon down.
    Stop,
}

/// A response from the daemon to a client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Response {
    Ok { message: Option<String> },
    Status(StatusInfo),
    Text { text: String },
    Events { events: Vec<Event>, last: u64 },
    Who { peers: Vec<PresenceEntry> },
    Error { message: String },
}

/// A presence/system log entry kept in the daemon's ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub kind: EventKind,
    pub id: String,
    pub nick: String,
    pub text: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A peer joined (announced a join request).
    Join,
    /// A peer's presence changed (came online / went offline / left).
    Presence,
    /// A local system notice.
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub id: String,
    pub nick: String,
    pub online: bool,
    pub last_seen_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub id: String,
    pub nick: String,
    pub room: String,
    pub online_peers: usize,
}

/// Send one request to the daemon and read one response.
pub async fn request(home: &Path, req: &Request) -> Result<Response> {
    let name = control_name(home)?;
    let stream = Stream::connect(name).await.context("connect to daemon")?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut line = serde_json::to_string(req).context("encode request")?;
    line.push('\n');
    write_half
        .write_all(line.as_bytes())
        .await
        .context("write request")?;
    write_half.flush().await.ok();

    let mut reader = BufReader::new(read_half);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .await
        .context("read response")?;
    let resp: Response = serde_json::from_str(resp_line.trim()).context("decode response")?;
    Ok(resp)
}
