//! Local control protocol between the daemon and its clients (CLI + MCP).
//!
//! Transport is a Unix domain socket carrying one newline-delimited JSON
//! request, answered by one newline-delimited JSON response.

use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

use crate::config::Contact;

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
    /// One-step onboarding: join a room from a ticket, auto-add the host as a
    /// contact, and announce a join request (the host auto-approves).
    Connect { ticket: String },
    /// Broadcast a chat line to the room.
    Send { text: String },
    /// Fetch chat/system events with seq greater than `since`.
    Log { since: u64 },
    /// Block until an event with seq greater than `since` arrives (event-based
    /// delivery), or until `timeout_ms` elapses. Returns whatever is available.
    Wait { since: u64, timeout_ms: u64 },
    /// List known peers and their online/contact status.
    Who,
    /// List saved contacts.
    ContactsList,
    /// Approve/add a contact by endpoint id.
    ContactsAdd { id: String, nick: Option<String> },
    /// Remove a contact by endpoint id.
    ContactsRemove { id: String },
    /// Place a 1:1 call to a contact (by nick or id) that is online.
    Call { who: String, text: Option<String> },
    /// Share a file as a resource and announce it to the room.
    Share { path: String, label: Option<String> },
    /// Download a shared resource (by label or ticket) to `out`.
    Get { resource: String, out: String },
    /// List announced resources.
    Resources,
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
    Contacts { contacts: Vec<Contact> },
    Who { peers: Vec<PresenceEntry> },
    Resources { resources: Vec<ResourceEntry> },
    Error { message: String },
}

/// A chat/system log entry kept in the daemon's ring buffer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub seq: u64,
    pub kind: EventKind,
    pub id: String,
    pub nick: String,
    pub text: String,
    pub ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Chat,
    Join,
    Call,
    Resource,
    System,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PresenceEntry {
    pub id: String,
    pub nick: String,
    pub online: bool,
    pub is_contact: bool,
    pub last_seen_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceEntry {
    pub label: String,
    pub ticket: String,
    pub from: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusInfo {
    pub id: String,
    pub nick: String,
    pub room: String,
    pub online_peers: usize,
    pub contacts: usize,
    pub resources: usize,
}

/// Send one request to the daemon and read one response.
pub async fn request(socket: &Path, req: &Request) -> Result<Response> {
    let stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("connect to daemon at {}", socket.display()))?;
    let (read_half, mut write_half) = stream.into_split();
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
    let resp: Response =
        serde_json::from_str(resp_line.trim()).context("decode response")?;
    Ok(resp)
}
