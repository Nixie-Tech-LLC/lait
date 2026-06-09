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

use crate::{config::Contact, proto::Tier};

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
    /// Broadcast a chat line to the room. `to` addresses specific recipients by
    /// nick or id (empty = whole room); `tier` sets urgency; `deadline_ms` is
    /// the ack window for needs_ack/interrupt; `notify_anyway` overrides the
    /// receiver's focus/mute.
    Send {
        text: String,
        #[serde(default)]
        to: Vec<String>,
        #[serde(default)]
        tier: Tier,
        #[serde(default)]
        deadline_ms: Option<u64>,
        #[serde(default)]
        notify_anyway: bool,
    },
    /// Acknowledge a received message by its local event `seq` — broadcasts an
    /// Acked receipt to its original sender.
    Ack { seq: u64 },
    /// Report delivery/read/ack status for outstanding messages we sent (or for
    /// one message by its local `seq`).
    Receipts { seq: Option<u64> },
    /// Set or clear the receiver focus: mute anything below `mute_below` unless
    /// it carries notify_anyway.
    Focus {
        #[serde(default)]
        mute_below: Option<Tier>,
        #[serde(default)]
        clear: bool,
    },
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
    Receipts { messages: Vec<MessageReceipts> },
    Error { message: String },
}

/// Delivery/read/ack status of one message we sent, reconciled against the
/// expected recipient roster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageReceipts {
    pub msg_id: u64,
    pub text: String,
    pub tier: Tier,
    /// Whether the ack deadline has lapsed with acks still outstanding.
    pub overdue: bool,
    pub recipients: Vec<RecipientReceipt>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientReceipt {
    pub id: String,
    pub nick: String,
    pub delivered: bool,
    pub seen: bool,
    pub acked: bool,
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
    /// Whether this event is addressed to us and warrants a response — a direct
    /// @mention or an inbound call — versus ambient room traffic worth only a
    /// glance. Lets an agent triage like a human reading notifications.
    /// Equivalent to `tier >= Direct` after the receiver's focus is applied.
    #[serde(default)]
    pub direct: bool,
    /// Effective urgency tier of this event after addressing + focus are applied.
    #[serde(default)]
    pub tier: Tier,
    /// For chat events, the original sender's message id — the handle used to
    /// `ack` it. The global identity is `(id, msg_id)`.
    #[serde(default)]
    pub msg_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    Chat,
    Join,
    Call,
    Resource,
    /// A peer's presence changed (came online / went offline / left).
    Presence,
    /// A receipt update for a message we sent (e.g. a peer acked it) or an
    /// overdue-ack alert.
    Receipt,
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
