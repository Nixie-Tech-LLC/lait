//! MCP server (stdio) exposing the groupchat actions as agent tools.
//!
//! Each tool is a thin wrapper over the same control protocol the CLI uses, so
//! an agent gets native `chat_send` / `chat_poll` / `call` / `share_resource`
//! tools that drive the local daemon (auto-spawned on first use).

use std::path::PathBuf;

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo},
    schemars, tool, tool_handler, tool_router,
    transport::stdio,
    ErrorData as McpError, ServerHandler, ServiceExt,
};
use serde::Deserialize;

use crate::{
    cli::client,
    control::{Request, Response},
    proto::Tier,
};

/// Map an agent-supplied tier name to a `Tier` (defaults to ambient).
fn parse_tier(s: Option<&str>) -> Result<Tier, McpError> {
    Ok(match s.map(|s| s.trim().to_lowercase()).as_deref() {
        None | Some("") | Some("ambient") => Tier::Ambient,
        Some("direct") => Tier::Direct,
        Some("needs_ack") | Some("needs-ack") | Some("needsack") => Tier::NeedsAck,
        Some("interrupt") => Tier::Interrupt,
        Some(other) => {
            return Err(McpError::invalid_params(
                format!("unknown tier '{other}' (use ambient|direct|needs_ack|interrupt)"),
                None,
            ))
        }
    })
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// The chat message to broadcast to the room.
    pub text: String,
    /// Address specific recipients by nick or id (empty = whole room). Addressed
    /// recipients always get delivery/read/ack receipts.
    #[serde(default)]
    pub to: Vec<String>,
    /// Urgency tier: "ambient" (default, room chatter), "direct" (worth a reply),
    /// "needs_ack" (require an explicit ack within the deadline — you'll be
    /// alerted if it isn't acked), or "interrupt" ("notify anyway": overrides the
    /// receiver's focus and re-broadcasts until acked).
    #[serde(default)]
    pub tier: Option<String>,
    /// Ack window in milliseconds for needs_ack/interrupt (defaults to 60000).
    #[serde(default)]
    pub deadline_ms: Option<u64>,
    /// Override the receiver's focus/mute (the iMessage "Notify Anyway" action).
    #[serde(default)]
    pub notify_anyway: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AckArgs {
    /// The `seq` of the event you're acknowledging (from chat_wait/chat_poll).
    pub seq: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ReceiptsArgs {
    /// Optionally scope to one message you sent, by its `seq`.
    #[serde(default)]
    pub seq: Option<u64>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct FocusArgs {
    /// Mute anything below this tier (ambient|direct|needs_ack|interrupt) unless
    /// it's sent with notify_anyway. Omit with clear=true to mute nothing.
    #[serde(default)]
    pub mute_below: Option<String>,
    /// Clear focus — mute nothing.
    #[serde(default)]
    pub clear: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct PollArgs {
    /// Only return events with sequence number greater than this. Pass 0 to
    /// get the whole log, then pass back the `last` value you received.
    #[serde(default)]
    pub since: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitArgs {
    /// Block until an event with sequence greater than this arrives. Pass back
    /// the `last` cursor from the previous call to follow the conversation.
    #[serde(default)]
    pub since: u64,
    /// Max milliseconds to block before returning (possibly with no new events).
    /// Defaults to 30000. Capped at 300000.
    #[serde(default = "default_wait_timeout")]
    pub timeout_ms: u64,
}

fn default_wait_timeout() -> u64 {
    30_000
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JoinArgs {
    /// A base32 room ticket from `invite_ticket`.
    pub ticket: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectArgs {
    /// A base32 room ticket from a coworker's `invite_ticket`.
    pub ticket: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ContactsAddArgs {
    /// The endpoint id (public key) of the contact to approve.
    pub id: String,
    /// Optional nickname for the contact.
    #[serde(default)]
    pub nick: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CallArgs {
    /// The contact to call, by nickname or endpoint id. Must be a contact and online.
    pub who: String,
    /// Optional message to deliver with the call.
    #[serde(default)]
    pub message: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ShareArgs {
    /// Path to the file to share.
    pub path: String,
    /// Optional human label for the resource (defaults to the file name).
    #[serde(default)]
    pub label: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct GetArgs {
    /// The resource to fetch, by label or by raw blob ticket.
    pub resource: String,
    /// Destination path to write the downloaded file to.
    pub out: String,
}

#[derive(Clone)]
pub struct GroupchatMcp {
    home: PathBuf,
    // Read by the `#[tool_handler]`-generated code, not by hand.
    #[allow(dead_code)]
    tool_router: ToolRouter<GroupchatMcp>,
}

#[tool_router]
impl GroupchatMcp {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            tool_router: Self::tool_router(),
        }
    }

    /// Drive the daemon and return its response as JSON text.
    async fn run(&self, req: Request) -> Result<CallToolResult, McpError> {
        match client(&self.home, req).await {
            Ok(resp) => {
                if let Response::Error { message } = &resp {
                    return Err(McpError::internal_error(message.clone(), None));
                }
                let json = serde_json::to_string(&resp)
                    .unwrap_or_else(|_| "{\"status\":\"ok\"}".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Err(McpError::internal_error(format!("{e:#}"), None)),
        }
    }

    #[tool(description = "Show this node's status: our id, nickname, room, online peer count, contacts, resources.")]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Status).await
    }

    #[tool(description = "Get this node's endpoint id — the handle a coworker adds as a contact.")]
    async fn my_id(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Id).await
    }

    #[tool(description = "Produce a base32 room ticket. Send it to a coworker so they can join your chat with join_room.")]
    async fn invite_ticket(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Invite).await
    }

    #[tool(description = "Join a room from a ticket and broadcast a request to be added to the chat.")]
    async fn join_room(&self, Parameters(a): Parameters<JoinArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Join { ticket: a.ticket }).await
    }

    #[tool(description = "One-step onboarding: connect to a coworker's room from their ticket. Joins the room, auto-adds them as a contact, and goes live — no separate approval needed. Use this instead of join_room when you have a ticket.")]
    async fn connect(&self, Parameters(a): Parameters<ConnectArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Connect { ticket: a.ticket }).await
    }

    #[tool(description = "Send a chat message to the room. Set `tier` to control urgency: ambient (default) is glanceable chatter; direct warrants a reply; needs_ack REQUIRES the recipient to ack within the deadline (you're alerted if they don't); interrupt is \"notify anyway\" — it overrides their focus and re-broadcasts until acked. Use `to` to address specific recipients (by nick/id); addressed messages always get delivery/read/ack receipts. Returns the message id.")]
    async fn chat_send(&self, Parameters(a): Parameters<SendArgs>) -> Result<CallToolResult, McpError> {
        let tier = parse_tier(a.tier.as_deref())?;
        self.run(Request::Send {
            text: a.text,
            to: a.to,
            tier,
            deadline_ms: a.deadline_ms,
            notify_anyway: a.notify_anyway,
        })
        .await
    }

    #[tool(description = "Acknowledge a message addressed to you, by its event `seq`. This sends a read+ack receipt back to the sender so they know you saw it and are acting on it. ALWAYS ack a needs_ack or interrupt event (tier in the event) — otherwise the sender is alerted that you ignored it and an interrupt will keep re-firing.")]
    async fn chat_ack(&self, Parameters(a): Parameters<AckArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Ack { seq: a.seq }).await
    }

    #[tool(description = "Show delivery/read/ack status for messages you sent that expect receipts (needs_ack/interrupt or addressed). Tells you, per recipient, whether your message was delivered, seen, and acked — and whether the ack deadline is overdue.")]
    async fn receipts(&self, Parameters(a): Parameters<ReceiptsArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Receipts { seq: a.seq }).await
    }

    #[tool(description = "Set or clear your receiver focus. With mute_below set, messages below that tier are silenced (logged but not flagged for you) unless the sender used notify_anyway. Use clear=true to mute nothing.")]
    async fn focus(&self, Parameters(a): Parameters<FocusArgs>) -> Result<CallToolResult, McpError> {
        let mute_below = match a.mute_below.as_deref() {
            Some(_) => Some(parse_tier(a.mute_below.as_deref())?),
            None => None,
        };
        self.run(Request::Focus {
            mute_below,
            clear: a.clear,
        })
        .await
    }

    #[tool(description = "Poll the chat log for new messages and events (join requests, calls, shared resources). Returns events plus a `last` sequence cursor to pass next time.")]
    async fn chat_poll(&self, Parameters(a): Parameters<PollArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Log { since: a.since }).await
    }

    #[tool(description = "Event-based read (your notification stream): BLOCK until a new event (seq > since) arrives, then return it immediately — or return empty after timeout_ms (default 30s). Each event has a `direct` flag: true = addressed to you (@mention or incoming call), open and reply; false = ambient chat / presence change, just note it. `kind` is chat|join|call|resource|presence|system. Loop on this passing back `last` to follow the room in real time without busy-polling.")]
    async fn chat_wait(&self, Parameters(a): Parameters<WaitArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Wait { since: a.since, timeout_ms: a.timeout_ms }).await
    }

    #[tool(description = "List known peers and whether they are online and a saved contact.")]
    async fn who(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Who).await
    }

    #[tool(description = "List saved contacts.")]
    async fn contacts_list(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::ContactsList).await
    }

    #[tool(description = "Approve/add a contact by endpoint id. Required before you can call them.")]
    async fn contacts_add(&self, Parameters(a): Parameters<ContactsAddArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::ContactsAdd { id: a.id, nick: a.nick }).await
    }

    #[tool(description = "Place a 1:1 call to a contact (by nick or id). They must be in your contacts and online.")]
    async fn call(&self, Parameters(a): Parameters<CallArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Call { who: a.who, text: a.message }).await
    }

    #[tool(description = "Share a local file as a resource and announce it to the room. Returns a blob ticket.")]
    async fn share_resource(&self, Parameters(a): Parameters<ShareArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Share { path: a.path, label: a.label }).await
    }

    #[tool(description = "Download a shared resource (by label or ticket) to a destination path.")]
    async fn get_resource(&self, Parameters(a): Parameters<GetArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Get { resource: a.resource, out: a.out }).await
    }

    #[tool(description = "List resources that have been shared in the room.")]
    async fn resources(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Resources).await
    }
}

#[tool_handler]
impl ServerHandler for GroupchatMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "Agent-to-agent group chat over iroh — treat it like your messaging app. \
                 Onboarding is one step: the host calls invite_ticket and shares the ticket; \
                 the other side calls connect (joins, auto-adds the host, goes live — no manual \
                 approval). \
                 \
                 Then run the notification loop: call chat_wait (it BLOCKS until something \
                 happens, passing back the `last` cursor) and triage each event like a human \
                 glancing at a notification. \
                 \
                 Each event has a `tier`: ambient (glanceable room chatter / presence changes — \
                 note and move on), direct (someone @mentioned you or addressed you — open and \
                 reply), needs_ack (they REQUIRE you to acknowledge — reply and call chat_ack with \
                 the event's `seq`, or you'll be marked as having ignored it), and interrupt \
                 ('notify anyway' — highest urgency, handle it now and chat_ack it; it keeps \
                 re-firing until you do). The `direct` flag is true for tier >= direct. \
                 \
                 When YOU need a guarantee the other side acted, send at tier needs_ack (or \
                 interrupt for must-not-miss) and then use `receipts` to see who delivered/saw/ \
                 acked it — you'll get an alert event if it goes unacked past the deadline. Use \
                 `focus` to mute low-tier noise while you work; senders can still break through \
                 with notify_anyway. \
                 \
                 Then loop back to chat_wait. Presence is kept accurate for you automatically — \
                 no need to manage contacts or the room by hand. call for a 1:1; share_resource / \
                 get_resource to exchange files; who for a presence snapshot."
                    .to_string(),
            )
    }
}

/// Run the MCP server over stdio until the client disconnects.
pub async fn run_mcp(home: &PathBuf) -> Result<()> {
    let service = GroupchatMcp::new(home.clone()).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
