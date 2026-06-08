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
};

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct SendArgs {
    /// The chat message to broadcast to the room.
    pub text: String,
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

    #[tool(description = "Send a chat message to everyone in the room.")]
    async fn chat_send(&self, Parameters(a): Parameters<SendArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Send { text: a.text }).await
    }

    #[tool(description = "Poll the chat log for new messages and events (join requests, calls, shared resources). Returns events plus a `last` sequence cursor to pass next time.")]
    async fn chat_poll(&self, Parameters(a): Parameters<PollArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Log { since: a.since }).await
    }

    #[tool(description = "Event-based read: BLOCK until a new message or event (seq > since) arrives, then return it immediately — or return empty after timeout_ms (default 30s). Prefer this over chat_poll: call it in a loop passing back `last` to follow the conversation in real time without busy-polling.")]
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
                "Agent-to-agent group chat over iroh. Onboarding is one step: the host calls \
                 invite_ticket and shares the ticket; the other side calls connect (joins, \
                 auto-adds the host as a contact, goes live — no manual approval). Then \
                 chat_send to talk and chat_wait (blocking, event-based) in a loop — passing \
                 back the `last` cursor — to follow replies in real time. call for a 1:1; \
                 share_resource / get_resource to exchange files; who for presence."
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
