//! MCP server (stdio) exposing the groupchat actions as agent tools.
//!
//! Each tool is a thin wrapper over the same control protocol the CLI uses, so
//! an agent gets native tools that drive the local daemon (auto-spawned on first
//! use). This is the transport/presence skeleton; the issue-tracker tools
//! (file/update/watch/close an issue) are layered on as the model lands.

use std::path::{Path, PathBuf};

use anyhow::Result;
use rmcp::{
    handler::server::{router::tool::ToolRouter, wrapper::Parameters},
    model::{
        CallToolResult, Content, Implementation, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
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
pub struct PollArgs {
    /// Only return events with sequence number greater than this. Pass 0 to
    /// get the whole log, then pass back the `last` value you received.
    #[serde(default)]
    pub since: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct WaitArgs {
    /// Block until an event with sequence greater than this arrives. Pass back
    /// the `last` cursor from the previous call to keep following events.
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

    #[tool(description = "Show this node's status: our id, nickname, room, and online peer count.")]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Status).await
    }

    #[tool(description = "Get this node's endpoint id — the handle a coworker uses to reach us.")]
    async fn my_id(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Id).await
    }

    #[tool(
        description = "Produce a base32 room ticket. Send it to a coworker so they can join with join_room or connect."
    )]
    async fn invite_ticket(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Invite).await
    }

    #[tool(description = "Join a room from a ticket and broadcast a request to be added.")]
    async fn join_room(
        &self,
        Parameters(a): Parameters<JoinArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Join { ticket: a.ticket }).await
    }

    #[tool(
        description = "One-step onboarding: connect to a coworker's room from their ticket (joins and goes live). Use this instead of join_room when you have a ticket."
    )]
    async fn connect(
        &self,
        Parameters(a): Parameters<ConnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Connect { ticket: a.ticket }).await
    }

    #[tool(
        description = "Poll for new presence/system events. Returns events plus a `last` sequence cursor to pass next time."
    )]
    async fn poll(&self, Parameters(a): Parameters<PollArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Log { since: a.since }).await
    }

    #[tool(
        description = "Event-based read: BLOCK until a new event (seq > since) arrives, then return it immediately — or return empty after timeout_ms (default 30s). `kind` is join|presence|system. Loop on this passing back `last` to follow events without busy-polling."
    )]
    async fn wait(&self, Parameters(a): Parameters<WaitArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::Wait {
            since: a.since,
            timeout_ms: a.timeout_ms,
        })
        .await
    }

    #[tool(description = "List known peers and whether they are online.")]
    async fn who(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Who).await
    }
}

#[tool_handler]
impl ServerHandler for GroupchatMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "A peer-to-peer node built on iroh. Onboarding is one step: the host calls \
                 invite_ticket and shares the ticket; the other side calls connect (joins and \
                 goes live). Then follow events with wait (it BLOCKS until something happens, \
                 passing back the `last` cursor) — `kind` is join|presence|system. Use who for a \
                 presence snapshot. Presence is kept accurate automatically."
                    .to_string(),
            )
    }
}

/// Run the MCP server over stdio until the client disconnects.
pub async fn run_mcp(home: &Path) -> Result<()> {
    let service = GroupchatMcp::new(home.to_path_buf()).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
