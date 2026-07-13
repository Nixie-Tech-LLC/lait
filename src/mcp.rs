//! MCP server (stdio) exposing the lait tracker as agent tools (A§12).
//!
//! Each tool is a thin wrapper over the **same** Layer-B `Request`/`Response`
//! the CLI uses (UI.md §1), so an agent drives the local daemon natively and
//! gets back the **same versioned DTO** the CLI `--json` emits (S§7.3). The tool
//! set is checked against the tracker command surface by `tests/mcp_parity.rs`
//! so the agent and human surfaces never drift.

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
    control::{BoardPos, Filter, Request, Response},
};

/// The tracker command tags (`Request` serde `cmd` values) an agent must be able
/// to drive. `tests/mcp_parity.rs` asserts every one has a tool below, so adding
/// a `Request` without an MCP tool fails the build gate (S§1/§7.3 parity).
pub const REQUIRED_TRACKER_COMMANDS: &[&str] = &[
    "issue_new",
    "issue_edit",
    "issue_move",
    "assign",
    "label",
    "comment",
    "issue_delete",
    "issue_view",
    "list",
    "board",
    "history",
    "project_new",
    "project_list",
    "label_new",
    "label_list",
    "activity",
    "member_add",
    "member_remove",
    "key_rotate",
    "members",
];

/// The set of MCP tool names this server exposes (kept beside the `#[tool]`
/// methods; the parity test cross-checks it covers `REQUIRED_TRACKER_COMMANDS`).
pub const MCP_TOOL_NAMES: &[&str] = &[
    // tracker
    "issue_new",
    "issue_edit",
    "issue_move",
    "assign",
    "label",
    "comment",
    "issue_delete",
    "issue_view",
    "list",
    "board",
    "history",
    "project_new",
    "project_list",
    "label_new",
    "label_list",
    "activity",
    "member_add",
    "member_remove",
    "key_rotate",
    "members",
    "member_requests",
    "member_approve",
    "member_alias",
    // transport / presence
    "status",
    "my_id",
    "invite_ticket",
    "join_room",
    "connect",
    "who",
];

// ---- tool argument schemas ----

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueNewArgs {
    /// Issue title.
    pub title: String,
    /// Project ref (key like `ENG` or a `prj_` id). Optional if there is one.
    #[serde(default)]
    pub project: Option<String>,
    /// Assignee refs (`@me`, or a 64-hex key).
    #[serde(default)]
    pub assignees: Vec<String>,
    /// Priority: none|low|medium|high|urgent.
    #[serde(default)]
    pub priority: Option<String>,
    /// Label refs (name or `lbl_` id).
    #[serde(default)]
    pub labels: Vec<String>,
    /// Optional body/description.
    #[serde(default)]
    pub body: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct RefArg {
    /// An issue ref: short `iss_` handle, or a `KEY-n` alias like `ENG-142`.
    pub reff: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueEditArgs {
    pub reff: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub priority: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct IssueMoveArgs {
    pub reff: String,
    /// New project (writes membership truth, S§5.5).
    #[serde(default)]
    pub project: Option<String>,
    /// Board position: top | bottom | before:<ref> | after:<ref>.
    #[serde(default)]
    pub position: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct AssignArgs {
    pub reff: String,
    /// User refs to add/remove (`@me` or key).
    pub who: Vec<String>,
    /// Remove instead of add.
    #[serde(default)]
    pub remove: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LabelArgs {
    pub reff: String,
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub remove: Vec<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct CommentArgs {
    pub reff: String,
    pub body: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ListArgs {
    #[serde(default)]
    pub project: Option<String>,
    #[serde(default)]
    pub mine: bool,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    /// Include done + tombstoned issues.
    #[serde(default)]
    pub all: bool,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct BoardArgs {
    /// Project ref (key or `prj_` id).
    pub project: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ProjectNewArgs {
    pub name: String,
    /// Short key (the `ENG` in `ENG-142`).
    pub key: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct LabelNewArgs {
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ActivityArgs {
    /// Only transitions with seq greater than this (pass back the `last`).
    #[serde(default)]
    pub since: u64,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MemberAddArgs {
    /// A user ref: `@me`, a local alias, a key id-prefix, or a 64-hex ed25519 key.
    pub who: String,
    /// Grant the admin role.
    #[serde(default)]
    pub admin: bool,
    /// Optional local petname to attach to the resolved key (never synced).
    #[serde(default)]
    pub alias: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MemberRemoveArgs {
    pub who: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MemberApproveArgs {
    /// A pending requester: a key id-prefix or a full 64-hex key. The joiner's
    /// self-asserted nick is not accepted — it is unauthenticated.
    pub who: String,
    /// Optional local petname to attach to the approved key (never synced).
    #[serde(default)]
    pub alias: Option<String>,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct MemberAliasArgs {
    /// A user ref: a key id-prefix, a full key, or an existing alias.
    pub who: String,
    /// The petname to assign (empty string clears it).
    pub name: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct JoinArgs {
    /// A base32 workspace ticket from `invite_ticket`.
    pub ticket: String,
}

#[derive(Debug, Deserialize, schemars::JsonSchema)]
pub struct ConnectArgs {
    /// A base32 workspace ticket from a coworker's `invite_ticket`.
    pub ticket: String,
}

#[derive(Clone)]
pub struct LaitMcp {
    home: PathBuf,
    #[allow(dead_code)]
    tool_router: ToolRouter<LaitMcp>,
}

fn parse_position(s: &str) -> Option<BoardPos> {
    match s {
        "top" => Some(BoardPos::Top),
        "bottom" => Some(BoardPos::Bottom),
        other => {
            if let Some(r) = other.strip_prefix("before:") {
                Some(BoardPos::Before {
                    reff: r.to_string(),
                })
            } else {
                other.strip_prefix("after:").map(|r| BoardPos::After {
                    reff: r.to_string(),
                })
            }
        }
    }
}

#[tool_router]
impl LaitMcp {
    pub fn new(home: PathBuf) -> Self {
        Self {
            home,
            tool_router: Self::tool_router(),
        }
    }

    /// Drive the daemon and return its `Response` as JSON text (the same
    /// versioned DTO the CLI `--json` emits).
    async fn run(&self, req: Request) -> Result<CallToolResult, McpError> {
        match client(&self.home, req).await {
            Ok(resp) => {
                if let Response::Error { message, .. } = &resp {
                    return Err(McpError::internal_error(message.clone(), None));
                }
                let json = serde_json::to_string(&resp)
                    .unwrap_or_else(|_| "{\"kind\":\"ok\"}".to_string());
                Ok(CallToolResult::success(vec![Content::text(json)]))
            }
            Err(e) => Err(McpError::internal_error(format!("{e:#}"), None)),
        }
    }

    // ---- tracker tools ----

    #[tool(description = "Create an issue. Returns the resolved canonical handle.")]
    async fn issue_new(
        &self,
        Parameters(a): Parameters<IssueNewArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::IssueNew {
            title: a.title,
            project: a.project,
            assignees: a.assignees,
            priority: a.priority,
            labels: a.labels,
            body: a.body,
        })
        .await
    }

    #[tool(description = "Edit an issue's title/status/priority (one commit = one activity row).")]
    async fn issue_edit(
        &self,
        Parameters(a): Parameters<IssueEditArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::IssueEdit {
            reff: a.reff,
            title: a.title,
            status: a.status,
            priority: a.priority,
        })
        .await
    }

    #[tool(description = "Move an issue to another project and/or board position.")]
    async fn issue_move(
        &self,
        Parameters(a): Parameters<IssueMoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::IssueMove {
            reff: a.reff,
            project: a.project,
            pos: a.position.as_deref().and_then(parse_position),
        })
        .await
    }

    #[tool(description = "Add or remove issue assignees (present-key set).")]
    async fn assign(
        &self,
        Parameters(a): Parameters<AssignArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Assign {
            reff: a.reff,
            who: a.who,
            add: !a.remove,
        })
        .await
    }

    #[tool(description = "Add and/or remove labels on an issue.")]
    async fn label(
        &self,
        Parameters(a): Parameters<LabelArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Label {
            reff: a.reff,
            add: a.add,
            remove: a.remove,
        })
        .await
    }

    #[tool(description = "Append a comment to an issue (immutable body).")]
    async fn comment(
        &self,
        Parameters(a): Parameters<CommentArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Comment {
            reff: a.reff,
            body: a.body,
        })
        .await
    }

    #[tool(description = "Delete (tombstone) an issue. It stays in history for backfill.")]
    async fn issue_delete(
        &self,
        Parameters(a): Parameters<RefArg>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::IssueDelete { reff: a.reff }).await
    }

    #[tool(
        description = "Show a full issue (lazily loads the issue doc): body, comments, metadata."
    )]
    async fn issue_view(
        &self,
        Parameters(a): Parameters<RefArg>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::IssueView { reff: a.reff }).await
    }

    #[tool(description = "List issue rows from the catalog cache (no issue-doc loads).")]
    async fn list(&self, Parameters(a): Parameters<ListArgs>) -> Result<CallToolResult, McpError> {
        self.run(Request::List {
            project: a.project,
            filter: Filter {
                mine: a.mine,
                status: a.status,
                label: a.label,
                all: a.all,
            },
        })
        .await
    }

    #[tool(description = "Render a project's board (workflow columns x ordered rows).")]
    async fn board(
        &self,
        Parameters(a): Parameters<BoardArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Board { project: a.project }).await
    }

    #[tool(description = "An issue's derived activity/time-travel feed.")]
    async fn history(&self, Parameters(a): Parameters<RefArg>) -> Result<CallToolResult, McpError> {
        self.run(Request::History { reff: a.reff }).await
    }

    #[tool(description = "Create a project registry entry.")]
    async fn project_new(
        &self,
        Parameters(a): Parameters<ProjectNewArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::ProjectNew {
            name: a.name,
            key: a.key,
        })
        .await
    }

    #[tool(description = "List projects.")]
    async fn project_list(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::ProjectList).await
    }

    #[tool(description = "Create a label registry entry.")]
    async fn label_new(
        &self,
        Parameters(a): Parameters<LabelNewArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::LabelNew {
            name: a.name,
            color: a.color,
        })
        .await
    }

    #[tool(description = "List labels.")]
    async fn label_list(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::LabelList).await
    }

    #[tool(description = "Workspace-wide recent transitions (the pulled activity feed).")]
    async fn activity(
        &self,
        Parameters(a): Parameters<ActivityArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Activity { since: a.since }).await
    }

    // ---- membership / ACL (P3) ----

    #[tool(description = "Add a workspace member (admin-only); seals them the workspace key.")]
    async fn member_add(
        &self,
        Parameters(a): Parameters<MemberAddArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::MemberAdd {
            who: a.who,
            admin: a.admin,
            as_name: a.alias,
        })
        .await
    }

    #[tool(
        description = "Remove a workspace member (admin-only) and rotate the key (lazy revocation)."
    )]
    async fn member_remove(
        &self,
        Parameters(a): Parameters<MemberRemoveArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::MemberRemove { who: a.who }).await
    }

    #[tool(description = "Rotate the workspace key (admin-only).")]
    async fn key_rotate(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::KeyRotate).await
    }

    #[tool(description = "List workspace members and their roles (from the signed ACL).")]
    async fn members(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Members).await
    }

    #[tool(description = "List pending join requests (announced joiners not yet added).")]
    async fn member_requests(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::MemberRequests).await
    }

    #[tool(
        description = "Approve a pending join request by id-prefix / key (admin-only); seals them the workspace key. The joiner's nick is not a valid ref (unauthenticated) — pass `alias` to name them locally."
    )]
    async fn member_approve(
        &self,
        Parameters(a): Parameters<MemberApproveArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::MemberApprove {
            who: a.who,
            as_name: a.alias,
        })
        .await
    }

    #[tool(
        description = "Set (or clear, with an empty name) a local petname for a key. Local to this device, never synced or part of the signed ACL."
    )]
    async fn member_alias(
        &self,
        Parameters(a): Parameters<MemberAliasArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::MemberAlias {
            who: a.who,
            name: a.name,
        })
        .await
    }

    // ---- transport / presence ----

    #[tool(
        description = "Show node + workspace status: id, nick, workspace, issue/project counts."
    )]
    async fn status(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Status).await
    }

    #[tool(description = "Get this node's endpoint id — the handle a coworker uses to reach us.")]
    async fn my_id(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Id).await
    }

    #[tool(
        description = "Produce a base32 workspace ticket to share so a coworker can join. The ticket carries a signed, single-use pass so they are auto-admitted on join (no separate approve step)."
    )]
    async fn invite_ticket(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: None,
        })
        .await
    }

    #[tool(description = "Join a workspace from a ticket and broadcast a request to be added.")]
    async fn join_room(
        &self,
        Parameters(a): Parameters<JoinArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Join { ticket: a.ticket }).await
    }

    #[tool(
        description = "One-step onboarding: connect to a workspace from a ticket (joins + live)."
    )]
    async fn connect(
        &self,
        Parameters(a): Parameters<ConnectArgs>,
    ) -> Result<CallToolResult, McpError> {
        self.run(Request::Connect { ticket: a.ticket }).await
    }

    #[tool(description = "List known peers and whether they are online.")]
    async fn who(&self) -> Result<CallToolResult, McpError> {
        self.run(Request::Who).await
    }
}

#[tool_handler]
impl ServerHandler for LaitMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::from_build_env())
            .with_protocol_version(ProtocolVersion::V_2024_11_05)
            .with_instructions(
                "A local-first, peer-to-peer issue tracker. File and drive issues natively: \
                 create with issue_new, edit with issue_edit, move/assign/label/comment, read \
                 with list/board/issue_view, and follow work with activity. Refs are a short \
                 iss_ handle or a KEY-n alias (ENG-142); @me is you. Onboarding across nodes is \
                 one step: the host calls invite_ticket and shares it; the other side calls \
                 connect. Every tool returns the same versioned JSON DTO the CLI --json emits."
                    .to_string(),
            )
    }
}

/// Run the MCP server over stdio until the client disconnects.
pub async fn run_mcp(home: &Path) -> Result<()> {
    let service = LaitMcp::new(home.to_path_buf()).serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
