//! Guards parity between the versioned DTO contract and the MCP surface.
//!
//! The MCP tools return the **same** versioned control `Response` DTO the
//! CLI `--json` emits, so agent and human surfaces never drift. These tests are
//! the "check" half of "generate/check, don't hand-maintain twice": they fail
//! the build gate if a replica `Request` is added without a corresponding MCP
//! tool, or if a `Response` DTO stops round-tripping (a silent contract break).

use lait::control::Response;
use lait::dto::{
    ActivityEvent, BoardColumn, BoardView, IssueView, Priority, ProjectDto, Row, WorkflowState,
    SCHEMA_VERSION,
};
use lait::ids::{DocId, ProjectId, SystemUlidSource, WorkspaceId};
use lait::mcp::{MCP_TOOL_NAMES, REQUIRED_TRACKER_COMMANDS};

/// Every replica command an agent must drive has exactly one MCP tool. Adding a
/// `Request` variant to the replica surface without wiring an MCP tool for it
/// fails here (the parity guard).
#[test]
fn every_replica_command_has_an_mcp_tool() {
    for cmd in REQUIRED_TRACKER_COMMANDS {
        assert!(
            MCP_TOOL_NAMES.contains(cmd),
            "replica command `{cmd}` has no MCP tool — the agent surface drifted \
             from the Layer-B command surface"
        );
    }
}

/// Onboarding/transport tools an agent needs but that live outside the replica
/// CRUD set (and so aren't covered by `REQUIRED_TRACKER_COMMANDS`). Pinned here so
/// removing, say, the `doctor` tool — the guided-join verifier's agent surface —
/// fails the build instead of silently dropping a channel.
#[test]
fn onboarding_and_transport_tools_stay_wired() {
    for tool in ["status", "doctor", "who", "my_id", "join_room"] {
        assert!(
            MCP_TOOL_NAMES.contains(&tool),
            "MCP tool `{tool}` is missing — an agent-facing channel regressed"
        );
    }
}

/// The MCP tool-name list has no duplicates (a copy-paste guard).
#[test]
fn mcp_tool_names_are_unique() {
    let mut seen = std::collections::HashSet::new();
    for name in MCP_TOOL_NAMES {
        assert!(seen.insert(*name), "duplicate MCP tool name: {name}");
    }
}

/// Every read `Response` DTO round-trips through JSON unchanged — the versioned
/// contract is stable and self-consistent (what `--json` and MCP both emit).
#[test]
fn response_dtos_round_trip() {
    let ulid = SystemUlidSource;
    let doc_id = DocId::mint(&ulid);
    let project = ProjectDto {
        id: ProjectId::mint(&ulid),
        name: "Engineering".into(),
        key: "ENG".into(),
        color: "blue".into(),
    };
    let row = Row {
        reff: "iss_3f9ab2c".into(),
        doc_id: doc_id.clone(),
        project_id: project.id.clone(),
        key_alias: Some("ENG-142".into()),
        title: "fix login race".into(),
        status: "in_progress".into(),
        priority: Priority::High,
        assignee_summary: "you +1".into(),
        assignees: vec![
            lait::ids::ActorId::from_incept_hash(&"a".repeat(64)),
            lait::ids::ActorId::from_incept_hash(&"b".repeat(64)),
        ],
        tombstone: false,
        provisional: false,
    };

    let samples = vec![
        Response::Ok {
            message: Some("done".into()),
        },
        Response::Ref {
            reff: "iss_3f9ab2c".into(),
        },
        Response::List {
            rows: vec![row.clone()],
        },
        Response::Board(Box::new(BoardView {
            schema_version: SCHEMA_VERSION,
            project: project.clone(),
            columns: vec![BoardColumn {
                state: WorkflowState {
                    id: "backlog".into(),
                    name: "Backlog".into(),
                    category: lait::dto::StatusCategory::Backlog,
                    color: "gray".into(),
                },
                rows: vec![row.clone()],
            }],
        })),
        Response::Issue(Box::new(IssueView {
            schema_version: SCHEMA_VERSION,
            reff: "iss_3f9ab2c".into(),
            doc_id: doc_id.clone(),
            workspace_id: WorkspaceId::mint(&ulid),
            project_id: project.id.clone(),
            project_key: Some("ENG".into()),
            key_alias: Some("ENG-142".into()),
            title: "fix login race".into(),
            description: "body".into(),
            status: "in_progress".into(),
            priority: Priority::High,
            assignees: vec![],
            labels: vec![],
            label_names: vec!["bug".into()],
            comments: vec![],
            created_by: lait::ids::ActorId::from_incept_hash(&"a".repeat(64)),
            created_at: 1000,
            provisional: false,
            corrupt_records: vec![],
        })),
        Response::Activity {
            events: vec![ActivityEvent {
                seq: 1,
                doc_id: Some(doc_id.clone()),
                reff: "iss_3f9ab2c".into(),
                kind: "edited".into(),
                changes: vec![],
                actor: None,
                actor_nick: "you".into(),
                text: String::new(),
                ts: 1000,
                collision: false,
            }],
            last: 1,
        },
        Response::not_found("no issue matches 'ENG-9x'"),
    ];

    for resp in samples {
        let json = serde_json::to_string(&resp).expect("serialize response");
        let back: Response = serde_json::from_str(&json).expect("deserialize response");
        let json2 = serde_json::to_string(&back).expect("re-serialize");
        assert_eq!(json, json2, "response DTO must round-trip: {json}");
        // The internal tag is `kind` (not `status`, which would collide with
        // IssueView.status) — assert it so a tag rename can't slip through.
        assert!(
            json.contains("\"kind\""),
            "response must be tagged by kind: {json}"
        );
    }
}

/// The `Issue` response carries its own `status` field alongside the `kind` tag
/// without a serde collision (the bug that motivated the `kind` tag).
#[test]
fn issue_response_status_field_survives_the_kind_tag() {
    let ulid = SystemUlidSource;
    let resp = Response::Issue(Box::new(IssueView {
        schema_version: SCHEMA_VERSION,
        reff: "iss_x".into(),
        doc_id: DocId::mint(&ulid),
        workspace_id: WorkspaceId::mint(&ulid),
        project_id: ProjectId::mint(&ulid),
        project_key: None,
        key_alias: None,
        title: "t".into(),
        description: String::new(),
        status: "done".into(),
        priority: Priority::None,
        assignees: vec![],
        labels: vec![],
        label_names: vec![],
        comments: vec![],
        created_by: lait::ids::ActorId::from_incept_hash(&"a".repeat(64)),
        created_at: 0,
        provisional: false,
        corrupt_records: vec![],
    }));
    let json = serde_json::to_string(&resp).unwrap();
    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["kind"], "issue");
    assert_eq!(
        v["status"], "done",
        "IssueView.status must survive next to the kind tag"
    );
}
