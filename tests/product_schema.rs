//! M6 — the committed product policy JSON Schema and canonical examples.
//!
//! `schema/product-policy.schema.json` is generated from the Rust policy
//! contract (role/workflow definitions, demand templates, assignment rows —
//! the plan-04 policy surface); this gate regenerates it and fails on drift
//! (run with `LAIT_BLESS_SCHEMA=1` to intentionally re-commit after a contract
//! change). The canonical examples decode through the Rust contract and are
//! replayed by a NON-Rust validator in CI (`ci/validate-dto-schema.py`).

use lait::world::roles::{RoleBody, ScopeKind};
use lait::world::workflow::{
    DemandTemplate, ResourceTemplate, WorkflowBody, WorkflowState, WorkflowTransition,
};

fn schema_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join("product-policy.schema.json")
}

fn role_example() -> RoleBody {
    RoleBody {
        role_id: "role_01JZX0000000000000000000".into(),
        scope_kind: ScopeKind::Space,
        name: "triage".into(),
        description: "labels and assigns incoming issues".into(),
        capabilities: vec!["issue.assign".into(), "issue.label".into()],
        tombstone: false,
    }
}

fn workflow_example() -> WorkflowBody {
    WorkflowBody {
        project_id: "prj_01JZX0000000000000000000".into(),
        name: "default".into(),
        states: vec![
            WorkflowState {
                state_id: "backlog".into(),
                name: "Backlog".into(),
                category: "backlog".into(),
                color: "gray".into(),
            },
            WorkflowState {
                state_id: "done".into(),
                name: "Done".into(),
                category: "done".into(),
                color: "green".into(),
            },
        ],
        transitions: vec![WorkflowTransition {
            transition_id: "ship".into(),
            source_state_ids: vec!["backlog".into()],
            destination_state_id: "done".into(),
            demand_template: DemandTemplate::Any {
                children: vec![
                    DemandTemplate::Require {
                        capability: "space.contributor".into(),
                        resource: ResourceTemplate::Space,
                    },
                    DemandTemplate::Require {
                        capability: "space.admin".into(),
                        resource: ResourceTemplate::Space,
                    },
                ],
            },
        }],
        tombstone: false,
    }
}

fn examples() -> serde_json::Value {
    serde_json::json!({
        "positive": [
            { "def": "RoleBody", "value": role_example() },
            { "def": "WorkflowBody", "value": workflow_example() },
            { "def": "AssignmentDto", "value": lait::dto::AssignmentDto {
                grant_id: "ab".repeat(32),
                actor: format!("act_{}", "a".repeat(64)),
                world: "com.lait.issues".into(),
                capability: "issue.assign".into(),
                resource: vec![],
            } },
        ],
        "negative": [
            {
                "def": "RoleBody",
                "reason": "missing required fields",
                "schemaExpressible": true,
                "value": { "role_id": "role_x" },
            },
            {
                "def": "WorkflowBody",
                "reason": "a transition's demand template kind is unknown",
                "schemaExpressible": true,
                "value": {
                    "project_id": "prj_01JZX0000000000000000000",
                    "name": "bad",
                    "states": [],
                    "transitions": [{
                        "transition_id": "x",
                        "source_state_ids": [],
                        "destination_state_id": "y",
                        "demand_template": { "op": "sometimes" },
                    }],
                    "tombstone": false,
                },
            },
        ],
    })
}

#[test]
fn the_committed_product_schema_matches_the_rust_contract() {
    let generated =
        serde_json::to_string_pretty(&lait::dto::product_policy_schema_bundle()).unwrap();
    let path = schema_path();
    if std::env::var("LAIT_BLESS_SCHEMA").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("schema/product-policy.schema.json is committed; LAIT_BLESS_SCHEMA=1 to create");
    let committed: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let generated: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert_eq!(
        committed, generated,
        "the committed product policy schema drifted from the Rust contract"
    );
}

#[test]
fn the_committed_product_examples_match_the_rust_corpus() {
    let generated = serde_json::to_string_pretty(&examples()).unwrap();
    let path = schema_path().with_file_name("product-policy.examples.json");
    if std::env::var("LAIT_BLESS_SCHEMA").is_ok() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("schema/product-policy.examples.json is committed; LAIT_BLESS_SCHEMA=1 to create");
    let committed: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let generated: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert_eq!(committed, generated);
}

#[test]
fn positive_examples_roundtrip_and_canonical_bytes_are_stable() {
    // Every positive example decodes through the Rust contract; the role and
    // workflow examples re-encode to their canonical policy bytes (the same
    // canonicalization the revision digests sign).
    let role = role_example();
    let json = serde_json::to_vec(&role).unwrap();
    let back: RoleBody = serde_json::from_slice(&json).unwrap();
    assert_eq!(back, role);
    let wf = workflow_example();
    let json = serde_json::to_vec(&wf).unwrap();
    let back: WorkflowBody = serde_json::from_slice(&json).unwrap();
    assert_eq!(back, wf);
}
