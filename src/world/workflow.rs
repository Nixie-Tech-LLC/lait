//! IssuesWorld workflow definitions — deterministic assembly lines (plan 04).
//!
//! A workflow revision is `WorkflowRevision { revision_id, predecessor_ids,
//! body }` with `body = { project_id, name, states, transitions, tombstone }`
//! in product canonical JSON. Each transition stores a stable TransitionId,
//! its allowed source states, the destination state, and a **demand
//! template** — `require`/`all`/`any` over bounded Space/Project placeholders,
//! no scripts, no clocks, no arbitrary code. IssuesWorld resolves the template
//! against the Manifest-pinned project and Mechanics evaluates the resolved
//! demand; ordinary gates use signatures and receipts, never FROST.

use serde::{Deserialize, Serialize};

use super::contract::PRODUCT_WORLD;
use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};

/// The BLAKE3 derive-key context for a workflow revision id.
const WORKFLOW_REVISION_CONTEXT: &str = "lait.issues.workflow-revision.v1";

/// Bounds (plan 04): ProjectId ≤ 64 bytes, body ≤ 1 MiB, predecessors 0..8.
pub const MAX_PROJECT_ID: usize = 64;
pub const MAX_WORKFLOW_BODY: usize = 1024 * 1024;
pub const MAX_PREDECESSORS: usize = 8;

/// A workflow state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowState {
    pub state_id: String,
    pub name: String,
    /// `backlog` | `active` | `done` — the category the work verbs target.
    pub category: String,
    pub color: String,
}

/// A bounded resource placeholder: the Space, or the issue's project.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceTemplate {
    Space,
    Project,
}

/// The bounded demand template a transition stores. Mirrors
/// `Require`/`All`/`Any`; `require` names a capability and a
/// [`ResourceTemplate`]. The exact canonical JSON tags are frozen:
/// `{"op":"require","capability":…,"resource":{"kind":…}}`,
/// `{"op":"all","children":[…]}`, `{"op":"any","children":[…]}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum DemandTemplate {
    Require {
        capability: String,
        resource: ResourceTemplate,
    },
    All {
        children: Vec<DemandTemplate>,
    },
    Any {
        children: Vec<DemandTemplate>,
    },
}

impl DemandTemplate {
    /// Resolve against the Space and a concrete project id into a canonical
    /// Mechanics demand.
    pub fn resolve(&self, project_id: &str) -> AuthorizationDemand {
        match self {
            DemandTemplate::Require {
                capability,
                resource,
            } => {
                let res = match resource {
                    ResourceTemplate::Space => PolicyResource::space(PRODUCT_WORLD),
                    ResourceTemplate::Project => PolicyResource::project(PRODUCT_WORLD, project_id),
                };
                AuthorizationDemand::require(PolicyCapability::new(PRODUCT_WORLD, capability), res)
            }
            DemandTemplate::All { children } => {
                AuthorizationDemand::All(children.iter().map(|c| c.resolve(project_id)).collect())
            }
            DemandTemplate::Any { children } => {
                AuthorizationDemand::Any(children.iter().map(|c| c.resolve(project_id)).collect())
            }
        }
    }

    /// Structural validation: capability grammar, non-empty composites,
    /// bounded depth.
    pub fn validate(&self, depth: usize) -> bool {
        if depth > 8 {
            return false;
        }
        match self {
            DemandTemplate::Require { capability, .. } => {
                !capability.is_empty()
                    && capability.len() <= 64
                    && capability.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)
                    })
            }
            DemandTemplate::All { children } | DemandTemplate::Any { children } => {
                !children.is_empty()
                    && children.len() <= 32
                    && children.iter().all(|c| c.validate(depth + 1))
            }
        }
    }
}

/// A workflow transition: id, allowed sources (the complete product
/// prerequisite in this format), destination, and the demand template its
/// authorization receipt binds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTransition {
    pub transition_id: String,
    pub source_state_ids: Vec<String>,
    pub destination_state_id: String,
    pub demand_template: DemandTemplate,
}

/// The complete canonical workflow body (excludes its revision id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkflowBody {
    pub project_id: String,
    pub name: String,
    pub states: Vec<WorkflowState>,
    pub transitions: Vec<WorkflowTransition>,
    pub tombstone: bool,
}

impl WorkflowBody {
    /// The product canonical JSON bytes (sorted keys via `serde_json::Value`,
    /// arrays already canonically sorted by the builder/validator).
    pub fn canonical_json(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("workflow body to value");
        serde_json::to_string(&value)
            .expect("workflow body canonical json")
            .into_bytes()
    }

    /// Structural validation: sorted unique states/transitions/source ids,
    /// every referenced state exists, valid transition-id grammar, valid
    /// templates.
    pub fn validate(&self) -> Result<(), String> {
        if self.project_id.is_empty() || self.project_id.len() > MAX_PROJECT_ID {
            return Err("invalid project id".into());
        }
        if self.states.is_empty() {
            return Err("a workflow needs at least one state".into());
        }
        let mut state_ids: Vec<&str> = self.states.iter().map(|s| s.state_id.as_str()).collect();
        let sorted = state_ids.windows(2).all(|w| w[0] < w[1]);
        if !sorted {
            return Err("states must be sorted by unique state_id".into());
        }
        state_ids.sort();
        for s in &self.states {
            if !matches!(s.category.as_str(), "backlog" | "active" | "done") {
                return Err(format!("unknown state category `{}`", s.category));
            }
        }
        let tids: Vec<&str> = self
            .transitions
            .iter()
            .map(|t| t.transition_id.as_str())
            .collect();
        if !tids.windows(2).all(|w| w[0] < w[1]) {
            return Err("transitions must be sorted by unique transition_id".into());
        }
        for t in &self.transitions {
            if t.transition_id.is_empty()
                || t.transition_id.len() > 64
                || !t
                    .transition_id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
            {
                return Err(format!("invalid transition id `{}`", t.transition_id));
            }
            if t.source_state_ids.is_empty() || !t.source_state_ids.windows(2).all(|w| w[0] < w[1])
            {
                return Err("transition sources must be sorted, unique, non-empty".into());
            }
            for s in &t.source_state_ids {
                if state_ids.binary_search(&s.as_str()).is_err() {
                    return Err(format!("transition source `{s}` names no state"));
                }
            }
            if state_ids
                .binary_search(&t.destination_state_id.as_str())
                .is_err()
            {
                return Err(format!(
                    "transition destination `{}` names no state",
                    t.destination_state_id
                ));
            }
            if !t.demand_template.validate(0) {
                return Err(format!(
                    "transition `{}` carries an invalid demand template",
                    t.transition_id
                ));
            }
        }
        Ok(())
    }

    /// The transition permitting `from → to`, if the workflow defines one.
    pub fn transition_for(&self, from: &str, to: &str) -> Option<&WorkflowTransition> {
        self.transitions
            .iter()
            .find(|t| t.destination_state_id == to && t.source_state_ids.iter().any(|s| s == from))
    }
}

/// One immutable workflow revision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowRevision {
    /// Hex of the 32-byte revision id.
    pub revision_id: String,
    pub predecessor_ids: Vec<String>,
    pub body: WorkflowBody,
}

/// The revision-id preimage: `u16 version=1` big-endian, `u16` ProjectId
/// length + bytes, `u16` predecessor count, the sorted 32-byte predecessor
/// ids, `u32` body length, the canonical JSON body bytes.
pub fn revision_preimage(project_id: &str, predecessors: &[[u8; 32]], body_json: &[u8]) -> Vec<u8> {
    let mut sorted = predecessors.to_vec();
    sorted.sort();
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(project_id.len() as u16).to_be_bytes());
    out.extend_from_slice(project_id.as_bytes());
    out.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for p in &sorted {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&(body_json.len() as u32).to_be_bytes());
    out.extend_from_slice(body_json);
    out
}

/// Build a revision over a validated body.
pub fn build_revision(
    body: WorkflowBody,
    predecessors: Vec<[u8; 32]>,
) -> Result<WorkflowRevision, String> {
    body.validate()?;
    if predecessors.len() > MAX_PREDECESSORS {
        return Err("more than 8 predecessors".into());
    }
    let json = body.canonical_json();
    if json.len() > MAX_WORKFLOW_BODY {
        return Err("workflow body exceeds 1 MiB".into());
    }
    let id = blake3::derive_key(
        WORKFLOW_REVISION_CONTEXT,
        &revision_preimage(&body.project_id, &predecessors, &json),
    );
    Ok(WorkflowRevision {
        revision_id: data_encoding::HEXLOWER.encode(&id),
        predecessor_ids: predecessors
            .iter()
            .map(|p| data_encoding::HEXLOWER.encode(p))
            .collect(),
        body,
    })
}

/// The default workflow body for `project_id` (plan 04, exactly): states
/// `backlog`, `done`, `in_progress`, `in_review` (sorted), every directed edge
/// between distinct states with TransitionId `default.<from>.<to>`, and gate
/// `Any(space.contributor at Space, workflow.transition.<id> at Project,
/// space.admin at Space)` — free movement preserved while every edge is an
/// explicit replaceable gate.
pub fn default_workflow_body(project_id: &str) -> WorkflowBody {
    let mut states = vec![
        WorkflowState {
            state_id: "backlog".into(),
            name: "Backlog".into(),
            category: "backlog".into(),
            color: "gray".into(),
        },
        WorkflowState {
            state_id: "in_progress".into(),
            name: "In Progress".into(),
            category: "active".into(),
            color: "blue".into(),
        },
        WorkflowState {
            state_id: "in_review".into(),
            name: "In Review".into(),
            category: "active".into(),
            color: "yellow".into(),
        },
        WorkflowState {
            state_id: "done".into(),
            name: "Done".into(),
            category: "done".into(),
            color: "green".into(),
        },
    ];
    states.sort_by(|a, b| a.state_id.cmp(&b.state_id));
    let ids: Vec<String> = states.iter().map(|s| s.state_id.clone()).collect();
    let mut transitions = Vec::new();
    for from in &ids {
        for to in &ids {
            if from == to {
                continue;
            }
            let tid = format!("default.{from}.{to}");
            transitions.push(WorkflowTransition {
                transition_id: tid.clone(),
                source_state_ids: vec![from.clone()],
                destination_state_id: to.clone(),
                demand_template: DemandTemplate::Any {
                    children: vec![
                        DemandTemplate::Require {
                            capability: "space.contributor".into(),
                            resource: ResourceTemplate::Space,
                        },
                        DemandTemplate::Require {
                            capability: format!("workflow.transition.{tid}"),
                            resource: ResourceTemplate::Project,
                        },
                        DemandTemplate::Require {
                            capability: "space.admin".into(),
                            resource: ResourceTemplate::Space,
                        },
                    ],
                },
            });
        }
    }
    transitions.sort_by(|a, b| a.transition_id.cmp(&b.transition_id));
    WorkflowBody {
        project_id: project_id.into(),
        name: "Default".into(),
        states,
        transitions,
        tombstone: false,
    }
}

/// The default workflow revision for a project.
pub fn default_workflow_revision(project_id: &str) -> WorkflowRevision {
    build_revision(default_workflow_body(project_id), vec![])
        .expect("the default workflow body is valid")
}

/// The evidence a workflow-transition transaction core carries; the
/// authorization receipt binds it through the demand/effect/core digests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkflowTransitionEvidence {
    pub transition_id: String,
    pub workflow_revision_id: String,
    pub source_state: String,
    pub destination_state: String,
    /// Hex of the resolved demand's canonical digest.
    pub resolved_demand_digest: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_workflow_is_valid_and_deterministic() {
        let a = default_workflow_revision("prj_x");
        let b = default_workflow_revision("prj_x");
        assert_eq!(a.revision_id, b.revision_id, "deterministic revision id");
        assert_eq!(a.body.states.len(), 4);
        assert_eq!(a.body.transitions.len(), 12, "every directed edge");
        // A different project yields a different revision id (the preimage
        // frames the project id).
        let c = default_workflow_revision("prj_y");
        assert_ne!(a.revision_id, c.revision_id);
    }

    #[test]
    fn transitions_resolve_to_bounded_canonical_demands() {
        let wf = default_workflow_body("prj_x");
        let t = wf.transition_for("backlog", "in_progress").expect("edge");
        assert_eq!(t.transition_id, "default.backlog.in_progress");
        let demand = t.demand_template.resolve("prj_x");
        let bytes = demand.encode_canonical().expect("canonical");
        // Round-trips through the canonical decoder (plan 01 limits hold).
        mechanics::demand::AuthorizationDemand::decode_canonical(&bytes).expect("canonical demand");
    }

    #[test]
    fn invalid_bodies_reject() {
        let mut wf = default_workflow_body("prj_x");
        wf.transitions[0].destination_state_id = "nowhere".into();
        assert!(wf.validate().is_err(), "dangling destination");
        let mut wf = default_workflow_body("prj_x");
        wf.states.swap(0, 1);
        assert!(wf.validate().is_err(), "unsorted states");
        let mut wf = default_workflow_body("prj_x");
        wf.transitions[0].demand_template = DemandTemplate::All { children: vec![] };
        assert!(wf.validate().is_err(), "empty composite template");
    }

    #[test]
    fn frozen_canonical_json_tags() {
        let t = DemandTemplate::Require {
            capability: "issue.edit".into(),
            resource: ResourceTemplate::Project,
        };
        assert_eq!(
            serde_json::to_string(&serde_json::to_value(&t).unwrap()).unwrap(),
            r#"{"capability":"issue.edit","op":"require","resource":{"kind":"project"}}"#
        );
        // Unknown fields/tags reject.
        assert!(serde_json::from_str::<DemandTemplate>(
            r#"{"op":"require","capability":"x","resource":{"kind":"space"},"extra":1}"#
        )
        .is_err());
        assert!(serde_json::from_str::<DemandTemplate>(r#"{"op":"script","code":"x"}"#).is_err());
    }
}
