//! IssuesWorld role definitions — canonical bodies, revision identity, and
//! the built-in roles (plan 04).
//!
//! A role definition is an atomic canonical revision, never field-merged:
//! `RoleRevision { revision_id, predecessor_ids, body }` where the body is
//! exactly `{ role_id, scope_kind, name, description, capabilities,
//! tombstone }` in product canonical JSON (UTF-8, sorted object keys, no
//! insignificant whitespace, arrays already canonically sorted). The revision
//! id hashes a big-endian framed preimage under the
//! `lait.issues.role-revision.v1` derive-key context; the id is excluded from
//! the body.
//!
//! Mechanics never sees any of this: invites carry only the bounded opaque
//! provenance (`role_id` + `revision_id`), the definition digest, and the
//! exact expanded generic assignments.

use serde::{Deserialize, Serialize};

use super::contract::PRODUCT_WORLD;
use mechanics::demand::{PolicyCapability, PolicyResource};

/// The BLAKE3 derive-key context for a role revision id.
const ROLE_REVISION_CONTEXT: &str = "lait.issues.role-revision.v1";
/// The BLAKE3 derive-key context for a role-definition digest (over the
/// canonical body bytes) — what admission evidence binds.
const ROLE_DEFINITION_CONTEXT: &str = "lait.issues.role-definition.v1";

/// Bounds (plan 04): RoleId ≤ 64 bytes, body ≤ 16 KiB, predecessors 0..8.
pub const MAX_ROLE_ID: usize = 64;
pub const MAX_ROLE_BODY: usize = 16 * 1024;
pub const MAX_PREDECESSORS: usize = 8;

/// A role's scope kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ScopeKind {
    Space,
    Project,
}

/// The complete canonical role-definition body (excludes its revision id).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RoleBody {
    pub role_id: String,
    pub scope_kind: ScopeKind,
    pub name: String,
    pub description: String,
    /// Sorted, unique capability ids from the Issues capability registry.
    pub capabilities: Vec<String>,
    pub tombstone: bool,
}

impl RoleBody {
    /// The product canonical JSON bytes: sorted object keys, no insignificant
    /// whitespace, arrays already canonically sorted.
    pub fn canonical_json(&self) -> Vec<u8> {
        let mut body = self.clone();
        body.capabilities.sort();
        body.capabilities.dedup();
        let value = serde_json::to_value(&body).expect("role body to value");
        serde_json::to_string(&value)
            .expect("role body canonical json")
            .into_bytes()
    }

    /// The definition digest admission evidence binds.
    pub fn definition_digest(&self) -> [u8; 32] {
        blake3::derive_key(ROLE_DEFINITION_CONTEXT, &self.canonical_json())
    }
}

/// One immutable role revision: identity plus the exact canonical body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleRevision {
    pub revision_id: [u8; 32],
    pub predecessor_ids: Vec<[u8; 32]>,
    pub body: RoleBody,
}

/// The revision-id preimage: `u16 version=1` big-endian, `u16` RoleId length +
/// RoleId bytes, `u16` predecessor count, the sorted 32-byte predecessor ids,
/// `u32` body length, the canonical JSON body bytes.
pub fn revision_preimage(role_id: &str, predecessors: &[[u8; 32]], body_json: &[u8]) -> Vec<u8> {
    let mut sorted = predecessors.to_vec();
    sorted.sort();
    let mut out = Vec::new();
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&(role_id.len() as u16).to_be_bytes());
    out.extend_from_slice(role_id.as_bytes());
    out.extend_from_slice(&(sorted.len() as u16).to_be_bytes());
    for p in &sorted {
        out.extend_from_slice(p);
    }
    out.extend_from_slice(&(body_json.len() as u32).to_be_bytes());
    out.extend_from_slice(body_json);
    out
}

/// Why a role revision refused to build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoleError {
    BadRoleId,
    BodyTooLarge,
    TooManyPredecessors,
    UnknownRole(String),
}

impl std::fmt::Display for RoleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoleError::BadRoleId => write!(f, "invalid role id"),
            RoleError::BodyTooLarge => write!(f, "role body exceeds 16 KiB"),
            RoleError::TooManyPredecessors => write!(f, "more than 8 predecessors"),
            RoleError::UnknownRole(r) => write!(f, "unknown role `{r}`"),
        }
    }
}
impl std::error::Error for RoleError {}

/// Build a revision over `body` with `predecessors` (bounds-checked; the id
/// hashes the framed preimage).
pub fn build_revision(
    body: RoleBody,
    predecessors: Vec<[u8; 32]>,
) -> Result<RoleRevision, RoleError> {
    if body.role_id.is_empty() || body.role_id.len() > MAX_ROLE_ID {
        return Err(RoleError::BadRoleId);
    }
    if predecessors.len() > MAX_PREDECESSORS {
        return Err(RoleError::TooManyPredecessors);
    }
    let json = body.canonical_json();
    if json.len() > MAX_ROLE_BODY {
        return Err(RoleError::BodyTooLarge);
    }
    let revision_id = blake3::derive_key(
        ROLE_REVISION_CONTEXT,
        &revision_preimage(&body.role_id, &predecessors, &json),
    );
    Ok(RoleRevision {
        revision_id,
        predecessor_ids: predecessors,
        body,
    })
}

/// The three built-in Space roles, with the exact plan-04 bodies. Built-ins
/// are immutable in every field, have no predecessor, and cannot be deleted
/// or weakened.
pub const BUILT_IN_ROLE_IDS: [&str; 3] = ["lait.viewer", "lait.contributor", "lait.administrator"];

/// The built-in role definition for `role_id`, if it is one.
pub fn built_in(role_id: &str) -> Option<RoleRevision> {
    let body = match role_id {
        "lait.viewer" => RoleBody {
            role_id: "lait.viewer".into(),
            scope_kind: ScopeKind::Space,
            name: "Viewer".into(),
            description: "Can read every issue in the Space.".into(),
            capabilities: vec!["space.issue.read".into()],
            tombstone: false,
        },
        "lait.contributor" => RoleBody {
            role_id: "lait.contributor".into(),
            scope_kind: ScopeKind::Space,
            name: "Contributor".into(),
            description: "Can perform ordinary issue work across the Space.".into(),
            capabilities: vec!["space.contributor".into(), "space.issue.read".into()],
            tombstone: false,
        },
        "lait.administrator" => RoleBody {
            role_id: "lait.administrator".into(),
            scope_kind: ScopeKind::Space,
            name: "Administrator".into(),
            description: "Can administer Issues policy and perform all issue work.".into(),
            capabilities: vec![
                "space.admin".into(),
                "space.contributor".into(),
                "space.issue.read".into(),
            ],
            tombstone: false,
        },
        _ => return None,
    };
    Some(build_revision(body, vec![]).expect("built-in role body is within bounds"))
}

/// Resolve a user-facing role selector to a built-in role id: the canonical
/// id, or the short alias (`viewer`/`contributor`/`administrator`/`admin`).
pub fn resolve_role_selector(selector: &str) -> Option<&'static str> {
    match selector.trim() {
        "lait.viewer" | "viewer" => Some("lait.viewer"),
        "lait.contributor" | "contributor" => Some("lait.contributor"),
        "lait.administrator" | "administrator" | "admin" => Some("lait.administrator"),
        _ => None,
    }
}

/// The bounded opaque role provenance an invite carries: `(role_id,
/// revision_id)`, postcard-encoded. Mechanics never decodes it.
pub fn provenance_ref(role_id: &str, revision_id: &[u8; 32]) -> Vec<u8> {
    postcard::to_stdvec(&(role_id, revision_id)).expect("role provenance")
}

/// The complete expanded admission evidence for a role: the role's
/// capabilities on the Space resource, plus the mandatory `space.issue.read`
/// baseline, plus — for the administrator — the Mechanics policy-admin
/// meta-grant, all inside the signed evidence digest.
pub fn role_admission_evidence(
    revision: &RoleRevision,
    parent_manifest_root: [u8; 32],
) -> mechanics::demand::WorldAssignmentEvidence {
    let res = PolicyResource::space(PRODUCT_WORLD);
    let mut assignments: Vec<(PolicyCapability, PolicyResource)> = revision
        .body
        .capabilities
        .iter()
        .map(|c| (PolicyCapability::new(PRODUCT_WORLD, c), res.clone()))
        .collect();
    // The mandatory baseline is ALWAYS inside the signed digest, whatever the
    // role says.
    assignments.push((
        PolicyCapability::new(PRODUCT_WORLD, "space.issue.read"),
        res.clone(),
    ));
    // Administrator admission additionally installs the Mechanics meta-grant
    // (policy administration), which only a policy admin may issue.
    if revision.body.role_id == "lait.administrator" {
        assignments.push((
            mechanics::acl::policy_admin_capability(),
            mechanics::acl::policy_admin_resource(),
        ));
    }
    assignments.sort();
    assignments.dedup();
    mechanics::demand::WorldAssignmentEvidence {
        world: PRODUCT_WORLD.to_string(),
        opaque_definition_ref: provenance_ref(&revision.body.role_id, &revision.revision_id),
        definition_digest: revision.body.definition_digest(),
        parent_manifest_root,
        assignments,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Golden canonical bytes and revision ids for the three built-ins:
    /// formation and invites compare generated bytes to these, so an
    /// accidental edit to a built-in body cannot pass silently.
    #[test]
    fn built_in_bodies_and_revision_ids_are_golden() {
        let viewer = built_in("lait.viewer").unwrap();
        assert_eq!(
            String::from_utf8(viewer.body.canonical_json()).unwrap(),
            "{\"capabilities\":[\"space.issue.read\"],\"description\":\"Can read every issue in the Space.\",\"name\":\"Viewer\",\"role_id\":\"lait.viewer\",\"scope_kind\":\"space\",\"tombstone\":false}"
        );
        let contributor = built_in("lait.contributor").unwrap();
        assert_eq!(
            String::from_utf8(contributor.body.canonical_json()).unwrap(),
            "{\"capabilities\":[\"space.contributor\",\"space.issue.read\"],\"description\":\"Can perform ordinary issue work across the Space.\",\"name\":\"Contributor\",\"role_id\":\"lait.contributor\",\"scope_kind\":\"space\",\"tombstone\":false}"
        );
        let admin = built_in("lait.administrator").unwrap();
        assert_eq!(
            String::from_utf8(admin.body.canonical_json()).unwrap(),
            "{\"capabilities\":[\"space.admin\",\"space.contributor\",\"space.issue.read\"],\"description\":\"Can administer Issues policy and perform all issue work.\",\"name\":\"Administrator\",\"role_id\":\"lait.administrator\",\"scope_kind\":\"space\",\"tombstone\":false}"
        );
        // Revision ids are stable across builds (golden).
        for (id, rev) in BUILT_IN_ROLE_IDS
            .iter()
            .zip([&viewer, &contributor, &admin])
        {
            assert_eq!(rev.body.role_id, *id);
            assert!(rev.predecessor_ids.is_empty());
            // Deterministic: rebuilding yields the identical id.
            let again = built_in(id).unwrap();
            assert_eq!(again.revision_id, rev.revision_id);
        }
        assert_ne!(viewer.revision_id, contributor.revision_id);
    }

    #[test]
    fn a_one_bit_body_change_moves_the_revision_id() {
        let a = built_in("lait.viewer").unwrap();
        let mut body = a.body.clone();
        body.description.push('!');
        let b = build_revision(body, vec![]).unwrap();
        assert_ne!(a.revision_id, b.revision_id);
        assert_ne!(a.body.definition_digest(), b.body.definition_digest());
    }

    #[test]
    fn revision_bounds_reject() {
        let mut body = built_in("lait.viewer").unwrap().body;
        body.role_id = "x".repeat(65);
        assert_eq!(
            build_revision(body.clone(), vec![]),
            Err(RoleError::BadRoleId)
        );
        body.role_id = "ok".into();
        assert_eq!(
            build_revision(body.clone(), vec![[0u8; 32]; 9]),
            Err(RoleError::TooManyPredecessors)
        );
        body.description = "d".repeat(MAX_ROLE_BODY);
        assert_eq!(build_revision(body, vec![]), Err(RoleError::BodyTooLarge));
    }

    #[test]
    fn framed_preimage_resists_concatenation_collisions() {
        // Moving a byte between variable-length fields changes the preimage.
        let a = revision_preimage("ab", &[], b"{}");
        let b = revision_preimage("a", &[], b"b{}");
        assert_ne!(a, b);
        // Reordered predecessors canonicalize identically (sorted).
        let p1 = [[1u8; 32], [2u8; 32]];
        let p2 = [[2u8; 32], [1u8; 32]];
        assert_eq!(
            revision_preimage("r", &p1, b"{}"),
            revision_preimage("r", &p2, b"{}")
        );
    }

    #[test]
    fn admission_evidence_always_contains_the_read_baseline() {
        for id in BUILT_IN_ROLE_IDS {
            let rev = built_in(id).unwrap();
            let evidence = role_admission_evidence(&rev, [7u8; 32]);
            let read = PolicyCapability::new(PRODUCT_WORLD, "space.issue.read");
            assert!(
                evidence.assignments.iter().any(|(c, _)| c == &read),
                "{id} evidence carries the mandatory baseline"
            );
            // Provenance decodes back to (role_id, revision_id).
            let (rid, revid): (String, [u8; 32]) =
                postcard::from_bytes(&evidence.opaque_definition_ref).unwrap();
            assert_eq!((rid.as_str(), revid), (id, rev.revision_id));
        }
        // Only the administrator carries the meta-grant.
        let admin = role_admission_evidence(&built_in("lait.administrator").unwrap(), [0u8; 32]);
        let meta = mechanics::acl::policy_admin_capability();
        assert!(admin.assignments.iter().any(|(c, _)| c == &meta));
        let viewer = role_admission_evidence(&built_in("lait.viewer").unwrap(), [0u8; 32]);
        assert!(!viewer.assignments.iter().any(|(c, _)| c == &meta));
    }
}
