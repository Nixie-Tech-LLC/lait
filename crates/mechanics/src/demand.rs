//! The bounded authorization-demand algebra — the World-defined,
//! Mechanics-enforced policy vocabulary.
//!
//! A World selects a canonical [`AuthorizationDemand`] for every mutation and
//! query; Mechanics evaluates it against the expanded effective capability
//! assignments at a pinned historical authority frontier. Lower planes never
//! interpret product roles or lifecycle states — only this bounded generic
//! algebra crosses the boundary.
//!
//! ```text
//! PolicyResource { world, segments[] }
//! PolicyCapability { world, name }
//! AuthorizationDemand = Require(capability, resource)
//!                     | All(demands[])
//!                     | Any(demands[])
//! ```
//!
//! The first format permits at most 8 resource segments of 1..64 UTF-8 bytes
//! and 512 resource bytes total; capability names are 1..64 lowercase ASCII
//! bytes from `[a-z0-9._-]`; demand depth is at most 8, each `All`/`Any` has
//! 1..32 children, there are at most 128 `Require` leaves, and canonical
//! encodings are at most 16 KiB. Nested same-kind nodes are flattened before
//! encoding; children sort by their complete canonical byte encoding and
//! duplicates reject. Empty nodes, unsorted input, wildcard segments, unknown
//! tags, and trailing bytes reject. Resource matching is exact; inheritance
//! and admin override occur only through explicit demand alternatives.
//! Threshold/separation-of-duty is reserved until specified.

use serde::{Deserialize, Serialize};

/// Maximum resource segments.
pub const MAX_RESOURCE_SEGMENTS: usize = 8;
/// Maximum bytes per resource segment.
pub const MAX_SEGMENT_BYTES: usize = 64;
/// Maximum total resource bytes (all segments).
pub const MAX_RESOURCE_BYTES: usize = 512;
/// Capability/world identifier bounds.
pub const MAX_NAME_BYTES: usize = 64;
/// Maximum demand nesting depth.
pub const MAX_DEMAND_DEPTH: usize = 8;
/// `All`/`Any` child count bounds.
pub const MAX_CHILDREN: usize = 32;
/// Maximum `Require` leaves in one demand.
pub const MAX_REQUIRE_LEAVES: usize = 128;
/// Maximum canonical encoded bytes.
pub const MAX_DEMAND_BYTES: usize = 16 * 1024;

/// BLAKE3 derive-key context for the demand digest.
const DEMAND_CONTEXT: &str = "lait.authorization-demand.v1";

const TAG_REQUIRE: u8 = 0x01;
const TAG_ALL: u8 = 0x02;
const TAG_ANY: u8 = 0x03;

/// Why a demand failed validation or decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DemandError {
    /// A world/capability identifier violates the grammar or bounds.
    BadIdentifier(String),
    /// A resource violates the segment/byte bounds or contains a wildcard.
    BadResource(String),
    /// The expression violates a structural bound (depth, children, leaves,
    /// bytes) or contains an empty node.
    BadStructure(String),
    /// Children are unsorted or duplicated (non-canonical input).
    NonCanonical(String),
    /// The encoded form has an unknown tag, truncation, or trailing bytes.
    BadEncoding(String),
}

impl std::fmt::Display for DemandError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DemandError::BadIdentifier(m) => write!(f, "bad identifier: {m}"),
            DemandError::BadResource(m) => write!(f, "bad resource: {m}"),
            DemandError::BadStructure(m) => write!(f, "bad demand structure: {m}"),
            DemandError::NonCanonical(m) => write!(f, "non-canonical demand: {m}"),
            DemandError::BadEncoding(m) => write!(f, "bad demand encoding: {m}"),
        }
    }
}
impl std::error::Error for DemandError {}

/// Whether an identifier is 1..=64 bytes of lowercase `[a-z0-9._-]`.
fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_NAME_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b))
}

/// A bounded generic policy resource: a World plus exact opaque segments.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyResource {
    /// The World whose namespace the resource lives in (canonical WorldId
    /// text; opaque to Mechanics beyond the grammar).
    pub world: String,
    /// Exact resource segments; matching is byte-exact, never hierarchical.
    pub segments: Vec<String>,
}

impl PolicyResource {
    /// The Space-level resource of a World (no segments).
    pub fn space(world: &str) -> Self {
        Self {
            world: world.to_string(),
            segments: Vec::new(),
        }
    }

    pub fn validate(&self) -> Result<(), DemandError> {
        if !valid_name(&self.world) {
            return Err(DemandError::BadIdentifier(format!(
                "world `{}`",
                self.world
            )));
        }
        if self.segments.len() > MAX_RESOURCE_SEGMENTS {
            return Err(DemandError::BadResource("too many segments".into()));
        }
        let mut total = 0usize;
        for seg in &self.segments {
            if seg.is_empty() || seg.len() > MAX_SEGMENT_BYTES {
                return Err(DemandError::BadResource(format!(
                    "segment length {}",
                    seg.len()
                )));
            }
            if seg == "*" {
                return Err(DemandError::BadResource("wildcard segment".into()));
            }
            total += seg.len();
        }
        if total > MAX_RESOURCE_BYTES {
            return Err(DemandError::BadResource("resource bytes exceed 512".into()));
        }
        Ok(())
    }
}

/// A World-namespaced capability name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyCapability {
    pub world: String,
    pub name: String,
}

impl PolicyCapability {
    pub fn new(world: &str, name: &str) -> Self {
        Self {
            world: world.to_string(),
            name: name.to_string(),
        }
    }

    pub fn validate(&self) -> Result<(), DemandError> {
        if !valid_name(&self.world) {
            return Err(DemandError::BadIdentifier(format!(
                "world `{}`",
                self.world
            )));
        }
        if !valid_name(&self.name) {
            return Err(DemandError::BadIdentifier(format!(
                "capability `{}`",
                self.name
            )));
        }
        Ok(())
    }
}

/// The bounded authorization-demand expression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthorizationDemand {
    /// Exact-lookup requirement: the actor must hold an effective grant of
    /// exactly this capability on exactly this resource.
    Require {
        capability: PolicyCapability,
        resource: PolicyResource,
    },
    /// Every child must be satisfied.
    All(Vec<AuthorizationDemand>),
    /// At least one child must be satisfied.
    Any(Vec<AuthorizationDemand>),
}

impl AuthorizationDemand {
    /// A single-requirement demand.
    pub fn require(capability: PolicyCapability, resource: PolicyResource) -> Self {
        AuthorizationDemand::Require {
            capability,
            resource,
        }
    }

    /// Canonicalize this expression: flatten nested same-kind nodes, sort
    /// children by their complete canonical bytes, reject duplicates, and
    /// validate every bound. Returns the canonical encoding.
    pub fn encode_canonical(&self) -> Result<Vec<u8>, DemandError> {
        let mut leaves = 0usize;
        let bytes = self.encode_node(1, &mut leaves)?;
        if bytes.len() > MAX_DEMAND_BYTES {
            return Err(DemandError::BadStructure(
                "canonical bytes exceed 16 KiB".into(),
            ));
        }
        Ok(bytes)
    }

    fn encode_node(&self, depth: usize, leaves: &mut usize) -> Result<Vec<u8>, DemandError> {
        if depth > MAX_DEMAND_DEPTH {
            return Err(DemandError::BadStructure("depth exceeds 8".into()));
        }
        match self {
            AuthorizationDemand::Require {
                capability,
                resource,
            } => {
                capability.validate()?;
                resource.validate()?;
                if capability.world != resource.world {
                    return Err(DemandError::BadStructure(
                        "capability and resource name different Worlds".into(),
                    ));
                }
                *leaves += 1;
                if *leaves > MAX_REQUIRE_LEAVES {
                    return Err(DemandError::BadStructure("more than 128 leaves".into()));
                }
                let mut out = vec![TAG_REQUIRE];
                push_str(&mut out, &capability.world);
                push_str(&mut out, &capability.name);
                out.push(resource.segments.len() as u8);
                for seg in &resource.segments {
                    push_str(&mut out, seg);
                }
                Ok(out)
            }
            AuthorizationDemand::All(children) | AuthorizationDemand::Any(children) => {
                let (tag, same_kind): (u8, fn(&AuthorizationDemand) -> bool) = match self {
                    AuthorizationDemand::All(_) => {
                        (TAG_ALL, |d| matches!(d, AuthorizationDemand::All(_)))
                    }
                    AuthorizationDemand::Any(_) => {
                        (TAG_ANY, |d| matches!(d, AuthorizationDemand::Any(_)))
                    }
                    AuthorizationDemand::Require { .. } => unreachable!(),
                };
                // Flatten nested same-kind nodes before encoding.
                let mut flat: Vec<&AuthorizationDemand> = Vec::new();
                let mut stack: Vec<&AuthorizationDemand> = children.iter().rev().collect();
                while let Some(child) = stack.pop() {
                    if same_kind(child) {
                        match child {
                            AuthorizationDemand::All(inner) | AuthorizationDemand::Any(inner) => {
                                for c in inner.iter().rev() {
                                    stack.push(c);
                                }
                            }
                            AuthorizationDemand::Require { .. } => unreachable!(),
                        }
                    } else {
                        flat.push(child);
                    }
                }
                if flat.is_empty() {
                    return Err(DemandError::BadStructure("empty node".into()));
                }
                if flat.len() > MAX_CHILDREN {
                    return Err(DemandError::BadStructure("more than 32 children".into()));
                }
                let mut encoded: Vec<Vec<u8>> = flat
                    .iter()
                    .map(|c| c.encode_node(depth + 1, leaves))
                    .collect::<Result<_, _>>()?;
                encoded.sort();
                for w in encoded.windows(2) {
                    if w[0] == w[1] {
                        return Err(DemandError::NonCanonical("duplicate children".into()));
                    }
                }
                let mut out = vec![tag];
                out.extend_from_slice(&(encoded.len() as u16).to_be_bytes());
                for child in encoded {
                    out.extend_from_slice(&(child.len() as u32).to_be_bytes());
                    out.extend_from_slice(&child);
                }
                Ok(out)
            }
        }
    }

    /// Strict canonical decode: unknown tags, truncation, trailing bytes,
    /// unsorted or duplicate children, bound overflow, and non-canonical
    /// nesting (a same-kind child that should have been flattened) all reject.
    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, DemandError> {
        if bytes.len() > MAX_DEMAND_BYTES {
            return Err(DemandError::BadEncoding("exceeds 16 KiB".into()));
        }
        let mut leaves = 0usize;
        let (demand, used) = Self::decode_node(bytes, 1, &mut leaves)?;
        if used != bytes.len() {
            return Err(DemandError::BadEncoding("trailing bytes".into()));
        }
        // Canonical means round-trip byte equality.
        let re = demand.encode_canonical()?;
        if re != bytes {
            return Err(DemandError::NonCanonical("re-encode mismatch".into()));
        }
        Ok(demand)
    }

    fn decode_node(
        bytes: &[u8],
        depth: usize,
        leaves: &mut usize,
    ) -> Result<(Self, usize), DemandError> {
        if depth > MAX_DEMAND_DEPTH {
            return Err(DemandError::BadStructure("depth exceeds 8".into()));
        }
        let tag = *bytes
            .first()
            .ok_or_else(|| DemandError::BadEncoding("empty".into()))?;
        match tag {
            TAG_REQUIRE => {
                let mut pos = 1;
                let world = read_str(bytes, &mut pos)?;
                let name = read_str(bytes, &mut pos)?;
                let count = *bytes
                    .get(pos)
                    .ok_or_else(|| DemandError::BadEncoding("truncated".into()))?
                    as usize;
                pos += 1;
                if count > MAX_RESOURCE_SEGMENTS {
                    return Err(DemandError::BadResource("too many segments".into()));
                }
                let mut segments = Vec::with_capacity(count);
                for _ in 0..count {
                    segments.push(read_str(bytes, &mut pos)?);
                }
                *leaves += 1;
                if *leaves > MAX_REQUIRE_LEAVES {
                    return Err(DemandError::BadStructure("more than 128 leaves".into()));
                }
                let demand = AuthorizationDemand::Require {
                    capability: PolicyCapability {
                        world: world.clone(),
                        name,
                    },
                    resource: PolicyResource { world, segments },
                };
                Ok((demand, pos))
            }
            TAG_ALL | TAG_ANY => {
                if bytes.len() < 3 {
                    return Err(DemandError::BadEncoding("truncated".into()));
                }
                let count = u16::from_be_bytes([bytes[1], bytes[2]]) as usize;
                if count == 0 {
                    return Err(DemandError::BadStructure("empty node".into()));
                }
                if count > MAX_CHILDREN {
                    return Err(DemandError::BadStructure("more than 32 children".into()));
                }
                let mut pos = 3;
                let mut children = Vec::with_capacity(count);
                let mut prev: Option<&[u8]> = None;
                for _ in 0..count {
                    if bytes.len() < pos + 4 {
                        return Err(DemandError::BadEncoding("truncated".into()));
                    }
                    let len = u32::from_be_bytes([
                        bytes[pos],
                        bytes[pos + 1],
                        bytes[pos + 2],
                        bytes[pos + 3],
                    ]) as usize;
                    pos += 4;
                    if bytes.len() < pos + len {
                        return Err(DemandError::BadEncoding("truncated child".into()));
                    }
                    let slice = &bytes[pos..pos + len];
                    if let Some(prev) = prev {
                        if prev >= slice {
                            return Err(DemandError::NonCanonical(
                                "children unsorted or duplicated".into(),
                            ));
                        }
                    }
                    // A same-kind nested child should have been flattened.
                    if slice.first() == Some(&tag) {
                        return Err(DemandError::NonCanonical(
                            "same-kind child not flattened".into(),
                        ));
                    }
                    let (child, used) = Self::decode_node(slice, depth + 1, leaves)?;
                    if used != len {
                        return Err(DemandError::BadEncoding("child trailing bytes".into()));
                    }
                    children.push(child);
                    prev = Some(slice);
                    pos += len;
                }
                let demand = if tag == TAG_ALL {
                    AuthorizationDemand::All(children)
                } else {
                    AuthorizationDemand::Any(children)
                };
                Ok((demand, pos))
            }
            other => Err(DemandError::BadEncoding(format!("unknown tag {other}"))),
        }
    }

    /// The demand digest over the canonical bytes.
    pub fn digest(&self) -> Result<[u8; 32], DemandError> {
        Ok(blake3::derive_key(
            DEMAND_CONTEXT,
            &self.encode_canonical()?,
        ))
    }
}

/// BLAKE3 derive-key context for the policy-evidence digest (the sorted,
/// deduplicated effective-grant-id witness set).
const EVIDENCE_CONTEXT: &str = "lait.policy-evidence.v1";
/// BLAKE3 derive-key context for the receipt digest.
const RECEIPT_CONTEXT: &str = "lait.authorization-receipt.v1";

/// Digest over a canonical witness: the sorted, deduplicated effective grant
/// ids that satisfied the demand.
pub fn policy_evidence_digest(witness: &[[u8; 32]]) -> [u8; 32] {
    let mut input = Vec::with_capacity(8 + witness.len() * 32);
    input.extend_from_slice(&(witness.len() as u64).to_be_bytes());
    for id in witness {
        input.extend_from_slice(id);
    }
    blake3::derive_key(EVIDENCE_CONTEXT, &input)
}

/// The deterministic World-authorization evidence Mechanics derives from the
/// pinned checkpoint and a canonical witness. It is **not** an actor assertion
/// or a separately signed token: authenticity comes from the signed authority
/// history it is derived from plus the outer transaction signature that
/// carries it. Denials are typed results and never receipts.
///
/// Distinct from the authority-batch receipt (history incorporation) and the
/// request receipt (request-replay outcome).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationReceipt {
    /// The Space (canonical SpaceId text).
    pub space: String,
    /// The World (canonical WorldId text).
    pub world: String,
    /// The authorized actor (canonical ActorId text).
    pub actor: String,
    /// The signing device's raw key.
    pub device: [u8; 32],
    /// The canonical authority-frontier bytes evaluation was pinned to.
    pub authority_frontier: Vec<u8>,
    /// The commitment of the materialized checkpoint at that frontier.
    pub authority_checkpoint_commitment: [u8; 32],
    /// Digest over the exact effective-grant witness set.
    pub policy_evidence_digest: [u8; 32],
    /// The parent Manifest root evaluation was pinned to.
    pub parent_manifest_root: [u8; 32],
    /// The authority-approved World implementation id active at the frontier.
    pub implementation_id: [u8; 32],
    /// Digest of the signed intent payload.
    pub intent_digest: [u8; 32],
    /// Digest of the canonical demand bytes.
    pub demand_digest: [u8; 32],
    /// Digest of the complete canonical staged effect/operation set.
    pub effect_operations_digest: [u8; 32],
    /// Digest of the complete canonical transaction core (excluding this
    /// receipt, the outer signature, and the outer transaction id).
    pub body_transaction_core_digest: [u8; 32],
    /// Always `1` (Allow). A denial is a typed result, never a receipt.
    pub decision: u8,
}

impl AuthorizationReceipt {
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("encode authorization receipt")
    }

    /// Canonical decode with exact re-encode equality and the Allow pin.
    pub fn decode(bytes: &[u8]) -> Result<Self, DemandError> {
        let r: AuthorizationReceipt = postcard::from_bytes(bytes)
            .map_err(|e| DemandError::BadEncoding(format!("receipt: {e}")))?;
        if r.encode() != bytes {
            return Err(DemandError::BadEncoding(
                "non-canonical receipt encoding".into(),
            ));
        }
        if r.decision != 1 {
            return Err(DemandError::BadEncoding(
                "a receipt is always an Allow".into(),
            ));
        }
        Ok(r)
    }

    /// The receipt digest (referenced by the request receipt).
    pub fn digest(&self) -> [u8; 32] {
        blake3::derive_key(RECEIPT_CONTEXT, &self.encode())
    }
}

/// The bounded generic evidence that crosses from a product World into
/// Mechanics as an invite's role expansion (plan 01). Mechanics treats the
/// reference/digest as opaque audit binding and interprets only the generic
/// `assignments`, the issuer's delegation authority, and the Space/World
/// coordinates — no RoleId, workflow type, or product DTO enters Mechanics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorldAssignmentEvidence {
    /// The World whose namespace the assignments live in (canonical WorldId).
    pub world: String,
    /// An opaque reference to the product role definition (audit only).
    pub opaque_definition_ref: Vec<u8>,
    /// The digest of the exact role definition the assignments expand.
    pub definition_digest: [u8; 32],
    /// The Manifest root the role definition was read from.
    pub parent_manifest_root: [u8; 32],
    /// The exact expanded effective assignments to install on redemption.
    pub assignments: Vec<(PolicyCapability, PolicyResource)>,
}

impl WorldAssignmentEvidence {
    /// The canonical bytes (postcard with sorted, deduplicated assignments).
    pub fn canonical(&self) -> Vec<u8> {
        let mut e = self.clone();
        e.assignments.sort();
        e.assignments.dedup();
        postcard::to_stdvec(&e).expect("postcard world-assignment evidence")
    }

    /// The evidence digest — bound into the admission capability's signature.
    pub fn digest(&self) -> [u8; 32] {
        blake3::derive_key("lait.world-assignment-evidence.v1", &self.canonical())
    }

    /// Structural validation: bounded assignment count, valid identifiers, and
    /// every assignment scoped to the declared World.
    pub fn validate(&self) -> Result<(), DemandError> {
        if !valid_name(&self.world) {
            return Err(DemandError::BadIdentifier(format!(
                "world `{}`",
                self.world
            )));
        }
        if self.assignments.len() > MAX_REQUIRE_LEAVES {
            return Err(DemandError::BadStructure("too many assignments".into()));
        }
        for (cap, res) in &self.assignments {
            cap.validate()?;
            res.validate()?;
            if cap.world != self.world || res.world != self.world {
                return Err(DemandError::BadStructure(
                    "assignment outside the declared World".into(),
                ));
            }
        }
        Ok(())
    }
}

fn push_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u16).to_be_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn read_str(bytes: &[u8], pos: &mut usize) -> Result<String, DemandError> {
    if bytes.len() < *pos + 2 {
        return Err(DemandError::BadEncoding("truncated".into()));
    }
    let len = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]) as usize;
    *pos += 2;
    if bytes.len() < *pos + len {
        return Err(DemandError::BadEncoding("truncated string".into()));
    }
    let s = std::str::from_utf8(&bytes[*pos..*pos + len])
        .map_err(|_| DemandError::BadEncoding("non-UTF-8".into()))?
        .to_string();
    *pos += len;
    if !valid_name(&s) {
        return Err(DemandError::BadIdentifier(s));
    }
    Ok(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cap(name: &str) -> PolicyCapability {
        PolicyCapability::new("com.lait.issues", name)
    }
    fn space() -> PolicyResource {
        PolicyResource::space("com.lait.issues")
    }
    fn project(p: &str) -> PolicyResource {
        PolicyResource {
            world: "com.lait.issues".into(),
            segments: vec!["project".into(), p.into()],
        }
    }

    #[test]
    fn require_roundtrips_canonically() {
        let d = AuthorizationDemand::require(cap("issue.edit"), project("prj1"));
        let bytes = d.encode_canonical().unwrap();
        let back = AuthorizationDemand::decode_canonical(&bytes).unwrap();
        assert_eq!(d, back);
    }

    #[test]
    fn all_any_sort_flatten_and_roundtrip() {
        let d = AuthorizationDemand::Any(vec![
            AuthorizationDemand::require(cap("space.admin"), space()),
            AuthorizationDemand::Any(vec![AuthorizationDemand::require(
                cap("issue.edit"),
                project("prj1"),
            )]),
            AuthorizationDemand::All(vec![
                AuthorizationDemand::require(cap("issue.move-out"), project("a")),
                AuthorizationDemand::require(cap("issue.move-in"), project("b")),
            ]),
        ]);
        let bytes = d.encode_canonical().unwrap();
        let back = AuthorizationDemand::decode_canonical(&bytes).unwrap();
        // Round-trip is stable (the decoded value re-encodes identically).
        assert_eq!(back.encode_canonical().unwrap(), bytes);
    }

    #[test]
    fn duplicates_reject() {
        let d = AuthorizationDemand::Any(vec![
            AuthorizationDemand::require(cap("space.admin"), space()),
            AuthorizationDemand::require(cap("space.admin"), space()),
        ]);
        assert!(matches!(
            d.encode_canonical(),
            Err(DemandError::NonCanonical(_))
        ));
    }

    #[test]
    fn empty_nodes_reject() {
        assert!(AuthorizationDemand::All(vec![]).encode_canonical().is_err());
        assert!(AuthorizationDemand::Any(vec![]).encode_canonical().is_err());
    }

    #[test]
    fn depth_and_child_and_leaf_bounds_reject() {
        // Depth: alternate All/Any nine levels deep.
        let mut d = AuthorizationDemand::require(cap("x"), space());
        for i in 0..9 {
            d = if i % 2 == 0 {
                AuthorizationDemand::All(vec![d])
            } else {
                AuthorizationDemand::Any(vec![d])
            };
        }
        assert!(matches!(
            d.encode_canonical(),
            Err(DemandError::BadStructure(_))
        ));

        // Children: 33 distinct leaves under one Any.
        let many: Vec<_> = (0..33)
            .map(|i| AuthorizationDemand::require(cap(&format!("c{i}")), space()))
            .collect();
        assert!(AuthorizationDemand::Any(many).encode_canonical().is_err());

        // Leaves: 129 across nested nodes (32 max children forces nesting).
        let leaf = |i: usize| AuthorizationDemand::require(cap(&format!("l{i}")), space());
        let groups: Vec<_> = (0..5)
            .map(|g| AuthorizationDemand::Any((0..26).map(|i| leaf(g * 26 + i)).collect()))
            .collect();
        // 5 * 26 = 130 leaves > 128.
        assert!(AuthorizationDemand::All(groups).encode_canonical().is_err());
    }

    #[test]
    fn exact_bounds_pass() {
        // Exactly 32 children.
        let many: Vec<_> = (0..32)
            .map(|i| AuthorizationDemand::require(cap(&format!("c{i}")), space()))
            .collect();
        AuthorizationDemand::Any(many).encode_canonical().unwrap();
        // Exactly 8 segments of exactly 64 bytes each = 512 resource bytes.
        let resource = PolicyResource {
            world: "com.lait.issues".into(),
            segments: (0..8).map(|_| "a".repeat(64)).collect(),
        };
        AuthorizationDemand::require(cap("x"), resource)
            .encode_canonical()
            .unwrap();
        // Depth exactly 8.
        let mut d = AuthorizationDemand::require(cap("x"), space());
        for i in 0..7 {
            d = if i % 2 == 0 {
                AuthorizationDemand::All(vec![d])
            } else {
                AuthorizationDemand::Any(vec![d])
            };
        }
        d.encode_canonical().unwrap();
    }

    #[test]
    fn resource_bounds_reject() {
        // 9 segments.
        let r = PolicyResource {
            world: "w".into(),
            segments: (0..9).map(|i| format!("s{i}")).collect(),
        };
        assert!(r.validate().is_err());
        // A 65-byte segment.
        let r = PolicyResource {
            world: "w".into(),
            segments: vec!["a".repeat(65)],
        };
        assert!(r.validate().is_err());
        // Wildcard.
        let r = PolicyResource {
            world: "w".into(),
            segments: vec!["*".into()],
        };
        assert!(r.validate().is_err());
        // Over 512 total bytes (8 segments of 64 = 512 ok; force overflow via
        // 8 segments of 64 + …: not representable; use 8x64 with one 65 —
        // already covered; validate the exact-limit pass instead).
        let r = PolicyResource {
            world: "w".into(),
            segments: (0..8).map(|_| "a".repeat(64)).collect(),
        };
        r.validate().unwrap();
    }

    #[test]
    fn identifier_grammar_rejects() {
        for bad in ["", "UPPER", "spa ce", "ünï", &"a".repeat(65)] {
            assert!(!valid_name(bad), "{bad:?} must be invalid");
        }
        for good in ["a", "space.admin", "issue.move_out", "role-x", "c0"] {
            assert!(valid_name(good), "{good:?} must be valid");
        }
    }

    #[test]
    fn unknown_tags_trailing_bytes_and_unsorted_reject() {
        let d = AuthorizationDemand::require(cap("x"), space());
        let mut bytes = d.encode_canonical().unwrap();
        // Unknown tag.
        let mut bad = bytes.clone();
        bad[0] = 0x7F;
        assert!(matches!(
            AuthorizationDemand::decode_canonical(&bad),
            Err(DemandError::BadEncoding(_))
        ));
        // Trailing bytes.
        bytes.push(0x00);
        assert!(matches!(
            AuthorizationDemand::decode_canonical(&bytes),
            Err(DemandError::BadEncoding(_))
        ));
        // Unsorted children: encode two leaves, swap them manually.
        let a = AuthorizationDemand::require(cap("aa"), space())
            .encode_canonical()
            .unwrap();
        let b = AuthorizationDemand::require(cap("bb"), space())
            .encode_canonical()
            .unwrap();
        let mut swapped = vec![TAG_ANY];
        swapped.extend_from_slice(&2u16.to_be_bytes());
        for child in [&b, &a] {
            swapped.extend_from_slice(&(child.len() as u32).to_be_bytes());
            swapped.extend_from_slice(child);
        }
        assert!(matches!(
            AuthorizationDemand::decode_canonical(&swapped),
            Err(DemandError::NonCanonical(_))
        ));
        // A same-kind nested child (should have been flattened).
        let inner_any = {
            let mut v = vec![TAG_ANY];
            v.extend_from_slice(&1u16.to_be_bytes());
            v.extend_from_slice(&(a.len() as u32).to_be_bytes());
            v.extend_from_slice(&a);
            v
        };
        let mut nested = vec![TAG_ANY];
        nested.extend_from_slice(&1u16.to_be_bytes());
        nested.extend_from_slice(&(inner_any.len() as u32).to_be_bytes());
        nested.extend_from_slice(&inner_any);
        assert!(matches!(
            AuthorizationDemand::decode_canonical(&nested),
            Err(DemandError::NonCanonical(_))
        ));
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let a = AuthorizationDemand::require(cap("issue.edit"), project("p"));
        let b = AuthorizationDemand::require(cap("issue.edit"), project("q"));
        assert_eq!(a.digest().unwrap(), a.digest().unwrap());
        assert_ne!(a.digest().unwrap(), b.digest().unwrap());
    }

    #[test]
    fn cross_world_require_rejects() {
        let d = AuthorizationDemand::Require {
            capability: PolicyCapability::new("com.lait.issues", "x"),
            resource: PolicyResource::space("com.other.world"),
        };
        assert!(d.encode_canonical().is_err());
    }
}
