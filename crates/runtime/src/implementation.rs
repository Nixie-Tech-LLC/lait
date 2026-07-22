//! The World implementation identity — the authority-approved
//! compatibility/trust identity a Space pins.
//!
//! `WorldImplementationId` is the canonical digest of a
//! [`WorldImplementationDescriptor`]. It is **not** native-code attestation:
//! trusted in-process Rust self-asserts its embedded descriptor; Runtime
//! hashes it and requires the resulting id to be **active in Mechanics at the
//! pinned authority frontier** before activation, dock, submit, query,
//! projection/audit helpers, or IAM expansion planning. Upgrade and rollback
//! are explicit authority operations
//! ([`mechanics::acl::AclAction::ActivateWorldImplementation`]), never
//! deployment configuration.
//!
//! Descriptor encoding version 1 is a fixed-order binary tuple: `u16` version
//! (big-endian, exactly 1); `u16`-length-prefixed canonical WorldId bytes;
//! `u32` policy protocol and implementation version (big-endian); `u16`
//! schema count followed by `u32`-length-prefixed schema descriptors sorted
//! by their complete canonical bytes; then exactly 32-byte policy-table
//! commitment and 32-byte artifact identity. Schema duplicates, unsorted
//! entries, unknown version, and trailing bytes reject.

use replica::body::{BodySchema, MutationModel};
use replica::ids::WorldId;

/// BLAKE3 derive-key context for the implementation id.
const IMPLEMENTATION_CONTEXT: &str = "lait.world-implementation.v1";
/// BLAKE3 derive-key context for the policy-table commitment.
const POLICY_TABLE_CONTEXT: &str = "lait.world-policy-table.v1";

/// Why a descriptor failed to encode/decode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DescriptorError {
    UnknownVersion(u16),
    UnsortedOrDuplicateSchemas,
    Truncated,
    TrailingBytes,
    BadWorldId,
}

impl std::fmt::Display for DescriptorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DescriptorError {}

/// The complete implementation descriptor a World embeds and self-asserts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldImplementationDescriptor {
    pub world: WorldId,
    /// The policy-protocol version this implementation speaks (demand
    /// selection semantics).
    pub policy_protocol: u32,
    pub implementation_version: u32,
    /// Canonical schema-descriptor bytes ([`canonical_schema_bytes`]),
    /// sorted by their complete canonical bytes, no duplicates.
    pub schemas: Vec<Vec<u8>>,
    /// BLAKE3 derive-key commitment over the checked-in exhaustive policy
    /// table bytes ([`policy_table_commitment`]).
    pub policy_table_commitment: [u8; 32],
    /// An authority-reviewed, build-embedded 32-byte release id — not a
    /// platform binary hash or attestation.
    pub artifact_identity: [u8; 32],
}

/// The canonical bytes of one schema declaration inside a descriptor:
/// `u16`+SchemaId bytes, `u32` version (BE), `u16`+EncodingId bytes, one
/// mutation-model tag byte, `u16` readable-predecessor count followed by each
/// `u32` (BE, sorted ascending).
pub fn canonical_schema_bytes(schema: &BodySchema) -> Vec<u8> {
    let mut out = Vec::new();
    let id = schema.id.as_str().as_bytes();
    out.extend_from_slice(&(id.len() as u16).to_be_bytes());
    out.extend_from_slice(id);
    out.extend_from_slice(&schema.version.to_be_bytes());
    let enc = schema.encoding.as_str().as_bytes();
    out.extend_from_slice(&(enc.len() as u16).to_be_bytes());
    out.extend_from_slice(enc);
    out.push(match schema.mutation {
        MutationModel::Atomic => 0,
        MutationModel::Collaborative(_) => 1,
    });
    let mut predecessors = schema.readable_predecessors.clone();
    predecessors.sort_unstable();
    predecessors.dedup();
    out.extend_from_slice(&(predecessors.len() as u16).to_be_bytes());
    for p in predecessors {
        out.extend_from_slice(&p.to_be_bytes());
    }
    out
}

/// The policy-table commitment over the checked-in exhaustive table bytes.
pub fn policy_table_commitment(table_bytes: &[u8]) -> [u8; 32] {
    blake3::derive_key(POLICY_TABLE_CONTEXT, table_bytes)
}

impl WorldImplementationDescriptor {
    /// Build a descriptor from a World's registration schemas (canonicalized
    /// and sorted here).
    pub fn from_schemas(
        world: WorldId,
        policy_protocol: u32,
        implementation_version: u32,
        schemas: &[BodySchema],
        policy_table_commitment: [u8; 32],
        artifact_identity: [u8; 32],
    ) -> Self {
        let mut canonical: Vec<Vec<u8>> = schemas.iter().map(canonical_schema_bytes).collect();
        canonical.sort();
        canonical.dedup();
        Self {
            world,
            policy_protocol,
            implementation_version,
            schemas: canonical,
            policy_table_commitment,
            artifact_identity,
        }
    }

    /// The fixed-order canonical descriptor encoding (version 1).
    pub fn encode(&self) -> Result<Vec<u8>, DescriptorError> {
        for w in self.schemas.windows(2) {
            if w[0] >= w[1] {
                return Err(DescriptorError::UnsortedOrDuplicateSchemas);
            }
        }
        let mut out = Vec::new();
        out.extend_from_slice(&1u16.to_be_bytes());
        let world = self.world.as_str().as_bytes();
        out.extend_from_slice(&(world.len() as u16).to_be_bytes());
        out.extend_from_slice(world);
        out.extend_from_slice(&self.policy_protocol.to_be_bytes());
        out.extend_from_slice(&self.implementation_version.to_be_bytes());
        out.extend_from_slice(&(self.schemas.len() as u16).to_be_bytes());
        for schema in &self.schemas {
            out.extend_from_slice(&(schema.len() as u32).to_be_bytes());
            out.extend_from_slice(schema);
        }
        out.extend_from_slice(&self.policy_table_commitment);
        out.extend_from_slice(&self.artifact_identity);
        Ok(out)
    }

    /// Strict decode of the canonical encoding.
    pub fn decode(bytes: &[u8]) -> Result<Self, DescriptorError> {
        let mut pos = 0usize;
        let take = |pos: &mut usize, n: usize| -> Result<&[u8], DescriptorError> {
            if bytes.len() < *pos + n {
                return Err(DescriptorError::Truncated);
            }
            let s = &bytes[*pos..*pos + n];
            *pos += n;
            Ok(s)
        };
        let version = u16::from_be_bytes(take(&mut pos, 2)?.try_into().unwrap());
        if version != 1 {
            return Err(DescriptorError::UnknownVersion(version));
        }
        let world_len = u16::from_be_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
        let world_bytes = take(&mut pos, world_len)?;
        let world = std::str::from_utf8(world_bytes)
            .ok()
            .and_then(WorldId::parse)
            .ok_or(DescriptorError::BadWorldId)?;
        let policy_protocol = u32::from_be_bytes(take(&mut pos, 4)?.try_into().unwrap());
        let implementation_version = u32::from_be_bytes(take(&mut pos, 4)?.try_into().unwrap());
        let count = u16::from_be_bytes(take(&mut pos, 2)?.try_into().unwrap()) as usize;
        let mut schemas = Vec::with_capacity(count);
        let mut prev: Option<Vec<u8>> = None;
        for _ in 0..count {
            let len = u32::from_be_bytes(take(&mut pos, 4)?.try_into().unwrap()) as usize;
            let schema = take(&mut pos, len)?.to_vec();
            if let Some(prev) = &prev {
                if prev >= &schema {
                    return Err(DescriptorError::UnsortedOrDuplicateSchemas);
                }
            }
            prev = Some(schema.clone());
            schemas.push(schema);
        }
        let policy_table_commitment: [u8; 32] = take(&mut pos, 32)?.try_into().unwrap();
        let artifact_identity: [u8; 32] = take(&mut pos, 32)?.try_into().unwrap();
        if pos != bytes.len() {
            return Err(DescriptorError::TrailingBytes);
        }
        Ok(Self {
            world,
            policy_protocol,
            implementation_version,
            schemas,
            policy_table_commitment,
            artifact_identity,
        })
    }

    /// The canonical implementation id.
    pub fn id(&self) -> Result<[u8; 32], DescriptorError> {
        Ok(blake3::derive_key(IMPLEMENTATION_CONTEXT, &self.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use replica::ids::{EncodingId, SchemaId};

    fn schema(name: &str, version: u32) -> BodySchema {
        BodySchema {
            id: SchemaId::parse(name).unwrap(),
            version,
            encoding: EncodingId::parse("json").unwrap(),
            mutation: MutationModel::Atomic,
            readable_predecessors: vec![],
        }
    }

    fn descriptor(schemas: &[BodySchema]) -> WorldImplementationDescriptor {
        WorldImplementationDescriptor::from_schemas(
            WorldId::parse("com.example.notes").unwrap(),
            1,
            7,
            schemas,
            [3u8; 32],
            [4u8; 32],
        )
    }

    #[test]
    fn roundtrip_empty_min_max_schema_sets() {
        for schemas in [
            vec![],
            vec![schema("a", 1)],
            (0..16).map(|i| schema(&format!("s{i:02}"), 1)).collect(),
        ] {
            let d = descriptor(&schemas);
            let bytes = d.encode().unwrap();
            let back = WorldImplementationDescriptor::decode(&bytes).unwrap();
            assert_eq!(d, back);
            assert_eq!(d.id().unwrap(), back.id().unwrap());
        }
    }

    #[test]
    fn reordered_and_duplicate_schemas_reject() {
        let d = descriptor(&[schema("aa", 1), schema("bb", 1)]);
        let good = d.encode().unwrap();
        WorldImplementationDescriptor::decode(&good).unwrap();

        // Manually swap the two schema entries.
        let mut manual = d.clone();
        manual.schemas.swap(0, 1);
        assert_eq!(
            manual.encode(),
            Err(DescriptorError::UnsortedOrDuplicateSchemas)
        );
        // A duplicated entry rejects on decode.
        let mut dup = d.clone();
        dup.schemas = vec![d.schemas[0].clone(), d.schemas[0].clone()];
        assert!(dup.encode().is_err());
    }

    #[test]
    fn every_field_perturbation_changes_the_id() {
        let base = descriptor(&[schema("aa", 1)]);
        let base_id = base.id().unwrap();
        let mut d = base.clone();
        d.policy_protocol = 2;
        assert_ne!(d.id().unwrap(), base_id);
        let mut d = base.clone();
        d.implementation_version = 8;
        assert_ne!(d.id().unwrap(), base_id);
        let mut d = base.clone();
        d.world = WorldId::parse("com.example.other").unwrap();
        assert_ne!(d.id().unwrap(), base_id);
        // One-bit substitutions of the two 32-byte identities.
        for byte in 0..32 {
            for bit in 0..8 {
                let mut d = base.clone();
                d.policy_table_commitment[byte] ^= 1 << bit;
                assert_ne!(d.id().unwrap(), base_id, "commitment bit {byte}:{bit}");
                let mut d = base.clone();
                d.artifact_identity[byte] ^= 1 << bit;
                assert_ne!(d.id().unwrap(), base_id, "artifact bit {byte}:{bit}");
            }
        }
    }

    #[test]
    fn unknown_version_and_trailing_bytes_reject() {
        let d = descriptor(&[schema("aa", 1)]);
        let mut bytes = d.encode().unwrap();
        let mut wrong = bytes.clone();
        wrong[1] = 2;
        assert_eq!(
            WorldImplementationDescriptor::decode(&wrong),
            Err(DescriptorError::UnknownVersion(2))
        );
        bytes.push(0);
        assert_eq!(
            WorldImplementationDescriptor::decode(&bytes),
            Err(DescriptorError::TrailingBytes)
        );
    }

    #[test]
    fn policy_table_commitment_is_content_bound() {
        assert_ne!(
            policy_table_commitment(b"table-a"),
            policy_table_commitment(b"table-b")
        );
    }
}
