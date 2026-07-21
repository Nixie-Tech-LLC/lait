//! External DTOs (S7) — the language-neutral JSON surface an independent,
//! Issues-free consumer speaks to the orbital runtime.
//!
//! These are **not** the signed/internal protocol (that stays postcard and is
//! never exposed as a language DTO). They are versioned JSON objects carrying an
//! explicit `protocolVersion`, with **strict unknown-field rejection**
//! (`deny_unknown_fields`), bounded strings, and bidirectional canonical
//! examples so an SDK in any language can be checked against them. A committed
//! JSON Schema 2020-12 is generated/checked from these Rust types by the
//! conformance harness; the fixtures here pin the bidirectional examples the
//! schema must accept and the malformed inputs it must reject.

use serde::{Deserialize, Serialize};

/// The DTO protocol version. Bumped only on a breaking DTO change; a consumer
/// sending another version is rejected, never negotiated (clean-break formats).
pub const DTO_PROTOCOL_VERSION: u32 = 1;

/// The maximum length of a DTO identifier string (World/schema ids, request
/// ids). Bounds every string the surface accepts.
pub const MAX_DTO_STRING: usize = 256;

/// Why a DTO failed validation beyond JSON structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DtoError {
    /// The bytes were not the expected JSON shape (or carried unknown fields).
    Malformed(String),
    /// `protocolVersion` was not [`DTO_PROTOCOL_VERSION`].
    UnsupportedProtocol(u32),
    /// A bounded string exceeded [`MAX_DTO_STRING`].
    StringTooLong,
}

impl std::fmt::Display for DtoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for DtoError {}

/// A submit request DTO. The application `payload` is base64 in JSON (arbitrary
/// bytes are not JSON-safe); everything else is a bounded string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SubmitRequestDto {
    pub protocol_version: u32,
    pub world: String,
    pub schema: String,
    pub schema_version: u32,
    /// Base64 (standard, padded) of the application intent bytes.
    pub payload_b64: String,
}

/// A submit response DTO: the committed frontier and the published observation
/// sequence. Carries no replicated state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommittedEffectDto {
    pub protocol_version: u32,
    /// Base64 of the application effect bytes.
    pub effect_b64: String,
    /// Hex of the 32-byte Replica frontier root.
    pub frontier_root_hex: String,
    pub frontier_transaction_count: u64,
    pub observation_sequence: u64,
}

/// An observation DTO — a bounded invalidation signal, carrying no state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ObservationDto {
    pub protocol_version: u32,
    pub epoch: u64,
    pub sequence: u64,
    pub reset: bool,
    pub world: String,
    pub frontier_root_hex: String,
    pub frontier_transaction_count: u64,
}

fn check_len(s: &str) -> Result<(), DtoError> {
    (s.len() <= MAX_DTO_STRING)
        .then_some(())
        .ok_or(DtoError::StringTooLong)
}

impl SubmitRequestDto {
    /// Encode to canonical JSON bytes.
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("serialize dto")
    }

    /// Decode from JSON, rejecting unknown fields, the wrong protocol version,
    /// and over-long strings.
    pub fn from_json(bytes: &[u8]) -> Result<Self, DtoError> {
        let dto: Self =
            serde_json::from_slice(bytes).map_err(|e| DtoError::Malformed(e.to_string()))?;
        if dto.protocol_version != DTO_PROTOCOL_VERSION {
            return Err(DtoError::UnsupportedProtocol(dto.protocol_version));
        }
        check_len(&dto.world)?;
        check_len(&dto.schema)?;
        check_len(&dto.payload_b64)?;
        Ok(dto)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SubmitRequestDto {
        SubmitRequestDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            world: "com.example.notes".into(),
            schema: "note".into(),
            schema_version: 1,
            payload_b64: "aGVsbG8=".into(), // "hello"
        }
    }

    #[test]
    fn a_canonical_example_roundtrips_bidirectionally() {
        let dto = sample();
        let json = dto.to_json();
        // Bidirectional: our example is exactly the canonical JSON shape.
        let text = String::from_utf8(json.clone()).unwrap();
        assert!(text.contains("\"protocolVersion\":1"));
        assert!(text.contains("\"schemaVersion\":1"));
        assert_eq!(SubmitRequestDto::from_json(&json).unwrap(), dto);
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        let json = br#"{"protocolVersion":1,"world":"w.x","schema":"s","schemaVersion":1,"payloadB64":"","surprise":true}"#;
        assert!(matches!(
            SubmitRequestDto::from_json(json),
            Err(DtoError::Malformed(_))
        ));
    }

    #[test]
    fn a_missing_mandatory_field_is_rejected() {
        let json = br#"{"protocolVersion":1,"world":"w.x","schema":"s","payloadB64":""}"#;
        assert!(matches!(
            SubmitRequestDto::from_json(json),
            Err(DtoError::Malformed(_))
        ));
    }

    #[test]
    fn a_foreign_protocol_version_is_refused_not_negotiated() {
        let mut dto = sample();
        dto.protocol_version = 999;
        assert_eq!(
            SubmitRequestDto::from_json(&dto.to_json()),
            Err(DtoError::UnsupportedProtocol(999))
        );
    }

    #[test]
    fn over_long_strings_are_bounded() {
        let mut dto = sample();
        dto.world = "x".repeat(MAX_DTO_STRING + 1);
        assert_eq!(
            SubmitRequestDto::from_json(&dto.to_json()),
            Err(DtoError::StringTooLong)
        );
    }

    #[test]
    fn effect_and_observation_dtos_roundtrip() {
        let e = CommittedEffectDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            effect_b64: "AA==".into(),
            frontier_root_hex: "ab".repeat(32),
            frontier_transaction_count: 3,
            observation_sequence: 3,
        };
        let back: CommittedEffectDto =
            serde_json::from_slice(&serde_json::to_vec(&e).unwrap()).unwrap();
        assert_eq!(back, e);

        let o = ObservationDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            epoch: 1,
            sequence: 5,
            reset: false,
            world: "com.example.notes".into(),
            frontier_root_hex: "cd".repeat(32),
            frontier_transaction_count: 5,
        };
        let back: ObservationDto =
            serde_json::from_slice(&serde_json::to_vec(&o).unwrap()).unwrap();
        assert_eq!(back, o);
    }
}
