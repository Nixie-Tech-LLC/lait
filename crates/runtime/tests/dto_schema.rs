//! C6.1 / G9 — the committed JSON Schema 2020-12 and canonical examples.
//!
//! `crates/runtime/schema/dto.schema.json` is generated from the Rust DTO
//! contract; this gate regenerates it and fails on drift (run with
//! `LAIT_BLESS_SCHEMA=1` to intentionally re-commit after a contract change).
//! The canonical positive examples must decode through the Rust contract and
//! re-encode byte-identically; the negative examples must be rejected, each
//! for its stated reason.

use runtime::dto::{
    CommittedEffectDto, DtoError, ErrorDto, ObservationCursorDto, ObservationDto, ProjectionDto,
    QueryRequestDto, SubmitRequestDto, DTO_PROTOCOL_VERSION,
};

fn schema_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("schema")
        .join("dto.schema.json")
}

#[test]
fn the_committed_schema_matches_the_rust_contract() {
    let generated = serde_json::to_string_pretty(&runtime::dto::schema_bundle()).unwrap();
    let path = schema_path();
    if std::env::var("LAIT_BLESS_SCHEMA").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("schema/dto.schema.json is committed; run with LAIT_BLESS_SCHEMA=1 to create");
    // Compare as JSON values (line endings and key order normalized).
    let committed: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let generated: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert_eq!(
        committed, generated,
        "the committed DTO schema drifted from the Rust contract"
    );
}

#[test]
fn the_schema_declares_draft_2020_12_and_strict_objects() {
    let bundle = runtime::dto::schema_bundle();
    assert_eq!(
        bundle["$schema"],
        "https://json-schema.org/draft/2020-12/schema"
    );
    // Every DTO definition rejects unknown fields and lists required members —
    // the language-neutral mirror of deny_unknown_fields.
    let defs = bundle["$defs"].as_object().unwrap();
    assert_eq!(defs.len(), 7);
    for (name, def) in defs {
        assert_eq!(
            def["additionalProperties"],
            serde_json::Value::Bool(false),
            "{name} must reject unknown fields"
        );
        assert!(
            def["required"]
                .as_array()
                .is_some_and(|r| r.iter().any(|f| f == "protocolVersion")),
            "{name} must require protocolVersion"
        );
    }
}

fn submit_example() -> SubmitRequestDto {
    SubmitRequestDto {
        protocol_version: DTO_PROTOCOL_VERSION,
        world: "com.example.notes".into(),
        schema: "note".into(),
        schema_version: 1,
        request_id_hex: "0a".repeat(16),
        payload_b64: "aGVsbG8=".into(),
    }
}

#[test]
fn canonical_positive_examples_roundtrip_bidirectionally() {
    // Rust → JSON → Rust → JSON, byte-identical both directions.
    macro_rules! roundtrip {
        ($value:expr, $ty:ty) => {{
            let v = $value;
            let json = v.to_json();
            let back = <$ty>::from_json(&json).unwrap();
            assert_eq!(back, v);
            assert_eq!(back.to_json(), json, "canonical re-encode");
        }};
    }
    roundtrip!(submit_example(), SubmitRequestDto);
    roundtrip!(
        QueryRequestDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            world: "com.example.notes".into(),
            schema: "note".into(),
            schema_version: 1,
            payload_b64: "AA==".into(),
        },
        QueryRequestDto
    );
    roundtrip!(
        CommittedEffectDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            effect_b64: "AA==".into(),
            frontier_root_hex: "ab".repeat(32),
            frontier_transaction_count: 3,
            scope_body_ids_hex: vec!["0b".repeat(16)],
        },
        CommittedEffectDto
    );
    roundtrip!(
        ProjectionDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            schema: "note".into(),
            schema_version: 1,
            bytes_b64: "aGVsbG8=".into(),
            frontier_root_hex: "cd".repeat(32),
            frontier_transaction_count: 9,
        },
        ProjectionDto
    );
    roundtrip!(
        ObservationCursorDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            epoch: 4,
            sequence: 42,
        },
        ObservationCursorDto
    );
    roundtrip!(
        ObservationDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            epoch: 4,
            sequence: 43,
            reset: false,
            world: "com.example.notes".into(),
            scope_body_ids_hex: vec!["0c".repeat(16)],
            frontier_root_hex: "ef".repeat(32),
            frontier_transaction_count: 10,
        },
        ObservationDto
    );
    roundtrip!(
        ErrorDto {
            protocol_version: DTO_PROTOCOL_VERSION,
            code: "request-id-conflict".into(),
            message: "the request id was reused with a different payload".into(),
        },
        ErrorDto
    );
}

#[test]
fn canonical_negative_examples_are_each_rejected_for_their_stated_reason() {
    // unknown mandatory field
    assert!(matches!(
        SubmitRequestDto::from_json(
            br#"{"protocolVersion":1,"world":"w.x","schema":"s","schemaVersion":1,"requestIdHex":"00000000000000000000000000000000","payloadB64":"","extra":1}"#
        ),
        Err(DtoError::Malformed(_))
    ));
    // missing mandatory field
    assert!(matches!(
        SubmitRequestDto::from_json(br#"{"protocolVersion":1,"world":"w.x"}"#),
        Err(DtoError::Malformed(_))
    ));
    // invalid identifier
    let mut bad = submit_example();
    bad.world = "Not An Id".into();
    assert_eq!(
        SubmitRequestDto::from_json(&bad.to_json()),
        Err(DtoError::BadIdentifier)
    );
    // malformed base64
    let mut bad = submit_example();
    bad.payload_b64 = "%%%".into();
    assert_eq!(
        SubmitRequestDto::from_json(&bad.to_json()),
        Err(DtoError::BadBase64)
    );
    // excessive DECODED payload
    let mut bad = submit_example();
    bad.payload_b64 = data_encoding::BASE64.encode(&vec![0u8; runtime::dto::MAX_DTO_PAYLOAD + 1]);
    assert_eq!(
        SubmitRequestDto::from_json(&bad.to_json()),
        Err(DtoError::PayloadTooLarge)
    );
    // wrong decoded hex length
    let mut bad = submit_example();
    bad.request_id_hex = "0a".repeat(17);
    assert_eq!(
        SubmitRequestDto::from_json(&bad.to_json()),
        Err(DtoError::BadHex)
    );
    // unsupported protocol version
    let mut bad = submit_example();
    bad.protocol_version = 2;
    assert_eq!(
        SubmitRequestDto::from_json(&bad.to_json()),
        Err(DtoError::UnsupportedProtocol(2))
    );
    // numeric overflow: a schemaVersion beyond u32 is malformed JSON-side
    assert!(matches!(
        SubmitRequestDto::from_json(
            br#"{"protocolVersion":1,"world":"w.x","schema":"s","schemaVersion":4294967296,"requestIdHex":"00000000000000000000000000000000","payloadB64":""}"#
        ),
        Err(DtoError::Malformed(_))
    ));
}
