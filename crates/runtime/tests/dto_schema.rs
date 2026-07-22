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
    QueryRequestDto, SignedSubmitDto, SubmitRequestDto, DTO_PROTOCOL_VERSION,
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
    assert_eq!(defs.len(), 8);
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

#[test]
fn identifier_patterns_agree_with_the_rust_parsers() {
    // Each language-neutral identifier pattern must accept exactly what the
    // authoritative Rust parser accepts, over positive and negative samples
    // covering length, alphabet, prefix, and case edges.
    let ids = runtime::dto::identifier_schemas();
    let pattern = |name: &str| {
        let p = ids[name]["pattern"].as_str().expect("pattern string");
        regex::Regex::new(p).expect("valid regex")
    };

    let space = pattern("SpaceId");
    for (s, ok) in [
        ("ws_00000000000000000000000000", true),
        ("ws_0123456789abcdefghijkmnpqv", true),
        ("ws_short", false),
        ("act_00000000000000000000000000", false),
        ("ws_0000000000000000000000000!", false),
    ] {
        assert_eq!(space.is_match(s), ok, "SpaceId pattern on {s}");
        assert_eq!(
            mechanics::ids::SpaceId::parse(s).is_some(),
            ok,
            "SpaceId parser on {s}"
        );
    }

    let actor = pattern("ActorId");
    for (s, ok) in [
        (format!("act_{}", "a".repeat(64)), true),
        (format!("act_{}", "a".repeat(63)), false),
        ("a".repeat(68), false),
    ] {
        assert_eq!(actor.is_match(&s), ok, "ActorId pattern on {s}");
        assert_eq!(
            mechanics::ids::ActorId::parse(&s).is_some(),
            ok,
            "ActorId parser on {s}"
        );
    }
    // The canonical wire form is lowercase; the Rust parser additionally
    // tolerates uppercase hex input and normalizes it. The pattern pins the
    // canonical form only.
    let shouting = format!("act_{}", "A".repeat(64));
    assert!(!actor.is_match(&shouting));
    assert!(mechanics::ids::ActorId::parse(&shouting).is_some());

    let device = pattern("DeviceId");
    for (s, ok) in [
        ("a".repeat(64), true),
        ("g".repeat(64), false),
        ("a".repeat(63), false),
    ] {
        assert_eq!(device.is_match(&s), ok, "DeviceId pattern on {s}");
        assert_eq!(
            mechanics::ids::DeviceId::parse(&s).is_some(),
            ok,
            "DeviceId parser on {s}"
        );
    }

    let world = pattern("WorldId");
    for (s, ok) in [
        ("com.example.notes", true),
        ("a.b", true),
        ("single", false),
        ("Upper.case", false),
        ("-bad.label", false),
        ("bad-.label", false),
    ] {
        assert_eq!(world.is_match(s), ok, "WorldId pattern on {s}");
        assert_eq!(
            replica::ids::WorldId::parse(s).is_some(),
            ok,
            "WorldId parser on {s}"
        );
    }

    let schema = pattern("SchemaId");
    for (s, ok) in [
        ("note", true),
        ("issues.catalog-v", true),
        ("_leading", false),
        ("", false),
        (&"a".repeat(64), false),
    ] {
        assert_eq!(schema.is_match(s), ok, "SchemaId pattern on {s}");
        assert_eq!(
            replica::ids::SchemaId::parse(s).is_some(),
            ok,
            "SchemaId parser on {s}"
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
    roundtrip!(signed_submit_example(), SignedSubmitDto);
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

fn signed_submit_example() -> SignedSubmitDto {
    SignedSubmitDto {
        protocol_version: DTO_PROTOCOL_VERSION,
        space_id: "ws_00000000000000000000000000".into(),
        world: "com.example.notes".into(),
        actor_id: format!("act_{}", "a".repeat(64)),
        device_hex: "b".repeat(64),
        request_id_hex: "0a".repeat(16),
        signed_action_b64: "c2lnbmVk".into(), // "signed"
    }
}

#[test]
fn a_signed_submit_dto_validates_every_spelled_coordinate() {
    // bad space id
    let mut bad = signed_submit_example();
    bad.space_id = "ws_short".into();
    assert_eq!(
        SignedSubmitDto::from_json(&bad.to_json()),
        Err(DtoError::BadIdentifier)
    );
    // bad actor id
    let mut bad = signed_submit_example();
    bad.actor_id = "act_nothex".into();
    assert_eq!(
        SignedSubmitDto::from_json(&bad.to_json()),
        Err(DtoError::BadIdentifier)
    );
    // bad device key
    let mut bad = signed_submit_example();
    bad.device_hex = "z".repeat(64);
    assert_eq!(
        SignedSubmitDto::from_json(&bad.to_json()),
        Err(DtoError::BadIdentifier)
    );
    // oversize decoded signed action
    let mut bad = signed_submit_example();
    bad.signed_action_b64 =
        data_encoding::BASE64.encode(&vec![0u8; runtime::dto::MAX_DTO_PAYLOAD + 1]);
    assert_eq!(
        SignedSubmitDto::from_json(&bad.to_json()),
        Err(DtoError::PayloadTooLarge)
    );
    // unknown field
    assert!(matches!(
        SignedSubmitDto::from_json(br#"{"protocolVersion":1,"surprise":true}"#),
        Err(DtoError::Malformed(_))
    ));
}

/// The committed canonical-example corpus: every positive example named by its
/// `$defs` entry, plus negatives with their rejection reason. A neutral
/// (non-Rust) JSON Schema validator replays this corpus against the committed
/// schema in CI (`ci/validate-dto-schema.py`); reasons only Rust-side
/// validation can see (decoded lengths, protocol pinning) are marked
/// `schemaExpressible: false` and skipped there.
fn canonical_examples() -> serde_json::Value {
    let positive = |def: &str, json: Vec<u8>| {
        serde_json::json!({
            "def": def,
            "value": serde_json::from_slice::<serde_json::Value>(&json).unwrap(),
        })
    };
    let positives = vec![
        positive("SubmitRequestDto", submit_example().to_json()),
        positive("SignedSubmitDto", signed_submit_example().to_json()),
        positive(
            "ErrorDto",
            ErrorDto {
                protocol_version: DTO_PROTOCOL_VERSION,
                code: "denied".into(),
                message: "the demand was not satisfied at the pinned frontier".into(),
            }
            .to_json(),
        ),
    ];
    let negatives = serde_json::json!([
        {
            "def": "SubmitRequestDto",
            "reason": "unknown field",
            "schemaExpressible": true,
            "value": {"protocolVersion": 1, "world": "w.x", "schema": "s", "schemaVersion": 1,
                       "requestIdHex": "00000000000000000000000000000000", "payloadB64": "", "surprise": true},
        },
        {
            "def": "SubmitRequestDto",
            "reason": "missing required fields",
            "schemaExpressible": true,
            "value": {"protocolVersion": 1, "world": "w.x"},
        },
        {
            "def": "SignedSubmitDto",
            "reason": "space id fails its grammar (Rust parser; schema patterns live under `identifiers`)",
            "schemaExpressible": false,
            "value": {"protocolVersion": 1, "spaceId": "ws_short", "world": "com.example.notes",
                       "actorId": format!("act_{}", "a".repeat(64)), "deviceHex": "b".repeat(64),
                       "requestIdHex": "0a".repeat(16), "signedActionB64": ""},
        },
        {
            "def": "SubmitRequestDto",
            "reason": "request id decodes to 17 bytes, not 16 (decoded length is Rust-side)",
            "schemaExpressible": false,
            "value": {"protocolVersion": 1, "world": "w.x", "schema": "s", "schemaVersion": 1,
                       "requestIdHex": "0a".repeat(17), "payloadB64": ""},
        },
    ]);
    serde_json::json!({ "positive": positives, "negative": negatives })
}

#[test]
fn the_committed_examples_match_the_rust_corpus() {
    let generated = serde_json::to_string_pretty(&canonical_examples()).unwrap();
    let path = schema_path().with_file_name("dto.examples.json");
    if std::env::var("LAIT_BLESS_SCHEMA").is_ok() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path)
        .expect("schema/dto.examples.json is committed; run with LAIT_BLESS_SCHEMA=1 to create");
    let committed: serde_json::Value = serde_json::from_str(&committed).unwrap();
    let generated: serde_json::Value = serde_json::from_str(&generated).unwrap();
    assert_eq!(
        committed, generated,
        "the committed example corpus drifted from the Rust contract"
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
