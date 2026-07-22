//! S1a golden fixtures freezing the collaborative operation algebra's canonical
//! postcard encoding. Positive vectors pin each variant's tag and layout;
//! negative vectors prove out-of-range tags and trailing bytes are rejected.

use replica::body::BodyOp;

/// postcard encodes an enum as `varint(variant_index) || fields...`.
#[test]
fn body_op_variant_tags_are_frozen() {
    // Nullary variants encode as a single tag byte.
    assert_eq!(postcard::to_stdvec(&BodyOp::Create).unwrap(), vec![12]);
    assert_eq!(postcard::to_stdvec(&BodyOp::Tombstone).unwrap(), vec![13]);

    // ReplaceAtomic is tag 0, then a length-prefixed byte vector.
    assert_eq!(
        postcard::to_stdvec(&BodyOp::ReplaceAtomic { value: vec![0xAB] }).unwrap(),
        vec![0, 1, 0xAB]
    );

    // CounterAdd is tag 11, then a zigzag varint delta (-1 -> 0x01).
    assert_eq!(
        postcard::to_stdvec(&BodyOp::CounterAdd {
            path: String::new(),
            delta: -1
        })
        .unwrap(),
        vec![11, 0, 0x01]
    );
}

#[test]
fn every_variant_roundtrips() {
    let ops = vec![
        BodyOp::ReplaceAtomic { value: vec![1, 2] },
        BodyOp::RegisterSet {
            path: "title".into(),
            value: vec![9],
        },
        BodyOp::RegisterClear {
            path: "title".into(),
        },
        BodyOp::MapSet {
            path: "labels".into(),
            key: "bug".into(),
            value: vec![],
        },
        BodyOp::MapRemove {
            path: "labels".into(),
            key: "bug".into(),
        },
        BodyOp::ListInsert {
            path: "items".into(),
            index: 0,
            value: vec![7],
        },
        BodyOp::ListRemove {
            path: "items".into(),
            element: "e_1".into(),
        },
        BodyOp::ListMove {
            path: "items".into(),
            element: "e_1".into(),
            index: 3,
        },
        BodyOp::TextSplice {
            path: "body".into(),
            index: 2,
            delete: 1,
            insert: "x".into(),
        },
        BodyOp::SetAdd {
            path: "tags".into(),
            value: vec![1],
        },
        BodyOp::SetRemove {
            path: "tags".into(),
            value: vec![1],
        },
        BodyOp::CounterAdd {
            path: "votes".into(),
            delta: 5,
        },
        BodyOp::Create,
        BodyOp::Tombstone,
    ];
    for op in ops {
        let bytes = postcard::to_stdvec(&op).unwrap();
        let back: BodyOp = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(op, back, "roundtrip for {op:?}");
    }
}

#[test]
fn unknown_variant_tag_is_rejected() {
    // Tag 99 is out of range for the frozen 14-variant algebra.
    let bytes = vec![99u8];
    assert!(postcard::from_bytes::<BodyOp>(&bytes).is_err());
}

#[test]
fn trailing_bytes_break_canonical_reencoding() {
    // `postcard::from_bytes` tolerates trailing bytes, so canonicality is proven
    // the way the envelope decoders do it: decode, then require re-encode to be
    // byte-exact. A trailing byte fails that check.
    let mut bytes = postcard::to_stdvec(&BodyOp::Create).unwrap();
    bytes.push(0xFF);
    let decoded: BodyOp = postcard::from_bytes(&bytes).unwrap();
    assert_ne!(
        postcard::to_stdvec(&decoded).unwrap(),
        bytes,
        "re-encode is shorter than the trailing-padded input"
    );
}
