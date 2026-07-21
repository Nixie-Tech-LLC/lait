//! Convergence fixtures for the collaborative algebra over the Loro engine:
//! two replicas fork from a common ancestor, edit concurrently, cross-merge,
//! and must converge to the same view with the declared semantics — add-wins
//! sets, summed counters, no lost list inserts, preserved concurrent text, and
//! an agreed LWW register winner.

use lait_fabric::{Fabric, FabricKey, FabricOp, FabricTransactionRequest, LoroFabric};

fn key() -> FabricKey {
    FabricKey::from_bytes(b"body/collab".to_vec())
}

fn req(ops: Vec<FabricOp>) -> FabricTransactionRequest {
    FabricTransactionRequest::new("test", ops)
}

/// A common ancestor with every path initialized (the documented discipline:
/// paths are created in the Body's creating transaction, before concurrent
/// editing), then forked into two engines.
fn forked_pair() -> (LoroFabric, LoroFabric) {
    let mut a = LoroFabric::new();
    a.commit(req(vec![
        FabricOp::CreateBody { key: key() },
        FabricOp::RegisterSet {
            key: key(),
            path: "title".into(),
            value: b"base".to_vec(),
        },
        FabricOp::MapSet {
            key: key(),
            path: "fields".into(),
            entry: "seed".into(),
            value: b"1".to_vec(),
        },
        FabricOp::ListInsert {
            key: key(),
            path: "items".into(),
            index: 0,
            value: b"first".to_vec(),
        },
        FabricOp::ListInsert {
            key: key(),
            path: "items".into(),
            index: 1,
            value: b"second".to_vec(),
        },
        FabricOp::TextSplice {
            key: key(),
            path: "notes".into(),
            index: 0,
            delete: 0,
            insert: "hello".into(),
        },
        FabricOp::SetAdd {
            key: key(),
            path: "tags".into(),
            value: b"keep".to_vec(),
        },
        FabricOp::CounterAdd {
            key: key(),
            path: "votes".into(),
            delta: 1,
        },
    ]))
    .unwrap();
    let snap = Fabric::snapshot(&a).unwrap();
    let b = LoroFabric::from_snapshot(&snap).unwrap();
    (a, b)
}

/// Cross-merge both engines and assert their views are identical.
fn converge(a: &mut LoroFabric, b: &mut LoroFabric) -> lait_fabric::CollaborativeView {
    let sa = Fabric::snapshot(a).unwrap();
    let sb = Fabric::snapshot(b).unwrap();
    a.merge(&sb).unwrap();
    b.merge(&sa).unwrap();
    let va = a.read_collaborative(&key()).unwrap();
    let vb = b.read_collaborative(&key()).unwrap();
    assert_eq!(va, vb, "both replicas converge to the same view");
    va
}

#[test]
fn concurrent_counter_increments_sum() {
    let (mut a, mut b) = forked_pair();
    a.commit(req(vec![FabricOp::CounterAdd {
        key: key(),
        path: "votes".into(),
        delta: 5,
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::CounterAdd {
        key: key(),
        path: "votes".into(),
        delta: 3,
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    // 1 (ancestor) + 5 + 3: concurrent increments never overwrite each other.
    assert_eq!(v.counters["votes"], 9);
}

#[test]
fn a_concurrent_add_survives_a_remove_add_wins() {
    let (mut a, mut b) = forked_pair();
    // A removes the common member while B concurrently re-adds it.
    a.commit(req(vec![FabricOp::SetRemove {
        key: key(),
        path: "tags".into(),
        value: b"keep".to_vec(),
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::SetAdd {
        key: key(),
        path: "tags".into(),
        value: b"keep".to_vec(),
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    // Add wins: B's add minted a tag A's remove never observed.
    assert_eq!(v.sets["tags"], vec![b"keep".to_vec()]);
}

#[test]
fn no_list_insert_is_lost() {
    let (mut a, mut b) = forked_pair();
    a.commit(req(vec![FabricOp::ListInsert {
        key: key(),
        path: "items".into(),
        index: 2,
        value: b"from-a".to_vec(),
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::ListInsert {
        key: key(),
        path: "items".into(),
        index: 2,
        value: b"from-b".to_vec(),
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    let values: Vec<&[u8]> = v.lists["items"]
        .iter()
        .map(|e| e.value.as_slice())
        .collect();
    assert_eq!(values.len(), 4, "2 ancestor + both concurrent inserts");
    assert!(values.contains(&&b"from-a"[..]));
    assert!(values.contains(&&b"from-b"[..]));
    // Ancestor order is preserved.
    assert_eq!(values[0], b"first");
    assert_eq!(values[1], b"second");
}

#[test]
fn stable_element_identity_survives_sync() {
    let (mut a, mut b) = forked_pair();
    // B learns the element ids from its own view (forked from the ancestor).
    let vb = b.read_collaborative(&key()).unwrap();
    let second = vb.lists["items"][1].element.clone();
    // A concurrently inserts at the front — shifting every index — while B
    // removes "second" BY ID. The remove targets the right element regardless.
    a.commit(req(vec![FabricOp::ListInsert {
        key: key(),
        path: "items".into(),
        index: 0,
        value: b"shifter".to_vec(),
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::ListRemove {
        key: key(),
        path: "items".into(),
        element: second,
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    let values: Vec<&[u8]> = v.lists["items"]
        .iter()
        .map(|e| e.value.as_slice())
        .collect();
    assert_eq!(values.len(), 2);
    assert!(values.contains(&&b"shifter"[..]));
    assert!(values.contains(&&b"first"[..]));
    assert!(!values.contains(&&b"second"[..]), "removed by stable id");
}

#[test]
fn concurrent_text_splices_both_survive() {
    let (mut a, mut b) = forked_pair();
    // Ancestor text is "hello". A prepends, B appends.
    a.commit(req(vec![FabricOp::TextSplice {
        key: key(),
        path: "notes".into(),
        index: 0,
        delete: 0,
        insert: "A:".into(),
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::TextSplice {
        key: key(),
        path: "notes".into(),
        index: 5,
        delete: 0,
        insert: ":B".into(),
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    let text = &v.texts["notes"];
    assert!(text.contains("A:"), "A's edit survives: {text}");
    assert!(text.contains(":B"), "B's edit survives: {text}");
    assert!(text.contains("hello"), "ancestor text survives: {text}");
}

#[test]
fn concurrent_register_sets_agree_on_one_winner() {
    let (mut a, mut b) = forked_pair();
    a.commit(req(vec![FabricOp::RegisterSet {
        key: key(),
        path: "title".into(),
        value: b"from-a".to_vec(),
    }]))
    .unwrap();
    b.commit(req(vec![FabricOp::RegisterSet {
        key: key(),
        path: "title".into(),
        value: b"from-b".to_vec(),
    }]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    let winner = &v.registers["title"];
    assert!(
        winner == b"from-a" || winner == b"from-b",
        "one of the concurrent writes wins on both replicas"
    );
}

#[test]
fn concurrent_map_entries_merge_disjoint_and_lww_same_key() {
    let (mut a, mut b) = forked_pair();
    a.commit(req(vec![
        FabricOp::MapSet {
            key: key(),
            path: "fields".into(),
            entry: "only_a".into(),
            value: b"a".to_vec(),
        },
        FabricOp::MapSet {
            key: key(),
            path: "fields".into(),
            entry: "shared".into(),
            value: b"a".to_vec(),
        },
    ]))
    .unwrap();
    b.commit(req(vec![
        FabricOp::MapSet {
            key: key(),
            path: "fields".into(),
            entry: "only_b".into(),
            value: b"b".to_vec(),
        },
        FabricOp::MapSet {
            key: key(),
            path: "fields".into(),
            entry: "shared".into(),
            value: b"b".to_vec(),
        },
    ]))
    .unwrap();
    let v = converge(&mut a, &mut b);
    let fields = &v.maps["fields"];
    // Disjoint entries both survive; the contested one has a single winner.
    assert_eq!(fields["only_a"], b"a");
    assert_eq!(fields["only_b"], b"b");
    assert_eq!(fields["seed"], b"1");
    assert!(fields["shared"] == b"a" || fields["shared"] == b"b");
}
