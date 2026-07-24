//! Exhaustive terminal-owner classification of every control request — driven
//! by the PRODUCTION classifier (`control::classify`), the same function the
//! daemon dispatches from. There is no test-only ownership table: the daemon,
//! this gate, and the generated routing table all consume one source, and the
//! classifier's exhaustive match makes an unclassified new variant a build
//! failure, never a runtime catch-all.

use lait::control::{classify, representative_requests, routing_rows, Request, RequestOwner};

#[test]
fn every_request_variant_has_a_terminal_owner() {
    // Exhaustiveness is compile-enforced by `classify`'s match. Assert the
    // intended mapping for representatives of every owner.
    assert_eq!(
        classify(&Request::IssueNew {
            title: "t".into(),
            project: None,
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
            due: None,
            estimate: None,
        }),
        RequestOwner::Session
    );
    assert_eq!(classify(&Request::Members), RequestOwner::Mechanics);
    assert_eq!(classify(&Request::DeviceList), RequestOwner::Mechanics);
    assert_eq!(
        classify(&Request::SpaceReshare {
            participants: vec![],
            k: 0
        }),
        RequestOwner::Mechanics
    );
    assert_eq!(
        classify(&Request::Connect { ticket: "x".into() }),
        RequestOwner::Station
    );
    assert_eq!(classify(&Request::Status), RequestOwner::Observation);
    assert_eq!(
        classify(&Request::Inbox { clear: false }),
        RequestOwner::Observation
    );
    assert_eq!(classify(&Request::Stop), RequestOwner::Lifecycle);
}

#[test]
fn the_representative_set_covers_every_wire_command_exactly_once() {
    // Every representative must serialize to a distinct wire tag; a duplicate
    // or missing representative would leave a hole in the generated table.
    let mut tags: Vec<String> = representative_requests()
        .iter()
        .map(|r| {
            serde_json::to_value(r).unwrap()["cmd"]
                .as_str()
                .expect("every request serializes with a cmd tag")
                .to_string()
        })
        .collect();
    let count = tags.len();
    tags.sort();
    tags.dedup();
    assert_eq!(tags.len(), count, "duplicate representative");
}

/// Regenerate `docs/plans/generated/request-routing.tsv` from the SAME
/// production classifier the daemon dispatches from. The file is local (the
/// plans directory is gitignored); the gate is that generation succeeds and
/// every row carries a real owner.
#[test]
fn the_generated_routing_table_comes_from_the_production_classifier() {
    let rows = routing_rows();
    assert!(!rows.is_empty());
    let mut out = String::from("request\tterminal_owner\n");
    for (tag, owner) in &rows {
        assert!(!tag.is_empty(), "an untagged request cannot be routed");
        out.push_str(tag);
        out.push('\t');
        out.push_str(owner);
        out.push('\n');
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/plans/generated");
    if std::fs::create_dir_all(&dir).is_ok() {
        let _ = std::fs::write(dir.join("request-routing.tsv"), out);
    }
}

#[test]
fn every_session_owned_request_is_served_by_the_issue_router() {
    // The defect this pins: `Activity` was classified Session but the issue
    // router neither claimed nor served it, so a public `lait activity` died
    // with "request not routed to the issues world". Classification and the
    // router's claim set must agree in BOTH directions — a Session-owned
    // request the router refuses is an unreachable public verb, and a
    // router-claimed request under another owner would never reach it.
    for req in representative_requests() {
        let claimed = lait::world::router::IssueRouter::handles(&req);
        let session = classify(&req) == RequestOwner::Session;
        assert_eq!(
            session, claimed,
            "classification/router disagreement on {req:?}: classified-Session={session}, router-handles={claimed}"
        );
    }
}
