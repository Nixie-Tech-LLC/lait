//! The product adopts the orbital lifecycle: form a Space, host the Issues
//! World, dock a Session, and drive create/edit/comment/query durably — through
//! the public `runtime` API, from the root application. This is the evidence
//! that the root `lait` crate depends on and exercises the new crates.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use lait::orbital::{open_orbital_runtime, IssueCommand, IssueQuery, IssueState, ISSUE_SCHEMA};
use lait_kernel::acl::Grant;
use lait_kernel::ids::{ActorId, DeviceId, StationId};
use runtime::{
    ActivationOptions, PrincipalFacts, SpaceFormationOptions, Standing, WorldIntent, WorldQuery,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-orbital-adopt-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn principal() -> PrincipalFacts {
    PrincipalFacts {
        actor: ActorId::from_incept_hash(&"a".repeat(64)),
        device: DeviceId::from_key_bytes(&[3u8; 32]),
        station: StationId::from_key_bytes([3u8; 32]),
        standing: Standing::new(vec![Grant::Write]),
        authority_frontier: ::replica::frontier::AuthorityFrontier::from_canonical_bytes(vec![1]),
    }
}

fn schema() -> ::replica::ids::SchemaId {
    ::replica::ids::SchemaId::parse(ISSUE_SCHEMA).unwrap()
}

fn intent(cmd: &IssueCommand) -> WorldIntent {
    WorldIntent {
        schema: schema(),
        schema_version: 1,
        payload: serde_json::to_vec(cmd).unwrap(),
    }
}

#[test]
fn the_product_hosts_issues_over_the_orbital_lifecycle() {
    let home = temp_home();
    let rt = open_orbital_runtime(home);
    let world = ::replica::ids::WorldId::parse(lait::orbital::ISSUES_WORLD_ID).unwrap();

    let orbit = rt.form_space(SpaceFormationOptions::default()).unwrap();
    let space = orbit.space_id().clone();
    let station = orbit.activate(ActivationOptions::default()).unwrap();
    let session = station.dock(&world, principal()).unwrap();

    // Create an issue.
    session
        .submit(intent(&IssueCommand::Create {
            id: "iss-1".into(),
            title: "first bug".into(),
            body: "it broke".into(),
        }))
        .unwrap();

    // Edit its title (read-modify-write against the committed snapshot).
    session
        .submit(intent(&IssueCommand::Edit {
            id: "iss-1".into(),
            title: Some("first bug (triaged)".into()),
            body: None,
        }))
        .unwrap();

    // Comment on it.
    let committed = session
        .submit(intent(&IssueCommand::Comment {
            id: "iss-1".into(),
            text: "looking into it".into(),
        }))
        .unwrap();
    assert_eq!(committed.observation.sequence, 3);

    // Query the current state.
    let get = |id: &str| -> IssueState {
        let proj = session
            .query(WorldQuery {
                schema: schema(),
                schema_version: 1,
                payload: serde_json::to_vec(&IssueQuery::Get { id: id.into() }).unwrap(),
            })
            .unwrap();
        serde_json::from_slice(&proj.bytes).unwrap()
    };
    let issue = get("iss-1");
    assert_eq!(issue.title, "first bug (triaged)");
    assert_eq!(issue.body, "it broke");
    assert_eq!(issue.comments, vec!["looking into it".to_string()]);

    // Durability: go dormant, reactivate, the issue is still there.
    let orbit = station.go_dormant().unwrap();
    drop(orbit);
    let station = rt
        .orbit(&space)
        .unwrap()
        .activate(ActivationOptions::default())
        .unwrap();
    let session = station.dock(&world, principal()).unwrap();
    let issue = {
        let proj = session
            .query(WorldQuery {
                schema: schema(),
                schema_version: 1,
                payload: serde_json::to_vec(&IssueQuery::Get { id: "iss-1".into() }).unwrap(),
            })
            .unwrap();
        serde_json::from_slice::<IssueState>(&proj.bytes).unwrap()
    };
    assert_eq!(issue.title, "first bug (triaged)");
    assert_eq!(issue.comments.len(), 1);
}
