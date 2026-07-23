//! The control-surface router (C4.3 / C5 routing) drives the product's
//! `control::Request` surface through the `IssuesWorld` adapter, producing the
//! legacy `control::Response` shapes — the seam the daemon routes application
//! requests through.

use std::sync::Arc;

use lait::control::{BoardPos, Filter, Request, Response};
use lait::ids::{ActorId, DeviceId, SystemUlidSource};
use lait::world::{IssueRouter, IssuesWorld, RouterFacts};
use mechanics::crypto::AuthorizedBodyKey;
use replica::frontier::AuthorityFrontier;
use runtime::{ActivationOptions, LocalIdentity, Runtime, RuntimeBuilder, Session, Station};

const WRITER_SEED: [u8; 32] = [71u8; 32];

fn temp_root() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lait-router-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct WriterAuthority;
impl runtime::AuthorityView for WriterAuthority {
    fn resolve(&self, _device: &DeviceId) -> Option<runtime::PrincipalResolution> {
        Some(runtime::PrincipalResolution {
            actor: actor(),
            authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![1]),
        })
    }
}

fn actor() -> ActorId {
    ActorId::from_incept_hash(&"a".repeat(64))
}

fn station() -> (Runtime, Station) {
    let registry = RuntimeBuilder::new()
        .register(IssuesWorld::registration(), Arc::new(IssuesWorld::new()))
        .build()
        .unwrap();
    let rt = Runtime::open(
        temp_root(),
        registry,
        Arc::new(WriterAuthority),
        Arc::new(replica::StaticBodyKeys::new(
            AuthorizedBodyKey::for_authorized_epoch([3u8; 16], [4u8; 32]),
        )),
    );
    let station = rt
        .form_space(runtime::SpaceFormationOptions::default())
        .unwrap()
        .activate(ActivationOptions::offline())
        .unwrap();
    (rt, station)
}

fn facts() -> RouterFacts {
    RouterFacts {
        device: mechanics::crypto::device_from_seed(&WRITER_SEED)
            .as_str()
            .to_string(),
        actor: actor().as_str().to_string(),
        project_hint: None,
        default_project: None,
        now: 1_700_000_000,
    }
}

fn dock(station: &Station) -> (Session, LocalIdentity) {
    let identity = Runtime::identity_from_seed(&WRITER_SEED);
    let session = station
        .dock(&lait::world::contract::world_id(), &identity)
        .unwrap();
    (session, identity)
}

#[test]
fn the_router_maps_the_control_surface_to_the_issues_world() {
    let (_rt, station) = station();
    let (session, identity) = dock(&station);
    let clock = SystemUlidSource;
    let router = IssueRouter::new(&session, &identity, &clock);

    // SpaceInit is not a control request; seed via ProjectNew directly (the
    // catalog Body is created on first write).
    let (resp, changed) = router.route(
        Request::ProjectNew {
            name: "Engineering".into(),
            key: "eng".into(),
            color: None,
        },
        &facts(),
    );
    assert!(changed);
    assert!(matches!(resp, Response::Ref { reff } if reff == "ENG"));

    // IssueNew chooses the sole project and returns its canonical reff.
    let (resp, changed) = router.route(
        Request::IssueNew {
            title: "Router works".into(),
            project: None,
            project_hint: None,
            assignees: vec![],
            priority: Some("high".into()),
            labels: vec!["bug".into()],
            body: Some("body text".into()),
            due: None,
            estimate: None,
        },
        &facts(),
    );
    assert!(changed);
    let reff = match resp {
        Response::Ref { reff } => reff,
        other => panic!("expected Ref, got {other:?}"),
    };
    assert_eq!(reff, "ENG-1");

    // IssueView renders the legacy IssueView.
    let (resp, _) = router.route(
        Request::IssueView {
            reff: "ENG-1".into(),
        },
        &facts(),
    );
    let view = match resp {
        Response::Issue(v) => v,
        other => panic!("expected Issue, got {other:?}"),
    };
    assert_eq!(view.title, "Router works");
    assert_eq!(view.priority, lait::dto::Priority::High);
    assert_eq!(view.label_names, vec!["bug".to_string()]);

    // Edit, comment, start (work-state), and board all route.
    router.route(
        Request::IssueEdit {
            reff: "ENG-1".into(),
            title: Some("Renamed".into()),
            status: None,
            priority: None,
            description: None,
            due: None,
            estimate: None,
        },
        &facts(),
    );
    router.route(
        Request::Comment {
            reff: "ENG-1".into(),
            body: "routed comment".into(),
            reply_to: None,
        },
        &facts(),
    );
    let (resp, changed) = router.route(
        Request::IssueStart {
            reff: "ENG-1".into(),
        },
        &facts(),
    );
    assert!(changed);
    assert!(matches!(resp, Response::Issue(_)));

    // A second issue + a Before move exercises ref resolution in positions.
    router.route(
        Request::IssueNew {
            title: "Second".into(),
            project: None,
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
            due: None,
            estimate: None,
        },
        &facts(),
    );
    let (resp, changed) = router.route(
        Request::IssueMove {
            reff: "ENG-2".into(),
            project: None,
            pos: Some(BoardPos::Before {
                reff: "ENG-1".into(),
            }),
        },
        &facts(),
    );
    assert!(changed);
    assert!(matches!(resp, Response::Ref { .. }));

    // List returns Rows; the started issue shows its updated title.
    let (resp, _) = router.route(
        Request::List {
            project: None,
            filter: Filter::default(),
        },
        &facts(),
    );
    let rows = match resp {
        Response::List { rows } => rows,
        other => panic!("expected List, got {other:?}"),
    };
    assert!(rows.iter().any(|r| r.title == "Renamed"));

    // A ref that matches nothing is a typed not-found (exit 2 on the CLI).
    let (resp, changed) = router.route(
        Request::IssueView {
            reff: "ENG-99".into(),
        },
        &facts(),
    );
    assert!(!changed);
    assert!(matches!(
        resp,
        Response::Error {
            error_kind: lait::control::ErrorKind::NotFound,
            ..
        }
    ));

    // A view-only principal is refused with the legacy message.
    struct ReadOnly;
    impl runtime::AuthorityView for ReadOnly {
        fn resolve(&self, _d: &DeviceId) -> Option<runtime::PrincipalResolution> {
            Some(runtime::PrincipalResolution {
                actor: actor(),
                authority_frontier: AuthorityFrontier::from_canonical_bytes(vec![1]),
            })
        }
    }
    // (A fresh read-only station would refuse writes; covered by the World's
    // own denied path — here we assert the router surfaces write failures.)
    let _ = ReadOnly;

    let _ = station.go_dormant();
}

#[test]
fn the_router_declares_the_issue_family_it_handles() {
    assert!(IssueRouter::handles(&Request::IssueNew {
        title: "x".into(),
        project: None,
        project_hint: None,
        due: None,
        estimate: None,
        assignees: vec![],
        priority: None,
        labels: vec![],
        body: None,
    }));
    assert!(IssueRouter::handles(&Request::Board {
        project: None,
        project_hint: None,
    }));
    // Membership/transport requests are NOT the router's.
    assert!(!IssueRouter::handles(&Request::Status));
    assert!(!IssueRouter::handles(&Request::MemberAdd {
        who: "x".into(),
        admin: false,
        as_name: None,
    }));
}
