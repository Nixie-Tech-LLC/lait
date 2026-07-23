//! `issues_policy_designer` — role/access/workflow authoring parity over the
//! REAL orbital daemon control surface (plan 50): built-in and custom roles,
//! revision heads and expected-revision refusal, tombstones, exact-expansion
//! assignment/revoke through Mechanics, deterministic workflow replacement,
//! and gate enforcement — a transition whose template grants no admin
//! override denies an admin until the matching role is assigned.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [111u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

struct MemFactory(MemNet);

#[async_trait]
impl TransportFactory for MemFactory {
    async fn build(
        &self,
        identity_seed: &[u8; 32],
        _network: &Network,
        _alpns: &[Alpn],
    ) -> Result<Arc<dyn Transport>> {
        Ok(Arc::new(
            self.0.peer(lait::crypto::device_from_seed(identity_seed)),
        ))
    }
}

fn temp_home() -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-policy-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn req(rt: &tokio::runtime::Runtime, home: &Path, r: Request) -> Response {
    rt.block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn text_of(resp: Response) -> serde_json::Value {
    match resp {
        Response::Text { text } => serde_json::from_str(&text).expect("json text"),
        other => panic!("expected Text, got {other:?}"),
    }
}

fn ok_msg(resp: &Response) -> &str {
    match resp {
        Response::Ok { message } => message.as_deref().unwrap_or(""),
        other => panic!("expected Ok, got {other:?}"),
    }
}

fn err_msg(resp: &Response) -> &str {
    match resp {
        Response::Error { message, .. } => message,
        other => panic!("expected Error, got {other:?}"),
    }
}

fn write_identity(home: &Path, seed: &[u8; 32]) {
    std::env::set_var("LAIT_HOME", home);
    std::fs::write(
        home.join("secret.key"),
        data_encoding::HEXLOWER.encode(seed),
    )
    .unwrap();
}

#[test]
fn role_access_and_workflow_authoring_round_trip_over_the_daemon() {
    let home = temp_home();
    let net = MemNet::new();
    std::fs::create_dir_all(&home).unwrap();
    write_identity(&home, &FOUNDER_SEED);
    lait::orbital::form_space(&home, &FOUNDER_SEED, "Policy Space").unwrap();

    let daemon_home = home.clone();
    let daemon_net = net.clone();
    let handle = std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = run_orbital_daemon(daemon_home, &MemFactory(daemon_net)).await {
                eprintln!("DAEMON ERR: {e:#}");
            }
        });
    });
    let rt = tokio::runtime::Runtime::new().unwrap();
    let online = {
        let start = Instant::now();
        loop {
            if matches!(req(&rt, &home, Request::Status), Response::Status(_)) {
                break true;
            }
            if start.elapsed() > Duration::from_secs(20) {
                break false;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    };
    assert!(online, "daemon online");

    // ---- built-ins are listed, immutable, and shown with revisions --------
    let roles = text_of(req(&rt, &home, Request::RoleList));
    let ids: Vec<&str> = roles
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["role_id"].as_str().unwrap())
        .collect();
    for built_in in ["lait.administrator", "lait.contributor", "lait.viewer"] {
        assert!(ids.contains(&built_in), "{built_in} listed");
    }
    let viewer = text_of(req(
        &rt,
        &home,
        Request::RoleShow {
            role: "lait.viewer".into(),
        },
    ));
    assert_eq!(viewer["built_in"], true);
    let resp = req(
        &rt,
        &home,
        Request::RoleEdit {
            role: "lait.viewer".into(),
            expect_revision: viewer["revision"]["revision_id"]
                .as_str()
                .unwrap()
                .to_string(),
            name: Some("Weakened".into()),
            description: None,
            capabilities: None,
        },
    );
    assert!(
        err_msg(&resp).contains("invalid"),
        "built-ins are immutable: {resp:?}"
    );

    // ---- custom role lifecycle: create → edit (exact head) → assign -------
    let project_key = match req(&rt, &home, Request::ProjectList) {
        Response::Projects { projects } => projects.first().unwrap().key.clone(),
        other => panic!("{other:?}"),
    };
    let created = req(
        &rt,
        &home,
        Request::RoleCreate {
            name: "Reviewer".into(),
            description: Some("Can pass reviews".into()),
            project: Some(project_key.clone()),
            capabilities: vec!["workflow.transition.ship".into()],
        },
    );
    let role_id = ok_msg(&created)
        .rsplit(' ')
        .next()
        .unwrap()
        .trim()
        .to_string();
    assert!(role_id.starts_with("role_"), "{role_id}");
    let shown = text_of(req(
        &rt,
        &home,
        Request::RoleShow {
            role: role_id.clone(),
        },
    ));
    let head = shown["revision"]["revision_id"]
        .as_str()
        .unwrap()
        .to_string();

    // A stale expected revision refuses; the exact head succeeds.
    let stale = req(
        &rt,
        &home,
        Request::RoleEdit {
            role: role_id.clone(),
            expect_revision: "ab".repeat(32),
            name: Some("Renamed".into()),
            description: None,
            capabilities: None,
        },
    );
    assert!(matches!(stale, Response::Error { .. }), "{stale:?}");
    let edited = req(
        &rt,
        &home,
        Request::RoleEdit {
            role: role_id.clone(),
            expect_revision: head.clone(),
            name: Some("Reviewer+".into()),
            description: None,
            capabilities: None,
        },
    );
    assert!(matches!(edited, Response::Ok { .. }), "{edited:?}");
    let after = text_of(req(
        &rt,
        &home,
        Request::RoleShow {
            role: role_id.clone(),
        },
    ));
    let head2 = after["revision"]["revision_id"]
        .as_str()
        .unwrap()
        .to_string();
    assert_ne!(head, head2, "an edit advances the head");
    assert_eq!(after["revision"]["body"]["name"], "Reviewer+");

    // An unregistered capability refuses at creation.
    let bogus = req(
        &rt,
        &home,
        Request::RoleCreate {
            name: "Bogus".into(),
            description: None,
            project: None,
            capabilities: vec!["nuke.everything".into()],
        },
    );
    assert!(matches!(bogus, Response::Error { .. }), "{bogus:?}");

    // ---- workflow: replace the default with a gated edge ------------------
    let wf = text_of(req(
        &rt,
        &home,
        Request::WorkflowShow {
            project: project_key.clone(),
        },
    ));
    let wf_head = wf["revision"]["revision_id"].as_str().unwrap().to_string();
    let project_id = wf["project_id"].as_str().unwrap().to_string();
    let mut body = wf["revision"]["body"].clone();
    // Remove the backlog→done edge entirely, and strip the admin/contributor
    // override from backlog→in_progress: only the qualified transition
    // capability may take it.
    {
        let transitions = body["transitions"].as_array_mut().unwrap();
        transitions.retain(|t| t["transition_id"] != "default.backlog.done");
        for t in transitions.iter_mut() {
            if t["transition_id"] == "default.backlog.in_progress" {
                t["demand_template"] = serde_json::json!({
                    "op": "require",
                    "capability": "workflow.transition.ship",
                    "resource": {"kind": "project"},
                });
            }
        }
    }
    // An invalid body refuses before any commit.
    let mut broken = body.clone();
    broken["transitions"].as_array_mut().unwrap()[0]["destination_state_id"] =
        serde_json::json!("nowhere");
    let invalid = req(
        &rt,
        &home,
        Request::WorkflowValidate {
            body_json: broken.to_string(),
        },
    );
    assert!(matches!(invalid, Response::Error { .. }), "{invalid:?}");
    let valid = req(
        &rt,
        &home,
        Request::WorkflowValidate {
            body_json: body.to_string(),
        },
    );
    assert!(matches!(valid, Response::Ok { .. }), "{valid:?}");
    let set = req(
        &rt,
        &home,
        Request::WorkflowSet {
            project: project_id.clone(),
            expect_heads: vec![wf_head],
            body_json: body.to_string(),
        },
    );
    assert!(matches!(set, Response::Ok { .. }), "{set:?}");

    // ---- gate enforcement: the removed edge is refused; the stripped edge
    // denies even the admin until the matching role is assigned -------------
    let filed = req(
        &rt,
        &home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: "Gated".into(),
            project: Some(project_id.clone()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    );
    let reff = match &filed {
        Response::Ref { reff } => reff.clone(),
        other => panic!("{other:?}"),
    };
    // backlog → done: the edge does not exist in the replaced workflow.
    let no_edge = req(
        &rt,
        &home,
        Request::IssueEdit {
            due: None,
            estimate: None,
            reff: reff.clone(),
            title: None,
            status: Some("done".into()),
            priority: None,
            description: None,
        },
    );
    assert!(matches!(no_edge, Response::Error { .. }), "{no_edge:?}");
    // backlog → in_progress: exists, but its template grants no admin
    // override — even the founder is denied until the role is assigned.
    let denied = req(
        &rt,
        &home,
        Request::IssueEdit {
            due: None,
            estimate: None,
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        },
    );
    assert!(
        err_msg(&denied).contains("view-only") || err_msg(&denied).contains("membership"),
        "the deterministic gate denies without the transition capability: {denied:?}"
    );

    // Assign the custom role (Project-scoped) to the founder, then the same
    // transition authorizes — role authoring + Mechanics assignment + gate.
    let me = match req(&rt, &home, Request::Members) {
        Response::Members { members } => members.into_iter().find(|m| m.me).unwrap().key,
        other => panic!("{other:?}"),
    };
    let granted = req(
        &rt,
        &home,
        Request::AccessGrant {
            actor: me.clone(),
            role: role_id.clone(),
            project: Some(project_id.clone()),
        },
    );
    assert!(matches!(granted, Response::Ok { .. }), "{granted:?}");
    let rows = match req(
        &rt,
        &home,
        Request::AccessList {
            actor: Some(me.clone()),
        },
    ) {
        Response::Assignments { rows } => rows,
        other => panic!("{other:?}"),
    };
    let grant = rows
        .iter()
        .find(|r| r.capability == "workflow.transition.ship")
        .expect("the exact expansion landed");
    assert_eq!(grant.resource, vec![project_id.clone()]);
    let allowed = req(
        &rt,
        &home,
        Request::IssueEdit {
            due: None,
            estimate: None,
            reff: reff.clone(),
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        },
    );
    assert!(
        matches!(allowed, Response::Ref { .. }),
        "the assigned transition capability authorizes the gate: {allowed:?}"
    );

    // ---- revoke: the assignment disappears and the gate denies again ------
    let revoked = req(
        &rt,
        &home,
        Request::AccessRevoke {
            grant_id: grant.grant_id.clone(),
        },
    );
    assert!(matches!(revoked, Response::Ok { .. }), "{revoked:?}");
    let rows = match req(
        &rt,
        &home,
        Request::AccessList {
            actor: Some(me.clone()),
        },
    ) {
        Response::Assignments { rows } => rows,
        other => panic!("{other:?}"),
    };
    assert!(
        !rows
            .iter()
            .any(|r| r.capability == "workflow.transition.ship"),
        "revocation removed the assignment"
    );
    let denied_again = req(
        &rt,
        &home,
        Request::IssueEdit {
            due: None,
            estimate: None,
            reff: reff.clone(),
            title: None,
            status: Some("backlog".into()),
            priority: None,
            description: None,
        },
    );
    // in_progress → backlog keeps the default (admin-overridable) template, so
    // this still succeeds; the STRIPPED edge denies again after revocation.
    assert!(matches!(denied_again, Response::Ref { .. }));
    let stripped = req(
        &rt,
        &home,
        Request::IssueEdit {
            due: None,
            estimate: None,
            reff,
            title: None,
            status: Some("in_progress".into()),
            priority: None,
            description: None,
        },
    );
    assert!(matches!(stripped, Response::Error { .. }), "{stripped:?}");

    // ---- tombstone: a deleted role no longer assigns ----------------------
    let deleted = req(
        &rt,
        &home,
        Request::RoleDelete {
            role: role_id.clone(),
            expect_revision: head2,
        },
    );
    assert!(matches!(deleted, Response::Ok { .. }), "{deleted:?}");
    let refused = req(
        &rt,
        &home,
        Request::AccessGrant {
            actor: me,
            role: role_id,
            project: Some(project_id),
        },
    );
    assert!(
        err_msg(&refused).contains("tombstoned"),
        "a tombstoned role assigns nothing: {refused:?}"
    );

    let _ = req(&rt, &home, Request::Stop);
    let _ = handle.join();
    let _ = std::fs::remove_dir_all(&home);
}
