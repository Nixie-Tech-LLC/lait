//! The real daemon, run in-process over an in-memory peer transport: **zero
//! network sockets**, no relay, no discovery, no spawned processes. (The local
//! control channel is still a unix socket / named pipe — that is the boundary
//! being held, not removed.)
//!
//! Every other multi-node suite pays tens of seconds for a real network to
//! converge, which caps how much daemon behaviour is worth asserting. Here the
//! network is a `HashMap` and some channels, so the same daemon code — gossip
//! announce, trigger-pull, catalog-first sync over the seam, import, doorbell —
//! runs deterministically in about a second, and lifecycle behaviour that a
//! process-shaped daemon hides behind `exit(0)` becomes assertable at all.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Filter, Request, Response};
use lait::net::Network;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

/// Attaches each daemon to one shared switchboard, deriving its peer identity
/// from the seed the daemon itself was built from — the same function the real
/// transport's edge uses, so the two agree by construction.
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

/// A factory that hands back a transport belonging to somebody else. Nothing
/// downstream of construction can detect this, which is why the daemon must.
struct MismatchedFactory(MemNet);

#[async_trait]
impl TransportFactory for MismatchedFactory {
    async fn build(
        &self,
        _identity_seed: &[u8; 32],
        _network: &Network,
        _alpns: &[Alpn],
    ) -> Result<Arc<dyn Transport>> {
        Ok(Arc::new(
            self.0.peer(lait::crypto::device_from_seed(&[0xAB; 32])),
        ))
    }
}

fn tmp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "gc-mem-{}-{}-{}",
        tag,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The space registry is machine-global; point it somewhere scratch so a test
/// run never touches the developer's real `spaces.json`. Also disable
/// idle-shutdown and run the protocol on a one-second heartbeat.
fn isolate_env(root: &Path) {
    std::env::set_var("LAIT_CONFIG_ROOT", root.join("cfgroot"));
    std::env::set_var("LAIT_IDLE_SECS", "0");
    std::env::set_var("LAIT_HEARTBEAT_SECS", "1");
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// Found a space in `home` under the same identity the daemon will load, since
/// the daemon is handed `home` as its identity directory.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::crypto::device_from_seed(&key);
    let store = lait::store::Store::open(home).expect("store");
    lait::replica::found_space(&store, &me, &key, "test", &lait::ids::SystemUlidSource)
        .expect("found space");
}

fn join_home(home: &Path, ticket: &str) {
    let t: lait::proto::SpaceTicket = ticket.parse().expect("parse ticket");
    let store = lait::store::Store::open(home).expect("store");
    lait::replica::join_space_store(
        &store,
        &t.space,
        &t.salt,
        &t.recovery_root,
        t.founder_inception
            .as_ref()
            .expect("ticket carries a founding proof"),
    )
    .expect("bootstrap joiner store");
}

fn req(rt: &tokio::runtime::Runtime, home: &Path, r: Request) -> Response {
    rt.block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
}

/// Start a daemon on `home` over `net` and wait until it answers control
/// requests. Returns the handle so a test can await its teardown.
fn start(
    rt: &tokio::runtime::Runtime,
    net: &MemNet,
    home: &Path,
) -> tokio::task::JoinHandle<Result<()>> {
    let factory = MemFactory(net.clone());
    let h = home.to_path_buf();
    let handle =
        rt.spawn(async move { lait::node::run_daemon_with(h.clone(), false, h, &factory).await });
    let online = poll_until(Duration::from_secs(20), || {
        matches!(req(rt, home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(
        online.is_some(),
        "daemon for {} never answered a control request",
        home.display()
    );
    handle
}

fn stop(rt: &tokio::runtime::Runtime, home: &Path, handle: tokio::task::JoinHandle<Result<()>>) {
    assert!(
        matches!(req(rt, home, Request::Stop), Response::Ok { .. }),
        "the daemon must acknowledge stop"
    );
    let ended = rt.block_on(async { tokio::time::timeout(Duration::from_secs(20), handle).await });
    ended
        .expect("the daemon must return from teardown, not hang")
        .expect("the daemon task must not panic")
        .expect("the daemon must return Ok from a clean stop");
}

fn list_titles(rt: &tokio::runtime::Runtime, home: &Path) -> Vec<String> {
    match req(
        rt,
        home,
        Request::List {
            project: None,
            filter: Filter::default(),
        },
    ) {
        Response::List { rows } => rows.into_iter().map(|r| r.title).collect(),
        _ => Vec::new(),
    }
}

fn text_of(r: Response) -> String {
    match r {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("expected text, got {other:?}"),
    }
}

fn new_issue(rt: &tokio::runtime::Runtime, home: &Path, title: &str, body: Option<&str>) {
    assert!(
        matches!(
            req(
                rt,
                home,
                Request::IssueNew {
                    title: title.into(),
                    project: Some("ENG".into()),
                    project_hint: None,
                    assignees: vec![],
                    priority: None,
                    labels: vec![],
                    body: body.map(str::to_string),
                }
            ),
            Response::Ref { .. }
        ),
        "issue new"
    );
}

/// The flagship: two real daemons, one switchboard, converging both ways
/// through the full stack — gossip announce, pull, `sync::serve` over the seam,
/// import, doorbell — with no network socket anywhere in the path.
#[test]
fn two_daemons_converge_over_an_in_memory_peer_transport() {
    let a_home = tmp_home("conv-a");
    let b_home = tmp_home("conv-b");
    isolate_env(&a_home);
    found_home(&a_home);

    let rt = rt();
    let net = MemNet::new();
    let a = start(&rt, &net, &a_home);

    assert!(
        matches!(
            req(
                &rt,
                &a_home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                }
            ),
            Response::Ref { .. }
        ),
        "A: projects new"
    );
    // The body lives only in the issue doc, never in the catalog row, so B
    // seeing it proves the document transferred and not just the catalog.
    new_issue(
        &rt,
        &a_home,
        "shared from A",
        Some("BODY_A: only in the doc"),
    );

    let ticket = text_of(req(
        &rt,
        &a_home,
        Request::Invite {
            require_approval: true,
            reusable: false,
            ttl_hours: None,
        },
    ));
    join_home(&b_home, &ticket);
    let b = start(&rt, &net, &b_home);
    assert!(
        matches!(
            req(&rt, &b_home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: connect"
    );

    // Space data is end-to-end encrypted: until A admits B, B holds ciphertext.
    let b_id = text_of(req(&rt, &b_home, Request::Id));
    assert!(
        list_titles(&rt, &b_home).is_empty(),
        "a non-member must see no readable issues"
    );
    assert!(
        matches!(
            req(
                &rt,
                &a_home,
                Request::MemberAdd {
                    who: b_id,
                    admin: false,
                    as_name: None
                }
            ),
            Response::Ok { .. }
        ),
        "A: member add B"
    );

    assert!(
        poll_until(Duration::from_secs(30), || list_titles(&rt, &b_home)
            .iter()
            .any(|t| t == "shared from A")
            .then_some(()))
        .is_some(),
        "A→B: B never converged to A's issue"
    );
    let a_ref = match req(
        &rt,
        &b_home,
        Request::List {
            project: None,
            filter: Filter::default(),
        },
    ) {
        Response::List { rows } => rows
            .into_iter()
            .find(|r| r.title == "shared from A")
            .map(|r| r.reff)
            .expect("B has a row for A's issue"),
        other => panic!("B: list returned {other:?}"),
    };
    assert!(
        poll_until(Duration::from_secs(30), || {
            match req(
                &rt,
                &b_home,
                Request::IssueView {
                    reff: a_ref.clone(),
                },
            ) {
                Response::Issue(v) if !v.provisional && v.description.contains("BODY_A") => {
                    Some(())
                }
                _ => None,
            }
        })
        .is_some(),
        "A→B: the catalog row arrived but the issue-doc body never did"
    );

    // And back the other way, which is a second pull in the opposite direction.
    new_issue(&rt, &b_home, "reply from B", None);
    assert!(
        poll_until(Duration::from_secs(30), || list_titles(&rt, &a_home)
            .iter()
            .any(|t| t == "reply from B")
            .then_some(()))
        .is_some(),
        "B→A: A never converged to B's issue"
    );

    stop(&rt, &b_home, b);
    stop(&rt, &a_home, a);
    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&b_home);
}

/// The onboarding path, deterministically: an invite carrying a
/// pre-authorization admits the joiner with no manual approve, which exercises
/// ticket-join re-subscribe, the sealed `JoinRequest` over gossip, and the
/// membership sync that follows.
#[test]
fn an_invite_pass_admits_a_joiner_over_an_in_memory_peer_transport() {
    let a_home = tmp_home("join-a");
    let b_home = tmp_home("join-b");
    isolate_env(&a_home);
    found_home(&a_home);

    let rt = rt();
    let net = MemNet::new();
    let a = start(&rt, &net, &a_home);
    assert!(
        matches!(
            req(
                &rt,
                &a_home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                }
            ),
            Response::Ref { .. }
        ),
        "A: projects new"
    );
    new_issue(&rt, &a_home, "for the joiner", None);

    let ticket = text_of(req(
        &rt,
        &a_home,
        Request::Invite {
            require_approval: false,
            reusable: false,
            ttl_hours: None,
        },
    ));
    join_home(&b_home, &ticket);
    let b = start(&rt, &net, &b_home);
    assert!(
        matches!(
            req(&rt, &b_home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: join"
    );

    assert!(
        poll_until(Duration::from_secs(30), || list_titles(&rt, &b_home)
            .iter()
            .any(|t| t == "for the joiner")
            .then_some(()))
        .is_some(),
        "an invite pass must admit the joiner and let it decrypt the board"
    );

    stop(&rt, &b_home, b);
    stop(&rt, &a_home, a);
    let _ = std::fs::remove_dir_all(&a_home);
    let _ = std::fs::remove_dir_all(&b_home);
}

/// What "stopped" has to mean for a daemon a caller can await: the entry
/// returns, the lock is free, the control endpoint is gone, and nothing the old
/// daemon spawned is still running against the home the next one now owns.
#[test]
fn a_stopped_daemon_hands_its_home_to_the_next_one() {
    let home = tmp_home("restart");
    isolate_env(&home);
    found_home(&home);

    let rt = rt();
    let net = MemNet::new();
    let first = start(&rt, &net, &home);
    assert!(
        matches!(
            req(
                &rt,
                &home,
                Request::ProjectNew {
                    name: "Engineering".into(),
                    key: "ENG".into(),
                }
            ),
            Response::Ref { .. }
        ),
        "the first daemon answers control requests"
    );
    stop(&rt, &home, first);

    // The control endpoint must be gone the moment the entry returns: a client
    // that connects to a half-dead server parks on a reply that never comes.
    assert!(
        rt.block_on(async { request(&home, &Request::Status).await })
            .is_err(),
        "the control endpoint must not outlive the daemon"
    );

    // The lock is what makes the next start legal, and it is only released by
    // the entry returning.
    let second = start(&rt, &net, &home);
    assert!(
        matches!(req(&rt, &home, Request::Status), Response::Status(_)),
        "a second daemon must start on the same home"
    );
    // A checkpoint task from the first daemon would still be committing into
    // this home; a heartbeat task would still be broadcasting under its
    // identity. Both would show up as a peer that is us.
    new_issue(&rt, &home, "after the restart", None);
    std::thread::sleep(Duration::from_secs(3));
    match req(&rt, &home, Request::Status) {
        Response::Status(s) => assert_eq!(
            s.online_peers, 0,
            "no task from the stopped daemon may still be broadcasting"
        ),
        other => panic!("status returned {other:?}"),
    }

    stop(&rt, &home, second);
    let _ = std::fs::remove_dir_all(&home);
}

/// The `Pull` frame a peer sends first, spelled out here rather than reached
/// through the daemon's own encoder. Postcard writes an enum as its variant
/// index followed by the variant's fields, so a frame is one discriminant byte
/// and this struct — which makes the discriminants below the actual wire
/// contract and not a restatement of it.
#[derive(serde::Serialize)]
struct PullFrame {
    protocol_version: u32,
    space: String,
    membership_vv: Vec<u8>,
    catalog_vv: Vec<u8>,
}

const MSG_PULL: u8 = 0;
const MSG_MEMBERSHIP: u8 = 1;
const MSG_CATALOG: u8 = 2;
const MSG_END_REQUESTS: u8 = 4;
const MSG_END_DOCS: u8 = 7;

/// The accept loop is what replaced a per-protocol handler registry, so it owes
/// two things: route by ALPN, and serve the sync protocol over the seam. A bare
/// switchboard peer — not a daemon — dials in and speaks it by hand.
#[test]
fn the_accept_loop_routes_by_alpn_and_serves_a_pull() {
    let home = tmp_home("alpn");
    isolate_env(&home);
    found_home(&home);

    let rt = rt();
    let net = MemNet::new();
    let daemon = start(&rt, &net, &home);
    let space = match req(&rt, &home, Request::Status) {
        Response::Status(s) => s.space.expect("a founded daemon reports its space"),
        other => panic!("status returned {other:?}"),
    };

    let peer = net.peer(lait::crypto::device_from_seed(&[0x5A; 32]));
    rt.block_on(async {
        // A presence dial opens no stream and sends nothing: landing at all is
        // the whole liveness signal, and it proves that ALPN is dispatched.
        let probe = peer
            .connect(
                lait::crypto::device_from_seed(
                    &lait::config::load_or_create_identity(&home).unwrap(),
                ),
                lait::presence::PRESENCE_ALPN,
            )
            .await
            .expect("the daemon accepts a presence dial");
        drop(probe);

        let me =
            lait::crypto::device_from_seed(&lait::config::load_or_create_identity(&home).unwrap());
        let mut s = peer
            .connect(me, lait::sync::SYNC_ALPN)
            .await
            .expect("the daemon accepts a sync dial");

        let mut frame = vec![MSG_PULL];
        frame.extend_from_slice(
            &postcard::to_stdvec(&PullFrame {
                protocol_version: lait::sync::PROTOCOL_VERSION,
                space,
                membership_vv: Vec::new(),
                catalog_vv: Vec::new(),
            })
            .unwrap(),
        );
        s.send(&frame).await.expect("send Pull");

        // Read nothing for a moment: the accepter has already answered and
        // parked, and its frames must still be here when we get round to them.
        tokio::time::sleep(Duration::from_millis(200)).await;

        let membership = s.recv().await.unwrap().expect("Membership frame");
        assert_eq!(membership[0], MSG_MEMBERSHIP);
        let catalog = s.recv().await.unwrap().expect("Catalog frame");
        assert_eq!(catalog[0], MSG_CATALOG);

        s.send(&[MSG_END_REQUESTS]).await.expect("send EndRequests");
        let end = s.recv().await.unwrap().expect("EndDocs frame");
        assert_eq!(end[0], MSG_END_DOCS);
        assert!(
            s.recv().await.unwrap().is_none(),
            "the accepter finishes cleanly at a frame boundary"
        );
    });

    stop(&rt, &home, daemon);
    let _ = std::fs::remove_dir_all(&home);
}

/// A transport whose identity is not the daemon's is refused at startup. Every
/// symptom of letting it through surfaces far from the cause: signed gossip
/// under one key, a dialable peer under another, tickets advertising a host
/// nobody can reach.
#[test]
fn a_transport_that_is_not_us_is_refused_at_startup() {
    let home = tmp_home("mismatch");
    isolate_env(&home);
    found_home(&home);

    let rt = rt();
    let factory = MismatchedFactory(MemNet::new());
    let err = rt
        .block_on(async {
            lait::node::run_daemon_with(home.clone(), false, home.clone(), &factory).await
        })
        .expect_err("a mismatched transport must not start a daemon");
    assert!(
        format!("{err:#}").contains("identity"),
        "the refusal must name the cause: {err:#}"
    );

    let _ = std::fs::remove_dir_all(&home);
}
