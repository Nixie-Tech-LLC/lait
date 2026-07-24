//! C5 step 5 — the orbital **join** flow driven end to end through two orbital
//! daemons over their real control sockets, with an in-memory transport.
//!
//! `orbital_join.rs` proves form → invite → enter → admission → auto-approve →
//! E2EE convergence at the Station level. This proves the SAME flow through the
//! product's front door: a founder daemon forms and serves a Space, a joiner
//! bootstraps its store from the founder's invite link (`orbital::enter_space`,
//! the `lait join` heir) and serves its own daemon, then the two daemons drive
//! Contact over the socket (`Connect`) until the joiner is admitted and reads
//! the founder's sealed issue. Nothing here touches the legacy node.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use lait::control::{request, Request, Response};
use lait::net::Network;
use lait::orbital::run_orbital_daemon_with;
use lait::transport::mem::MemNet;
use lait::transport::{Alpn, Transport, TransportFactory};

const FOUNDER_SEED: [u8; 32] = [201u8; 32];
const JOINER_SEED: [u8; 32] = [202u8; 32];

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

fn temp_home(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("lait-2node-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
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

/// Spawn an orbital daemon for `home` on its own OS thread + runtime, with an
/// explicit device seed (the injectable multi-node contract — no shared global
/// identity between the two daemons).
fn spawn_daemon(home: PathBuf, seed: [u8; 32], net: MemNet) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async move {
            if let Err(e) = run_orbital_daemon_with(home, seed, &MemFactory(net)).await {
                eprintln!("DAEMON ERR: {e:#}");
            }
        });
    })
}

fn wait_online(rt: &tokio::runtime::Runtime, home: &Path) {
    let online = poll_until(Duration::from_secs(20), || {
        matches!(req(rt, home, Request::Status), Response::Status(_)).then_some(())
    });
    assert!(
        online.is_some(),
        "daemon at {} never came online",
        home.display()
    );
}

#[test]
fn two_orbital_daemons_join_admit_and_converge_over_the_socket() {
    let net = MemNet::new();

    // -- Founder: form the Space, seed a project + a sealed issue, then serve. --
    let founder_home = temp_home("founder");
    lait::orbital::form_space(&founder_home, &FOUNDER_SEED, "Two Node Space").unwrap();

    let founder_handle = spawn_daemon(founder_home.clone(), FOUNDER_SEED, net.clone());

    let client = tokio::runtime::Runtime::new().unwrap();
    wait_online(&client, &founder_home);

    // A project + an issue with a sealed body, filed by the founder over the wire.
    let resp = req(
        &client,
        &founder_home,
        Request::ProjectNew {
            name: "Core".into(),
            key: "core".into(),
            color: None,
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "CORE"),
        "{resp:?}"
    );
    let resp = req(
        &client,
        &founder_home,
        Request::IssueNew {
            due: None,
            estimate: None,
            title: "Secret plan".into(),
            // Formation seeded the default project too — pick the explicit one.
            project: Some("core".into()),
            project_hint: None,
            assignees: vec![],
            priority: Some("high".into()),
            labels: vec![],
            body: Some("the sealed body".into()),
        },
    );
    assert!(
        matches!(&resp, Response::Ref { reff } if reff == "CORE-1"),
        "{resp:?}"
    );

    // The founder mints an auto-approving invite link (Coordinates v1).
    let resp = req(
        &client,
        &founder_home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    );
    let Response::Ref { reff: invite } = resp else {
        panic!("expected an invite Ref, got {resp:?}");
    };

    // -- Joiner: bootstrap the store from the invite link, then serve. --
    let joiner_home = temp_home("joiner");
    lait::orbital::enter_space(&joiner_home, &JOINER_SEED, &invite).unwrap();

    let joiner_handle = spawn_daemon(joiner_home.clone(), JOINER_SEED, net.clone());
    wait_online(&client, &joiner_home);

    // Before admission the joiner is pending: no epoch key, no standing.
    let Response::Status(info) = req(&client, &joiner_home, Request::Status) else {
        panic!("expected Status");
    };
    assert_eq!(
        info.membership, "pending",
        "un-admitted joiner has no standing"
    );

    // Drive Contact over the sockets. Admission is a three-leg handshake:
    //   1. joiner pulls founder  (retains the founder's Bodies opaquely),
    //   2. founder pulls joiner   (redeems admission: AddMember + epoch sealing),
    //   3. joiner pulls founder   (imports membership + keys, upgrades Bodies).
    let founder_device = lait::crypto::device_from_seed(&FOUNDER_SEED).to_string();
    let joiner_device = lait::crypto::device_from_seed(&JOINER_SEED).to_string();

    let admitted = poll_until(Duration::from_secs(20), || {
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
        req(
            &client,
            &founder_home,
            Request::Connect {
                ticket: joiner_device.clone(),
            },
        );
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: founder_device.clone(),
            },
        );
        match req(&client, &joiner_home, Request::Status) {
            Response::Status(info) if info.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(
        admitted.is_some(),
        "the joiner was never admitted through the daemons"
    );

    // The founder now lists the joiner as a member over its own socket.
    let Response::Members { members } = req(&client, &founder_home, Request::Members) else {
        panic!("expected Members");
    };
    assert_eq!(members.len(), 2, "founder + admitted joiner: {members:?}");

    // The admitted joiner reads the founder's previously-opaque sealed issue.
    let resp = req(
        &client,
        &joiner_home,
        Request::IssueView {
            reff: "CORE-1".into(),
        },
    );
    let Response::Issue(view) = resp else {
        panic!("expected Issue, got {resp:?}");
    };
    assert_eq!(view.title, "Secret plan");
    assert_eq!(
        view.description, "the sealed body",
        "the E2EE body decrypted"
    );

    // The joiner writes back; the founder converges it.
    req(
        &client,
        &joiner_home,
        Request::Comment {
            reply_to: None,
            reff: "CORE-1".into(),
            body: "joined over the socket".into(),
        },
    );
    let converged = poll_until(Duration::from_secs(20), || {
        req(
            &client,
            &founder_home,
            Request::Connect {
                ticket: joiner_device.clone(),
            },
        );
        match req(
            &client,
            &founder_home,
            Request::IssueView {
                reff: "CORE-1".into(),
            },
        ) {
            Response::Issue(v)
                if v.comments
                    .iter()
                    .any(|c| c.body == "joined over the socket") =>
            {
                Some(())
            }
            _ => None,
        }
    });
    assert!(
        converged.is_some(),
        "the joiner's comment never converged back to the founder"
    );

    // Inbox reconstruction (plan 04): the founder assigns itself by starting
    // the issue, so the JOINER's converged comment is addressed to it — the
    // inbox is a pure projection over the synced state, rebuilt from query.
    let resp = req(
        &client,
        &founder_home,
        Request::IssueStart {
            reff: "CORE-1".into(),
        },
    );
    assert!(!matches!(resp, Response::Error { .. }), "{resp:?}");
    let inboxed = poll_until(Duration::from_secs(10), || {
        match req(&client, &founder_home, Request::Inbox { clear: false }) {
            Response::Inbox { entries, .. }
                if entries
                    .iter()
                    .any(|e| e.kind == "comment" && e.detail == "joined over the socket") =>
            {
                Some(())
            }
            _ => None,
        }
    });
    assert!(
        inboxed.is_some(),
        "the joiner's comment never surfaced in the founder's inbox projection"
    );

    // Teardown.
    let _ = req(&client, &joiner_home, Request::Stop);
    let _ = req(&client, &founder_home, Request::Stop);
    let _ = joiner_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&joiner_home);
}

/// The `lait join` contract: the joiner drives Contact to the inviter's
/// approach Station and the inviter's driver **reciprocates on its own** to
/// redeem the admission — no manual admin-side Connect. This is what makes an
/// auto-approving invite "just work" from the joiner's side alone.
#[test]
fn the_inviter_reciprocates_so_a_joiner_side_only_connect_admits() {
    const F_SEED: [u8; 32] = [211u8; 32];
    const J_SEED: [u8; 32] = [212u8; 32];
    let net = MemNet::new();

    let founder_home = temp_home("recip-founder");
    lait::orbital::found_space_cli(&founder_home, &F_SEED, "Reciprocal Space").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), F_SEED, net.clone());

    let client = tokio::runtime::Runtime::new().unwrap();
    wait_online(&client, &founder_home);

    let Response::Ref { reff: invite } = req(
        &client,
        &founder_home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };

    // Joiner bootstraps from the link and serves.
    let joiner_home = temp_home("recip-joiner");
    lait::orbital::enter_space(&joiner_home, &J_SEED, &invite).unwrap();
    let joiner_handle = spawn_daemon(joiner_home.clone(), J_SEED, net.clone());
    wait_online(&client, &joiner_home);

    // Only the JOINER drives Connect (to the invite's approach Station). The
    // founder's driver must reciprocate to redeem the admission.
    let approach = lait::crypto::device_from_seed(&F_SEED).to_string();
    let admitted = poll_until(Duration::from_secs(25), || {
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: approach.clone(),
            },
        );
        match req(&client, &joiner_home, Request::Status) {
            Response::Status(info) if info.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(
        admitted.is_some(),
        "the inviter never reciprocated — joiner-side-only Connect did not admit"
    );

    let _ = req(&client, &joiner_home, Request::Stop);
    let _ = req(&client, &founder_home, Request::Stop);
    let _ = joiner_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&joiner_home);
}

/// GOV-11: elevation and demotion are signed `SetGrants` ops with a real
/// product surface — promote/demote over the control socket, short-prefix
/// subject resolution, and the last-admin fence.
#[test]
fn members_promote_and_demote_over_the_socket() {
    const F_SEED: [u8; 32] = [231u8; 32];
    const J_SEED: [u8; 32] = [232u8; 32];
    let net = MemNet::new();

    let founder_home = temp_home("role-founder");
    lait::orbital::found_space_cli(&founder_home, &F_SEED, "Role Space").unwrap();
    let founder_handle = spawn_daemon(founder_home.clone(), F_SEED, net.clone());
    let client = tokio::runtime::Runtime::new().unwrap();
    wait_online(&client, &founder_home);

    let Response::Ref { reff: invite } = req(
        &client,
        &founder_home,
        Request::Invite {
            role: None,
            reusable: false,
            ttl_hours: Some(24),
        },
    ) else {
        panic!("expected an invite link");
    };
    let joiner_home = temp_home("role-joiner");
    lait::orbital::enter_space(&joiner_home, &J_SEED, &invite).unwrap();
    let joiner_handle = spawn_daemon(joiner_home.clone(), J_SEED, net.clone());
    wait_online(&client, &joiner_home);
    let approach = lait::crypto::device_from_seed(&F_SEED).to_string();
    let admitted = poll_until(Duration::from_secs(25), || {
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: approach.clone(),
            },
        );
        match req(&client, &joiner_home, Request::Status) {
            Response::Status(info) if info.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(admitted.is_some(), "the joiner was never admitted");

    // The joiner's actor id, from the founder's roster (non-me row).
    let joiner_actor = {
        let Response::Members { members } = req(&client, &founder_home, Request::Members) else {
            panic!("expected Members");
        };
        members
            .iter()
            .find(|m| !m.me)
            .expect("joiner row")
            .key
            .clone()
    };
    let role_of = |actor: &str| -> String {
        let Response::Members { members } = req(&client, &founder_home, Request::Members) else {
            panic!("expected Members");
        };
        members
            .iter()
            .find(|m| m.key == actor)
            .map(|m| m.role.clone())
            .unwrap_or_default()
    };
    assert_eq!(role_of(&joiner_actor), "member");

    // Promote by SHORT PREFIX — the form every surface prints.
    let short: String = joiner_actor.chars().take(12).collect();
    let resp = req(
        &client,
        &founder_home,
        Request::MemberSetRole {
            who: short,
            admin: true,
        },
    );
    assert!(
        matches!(&resp, Response::Ok { .. }),
        "promote failed: {resp:?}"
    );
    assert_eq!(role_of(&joiner_actor), "admin");

    // A promoted admin is a FULL admin (GOV-11): promotion installs the
    // policy-admin meta-grant, not just ACL standing, so the joiner can mint
    // an invite from its OWN node. Converge the promotion, then mint as the
    // joiner (the exact capability a half-admin lacked).
    let minted = poll_until(Duration::from_secs(20), || {
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: approach.clone(),
            },
        );
        match req(
            &client,
            &joiner_home,
            Request::Invite {
                role: Some("contributor".into()),
                reusable: false,
                ttl_hours: Some(24),
            },
        ) {
            Response::Ref { .. } => Some(()),
            _ => None,
        }
    });
    assert!(
        minted.is_some(),
        "a promoted admin could not mint an invite — promotion left the meta-grant off"
    );

    // Demote back to a plain member.
    let resp = req(
        &client,
        &founder_home,
        Request::MemberSetRole {
            who: joiner_actor.clone(),
            admin: false,
        },
    );
    assert!(
        matches!(&resp, Response::Ok { .. }),
        "demote failed: {resp:?}"
    );
    assert_eq!(role_of(&joiner_actor), "member");

    // Demotion reverses both layers: once it converges, the joiner can no
    // longer mint invites (ACL standing gone and the meta-grant revoked).
    let refused = poll_until(Duration::from_secs(20), || {
        req(
            &client,
            &joiner_home,
            Request::Connect {
                ticket: approach.clone(),
            },
        );
        match req(
            &client,
            &joiner_home,
            Request::Invite {
                role: Some("contributor".into()),
                reusable: false,
                ttl_hours: Some(24),
            },
        ) {
            Response::Error { .. } => Some(()),
            _ => None,
        }
    });
    assert!(
        refused.is_some(),
        "a demoted member could still mint invites — the capability layer was not reversed"
    );

    // The last admin cannot demote themselves into a repair-proof space.
    let founder_actor = {
        let Response::Members { members } = req(&client, &founder_home, Request::Members) else {
            panic!("expected Members");
        };
        members.iter().find(|m| m.me).expect("me row").key.clone()
    };
    let resp = req(
        &client,
        &founder_home,
        Request::MemberSetRole {
            who: founder_actor,
            admin: false,
        },
    );
    assert!(
        matches!(&resp, Response::Error { ref message, .. } if message.contains("last admin")),
        "the last-admin fence did not hold: {resp:?}"
    );

    let _ = req(&client, &joiner_home, Request::Stop);
    let _ = req(&client, &founder_home, Request::Stop);
    let _ = joiner_handle.join();
    let _ = founder_handle.join();
    let _ = std::fs::remove_dir_all(&founder_home);
    let _ = std::fs::remove_dir_all(&joiner_home);
}
