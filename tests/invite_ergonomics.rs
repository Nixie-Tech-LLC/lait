//! Invite/remote ergonomics end-to-end (WS1+WS2+WS3): two real nodes exercise the
//! join-request approval flow — `members requests` surfaces an announced joiner,
//! and `members approve` is **key-first**: it resolves only by authenticated
//! id-prefix / key (never the joiner's self-asserted nick), seals them the
//! workspace key, and attaches a trusted local petname via `--as`. Also asserts
//! the `seed`/`remote` list is a structured DTO. Drives daemons over the Layer-B
//! control channel, same as `two_node_sync.rs` (never shells the CLI).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use lait::control::{request, Filter, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

/// A current-thread runtime: each `req` is a single control-channel round trip, so
/// spinning up the default multi-thread runtime (and its worker-thread pool) per
/// call — hundreds of times over a tight poll — is pure churn. This is far cheaper
/// to build and tear down.
fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn tmp_home(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "gc-invite-{}-{}-{}",
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

struct Daemon {
    child: Child,
    home: PathBuf,
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

#[allow(clippy::zombie_processes)] // the returned Daemon kills+waits on drop
fn spawn_daemon(home: &Path) -> Daemon {
    let mut child = Command::new(bin())
        .arg("daemon")
        .env("LAIT_HOME", home)
        // Isolate the workspace registry per node: the daemon-boot upsert must land
        // in a scratch config root, never the developer's real workspaces.json.
        .env("LAIT_CONFIG_ROOT", home.join("cfgroot"))
        .env("LAIT_IDLE_SECS", "0")
        // Run the protocol on a fast heartbeat so catch-up/absence windows are
        // seconds, not the 10s production default — the pipeline's biggest lever.
        .env("LAIT_HEARTBEAT_SECS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let rt = rt();
    let online = poll_until(Duration::from_secs(30), || {
        rt.block_on(async { request(home, &Request::Status).await })
            .ok()
    });
    if online.is_some() {
        return Daemon {
            child,
            home: home.to_path_buf(),
        };
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon for {} never came online", home.display());
}

/// Poll `check` immediately, then every 50 ms, until it yields `Some` or `timeout`
/// elapses (returns `None`). Returning the instant the condition holds keeps a
/// fast-converging case in the millisecond range instead of burning whole poll
/// ticks — the generous deadline is only a slow-CI backstop.
fn poll_until<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    let start = Instant::now();
    loop {
        if let Some(v) = check() {
            return Some(v);
        }
        if start.elapsed() >= timeout {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::err(format!("{e:#}")))
}

/// Found a workspace in `home` in-process, using the SAME identity the daemon
/// will load (`<home>/secret.key`, since the daemon runs with `LAIT_HOME=home`).
/// Workspaces are never minted lazily anymore — a daemon errors on an
/// uninitialized store — so every founder home goes through this first.
fn found_home(home: &Path) {
    let key = lait::config::load_or_create_identity(home).expect("identity");
    let me = lait::ids::UserId::from_key_string(key.public().to_string());
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::found_workspace(&store, &me, "test", &lait::ids::SystemUlidSource)
        .expect("found workspace");
}

/// Bootstrap a joiner store from a ticket (the client half of `lait join`), so
/// its daemon boots already bound to the host's workspace — the daemon-side
/// Connect/Join no longer adopts a foreign workspace.
fn join_home(home: &Path, ticket: &str) {
    let t: lait::proto::WorkspaceTicket = ticket.parse().expect("parse ticket");
    let store = lait::store::Store::open(home).expect("store");
    lait::tracker::join_workspace_store(&store, &t.workspace, &t.host.to_string())
        .expect("bootstrap joiner store");
}

/// Give a home a deterministic self-asserted nick via the store-layer
/// `config.json` (profile.json is gone — nick lives in layered config now).
fn set_nick(home: &Path, nick: &str) {
    std::fs::write(
        home.join("config.json"),
        format!(r#"{{"user.nick":"{nick}"}}"#),
    )
    .unwrap();
}

fn list_titles(home: &Path) -> Vec<String> {
    match req(
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

fn poll_title(home: &Path, needle: &str, timeout: Duration) -> bool {
    poll_until(timeout, || {
        list_titles(home).iter().any(|t| t == needle).then_some(())
    })
    .is_some()
}

#[test]
fn approve_join_request_key_first_and_seed_list_is_structured() {
    let a_home = tmp_home("a");
    let b_home = tmp_home("b");
    // Give B a distinct, deterministic nick so we can approve it by name — on one
    // machine A and B otherwise share the same OS-username default nick.
    set_nick(&b_home, "bob");

    found_home(&a_home);
    let a = spawn_daemon(&a_home);

    // WS3: the seed/remote list is a structured DTO even when empty.
    assert!(
        matches!(req(&a.home, Request::SeedList), Response::Seeds { .. }),
        "seed ls must return the structured Seeds DTO, not a text blob"
    );

    // A (the founder) adds a project + files an issue (E2EE — B can't read
    // until added).
    assert!(matches!(
        req(
            &a.home,
            Request::ProjectNew {
                name: "Engineering".into(),
                key: "ENG".into(),
            }
        ),
        Response::Ref { .. }
    ));
    assert!(matches!(
        req(
            &a.home,
            Request::IssueNew {
                title: "shared from A".into(),
                project: Some("ENG".into()),
                project_hint: None,
                assignees: vec![],
                priority: Some("high".into()),
                labels: vec![],
                body: None,
            }
        ),
        Response::Ref { .. }
    ));

    // B bootstraps from A's ticket BEFORE its daemon first starts, then
    // connects — announcing a join request carrying nick "bob".
    let ticket = match req(
        &a.home,
        Request::Invite {
            require_approval: true,
            reusable: false,
            ttl_hours: None,
        },
    ) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
    join_home(&b_home, &ticket);
    let b = spawn_daemon(&b_home);
    assert!(
        matches!(
            req(&b.home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: connect"
    );
    let b_id = match req(&b.home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("B: id returned {other:?}"),
    };

    // Anchor DX: B's own `status` tells the honest truth — it has only *requested*
    // to join and isn't a member yet, so it reads `pending` (not "you're live").
    match req(&b.home, Request::Status) {
        Response::Status(s) => assert_eq!(
            s.membership, "pending",
            "a joiner that hasn't been approved must read as `pending` in status"
        ),
        other => panic!("B: status returned {other:?}"),
    }

    // WS2: A sees B in `members requests`, carrying B's key AND nick.
    let claimed_nick = poll_until(Duration::from_secs(30), || {
        match req(&a.home, Request::MemberRequests) {
            Response::JoinRequests { requests } => {
                requests.into_iter().find(|r| r.key == b_id).map(|r| r.nick)
            }
            _ => None,
        }
    });
    assert_eq!(
        claimed_nick.as_deref(),
        Some("bob"),
        "A never saw B's join request carrying the announced nick"
    );

    // Anchor DX: A's `status` now nudges the host that someone is waiting — the
    // signal that unblocks onboarding (a host otherwise has no reason to run
    // `members approve`, and the joiner stalls in ciphertext forever).
    match req(&a.home, Request::Status) {
        Response::Status(s) => {
            assert_eq!(s.membership, "admin", "the founder must read as `admin`");
            assert!(
                s.pending_requests >= 1,
                "the host's status must surface the pending join request as a nudge"
            );
        }
        other => panic!("A: status returned {other:?}"),
    }

    // Security: the joiner's self-asserted nick is NOT a valid approval ref — an
    // unauthenticated name must never select who gets sealed the workspace key.
    assert!(
        matches!(
            req(
                &a.home,
                Request::MemberApprove {
                    who: "bob".into(),
                    as_name: None,
                }
            ),
            Response::Error { .. }
        ),
        "approving by the self-asserted wire nick must be rejected (key-first only)"
    );

    // WS1+WS2: approve KEY-FIRST — by B's authenticated id — attaching a trusted
    // local petname in the same step.
    assert!(
        matches!(
            req(
                &a.home,
                Request::MemberApprove {
                    who: b_id.clone(),
                    as_name: Some("bob".into()),
                }
            ),
            Response::Ok { .. }
        ),
        "A: approve B by key + alias"
    );

    // B converges (decrypts A's issue) — proves the approval actually added B.
    assert!(
        poll_title(&b.home, "shared from A", Duration::from_secs(30)),
        "B did not converge after approval (membership never sealed?)"
    );

    // Anchor DX: once approved + synced, B's `status` flips `pending` → `member`,
    // so the joiner can finally see they're on the board.
    let became_member = poll_until(Duration::from_secs(10), || {
        match req(&b.home, Request::Status) {
            Response::Status(s) if s.membership == "member" => Some(()),
            _ => None,
        }
    });
    assert!(
        became_member.is_some(),
        "after approval B's status should read `member`, not `pending`"
    );

    // The local petname is now attached to B's authenticated key and surfaces in
    // `members` — the trusted replacement for the spoofable wire nick.
    match req(&a.home, Request::Members) {
        Response::Members { members } => assert!(
            members
                .iter()
                .any(|m| m.key.as_str() == b_id && m.alias == "bob"),
            "approved member should carry the local alias 'bob'"
        ),
        other => panic!("A: members returned {other:?}"),
    }

    // Approved member is no longer pending.
    if let Response::JoinRequests { requests } = req(&a.home, Request::MemberRequests) {
        assert!(
            !requests.iter().any(|r| r.key == b_id),
            "an approved member must drop out of the pending requests list"
        );
    }

    drop(a);
    drop(b);
}

/// End-to-end alias-spoofing defense: a joiner's **self-asserted** nick must never
/// resolve to their key at any trust boundary — not for `add`, not for `approve`,
/// and not even after they're a member. Only a **local alias** the admin chooses
/// resolves, and it stays glued to the authenticated key the admin approved.
#[test]
fn self_asserted_nick_never_resolves_only_admin_chosen_alias_does() {
    let a_home = tmp_home("spoof-a");
    let b_home = tmp_home("spoof-b");
    // Give B a distinct, deterministic self-asserted nick "bob" (otherwise A and B
    // share the same OS-username default nick on one machine). This is exactly the
    // spoofable wire nick whose resolution we're proving is disabled.
    set_nick(&b_home, "bob");
    found_home(&a_home);
    let a = spawn_daemon(&a_home);

    // A (the founder) adds a project; B bootstraps from A's ticket, then
    // connects, announcing the self-asserted nick "bob".
    assert!(matches!(
        req(
            &a.home,
            Request::ProjectNew {
                name: "Engineering".into(),
                key: "ENG".into(),
            }
        ),
        Response::Ref { .. }
    ));
    let ticket = match req(
        &a.home,
        Request::Invite {
            require_approval: true,
            reusable: false,
            ttl_hours: None,
        },
    ) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
    join_home(&b_home, &ticket);
    let b = spawn_daemon(&b_home);
    assert!(
        matches!(
            req(&b.home, Request::Connect { ticket }),
            Response::Ok { .. }
        ),
        "B: connect"
    );
    let b_id = match req(&b.home, Request::Id) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("B: id returned {other:?}"),
    };

    // Wait until A sees the pending request carrying the claimed nick "bob".
    let saw = poll_until(Duration::from_secs(30), || {
        match req(&a.home, Request::MemberRequests) {
            Response::JoinRequests { requests }
                if requests.iter().any(|r| r.key == b_id && r.nick == "bob") =>
            {
                Some(())
            }
            _ => None,
        }
    });
    assert!(saw.is_some(), "A never saw B's claimed-nick join request");

    // SPOOF DEFENSE 1 — the self-asserted nick is not a resolvable ref: neither
    // `add` nor `approve` by "bob" can select B's key.
    assert!(
        matches!(
            req(
                &a.home,
                Request::MemberAdd {
                    who: "bob".into(),
                    admin: false,
                    as_name: None,
                }
            ),
            Response::Error { .. }
        ),
        "adding a member by the self-asserted wire nick must be rejected"
    );
    assert!(
        matches!(
            req(
                &a.home,
                Request::MemberApprove {
                    who: "bob".into(),
                    as_name: None,
                }
            ),
            Response::Error { .. }
        ),
        "approving by the self-asserted wire nick must be rejected"
    );

    // Approve key-first, but deliberately assign a DIFFERENT local alias ("eve")
    // than the nick B announced ("bob") — the admin owns the name↔key binding.
    assert!(
        matches!(
            req(
                &a.home,
                Request::MemberApprove {
                    who: b_id.clone(),
                    as_name: Some("eve".into()),
                }
            ),
            Response::Ok { .. }
        ),
        "A: approve B by key with the admin-chosen alias 'eve'"
    );

    // The member carries the admin-chosen alias, not the claimed nick. (A's ACL
    // add and the alias write both complete synchronously before `approve`
    // returns, so A's own view is immediately consistent — no wait needed.)
    match req(&a.home, Request::Members) {
        Response::Members { members } => assert!(
            members
                .iter()
                .any(|m| m.key.as_str() == b_id && m.alias == "eve"),
            "approved member should carry the admin-chosen alias 'eve', not 'bob'"
        ),
        other => panic!("A: members returned {other:?}"),
    }

    // SPOOF DEFENSE 2 — post-approval the split still holds: the admin-chosen alias
    // resolves to B's key, but the joiner's self-asserted nick still resolves to
    // nobody. Prove both via `assign` (which runs the same ref resolver).
    let iss = match req(
        &a.home,
        Request::IssueNew {
            title: "spoof check".into(),
            project: Some("ENG".into()),
            project_hint: None,
            assignees: vec![],
            priority: None,
            labels: vec![],
            body: None,
        },
    ) {
        Response::Ref { reff } => reff,
        other => panic!("A: issue new returned {other:?}"),
    };
    assert!(
        matches!(
            req(
                &a.home,
                Request::Assign {
                    reff: iss.clone(),
                    who: vec!["eve".into()],
                    add: true,
                }
            ),
            Response::Ref { .. }
        ),
        "assigning by the admin-chosen alias 'eve' must resolve to B's key"
    );
    assert!(
        matches!(
            req(
                &a.home,
                Request::Assign {
                    reff: iss,
                    who: vec!["bob".into()],
                    add: true,
                }
            ),
            Response::Error { .. }
        ),
        "assigning by the self-asserted wire nick 'bob' must be rejected"
    );

    drop(a);
    drop(b);
}
