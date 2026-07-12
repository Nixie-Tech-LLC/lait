//! Invite/remote ergonomics end-to-end (WS1+WS2+WS3): two real nodes exercise the
//! join-request approval flow — `members requests` surfaces an announced joiner,
//! and `members approve <nick>` resolves that nick to a key through the
//! presence-fed directory and seals them the workspace key. Also asserts the
//! `seed`/`remote` list is a structured DTO. Drives daemons over the Layer-B
//! control channel, same as `two_node_sync.rs` (never shells the CLI).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use lait::control::{request, Filter, Request, Response};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lait")
}

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Runtime::new().unwrap()
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
        .env("LAIT_IDLE_SECS", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn daemon");
    let rt = rt();
    for _ in 0..60 {
        std::thread::sleep(Duration::from_millis(500));
        if rt
            .block_on(async { request(home, &Request::Status).await })
            .is_ok()
        {
            return Daemon {
                child,
                home: home.to_path_buf(),
            };
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("daemon for {} never came online", home.display());
}

fn req(home: &Path, r: Request) -> Response {
    rt().block_on(async { request(home, &r).await })
        .unwrap_or_else(|e| Response::Error {
            message: format!("{e:#}"),
        })
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

fn poll_title(home: &Path, needle: &str, tries: u32) -> bool {
    for _ in 0..tries {
        std::thread::sleep(Duration::from_secs(2));
        if list_titles(home).iter().any(|t| t == needle) {
            return true;
        }
    }
    false
}

#[test]
fn approve_join_request_by_nick_and_seed_list_is_structured() {
    let a_home = tmp_home("a");
    let b_home = tmp_home("b");
    // Give B a distinct, deterministic nick so we can approve it by name — on one
    // machine A and B otherwise share the same OS-username default nick.
    std::fs::write(
        b_home.join("profile.json"),
        r#"{"nick":"bob","room":"default"}"#,
    )
    .unwrap();

    let a = spawn_daemon(&a_home);
    let b = spawn_daemon(&b_home);

    // WS3: the seed/remote list is a structured DTO even when empty.
    assert!(
        matches!(req(&a.home, Request::SeedList), Response::Seeds { .. }),
        "seed ls must return the structured Seeds DTO, not a text blob"
    );

    // A founds the workspace + files an issue (E2EE — B can't read until added).
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
                assignees: vec![],
                priority: Some("high".into()),
                labels: vec![],
                body: None,
            }
        ),
        Response::Ref { .. }
    ));

    // B connects — announcing a join request carrying nick "bob".
    let ticket = match req(&a.home, Request::Invite) {
        Response::Text { text } => text.trim().to_string(),
        other => panic!("A: invite returned {other:?}"),
    };
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

    // WS2: A sees B in `members requests`, carrying B's key AND nick.
    let mut saw = false;
    for _ in 0..30 {
        std::thread::sleep(Duration::from_secs(1));
        if let Response::JoinRequests { requests } = req(&a.home, Request::MemberRequests) {
            if requests.iter().any(|r| r.key == b_id) {
                assert!(
                    requests.iter().any(|r| r.nick == "bob"),
                    "the join request should carry B's announced nick"
                );
                saw = true;
                break;
            }
        }
    }
    assert!(saw, "A never saw B's join request in `members requests`");

    // WS1+WS2: approve BY NICK — resolves "bob" -> B's key via the pending dir.
    assert!(
        matches!(
            req(&a.home, Request::MemberApprove { who: "bob".into() }),
            Response::Ok { .. }
        ),
        "A: approve bob by nick"
    );

    // B converges (decrypts A's issue) — proves approve-by-nick actually added B.
    assert!(
        poll_title(&b.home, "shared from A", 40),
        "B did not converge after approve-by-nick (membership never sealed?)"
    );

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
