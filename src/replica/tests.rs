use super::*;
use crate::control::CatalogScope;
use std::sync::atomic::{AtomicU64, Ordering};

/// Drive a command that must succeed, yielding its value and what it committed.
/// Panics with the typed error rather than an opaque response, so a broken
/// setup step names itself.
fn ok<T>(r: ChangeResult<T>) -> (T, Option<DirtySet>) {
    match r {
        Ok(change) => change.into_parts(),
        Err(e) => panic!("expected the command to succeed, got: {e}"),
    }
}

/// Drive a command that must be refused, yielding the typed reason. Asserts the
/// half of validate-then-commit that the type guarantees: a refusal carries no
/// dirty set, so nothing rang.
fn refused<T: std::fmt::Debug>(r: ChangeResult<T>) -> ReplicaError {
    match r {
        Err(e) => e,
        Ok(change) => {
            let (value, dirty) = change.into_parts();
            panic!(
                "expected a refusal, got {value:?} (dirty: {})",
                dirty.is_some()
            )
        }
    }
}

/// Deterministic, Send+Sync clock/entropy: fixed ms, monotonic entropy so
/// minted ids are distinct (and canonical handles unique) without wall-clock
/// or RNG flakiness.
struct FakeClock {
    ms: u64,
    ctr: AtomicU64,
}
impl FakeClock {
    fn new(ms: u64) -> Self {
        Self {
            ms,
            ctr: AtomicU64::new(1),
        }
    }
}
impl UlidSource for FakeClock {
    fn now_ms(&self) -> u64 {
        self.ms
    }
    fn rand80(&self) -> u128 {
        self.ctr.fetch_add(1, Ordering::SeqCst) as u128
    }
}

const ME_SEED: [u8; 32] = [7u8; 32];
/// A flat-FROST rotation proposal naming `t`'s CURRENT authority, so the
/// only reason a test proposal is rejected is the thing that test is about.
fn test_proposal(
    t: &Replica,
    nonce: [u8; 16],
    k: u16,
    participants: Vec<DeviceId>,
) -> crate::dkg::KeyCeremonyProposal {
    let principals: Vec<crate::authority::PrincipalId> = participants
        .iter()
        .map(crate::authority::PrincipalId::of_device)
        .collect();
    crate::dkg::frost_rotation_proposal(
        nonce,
        k,
        principals,
        t.current_authority()
            .expect("a fresh node knows its solo authority"),
    )
}

/// Perform the custody step an indispensable arrangement requires: export a
/// portable package, verify it by reopening, and attest on the board.
fn attest_custody(node: &mut TestNode, tag: &str) {
    let path = node.home.join(format!("custody-{tag}.pkg"));
    let (resp, _) = node.replica.space_custody_export_cmd(
        path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
    );
    assert!(
        matches!(resp, Response::Ok { .. }),
        "custody export: {resp:?}"
    );
}

fn me() -> DeviceId {
    // A real ed25519 key (so the founder can seal the space key to itself).
    crypto::device_from_seed(&ME_SEED)
}

struct TestNode {
    replica: Replica,
    home: std::path::PathBuf,
}
impl Drop for TestNode {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn new_node() -> TestNode {
    new_node_as(me(), ME_SEED)
}

fn device_from_seed(seed: [u8; 32]) -> DeviceId {
    crypto::device_from_seed(&seed)
}

/// A single-device actor inception for `seed` in `t`'s space (a joiner's
/// identity, as it would ride in a JoinRequest).
fn incept_for(seed: [u8; 32], t: &Replica) -> actor::SignedEvent {
    let (ev, _) = actor::incept_single(
        &seed,
        &t.space_id,
        [seed[0]; 16],
        [seed[0] ^ 0x33; 16],
        None,
    );
    ev
}
fn actor_of(ev: &actor::SignedEvent) -> ActorId {
    ActorId::from_incept_hash(&ev.hash())
}

fn new_node_as(device: DeviceId, seed: [u8; 32]) -> TestNode {
    let home = std::env::temp_dir().join(format!(
        "gc-trk-{}-{}",
        std::process::id(),
        DocId::mint(&crate::ids::SystemUlidSource)
    ));
    std::fs::create_dir_all(&home).unwrap();
    let store = Store::open(&home).unwrap();
    // Distinct clock per node (seed-derived ms) so two nodes mint DIFFERENT
    // space ids — otherwise the deterministic clock collides them.
    let clock = FakeClock::new(1_000_000 + seed[0] as u64 * 100_000);
    // Explicit founding (no lazy mint): seeds the "Testbed" space with
    // its default TEST project, so replicas open like real founder stores.
    found_space(&store, &device, &seed, "Testbed", &clock).unwrap();
    let replica = Replica::open(store, device, "tester".into(), seed, Box::new(clock)).unwrap();
    TestNode { replica, home }
}

/// A node whose store was bootstrapped from a ticket (the `lait join` path):
/// genesis rooted on the verified founding proof `(salt, founder_inception)`,
/// empty catalog/membership awaiting sync. Obtain the proof from the founder
/// node via `founding_proof()`.
fn new_joiner_node_as(
    device: DeviceId,
    seed: [u8; 32],
    ws: &str,
    proof: &([u8; 16], [u8; 32], actor::SignedEvent),
) -> TestNode {
    let home = std::env::temp_dir().join(format!(
        "gc-trk-{}-{}",
        std::process::id(),
        DocId::mint(&crate::ids::SystemUlidSource)
    ));
    std::fs::create_dir_all(&home).unwrap();
    let store = Store::open(&home).unwrap();
    join_space_store(&store, ws, &proof.0, &proof.1, &proof.2).unwrap();
    let clock = FakeClock::new(1_000_000 + seed[0] as u64 * 100_000);
    let replica = Replica::open(store, device, "tester".into(), seed, Box::new(clock)).unwrap();
    TestNode { replica, home }
}

/// Create a project + return its key.
fn with_project(t: &mut Replica) -> String {
    let (resp, _) = t.handle(Request::ProjectNew {
        name: "Engineering".into(),
        key: "ENG".into(),
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    "ENG".to_string()
}

fn new_issue(t: &mut Replica, title: &str) -> String {
    let (resp, dirty) = t.handle(Request::IssueNew {
        title: title.into(),
        project: Some("ENG".into()),
        project_hint: None,
        assignees: vec![],
        priority: None,
        labels: vec![],
        body: None,
    });
    assert!(dirty.is_some(), "a create must ring a doorbell");
    match resp {
        Response::Ref { reff } => reff,
        other => panic!("expected Ref, got {other:?}"),
    }
}

#[test]
fn issue_view_preserves_ambiguous_and_near_miss_candidates() {
    let mut node = new_node();
    with_project(&mut node.replica);
    new_issue(&mut node.replica, "first candidate");
    new_issue(&mut node.replica, "second candidate");

    // A deliberately short DocId prefix matches both issues. This exercises
    // RefResolution::Many -> RefError::Candidates -> Response::Candidates at
    // the dispatch boundary, including the "ambiguous" marker.
    let (ambiguous, dirty) = node.replica.handle(Request::IssueView {
        reff: "iss_".into(),
    });
    assert!(dirty.is_none(), "a failed read must not ring a doorbell");
    match ambiguous {
        Response::Candidates {
            candidates,
            near_miss_for,
        } => {
            assert_eq!(near_miss_for, None, "an ambiguous ref is not a typo");
            assert_eq!(candidates.len(), 2, "both matching issues must be offered");
            let aliases: Vec<_> = candidates
                .iter()
                .filter_map(|candidate| candidate.key_alias.as_deref())
                .collect();
            assert!(aliases.contains(&"ENG-1"), "missing ENG-1: {candidates:?}");
            assert!(aliases.contains(&"ENG-2"), "missing ENG-2: {candidates:?}");
        }
        other => panic!("ambiguous issue ref must yield Candidates, got {other:?}"),
    }

    // ENG-3 matches nothing but is one edit from the two real aliases. This
    // takes the distinct Zero + near-misses path and must retain the original
    // typo so the CLI renders its "did you mean" form.
    let (near_miss, dirty) = node.replica.handle(Request::IssueView {
        reff: "ENG-3".into(),
    });
    assert!(dirty.is_none(), "a failed read must not ring a doorbell");
    match near_miss {
        Response::Candidates {
            candidates,
            near_miss_for,
        } => {
            assert_eq!(near_miss_for.as_deref(), Some("ENG-3"));
            let aliases: Vec<_> = candidates
                .iter()
                .filter_map(|candidate| candidate.key_alias.as_deref())
                .collect();
            assert!(aliases.contains(&"ENG-1"), "missing ENG-1: {candidates:?}");
            assert!(aliases.contains(&"ENG-2"), "missing ENG-2: {candidates:?}");
        }
        other => panic!("near-miss issue ref must yield Candidates, got {other:?}"),
    }
}

/// Perf harness (run: `GC_PERF_N=5000 cargo test --release -p lait --lib
/// perf_seed_and_cold_load -- --ignored --nocapture`). Proves/refutes the
/// scaling claims: cold-load is O(issues) (loads every doc), board/list reads
/// are O(catalog) (must stay flat as issue count grows).
#[test]
#[ignore]
fn perf_seed_and_cold_load() {
    use std::time::Instant;
    let n: usize = std::env::var("GC_PERF_N")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5000);
    let home = std::env::temp_dir().join(format!(
        "gc-perf-{}-{}",
        std::process::id(),
        DocId::mint(&crate::ids::SystemUlidSource)
    ));
    std::fs::create_dir_all(&home).unwrap();

    // --- seed N issues through the real Request path ---
    // Git snapshotting is deferred off the mutation path (mark_dirty), so the
    // seed measures the replica/store cost WITHOUT a `git add -A` per create;
    // the whole batch is committed by one explicit `checkpoint` afterwards.
    let t0 = Instant::now();
    let checkpoint;
    {
        let store = Store::open(&home).unwrap();
        let clock = FakeClock::new(1_000_000);
        let mut t = Replica::open(store, me(), "perf".into(), ME_SEED, Box::new(clock)).unwrap();
        with_project(&mut t);
        for i in 0..n {
            let (resp, dirty) = t.handle(Request::IssueNew {
                title: format!("issue {i}"),
                project: Some("ENG".into()),
                project_hint: None,
                assignees: vec![],
                priority: None,
                labels: vec![],
                body: None,
            });
            assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
            assert!(dirty.is_some());
        }
        // One coalesced git commit for all N creates (the daemon does this on
        // a periodic tick; here we drive it explicitly to measure it).
        let c0 = Instant::now();
        t.checkpoint();
        checkpoint = c0.elapsed();
    }
    let seed = t0.elapsed();
    let store_bytes = fs_dir_size(&home);

    // --- cold-load: reopen the store (recompute_all_rows loads every doc) ---
    let t1 = Instant::now();
    let store = Store::open(&home).unwrap();
    let clock = FakeClock::new(1_000_000);
    let mut t = Replica::open(store, me(), "perf".into(), ME_SEED, Box::new(clock)).unwrap();
    let cold_load = t1.elapsed();
    assert_eq!(t.issue_count(), n, "all seeded issues must be present");

    // --- board latency (catalog-only read; must be flat vs n) ---
    let k = 50u32;
    let tb = Instant::now();
    for _ in 0..k {
        let (r, _) = t.handle(Request::Board {
            project: Some("ENG".into()),
            project_hint: None,
        });
        assert!(matches!(r, Response::Board(_)), "{r:?}");
    }
    let board_avg = tb.elapsed() / k;

    // --- list latency (catalog-only read) ---
    let tl = Instant::now();
    for _ in 0..k {
        let (r, _) = t.handle(Request::List {
            project: Some("ENG".into()),
            filter: Filter::default(),
        });
        assert!(matches!(r, Response::List { .. }), "{r:?}");
    }
    let list_avg = tl.elapsed() / k;

    // --- catalog VV-diff export cost (sync phase-1 whole-catalog cost) ---
    let empty_vv: Vec<u8> = vec![];
    let tc = Instant::now();
    let cat_diff = t.export_catalog_from(&empty_vv).unwrap();
    let catalog_export = tc.elapsed();

    println!(
        "PERF n={n} seed={seed:?} checkpoint={checkpoint:?} store={store_kb}KB \
         cold_load={cold_load:?} board_avg={board_avg:?} list_avg={list_avg:?} \
         catalog_full_export={catalog_export:?} catalog_bytes={cat_bytes}",
        store_kb = store_bytes / 1024,
        cat_bytes = cat_diff.len(),
    );
    std::fs::remove_dir_all(&home).ok();
}

fn fs_dir_size(p: &std::path::Path) -> u64 {
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let md = e.metadata();
            if let Ok(md) = md {
                if md.is_dir() {
                    total += fs_dir_size(&e.path());
                } else {
                    total += md.len();
                }
            }
        }
    }
    total
}

#[test]
fn validate_then_commit_rejects_before_any_change() {
    // A rejected write returns Error, rings NO doorbell, and changes nothing
    // making an optimistic rollback race-free.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "fix login");
    let before_head = n.replica.row_head_for(&reff);

    // bad status → Error, no dirty-set (no doorbell), state untouched.
    let (resp, dirty) = n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("nonsense_status".into()),
        priority: None,
        description: None,
    });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
    assert!(dirty.is_none(), "a rejected write must ring no doorbell");
    assert_eq!(
        n.replica.row_head_for(&reff),
        before_head,
        "a rejected write must not move the issue head"
    );

    // an unknown ref also errors with no doorbell.
    let (resp, dirty) = n.replica.handle(Request::IssueEdit {
        reff: "iss_zzzzzzz".into(),
        title: Some("x".into()),
        status: None,
        priority: None,
        description: None,
    });
    assert!(matches!(resp, Response::Error { .. }));
    assert!(dirty.is_none());
}

#[test]
fn one_request_is_one_activity_row_even_multi_field() {
    // A single IssueEdit moving several fields produces one activity row.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "t");
    let before = n.replica.activity_high_water();
    let (resp, _) = n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: Some("t2".into()),
        status: Some("in_progress".into()),
        priority: Some("high".into()),
        description: None,
    });
    assert!(matches!(resp, Response::Ref { .. }));
    assert_eq!(
        n.replica.activity_high_water() - before,
        1,
        "multi-field edit is one commit is one activity row"
    );
    // and that row carries all three field changes.
    if let Response::Activity { events, .. } = n.replica.handle(Request::History { reff }).0 {
        let last = events.last().unwrap();
        assert_eq!(last.changes.len(), 3);
    } else {
        panic!("expected activity");
    }
}

#[test]
fn writer_direction_row_follows_issue_doc() {
    // The DocMeta row is recomputed from the issue document on every edit.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "orig");
    n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: Some("changed".into()),
        status: Some("in_progress".into()),
        priority: None,
        description: None,
    });
    let rows = match n
        .replica
        .handle(Request::List {
            project: Some("ENG".into()),
            filter: Filter::default(),
        })
        .0
    {
        Response::List { rows } => rows,
        other => panic!("{other:?}"),
    };
    let row = rows.iter().find(|r| r.reff == reff).unwrap();
    assert_eq!(row.title, "changed");
    assert_eq!(row.status, "in_progress");
}

#[test]
fn load_time_head_recompute_self_heals_stale_row() {
    // A crash between the issue commit and the head mirror leaves a
    // stale head; on reopen the replica recomputes it from the real issue
    // frontiers. Simulate by editing the issue doc + saving it WITHOUT
    // updating the catalog row, then reopening.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "heal me");
    let stale_head = n.replica.row_head_for(&reff).unwrap();

    // Reach into the store: mutate the issue doc and save it, but do NOT
    // touch the catalog (the "crash between two docs" window).
    let store = Store::open(&n.home).unwrap();
    let ids = store.issue_doc_ids();
    let issue = store.load_issue(&ids[0]).unwrap().unwrap();
    issue.set_title("healed on disk").unwrap();
    issue.apply(&OpCtx::content("edited", &me()));
    store.save_issue(&issue).unwrap();
    let real_head = issue.head_hash();
    assert_ne!(real_head, stale_head, "precondition: the head moved");

    // Reopen the replica — recompute_all_rows must reconcile the row.
    let store2 = Store::open(&n.home).unwrap();
    let mut t2 = Replica::open(
        store2,
        me(),
        "tester".into(),
        ME_SEED,
        Box::new(FakeClock::new(1_000_000)),
    )
    .unwrap();
    assert_eq!(
        t2.row_head_for(&reff),
        Some(real_head),
        "load-time recompute must heal the stale head"
    );
    assert_eq!(t2.issue_head_for(&reff), t2.row_head_for(&reff));
}

#[test]
fn project_move_is_single_membership_with_self_healing_boards() {
    // Issue.projectId is the single source of project membership; board lists
    // self-heal. Moving A from ENG to OPS leaves it in exactly one board.
    let mut n = new_node();
    with_project(&mut n.replica);
    n.replica.handle(Request::ProjectNew {
        name: "Operations".into(),
        key: "OPS".into(),
    });
    let reff = new_issue(&mut n.replica, "movable");

    let (resp, dirty) = n.replica.handle(Request::IssueMove {
        reff: reff.clone(),
        project: Some("OPS".into()),
        pos: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    // the doorbell dirties BOTH boards (old + new).
    let scopes = dirty.unwrap().dirty_catalog;
    assert!(
        scopes
            .iter()
            .filter(|s| matches!(s, CatalogScope::Boards { .. }))
            .count()
            >= 2,
        "a cross-project move dirties both boards: {scopes:?}"
    );

    // ENG board no longer lists it; OPS board does; exactly one membership.
    let eng = board_reffs(&mut n.replica, "ENG");
    let ops = board_reffs(&mut n.replica, "OPS");
    assert!(!eng.contains(&reff), "old project board must drop it");
    assert!(ops.contains(&reff), "new project board must list it");

    // Regression guard for the incremental alias upkeep: a project move
    // changes projectId, so the `KEY-n` alias must re-group ENG-1 → OPS-1
    // (with only incremental `reconcile_doc` on the edit tail, a stale table
    // would keep showing ENG-1 on the OPS board row).
    let ops_aliases = board_key_aliases(&mut n.replica, "OPS");
    assert!(
        ops_aliases.contains(&"OPS-1".to_string()),
        "moved issue's alias must re-group to the new project: {ops_aliases:?}"
    );
}

fn board_key_aliases(t: &mut Replica, project: &str) -> Vec<String> {
    match t
        .handle(Request::Board {
            project: Some(project.into()),
            project_hint: None,
        })
        .0
    {
        Response::Board(b) => b
            .columns
            .iter()
            .flat_map(|c| c.rows.iter().filter_map(|r| r.key_alias.clone()))
            .collect(),
        other => panic!("{other:?}"),
    }
}

fn board_reffs(t: &mut Replica, project: &str) -> Vec<String> {
    match t
        .handle(Request::Board {
            project: Some(project.into()),
            project_hint: None,
        })
        .0
    {
        Response::Board(b) => b
            .columns
            .iter()
            .flat_map(|c| c.rows.iter().map(|r| r.reff.clone()))
            .collect(),
        other => panic!("{other:?}"),
    }
}

/// In-process E2EE: a non-member can't decrypt; after `member_add` + a
/// membership sync the added member unseals the key and decrypts the catalog
/// + issue docs; after `member_remove` + rotation new content is unreadable.
fn sync_membership(from: &mut Replica, to: &mut Replica) {
    let vv = to.membership_vv_bytes();
    let upd = from.export_membership_from(&vv).unwrap();
    to.import_membership(&upd).unwrap();
}
fn sync_all(from: &mut Replica, to: &mut Replica) {
    sync_membership(from, to);
    let cvv = to.catalog_vv_bytes();
    let cupd = from.export_catalog_from(&cvv).unwrap();
    let needs = to.import_catalog_and_compute_needs(&cupd).unwrap();
    for need in needs {
        if let Ok(Some(bytes)) = from.export_doc_from(&need.doc_id, &need.vv) {
            to.import_doc(&need.doc_id, &bytes).unwrap();
        }
    }
}
/// Sync every ordered pair, `rounds` times. Nodes left out of the slice are
/// genuinely absent: ceremonies advance on import, so a node that never
/// syncs never contributes.
fn sync_mesh(nodes: &mut [TestNode], rounds: usize) {
    let n = nodes.len();
    for _ in 0..rounds {
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                let (from, to) = if i < j {
                    let (l, r) = nodes.split_at_mut(j);
                    (&mut l[i], &mut r[0])
                } else {
                    let (l, r) = nodes.split_at_mut(i);
                    (&mut r[0], &mut l[j])
                };
                sync_all(&mut from.replica, &mut to.replica);
            }
        }
    }
}

fn titles(t: &mut Replica) -> Vec<String> {
    match t
        .handle(Request::List {
            project: None,
            filter: Filter::default(),
        })
        .0
    {
        Response::List { rows } => rows.into_iter().map(|r| r.title).collect(),
        _ => Vec::new(),
    }
}

#[test]
fn recover_resets_device_set_with_the_offline_key() {
    let mut a = new_node(); // founder, recovery.key provisioned beside the store
    let x = a.replica.my_actor().unwrap();
    let da = a.replica.me.clone();

    // Add a second device dB.
    let db_seed = [60u8; 32];
    let db = device_from_seed(db_seed);
    let binding = actor::consent_sign(
        &db_seed,
        &a.replica.space_str(),
        [61u8; 16],
        &actor::ConsentCtx::Member { actor: &x },
    );
    let hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());
    a.replica.device_add_cmd(hex);
    assert!(a.replica.actor_plane().is_device_of(&x, &db));

    // Recover with the offline key: device set resets to just this device.
    let (resp, _) = a.replica.recover();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let devices = a.replica.actor_plane().devices_of(&x);
    assert_eq!(devices, vec![da], "recovery reset the set to this device");
    assert!(a.replica.actor_plane().state(&x).unwrap().recovered);
}

#[test]
fn fresh_device_recovers_and_decrypts_after_peer_reseal() {
    // The real recovery scenario: a brand-new device that was NEVER enrolled
    // restores the offline recovery key, recovers the founder actor (resolved
    // by its pre-rotation commitment, not by any device it holds), and — after
    // a key-holding peer syncs and re-seals — decrypts the existing content.
    let mut a = new_node(); // founder dA, recovery.key beside its store
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let x = a.replica.my_actor().unwrap();
    let a_ws = a.replica.space_str();

    // A fresh device dC bootstraps on X's space from a ticket. It is not a
    // device of any actor and holds no key.
    let c_seed = [70u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(
        c_device.clone(),
        c_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );

    // dC learns the actor plane (X's inception + recovery commitment) and the
    // encrypted catalog, but cannot read it — no key, no membership.
    sync_all(&mut a.replica, &mut c.replica);
    assert_eq!(c.replica.my_actor(), None, "dC is not yet any actor");
    assert!(
        !titles(&mut c.replica).contains(&"secret".to_string()),
        "a keyless fresh device cannot read the space"
    );

    // A keyless device with an active epoch must NEVER serve cleartext.
    let empty_vv = c.replica.catalog_vv_bytes();
    // (self-export from an empty vv would be the whole catalog, in clear, if
    // the leak were present)
    assert!(
        c.replica.export_catalog_from(&empty_vv).unwrap().is_empty(),
        "a device that cannot encrypt under the active epoch serves nothing"
    );

    // Restore the offline recovery key beside dC's store and recover.
    let key = std::fs::read(a.home.join("recovery.key")).unwrap();
    std::fs::write(c.home.join("recovery.key"), key).unwrap();
    let (resp, _) = c.replica.recover();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert_eq!(
        c.replica.actor_plane().devices_of(&x),
        vec![c_device.clone()],
        "recovery reset X's device set to the fresh device"
    );
    assert_eq!(
        c.replica.my_actor(),
        Some(x.clone()),
        "dC now resolves to the recovered actor X"
    );
    // Still no key — recovery reset the identity, not the content access.
    assert!(!titles(&mut c.replica).contains(&"secret".to_string()));

    // dC pushes its recovery to A; A (still holding the key) re-seals the
    // active epoch to dC as part of importing the Recover.
    sync_all(&mut c.replica, &mut a.replica);
    // A pushes the freshly sealed envelope + catalog back to dC.
    sync_all(&mut a.replica, &mut c.replica);
    assert!(
        titles(&mut c.replica).contains(&"secret".to_string()),
        "recovered fresh device decrypts once a peer re-seals the epoch"
    );
}

#[test]
fn second_device_decrypts_then_revocation_fences_it() {
    // Multi-device end to end: A adds a second device dB to its actor (seal-
    // on-add), dB decrypts the space; A then revokes dB and rotates, and
    // dB is fenced from post-revocation content.
    let mut a = new_node(); // founder, device dA
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let x = a.replica.my_actor().unwrap(); // the founder actor
    let a_ws = a.replica.space_str();

    // dB (seed 50) consents into actor X (as `device accept` would).
    let db_seed = [50u8; 32];
    let db_device = device_from_seed(db_seed);
    let binding = actor::consent_sign(
        &db_seed,
        &a_ws,
        [51u8; 16],
        &actor::ConsentCtx::Member { actor: &x },
    );
    let consent_hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());

    // A adds dB.
    let (resp, _) = a.replica.device_add_cmd(consent_hex);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert!(
        a.replica.actor_plane().is_device_of(&x, &db_device),
        "dB is now a device of X"
    );

    // dB bootstraps its own store on X's space and syncs — it is the SAME
    // actor (the founder), so it unseals the key and decrypts.
    let mut b = new_joiner_node_as(
        db_device.clone(),
        db_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    sync_all(&mut a.replica, &mut b.replica);
    assert_eq!(
        b.replica.my_actor(),
        Some(x.clone()),
        "dB resolves to actor X"
    );
    assert!(
        titles(&mut b.replica).contains(&"secret".to_string()),
        "second device decrypts the space (seal-on-add)"
    );

    // A revokes dB and rotates; dB loses future content.
    let (resp, _) = a.replica.device_revoke_cmd(db_device.as_str().to_string());
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert!(
        !a.replica.actor_plane().is_device_of(&x, &db_device),
        "dB revoked from X"
    );
    new_issue(&mut a.replica, "after-revoke");
    sync_all(&mut a.replica, &mut b.replica);
    assert!(
        !titles(&mut b.replica).iter().any(|t| t == "after-revoke"),
        "a revoked device is fenced from post-revocation content"
    );
}

#[test]
fn single_use_invite_admits_exactly_one_actor_under_concurrency() {
    // Two admins concurrently redeem the same single-use
    // invite for different actors; after merge exactly one is admitted, and
    // both replicas agree (nonce bound into the op + deterministic dedup).
    let mut a = new_node(); // founder/admin
    let a_ws = a.replica.space_str();

    let mut b = new_joiner_node_as(
        device_from_seed([2; 32]),
        [2; 32],
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    assert!(b.replica.am_i_admin());

    let nonce = [7u8; 16];
    let j1 = incept_for([8; 32], &a.replica);
    let j2 = incept_for([9; 32], &a.replica);
    let j1a = actor_of(&j1);
    let j2a = actor_of(&j2);
    let issuer = a.replica.me.clone(); // an admin's device signed the invite

    // Concurrent redemptions on the two un-merged admins.
    ok(a.replica.redeem_invite(&issuer, &j1, &nonce, true));
    ok(b.replica.redeem_invite(&issuer, &j2, &nonce, true));

    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut b.replica, &mut a.replica);

    let a1 = a.replica.is_member_actor(&j1a);
    let a2 = a.replica.is_member_actor(&j2a);
    let b1 = b.replica.is_member_actor(&j1a);
    let b2 = b.replica.is_member_actor(&j2a);
    assert_eq!((a1, a2), (b1, b2), "both replicas agree on the winner");
    assert!(a1 ^ a2, "a single-use invite admits exactly one actor");
}

#[test]
fn concurrent_rotations_converge_and_fence() {
    // Two admins remove different members concurrently, each
    // rotating the key. Content-addressed epochs + the heal on merge must
    // converge (both admins read post-heal content) and fence both removed
    // members — no split-brain undecryptable key.
    let mut a = new_node(); // founder/admin
    with_project(&mut a.replica);
    let a_ws = a.replica.space_str();

    let mut b = new_joiner_node_as(
        device_from_seed([2; 32]),
        [2; 32],
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let mut c = new_joiner_node_as(
        device_from_seed([3; 32]),
        [3; 32],
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let mut d = new_joiner_node_as(
        device_from_seed([4; 32]),
        [4; 32],
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    let c_incept = c.replica.self_inception().unwrap();
    let d_incept = d.replica.self_inception().unwrap();
    let c_actor = actor_of(&c_incept);
    let d_actor = actor_of(&d_incept);

    // B is a second admin; C and D are members.
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    ok(a.replica.admit_member(&c_incept, vec![Grant::Write]));
    ok(a.replica.admit_member(&d_incept, vec![Grant::Write]));
    for n in [&mut b, &mut c, &mut d] {
        sync_all(&mut a.replica, &mut n.replica);
    }
    assert!(b.replica.am_i_admin(), "B synced admin standing");

    // Concurrent removals (no sync between): A removes C, B removes D. Each
    // rotates locally to a fresh content-addressed epoch.
    ok(a.replica.member_remove(&c_actor));
    ok(b.replica.member_remove(&d_actor));

    // Merge both ways + a settling round so the heal epoch propagates.
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut b.replica, &mut a.replica);
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut b.replica, &mut a.replica);

    // The active epoch converged (both admins agree) — no key split-brain.
    assert_eq!(
        a.replica.active_epoch().map(|e| e.id),
        b.replica.active_epoch().map(|e| e.id),
        "admins converge on one active epoch after concurrent rotations"
    );

    // Post-heal content is written under the fenced tip and is readable by
    // both surviving admins but not by either removed member.
    new_issue(&mut a.replica, "afterHeal");
    sync_all(&mut a.replica, &mut b.replica);
    assert!(
        titles(&mut a.replica).contains(&"afterHeal".to_string()),
        "A reads post-heal content"
    );
    assert!(
        titles(&mut b.replica).contains(&"afterHeal".to_string()),
        "B reads post-heal content (no split-brain key)"
    );
    sync_all(&mut a.replica, &mut c.replica);
    sync_all(&mut a.replica, &mut d.replica);
    assert!(
        !titles(&mut c.replica).iter().any(|t| t == "afterHeal"),
        "removed C is fenced from post-heal content"
    );
    assert!(
        !titles(&mut d.replica).iter().any(|t| t == "afterHeal"),
        "removed D is fenced from post-heal content"
    );
}

#[test]
fn e2ee_membership_gates_decryption() {
    let mut a = new_node(); // founder + admin
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret issue");

    let b_seed = [8u8; 32];
    let b_device = device_from_seed(b_seed);
    let a_ws = a.replica.space_str();
    // B's store is bootstrapped from the ticket (the `lait join` path).
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    assert_eq!(b.replica.space_str(), a_ws, "B is rooted on A's space");

    // Before add: B syncs but cannot decrypt — sees only ciphertext.
    sync_all(&mut a.replica, &mut b.replica);
    assert!(
        titles(&mut b.replica).is_empty(),
        "non-member decrypts nothing"
    );
    assert!(!b.replica.am_i_member());

    // A adds B → B syncs membership, unseals the key, decrypts everything.
    // B's inception rides to A (here: passed directly, as a JoinRequest would).
    let b_incept = b.replica.self_inception().unwrap();
    let b_actor = actor_of(&b_incept);
    ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    assert!(b.replica.am_i_member(), "B is now a member");
    assert_eq!(
        titles(&mut b.replica),
        vec!["secret issue".to_string()],
        "B decrypts"
    );

    // A removes B + rotates; new content is encrypted under an epoch B lacks.
    ok(a.replica.member_remove(&b_actor));
    new_issue(&mut a.replica, "post-removal");
    sync_all(&mut a.replica, &mut b.replica);
    assert!(
        !titles(&mut b.replica).iter().any(|t| t == "post-removal"),
        "lazy revocation: removed member can't read post-removal content"
    );
}

#[test]
fn a_viewer_reads_but_is_refused_writes_until_granted() {
    // The view-only member end to end: B is admitted with EMPTY grants, syncs
    // and decrypts (reads), but every content write is refused until an admin
    // grants Write — then the identical write succeeds.
    let mut a = new_node(); // founder/admin
    let proj = with_project(&mut a.replica);
    new_issue(&mut a.replica, "existing");
    let a_ws = a.replica.space_str();

    let b_seed = [12u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device,
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    let b_actor = actor_of(&b_incept);

    // Admit B as a VIEWER (no grants), then sync.
    ok(a.replica.admit_member(&b_incept, vec![]));
    sync_all(&mut a.replica, &mut b.replica);
    assert!(b.replica.am_i_member(), "a viewer is a member");
    assert_eq!(
        b.replica.acl_state().standing(&b_actor),
        Some("viewer"),
        "empty grants ⇒ viewer standing"
    );
    // Reads work: the viewer decrypts existing content.
    assert!(
        titles(&mut b.replica).contains(&"existing".to_string()),
        "a viewer decrypts and reads the space"
    );

    // Writes are refused, and nothing is committed (no dirty-set).
    let write = |title: &str| Request::IssueNew {
        title: title.into(),
        project: Some(proj.clone()),
        project_hint: None,
        assignees: vec![],
        priority: None,
        labels: vec![],
        body: None,
    };
    let (resp, dirty) = b.replica.handle(write("sneaky"));
    assert!(
        matches!(resp, Response::Error { .. }) && dirty.is_none(),
        "a viewer's write is refused with no commit: {resp:?}"
    );

    // Admin grants B Write; the same write now succeeds.
    ok(a.replica
        .member_add(&b_actor, vec![Grant::Admin, Grant::Write]));
    // member_add re-grant is authored against the *actor* frontier; grant
    // Write specifically (Admin+Write here) and sync so B sees its new grant.
    sync_all(&mut a.replica, &mut b.replica);
    assert!(b.replica.can_write_now(), "B now holds write standing");
    let (resp, dirty) = b.replica.handle(write("now allowed"));
    assert!(
        matches!(resp, Response::Ref { .. }) && dirty.is_some(),
        "a granted member's write succeeds: {resp:?}"
    );
}

#[test]
fn injected_epoch_without_an_authorized_mint_is_never_adopted() {
    // Regression for the unauthenticated-epoch hijack. An attacker on the
    // space topic pushes a membership diff that injects a HIGHER-gen epoch
    // — a FORGED MintEpoch signed by an actor it self-incepted (so the
    // device→actor binding resolves) but that is NOT a member/writer, plus a
    // sealed envelope carrying an attacker-chosen key. Because the mint fails
    // the write-standing check in acl::replay, the epoch is never authorized,
    // so the victim never selects it and never adopts the attacker's key.
    use crate::membership::MembershipDoc;
    let mut a = new_node(); // founder/admin (victim)
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let victim_dev = a.replica.me.clone();
    let victim_actor = a.replica.my_actor().unwrap();
    let ws = a.replica.space_id().clone();
    let legit_epoch = a.replica.active_epoch().unwrap().id;
    let a_vv = a.replica.membership_vv_bytes();

    // Attacker self-incepts an actor that never joined, then forges the mint.
    let atk_seed = [0x33u8; 32];
    let atk_dev = device_from_seed(atk_seed);
    let (atk_incept, atk_actor) =
        actor::incept_single(&atk_seed, &ws, [0x44u8; 16], [0x45u8; 16], None);
    let attacker_key = crate::crypto::random_key(); // the attacker knows this
    let poison_id = [0xEEu8; 16];
    let key_commit = *blake3::hash(&attacker_key).as_bytes();

    let evil = MembershipDoc::empty(None);
    evil.import(&a.replica.export_membership_from(&[]).unwrap())
        .unwrap();
    evil.add_actor_event(&atk_incept).unwrap();
    let forged_mint = acl::sign_op(
        &atk_seed,
        &AclOp {
            action: AclAction::MintEpoch {
                id: poison_id,
                gen: 9999, // far above the legit tip — would win IF authorized
                key_commit,
                members: vec![victim_actor.clone()],
            },
            by: atk_actor.clone(),
            actor_asof: vec![atk_incept.hash()],
            nonce: None,
        },
        evil.heads(),
        &ws,
    );
    evil.add_op(&forged_mint).unwrap();
    let sealed = crate::crypto::seal_to(&victim_dev, &attacker_key).unwrap();
    evil.put_sealed(&poison_id, &victim_dev, &sealed).unwrap();
    evil.apply(&crate::fabric::op::OpCtx::authority("poison", &atk_dev));
    let diff = evil.export_from_bytes(&a_vv).unwrap();

    // Victim imports it over sync (import_membership is ungated by design).
    a.replica.import_membership(&diff).unwrap();

    // The forged epoch is NOT authorized, so it is never the active tip...
    assert_eq!(
        a.replica.active_epoch().map(|e| e.id),
        Some(legit_epoch),
        "an injected epoch with no authorized mint must never be selected"
    );
    // ...and new content stays under the legit key — the attacker cannot read.
    new_issue(&mut a.replica, "STILL-SECRET-after-injection");
    let export = a.replica.export_catalog_from(&[]).unwrap();
    let (_id, ct) = export.split_at(16);
    assert!(
        crate::crypto::aead_decrypt(&attacker_key, ct).is_none(),
        "the attacker's key must not decrypt the victim's content"
    );
}

#[test]
fn heal_supersedes_the_epoch_of_a_removed_minter() {
    // Backstop for the revocation bypass (a minter controls its epoch's
    // recipient list and key): if the active epoch was minted by an actor who
    // is later removed, an admin's heal re-keys it, so the departed member's
    // key never lingers as the live tip.
    let mut a = new_node(); // founder/admin A
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let a_actor = a.replica.my_actor().unwrap();
    let a_ws = a.replica.space_str();

    // B joins, is admitted as an ADMIN, and syncs.
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    let b_actor = actor_of(&b_incept);
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    // B (admin) rotates the key: the active epoch is now minted by B.
    ok(b.replica.key_rotate_cmd());
    sync_all(&mut b.replica, &mut a.replica);
    assert_eq!(
        a.replica.active_epoch().unwrap().minted_by,
        b_actor,
        "the active epoch was minted by B"
    );

    // A removes B WITHOUT the auto-rotation (author the op directly), leaving
    // B's epoch as the active tip — the concurrent-race residual heal guards.
    let rm = a
        .replica
        .author_acl(AclAction::RemoveMember {
            actor: b_actor.clone(),
        })
        .unwrap();
    a.replica.membership.add_op(&rm).unwrap();
    a.replica
        .persist_membership("test_remove_no_rotate")
        .unwrap();
    assert!(!a.replica.acl_state().is_member(&b_actor), "B is removed");
    assert_eq!(
        a.replica.active_epoch().unwrap().minted_by,
        b_actor,
        "B's epoch is still the tip before heal"
    );

    // Heal: A sees the tip was minted by a non-member and re-keys.
    a.replica.heal_epoch().unwrap();
    let healed = a.replica.active_epoch().unwrap();
    assert_eq!(healed.minted_by, a_actor, "A re-keyed the tip away from B");
    assert!(
        !a.replica
            .membership
            .sealed_devices(&healed.id)
            .contains(&b_device),
        "the healed epoch is not sealed to the removed member's device"
    );
}

#[test]
fn a_non_admin_device_revoke_is_honest_about_pending_rotation() {
    // A non-admin can de-list its own device but cannot mint the key rotation
    // that fences it, so the command says the rotation is pending an admin
    // rather than claiming a rotation that would be inert.
    let mut a = new_node(); // founder/admin
    let a_ws = a.replica.space_str();

    // B joins as a plain WRITER (no admin).
    let b_seed = [41u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device,
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    let b_actor = actor_of(&b_incept);
    ok(a.replica.admit_member(&b_incept, vec![Grant::Write])); // writer, not admin
    sync_all(&mut a.replica, &mut b.replica);

    // B adds a second device so it has one to revoke.
    let b2_seed = [42u8; 32];
    let b2_device = device_from_seed(b2_seed);
    let binding = actor::consent_sign(
        &b2_seed,
        &a_ws,
        [43u8; 16],
        &actor::ConsentCtx::Member { actor: &b_actor },
    );
    let hex = data_encoding::HEXLOWER.encode(&postcard::to_stdvec(&binding).unwrap());
    let (resp, _) = b.replica.device_add_cmd(hex);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

    let gen_before = b.replica.active_epoch().map(|e| e.gen);
    // B (non-admin) revokes its second device.
    let (resp, _) = b.replica.device_revoke_cmd(b2_device.as_str().to_string());
    match resp {
        Response::Ok { message: Some(m) } => {
            assert!(
                m.contains("admin"),
                "expected a pending-rotation notice: {m}"
            )
        }
        other => panic!("expected Ok with a pending-rotation notice, got {other:?}"),
    }
    // The device is de-listed, but a non-admin's mint is inert: no rotation.
    assert!(
        !b.replica.actor_plane().is_device_of(&b_actor, &b2_device),
        "the second device is de-listed"
    );
    assert_eq!(
        b.replica.active_epoch().map(|e| e.gen),
        gen_before,
        "a non-admin cannot rotate the key"
    );
}

#[test]
fn a_non_founder_invite_roots_the_joiner_on_the_true_founder() {
    // Fork guard: a ticket must anchor on the space's founding actor, not
    // the inviter. A joiner roots acl::replay on the ticket's founder, so an
    // inviter-anchored ticket would fork the joiner onto a genesis where the
    // real founder — and the founding key-epoch — carry no authority.
    let mut a = new_node(); // founder A
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "founders-secret");
    let a_actor = a.replica.my_actor().unwrap();
    let a_ws = a.replica.space_str();

    // B joins rooted on A (as A's ticket would), admitted admin, and syncs.
    let b_seed = [51u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device,
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    let b_actor = actor_of(&b_incept);
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    assert!(b.replica.am_i_member());
    // The fix: B (a non-founder) anchors an invite on the FOUNDER, not itself.
    assert_eq!(
        b.replica.founding_actor(),
        Some(a_actor.clone()),
        "a joiner anchors on the true founder"
    );
    assert_ne!(
        b.replica.founding_actor(),
        Some(b_actor.clone()),
        "never on the inviter"
    );

    // C joins on the founding proof B would ship (which is A's, not B's), is
    // admitted by B, and syncs through B. Rooted on A, C converges — sees the
    // founder's authority AND adopts the founder's key-epoch to read content.
    let c_seed = [52u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(
        c_device,
        c_seed,
        &a_ws,
        &b.replica.founding_proof().unwrap(),
    );
    let c_incept = c.replica.self_inception().unwrap();
    ok(b.replica.admit_member(&c_incept, vec![Grant::Write]));
    sync_all(&mut b.replica, &mut c.replica);
    assert!(c.replica.am_i_member(), "C is a member");
    assert!(
        c.replica.acl_state().is_admin(&a_actor),
        "C sees the true founder as admin (not forked away from it)"
    );
    assert!(
        titles(&mut c.replica).contains(&"founders-secret".to_string()),
        "C adopts the founder's key-epoch and reads founder content"
    );

    // Negative control — the fork is now CRYPTOGRAPHICALLY impossible. A
    // forged ticket that presents the inviter's own inception as the founder
    // for A's space is rejected at join: the self-certifying id does not
    // commit to B's device (lait/space/1), so verify_founding fails.
    let (a_salt, a_rr, _a_incept) = a.replica.founding_proof().unwrap();
    let forged_home = std::env::temp_dir().join(format!(
        "gc-trk-{}-{}",
        std::process::id(),
        DocId::mint(&crate::ids::SystemUlidSource)
    ));
    std::fs::create_dir_all(&forged_home).unwrap();
    let forged_store = Store::open(&forged_home).unwrap();
    let err = join_space_store(&forged_store, &a_ws, &a_salt, &a_rr, &b_incept);
    assert!(
        err.is_err(),
        "a ticket rooting on the inviter's inception is rejected, not forked"
    );
    let _ = std::fs::remove_dir_all(&forged_home);
}

#[test]
fn break_glass_recovery_re_roots_the_space() {
    // W5: the live admin (A) is lost/compromised. A holder restores the
    // offline space recovery key on a FRESH device C and recovers —
    // re-rooting the space to C, evicting A, convergently for all peers.
    let mut a = new_node(); // founder A; 1-of-1 space recovery key beside its store
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "old");
    let a_actor = a.replica.my_actor().unwrap();
    let a_ws = a.replica.space_str();

    // Fresh device C bootstraps on A's space (verifies the founding), then
    // syncs the state from a survivor (here A) — the realistic break-glass
    // flow: pull the space, then re-root.
    let c_seed = [71u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(
        c_device,
        c_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    sync_all(&mut a.replica, &mut c.replica);

    // The offline recovery key is restored beside C's store.
    std::fs::copy(
        a.home.join("space-recovery.key"),
        c.home.join("space-recovery.key"),
    )
    .unwrap();

    // C recovers: the solo recovery key re-roots the space to C.
    let (resp, _) = c.replica.space_recover_cmd();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let c_actor = c.replica.my_actor().unwrap();
    assert!(
        c.replica.acl_state().is_admin(&c_actor),
        "the recovered device is the new root admin"
    );
    assert!(
        !c.replica.acl_state().is_admin(&a_actor),
        "the old root no longer holds authority"
    );

    // Convergent: A syncs C's recovery and agrees it is no longer the root.
    sync_all(&mut c.replica, &mut a.replica);
    assert!(
        a.replica.acl_state().is_admin(&c_actor) && !a.replica.acl_state().is_admin(&a_actor),
        "every replica converges on the recovered root"
    );
}

#[test]
fn elevate_solo_recovery_to_a_2_of_2_dkg_group_key() {
    // W5 elevation (the "airplane" story): A founds solo with a bootstrap
    // recovery key, later adds co-founder B and elevates the recovery authority
    // to a 2-of-2 FROST group key via a DKG that rides the synced bulletin
    // board — no dealer, no secret ever leaves its holder.
    let mut a = new_node(); // founder A, holds solo space-recovery.key
    with_project(&mut a.replica);
    let a_ws = a.replica.space_str();
    let commit0 = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    )
    .recovery_commit;

    // Co-founder B joins and is admitted; both sync.
    let b_seed = [81u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    // A elevates to a 2-of-2 over {A, B}.
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

    // Drive the DKG to a fixpoint via sync round-trips (each import advances).
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }

    // The recovery authority is now the DKG group key, not A's solo key.
    let after = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert!(!after.recovered); // no re-root happened, only a Rotate
    assert_ne!(
        after.recovery_commit, commit0,
        "the recovery authority rotated to the group key"
    );
    // Both replicas converge on the same new authority.
    let b_after = crate::space::replay(
        &b.replica.genesis,
        &b.replica.space_id,
        &b.replica.membership.space_events(),
    );
    assert_eq!(after.recovery_commit, b_after.recovery_commit);

    // The standing arrangement is replicated on the space plane, not just the key. Both
    // replicas agree on it, it is no longer `Single`, and it is the exact
    // 2-of-2 configuration the elevation built — learnable by replay without
    // holding a share.
    assert_eq!(after.configuration, b_after.configuration);
    assert_ne!(
        after.configuration,
        crate::authority::AuthorityConfigurationId::single(),
        "the space is no longer a solo authority"
    );
    let dkg = a.replica.standing_dkg_session().expect("standing group");
    let expected = a
        .replica
        .dkg_manifest(&dkg)
        .expect("manifest")
        .configuration
        .id();
    assert_eq!(
        after.configuration, expected,
        "the on-plane configuration is the arrangement the ceremony produced"
    );

    // A's solo key is retired: recovery now runs through the group ceremony,
    // and a lone holder cannot meet the 2-of-2 threshold by itself.
    let (resp, _) = a.replica.space_recover_cmd();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let still = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert!(
        !still.recovered,
        "one holder alone cannot complete a 2-of-2 group recovery"
    );
}

/// Content-derived transcript ids make concurrency visible: two holders
/// independently requesting the same recovery author different nodes, so they
/// open different transcripts and commitments would split across both.
/// Holders converge on the lowest id.
#[test]
fn concurrent_signing_requests_converge_on_the_lowest_transcript() {
    let a = new_node();
    let authority = crate::dkg::TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
    let op_bytes = vec![1u8, 2, 3];
    let mk = |nonce: [u8; 16]| crate::dkg::CeremonyOp::SignRequest {
        nonce,
        authority,
        target: crate::dkg::SignTarget::SpaceOp,
        coordinator: a.replica.me.clone(),
        op: op_bytes.clone(),
    };
    let e1 = crate::dkg::sign_ceremony(&[1u8; 32], &mk([1u8; 16]), &a.replica.space_id);
    let e2 = crate::dkg::sign_ceremony(&[2u8; 32], &mk([2u8; 16]), &a.replica.space_id);
    let (id1, id2) = (
        crate::dkg::TranscriptId::of(&e1).unwrap(),
        crate::dkg::TranscriptId::of(&e2).unwrap(),
    );
    assert_ne!(id1, id2, "distinct authors open distinct transcripts");
    a.replica.membership.add_ceremony_event(&e1).unwrap();
    a.replica.membership.add_ceremony_event(&e2).unwrap();

    let events = a.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &a.replica.space_id);
    let chosen = a
        .replica
        .canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            2,
        )
        .expect("one of the two");
    assert_eq!(chosen, id1.min(id2), "the lowest id wins");
}

/// The tie-break is a preference, not an override. Abandoning a transcript
/// that is one share from completing, in favour of a lower one that may
/// never gather K, is the wrong trade for break-glass — and correctness never
/// depended on it, since both sign gen+1 and the space plane's monotonicity
/// guard rejects the loser.
#[test]
fn a_signing_transcript_at_threshold_beats_a_lower_incomplete_one() {
    let a = new_node();
    let authority = crate::dkg::TranscriptId::parse_hex(&"a".repeat(64)).unwrap();
    let op_bytes = vec![1u8, 2, 3];
    let mk = |nonce: [u8; 16]| crate::dkg::CeremonyOp::SignRequest {
        nonce,
        authority,
        target: crate::dkg::SignTarget::SpaceOp,
        coordinator: a.replica.me.clone(),
        op: op_bytes.clone(),
    };
    let e1 = crate::dkg::sign_ceremony(&[1u8; 32], &mk([1u8; 16]), &a.replica.space_id);
    let e2 = crate::dkg::sign_ceremony(&[2u8; 32], &mk([2u8; 16]), &a.replica.space_id);
    let (id1, id2) = (
        crate::dkg::TranscriptId::of(&e1).unwrap(),
        crate::dkg::TranscriptId::of(&e2).unwrap(),
    );
    let (low, high) = if id1 < id2 { (id1, id2) } else { (id2, id1) };
    a.replica.membership.add_ceremony_event(&e1).unwrap();
    a.replica.membership.add_ceremony_event(&e2).unwrap();
    // Two shares land on the HIGHER transcript, reaching a threshold of 2.
    for seed in [[3u8; 32], [4u8; 32]] {
        let ev = crate::dkg::sign_ceremony(
            &seed,
            &crate::dkg::CeremonyOp::SignRound2 {
                signing: high,
                share: vec![0u8; 32],
            },
            &a.replica.space_id,
        );
        a.replica.membership.add_ceremony_event(&ev).unwrap();
    }

    let events = a.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &a.replica.space_id);
    let chosen = a
        .replica
        .canonical_signing_session(
            &board,
            &authority,
            crate::dkg::SignTarget::SpaceOp,
            &op_bytes,
            2,
        )
        .unwrap();
    assert_eq!(chosen, high, "a transcript at threshold is not abandoned");
    assert_ne!(chosen, low);
}

/// A FROST nonce may produce a share for exactly one signing
/// package. Producing shares for two under one nonce gives two equations in
/// one unknown and yields the holder's signing share — so if the package has
/// moved since we committed, the signer must refuse rather than sign.
///
/// Drives a real 2-of-2 group to the point where a nonce record exists, then
/// repoints the record's binding as a package change would, and asserts no
/// second share is ever published.
#[test]
fn a_nonce_bound_to_another_package_refuses_to_sign() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    // Elevate {A, B} to a 2-of-2 group recovery key.
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }

    // B opens a break-glass recovery: this commits B's nonces.
    let (resp, _) = b.replica.space_recover_cmd();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let events = b.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &b.replica.space_id);
    let signing = *board.signing.keys().next().expect("B opened a request");
    let raw = b
        .replica
        .dkg_read(&signing, "nonce")
        .expect("B committed nonces");
    let mut pending: crate::dkg::PendingNonce = postcard::from_bytes(&raw).unwrap();

    // Pin the record to a package B will never see — exactly what a shifted
    // signer set or a changed message would produce.
    pending.binding = [0xAB; 32];
    b.replica
        .dkg_write(&signing, "nonce", &postcard::to_stdvec(&pending).unwrap())
        .unwrap();

    // A consents, so the signer set completes and B would otherwise sign.
    let b_actor = b.replica.my_actor().unwrap();
    for _ in 0..4 {
        sync_all(&mut b.replica, &mut a.replica);
        sync_all(&mut a.replica, &mut b.replica);
    }
    let (resp, _) = a
        .replica
        .space_recover_approve_cmd(signing.to_hex(), vec![b_actor.as_str().to_string()]);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }

    // B published no share, and the nonce record survives — the refusal is
    // the comparison, not the deletion, precisely so a crash between
    // publishing and deleting cannot re-open the door.
    let events = b.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &b.replica.space_id);
    let b_shares = board.signing[&signing]
        .rounds
        .iter()
        .filter(|v| {
            v.author == b.replica.me && matches!(v.op, crate::dkg::CeremonyOp::SignRound2 { .. })
        })
        .count();
    assert_eq!(
        b_shares, 0,
        "a nonce pinned to a different package must never produce a share"
    );
    assert!(
        b.replica.dkg_read(&signing, "nonce").is_some(),
        "the record is kept for inspection rather than silently replaced"
    );
}

/// A share protected under a different Windows account is *present*, not
/// absent — the holder exists and cannot act. Break-glass recovery must say
/// which of those it is, because for an N-of-N group it is the difference
/// between a degraded holder and an unrecoverable space.
#[test]
fn an_unreadable_share_is_reported_as_degraded_not_absent() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let dkg_id = b.replica.active_dkg_session().expect("B holds a share");
    assert!(
        b.replica.degraded_recovery_holders().is_empty(),
        "a healthy holder reports nothing"
    );

    // Simulate a store restored onto another Windows account: the bytes are
    // present and wrapped, but this identity cannot open them.
    let mut corrupt = b"lait-dpapi-1\n".to_vec();
    corrupt.extend_from_slice(&[0xAB; 96]);
    std::fs::write(b.replica.dkg_path(&dkg_id, "share"), &corrupt).unwrap();

    // The share is neither usable nor absent, and is named as such.
    assert!(matches!(
        b.replica.dkg_artifact(&dkg_id, "share"),
        ArtifactRead::Unreadable(_)
    ));
    let reported = b.replica.degraded_recovery_holders();
    assert_eq!(reported.len(), 1, "one degraded transcript");
    assert_eq!(
        reported[0].transcript,
        dkg_id.to_hex(),
        "named by transcript"
    );
    assert!(
        matches!(
            reported[0].reason,
            RecoveryArtifactFailure::Undecryptable(_)
        ),
        "an undecryptable wrap is reported as such"
    );
    assert_eq!(
        reported[0].is_current_authority,
        Some(true),
        "the public-key package is portable, so currency is still provable \
         after the share becomes unreadable"
    );

    // Break-glass tells the operator what actually happened rather than
    // "no way to recover from this device".
    let (resp, _) = b.replica.space_recover_cmd();
    match resp {
        Response::Error { message, .. } => {
            assert!(
                message.contains("another Windows account"),
                "must name the actual cause: {message}"
            );
            assert!(
                message.contains("current recovery key"),
                "must say this share is for the live authority: {message}"
            );
            assert!(
                message.contains(&dkg_id.to_hex()),
                "must name the transcript: {message}"
            );
            assert!(
                message.contains("cannot take part in recovery"),
                "must say what THIS device can do: {message}"
            );
            assert!(
                !message.contains("can still recover the space"),
                "must not claim other holders can recover — this device cannot know that: {message}"
            );
        }
        other => panic!("expected a typed failure, got {other:?}"),
    }
}

/// A share belonging to a group that is **not** the space's recovery
/// authority is not a recovery problem: it could not recover this space
/// even if it were readable. Announcing it as "a share for the space
/// recovery key" would be false, so currency is established from the
/// public-key package before anything is reported.
#[test]
fn an_unreadable_share_for_another_group_is_not_reported() {
    let mut a = new_node();

    // A real 2-of-2 DKG for a group unrelated to this space, so its
    // public-key package parses and derives a group key that is genuinely
    // not the standing recovery authority.
    let (s1_a, p1_a) = crate::dkg::dkg_round1(1, 2, 2).unwrap();
    let (s1_b, p1_b) = crate::dkg::dkg_round1(2, 2, 2).unwrap();
    let others_a: crate::dkg::Packages = [(2u16, p1_b.clone())].into_iter().collect();
    let others_b: crate::dkg::Packages = [(1u16, p1_a.clone())].into_iter().collect();
    let (s2_a, out_a) = crate::dkg::dkg_round2(&s1_a, &others_a).unwrap();
    let (_s2_b, out_b) = crate::dkg::dkg_round2(&s1_b, &others_b).unwrap();
    let to_a: crate::dkg::Packages = [(2u16, out_b[&1].clone())].into_iter().collect();
    let (_share, pkp, foreign_group) = crate::dkg::dkg_round3(&s2_a, &others_a, &to_a).unwrap();
    let _ = out_a;
    assert_ne!(
        crate::space::recovery_commit(&foreign_group),
        Some(
            crate::space::replay(
                &a.replica.genesis,
                &a.replica.space_id,
                &a.replica.membership.space_events(),
            )
            .recovery_commit
        ),
        "the fixture group is not this space's authority"
    );

    // Put a transcript for it on the board so it is a candidate at all.
    let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(
        &a.replica,
        [5u8; 16],
        2,
        vec![a.replica.me.clone(), device_from_seed([31u8; 32])],
    ));
    let ev = crate::dkg::sign_ceremony(&[31u8; 32], &propose, &a.replica.space_id);
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.persist_membership("foreign").unwrap();

    // Its package is readable; its share is not.
    a.replica.dkg_write_portable(&id, "pkp", &pkp).unwrap();
    let mut corrupt = b"lait-dpapi-1\n".to_vec();
    corrupt.extend_from_slice(&[0xAB; 96]);
    std::fs::write(a.replica.dkg_path(&id, "share"), &corrupt).unwrap();
    assert!(matches!(
        a.replica.dkg_artifact(&id, "share"),
        ArtifactRead::Unreadable(_)
    ));

    assert!(
        a.replica.degraded_recovery_holders().is_empty(),
        "a share for another group must not be announced as the space recovery key"
    );

    // But if the package itself cannot be read, currency is UNKNOWN — and an
    // unknown share is reported rather than silently dropped.
    std::fs::write(a.replica.dkg_path(&id, "pkp"), &corrupt).unwrap();
    let reported = a.replica.degraded_recovery_holders();
    assert_eq!(reported.len(), 1, "unprovable currency is still surfaced");
    assert_eq!(
        reported[0].is_current_authority, None,
        "and is reported as undetermined rather than asserted either way"
    );
}

/// An I/O failure is not an account mismatch. Diagnosing every read failure
/// as DPAPI identity would send an operator to the wrong remedy.
#[test]
fn an_io_failure_is_not_diagnosed_as_an_account_mismatch() {
    let dir = std::env::temp_dir().join(format!("lait-io-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    crate::secretfs::create_private_dir(&dir).unwrap();
    // A directory where a file is expected: present, but unreadable for a
    // filesystem reason rather than a cryptographic one.
    let path = dir.join("share");
    std::fs::create_dir(&path).unwrap();
    match crate::secretfs::read_private(&path) {
        Err(crate::secretfs::SecretError::Io(_)) => {}
        other => panic!("expected a typed Io failure, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// A node that cannot mint must be TOLD it is waiting on one. The automatic
/// repair covers admins; a plain member observing a revoke-fenced eviction
/// has no way to discharge the fence itself, and until now nothing said so.
///
/// This is the accessor the diagnose `keys` gate reads, so it is worth
/// pinning that it actually fires rather than being permanently `None`.
#[test]
fn a_non_admin_is_told_a_rekey_is_pending() {
    let mut a = new_node(); // founder/admin A
    with_project(&mut a.replica);
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();

    // B is a second ADMIN (so it can redeem), C a plain writer.
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let mut c = new_joiner_node_as(device_from_seed(c_seed), c_seed, &a_ws, &proof);
    let b_incept = b.replica.self_inception().unwrap();
    let c_incept = c.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    ok(a.replica.admit_member(&c_incept, vec![Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut a.replica, &mut c.replica);
    assert!(!c.replica.am_i_admin(), "C cannot mint");
    assert!(
        c.replica.rekey_pending_notice().is_none(),
        "nothing pending in the steady state"
    );

    // PARTITION: B redeems an invite that A concurrently revokes.
    let nonce = [7u8; 16];
    let x_incept = incept_for([61u8; 32], &b.replica);
    let x_actor = actor_of(&x_incept);
    ok(b.replica.redeem_invite(&b_device, &x_incept, &nonce, true));
    ok(a.replica
        .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce)));

    // C observes BOTH branches before any admin has rotated past the fence.
    sync_membership(&mut b.replica, &mut c.replica);
    sync_membership(&mut a.replica, &mut c.replica);

    assert!(
        !c.replica.is_member_actor(&x_actor),
        "revoke wins on C as well"
    );
    let notice = c
        .replica
        .rekey_pending_notice()
        .expect("C cannot discharge the fence and must be told");
    assert!(
        notice.contains(&x_actor.short()),
        "names the evicted actor: {notice}"
    );
    assert!(
        notice.contains("admin must sync"),
        "says who can fix it: {notice}"
    );
    assert!(
        notice.contains("already shared"),
        "states the residual — rotation fences future content only: {notice}"
    );

    // Once an admin rotates past the fence, the notice clears.
    sync_membership(&mut b.replica, &mut a.replica);
    sync_membership(&mut a.replica, &mut c.replica);
    assert!(
        c.replica.rekey_pending_notice().is_none(),
        "a discharged fence stops warning"
    );
}

/// A proposal names the authority it replaces, so one authorized under a
/// past authority cannot be replayed against the current one. Without this,
/// a grant would mean "some ceremony may run" rather than "this ceremony may
/// replace this exact authority".
#[test]
fn a_proposal_naming_the_wrong_authority_is_rejected() {
    let mut a = new_node();
    let secret = a.replica.read_space_recovery_key().expect("solo key");

    // A well-formed proposal whose `current` is some other authority.
    let stranger = crate::authority::AuthorityId::single(device_from_seed([123u8; 32]));
    let principals = {
        let mut v: Vec<crate::authority::PrincipalId> =
            [a.replica.me.clone(), device_from_seed([44u8; 32])]
                .iter()
                .map(crate::authority::PrincipalId::of_device)
                .collect();
        v.sort();
        v
    };
    let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
        [6u8; 16], 2, principals, stranger,
    ));
    let ev = crate::dkg::sign_ceremony(&[44u8; 32], &propose, &a.replica.space_id);
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    // Authorized by the REAL recovery key: only the named authority is wrong.
    let grant = crate::dkg::sign_authority_grant(&secret, &a.replica.space_id, &id);
    let aev = crate::dkg::sign_ceremony(
        &[44u8; 32],
        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("wrong_authority").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&id).is_none(),
        "a proposal must name the authority it actually replaces"
    );
}

/// Acceptance checks the arrangement against the replicated standing
/// configuration, so a proposal naming the correct key but the wrong
/// configuration is rejected — the case the old key-alone acceptance let
/// through, and the one that had to close before same-key transitions.
#[test]
fn a_proposal_with_the_right_key_but_wrong_configuration_is_rejected() {
    let mut a = new_node();
    let secret = a.replica.read_space_recovery_key().expect("solo key");
    let standing = a.replica.current_authority().expect("solo authority");

    // Same key (the real standing solo key), but claim it is operated by a
    // group arrangement it is not.
    let mut members: Vec<crate::authority::PrincipalId> =
        [a.replica.me.clone(), device_from_seed([44u8; 32])]
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
    members.sort();
    let lying_cfg = crate::authority::AuthorityConfiguration::frost_threshold(
        &crate::authority::FrostThresholdConfig {
            k: 2,
            participants: members.clone(),
        },
    );
    let lie = crate::authority::AuthorityId::new(standing.public_key.clone(), &lying_cfg);
    assert_eq!(
        crate::space::recovery_commit(&lie.public_key),
        crate::space::recovery_commit(&standing.public_key),
        "the KEY is genuinely the standing one"
    );
    assert_ne!(
        lie.configuration, standing.configuration,
        "only the claimed arrangement differs"
    );

    let propose = crate::dkg::CeremonyOp::DkgPropose(crate::dkg::frost_rotation_proposal(
        [6u8; 16], 2, members, lie,
    ));
    let ev = crate::dkg::sign_ceremony(&[44u8; 32], &propose, &a.replica.space_id);
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    let grant = crate::dkg::sign_authority_grant(&secret, &a.replica.space_id, &id);
    let aev = crate::dkg::sign_ceremony(
        &[44u8; 32],
        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("wrong_config").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&id).is_none(),
        "a proposal must name the standing configuration, not just the standing key"
    );
}

/// `Reshare` keeps the public key and changes only the arrangement. It needs
/// a protocol that never reconstructs the secret, which does not exist yet —
/// so the variant round-trips in the format but must never be acted on.
/// Accepting one would promise a transition the code cannot perform.
#[test]
fn a_reshare_proposal_is_refused_until_the_protocol_exists() {
    let mut a = new_node();
    let secret = a.replica.read_space_recovery_key().expect("solo key");
    let current = a.replica.current_authority().expect("solo authority");
    let mut principals: Vec<crate::authority::PrincipalId> =
        [a.replica.me.clone(), device_from_seed([45u8; 32])]
            .iter()
            .map(crate::authority::PrincipalId::of_device)
            .collect();
    principals.sort();

    let proposal = crate::dkg::KeyCeremonyProposal {
        nonce: [7u8; 16],
        configuration: crate::authority::AuthorityConfiguration::frost_threshold(
            &crate::authority::FrostThresholdConfig {
                k: 2,
                participants: principals,
            },
        ),
        transition: crate::dkg::ProposedTransition::Reshare { authority: current },
    };
    // Everything else is impeccable: well-formed configuration, real grant.
    assert!(proposal.configuration.is_well_formed());
    assert!(
        proposal.frost_config().is_none(),
        "an unimplemented transition yields no usable configuration"
    );

    let ev = crate::dkg::sign_ceremony(
        &[45u8; 32],
        &crate::dkg::CeremonyOp::DkgPropose(proposal),
        &a.replica.space_id,
    );
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    let grant = crate::dkg::sign_authority_grant(&secret, &a.replica.space_id, &id);
    let aev = crate::dkg::sign_ceremony(
        &[45u8; 32],
        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("reshare").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&id).is_none() && a.replica.dkg_read(&id, "r1").is_none(),
        "resharing must not be attempted before a same-key protocol exists"
    );
}

/// B3 + B4 end to end: a standing GROUP authorizes its own replacement and
/// signs the rotation that installs it.
///
/// This is the lifecycle the one-way door used to block. Nothing here can be
/// done by a solo key: the current authority is a group, so the grant needs
/// a threshold signature (B3) and so does the rotation (B4).
#[test]
fn a_group_authorizes_and_installs_its_own_replacement() {
    let mut a = new_node(); // founder, holds the bootstrap solo key
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();

    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(c_device.clone(), c_seed, &a_ws, &proof);
    for incept in [
        b.replica.self_inception().unwrap(),
        c.replica.self_inception().unwrap(),
    ] {
        ok(a.replica
            .admit_member(&incept, vec![Grant::Admin, Grant::Write]));
    }
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut a.replica, &mut c.replica);

    // ---- solo → group: {A, B} 2-of-2.
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..8 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let after_first = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert_eq!(after_first.gen, 1, "the 2-of-2 group key is installed");
    let first_authority = a
        .replica
        .current_authority()
        .expect("A can attribute the standing key");
    assert_eq!(
        first_authority.public_key,
        a.replica
            .group_key_of_transcript(&a.replica.active_dkg_session().unwrap())
            .unwrap(),
        "the standing authority IS the group we just built"
    );

    // ---- group → group: {A, B, C} 2-of-3, proposed by a group holder.
    // A no longer has a usable solo key, so this can only proceed by
    // threshold authorization.
    let (resp, _) = a.replica.space_elevate_cmd(
        vec![b_device.as_str().to_string(), c_device.as_str().to_string()],
        2,
    );
    let msg = match resp {
        Response::Ok { message: Some(m) } => m,
        other => panic!("expected a pending group authorization, got {other:?}"),
    };
    assert!(
        msg.contains("elevate-approve"),
        "a group elevation must ask the other holders to authorize: {msg}"
    );

    // Pull the request and the proposal ids off the verified board.
    let events = a.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &a.replica.space_id);
    let (signing, proposal) = board
        .signing
        .iter()
        .find_map(|(id, t)| match &t.request.as_ref()?.op {
            crate::dkg::CeremonyOp::SignRequest {
                target: crate::dkg::SignTarget::AuthorityGrant,
                op,
                ..
            } => {
                let g: crate::dkg::AuthorityGrant = postcard::from_bytes(op).ok()?;
                Some((*id, g.proposal))
            }
            _ => None,
        })
        .expect("A opened a grant request");

    // B, the other current holder, must consent — and consent binds to the
    // proposal, not to an opaque session id.
    for _ in 0..4 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let (bad, _) = b
        .replica
        .space_elevate_approve_cmd(signing.to_hex(), "f".repeat(64));
    assert!(
        matches!(bad, Response::Error { .. }),
        "approving a session while naming the wrong proposal must be refused: {bad:?}"
    );
    let (resp, _) = b
        .replica
        .space_elevate_approve_cmd(signing.to_hex(), proposal.to_hex());
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

    // Everything else is automatic: the group signs the grant, the new DKG
    // runs, the group signs the rotation, the plane installs it.
    for _ in 0..8 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut c.replica);
        sync_all(&mut c.replica, &mut a.replica);
        sync_all(&mut b.replica, &mut a.replica);
        sync_all(&mut c.replica, &mut b.replica);
        sync_all(&mut a.replica, &mut c.replica);
    }

    let after_second = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert_eq!(
        after_second.gen, 2,
        "the group authorized and installed its own replacement"
    );
    assert_ne!(
        after_second.recovery_commit, after_first.recovery_commit,
        "rotation produces a DIFFERENT key — this is not a reshare"
    );

    // C, who held no share of the old group, holds one of the new authority.
    let c_authority = c
        .replica
        .current_authority()
        .expect("C can attribute the standing key");
    assert_eq!(
        c_authority.public_key.as_str(),
        a.replica.current_authority().unwrap().public_key.as_str(),
        "every holder agrees on the standing authority"
    );
    let c_cfg = c
        .replica
        .dkg_manifests()
        .into_iter()
        .find(|(id, _)| {
            c.replica.group_key_of_transcript(id).as_ref() == Some(&c_authority.public_key)
        })
        .map(|(_, m)| m.configuration)
        .expect("C accepted the ceremony that produced it");
    let frost = c_cfg.as_frost_threshold().unwrap();
    assert_eq!(
        (frost.k, frost.participants.len()),
        (2, 3),
        "the new arrangement is the 2-of-3 that was proposed"
    );
}

/// B6: **any** available K can sign, not a predetermined K.
///
/// The old rule fixed the signer set to the `threshold` lowest-index
/// holders, so a 2-of-3 could not recover without holder #1 — which is not
/// threshold availability in any useful sense. This drives a recovery with
/// holder #1 deliberately absent: it never syncs, so it never contributes.
#[test]
fn any_k_of_n_can_sign_without_the_lowest_index_holder() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(c_device.clone(), c_seed, &a_ws, &proof);
    for incept in [
        b.replica.self_inception().unwrap(),
        c.replica.self_inception().unwrap(),
    ] {
        ok(a.replica
            .admit_member(&incept, vec![Grant::Admin, Grant::Write]));
    }
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut a.replica, &mut c.replica);

    // A 2-of-3 group over {A, B, C}.
    let (resp, _) = a.replica.space_elevate_cmd(
        vec![b_device.as_str().to_string(), c_device.as_str().to_string()],
        2,
    );
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let mut nodes = vec![a, b, c];
    sync_mesh(&mut nodes, 8);
    assert_eq!(
        crate::space::replay(
            &nodes[0].replica.genesis,
            &nodes[0].replica.space_id,
            &nodes[0].replica.membership.space_events(),
        )
        .gen,
        1,
        "the 2-of-3 group key is installed"
    );

    // Participant index is position in the sorted device list, so sorting
    // the nodes the same way tells us who holder #1 is.
    nodes.sort_by(|x, y| x.replica.me.as_str().cmp(y.replica.me.as_str()));
    let absent = nodes.remove(0); // index 1 — the one the old rule required
    assert_eq!(nodes.len(), 2, "two holders remain: exactly the threshold");

    // The remaining two recover, with #1 never syncing again.
    let recovering = nodes[0].replica.my_actor().unwrap();
    let (resp, _) = nodes[0].replica.space_recover_cmd();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    sync_mesh(&mut nodes, 3);

    let events = nodes[1].replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &nodes[1].replica.space_id);
    let session = *board
        .signing
        .keys()
        .next()
        .expect("a recovery request reached the other holder");
    let (resp, _) = nodes[1]
        .replica
        .space_recover_approve_cmd(session.to_hex(), vec![recovering.as_str().to_string()]);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    sync_mesh(&mut nodes, 8);

    let after = crate::space::replay(
        &nodes[0].replica.genesis,
        &nodes[0].replica.space_id,
        &nodes[0].replica.membership.space_events(),
    );
    assert!(
        after.recovered && after.root == vec![recovering.clone()],
        "two of three signed a recovery without holder #1"
    );

    // And the plan says so: the chosen signers are indices 2 and 3.
    let events = nodes[0].replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &nodes[0].replica.space_id);
    let plan = board
        .signing
        .values()
        .find_map(|t| t.plan())
        .expect("the coordinator published a plan");
    let crate::dkg::AccessWitness::FrostThreshold {
        k,
        participant_indices,
    } = &plan.witness
    else {
        panic!("flat FROST witness expected");
    };
    assert_eq!(*k, 2);
    assert_eq!(
        participant_indices,
        &vec![2u16, 3u16],
        "the signer set excludes holder #1 — the point of any-K"
    );
    drop(absent);
}

/// B7: an indispensable arrangement must not install until every custodian
/// has verified a portable backup.
///
/// The failure this prevents is silent and delayed: an N-of-N group created
/// while one holder's share exists only behind a Windows profile looks
/// perfectly healthy, and the space finds out on the day it needs to
/// recover. So the gate reads signed attestations from the board — local
/// state would let another node install ahead of the checks.
#[test]
fn an_indispensable_arrangement_waits_for_verified_custody() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    let commit0 = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    )
    .recovery_commit;

    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..8 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }

    // The DKG is complete — both hold shares — but nothing has installed.
    let dkg =
        *crate::dkg::parse_board(&a.replica.membership.ceremony_events(), &a.replica.space_id)
            .dkg
            .keys()
            .next()
            .unwrap();
    assert!(a.replica.dkg_read(&dkg, "share").is_some());
    assert!(b.replica.dkg_read(&dkg, "share").is_some());
    assert_eq!(
        crate::space::replay(
            &a.replica.genesis,
            &a.replica.space_id,
            &a.replica.membership.space_events(),
        )
        .recovery_commit,
        commit0,
        "an indispensable arrangement must not install on unverified custody"
    );

    // Status says exactly why, rather than reporting a healthy holder.
    assert_eq!(
        a.replica.recovery_status().local_custody,
        LocalCustodyState::BackupUnverified,
        "holding a share is not the same as being able to keep it"
    );

    // One custodian attests: still blocked, because ALL are required.
    attest_custody(&mut a, "a");
    for _ in 0..4 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    assert_eq!(
        crate::space::replay(
            &a.replica.genesis,
            &a.replica.space_id,
            &a.replica.membership.space_events(),
        )
        .recovery_commit,
        commit0,
        "one of two attestations is not enough for an N-of-N arrangement"
    );

    // Both attest: it installs.
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    assert_ne!(
        crate::space::replay(
            &a.replica.genesis,
            &a.replica.space_id,
            &a.replica.membership.space_events(),
        )
        .recovery_commit,
        commit0,
        "with every custodian verified, the arrangement installs"
    );
    assert_eq!(
        a.replica.recovery_status().local_custody,
        LocalCustodyState::Ready
    );
    let st = a.replica.recovery_status();
    assert_eq!((st.k, st.n), (2, 2));
    assert_eq!(st.scheme, crate::authority::AuthorityScheme::FrostThreshold);
}

/// A redundant arrangement is NOT gated: tolerating a lost holder is what
/// redundancy means, so requiring every custodian to attest would impose a
/// cost the shape does not need.
#[test]
fn a_redundant_arrangement_installs_without_universal_attestation() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(c_device.clone(), c_seed, &a_ws, &proof);
    for incept in [
        b.replica.self_inception().unwrap(),
        c.replica.self_inception().unwrap(),
    ] {
        ok(a.replica
            .admit_member(&incept, vec![Grant::Admin, Grant::Write]));
    }
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut a.replica, &mut c.replica);

    let (resp, _) = a.replica.space_elevate_cmd(
        vec![b_device.as_str().to_string(), c_device.as_str().to_string()],
        2, // 2-of-3: one holder may be lost
    );
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let mut nodes = vec![a, b, c];
    sync_mesh(&mut nodes, 8);
    assert_eq!(
        crate::space::replay(
            &nodes[0].replica.genesis,
            &nodes[0].replica.space_id,
            &nodes[0].replica.membership.space_events(),
        )
        .gen,
        1,
        "a redundant arrangement installs without attestation"
    );
    assert_eq!(
        nodes[0].replica.recovery_status().local_custody,
        LocalCustodyState::Ready,
        "and its holders are Ready, not BackupUnverified"
    );
}

/// A custody backup must be restorable, not merely preserved.
///
/// Simulates the case the whole custody design exists for: a holder loses
/// its local material (account or machine gone) and comes back with the
/// portable package. Before the import path existed, the share survived and
/// the product still could not resume signing with it.
#[test]
fn a_lost_share_is_restored_from_its_portable_package() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let dkg = b.replica.standing_dkg_session().expect("standing group");

    // B exports a portable package, then loses its local material.
    let pkg_path = b.home.join("rescue.pkg");
    let (resp, _) = b.replica.space_custody_export_cmd(
        pkg_path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
    );
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    // Only the SHARE goes. The public-key package is stored portable exactly
    // so it survives an account change — which is what lets this device still
    // say which group it belongs to after losing the ability to sign for it.
    std::fs::remove_file(b.replica.dkg_path(&dkg, "share")).unwrap();

    // Report the lost share as missing rather than claiming this device is
    // not a holder; the arrangement's real shape must survive the loss.
    let st = b.replica.recovery_status();
    assert_eq!(
        st.local_custody,
        LocalCustodyState::Missing,
        "a holder whose standing share vanished is Missing, not NotAHolder"
    );
    assert_eq!(
        (st.k, st.n),
        (2, 2),
        "the standing arrangement's shape does not collapse to 1-of-1"
    );
    assert!(
        b.replica.active_dkg_session().is_none(),
        "and it cannot sign"
    );

    // The package brings it back.
    let (resp, _) = b.replica.space_custody_import_cmd(
        pkg_path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
        false,
    );
    assert!(matches!(resp, Response::Ok { .. }), "restore: {resp:?}");
    assert_eq!(
        b.replica.recovery_status().local_custody,
        LocalCustodyState::Ready
    );
    assert_eq!(
        b.replica.active_dkg_session(),
        Some(dkg),
        "the restored holder can sign again"
    );

    // Re-importing over usable material is refused unless forced, so a
    // mistaken run cannot turn a working device into the loss it prevents.
    let (resp, _) = b.replica.space_custody_import_cmd(
        pkg_path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
        false,
    );
    assert!(
        matches!(resp, Response::Error { .. }),
        "must not clobber a readable share: {resp:?}"
    );
    let (resp, _) = b.replica.space_custody_import_cmd(
        pkg_path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
        true,
    );
    assert!(matches!(resp, Response::Ok { .. }), "forced: {resp:?}");

    // A wrong passphrase restores nothing.
    let (resp, _) = b.replica.space_custody_import_cmd(
        pkg_path.to_string_lossy().to_string(),
        "not-the-right-passphrase".into(),
        true,
    );
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

    // Losing the public package too is a harder case, and the honest answer
    // is that this device can no longer tell which group it belonged to —
    // so it reports NotAHolder rather than inventing a shape. The package
    // still restores it, because the package carries its own public half.
    std::fs::remove_file(b.replica.dkg_path(&dkg, "share")).unwrap();
    std::fs::remove_file(b.replica.dkg_path(&dkg, "pkp")).unwrap();
    assert_eq!(
        b.replica.recovery_status().local_custody,
        LocalCustodyState::NotAHolder,
        "with no public package there is nothing to attribute the device to"
    );
    let (resp, _) = b.replica.space_custody_import_cmd(
        pkg_path.to_string_lossy().to_string(),
        "a-sufficiently-long-passphrase".into(),
        true,
    );
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert_eq!(
        b.replica.active_dkg_session(),
        Some(dkg),
        "the package carries its own public half, so it restores both"
    );
}

/// A rotation whose new arrangement excludes too many current
/// holders can never be installed, because only a participant of the new
/// ceremony can derive the key the current group must sign for.
///
/// It must be refused at authorization. Otherwise it authorizes cleanly,
/// runs the whole DKG, collects custody attestations, and stalls forever at
/// the last step with everyone believing it worked.
#[test]
fn a_rotation_that_could_never_install_is_refused_up_front() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let c_device = device_from_seed(c_seed);
    let mut c = new_joiner_node_as(c_device.clone(), c_seed, &a_ws, &proof);
    let d_seed = [41u8; 32];
    let d_device = device_from_seed(d_seed);
    let mut d = new_joiner_node_as(d_device.clone(), d_seed, &a_ws, &proof);
    for incept in [
        b.replica.self_inception().unwrap(),
        c.replica.self_inception().unwrap(),
        d.replica.self_inception().unwrap(),
    ] {
        ok(a.replica
            .admit_member(&incept, vec![Grant::Admin, Grant::Write]));
    }
    for other in [&mut b, &mut c, &mut d] {
        sync_all(&mut a.replica, &mut other.replica);
    }

    // A 2-of-2 group over {A, B}.
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    assert!(
        a.replica.standing_dkg_session().is_some(),
        "group installed"
    );

    // Now propose a handover to {C, D} — disjoint from the current holders.
    // The current group is 2-of-2, so it needs BOTH of {A, B} to sign the
    // rotation, and neither would be able to derive the new key.
    let (resp, _) = a.replica.space_elevate_cmd(
        vec![c_device.as_str().to_string(), d_device.as_str().to_string()],
        2,
    );
    match resp {
        Response::Error { message, .. } => assert!(
            message.contains("current holders"),
            "must explain why it cannot work: {message}"
        ),
        other => panic!("a disjoint handover must be refused, got {other:?}"),
    }

    // Keeping one current holder is still not enough for a 2-of-2: two
    // signatures are needed and only one signer could derive the key.
    let (resp, _) = a.replica.space_elevate_cmd(
        vec![b_device.as_str().to_string(), c_device.as_str().to_string()],
        2,
    );
    // {A, B, C}: both current holders are present, so this one CAN install.
    assert!(
        matches!(resp, Response::Ok { .. }),
        "an overlapping arrangement is allowed: {resp:?}"
    );
}

/// A rogue proposal carries a perfectly
/// valid *device* signature — authentication was never the missing piece.
/// Without an authorization from the recovery authority, no honest node may
/// spend a single DKG round on it, because acting on it is what would
/// eventually let its configuration be installed as the recovery authority.
#[test]
fn an_unauthorized_proposal_moves_no_honest_node() {
    let mut a = new_node(); // founder; holds the solo recovery key
    let a_ws = a.replica.space_str();
    let rogue_seed = [77u8; 32];
    let rogue = device_from_seed(rogue_seed);

    // The attacker names A as a participant, with a threshold they control.
    let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.replica, [1u8; 16], 2, {
        let mut v = vec![a.replica.me.clone(), rogue.clone()];
        v.sort();
        v
    }));
    let ev = crate::dkg::sign_ceremony(&rogue_seed, &propose, &a.replica.space_id);
    assert!(
        ev.verify_sig(crate::dkg::CEREMONY_DOMAIN, &a_ws),
        "the rogue proposal is genuinely signature-valid"
    );
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.persist_membership("rogue").unwrap();

    a.replica.dkg_advance().unwrap();

    assert!(
        a.replica.dkg_read(&id, "r1").is_none(),
        "no round-1 secret was computed for an unauthorized proposal"
    );
    assert!(
        a.replica.dkg_manifest(&id).is_none(),
        "and no acceptance was recorded"
    );
    // Nothing reached the space plane either.
    let cur = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert_eq!(cur.gen, 0, "the recovery authority is untouched");
}

/// The same rogue proposal, now injected into a transcript alongside a
/// *genuine* authorization for a different proposal. Authorization is bound
/// to one proposal hash, so it cannot be lifted to cover another.
#[test]
fn an_authorization_cannot_be_lifted_to_another_proposal() {
    let mut a = new_node();
    let rogue_seed = [78u8; 32];
    let rogue = device_from_seed(rogue_seed);
    let secret = a.replica.read_space_recovery_key().expect("solo key");

    let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.replica, [2u8; 16], 2, {
        let mut v = vec![a.replica.me.clone(), rogue.clone()];
        v.sort();
        v
    }));
    let ev = crate::dkg::sign_ceremony(&rogue_seed, &propose, &a.replica.space_id);
    let rogue_id = crate::dkg::TranscriptId::of(&ev).unwrap();

    // A real authorization, by the real recovery key — but for a DIFFERENT
    // proposal id. Re-pointing it at the rogue proposal must not verify.
    let other = crate::dkg::TranscriptId::parse_hex(&"c".repeat(64)).unwrap();
    // A real grant, by the real recovery key — but for a DIFFERENT proposal.
    // Re-pointing it at the rogue proposal breaks the signature, because the
    // proposal id is inside the signed payload rather than beside it.
    let real = crate::dkg::sign_authority_grant(&secret, &a.replica.space_id, &other);
    let mut lifted = real.clone();
    lifted.op = postcard::to_stdvec(&crate::dkg::AuthorityGrant { proposal: rogue_id }).unwrap();
    let aev = crate::dkg::sign_ceremony(
        &rogue_seed,
        &crate::dkg::CeremonyOp::DkgAuthorize(lifted),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("lifted").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&rogue_id).is_none()
            && a.replica.dkg_read(&rogue_id, "r1").is_none(),
        "an authorization for another proposal authorizes nothing here"
    );
}

/// A proposal authorized by a key that is no longer the recovery authority
/// is not accepted. Guards the case where an old solo key, superseded by a
/// group, is used to authorize a fresh elevation back to attacker control.
#[test]
fn a_proposal_authorized_by_a_superseded_authority_is_rejected() {
    let mut a = new_node();
    let stale_seed = [66u8; 32]; // never the space's recovery key
    let rogue = device_from_seed([79u8; 32]);

    let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(&a.replica, [3u8; 16], 2, {
        let mut v = vec![a.replica.me.clone(), rogue];
        v.sort();
        v
    }));
    let ev = crate::dkg::sign_ceremony(&stale_seed, &propose, &a.replica.space_id);
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    // Well-formed authorization, signed by a key that is not the authority.
    let grant = crate::dkg::sign_authority_grant(&stale_seed, &a.replica.space_id, &id);
    assert!(
        crate::dkg::authority_grant_of(&grant, &a.replica.space_id).is_some(),
        "the grant itself is well formed — only the signer is wrong"
    );
    let aev = crate::dkg::sign_ceremony(
        &stale_seed,
        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("stale").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&id).is_none() && a.replica.dkg_read(&id, "r1").is_none(),
        "authorization must come from the STANDING recovery authority"
    );
}

/// A malformed participant list is rejected at the acceptor, not merely at
/// the proposer. `space_elevate_cmd` sorts and dedupes; a hostile proposer
/// does not, and duplicate entries would corrupt the index→participant map.
#[test]
fn a_malformed_participant_list_is_rejected_by_the_acceptor() {
    let mut a = new_node();
    let secret = a.replica.read_space_recovery_key().expect("solo key");
    let me = a.replica.me.clone();

    // Duplicated participant, and n disagreeing with the list length.
    let propose = crate::dkg::CeremonyOp::DkgPropose(test_proposal(
        &a.replica,
        [4u8; 16],
        2,
        vec![me.clone(), me.clone()],
    ));
    let ev = crate::dkg::sign_ceremony(&[80u8; 32], &propose, &a.replica.space_id);
    let id = crate::dkg::TranscriptId::of(&ev).unwrap();
    // Authorized by the REAL recovery key — only the shape is wrong.
    let grant = crate::dkg::sign_authority_grant(&secret, &a.replica.space_id, &id);
    let aev = crate::dkg::sign_ceremony(
        &[80u8; 32],
        &crate::dkg::CeremonyOp::DkgAuthorize(grant),
        &a.replica.space_id,
    );
    a.replica.membership.add_ceremony_event(&ev).unwrap();
    a.replica.membership.add_ceremony_event(&aev).unwrap();
    a.replica.persist_membership("malformed").unwrap();

    a.replica.dkg_advance().unwrap();
    assert!(
        a.replica.dkg_manifest(&id).is_none() && a.replica.dkg_read(&id, "r1").is_none(),
        "a duplicated/miscounted participant list is not well-formed"
    );
}

/// The rotation target is derived from the stored public-key package, so
/// swapping that artifact cannot redirect the recovery authority — it
/// produces an unusable package rather than an attacker-chosen group key.
#[test]
fn a_swapped_public_key_package_cannot_redirect_the_rotation() {
    let mut a = new_node();
    let a_ws = a.replica.space_str();
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let installed = crate::space::replay(
        &a.replica.genesis,
        &a.replica.space_id,
        &a.replica.membership.space_events(),
    );
    assert_eq!(installed.gen, 1, "the group key was installed");

    // Corrupt the local public-key package; the group key is derived from it,
    // so it can no longer be resolved and the share stops being usable.
    let dkg_id = a.replica.active_dkg_session().expect("A holds a share");
    a.replica.dkg_write(&dkg_id, "pkp", b"swapped").unwrap();
    assert!(
        a.replica.group_key_of_transcript(&dkg_id).is_none(),
        "a swapped package yields no group key rather than an attacker's"
    );
    assert!(
        a.replica.active_dkg_session().is_none(),
        "and the transcript no longer resolves as the live authority"
    );
}
#[test]
fn group_break_glass_recovery_needs_the_threshold_and_re_roots() {
    // After elevation to a 2-of-2 group key, break-glass recovery is a FROST
    // signing ceremony: a holder (B) requests a Recover, both holders co-sign
    // over the synced bulletin board, and the aggregated group signature
    // re-roots the space — convergently, with no solo key anywhere.
    let mut a = new_node();
    with_project(&mut a.replica);
    let a_ws = a.replica.space_str();
    let a_actor = a.replica.my_actor().unwrap();

    let b_seed = [82u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);

    // Elevate {A, B} to a 2-of-2 group recovery key.
    let (resp, _) = a
        .replica
        .space_elevate_cmd(vec![b_device.as_str().to_string()], 2);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    // 2-of-2 is indispensable: both custodians must verify a portable
    // backup before the arrangement may install.
    attest_custody(&mut a, "a");
    attest_custody(&mut b, "b");
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }
    let elevated = crate::space::replay(
        &b.replica.genesis,
        &b.replica.space_id,
        &b.replica.membership.space_events(),
    );
    assert!(!elevated.recovered);

    // B triggers break-glass recovery, re-rooting to itself.
    let (resp, _) = b.replica.space_recover_cmd();
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    let b_actor = b.replica.my_actor().unwrap();
    // The transcript id B posted its request under — the hash of the signed
    // request node, read off the verified board.
    let events = b.replica.membership.ceremony_events();
    let board = crate::dkg::parse_board(&events, &b.replica.space_id);
    let session_hex = board
        .signing
        .keys()
        .next()
        .map(|id| id.to_hex())
        .expect("B posted a recovery request");

    // SECURITY: ceremony automation runs on every import, but it must not
    // co-sign B's UNSOLICITED request. Sync the request to A and spin the
    // ceremony; nothing recovers, because A has given no local consent. Were
    // this to auto-sign, any member could re-root the space to itself.
    for _ in 0..6 {
        sync_all(&mut b.replica, &mut a.replica);
        sync_all(&mut a.replica, &mut b.replica);
    }
    assert!(
        !crate::space::replay(
            &b.replica.genesis,
            &b.replica.space_id,
            &b.replica.membership.space_events(),
        )
        .recovered,
        "passive sync must not auto-co-sign a recovery no other holder consented to"
    );

    // A must name the expected target: approving with the WRONG target is
    // refused before any share is contributed (consent binds to the roots).
    let (bad, _) = a
        .replica
        .space_recover_approve_cmd(session_hex.clone(), vec![a_actor.as_str().to_string()]);
    assert!(
        matches!(bad, Response::Error { .. }),
        "approving a mismatched target must be refused: {bad:?}"
    );
    // A explicitly co-signs, having verified out-of-band that it re-roots to B.
    let (resp, _) = a
        .replica
        .space_recover_approve_cmd(session_hex, vec![b_actor.as_str().to_string()]);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");

    // Now the threshold consents; the group signature aggregates and installs.
    for _ in 0..6 {
        sync_all(&mut a.replica, &mut b.replica);
        sync_all(&mut b.replica, &mut a.replica);
    }

    // The space is re-rooted to B, evicting A, convergently on both.
    for t in [&b.replica, &a.replica] {
        let acl = t.acl_state();
        assert!(acl.is_admin(&b_actor), "recovered root is the new admin");
        assert!(!acl.is_admin(&a_actor), "old root is evicted");
    }
    let rb = crate::space::replay(
        &b.replica.genesis,
        &b.replica.space_id,
        &b.replica.membership.space_events(),
    );
    assert!(rb.recovered && rb.root == vec![b_actor]);
}

#[test]
fn redeem_invite_seals_joiner_and_burns_single_use_nonce() {
    let mut a = new_node(); // founder + admin (me())
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "gated issue");
    let j_incept = incept_for([8u8; 32], &a.replica);
    let j_actor = actor_of(&j_incept);
    let nonce = [1u8; 16];

    let (_, dirty) = ok(a.replica.redeem_invite(&me(), &j_incept, &nonce, true));
    assert!(
        dirty.is_some(),
        "a successful admit dirties the catalog/ACL"
    );
    assert!(
        a.replica.is_member_actor(&j_actor),
        "joiner is now a member"
    );
    assert!(
        a.replica.acl_state().is_nonce_spent(&nonce),
        "single-use nonce is burned in the same commit"
    );

    // Replay: the same nonce must not seat a second, different joiner.
    let other = incept_for([9u8; 32], &a.replica);
    let refusal = refused(a.replica.redeem_invite(&me(), &other, &nonce, true));
    assert!(
        matches!(refusal, ReplicaError::Conflict(Conflict::InviteRedeemed)),
        "spent nonce is rejected as a replay, not something else: {refusal:?}"
    );
    assert!(
        !a.replica.is_member_actor(&actor_of(&other)),
        "replay seats no one"
    );
}

#[test]
fn a_revoked_invite_admits_no_one() {
    // The kill switch: once an admin revokes a nonce, no redemption via it
    // seats anyone — the only way to retire a leaked (esp. reusable) invite.
    let mut a = new_node(); // founder + admin
    let nonce = [7u8; 16];
    let j_incept = incept_for([61u8; 32], &a.replica);
    let j_actor = actor_of(&j_incept);

    ok(a.replica
        .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce)));
    assert!(a.replica.acl_state().is_invite_revoked(&nonce));

    let refusal = refused(a.replica.redeem_invite(&me(), &j_incept, &nonce, true));
    assert!(
        matches!(refusal, ReplicaError::Conflict(Conflict::InviteRevoked)),
        "a revoked invite admits no one: {refusal:?}"
    );
    assert!(!a.replica.is_member_actor(&j_actor));

    // A different, un-revoked nonce still admits the same joiner.
    let (admitted, dirty) = ok(a.replica.redeem_invite(&me(), &j_incept, &[8u8; 16], true));
    assert!(
        matches!(admitted, Admission::AutoApproved(_)),
        "{admitted:?}"
    );
    assert!(dirty.is_some(), "an admission commits");
    assert!(a.replica.is_member_actor(&j_actor));
}

/// Unstaggered repair is bounded: admins that observe the fence independently
/// each mint once, the concurrent mints converge by `(gen, id)`, and once a
/// discharging epoch is visible no further import mints again.
///
/// Only two of the three can race by construction — B has to redeem *before*
/// seeing the revoke (`redeem_invite` refuses a revoked nonce outright), so
/// B necessarily learns of the fence together with someone's mint. That is
/// itself the stop-minting property, asserted at the end.
#[test]
fn concurrent_fence_repairs_converge_and_then_stop() {
    let mut a = new_node(); // founder + admin A
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let a_ws = a.replica.space_str();
    let proof = a.replica.founding_proof().unwrap();

    // B and C join as admins.
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(b_device.clone(), b_seed, &a_ws, &proof);
    let c_seed = [31u8; 32];
    let mut c = new_joiner_node_as(device_from_seed(c_seed), c_seed, &a_ws, &proof);
    for incept in [
        b.replica.self_inception().unwrap(),
        c.replica.self_inception().unwrap(),
    ] {
        ok(a.replica
            .admit_member(&incept, vec![Grant::Admin, Grant::Write]));
    }
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut a.replica, &mut c.replica);
    let gen_before = a.replica.active_epoch().unwrap().gen;

    // ---- PARTITION: B redeems, A revokes ----
    let nonce = [7u8; 16];
    let x_seed = [61u8; 32];
    let x_device = device_from_seed(x_seed);
    let x_incept = incept_for(x_seed, &b.replica);
    let x_actor = actor_of(&x_incept);
    ok(b.replica.redeem_invite(&b_device, &x_incept, &nonce, true));
    ok(a.replica
        .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce)));

    // C sees the redemption first (no fence yet), then the revoke — so C
    // raises the fence and repairs without having seen anyone else's mint.
    sync_membership(&mut b.replica, &mut c.replica);
    assert_eq!(
        c.replica.active_epoch().unwrap().gen,
        gen_before,
        "a redemption alone raises no fence"
    );
    sync_membership(&mut a.replica, &mut c.replica);
    // A independently receives the redemption and repairs too.
    sync_membership(&mut b.replica, &mut a.replica);

    let a_epoch = a.replica.active_epoch().unwrap();
    let c_epoch = c.replica.active_epoch().unwrap();
    assert_eq!(
        (a_epoch.gen, c_epoch.gen),
        (gen_before + 1, gen_before + 1),
        "both admins minted once, at the same generation"
    );
    assert_ne!(a_epoch.id, c_epoch.id, "the mints are genuinely concurrent");

    // ---- MERGE: converge on one tip ----
    sync_membership(&mut a.replica, &mut c.replica);
    sync_membership(&mut c.replica, &mut a.replica);
    let winner = a.replica.active_epoch().unwrap();
    assert_eq!(
        c.replica.active_epoch().unwrap().id,
        winner.id,
        "(gen, id) selects one tip on both replicas"
    );
    assert_eq!(
        winner.gen,
        gen_before + 1,
        "converging on a concurrent mint does not escalate the generation"
    );

    // B learns of the fence and a discharging epoch together: no new mint.
    sync_membership(&mut a.replica, &mut b.replica);
    assert_eq!(
        b.replica.active_epoch().unwrap().id,
        winner.id,
        "B adopts the fenced tip rather than minting again"
    );
    // And a further round of imports is inert everywhere.
    sync_membership(&mut b.replica, &mut a.replica);
    sync_membership(&mut a.replica, &mut c.replica);
    assert_eq!(
        a.replica.active_epoch().unwrap().id,
        winner.id,
        "a satisfied fence never re-raises"
    );
    assert_eq!(c.replica.active_epoch().unwrap().id, winner.id);

    // The security property, on the tip everyone settled on.
    for node in [&a, &b, &c] {
        assert!(!node.replica.is_member_actor(&x_actor), "X is evicted");
        assert!(
            node.replica.acl_state().rekey_fences().is_empty(),
            "no outstanding obligation"
        );
        assert!(
            !node
                .replica
                .membership
                .sealed_devices(&winner.id)
                .contains(&x_device),
            "X holds no key for the converged tip"
        );
    }
}

/// End-to-end kill switch across a partition: A revokes a leaked invite
/// while B concurrently redeems it. After merge the admitted actor must be
/// out of the member set *and* fenced off the live key.
///
/// The fence has to be **causal**, not a recipient-list comparison, and this
/// test pins why: `seal_epochs_to_actor` seals epochs to a joiner by writing
/// blobs into the membership store without ever touching `EpochAuth.members`,
/// so the admitted actor holds the live key while absent from its declared
/// recipient list. The asserts below show every state trigger reading
/// "healthy" at the moment the key is compromised.
#[test]
fn a_concurrently_revoked_invite_is_fenced_by_an_automatic_rekey() {
    let mut a = new_node(); // founder + admin A
    with_project(&mut a.replica);
    new_issue(&mut a.replica, "secret");
    let a_ws = a.replica.space_str();

    // B joins as a second ADMIN and syncs.
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica
        .admit_member(&b_incept, vec![Grant::Admin, Grant::Write]));
    sync_all(&mut a.replica, &mut b.replica);
    let epoch_before = b.replica.active_epoch().expect("an epoch exists");

    // ---- PARTITION ----
    // A revokes the leaked invite.
    let nonce = [7u8; 16];
    ok(a.replica
        .invite_revoke_cmd(data_encoding::HEXLOWER.encode(&nonce)));

    // B, not having seen the revoke, redeems it for X — sealing X the epochs
    // live at that moment.
    let x_seed = [61u8; 32];
    let x_device = device_from_seed(x_seed);
    let x_incept = incept_for(x_seed, &b.replica);
    let x_actor = actor_of(&x_incept);
    ok(b.replica.redeem_invite(&b_device, &x_incept, &nonce, true));
    assert!(
        b.replica
            .membership
            .sealed_devices(&epoch_before.id)
            .contains(&x_device),
        "X holds the live epoch's key"
    );
    assert!(
        !epoch_before.members.contains(&x_actor),
        "yet X never appears in that epoch's declared recipient list — the \
         blind spot a recipient-set trigger cannot see through"
    );

    // ---- MERGE ----
    sync_membership(&mut b.replica, &mut a.replica);
    sync_membership(&mut a.replica, &mut b.replica);

    // Revoke wins: X is out, and the fence was discharged by a rotation.
    assert!(
        !a.replica.is_member_actor(&x_actor),
        "revoke wins over the concurrent redemption"
    );
    assert!(
        a.replica.acl_state().rekey_fences().is_empty(),
        "the rekey obligation was discharged automatically on import"
    );
    let active = a.replica.active_epoch().unwrap();
    assert!(
        active.gen > epoch_before.gen,
        "an admin rotated past the fence on merge"
    );
    assert!(
        !a.replica
            .membership
            .sealed_devices(&active.id)
            .contains(&x_device),
        "the evicted actor holds no key for the fenced epoch"
    );

    // Convergent: B lands on the same tip and mints nothing further.
    let gen_after = active.gen;
    sync_membership(&mut a.replica, &mut b.replica);
    assert_eq!(
        b.replica.active_epoch().map(|e| e.gen),
        Some(gen_after),
        "B converges on the fenced tip without minting again"
    );
}

#[test]
fn redeem_invite_rejects_a_non_admin_issuer() {
    let mut a = new_node(); // only me() is an admin
    let issuer = device_from_seed([5u8; 32]); // never added to the ACL
    let j_incept = incept_for([8u8; 32], &a.replica);

    let refusal = refused(
        a.replica
            .redeem_invite(&issuer, &j_incept, &[2u8; 16], true),
    );
    assert!(
        matches!(refusal, ReplicaError::Denied(Denied::IssuerNotAdmin)),
        "a pass signed by a non-admin is not honored: {refusal:?}"
    );
    assert!(
        !a.replica.is_member_actor(&actor_of(&j_incept)),
        "no membership granted on a bad issuer"
    );
}

#[test]
fn redeem_invite_is_idempotent_for_an_existing_member() {
    let mut a = new_node();
    let j_incept = incept_for([8u8; 32], &a.replica);
    let j_actor = actor_of(&j_incept);
    ok(a.replica.admit_member(&j_incept, vec![Grant::Write]));
    assert!(a.replica.is_member_actor(&j_actor));

    let (admitted, dirty) = ok(a.replica.redeem_invite(&me(), &j_incept, &[3u8; 16], true));
    assert!(
        matches!(admitted, Admission::AlreadyMember(_)),
        "the seat was already held: {admitted:?}"
    );
    assert!(dirty.is_none(), "already a member ⇒ no ACL churn");
}

#[test]
fn redeem_invite_reusable_pass_admits_many_without_burning() {
    let mut a = new_node();
    let nonce = [4u8; 16];
    let j1 = incept_for([8u8; 32], &a.replica);
    let j2 = incept_for([9u8; 32], &a.replica);

    let (r1, _) = ok(a.replica.redeem_invite(&me(), &j1, &nonce, false));
    let (r2, _) = ok(a.replica.redeem_invite(&me(), &j2, &nonce, false));
    assert!(matches!(r1, Admission::AutoApproved(_)), "{r1:?}");
    assert!(matches!(r2, Admission::AutoApproved(_)), "{r2:?}");
    assert!(a.replica.is_member_actor(&actor_of(&j1)) && a.replica.is_member_actor(&actor_of(&j2)));
    assert!(
        !a.replica.acl_state().is_nonce_spent(&nonce),
        "a reusable pass is never burned"
    );
}

#[test]
fn completion_leaves_board_list_but_stays_in_docs() {
    // A done issue is removed from boards[proj] but stays in docs and
    // renders in the Done column via the append rule.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "finish me");
    let board_len = |t: &Replica| {
        let pid = t.catalog().project_by_key("ENG").unwrap().id;
        t.catalog().board_order(&pid).len()
    };
    assert_eq!(board_len(&n.replica), 1);
    n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("done".into()),
        priority: None,
        description: None,
    });
    // board movable list is now empty (bounded to the active set)...
    assert_eq!(board_len(&n.replica), 0);
    // ...but the issue still renders in the Done column.
    let done_present = match n
        .replica
        .handle(Request::Board {
            project: Some("ENG".into()),
            project_hint: None,
        })
        .0
    {
        Response::Board(b) => b
            .columns
            .iter()
            .find(|c| c.state.id == "done")
            .map(|c| c.rows.iter().any(|r| r.reff == reff))
            .unwrap_or(false),
        _ => false,
    };
    assert!(done_present, "done issue renders in the Done column");
    // and it is still counted as an existing issue.
    assert_eq!(n.replica.issue_count(), 1);
}

#[test]
fn derive_project_key_shapes() {
    assert_eq!(derive_project_key("Engineering"), "ENGI");
    assert_eq!(derive_project_key("lait"), "LAIT");
    assert_eq!(derive_project_key("my cool app"), "MCA");
    assert_eq!(
        derive_project_key("Media Automation Stack Thing Extra"),
        "MAST"
    );
    assert_eq!(derive_project_key("x-1"), "X");
    assert_eq!(derive_project_key("42"), "PRJ");
    assert_eq!(derive_project_key(""), "PRJ");
    // Always alias/branch-parseable: 1-8 ASCII letters.
    for name in ["Engineering", "a b c d e f", "ünïcödé", "--- ---"] {
        let k = derive_project_key(name);
        assert!(
            (1..=8).contains(&k.len()) && k.chars().all(|c| c.is_ascii_uppercase()),
            "{name} → {k}"
        );
    }
}

#[test]
fn founding_seeds_a_usable_space() {
    let mut n = new_node();
    // The founder can create an issue immediately — no `projects new` first.
    let (resp, dirty) = n.replica.handle(Request::IssueNew {
        title: "first".into(),
        project: None,
        project_hint: None,
        assignees: vec![],
        priority: None,
        labels: vec![],
        body: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    assert!(dirty.is_some());
    assert_eq!(n.replica.project_count(), 1, "exactly the seeded project");
    assert_eq!(n.replica.space_name(), "Testbed");
    let seeded = &n.replica.catalog().projects_list()[0];
    assert_eq!(seeded.key, "TEST", "key derived from the space name");
}

#[test]
fn founding_twice_errors() {
    let n = new_node();
    let store = Store::open(&n.home).unwrap();
    let err = found_space(&store, &me(), &[1u8; 32], "Again", &FakeClock::new(1)).unwrap_err();
    assert!(
        format!("{err:#}").contains("already initialized"),
        "{err:#}"
    );
}

#[test]
fn open_errors_on_an_uninitialized_store() {
    let home = std::env::temp_dir().join(format!(
        "gc-trk-noinit-{}-{}",
        std::process::id(),
        DocId::mint(&crate::ids::SystemUlidSource)
    ));
    std::fs::create_dir_all(&home).unwrap();
    let store = Store::open(&home).unwrap();
    let err = match Replica::open(
        store,
        me(),
        "tester".into(),
        ME_SEED,
        Box::new(FakeClock::new(1)),
    ) {
        Ok(_) => panic!("open must not lazily found a space"),
        Err(e) => e,
    };
    assert!(
        format!("{err:#}").contains("not initialized"),
        "no lazy mint: {err:#}"
    );
    let _ = std::fs::remove_dir_all(&home);
}

#[test]
fn choose_project_chain() {
    let mut n = new_node(); // seeded TEST project
                            // Sole project: no -p needed.
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: None,
    });
    assert!(matches!(resp, Response::Board(_)), "{resp:?}");

    with_project(&mut n.replica); // + ENG → ambiguous
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: None,
    });
    let msg = match resp {
        Response::Error { ref message, .. } => message.clone(),
        other => panic!("expected teaching error, got {other:?}"),
    };
    assert!(msg.contains("TEST") && msg.contains("ENG"), "{msg}");
    assert!(msg.contains("project.default"), "teaches the fix: {msg}");

    // A resolvable hint (the CLI's git-branch key) breaks the tie…
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: Some("eng".into()),
    });
    assert!(
        matches!(resp, Response::Board(_)),
        "hint resolves: {resp:?}"
    );
    // …an unresolvable hint falls through silently (back to ambiguous).
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: Some("wip".into()),
    });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

    // Explicit beats everything, and an explicit miss is a hard error.
    let (resp, _) = n.replica.handle(Request::Board {
        project: Some("NOPE".into()),
        project_hint: Some("eng".into()),
    });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");

    // A configured default resolves the ambiguity…
    let mut store_cfg = crate::config::ConfigMap::default();
    store_cfg.set("project.default", "ENG");
    store_cfg
        .save(&crate::config::store_config_path(&n.home))
        .unwrap();
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: None,
    });
    assert!(matches!(resp, Response::Board(_)), "{resp:?}");
    // …but a stale one errors loudly instead of silently rotting.
    let mut store_cfg = crate::config::ConfigMap::default();
    store_cfg.set("project.default", "GONE");
    store_cfg
        .save(&crate::config::store_config_path(&n.home))
        .unwrap();
    let (resp, _) = n.replica.handle(Request::Board {
        project: None,
        project_hint: None,
    });
    let msg = match resp {
        Response::Error { ref message, .. } => message.clone(),
        other => panic!("expected stale-default error, got {other:?}"),
    };
    assert!(msg.contains("GONE"), "{msg}");
}

#[test]
fn work_state_verbs_are_atomic_and_idempotent() {
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "flaky reconnect");
    let me_actor = n.replica.my_actor().unwrap();

    // start: one request = assignee + status in ONE commit / ONE activity row.
    let before = n.replica.activity_high_water();
    let (resp, dirty) = n.replica.handle(Request::IssueStart { reff: reff.clone() });
    let v = match resp {
        Response::Issue(v) => v,
        other => panic!("start returns the fresh snapshot, got {other:?}"),
    };
    assert_eq!(v.status, "in_progress", "first Active-category state");
    assert!(v.assignees.contains(&me_actor), "start assigns the caller");
    assert!(dirty.is_some());
    assert_eq!(
        n.replica.activity_high_water(),
        before + 1,
        "one intent = one activity row"
    );

    // idempotent: already started → snapshot back, no commit, no doorbell.
    let (resp, dirty) = n.replica.handle(Request::IssueStart { reff: reff.clone() });
    assert!(matches!(resp, Response::Issue(_)));
    assert!(dirty.is_none(), "no-op start must not ring");
    assert_eq!(n.replica.activity_high_water(), before + 1);

    // Done changes status only, keeps the assignee, and empties the board list.
    let (resp, _) = n.replica.handle(Request::IssueDone { reff: reff.clone() });
    let v = match resp {
        Response::Issue(v) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(v.status, "done");
    assert!(v.assignees.contains(&me_actor), "done keeps the assignee");

    // stop: back to backlog, unassigned.
    let (resp, _) = n.replica.handle(Request::IssueStop { reff });
    let v = match resp {
        Response::Issue(v) => v,
        other => panic!("{other:?}"),
    };
    assert_eq!(v.status, "backlog", "first Backlog-category state");
    assert!(
        !v.assignees.contains(&me_actor),
        "stop unassigns the caller"
    );
}

#[test]
fn labels_are_created_on_first_use_for_adds_only() {
    let mut n = new_node();
    with_project(&mut n.replica);
    // Creating an issue with an unknown label mints it (gray).
    let (resp, dirty) = n.replica.handle(Request::IssueNew {
        title: "tagged".into(),
        project: Some("ENG".into()),
        project_hint: None,
        assignees: vec![],
        priority: None,
        labels: vec!["perf".into()],
        body: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    assert!(
        dirty.unwrap().dirty_catalog.contains(&CatalogScope::Labels),
        "a minted label dirties the Labels scope"
    );
    assert!(
        n.replica.catalog().label_by_name("perf").is_some(),
        "label exists after first use"
    );

    // `label <ref> +new` also creates; `-unknown` (remove) still errors.
    let reff = new_issue(&mut n.replica, "plain");
    let (resp, _) = n.replica.handle(Request::Label {
        reff: reff.clone(),
        add: vec!["ux".into()],
        remove: vec![],
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    assert!(n.replica.catalog().label_by_name("ux").is_some());
    let (resp, dirty) = n.replica.handle(Request::Label {
        reff,
        add: vec![],
        remove: vec!["never-existed".into()],
    });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
    assert!(dirty.is_none());

    // A dangling lbl_ id is a typo, not a new name — and creates nothing.
    let count_before = n.replica.catalog().labels_list().len();
    let (resp, _) = n.replica.handle(Request::IssueNew {
        title: "typo".into(),
        project: Some("ENG".into()),
        project_hint: None,
        assignees: vec![],
        priority: None,
        labels: vec!["lbl_00000000000000000000000000".into()],
        body: None,
    });
    assert!(matches!(resp, Response::Error { .. }), "{resp:?}");
    assert_eq!(n.replica.catalog().labels_list().len(), count_before);
}

#[test]
fn inbox_derives_addressed_to_me_from_imports() {
    let mut a = new_node(); // founder
    with_project(&mut a.replica);
    let b_seed = [8u8; 32];
    let b_device = device_from_seed(b_seed);
    let a_ws = a.replica.space_str();
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));

    // A files an issue assigned to B, then syncs: the doc is NEW to B, so
    // backfill emits exactly ONE entry (assigned), no comment/status flood.
    let (resp, _) = a.replica.handle(Request::IssueNew {
        title: "for bob".into(),
        project: Some("ENG".into()),
        project_hint: None,
        assignees: vec![b_device.as_str().to_string()],
        priority: None,
        labels: vec![],
        body: None,
    });
    let reff = match resp {
        Response::Ref { reff } => reff,
        other => panic!("{other:?}"),
    };
    sync_all(&mut a.replica, &mut b.replica);
    let (entries, unread) = crate::inbox::list(&b.home);
    assert_eq!(entries.len(), 1, "backfill-bounded: {entries:?}");
    assert_eq!(entries[0].kind, "assigned");
    assert_eq!(unread, 1);

    // A comments + moves status; B's next import derives both, with the
    // comment attributed to A's **actor** — the person, not the device that
    // happened to type it, so the attribution outlives A rotating devices.
    let (resp, _) = a.replica.handle(Request::Comment {
        reff: reff.clone(),
        body: "root cause found".into(),
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    let (resp, _) = a.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("in_progress".into()),
        priority: None,
        description: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    sync_all(&mut a.replica, &mut b.replica);
    let (entries, _) = crate::inbox::list(&b.home);
    assert_eq!(entries.len(), 3, "{entries:?}");
    let comment = entries.iter().find(|e| e.kind == "comment").unwrap();
    assert_eq!(comment.detail, "root cause found");
    let a_actor = a.replica.my_actor().expect("A has an actor identity");
    assert_eq!(
        comment.actor.as_deref(),
        Some(a_actor.as_str()),
        "a comment is attributed to the authoring actor, not its device key"
    );
    let status = entries.iter().find(|e| e.kind == "status").unwrap();
    assert!(status.detail.contains("in_progress"), "{status:?}");

    // A's own local mutations never enter A's inbox; and B's imports of an
    // issue that isn't B's produce nothing.
    assert!(crate::inbox::list(&a.home).0.is_empty());
    new_issue(&mut a.replica, "not bob's");
    sync_all(&mut a.replica, &mut b.replica);
    assert_eq!(
        crate::inbox::list(&b.home).0.len(),
        3,
        "unrelated docs stay out"
    );
}

#[test]
fn history_survives_daemon_restart() {
    // `lait history` is derived from the oplog on
    // disk, not a per-session ring — a fresh replica over the same store
    // (the daemon-restart case, which idle-shutdown makes the NORMAL case)
    // returns the full feed with kinds, actors, timestamps and transitions.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "durable");
    let (resp, _) = n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("in_progress".into()),
        priority: Some("high".into()),
        description: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

    // "Restart": a brand-new replica over the same store. The old activity
    // ring is dropped with the old instance.
    let store2 = Store::open(&n.home).unwrap();
    let mut t2 = Replica::open(
        store2,
        me(),
        "tester".into(),
        ME_SEED,
        Box::new(FakeClock::new(1_000_000)),
    )
    .unwrap();
    let (resp, _) = t2.handle(Request::History { reff });
    let events = match resp {
        Response::Activity { events, .. } => events,
        other => panic!("{other:?}"),
    };
    assert_eq!(events.len(), 2, "created + edited: {events:?}");
    assert_eq!(events[0].kind, "created");
    assert_eq!(events[1].kind, "edited");
    assert_eq!(events[1].actor, Some(me()), "advisory actor survives");
    let status = events[1]
        .changes
        .iter()
        .find(|c| c.field == "status")
        .expect("status transition recorded");
    assert_eq!(status.from.as_deref(), Some("backlog"));
    assert_eq!(status.to.as_deref(), Some("in_progress"));
    assert!(
        events[1].changes.iter().any(|c| c.field == "priority"),
        "multi-field edit keeps all transitions: {events:?}"
    );
}

#[test]
fn synced_rows_carry_field_changes_actor_and_collision() {
    // A remote change arrives with field-level changes
    // and its (advisory) actor, and a genuinely concurrent import raises
    // the DAG collision flag — the compensating control for LWW fields.
    let mut a = new_node();
    with_project(&mut a.replica);
    let b_seed = [9u8; 32];
    let b_device = device_from_seed(b_seed);
    let a_ws = a.replica.space_str();
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));
    let reff = new_issue(&mut a.replica, "contested");
    sync_all(&mut a.replica, &mut b.replica);

    // Concurrent edits: A moves the title while B moves the status.
    let (resp, _) = a.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: Some("renamed by a".into()),
        status: None,
        priority: None,
        description: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    let (resp, _) = b.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("in_progress".into()),
        priority: None,
        description: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

    let before = b.replica.activity_high_water();
    // Drive A's concurrent doc edit into B directly. (A single
    // catalog-triggered pull can transiently *skip* a concurrent same-doc
    // edit: the catalog row `head` is one LWW cell both peers write, so
    // when the puller wins that race `local_head == cat_head` looks
    // up-to-date though the provider holds a concurrent op. It self-heals
    // over bidirectional gossip rounds — a convergence lag orthogonal to
    // this test, which is about the *import* producing a correct synced
    // row. An empty VV requests the full doc; import is idempotent and the
    // concurrent branch still registers.)
    let did = a.replica.resolve_issue(&reff).unwrap().to_string();
    let enc = a.replica.export_doc_from(&did, &[]).unwrap().unwrap();
    b.replica.import_doc(&did, &enc).unwrap();
    let (resp, _) = b.replica.handle(Request::Activity { since: before });
    let events = match resp {
        Response::Activity { events, .. } => events,
        other => panic!("{other:?}"),
    };
    let synced = events
        .iter()
        .find(|e| e.kind == "synced")
        .expect("import produces a synced row");
    assert!(
        synced
            .changes
            .iter()
            .any(|c| { c.field == "title" && c.to.as_deref() == Some("renamed by a") }),
        "field-level change on the synced row: {synced:?}"
    );
    assert_eq!(
        synced.actor,
        Some(me()),
        "the incoming change's advisory actor is surfaced"
    );
    assert!(
        synced.collision,
        "concurrent branches must raise the collision flag: {synced:?}"
    );
}

#[test]
fn link_parent_graph_roundtrip() {
    let mut n = new_node();
    with_project(&mut n.replica);
    new_issue(&mut n.replica, "epic");
    new_issue(&mut n.replica, "child");
    new_issue(&mut n.replica, "blocker");
    // Re-resolve after all creates: a canonical short handle minted earlier
    // can become ambiguous once same-millisecond siblings share its prefix.
    let by_title = |t: &mut Replica, title: &str| -> String {
        match t
            .handle(Request::List {
                project: None,
                filter: Filter::default(),
            })
            .0
        {
            Response::List { rows } => rows
                .into_iter()
                .find(|r| r.title == title)
                .map(|r| r.reff)
                .expect("row present"),
            other => panic!("{other:?}"),
        }
    };
    let epic = by_title(&mut n.replica, "epic");
    let child = by_title(&mut n.replica, "child");
    let blocker = by_title(&mut n.replica, "blocker");

    let (resp, dirty) = n.replica.handle(Request::IssueParent {
        reff: child.clone(),
        parent: Some(epic.clone()),
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    assert!(dirty.is_some(), "a parent change rings a doorbell");

    let (resp, _) = n.replica.handle(Request::IssueLink {
        reff: blocker.clone(),
        kind: "blocks".into(),
        target: child.clone(),
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

    let (resp, _) = n.replica.handle(Request::IssueGraph {
        reff: child.clone(),
    });
    let g = match resp {
        Response::Graph(g) => g,
        other => panic!("{other:?}"),
    };
    assert_eq!(g.parent.as_ref().map(|r| r.title.as_str()), Some("epic"));
    assert_eq!(g.links.len(), 1);
    assert_eq!(g.links[0].kind, "blocks");
    assert_eq!(g.links[0].direction, "in");
    assert_eq!(
        g.blocked_by
            .iter()
            .map(|r| r.title.as_str())
            .collect::<Vec<_>>(),
        vec!["blocker"],
        "open blocker surfaces transitively"
    );

    // Finishing the blocker clears the blocked_by set (it is open-only)…
    let (resp, _) = n.replica.handle(Request::IssueDone {
        reff: blocker.clone(),
    });
    assert!(matches!(resp, Response::Issue(_)), "{resp:?}");
    let (resp, _) = n.replica.handle(Request::IssueGraph {
        reff: child.clone(),
    });
    let g = match resp {
        Response::Graph(g) => g,
        other => panic!("{other:?}"),
    };
    assert!(g.blocked_by.is_empty(), "{:?}", g.blocked_by);
    // …while the link itself remains until unlinked.
    assert_eq!(g.links.len(), 1);
    let (resp, _) = n.replica.handle(Request::IssueUnlink {
        reff: blocker.clone(),
        kind: "blocks".into(),
        target: child.clone(),
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");

    // Cycle guard: the epic cannot become its own descendant.
    let (resp, dirty) = n.replica.handle(Request::IssueParent {
        reff: epic.clone(),
        parent: Some(child.clone()),
    });
    assert!(
        matches!(&resp, Response::Error { message, .. } if message.contains("ancestor")),
        "{resp:?}"
    );
    assert!(dirty.is_none(), "a rejected parent rings no doorbell");

    // Unparent restores a top-level issue.
    let (resp, _) = n.replica.handle(Request::IssueParent {
        reff: child.clone(),
        parent: None,
    });
    assert!(matches!(resp, Response::Ref { .. }), "{resp:?}");
    let (resp, _) = n.replica.handle(Request::IssueGraph { reff: child });
    match resp {
        Response::Graph(g) => assert!(g.parent.is_none()),
        other => panic!("{other:?}"),
    }
}

#[test]
fn signed_delete_syncs_agents_cannot_delete_and_restore_wins() {
    // Exercise signed authorization operations through the real sync path:
    //  - a member's signed delete propagates to a peer (tombstone is a
    //    cache of the authz replay, reconciled on import),
    //  - a sponsored agent cannot delete (no content authority),
    //  - restore clears it, and the members log attributes everything.
    let mut a = new_node(); // founder/admin
    with_project(&mut a.replica);
    let b_seed = [21u8; 32];
    let b_device = device_from_seed(b_seed);
    let a_ws = a.replica.space_str();
    let mut b = new_joiner_node_as(
        b_device.clone(),
        b_seed,
        &a_ws,
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();
    ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));
    // B must sync to learn it is a member before it can act as one.
    sync_all(&mut a.replica, &mut b.replica);
    let b_actor = actor_of(&b_incept);
    assert!(
        b.replica.acl_state().is_human_member(&b_actor),
        "B sees itself"
    );

    // B sponsors an agent (the agent self-incepted its degenerate actor).
    let agent_incept = incept_for([99u8; 32], &b.replica);
    let agent_actor = actor_of(&agent_incept);
    let (resp, _) = b.replica.agent_add(&agent_incept);
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert!(b.replica.acl_state().is_agent(&agent_actor));
    assert_eq!(
        b.replica.acl_state().sponsor_of(&agent_actor),
        Some(&b_actor),
        "the agent's sponsor is B"
    );
    assert!(
        !b.replica.acl_state().is_human_member(&agent_actor),
        "an agent is not a human member"
    );

    let reff = new_issue(&mut a.replica, "delete me");
    sync_all(&mut a.replica, &mut b.replica);
    sync_all(&mut b.replica, &mut a.replica);

    // B (a human member) deletes; it must appear deleted on A after sync.
    let (resp, _) = b
        .replica
        .handle(Request::IssueDelete { reff: reff.clone() });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    assert!(
        b.replica
            .authz_state()
            .is_tombstoned(&b.replica.resolve_issue(&reff).unwrap()),
        "deleted locally on B"
    );
    sync_all(&mut b.replica, &mut a.replica);
    let a_id = a.replica.resolve_issue(&reff).unwrap();
    assert!(
        a.replica.catalog().row(&a_id).unwrap().tombstone,
        "a peer's signed delete reconciles into A's tombstone cache"
    );

    // Restore on A, sync back: restore clears it on B (restore-wins).
    let (resp, _) = a
        .replica
        .handle(Request::IssueRestore { reff: reff.clone() });
    assert!(matches!(resp, Response::Ok { .. }), "{resp:?}");
    sync_all(&mut a.replica, &mut b.replica);
    let b_id = b.replica.resolve_issue(&reff).unwrap();
    assert!(
        !b.replica.catalog().row(&b_id).unwrap().tombstone,
        "the restore propagates and clears the tombstone on B"
    );

    // The members log is cryptographic provenance, in causal order.
    let log = match a.replica.handle(Request::MemberLog).0 {
        Response::MemberLog { entries } => entries,
        other => panic!("{other:?}"),
    };
    assert!(
        log.iter().any(|e| e.kind == "add_member" && e.authorized),
        "the member-add is logged authorized: {log:?}"
    );
    assert!(
        log.iter().any(|e| e.kind == "add_agent" && e.authorized),
        "the agent sponsorship is logged authorized: {log:?}"
    );
}

#[test]
fn project_key_charset_is_validated() {
    let mut n = new_node();
    for bad in ["A-1", "MY KEY", "TOOLONGKEY", "42"] {
        let (resp, dirty) = n.replica.handle(Request::ProjectNew {
            name: "X".into(),
            key: bad.into(),
        });
        assert!(
            matches!(resp, Response::Error { .. }),
            "'{bad}' should be rejected, got {resp:?}"
        );
        assert!(dirty.is_none());
    }
}

/// The read contract the **web viewer** depends on, pinned so a fabric change
/// can't silently rot it.
///
/// This exists because it already happened once. The fabric moved per-issue
/// history from a session ring onto the durable oplog, which changed how an
/// `ActivityEvent` attributes: `actor` became the real per-op key and
/// `actor_nick` went empty. The viewer read `actor_nick` for the display name,
/// so every history row lost its author — and nothing caught it, because
/// `tests/viewer_parity.rs` guards *Request field names*, never *Response
/// semantics*. This is the missing half: a behavioral pin on the values the
/// client reads. If one of these assertions fails, a viewer that depends on it
/// (`viewer/src/core/activity.ts`) needs updating in the same change.
#[test]
fn history_is_the_contract_the_viewer_reads() {
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "fix login");
    n.replica.handle(Request::IssueEdit {
        reff: reff.clone(),
        title: None,
        status: Some("in_progress".into()),
        priority: None,
        description: None,
    });
    n.replica.handle(Request::Comment {
        reff: reff.clone(),
        body: "on it".into(),
    });

    let (resp, _) = n.replica.handle(Request::History { reff });
    let events = match resp {
        Response::Activity { events, .. } => events,
        other => panic!("History must reply Activity, got {other:?}"),
    };
    assert!(
        !events.is_empty(),
        "a created+edited+commented issue has history"
    );

    for e in &events {
        // 1. Attribution travels in `actor` (a key the client resolves), NOT in
        //    `actor_nick`. The viewer's describeEvent resolves `actor`; if this
        //    flips, it shows no name. This is the exact regression, pinned.
        assert!(
            !e.actor_nick.is_empty() || e.actor.is_some(),
            "event {:?} has neither actor nor actor_nick — viewer would show no author",
            e.kind
        );
        if let Some(actor) = &e.actor {
            assert_eq!(
                actor.as_str().len(),
                64,
                "actor must be a full key the viewer can resolve to a member: {actor:?}"
            );
        }

        // 2. Durable history carries real timestamps (the viewer renders `when(ts)`).
        assert_ne!(
            e.ts, 0,
            "history event {:?} has ts 0 — not a durable op",
            e.kind
        );

        // 3. No synthetic `synced` in per-issue history. The viewer's
        //    synced->no-name special case is for the space Activity feed
        //    only; a `synced` here would make it drop a real author.
        assert_ne!(
            e.kind, "synced",
            "per-issue history must be real ops, not a synced marker"
        );
    }

    // 4. The states the viewer walks are present as real ops, each attributed.
    let created = events.iter().find(|e| e.kind == "created");
    assert!(created.is_some(), "history includes the `created` op");
    assert!(
        created.unwrap().actor.is_some(),
        "even `created` carries a resolvable actor — the viewer names it"
    );
}

// ---- Change, and the read side of the control adapter ----
//
// These assert the distinction the daemon actually acts on: `None` means
// nothing happened and no doorbell rings, while `Some(empty)` means a commit
// landed whose scope no subscriber needs. `node::ring_doorbell` does not check
// `DirtySet::is_empty()`, so collapsing the two would ring for rejected writes.

#[test]
fn an_unchanged_command_reports_no_dirty_set() {
    let (value, dirty) = Change::unchanged("ok").into_parts();
    assert_eq!(value, "ok");
    assert!(dirty.is_none(), "an idempotent no-op rings no doorbell");
}

#[test]
fn a_committed_command_reports_its_dirty_set() {
    let dirty = DirtySet::catalog(CatalogScope::Acl);
    let (value, reported) = Change::committed("ok", dirty.clone()).into_parts();
    assert_eq!(value, "ok");
    assert_eq!(reported, Some(dirty));
}

#[test]
fn an_empty_dirty_set_survives_as_some() {
    let (_, dirty) = Change::committed((), DirtySet::default()).into_parts();
    assert_eq!(
        dirty,
        Some(DirtySet::default()),
        "a commit with no subscriber-visible scope is still a commit"
    );
}

#[test]
fn mapping_a_change_keeps_its_report() {
    let dirty = DirtySet::catalog(CatalogScope::Projects);
    let (value, reported) = Change::committed(1u8, dirty.clone())
        .map(|n| n + 1)
        .into_parts();
    assert_eq!(value, 2);
    assert_eq!(
        reported,
        Some(dirty),
        "adapting the value is not a re-report"
    );

    let (value, reported) = Change::unchanged(1u8).map(|n| n + 1).into_parts();
    assert_eq!(value, 2);
    assert!(reported.is_none());
}

#[test]
fn into_dirty_yields_the_report_alone() {
    assert!(Change::unchanged(()).into_dirty().is_none());
    assert_eq!(
        Change::committed((), DirtySet::default()).into_dirty(),
        Some(DirtySet::default())
    );
}

#[test]
fn a_successful_read_announces_nothing() {
    let (resp, dirty) = Replica::respond_read(Ok(7), |n| Response::Ok {
        message: Some(n.to_string()),
    });
    assert!(matches!(resp, Response::Ok { message } if message.as_deref() == Some("7")));
    assert!(
        dirty.is_none(),
        "a read has no persistence effect to report"
    );
}

#[test]
fn a_refused_read_renders_its_error_and_announces_nothing() {
    let refusal: ReplicaResult<u8> = Err(ReplicaError::NotFound(NotFound::Project {
        named: "web".into(),
    }));
    let (resp, dirty) = Replica::respond_read(refusal, |_| unreachable!("not the Ok arm"));
    // NotFound is the one family the control plane reports as such: exit 2,
    // so a script can tell "absent" from "refused" without reading prose.
    assert!(matches!(&resp, Response::Error { message, error_kind }
            if message == "no project matches 'web'"
                && *error_kind == crate::control::ErrorKind::NotFound));
    assert!(dirty.is_none());
}

// ---- the read surface's refusals, pinned exactly ----
//
// Stage 2 moved every project read off `Response` and onto typed results, so
// its prose now renders at the dispatch adapter instead of at the detection
// site. These assert the observable half of that move: the exact sentence and
// the exact `ErrorKind`, since scripts branch on the kind (NotFound is exit 2)
// and people read the message. They are the behavioral lock for this stage —
// the golden-strings fixture is provenance, not a gate, and never covered
// these paths.

/// The message and kind of a refusal, or a panic naming what came back instead.
fn refusal(resp: Response) -> (String, crate::control::ErrorKind) {
    match resp {
        Response::Error {
            message,
            error_kind,
        } => (message, error_kind),
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn a_read_that_names_a_missing_project_or_label_is_not_found() {
    let mut n = new_node();
    use crate::control::ErrorKind::NotFound;

    let (msg, kind) = refusal(
        n.replica
            .handle(Request::List {
                project: Some("NOPE".into()),
                filter: Filter::default(),
            })
            .0,
    );
    assert_eq!(msg, "no project matches 'NOPE'");
    assert_eq!(kind, NotFound, "exit 2: absent, not refused");

    let (msg, kind) = refusal(
        n.replica
            .handle(Request::List {
                project: None,
                filter: Filter {
                    label: Some("nope".into()),
                    ..Filter::default()
                },
            })
            .0,
    );
    assert_eq!(msg, "no label matches 'nope'");
    assert_eq!(kind, NotFound);

    let (msg, kind) = refusal(
        n.replica
            .handle(Request::Board {
                project: Some("NOPE".into()),
                project_hint: None,
            })
            .0,
    );
    assert_eq!(msg, "no project matches 'NOPE'");
    assert_eq!(kind, NotFound);
}

#[test]
fn a_read_that_names_a_missing_issue_is_not_found() {
    let mut n = new_node();
    use crate::control::ErrorKind::NotFound;

    // No issues exist, so nothing is near enough to offer as a candidate and
    // the reply is a refusal rather than a picker.
    let (msg, kind) = refusal(
        n.replica
            .handle(Request::IssueView {
                reff: "zz-999".into(),
            })
            .0,
    );
    assert_eq!(msg, "no issue matches 'zz-999'");
    assert_eq!(kind, NotFound);

    let (msg, kind) = refusal(
        n.replica
            .handle(Request::History {
                reff: "zz-999".into(),
            })
            .0,
    );
    assert_eq!(msg, "no issue matches 'zz-999'");
    assert_eq!(kind, NotFound);
}

#[test]
fn a_read_that_cannot_choose_a_project_teaches_the_fix() {
    let mut n = new_node();
    with_project(&mut n.replica); // TEST + ENG → ambiguous
    let (msg, kind) = refusal(
        n.replica
            .handle(Request::Board {
                project: None,
                project_hint: None,
            })
            .0,
    );
    // Ambiguity is a configuration gap, not an absence: exit 1, and the
    // message carries the way out.
    assert_eq!(
        msg,
        "more than one project (ENG, TEST) — pass -p <KEY> or set a default: `lait config set project.default <KEY>`"
    );
    assert_eq!(kind, crate::control::ErrorKind::Error);
}

#[test]
fn the_infallible_reads_answer_without_a_doorbell() {
    let mut n = new_node();
    let (resp, dirty) = n.replica.handle(Request::ProjectList);
    assert!(matches!(resp, Response::Projects { projects } if !projects.is_empty()));
    assert!(dirty.is_none(), "a read commits nothing");

    let (resp, dirty) = n.replica.handle(Request::LabelList);
    assert!(matches!(resp, Response::Labels { .. }));
    assert!(dirty.is_none());

    let (resp, dirty) = n.replica.handle(Request::Activity { since: 0 });
    assert!(matches!(resp, Response::Activity { .. }));
    assert!(dirty.is_none());
}

// ---- the mutation taxonomy renders the sentences it replaces ----
//
// These variants exist to carry the data a refusal interpolates, so the prose
// can live at the adapter instead of at the detection site. The strings below
// are the ones `mutate.rs` produced before the conversion; asserting them here,
// before any call site uses a variant, is what makes the conversion provably
// text-neutral rather than merely intended to be.

#[test]
fn the_mutation_refusals_read_exactly_as_before() {
    let cases: Vec<(ReplicaError, &str)> = vec![
        (
            ReplicaError::Invalid(Invalid::Priority { value: "urgent".into() }),
            "bad priority 'urgent'",
        ),
        (
            ReplicaError::Invalid(Invalid::Status { value: "wip".into() }),
            "no such status 'wip'",
        ),
        (
            ReplicaError::Invalid(Invalid::LinkKind { value: "causes".into() }),
            "unknown link kind 'causes' — one of: blocks, relates, duplicates",
        ),
        (
            ReplicaError::Invalid(Invalid::ProjectKey { value: "toolongkey".into() }),
            "bad project key 'toolongkey' — use 1-8 ASCII letters (it becomes the KEY in KEY-1 refs)",
        ),
        (
            ReplicaError::Invalid(Invalid::Empty(EmptyField::Title)),
            "title must not be empty",
        ),
        (
            ReplicaError::Invalid(Invalid::Empty(EmptyField::Comment)),
            "comment body must not be empty",
        ),
        (
            ReplicaError::Invalid(Invalid::Empty(EmptyField::LabelName)),
            "label name is required",
        ),
        (
            ReplicaError::Invalid(Invalid::Empty(EmptyField::ProjectNameKey)),
            "project name and key are required",
        ),
        (
            ReplicaError::Conflict(Conflict::NoStatusInCategory {
                category: StatusCategory::Active,
            }),
            "this space's workflow has no active-category status",
        ),
        (
            ReplicaError::Conflict(Conflict::ProjectKeyExists { key: "ENG".into() }),
            "project key 'ENG' already exists",
        ),
        (
            ReplicaError::Conflict(Conflict::LabelExists { name: "bug".into() }),
            "label 'bug' already exists",
        ),
        (
            ReplicaError::NotFound(NotFound::Member { named: "ab".into() }),
            "no known member matches 'ab'",
        ),
        (
            ReplicaError::NotFound(NotFound::Link(Box::new(LinkRef {
                reff: "ENG-1".into(),
                kind: "blocks".into(),
                target: "ENG-2".into(),
            }))),
            "no such link: ENG-1 blocks ENG-2",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn the_two_not_found_families_score_exit_two() {
    // NotFound is the one family the control plane reports as absent rather
    // than refused, and scripts branch on that.
    for error in [
        ReplicaError::NotFound(NotFound::Member { named: "ab".into() }),
        ReplicaError::NotFound(NotFound::Link(Box::new(LinkRef {
            reff: "ENG-1".into(),
            kind: "blocks".into(),
            target: "ENG-2".into(),
        }))),
    ] {
        let (_, kind) = refusal(Replica::error_response(error));
        assert_eq!(kind, crate::control::ErrorKind::NotFound);
    }
    // The link *kind* being unknown is a bad argument, not an absence.
    let (_, kind) = refusal(Replica::error_response(ReplicaError::Invalid(
        Invalid::LinkKind {
            value: "causes".into(),
        },
    )));
    assert_eq!(kind, crate::control::ErrorKind::Error);
}

#[test]
fn a_replica_error_stays_small_enough_to_return_by_value() {
    // Ceremony is boxed precisely so every Result in the replica does not pay
    // for the widest variant; this is what keeps clippy::result_large_err quiet
    // across ~50 signatures.
    assert!(
        std::mem::size_of::<ReplicaError>() <= 64,
        "ReplicaError grew to {} bytes — box the variant that did it",
        std::mem::size_of::<ReplicaError>()
    );
}

// ---- the mutation surface, after decoupling ----

#[test]
fn work_state_snapshot_matches_a_fresh_read() {
    // `work_state` renders its snapshot *before* persisting, so that nothing
    // fallible follows the commit and the doorbell can never be lost. That is
    // only sound while the view does not depend on what persisting changes —
    // the catalog row's project and the alias table. This is that guarantee:
    // if a future edit makes the verb move projects, the hoisted view goes
    // stale and this fails rather than silently returning the wrong snapshot.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "hoist me");

    let (started, dirty) = n.replica.handle(Request::IssueStart { reff: reff.clone() });
    assert!(dirty.is_some(), "a real transition rings the doorbell");
    let hoisted = match started {
        Response::Issue(view) => *view,
        other => panic!("expected the issue snapshot, got {other:?}"),
    };

    let (read_back, dirty) = n.replica.handle(Request::IssueView { reff });
    assert!(dirty.is_none());
    let fresh = match read_back {
        Response::Issue(view) => *view,
        other => panic!("expected the issue snapshot, got {other:?}"),
    };

    assert_eq!(hoisted.reff, fresh.reff);
    assert_eq!(hoisted.key_alias, fresh.key_alias);
    assert_eq!(hoisted.project_id, fresh.project_id);
    assert_eq!(hoisted.project_key, fresh.project_key);
    assert_eq!(hoisted.status, fresh.status);
    assert_eq!(hoisted.assignees, fresh.assignees);
    assert_eq!(hoisted.title, fresh.title);
}

#[test]
fn an_idempotent_work_state_commits_nothing() {
    // The canonical Change::unchanged case: `start` twice. The second call must
    // report no persistence effect at all, not an empty one — `ring_doorbell`
    // does not check emptiness, so Some(empty) would wake every subscriber.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "already started");

    let (_, dirty) = n.replica.handle(Request::IssueStart { reff: reff.clone() });
    assert!(dirty.is_some(), "the first transition commits");
    let (resp, dirty) = n.replica.handle(Request::IssueStart { reff });
    assert!(
        matches!(resp, Response::Issue(_)),
        "a no-op still answers with the snapshot: {resp:?}"
    );
    assert!(dirty.is_none(), "a no-op rings nothing");
}

#[test]
fn a_refused_mutation_commits_nothing_and_reads_as_before() {
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "subject");

    // One case per family the conversion introduced, asserting both the exact
    // sentence and that no doorbell rang.
    let cases: Vec<(Request, &str, crate::control::ErrorKind)> = vec![
        (
            Request::IssueNew {
                title: "   ".into(),
                project: Some("ENG".into()),
                project_hint: None,
                assignees: vec![],
                priority: None,
                labels: vec![],
                body: None,
            },
            "title must not be empty",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::IssueEdit {
                reff: reff.clone(),
                title: None,
                status: None,
                priority: Some("blazing".into()),
                description: None,
            },
            "bad priority 'blazing'",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::IssueEdit {
                reff: reff.clone(),
                title: None,
                status: Some("nowhere".into()),
                priority: None,
                description: None,
            },
            "no such status 'nowhere'",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::IssueEdit {
                reff: reff.clone(),
                title: None,
                status: None,
                priority: None,
                description: None,
            },
            "nothing to edit",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::IssueLink {
                reff: reff.clone(),
                kind: "causes".into(),
                target: reff.clone(),
            },
            "unknown link kind 'causes' — one of: blocks, relates, duplicates",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::IssueParent {
                reff: reff.clone(),
                parent: Some(reff.clone()),
            },
            "an issue cannot be its own parent",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::Assign {
                reff: reff.clone(),
                who: vec!["nobody".into()],
                add: true,
            },
            "no known member matches 'nobody'",
            crate::control::ErrorKind::NotFound,
        ),
        (
            Request::ProjectNew {
                name: "Engineering".into(),
                key: "ENG".into(),
            },
            "project key 'ENG' already exists",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::ProjectNew {
                name: "Too Long".into(),
                key: "TOOLONGKEY".into(),
            },
            "bad project key 'TOOLONGKEY' — use 1-8 ASCII letters (it becomes the KEY in KEY-1 refs)",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::LabelNew {
                name: "  ".into(),
                color: None,
            },
            "label name is required",
            crate::control::ErrorKind::Error,
        ),
        (
            Request::Comment {
                reff: reff.clone(),
                body: "\n".into(),
            },
            "comment body must not be empty",
            crate::control::ErrorKind::Error,
        ),
    ];
    for (req, expected, expected_kind) in cases {
        let (resp, dirty) = n.replica.handle(req);
        let (msg, kind) = refusal(resp);
        assert_eq!(msg, expected);
        assert_eq!(kind, expected_kind, "{expected}");
        assert!(dirty.is_none(), "a refused write rings nothing: {expected}");
    }
}

#[test]
fn deleting_and_restoring_pick_their_own_verb() {
    // The domain reports the direction; the sentence is the adapter's.
    let mut n = new_node();
    with_project(&mut n.replica);
    let reff = new_issue(&mut n.replica, "doomed");

    let (resp, dirty) = n
        .replica
        .handle(Request::IssueDelete { reff: reff.clone() });
    assert!(dirty.is_some());
    assert!(
        matches!(&resp, Response::Ok { message } if message.as_deref() == Some(&*format!("deleted {reff}"))),
        "{resp:?}"
    );

    let (resp, dirty) = n
        .replica
        .handle(Request::IssueRestore { reff: reff.clone() });
    assert!(dirty.is_some());
    assert!(
        matches!(&resp, Response::Ok { message } if message.as_deref() == Some(&*format!("restored {reff}"))),
        "{resp:?}"
    );
}

// ---- the membership sentences, pinned at the adapter ----
//
// The direct tests above now assert typed outcomes, which is the point — but it
// means nothing above would notice if a membership message changed wording on
// its way out. These drive `handle` and pin the observable text and kind.

#[test]
fn membership_refusals_read_exactly_as_before() {
    let mut n = new_node();
    let cases: Vec<(Request, &str, crate::control::ErrorKind)> = vec![
        (
            Request::MemberAdd {
                who: "nobody".into(),
                admin: false,
                as_name: None,
            },
            "no known actor matches 'nobody' — invite them first so their identity arrives",
            crate::control::ErrorKind::NotFound,
        ),
        (
            // The remove path drops the invitation hint: you do not invite
            // someone in order to remove them.
            Request::MemberRemove {
                who: "nobody".into(),
            },
            "no known actor matches 'nobody'",
            crate::control::ErrorKind::NotFound,
        ),
        (
            Request::InviteRevoke {
                invite: "not-a-ticket".into(),
            },
            "not a valid invite — pass the ticket or its 32-hex nonce",
            crate::control::ErrorKind::Error,
        ),
    ];
    for (req, expected, expected_kind) in cases {
        let (resp, dirty) = n.replica.handle(req);
        let (msg, kind) = refusal(resp);
        assert_eq!(msg, expected);
        assert_eq!(kind, expected_kind, "{expected}");
        assert!(dirty.is_none(), "a refused membership op rings nothing");
    }
}

#[test]
fn membership_acknowledgements_read_exactly_as_before() {
    let mut a = new_node();

    let (resp, dirty) = a.replica.handle(Request::KeyRotate);
    let gen = a.replica.active_epoch().unwrap().gen;
    assert!(
        matches!(&resp, Response::Ok { message }
            if message.as_deref() == Some(&*format!("rotated the space key (generation {gen})"))),
        "{resp:?}"
    );
    assert!(dirty.is_some());

    // A fresh revoke promises only what it can keep: the invite admits no one
    // from here on. It never claims to undo an admission.
    let nonce = [9u8; 16];
    let (resp, dirty) = a.replica.handle(Request::InviteRevoke {
        invite: data_encoding::HEXLOWER.encode(&nonce),
    });
    let message = match resp {
        Response::Ok { message } => message.unwrap_or_default(),
        other => panic!("expected an acknowledgement, got {other:?}"),
    };
    assert!(
        message.starts_with("revoked the invite — it admits no one from here on."),
        "{message}"
    );
    assert!(
        message.contains("content shared before then stays readable by them"),
        "the honest caveat survives: {message}"
    );
    assert!(dirty.is_some());
}

#[test]
fn admitting_someone_already_seated_says_so_and_commits_nothing() {
    let mut a = new_node();
    let b_seed = [8u8; 32];
    let mut b = new_joiner_node_as(
        device_from_seed(b_seed),
        b_seed,
        &a.replica.space_str(),
        &a.replica.founding_proof().unwrap(),
    );
    let b_incept = b.replica.self_inception().unwrap();

    let (admitted, dirty) = ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));
    assert!(matches!(admitted, Admission::Added(_)), "{admitted:?}");
    assert!(dirty.is_some(), "the first admission commits");

    let (again, dirty) = ok(a.replica.admit_member(&b_incept, vec![Grant::Write]));
    assert!(
        matches!(again, Admission::AlreadyMember(_)),
        "the second is a no-op: {again:?}"
    );
    assert!(dirty.is_none(), "re-admitting rings nothing");
}
