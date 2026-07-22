//! C0.3 / G3 — real OS process death at journal boundaries.
//!
//! The fault-injection matrix (`journal_faults.rs`) models a crash as an error
//! return; this suite kills an actual child process (`std::process::abort`)
//! mid-commit at representative boundaries and then reopens the store in the
//! parent, asserting recovery lands on exactly one complete state: the old one
//! before the manifest rename, the new one after. Fault closures alone do not
//! prove OS/process crash behavior — this does.
//!
//! Mechanics: the parent re-executes this same test binary, selecting the
//! `crash_child` "test" with `--exact` and pointing it at a store directory
//! and crash point via environment variables. Without those variables the
//! child entry is a no-op (so an ordinary test run passes it trivially).

use std::path::PathBuf;
use std::process::Command;

use journal::JournaledStore;

const ENV_DIR: &str = "LAIT_JOURNAL_CRASH_DIR";
const ENV_POINT: &str = "LAIT_JOURNAL_CRASH_POINT";

fn temp_root(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("lait-journal-child-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The child entry: only acts when the crash environment is present. It opens
/// the store, arms a real `abort()` at the named point, and attempts the
/// "new" commit — dying mid-protocol exactly where a power loss would.
#[test]
fn crash_child() {
    let (Ok(dir), Ok(point)) = (std::env::var(ENV_DIR), std::env::var(ENV_POINT)) else {
        return; // ordinary test run: nothing to do
    };
    let mut store = JournaledStore::open(dir)
        .unwrap()
        .with_fault_injector(Box::new(move |name| {
            if name == point {
                std::process::abort();
            }
            false
        }));
    let _ = store.commit(&[b"new-object".to_vec()], &[], b"new-meta".to_vec());
    // Post-authoritative points may let commit() return; exit cleanly then —
    // the parent classifies by on-disk state, not exit code.
    std::process::exit(0);
}

/// Representative boundaries: before material lands, at object renames, at the
/// authoritative manifest switch, and in post-authoritative cleanup.
const POINTS: [&str; 4] = [
    "objects",
    "rename-objects",
    "manifest-rename",
    "journal-committed",
];

#[test]
fn a_killed_process_recovers_to_exactly_one_complete_state() {
    for &point in POINTS.iter() {
        let dir = temp_root(point);
        // Seed the OLD committed state.
        let old_seq = {
            let mut store = JournaledStore::open(&dir).unwrap();
            store
                .commit(&[b"old-object".to_vec()], &[], b"old-meta".to_vec())
                .unwrap()
        };

        // Kill a real child mid-commit at the boundary.
        let exe = std::env::current_exe().unwrap();
        let status = Command::new(&exe)
            .args(["--exact", "crash_child", "--test-threads=1", "--nocapture"])
            .env(ENV_DIR, &dir)
            .env(ENV_POINT, point)
            .status()
            .unwrap();
        assert!(
            !status.success() || point == "journal-committed",
            "{point}: pre-authoritative aborts must kill the child"
        );

        // Reopen: recovery must expose the complete old or the complete new
        // state — and after the manifest rename, only the new one.
        let store = JournaledStore::open(&dir).unwrap();
        let manifest = store.manifest().expect("a manifest survives").clone();
        for obj in &manifest.objects {
            store
                .read_object(obj)
                .expect("every object named by the exposed manifest is intact");
        }
        match point {
            // Before the manifest rename the old state is authoritative.
            "objects" | "rename-objects" | "manifest-rename" => {
                assert_eq!(manifest.meta, b"old-meta", "{point}: old state exposed");
                assert_eq!(manifest.sequence, old_seq);
            }
            // After the rename the commit IS committed; only cleanup was lost.
            "journal-committed" => {
                assert_eq!(manifest.meta, b"new-meta", "{point}: new state exposed");
                assert!(manifest.sequence > old_seq);
            }
            _ => unreachable!(),
        }

        // The next commit proceeds with a strictly-forward sequence.
        let mut store = store;
        let next = store
            .commit(&[b"after".to_vec()], &[], b"after-meta".to_vec())
            .unwrap();
        assert!(next > manifest.sequence, "sequences never reuse");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[test]
fn many_consecutive_commits_stay_monotone_and_complete() {
    // C0.3: two-and-many consecutive commits on every supported platform (this
    // test runs wherever CI runs it — Windows, Linux, macOS).
    let dir = temp_root("many");
    let mut store = JournaledStore::open(&dir).unwrap();
    let mut last = 0;
    for i in 0..25u32 {
        let seq = store
            .commit(
                &[format!("object-{i}").into_bytes()],
                &[],
                format!("meta-{i}").into_bytes(),
            )
            .unwrap();
        assert!(seq > last, "strictly forward");
        last = seq;
    }
    // A cold reopen exposes the final complete state.
    drop(store);
    let store = JournaledStore::open(&dir).unwrap();
    let manifest = store.manifest().unwrap();
    assert_eq!(manifest.meta, b"meta-24");
    for obj in &manifest.objects {
        store.read_object(obj).unwrap();
    }
    let _ = std::fs::remove_dir_all(&dir);
}
