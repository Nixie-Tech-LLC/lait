//! The joined-workspace registry (see `docs/GUIDED-JOIN.md` §B).
//!
//! A small global index, `workspaces.json` under [`crate::config::config_root`],
//! mapping each **store path** to the workspace it holds. The daemon upserts an
//! entry on a successful `Join`; the CLI reads it to answer "which directory
//! holds the workspace you joined?" — the breadcrumb that defuses the directory
//! trap (a joiner running commands from the wrong folder). It carries **no
//! secrets and no trust** (the signed ACL still gates every op); it is pure
//! navigation state, and a corrupt/absent file degrades to "no known
//! workspaces", never an error.

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::config_root;

/// One registered store: a path on this machine and the workspace it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    /// The workspace id (`ws_…`) bound in this store.
    pub workspace: String,
    /// The gossip room / topic (the folder name by default).
    pub room: String,
    /// The absolute store path (the `.lait/` dir, or a `$LAIT_HOME`).
    pub path: String,
    /// The inviter's nick from the ticket, for a friendlier listing. May be empty.
    #[serde(default)]
    pub host_nick: String,
    /// Unix seconds of the last join/refresh — newest-first ordering for lists.
    #[serde(default)]
    pub last_seen: u64,
}

/// Path to the registry file (`config_root/workspaces.json`).
pub fn registry_file() -> Result<PathBuf> {
    Ok(config_root()?.join("workspaces.json"))
}

/// Read the registry, newest-first. Best-effort: a missing or corrupt file
/// yields an empty list rather than an error (navigation state, never a gate).
pub fn list() -> Vec<WorkspaceEntry> {
    let Ok(path) = registry_file() else {
        return Vec::new();
    };
    let mut entries: Vec<WorkspaceEntry> = std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    entries.sort_by_key(|e| std::cmp::Reverse(e.last_seen));
    entries
}

/// Insert or refresh an entry, keyed by **store path** (one store holds exactly
/// one workspace, so a re-join at the same path replaces the row). Best-effort
/// persistence; a write failure is returned so the caller can log it, but callers
/// treat it as non-fatal (the registry is a convenience, not a source of truth).
pub fn upsert(entry: WorkspaceEntry) -> Result<()> {
    let path = registry_file()?;
    let mut entries = list();
    entries.retain(|e| e.path != entry.path);
    entries.push(entry);
    let json = serde_json::to_string_pretty(&entries).context("encode workspace registry")?;
    // Write atomically (temp file + rename) so a concurrent reader — notably the
    // CLI directory-trap guard, whose whole job is to see this registry — never
    // observes a half-written, unparseable file and wrongly concludes "no joined
    // workspaces". `rename` replaces the destination atomically on both unix and
    // Windows (std uses MOVEFILE_REPLACE_EXISTING).
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("commit {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // `LAIT_CONFIG_ROOT` is process-global, so these tests can't run concurrently:
    // one setting the env would clobber another mid-flight. Serialize them behind a
    // lock (held for the whole test) rather than hoping the scheduler cooperates.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Point `config_root` at a fresh scratch dir for the duration of a test, while
    /// holding the env lock so no other test observes our `LAIT_CONFIG_ROOT`.
    struct ScopedRoot {
        dir: PathBuf,
        _guard: MutexGuard<'static, ()>,
    }
    impl ScopedRoot {
        fn new(tag: &str) -> Self {
            let guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let dir =
                std::env::temp_dir().join(format!("lait-wsreg-{}-{}", tag, std::process::id(),));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            std::env::set_var("LAIT_CONFIG_ROOT", &dir);
            ScopedRoot { dir, _guard: guard }
        }
    }
    impl Drop for ScopedRoot {
        fn drop(&mut self) {
            std::env::remove_var("LAIT_CONFIG_ROOT");
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn entry(workspace: &str, path: &str, last_seen: u64) -> WorkspaceEntry {
        WorkspaceEntry {
            workspace: workspace.into(),
            room: "lait".into(),
            path: path.into(),
            host_nick: "host".into(),
            last_seen,
        }
    }

    #[test]
    fn upsert_then_list_returns_the_entry() {
        let _root = ScopedRoot::new("basic");
        upsert(entry("ws_A", "/tmp/a", 10)).unwrap();
        let got = list();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].workspace, "ws_A");
    }

    #[test]
    fn upsert_is_keyed_by_path_not_duplicated() {
        let _root = ScopedRoot::new("dedup");
        upsert(entry("ws_A", "/tmp/a", 10)).unwrap();
        // Same path, newer join to a different workspace → replace, not duplicate.
        upsert(entry("ws_B", "/tmp/a", 20)).unwrap();
        let got = list();
        assert_eq!(got.len(), 1, "same path must not create a second row");
        assert_eq!(got[0].workspace, "ws_B", "re-join replaces the row");
    }

    #[test]
    fn list_is_newest_first() {
        let _root = ScopedRoot::new("order");
        upsert(entry("ws_old", "/tmp/old", 5)).unwrap();
        upsert(entry("ws_new", "/tmp/new", 50)).unwrap();
        let got = list();
        assert_eq!(got[0].workspace, "ws_new", "newest last_seen sorts first");
    }

    #[test]
    fn missing_registry_is_empty_not_an_error() {
        let _root = ScopedRoot::new("empty");
        assert!(list().is_empty());
    }
}
