//! The workspace registry (see `docs/GUIDED-JOIN.md` §B).
//!
//! A small global index, `workspaces.json` under [`crate::config::config_root`],
//! mapping each **store path** to the workspace it holds. Written at every
//! chokepoint a workspace becomes bound to a path — `lait init` (founding),
//! `lait join` (bootstrapping), and every successful daemon open — so founders
//! and joiners alike are observable via `lait workspaces` and addressable via
//! `-w`. It carries **no secrets and no trust** (the signed ACL still gates
//! every op); it is pure navigation state: the `name` and `projects` fields are
//! advisory snapshots refreshed on open, a corrupt/absent file degrades to "no
//! known workspaces", and nothing here is ever a source of truth.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::config_root;

/// Where a store's workspace came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Founded here via `lait init` (this node minted the genesis).
    Founded,
    /// Bootstrapped from someone else's invite via `lait join`.
    #[default]
    Joined,
}

impl std::fmt::Display for Origin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Origin::Founded => "founded",
            Origin::Joined => "joined",
        })
    }
}

/// Advisory snapshot of one project, for cross-workspace listings. Display
/// only — the authoritative list is the workspace's own catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectBrief {
    pub key: String,
    pub name: String,
}

/// One registered store: a path on this machine and the workspace it holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceEntry {
    /// The workspace id (`ws_…`) bound in this store.
    pub workspace: String,
    /// The workspace display name at last open (advisory; may lag a rename).
    #[serde(default)]
    pub name: String,
    /// The absolute store path (the `.lait/` dir, or a `$LAIT_HOME`).
    pub path: String,
    /// Founded here vs joined from an invite.
    #[serde(default)]
    pub origin: Origin,
    /// The inviter's nick from the ticket (joined only). May be empty.
    #[serde(default)]
    pub host_nick: String,
    /// Unix seconds of the last init/join/daemon-open — newest-first ordering.
    #[serde(default)]
    pub last_opened: u64,
    /// Advisory project snapshot (key + name), refreshed on open and on
    /// project-config changes. Display only.
    #[serde(default)]
    pub projects: Vec<ProjectBrief>,
}

/// Filesystem-level status of a registered entry. Whether a daemon is *up* is
/// a live control-channel probe, done by the CLI layer (it needs async).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorePresence {
    /// The path holds an initialized store (genesis + catalog on disk).
    Present,
    /// The path is gone or no longer holds an initialized store.
    Missing,
}

/// Check whether an entry's path still holds an initialized store. Mirrors
/// `Store::is_initialized` without opening (or creating) anything.
pub fn presence(entry: &WorkspaceEntry) -> StorePresence {
    if crate::store::initialized_at(Path::new(&entry.path)) {
        StorePresence::Present
    } else {
        StorePresence::Missing
    }
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
    entries.sort_by_key(|e| std::cmp::Reverse(e.last_opened));
    entries
}

fn save(entries: &[WorkspaceEntry]) -> Result<()> {
    let path = registry_file()?;
    let json = serde_json::to_string_pretty(entries).context("encode workspace registry")?;
    // Write atomically (temp file + rename) so a concurrent reader never
    // observes a half-written, unparseable file and wrongly concludes "no known
    // workspaces". `rename` replaces the destination atomically on both unix
    // and Windows (std uses MOVEFILE_REPLACE_EXISTING).
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    std::fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, &path).with_context(|| format!("commit {}", path.display()))?;
    Ok(())
}

/// Insert or refresh an entry, keyed by **store path** (one store holds exactly
/// one workspace). A refresh preserves fields the caller didn't recompute: an
/// empty `name`/`projects`/`host_nick` on the new entry keeps the old value, and
/// `origin` sticks once founded (a daemon-open upsert must not relabel a founder
/// as joined). Best-effort persistence; callers treat failure as non-fatal (the
/// registry is a convenience, not a source of truth).
pub fn upsert(mut entry: WorkspaceEntry) -> Result<()> {
    let mut entries = list();
    if let Some(old) = entries.iter().find(|e| e.path == entry.path) {
        // Same store re-registered: merge, don't blank.
        if old.workspace == entry.workspace {
            if entry.name.is_empty() {
                entry.name = old.name.clone();
            }
            if entry.projects.is_empty() {
                entry.projects = old.projects.clone();
            }
            if entry.host_nick.is_empty() {
                entry.host_nick = old.host_nick.clone();
            }
            if old.origin == Origin::Founded {
                entry.origin = Origin::Founded;
            }
        }
        // A different workspace at the same path (re-init after rm) replaces
        // the row wholesale.
    }
    entries.retain(|e| e.path != entry.path);
    entries.push(entry);
    save(&entries)
}

/// Deregister entries matching `sel` (exact path, exact workspace id, or a
/// **unique** workspace-id prefix — an ambiguous prefix removes nothing, so a
/// stray `forget ws_` can never wipe the registry). Never touches the store on
/// disk. Returns the removed entries.
pub fn forget(sel: &str) -> Result<Vec<WorkspaceEntry>> {
    let entries = list();
    let exact = |e: &WorkspaceEntry| e.path == sel || e.workspace == sel;
    let matches_exact = entries.iter().filter(|e| exact(e)).count();
    let prefix_hits = entries
        .iter()
        .filter(|e| sel.starts_with("ws_") && e.workspace.starts_with(sel))
        .count();
    let (removed, kept): (Vec<_>, Vec<_>) = entries.into_iter().partition(|e| {
        exact(e) || (matches_exact == 0 && prefix_hits == 1 && e.workspace.starts_with(sel))
    });
    if !removed.is_empty() {
        save(&kept)?;
    }
    Ok(removed)
}

/// Drop every entry whose path no longer holds an initialized store. Returns
/// the removed entries.
pub fn prune() -> Result<Vec<WorkspaceEntry>> {
    let entries = list();
    let (removed, kept): (Vec<_>, Vec<_>) = entries
        .into_iter()
        .partition(|e| presence(e) == StorePresence::Missing);
    if !removed.is_empty() {
        save(&kept)?;
    }
    Ok(removed)
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

    fn entry(workspace: &str, path: &str, last_opened: u64) -> WorkspaceEntry {
        WorkspaceEntry {
            workspace: workspace.into(),
            name: "demo".into(),
            path: path.into(),
            origin: Origin::Joined,
            host_nick: "host".into(),
            last_opened,
            projects: vec![],
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
        // Same path, different workspace (re-init after rm) → replace, not duplicate.
        upsert(entry("ws_B", "/tmp/a", 20)).unwrap();
        let got = list();
        assert_eq!(got.len(), 1, "same path must not create a second row");
        assert_eq!(got[0].workspace, "ws_B", "re-register replaces the row");
    }

    #[test]
    fn refresh_merges_instead_of_blanking() {
        let _root = ScopedRoot::new("merge");
        let mut founded = entry("ws_A", "/tmp/a", 10);
        founded.origin = Origin::Founded;
        founded.projects = vec![ProjectBrief {
            key: "ENG".into(),
            name: "Engineering".into(),
        }];
        upsert(founded).unwrap();
        // A later daemon-open upsert that didn't recompute name/projects and
        // defaulted origin must keep the founded origin and the old snapshots.
        upsert(WorkspaceEntry {
            workspace: "ws_A".into(),
            name: String::new(),
            path: "/tmp/a".into(),
            origin: Origin::Joined,
            host_nick: String::new(),
            last_opened: 20,
            projects: vec![],
        })
        .unwrap();
        let got = list();
        assert_eq!(got[0].origin, Origin::Founded, "founded origin sticks");
        assert_eq!(got[0].name, "demo", "empty name keeps the old value");
        assert_eq!(
            got[0].projects.len(),
            1,
            "empty projects keeps the old value"
        );
        assert_eq!(got[0].last_opened, 20, "freshness does update");
    }

    #[test]
    fn list_is_newest_first() {
        let _root = ScopedRoot::new("order");
        upsert(entry("ws_old", "/tmp/old", 5)).unwrap();
        upsert(entry("ws_new", "/tmp/new", 50)).unwrap();
        let got = list();
        assert_eq!(got[0].workspace, "ws_new", "newest last_opened sorts first");
    }

    #[test]
    fn missing_registry_is_empty_not_an_error() {
        let _root = ScopedRoot::new("empty");
        assert!(list().is_empty());
    }

    #[test]
    fn forget_removes_by_path_or_id_prefix() {
        let _root = ScopedRoot::new("forget");
        upsert(entry("ws_AAAA", "/tmp/a", 10)).unwrap();
        upsert(entry("ws_BBBB", "/tmp/b", 20)).unwrap();
        // An ambiguous prefix removes NOTHING (a stray `forget ws_` must never
        // wipe the registry).
        assert!(forget("ws_").unwrap().is_empty());
        assert_eq!(list().len(), 2);
        assert_eq!(forget("/tmp/a").unwrap().len(), 1);
        assert_eq!(list().len(), 1);
        assert_eq!(
            forget("ws_BB").unwrap().len(),
            1,
            "unique id prefix matches"
        );
        assert!(list().is_empty());
    }

    #[test]
    fn prune_drops_only_missing_stores() {
        let _root = ScopedRoot::new("prune");
        // A real initialized store on disk…
        let live = std::env::temp_dir().join(format!("lait-wsreg-live-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&live);
        std::fs::create_dir_all(live.join("repo")).unwrap();
        std::fs::write(live.join("repo").join("genesis.json"), "{}").unwrap();
        std::fs::write(live.join("repo").join("catalog.loro"), "x").unwrap();
        upsert(entry("ws_LIVE", live.to_str().unwrap(), 10)).unwrap();
        // …and a registered path that holds nothing.
        upsert(entry("ws_GONE", "/tmp/definitely-gone-xyz", 20)).unwrap();
        let removed = prune().unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].workspace, "ws_GONE");
        let kept = list();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].workspace, "ws_LIVE");
        let _ = std::fs::remove_dir_all(&live);
    }
}
