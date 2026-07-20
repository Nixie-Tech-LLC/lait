//! Git-backed local durability and inspection. Each node owns one repository;
//! Git never transports state between nodes. The durable layout is:
//!
//! ```text
//! <home>/repo/
//!   genesis.json        // spaceId + founding admin keys (public only)
//!   catalog.loro        // export(Snapshot) of the Catalog doc
//!   membership.loro     // signed authority inputs and sealed envelopes
//!   docs/<DocId>.loro   // per-issue snapshot, lazily loaded
//!   peer_id              // stable Loro peer id for this store
//! ```
//!
//! The repository contains public genesis material, Loro snapshots, signed
//! events, and sealed envelopes. Device private keys, actor recovery material,
//! custody plaintext, configuration, and navigation state live outside it.
//! Git is used via the `git` CLI as a best-effort
//! durability/inspectability layer: the store is correct on the filesystem alone
//! and never requires Git at runtime. Snapshots are currently written whole per
//! save; incremental `export(updates)` is a deferred optimization.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::{anyhow, Context, Result};

use crate::catalog::CatalogDoc;
use crate::genesis::Genesis;
use crate::ids::DocId;
use crate::issue::IssueDoc;

/// Whether `home` holds an initialized store — a pure probe (no dirs created,
/// unlike `Store::open`), for the registry and the CLI pre-flight checks.
pub fn initialized_at(home: &Path) -> bool {
    let repo = home.join("repo");
    repo.join("genesis.json").exists() && repo.join("catalog.loro").exists()
}

/// The git-backed store rooted at `<home>/repo`.
pub struct Store {
    repo: PathBuf,
    git: bool,
    /// Durable-store mutations recorded since the last git commit. The git
    /// snapshot is **deferred** off the mutation hot path (see [`Store::commit`]
    /// vs [`Store::mark_dirty`]/[`Store::checkpoint`]): a `git add -A` is a
    /// subprocess whose cost grows with the tree, so committing per edit is a
    /// per-keystroke tax at thousands of docs. Durability does **not** depend on
    /// it — every `.loro` write is fsync'd in [`write_atomic`] — so coalescing
    /// commits only coarsens git history, never risks data.
    pending: AtomicU64,
    /// The store's **stable peer id** (`docs/DATA-CONTRACT.md`): minted randomly
    /// once per store and persisted beside the docs, so a daemon restart reuses
    /// it (no version-vector growth per session) while a re-created store mints
    /// a fresh one (reusing a peer id over an empty store and then importing
    /// the old ops silently drops them — verified against Loro). Copying
    /// a store directory to a second live node stays forbidden, as it already
    /// was for the identity key.
    peer_id: u64,
}

impl Store {
    /// Open (creating if needed) the store under a home directory. Initializes a
    /// git repo when a `git` binary is available; otherwise degrades to a plain
    /// directory (still durable, still correct).
    pub fn open(home: &Path) -> Result<Self> {
        let repo = home.join("repo");
        fs::create_dir_all(repo.join("docs"))
            .with_context(|| format!("create store {}", repo.display()))?;
        let git = git_available();
        if git && !repo.join(".git").exists() {
            let _ = run_git(&repo, &["init", "--quiet"]);
            // Local identity so commits never fail on an unconfigured CI box.
            let _ = run_git(&repo, &["config", "user.email", "lait@localhost"]);
            let _ = run_git(&repo, &["config", "user.name", "lait"]);
        }
        let peer_id = load_or_mint_peer_id(&repo)?;
        Ok(Self {
            repo,
            git,
            pending: AtomicU64::new(0),
            peer_id,
        })
    }

    /// The stable per-store Loro peer id (see the field docs).
    pub fn peer_id(&self) -> u64 {
        self.peer_id
    }

    pub fn repo_path(&self) -> &Path {
        &self.repo
    }

    fn genesis_path(&self) -> PathBuf {
        self.repo.join("genesis.json")
    }
    fn catalog_path(&self) -> PathBuf {
        self.repo.join("catalog.loro")
    }
    fn issue_path(&self, doc_id: &DocId) -> PathBuf {
        self.repo.join("docs").join(format!("{doc_id}.loro"))
    }

    // ---- genesis ----

    pub fn genesis(&self) -> Result<Option<Genesis>> {
        let p = self.genesis_path();
        if !p.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(&p).context("read genesis.json")?;
        Ok(Some(
            serde_json::from_str(&data).context("parse genesis.json")?,
        ))
    }

    pub fn write_genesis(&self, g: &Genesis) -> Result<()> {
        let data = serde_json::to_string_pretty(g).context("serialize genesis")?;
        write_atomic(&self.genesis_path(), data.as_bytes())?;
        Ok(())
    }

    pub fn is_initialized(&self) -> bool {
        self.genesis_path().exists() && self.catalog_path().exists()
    }

    /// The home directory this store lives in (the `.lait/` dir or `$LAIT_HOME`)
    /// — where the store-layer `config.json` sits, beside `repo/`.
    pub fn home_path(&self) -> &Path {
        self.repo
            .parent()
            .expect("store repo has a parent home dir")
    }

    // ---- catalog ----

    pub fn load_catalog(&self) -> Result<Option<CatalogDoc>> {
        let p = self.catalog_path();
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p).context("read catalog.loro")?;
        let catalog = CatalogDoc::from_snapshot(&bytes, Some(self.peer_id))?;
        // Gate the on-disk schema window before exposing any contents.
        check_schema_version(catalog.schema_version())?;
        Ok(Some(catalog))
    }

    pub fn save_catalog(&self, catalog: &CatalogDoc) -> Result<()> {
        let bytes = catalog.snapshot()?;
        write_atomic(&self.catalog_path(), &bytes)?;
        Ok(())
    }

    // ---- membership (plaintext authority inputs and sealed envelopes) ----

    fn membership_path(&self) -> PathBuf {
        self.repo.join("membership.loro")
    }

    pub fn load_membership(&self) -> Result<Option<crate::membership::MembershipDoc>> {
        let p = self.membership_path();
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p).context("read membership.loro")?;
        Ok(Some(crate::membership::MembershipDoc::from_snapshot(
            &bytes,
            Some(self.peer_id),
        )?))
    }

    pub fn save_membership(&self, m: &crate::membership::MembershipDoc) -> Result<()> {
        let bytes = m.snapshot()?;
        write_atomic(&self.membership_path(), &bytes)?;
        Ok(())
    }

    // ---- issue docs ----

    pub fn issue_doc_ids(&self) -> Vec<DocId> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(self.repo.join("docs")) {
            for e in entries.flatten() {
                if let Some(name) = e.file_name().to_str() {
                    if let Some(stem) = name.strip_suffix(".loro") {
                        if let Some(id) = DocId::parse(stem) {
                            out.push(id);
                        }
                    }
                }
            }
        }
        out.sort();
        out
    }

    pub fn load_issue(&self, doc_id: &DocId) -> Result<Option<IssueDoc>> {
        let p = self.issue_path(doc_id);
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p).context("read issue.loro")?;
        Ok(Some(IssueDoc::from_snapshot(&bytes, Some(self.peer_id))?))
    }

    pub fn save_issue(&self, issue: &IssueDoc) -> Result<()> {
        let doc_id = issue.doc_id().ok_or_else(|| anyhow!("issue has no id"))?;
        let bytes = issue.snapshot()?;
        write_atomic(&self.issue_path(&doc_id), &bytes)?;
        Ok(())
    }

    /// Record that the durable store changed but **defer** the git snapshot to
    /// the next [`checkpoint`](Self::checkpoint). The mutation hot path calls
    /// this instead of [`commit`](Self::commit) so no `git add -A` subprocess
    /// runs per edit. Durability is unaffected — the `.loro` bytes are already
    /// fsync'd by the time this is called.
    pub fn mark_dirty(&self) {
        self.pending.fetch_add(1, Ordering::Relaxed);
    }

    /// Coalesce every mutation marked since the last commit into a **single**
    /// git commit (best-effort, for inspectability/history). A no-op when
    /// nothing is pending or git is unavailable. Returns whether it committed.
    /// The daemon calls this on a slow periodic tick; tests/harness call it
    /// explicitly. Safe at any time — it never touches durability.
    pub fn checkpoint(&self) -> bool {
        let n = self.pending.swap(0, Ordering::Relaxed);
        if n == 0 {
            return false;
        }
        let plural = if n == 1 { "" } else { "s" };
        self.git_commit(&format!("lait: checkpoint ({n} change{plural})"))
    }

    /// Commit immediately under a descriptive `message` — for one-time
    /// structural events (init/adopt/membership), not the per-edit path. Also
    /// flushes any pending mutation batch into this same commit.
    pub fn commit(&self, message: &str) -> bool {
        self.pending.store(0, Ordering::Relaxed);
        self.git_commit(message)
    }

    /// The actual `git add -A && git commit` (best-effort). A no-op returning
    /// `false` when git is unavailable or there is nothing to commit.
    fn git_commit(&self, message: &str) -> bool {
        if !self.git {
            return false;
        }
        if run_git(&self.repo, &["add", "-A"]).is_none() {
            return false;
        }
        run_git(
            &self.repo,
            &[
                "-c",
                "user.email=lait@localhost",
                "-c",
                "user.name=lait",
                "commit",
                "--quiet",
                "-m",
                message,
            ],
        )
        .is_some()
    }
}

/// Write bytes durably: write to a temp file, `fsync` it, then rename over the
/// target and `fsync` the parent directory. Atomicity (via rename) means a crash
/// mid-write never truncates the durable copy; the two `fsync`s add crash *and*
/// power-loss durability — without them the OS may report success while the data
/// (or the rename itself) still sits in the page cache and is lost on power loss
/// (the classic rename-without-fsync hole).
fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    // Write and flush the temp file's *contents* to disk before we rename, so
    // the rename can never publish a file whose bytes aren't durable yet.
    {
        let mut f = fs::File::create(&tmp).with_context(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes)
            .with_context(|| format!("write {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp.display()))?;
    }
    fs::rename(&tmp, path).with_context(|| format!("rename into {}", path.display()))?;
    // Persist the directory entry created by the rename. On unix this is the only
    // way to make the rename itself survive power loss; on Windows a directory
    // handle can't be fsynced this way and MoveFileEx durability is handled by
    // the filesystem, so it's a no-op there.
    fsync_parent_dir(path);
    Ok(())
}

/// Load the store's persisted peer id, minting (and persisting) a random one
/// on first open. See `Store::peer_id` for the design constraints.
fn load_or_mint_peer_id(repo: &Path) -> Result<u64> {
    let p = repo.join("peer_id");
    if let Ok(s) = fs::read_to_string(&p) {
        if let Ok(v) = u64::from_str_radix(s.trim(), 16) {
            return Ok(v);
        }
    }
    let mut buf = [0u8; 8];
    getrandom::fill(&mut buf).expect("getrandom");
    let v = u64::from_le_bytes(buf);
    write_atomic(&p, format!("{v:016x}").as_bytes())?;
    Ok(v)
}

/// Best-effort `fsync` of a path's parent directory so a just-created/renamed
/// entry is durable. Unix only — directory `fsync` has no portable Windows
/// equivalent. Errors are ignored: the data file is already synced, and a failed
/// directory sync is rare and non-fatal to correctness.
#[cfg(unix)]
fn fsync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}
#[cfg(not(unix))]
fn fsync_parent_dir(_path: &Path) {}

fn git_available() -> bool {
    Command::new("git")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Run a git subcommand in the repo. Returns Some(stdout) on success, None on
/// any failure (best-effort — the store is correct without git).
fn run_git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .ok()?;
    if out.status.success() {
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    } else {
        None
    }
}

/// Gate a loaded store's on-disk schema version against the window this build
/// supports (`[dto::MIN_SUPPORTED_SCHEMA, dto::SCHEMA_VERSION]`).
///
/// Both bounds are closed. A **newer** store is refused because an older binary
/// would drop or misread fields it does not know. An **older** store is refused
/// because there is no migration: a v2 store's space id lives under keys a v3
/// reader never consults, so accepting it would open a store that then projects
/// as spaceless. A refusal that names the version is recoverable; a store that
/// opens wrong is not.
///
/// `0` is **not** an old version — it is the absence of the key, which is what a
/// joiner's catalog reads until the founder's ops arrive over sync
/// ([`CatalogDoc::empty`] stamps nothing). Refusing it would make `lait join`
/// impossible. An unstamped store carries no shape to be wrong about; the
/// genesis is the root of truth at that point, and a v0.5.x genesis fails to
/// parse on its own. Pure, so the window policy is unit-testable without
/// touching the filesystem.
fn check_schema_version(found: u32) -> Result<()> {
    let supported = crate::dto::SCHEMA_VERSION;
    let min = crate::dto::MIN_SUPPORTED_SCHEMA;
    if found > supported {
        return Err(anyhow!(
            "this space store was written by a newer lait (schema v{found}); \
             this build supports up to schema v{supported} — upgrade lait to open it"
        ));
    }
    if found != 0 && found < min {
        return Err(anyhow!(
            "this space store was written by lait v0.5.x or earlier (schema v{found}); \
             v0.6 changed the on-disk shape and does not migrate — re-found it with \
             `lait init`, or re-join from a fresh invite"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::{Priority, MIN_SUPPORTED_SCHEMA, SCHEMA_VERSION};
    use crate::ids::SpaceId;

    #[test]
    fn schema_gate_accepts_supported_and_refuses_outside_the_window() {
        // The window is closed at both ends: a newer store and a retired older
        // one are both refused, so a v0.5.x store cannot open and mis-project.
        assert!(check_schema_version(SCHEMA_VERSION).is_ok());
        assert!(check_schema_version(MIN_SUPPORTED_SCHEMA - 1).is_err());
        // `0` is the key's absence, not a version: a joiner's catalog reads it
        // until the founder's ops land, and refusing it would break `lait join`.
        assert!(check_schema_version(0).is_ok());
        assert!(check_schema_version(SCHEMA_VERSION + 1).is_err());
    }
    use crate::ids::{ProjectId, SystemUlidSource};
    use crate::issue::NewIssue;

    fn tmp_home() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "gc-store-{}-{}",
            std::process::id(),
            DocId::mint(&SystemUlidSource)
        ));
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn genesis_roundtrips() {
        let home = tmp_home();
        let store = Store::open(&home).unwrap();
        assert!(store.genesis().unwrap().is_none());
        let g = Genesis {
            space_id: SpaceId::mint(&SystemUlidSource),
            founding_actors: vec![crate::ids::ActorId::from_incept_hash(&"a".repeat(64))],
            salt: [0u8; 16],
            recovery_root: [0u8; 32],
        };
        store.write_genesis(&g).unwrap();
        assert_eq!(store.genesis().unwrap(), Some(g));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn catalog_and_issue_persist_and_reload() {
        let home = tmp_home();
        let store = Store::open(&home).unwrap();
        let ws = SpaceId::mint(&SystemUlidSource);
        let me = crate::ids::DeviceId::from_key_string("a".repeat(64));
        let cat = CatalogDoc::create(&ws, "test", None, &me).unwrap();
        let p = ProjectId::mint(&SystemUlidSource);
        cat.add_project(&p, "Eng", "ENG", "blue").unwrap();
        let issue = IssueDoc::create(NewIssue {
            doc_id: DocId::mint(&SystemUlidSource),
            space_id: ws.clone(),
            project_id: p.clone(),
            title: "persist me".into(),
            priority: Priority::Low,
            created_by: crate::ids::ActorId::from_incept_hash(&"a".repeat(64)),
            committed_by: me.clone(),
            created_at: 7,
            body: None,
            peer: None,
        })
        .unwrap();
        cat.upsert_row(&issue).unwrap();
        cat.apply(&crate::op::OpCtx::structure("seed", &me));
        store.save_catalog(&cat).unwrap();
        store.save_issue(&issue).unwrap();

        // reopen
        let store2 = Store::open(&home).unwrap();
        let cat2 = store2.load_catalog().unwrap().unwrap();
        assert_eq!(cat2.project_by_key("ENG").map(|x| x.id), Some(p));
        let ids = store2.issue_doc_ids();
        assert_eq!(ids.len(), 1);
        let loaded = store2.load_issue(&ids[0]).unwrap().unwrap();
        assert_eq!(loaded.title(), "persist me");
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn atomic_write_leaves_no_tmp() {
        let home = tmp_home();
        let store = Store::open(&home).unwrap();
        let ws = SpaceId::mint(&SystemUlidSource);
        let cat = CatalogDoc::create(
            &ws,
            "test",
            None,
            &crate::ids::DeviceId::from_key_string("a".repeat(64)),
        )
        .unwrap();
        store.save_catalog(&cat).unwrap();
        assert!(!store.repo.join("catalog.tmp").exists());
        assert!(store.repo.join("catalog.loro").exists());
        let _ = fs::remove_dir_all(&home);
    }
}
