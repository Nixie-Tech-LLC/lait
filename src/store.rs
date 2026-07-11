//! Layer A durability — the **git-backed local store** (ARCHITECTURE §6, SCHEMA
//! §8). One repo per node whose only role is durable local persistence; git
//! **never** transports between nodes. Layout:
//!
//! ```text
//! <home>/repo/
//!   genesis.json        // workspaceId + founding admin keys (public only)
//!   catalog.loro        // export(Snapshot) of the Catalog doc
//!   docs/<DocId>.loro   // per-issue snapshot, lazily loaded
//!   heads               // DocId -> head-hash table (cache; recomputed on load)
//!   acl.loro            // persisted signed ACL log (P3; empty at P0)
//! ```
//!
//! Only **public keys, signed ops, and Loro snapshots/updates** are stored —
//! **never secrets** (A§6). git is used via the `git` CLI as a best-effort
//! durability/inspectability layer: the store is correct on the filesystem alone
//! and never *requires* git at runtime (keeps the build pure-Rust, no C deps —
//! decision log). Snapshots are written whole per save at P0 (incremental
//! `export(updates)` is a deferred optimization).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, Context, Result};
use loro::LoroDoc;
use serde::{Deserialize, Serialize};

use crate::catalog::CatalogDoc;
use crate::ids::{DocId, UserId, WorkspaceId};
use crate::issue::IssueDoc;

/// The workspace genesis — the root of trust (A§6, S§6). Distributed in the
/// invite ticket; persisted here as public data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub workspace_id: WorkspaceId,
    pub founding_admins: Vec<UserId>,
}

/// The git-backed store rooted at `<home>/repo`.
pub struct Store {
    repo: PathBuf,
    git: bool,
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
            let _ = run_git(&repo, &["config", "user.email", "groupchat@localhost"]);
            let _ = run_git(&repo, &["config", "user.name", "groupchat"]);
        }
        Ok(Self { repo, git })
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

    // ---- catalog ----

    pub fn load_catalog(&self) -> Result<Option<CatalogDoc>> {
        let p = self.catalog_path();
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p).context("read catalog.loro")?;
        let doc = LoroDoc::new();
        doc.import(&bytes)
            .map_err(|e| anyhow!("import catalog: {e}"))?;
        Ok(Some(CatalogDoc::from_doc(doc)))
    }

    pub fn save_catalog(&self, catalog: &CatalogDoc) -> Result<()> {
        let bytes = catalog.snapshot()?;
        write_atomic(&self.catalog_path(), &bytes)?;
        Ok(())
    }

    // ---- membership (plaintext ACL + sealed key envelopes, A§11) ----

    fn membership_path(&self) -> PathBuf {
        self.repo.join("membership.loro")
    }

    pub fn load_membership(&self) -> Result<Option<crate::membership::MembershipDoc>> {
        let p = self.membership_path();
        if !p.exists() {
            return Ok(None);
        }
        let bytes = fs::read(&p).context("read membership.loro")?;
        let doc = LoroDoc::new();
        doc.import(&bytes)
            .map_err(|e| anyhow!("import membership: {e}"))?;
        Ok(Some(crate::membership::MembershipDoc::from_doc(doc)))
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
        let doc = LoroDoc::new();
        doc.import(&bytes)
            .map_err(|e| anyhow!("import issue: {e}"))?;
        Ok(Some(IssueDoc::from_doc(doc)))
    }

    pub fn save_issue(&self, issue: &IssueDoc) -> Result<()> {
        let doc_id = issue.doc_id().ok_or_else(|| anyhow!("issue has no id"))?;
        let bytes = issue.snapshot()?;
        write_atomic(&self.issue_path(&doc_id), &bytes)?;
        Ok(())
    }

    /// Commit the current store state as a durability point (best-effort). A
    /// no-op when git is unavailable or there is nothing to commit.
    pub fn commit(&self, message: &str) -> bool {
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
                "user.email=groupchat@localhost",
                "-c",
                "user.name=groupchat",
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Priority;
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
            workspace_id: WorkspaceId::mint(&SystemUlidSource),
            founding_admins: vec![UserId::from_key_string("a".repeat(64))],
        };
        store.write_genesis(&g).unwrap();
        assert_eq!(store.genesis().unwrap(), Some(g));
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn catalog_and_issue_persist_and_reload() {
        let home = tmp_home();
        let store = Store::open(&home).unwrap();
        let ws = WorkspaceId::mint(&SystemUlidSource);
        let cat = CatalogDoc::create(&ws).unwrap();
        let p = ProjectId::mint(&SystemUlidSource);
        cat.add_project(&p, "Eng", "ENG", "blue").unwrap();
        let issue = IssueDoc::create(NewIssue {
            doc_id: DocId::mint(&SystemUlidSource),
            workspace_id: ws.clone(),
            project_id: p.clone(),
            title: "persist me".into(),
            priority: Priority::Low,
            created_by: UserId::from_key_string("a".repeat(64)),
            created_at: 7,
            body: None,
        })
        .unwrap();
        cat.upsert_row(&issue).unwrap();
        cat.doc().commit();
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
        let ws = WorkspaceId::mint(&SystemUlidSource);
        let cat = CatalogDoc::create(&ws).unwrap();
        store.save_catalog(&cat).unwrap();
        assert!(!store.repo.join("catalog.tmp").exists());
        assert!(store.repo.join("catalog.loro").exists());
        let _ = fs::remove_dir_all(&home);
    }
}
