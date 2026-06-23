//! `groupchat doctor` / `groupchat prune`: install hygiene.
//!
//! Pure decision functions (which binaries to remove, is the keeper on PATH,
//! which identities to prune) live here, separated from the thin fs/daemon
//! side-effecting wrappers so the risky "what to delete" logic is unit-tested.

use std::fs;
use std::path::{Path, PathBuf};

/// Directories worth scanning for a groupchat binary: everything on `$PATH`
/// plus the install locations our two installers use, even if not on PATH.
pub fn candidate_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        dirs.extend(std::env::split_paths(&path));
    }
    if let Some(home) = directories::BaseDirs::new().map(|b| b.home_dir().to_path_buf()) {
        for sub in [".cargo/bin", ".local/bin", "bin"] {
            dirs.push(home.join(sub));
        }
    }
    dirs.push(PathBuf::from("/usr/local/bin"));
    dirs.push(PathBuf::from("/opt/homebrew/bin"));
    dirs
}

/// Existing `groupchat` files in `dirs`, canonicalized and deduped.
pub fn discover_binaries(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        let candidate = dir.join("groupchat");
        if !candidate.is_file() {
            continue;
        }
        let canon = candidate.canonicalize().unwrap_or(candidate);
        if !out.contains(&canon) {
            out.push(canon);
        }
    }
    out
}

/// Remove each binary and its `groupchat-update` sibling (if present). Returns
/// the outcome per binary path so callers can report permission errors without
/// aborting the run.
pub fn remove_binaries(paths: &[PathBuf]) -> Vec<(PathBuf, std::io::Result<()>)> {
    let mut outcomes = Vec::new();
    for p in paths {
        let res = fs::remove_file(p);
        if res.is_ok() {
            let upd = updater_sibling(p);
            if upd.exists() {
                let _ = fs::remove_file(&upd);
            }
        }
        outcomes.push((p.clone(), res));
    }
    outcomes
}

/// Every found binary except the keeper (compared by canonical path).
pub fn removal_set(found: &[PathBuf], keeper: &Path) -> Vec<PathBuf> {
    found.iter().filter(|p| p.as_path() != keeper).cloned().collect()
}

/// Whether the keeper's directory is present anywhere on PATH.
pub fn dir_on_path(path_dirs: &[PathBuf], keeper_dir: &Path) -> bool {
    path_dirs.iter().any(|d| d.as_path() == keeper_dir)
}

/// If some PATH entry *earlier* than the keeper's dir also contains a groupchat
/// binary, the keeper is shadowed; return that earlier dir. `binary_dirs` is the
/// set of dirs known to hold a groupchat binary.
pub fn shadowed_by(
    path_dirs: &[PathBuf],
    keeper_dir: &Path,
    binary_dirs: &[PathBuf],
) -> Option<PathBuf> {
    let keeper_idx = path_dirs.iter().position(|d| d.as_path() == keeper_dir)?;
    path_dirs
        .iter()
        .take(keeper_idx)
        .find(|d| binary_dirs.iter().any(|b| b.as_path() == d.as_path()))
        .cloned()
}

/// The cargo-dist self-updater that sits next to a binary.
pub fn updater_sibling(binary: &Path) -> PathBuf {
    binary.with_file_name("groupchat-update")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn removal_set_excludes_only_the_keeper() {
        let a = PathBuf::from("/a/groupchat");
        let b = PathBuf::from("/b/groupchat");
        let c = PathBuf::from("/c/groupchat");
        let out = removal_set(&[a.clone(), b.clone(), c.clone()], &b);
        assert_eq!(out, vec![a, c]);
    }

    #[test]
    fn dir_on_path_detects_presence() {
        let dirs = vec![PathBuf::from("/usr/bin"), PathBuf::from("/home/me/.cargo/bin")];
        assert!(dir_on_path(&dirs, Path::new("/home/me/.cargo/bin")));
        assert!(!dir_on_path(&dirs, Path::new("/home/me/.local/bin")));
    }

    #[test]
    fn shadowed_by_finds_earlier_dir_with_binary() {
        let path = vec![
            PathBuf::from("/home/me/.local/bin"),
            PathBuf::from("/home/me/.cargo/bin"),
        ];
        let binary_dirs = vec![PathBuf::from("/home/me/.local/bin")];
        // keeper is in .cargo/bin, but .local/bin (earlier) also has one
        assert_eq!(
            shadowed_by(&path, Path::new("/home/me/.cargo/bin"), &binary_dirs),
            Some(PathBuf::from("/home/me/.local/bin"))
        );
        // no earlier dir holds a binary -> not shadowed
        assert_eq!(
            shadowed_by(&path, Path::new("/home/me/.local/bin"), &binary_dirs),
            None
        );
    }

    #[test]
    fn updater_sibling_is_next_to_binary() {
        assert_eq!(
            updater_sibling(Path::new("/home/me/.cargo/bin/groupchat")),
            PathBuf::from("/home/me/.cargo/bin/groupchat-update")
        );
    }

    #[test]
    fn discover_finds_groupchat_files_and_dedupes() {
        let base = std::env::temp_dir().join(format!("gc-discover-{}", std::process::id()));
        let d1 = base.join("a");
        let d2 = base.join("b");
        std::fs::create_dir_all(&d1).unwrap();
        std::fs::create_dir_all(&d2).unwrap();
        std::fs::write(d1.join("groupchat"), b"x").unwrap();
        std::fs::write(d2.join("groupchat"), b"x").unwrap();
        std::fs::write(d2.join("other"), b"x").unwrap();

        let found = discover_binaries(&[d1.clone(), d2.clone(), d1.clone()]);
        assert_eq!(found.len(), 2, "two groupchat files, dir listed twice deduped");
        assert!(found.iter().all(|p| p.ends_with("groupchat")));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn remove_binaries_deletes_targets_and_updater() {
        let base = std::env::temp_dir().join(format!("gc-remove-{}", std::process::id()));
        std::fs::create_dir_all(&base).unwrap();
        let bin = base.join("groupchat");
        let upd = base.join("groupchat-update");
        std::fs::write(&bin, b"x").unwrap();
        std::fs::write(&upd, b"x").unwrap();

        let outcomes = remove_binaries(&[bin.clone()]);
        assert!(outcomes.iter().all(|(_, r)| r.is_ok()));
        assert!(!bin.exists(), "binary removed");
        assert!(!upd.exists(), "sibling updater removed");

        let _ = std::fs::remove_dir_all(&base);
    }
}
