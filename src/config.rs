//! On-disk state: identity and room/profile settings.
//!
//! Two locations (DUR-5): a **global identity** (the `secret.key`, under the
//! platform config dir) and a **per-repo workspace store** (the `.groupchat/`
//! dir discovered git-style by walking up from the cwd). One identity spans every
//! repo-bound store, like a single `git` `user.email` across many repos.
//! `$GROUPCHAT_HOME` collapses both into one self-contained dir (tests, `--home`,
//! advanced setups).

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};

use crate::registry::{agents_base, Registry, SessionMap};

/// The base config directory (ignoring `$GROUPCHAT_HOME`) — where the named
/// identity registry (`agents/`) and the session map live.
pub fn config_root() -> Result<PathBuf> {
    let dir = match std::env::var_os("GROUPCHAT_CONFIG_ROOT") {
        Some(p) => PathBuf::from(p),
        None => directories::ProjectDirs::from("dev", "nixi", "groupchat")
            .context("could not determine config directory")?
            .config_dir()
            .to_path_buf(),
    };
    fs::create_dir_all(&dir).with_context(|| format!("create config dir {}", dir.display()))?;
    Ok(dir)
}

/// The registry of named identities, and the session→identity map beside it.
pub fn registry() -> Result<(Registry, PathBuf)> {
    let root = config_root()?;
    let base = agents_base(&root);
    fs::create_dir_all(&base)?;
    Ok((Registry::new(base), root.join("sessions.json")))
}

/// The per-repo workspace store directory name, discovered git-style.
const STORE_DIR: &str = ".groupchat";

/// Walk up from `start` for an existing `.groupchat/` workspace store, so a
/// command run anywhere inside a repo binds that repo's store (like `git`
/// finding `.git`). Returns the store dir, or `None` if none exists above `start`.
fn find_store_dir(start: &Path) -> Option<PathBuf> {
    for dir in start.ancestors() {
        let candidate = dir.join(STORE_DIR);
        if candidate.is_dir() {
            return Some(candidate);
        }
    }
    None
}

/// Canonicalize a path so the CLI and the daemon it spawns hash the *same* store
/// path (the control channel + single-instance lock are keyed on it). Falls back
/// to the input if canonicalization fails (e.g. the dir was just created).
fn canonical(p: &Path) -> PathBuf {
    match fs::canonicalize(p) {
        Ok(c) => strip_extended_prefix(c),
        Err(_) => p.to_path_buf(),
    }
}

/// On Windows, `fs::canonicalize` returns an extended-length `\\?\C:\…` path.
/// That prefix breaks a lot of tooling and Windows APIs (and would flow into the
/// daemon we spawn), so strip it for ordinary drive paths — leaving genuine UNC
/// (`\\?\UNC\…`) paths untouched. No-op on unix.
#[cfg(windows)]
fn strip_extended_prefix(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_prefix(r"\\?\") {
        // Only unwrap plain `X:\…` drive paths, not `\\?\UNC\server\share`.
        let b = rest.as_bytes();
        if b.len() >= 2 && b[1] == b':' {
            return PathBuf::from(rest);
        }
    }
    p
}
#[cfg(not(windows))]
fn strip_extended_prefix(p: PathBuf) -> PathBuf {
    p
}

/// Drop a `.gitignore` into a fresh store so the parent repo never accidentally
/// commits this node's local workspace replica + daemon state — it syncs over
/// P2P, and (like `.git/`) is per-node, not source. No-op if one already exists.
fn ensure_store_gitignore(store: &Path) {
    let p = store.join(".gitignore");
    if !p.exists() {
        let _ = fs::write(
            &p,
            "# groupchat local store — per-node, synced over P2P, do not commit\n*\n",
        );
    }
}

/// Seed a freshly-created repo store's profile so distinct repos default to
/// distinct gossip rooms (the repo directory name) instead of all sharing
/// `"default"` and colliding on one topic. No-op if a profile already exists.
fn seed_repo_profile(store: &Path) {
    if store.join("profile.json").exists() {
        return;
    }
    let mut p = Profile::default();
    if let Some(name) = store
        .parent()
        .and_then(|d| d.file_name())
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty())
    {
        p.room = name.to_string();
    }
    let _ = p.save(store);
}

/// Resolve the **workspace store** directory for this invocation (the per-repo
/// `.groupchat/`). Precedence:
///   1. an explicit named identity (`resume`/`--as`) — a self-contained home
///      under the identity registry.
///   2. `$GROUPCHAT_HOME` — explicit, self-contained override (identity + store
///      in one dir): `--home`, tests, advanced setups.
///   3. `$GROUPCHAT_STORE` — internal pin passed to the daemon we spawn so it
///      binds the exact store the CLI resolved, independent of its cwd.
///   4. git-style discovery: walk up from the cwd for a `.groupchat/` and use it;
///      otherwise auto-create `.groupchat/` in the cwd.
///
/// The identity key is resolved separately ([`identity_dir`]) — global by
/// default, so one identity spans every repo-bound store.
pub fn resolve_home(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(name) = explicit {
        let (reg, _) = registry()?;
        let home = reg.home_for(name);
        fs::create_dir_all(&home)?;
        return Ok(home);
    }
    if let Some(p) = std::env::var_os("GROUPCHAT_HOME") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }
    let store = if let Some(p) = std::env::var_os("GROUPCHAT_STORE") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        canonical(&dir)
    } else {
        let cwd = std::env::current_dir().context("get current dir")?;
        let dir = match find_store_dir(&cwd) {
            Some(s) => s,
            None => {
                let s = cwd.join(STORE_DIR);
                fs::create_dir_all(&s)?;
                s
            }
        };
        canonical(&dir)
    };
    seed_repo_profile(&store);
    ensure_store_gitignore(&store);
    Ok(store)
}

/// The directory holding this node's identity `secret.key`. A self-contained
/// home (`$GROUPCHAT_HOME`) keeps the key beside its store; otherwise the key is
/// **global** (under [`config_root`]) so one identity spans every repo-bound
/// store — like one `git` `user.email` across many repos.
pub fn identity_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("GROUPCHAT_HOME") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }
    config_root()
}

/// The store this invocation WOULD bind if it already exists — WITHOUT creating
/// one. For commands like `update` that must not spawn a stray `.groupchat/` just
/// to look for a running daemon.
pub fn existing_home() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("GROUPCHAT_HOME") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("GROUPCHAT_STORE") {
        return Some(canonical(&PathBuf::from(p)));
    }
    let cwd = std::env::current_dir().ok()?;
    find_store_dir(&cwd).map(|s| canonical(&s))
}

/// Names of all registered identities.
pub fn list_identities() -> Result<Vec<String>> {
    let (reg, _) = registry()?;
    Ok(reg.list())
}

/// Bind the current session to a named identity (creating it if needed) so this
/// session — and future resumes of it — recall that identity. Returns its home.
pub fn bind_session(name: &str) -> Result<PathBuf> {
    let (reg, sessions) = registry()?;
    let home = reg.home_for(name);
    fs::create_dir_all(&home)?;
    if let Ok(sid) = std::env::var("CLAUDE_CODE_SESSION_ID") {
        SessionMap::load(sessions).set(&sid, name)?;
    }
    Ok(home)
}

/// A short, stable hex token derived from a home path. Used to name the control
/// channel uniquely per home (so several `$GROUPCHAT_HOME` nodes on one machine
/// never collide) — as a filesystem socket name on unix and a named-pipe name on
/// Windows. Both the daemon and its clients hash the same home, so they agree.
pub fn home_hash(home: &Path) -> String {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    home.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Filesystem path to the control socket for the running daemon (unix only; on
/// Windows the control channel is a named pipe, see `control::control_name`).
///
/// AF_UNIX socket paths are capped at 104 bytes on macOS (`sun_path`; 108 on
/// Linux). The per-agent home under `~/Library/Application Support/…/agents/
/// agent-XXXXXX/` can exceed that for longer usernames — the daemon then fails
/// to `bind()` and never comes online ("daemon did not come online in time").
/// When the natural in-home path would be too long, fall back to a short, stable
/// path in the temp dir derived from a hash of the home. Both the daemon and the
/// CLI client resolve this the same way (same binary, same home), so they agree
/// on where to bind/connect.
#[cfg(unix)]
pub fn socket_path(home: &Path) -> PathBuf {
    let direct = home.join("control.sock");
    // Leave margin below the 104-byte macOS limit (path bytes + NUL terminator).
    const MAX_SUN_PATH: usize = 100;
    if direct.as_os_str().len() <= MAX_SUN_PATH {
        return direct;
    }

    std::env::temp_dir().join(format!("gc-{}.sock", home_hash(home)))
}

/// Path to the single-instance lock file for a home.
fn lock_path(home: &Path) -> PathBuf {
    home.join("daemon.lock")
}

/// A held single-instance lock for a daemon home. The underlying OS advisory
/// lock (`flock(2)` on unix, `LockFileEx` on Windows, via `fs2`) is released
/// automatically when this value is dropped or the process exits — even on a
/// crash — so the lock can never go stale.
#[derive(Debug)]
pub struct DaemonLock {
    _file: fs::File,
}

/// Acquire the exclusive single-instance lock for a home, guaranteeing at most
/// one daemon per home. Returns an error if another daemon already holds it,
/// which is how we avoid the startup race that used to spawn duplicate daemons.
pub fn acquire_daemon_lock(home: &Path) -> Result<DaemonLock> {
    use fs2::FileExt;
    let path = lock_path(home);
    let file =
        fs::File::create(&path).with_context(|| format!("create lock file {}", path.display()))?;
    // Exclusive, non-blocking advisory lock held by this open file handle. The
    // OS releases it when the handle closes (process exit or crash), so the lock
    // can never go stale. A second daemon for the same home gets a would-block
    // error here and bails instead of clobbering the live one. `fs2` maps to
    // flock(2) on unix and LockFileEx on Windows — same guarantee, portably.
    file.try_lock_exclusive().map_err(|_| {
        anyhow!(
            "another groupchat daemon is already running for this home ({})",
            home.display()
        )
    })?;
    Ok(DaemonLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_store_dir_walks_up_to_the_nearest_groupchat() {
        let root = std::env::temp_dir().join(format!("gc-disc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = root.join("repo");
        let nested = repo.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        // No `.groupchat/` anywhere above `nested`.
        assert_eq!(find_store_dir(&nested), None);

        // Create the store at the repo root; discovery from a deep subdir and
        // from the root itself both bind it (git-style walk-up).
        let store = repo.join(STORE_DIR);
        std::fs::create_dir_all(&store).unwrap();
        assert_eq!(find_store_dir(&nested), Some(store.clone()));
        assert_eq!(find_store_dir(&repo), Some(store));

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn second_daemon_lock_fails_while_first_is_held() {
        let dir = std::env::temp_dir().join(format!("gc-locktest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();

        let first = acquire_daemon_lock(&dir).expect("first lock should succeed");
        let second = acquire_daemon_lock(&dir);
        assert!(
            second.is_err(),
            "a second daemon lock must fail while the first is held"
        );

        drop(first);
        let third = acquire_daemon_lock(&dir)
            .expect("lock should be available again after the first is dropped");
        drop(third);

        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_stays_under_the_unix_limit() {
        // Short home: socket lives in the home, as before.
        let short = PathBuf::from("/Users/moon/Library/Application Support/dev.nixi.groupchat");
        assert_eq!(socket_path(&short), short.join("control.sock"));

        // Long per-agent home (longer username) that would blow past macOS's
        // 104-byte sun_path limit — must fall back to a short, bindable path.
        let long = PathBuf::from(
            "/Users/savannahmoongoldstein/Library/Application Support/\
             dev.nixi.groupchat/agents/agent-6c8502",
        );
        assert!(
            long.join("control.sock").as_os_str().len() > 104,
            "test premise: the natural path should exceed the limit"
        );
        let p = socket_path(&long);
        assert!(
            p.as_os_str().len() <= 104,
            "control socket path must fit in sun_path: {} bytes ({})",
            p.as_os_str().len(),
            p.display()
        );

        // Deterministic: daemon and CLI must resolve the same long home identically.
        assert_eq!(socket_path(&long), socket_path(&long));
    }
}

fn secret_key_path(home: &Path) -> PathBuf {
    home.join("secret.key")
}

/// Load the persistent identity, creating one on first run.
pub fn load_or_create_identity(home: &Path) -> Result<SecretKey> {
    let path = secret_key_path(home);
    if path.exists() {
        let hex = fs::read_to_string(&path).context("read secret key")?;
        let key: SecretKey = hex
            .trim()
            .parse()
            .map_err(|e| anyhow::anyhow!("parse secret key: {e}"))?;
        Ok(key)
    } else {
        let key = SecretKey::generate();
        let hex = data_encoding::HEXLOWER.encode(&key.to_bytes());
        fs::write(&path, hex).context("write secret key")?;
        Ok(key)
    }
}

/// Profile/room settings, persisted to `profile.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Our display nickname.
    pub nick: String,
    /// The room name we share a gossip topic with (everyone using the same name
    /// lands in the same topic). Becomes the per-workspace topic in the tracker.
    pub room: String,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            nick: whoami_fallback(),
            room: "default".to_string(),
        }
    }
}

impl Profile {
    fn path(home: &Path) -> PathBuf {
        home.join("profile.json")
    }

    pub fn load(home: &Path) -> Result<Self> {
        let path = Self::path(home);
        if !path.exists() {
            let p = Self::default();
            p.save(home)?;
            return Ok(p);
        }
        let data = fs::read_to_string(&path).context("read profile")?;
        serde_json::from_str(&data).context("parse profile")
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self).context("serialize profile")?;
        fs::write(Self::path(home), data).context("write profile")?;
        Ok(())
    }
}

fn whoami_fallback() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anon".to_string())
}
