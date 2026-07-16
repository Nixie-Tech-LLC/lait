//! On-disk state: identity, store discovery, and layered local settings.
//!
//! Two locations (DUR-5): a **global identity** (the `secret.key`, under the
//! platform config dir) and a **per-repo workspace store** (the `.lait/`
//! dir discovered git-style by walking up from the cwd). One identity spans every
//! repo-bound store, like a single `git` `user.email` across many repos.
//! `$LAIT_HOME` collapses both into one self-contained dir (tests, `--home`,
//! advanced setups).
//!
//! Discovery **never creates a store**: workspaces come into being only through
//! the two explicit verbs (`lait init` founds, `lait join` bootstraps from a
//! ticket) via [`store_dir_for_init`]. Every other command resolves an existing
//! store or fails with [`NoStoreHere`] — the silent decoy-store auto-create (and
//! the directory-trap guard rail it required) is gone by design.
//!
//! Settings are git-style layered key/value maps ([`Settings`]): a global
//! `config.json` under the config root and a per-store `config.json` inside
//! `.lait/`, nearest (store) wins. Keys are validated against the static
//! [`KEYS`] table; the `workspace.*` namespace is reserved for future settings
//! synced through the Catalog.

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};

use crate::registry::{agents_base, Registry, SessionMap};

/// The base config directory (ignoring `$LAIT_HOME`) — where the named
/// identity registry (`agents/`) and the session map live.
pub fn config_root() -> Result<PathBuf> {
    let dir = match std::env::var_os("LAIT_CONFIG_ROOT") {
        Some(p) => PathBuf::from(p),
        None => directories::ProjectDirs::from("dev", "nixi", "lait")
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
const STORE_DIR: &str = ".lait";

/// Walk up from `start` for an existing `.lait/` workspace store, so a
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
            "# lait local store — per-node, synced over P2P, do not commit\n*\n",
        );
    }
}

/// Typed "no workspace store here" error, so callers (the app dispatcher) can
/// tell "nothing to bind" apart from real I/O failures and print the guided
/// error (`lait init` / `lait join` / `-w`) instead of a bare failure.
#[derive(Debug)]
pub struct NoStoreHere {
    /// The directory discovery started from.
    pub cwd: PathBuf,
}
impl std::fmt::Display for NoStoreHere {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no lait workspace found here (searched up from {})",
            self.cwd.display()
        )
    }
}
impl std::error::Error for NoStoreHere {}

/// Resolve the **existing** workspace store for this invocation — never
/// creating one. Precedence:
///   1. an explicit named identity (`resume`/`--as`) — a self-contained home
///      under the identity registry (created on demand: it is an identity
///      container, not a workspace).
///   2. `$LAIT_HOME` — explicit, self-contained override (identity + store
///      in one dir): `--home`, tests, advanced setups.
///   3. `$LAIT_STORE` — pin set by the CLI for the daemon it spawns (and by
///      `-w`), so both bind the exact store the CLI resolved, independent
///      of cwd.
///   4. git-style discovery: walk up from the cwd for a `.lait/`.
///
/// A discovery miss is a typed [`NoStoreHere`] error — stores are only born in
/// [`store_dir_for_init`] (`lait init` / `lait join`). The identity key is
/// resolved separately ([`identity_dir`]) — global by default, so one identity
/// spans every repo-bound store.
pub fn resolve_existing_store(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(name) = explicit {
        let (reg, _) = registry()?;
        let home = reg.home_for(name);
        fs::create_dir_all(&home)?;
        return Ok(home);
    }
    if let Some(p) = std::env::var_os("LAIT_HOME") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }
    if let Some(p) = std::env::var_os("LAIT_STORE") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(canonical(&dir));
    }
    let cwd = std::env::current_dir().context("get current dir")?;
    match find_store_dir(&cwd) {
        Some(s) => Ok(canonical(&s)),
        None => Err(anyhow::Error::new(NoStoreHere { cwd })),
    }
}

/// Create (or reuse) the `.lait/` store dir under `dir` — the raw creation
/// primitive, ignoring `$LAIT_HOME` (used by `join --dir`, where the explicit
/// argument must win).
pub fn store_dir_under(dir: &Path) -> Result<PathBuf> {
    let store = dir.join(STORE_DIR);
    fs::create_dir_all(&store).with_context(|| format!("create store dir {}", store.display()))?;
    let store = canonical(&store);
    ensure_store_gitignore(&store);
    Ok(store)
}

/// The store directory a creation verb (`init`/`join`) will populate: an
/// explicit `$LAIT_HOME` if set, else `<dir>/.lait`. Creates the directory and
/// drops the store `.gitignore`. Together with [`store_dir_under`], the ONLY
/// paths that bring a store into existence.
pub fn store_dir_for_init(dir: &Path) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LAIT_HOME") {
        let d = PathBuf::from(p);
        fs::create_dir_all(&d)?;
        ensure_store_gitignore(&d);
        return Ok(d);
    }
    store_dir_under(dir)
}

/// The directory holding this node's identity `secret.key`. A self-contained
/// home (`$LAIT_HOME`) keeps the key beside its store; otherwise the key is
/// **global** (under [`config_root`]) so one identity spans every repo-bound
/// store — like one `git` `user.email` across many repos.
pub fn identity_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("LAIT_HOME") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }
    config_root()
}

/// The store this invocation WOULD bind if it already exists — WITHOUT creating
/// one. For commands like `update` that must not spawn a stray `.lait/` just
/// to look for a running daemon.
pub fn existing_home() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("LAIT_HOME") {
        return Some(PathBuf::from(p));
    }
    if let Some(p) = std::env::var_os("LAIT_STORE") {
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
/// channel uniquely per home (so several `$LAIT_HOME` nodes on one machine
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

/// Path to the file naming the daemon that holds a home. Deliberately not the
/// lock file — see `acquire_daemon_lock`.
fn pid_path(home: &Path) -> PathBuf {
    home.join("daemon.pid")
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
            "another lait daemon is already running for this home ({})",
            home.display()
        )
    })?;
    // Name ourselves *beside* the lock, never inside it. The lock says only that
    // *someone* holds this home; the pid says who, which is what lets a client
    // clean up a daemon that has stopped answering (`Request::Stop` alone is not
    // enough — a v0.4.8-era daemon acknowledges `stop` and keeps running, see
    // `node::signal_shutdown`, so the fallback needs a signal target).
    //
    // Writing it into the lock file itself is a unix-only assumption, not a
    // unix-only API — which is why it compiled everywhere and only failed on
    // Windows CI. `flock(2)` is *advisory*, so any handle may read a locked file;
    // `LockFileEx` is **mandatory** and blocks other handles from reading the
    // locked range, making the pid unreadable by precisely the client that needs
    // it. A separate file is readable on both.
    //
    // Best-effort: a failure here costs the cleanup path, not the daemon.
    let _ = fs::write(pid_path(home), std::process::id().to_string());
    Ok(DaemonLock { _file: file })
}

/// The pid of the daemon that last held this home, if one recorded itself.
///
/// Only meaningful once a caller has *independently* established that a daemon is
/// there (`control::probe` answering anything but `Absent`). This file outlives a
/// crashed daemon, and a pid is reused; the probe is what rules out signalling a
/// stranger. A daemon that predates the stamp simply returns `None`.
pub fn daemon_pid(home: &Path) -> Option<u32> {
    fs::read_to_string(pid_path(home)).ok()?.trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_lock_holder_stays_identifiable_while_it_holds_the_lock() {
        let dir = std::env::temp_dir().join(format!("gc-lock-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let _held = acquire_daemon_lock(&dir).expect("first daemon takes the lock");
        // Readable *while the lock is held* — the only moment it is worth
        // anything, and the reason the pid cannot live inside the lock file:
        // Windows locks are mandatory, so that read would fail there while
        // passing on unix.
        assert_eq!(
            daemon_pid(&dir),
            Some(std::process::id()),
            "the daemon holding a home must be identifiable while it holds it",
        );

        // A second daemon must lose, and must not disturb the winner's identity —
        // it never gets far enough to write one.
        assert!(
            acquire_daemon_lock(&dir).is_err(),
            "a second daemon must not get the lock",
        );
        assert_eq!(
            daemon_pid(&dir),
            Some(std::process::id()),
            "a daemon that lost the lock race must not blank the winner's pid",
        );

        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn settings_store_layer_wins_over_global() {
        let dir = std::env::temp_dir().join(format!("gc-settings-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut store = ConfigMap::default();
        store.set("user.nick", "store-nick");
        store.save(&store_config_path(&dir)).unwrap();
        let s = Settings {
            global: {
                let mut g = ConfigMap::default();
                g.set("user.nick", "global-nick");
                g.set("project.default", "ENG");
                g
            },
            store: ConfigMap::load(&store_config_path(&dir)),
        };
        assert_eq!(s.get("user.nick"), Some("store-nick"));
        assert_eq!(s.get("project.default"), Some("ENG"));
        assert_eq!(s.nick(), "store-nick");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_map_roundtrips_and_degrades_to_empty() {
        let dir = std::env::temp_dir().join(format!("gc-cfgmap-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.json");
        assert!(ConfigMap::load(&p).0.is_empty(), "missing file → empty");
        let mut m = ConfigMap::default();
        m.set("user.nick", "x");
        m.save(&p).unwrap();
        assert_eq!(ConfigMap::load(&p).get("user.nick"), Some("x"));
        fs::write(&p, "{corrupt").unwrap();
        assert!(ConfigMap::load(&p).0.is_empty(), "corrupt file → empty");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn key_table_rejects_unknown_and_reserves_workspace_namespace() {
        assert!(key_spec("user.nick").is_ok());
        assert!(key_spec("project.default").is_ok());
        let unknown = key_spec("user.nickk").unwrap_err().to_string();
        assert!(unknown.contains("known keys"), "{unknown}");
        let reserved = key_spec("workspace.name").unwrap_err().to_string();
        assert!(reserved.contains("reserved"), "{reserved}");
    }

    #[test]
    fn discovery_never_creates_but_init_path_does() {
        let root = std::env::temp_dir().join(format!("gc-nostore-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        // Bare dir: discovery finds nothing and creates nothing.
        assert_eq!(find_store_dir(&root), None);
        assert!(!root.join(STORE_DIR).exists());
        // The creation verb path mints the store + gitignore.
        let store = store_dir_for_init(&root).unwrap();
        assert!(store.is_dir());
        assert!(store.join(".gitignore").exists());
        // And discovery now binds it.
        assert!(find_store_dir(&root).is_some());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn find_store_dir_walks_up_to_the_nearest_lait() {
        let root = std::env::temp_dir().join(format!("gc-disc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let repo = root.join("repo");
        let nested = repo.join("a").join("b");
        std::fs::create_dir_all(&nested).unwrap();

        // No `.lait/` anywhere above `nested`.
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
        let short = PathBuf::from("/Users/moon/Library/Application Support/dev.nixi.lait");
        assert_eq!(socket_path(&short), short.join("control.sock"));

        // Long per-agent home (longer username) that would blow past macOS's
        // 104-byte sun_path limit — must fall back to a short, bindable path.
        let long = PathBuf::from(
            "/Users/maximiliana.rosencrantz-hutchinson/Library/Application Support/\
             dev.nixi.lait/agents/agent-6c8502",
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

// ---- layered local settings (`lait config`) ----

/// Which layers a config key may be written to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLayers {
    /// Both the global and the per-store file (store wins on read).
    GlobalAndStore,
    /// Per-store only (`--global` is rejected).
    StoreOnly,
}

/// One row of the closed key table: `lait config` refuses names not listed
/// here (typo safety — git's anything-goes is a support trap for a tool this
/// young). Add a row to introduce a key.
#[derive(Debug, Clone, Copy)]
pub struct KeySpec {
    pub name: &'static str,
    pub layers: KeyLayers,
    /// Whether a running daemon consumes this key (⇒ `config set` sends a
    /// best-effort `ConfigReload` so the change is never a silent no-op).
    pub daemon_read: bool,
    pub help: &'static str,
    /// The built-in fallback when unset at every layer, if one exists.
    pub built_in: fn() -> Option<String>,
}

/// The closed set of recognized config keys.
pub const KEYS: &[KeySpec] = &[
    KeySpec {
        name: "user.nick",
        layers: KeyLayers::GlobalAndStore,
        daemon_read: true,
        help: "Display nickname (presence, activity attribution).",
        built_in: || Some(whoami_fallback()),
    },
    KeySpec {
        name: "project.default",
        layers: KeyLayers::StoreOnly,
        daemon_read: false,
        help: "Project key issue-creating commands fall back to when -p is omitted.",
        built_in: || None,
    },
];

/// Look up a key in the table. `workspace.*` names get the reserved-namespace
/// error (future synced workspace settings); anything else unknown lists the
/// valid keys.
///
/// The `tui.*` namespace (theme, saved tabs, and the open `tui.key.<action-id>`
/// override prefix) went with the TUI. The web client keeps the same *shape* of
/// idea — rebind by stable action id, warn rather than gate — but its overrides
/// live client-side for now; see docs/SERVE.md. If they ever want a home on disk,
/// this table is where a `web.key.*` prefix would go.
pub fn key_spec(name: &str) -> Result<&'static KeySpec> {
    if name.starts_with("workspace.") {
        anyhow::bail!("'{name}' is reserved for synced workspace settings (not available yet)");
    }
    KEYS.iter().find(|k| k.name == name).ok_or_else(|| {
        let known: Vec<&str> = KEYS.iter().map(|k| k.name).collect();
        anyhow!(
            "unknown config key '{name}' — known keys: {}",
            known.join(", ")
        )
    })
}

/// Path of the global settings file (`config_root/config.json`).
pub fn global_config_path() -> Result<PathBuf> {
    Ok(config_root()?.join("config.json"))
}

/// Path of a store's settings file (`.lait/config.json`).
pub fn store_config_path(home: &Path) -> PathBuf {
    home.join("config.json")
}

/// One settings file: a flat `key → value` string map, so `get`/`set`/`unset`
/// need no struct churn as keys are added. Missing or corrupt files degrade to
/// empty (settings are conveniences, never gates).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ConfigMap(pub std::collections::BTreeMap<String, String>);

impl ConfigMap {
    pub fn load(path: &Path) -> Self {
        fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    /// Persist atomically (temp file + rename) so a concurrent reader — e.g. a
    /// daemon handling `ConfigReload` — never sees a half-written file.
    pub fn save(&self, path: &Path) -> Result<()> {
        let json = serde_json::to_string_pretty(self).context("encode config")?;
        let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
        fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
        fs::rename(&tmp, path).with_context(|| format!("commit {}", path.display()))?;
        Ok(())
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(|s| s.as_str())
    }
    pub fn set(&mut self, key: &str, value: &str) {
        self.0.insert(key.to_string(), value.to_string());
    }
    /// Returns whether the key was present.
    pub fn unset(&mut self, key: &str) -> bool {
        self.0.remove(key).is_some()
    }
}

/// The merged two-layer view: per-store `config.json` over the global one
/// (nearest wins, like git). Load is cheap (two small files); daemon paths that
/// need a per-request fresh value (e.g. `project.default`) just re-load.
#[derive(Debug, Default)]
pub struct Settings {
    pub global: ConfigMap,
    pub store: ConfigMap,
}

impl Settings {
    /// Load both layers for a store. `home = None` loads only the global layer
    /// (e.g. `lait config --global` outside any workspace).
    pub fn load(home: Option<&Path>) -> Self {
        let global = global_config_path()
            .map(|p| ConfigMap::load(&p))
            .unwrap_or_default();
        let store = home
            .map(|h| ConfigMap::load(&store_config_path(h)))
            .unwrap_or_default();
        Settings { global, store }
    }

    /// Effective value: store layer, then global. No built-in fallback — use
    /// the key's `built_in` for that, so display code can annotate `(default)`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.store.get(key).or_else(|| self.global.get(key))
    }

    /// The effective display nickname (built-in: `$USER`/`$USERNAME`/"anon").
    pub fn nick(&self) -> String {
        self.get("user.nick")
            .map(str::to_string)
            .unwrap_or_else(whoami_fallback)
    }

    /// The configured default project key, if any.
    pub fn default_project(&self) -> Option<String> {
        self.get("project.default").map(str::to_string)
    }
}

fn whoami_fallback() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "anon".to_string())
}
