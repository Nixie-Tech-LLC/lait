//! On-disk state: identity, contacts, and room/profile settings.
//!
//! Everything lives under one home directory, resolved from `$GROUPCHAT_HOME`
//! (handy for running several nodes on one machine) or the platform config dir.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, Context, Result};
use iroh::{EndpointId, SecretKey};
use serde::{Deserialize, Serialize};

use crate::{
    proto::Tier,
    registry::{agents_base, select, Registry, Selection, SessionMap},
};

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

/// Mint a fresh per-session identity name, unique within the registry.
fn mint_name(reg: &Registry, session_id: &str) -> String {
    let short = &session_id[..session_id.len().min(6)];
    let mut name = format!("agent-{short}");
    let mut n = 2;
    while reg.exists(&name) {
        name = format!("agent-{short}-{n}");
        n += 1;
    }
    name
}

/// Resolve which identity's home directory this invocation should use, and
/// return it (created on demand). Order:
///   1. `$GROUPCHAT_HOME` — explicit override (advanced / the spawned daemon).
///   2. an explicit `--as <name>` — use/create that named identity.
///   3. a session already mapped to an existing identity — recall it (0-step).
///   4. otherwise (model B) mint a fresh per-session identity, so each new
///      agent/tab is private by default; without a session id, fall back to the
///      single identity, or require `--as` when there are several.
pub fn resolve_home(explicit: Option<&str>) -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("GROUPCHAT_HOME") {
        let dir = PathBuf::from(p);
        fs::create_dir_all(&dir)?;
        return Ok(dir);
    }

    let (reg, sessions_path) = registry()?;
    let mut map = SessionMap::load(sessions_path);
    let sid = std::env::var("CLAUDE_CODE_SESSION_ID").ok();

    let name = if let Some(name) = explicit {
        name.to_string()
    } else if let Some(s) = sid.as_deref() {
        // Model B: recall this session's identity if mapped, else mint a FRESH
        // per-session identity. Never auto-attach to another session's identity.
        match map.get(s) {
            Some(n) if reg.exists(n) => n.to_string(),
            _ => mint_name(&reg, s),
        }
    } else {
        // No session anchor (e.g. plain shell): fall back to the never-guess
        // selection — attach only when there's exactly one identity.
        match select(reg.list(), None) {
            Selection::Attach(n) => n,
            Selection::Empty => "default".to_string(),
            Selection::Choose(opts) => {
                return Err(anyhow!(
                    "multiple identities — choose one with --as <name>: {}",
                    opts.join(", ")
                ))
            }
        }
    };

    if let Some(s) = sid.as_deref() {
        let _ = map.set(s, &name);
    }
    let home = reg.home_for(&name);
    fs::create_dir_all(&home)?;
    Ok(home)
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

/// Path to the control socket for the running daemon.
///
/// AF_UNIX socket paths are capped at 104 bytes on macOS (`sun_path`; 108 on
/// Linux). The per-agent home under `~/Library/Application Support/…/agents/
/// agent-XXXXXX/` can exceed that for longer usernames — the daemon then fails
/// to `bind()` and never comes online ("daemon did not come online in time").
/// When the natural in-home path would be too long, fall back to a short, stable
/// path in the temp dir derived from a hash of the home. Both the daemon and the
/// CLI client resolve this the same way (same binary, same home), so they agree
/// on where to bind/connect.
pub fn socket_path(home: &Path) -> PathBuf {
    use std::hash::{Hash, Hasher};

    let direct = home.join("control.sock");
    // Leave margin below the 104-byte macOS limit (path bytes + NUL terminator).
    const MAX_SUN_PATH: usize = 100;
    if direct.as_os_str().len() <= MAX_SUN_PATH {
        return direct;
    }

    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    home.hash(&mut hasher);
    std::env::temp_dir().join(format!("gc-{:016x}.sock", hasher.finish()))
}

/// Path to the blob store directory.
pub fn blob_store_path(home: &Path) -> PathBuf {
    home.join("blobs")
}

/// Path to the single-instance lock file for a home.
fn lock_path(home: &Path) -> PathBuf {
    home.join("daemon.lock")
}

/// A held single-instance lock for a daemon home. The underlying `flock(2)` is
/// released automatically when this value is dropped or the process exits — even
/// on a crash — so the lock can never go stale.
#[derive(Debug)]
pub struct DaemonLock {
    _file: fs::File,
}

/// Acquire the exclusive single-instance lock for a home, guaranteeing at most
/// one daemon per home. Returns an error if another daemon already holds it,
/// which is how we avoid the startup race that used to spawn duplicate daemons.
pub fn acquire_daemon_lock(home: &Path) -> Result<DaemonLock> {
    use std::os::fd::AsRawFd;
    let path = lock_path(home);
    let file = fs::File::create(&path)
        .with_context(|| format!("create lock file {}", path.display()))?;
    // Exclusive, non-blocking advisory lock held by this open file description.
    // flock(2) is released automatically when the fd closes (process exit or
    // crash), so the lock can never go stale. A second daemon for the same home
    // gets EWOULDBLOCK here and bails instead of clobbering the live one.
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(anyhow!(
            "another groupchat daemon is already running for this home ({})",
            home.display()
        ));
    }
    Ok(DaemonLock { _file: file })
}

#[cfg(test)]
mod tests {
    use super::*;

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

/// A single contact: an endpoint id (the identity/handle) plus a nickname.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contact {
    pub id: String,
    pub nick: String,
}

/// Persisted contact list, keyed by endpoint id string.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Contacts {
    #[serde(default)]
    contacts: BTreeMap<String, Contact>,
}

impl Contacts {
    fn path(home: &Path) -> PathBuf {
        home.join("contacts.json")
    }

    pub fn load(home: &Path) -> Result<Self> {
        let path = Self::path(home);
        if !path.exists() {
            return Ok(Self::default());
        }
        let data = fs::read_to_string(&path).context("read contacts")?;
        Ok(serde_json::from_str(&data).context("parse contacts")?)
    }

    pub fn save(&self, home: &Path) -> Result<()> {
        let data = serde_json::to_string_pretty(self).context("serialize contacts")?;
        fs::write(Self::path(home), data).context("write contacts")?;
        Ok(())
    }

    pub fn add(&mut self, id: EndpointId, nick: String) {
        let id = id.to_string();
        self.contacts.insert(id.clone(), Contact { id, nick });
    }

    pub fn remove(&mut self, id: &EndpointId) -> bool {
        self.contacts.remove(&id.to_string()).is_some()
    }

    /// Remove any contacts that share `nick` but are not `keep` — used to dedupe
    /// when a peer rejoins under the same nick with a fresh identity (e.g. after
    /// a reinstall). Returns the nicks/ids removed.
    pub fn remove_stale_nick(&mut self, nick: &str, keep: &EndpointId) -> Vec<String> {
        let keep = keep.to_string();
        let stale: Vec<String> = self
            .contacts
            .values()
            .filter(|c| c.nick == nick && c.id != keep)
            .map(|c| c.id.clone())
            .collect();
        for id in &stale {
            self.contacts.remove(id);
        }
        stale
    }

    pub fn contains(&self, id: &EndpointId) -> bool {
        self.contacts.contains_key(&id.to_string())
    }

    pub fn nick_of(&self, id: &EndpointId) -> Option<String> {
        self.contacts.get(&id.to_string()).map(|c| c.nick.clone())
    }

    pub fn list(&self) -> Vec<Contact> {
        self.contacts.values().cloned().collect()
    }
}

/// Profile/room settings, persisted to `profile.json`.
#[derive(Debug, Serialize, Deserialize)]
pub struct Profile {
    /// Our display nickname.
    pub nick: String,
    /// The room name we chat in (everyone sharing a name shares a topic).
    pub room: String,
    /// Whether to auto-approve inbound join requests as contacts. Set once you
    /// mint an invite; persisted so a reused ticket keeps working across daemon
    /// restarts.
    #[serde(default)]
    pub auto_approve: bool,
    /// Receiver focus: messages whose effective tier is below this are silenced
    /// (downgraded to ambient) unless they carry notify_anyway. Defaults to
    /// `Ambient`, which mutes nothing.
    #[serde(default)]
    pub mute_below: Tier,
}

impl Default for Profile {
    fn default() -> Self {
        Self {
            nick: whoami_fallback(),
            room: "default".to_string(),
            auto_approve: false,
            mute_below: Tier::Ambient,
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
        Ok(serde_json::from_str(&data).context("parse profile")?)
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
