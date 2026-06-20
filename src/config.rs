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
pub fn socket_path(home: &Path) -> PathBuf {
    home.join("control.sock")
}

/// Path to the blob store directory.
pub fn blob_store_path(home: &Path) -> PathBuf {
    home.join("blobs")
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
