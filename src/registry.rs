//! Named identity registry + reentry selection.
//!
//! Each agent is a persistent, private identity living in its own home under a
//! base directory (default `~/.groupchat/agents/<name>/`). Separate homes mean
//! separate `secret.key`s, logs, and daemon processes — OS-level isolation, so
//! one agent can't read another.
//!
//! Reentry must answer "which identity is this?" We resolve it **conservatively**
//! (the never-guess invariant): attach automatically ONLY when it's unambiguous
//! (exactly one identity), otherwise the caller must name it (`resume <name>`).
//! A wrong auto-attach would be a cross-identity leak, so we never guess.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Outcome of resolving which identity a session should attach to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// Unambiguous — attach to this identity (0-step).
    Attach(String),
    /// Ambiguous — the caller must pick one of these (1-step `resume <name>`).
    Choose(Vec<String>),
    /// No identities exist yet — first run (create one).
    Empty,
}

/// Resolve which identity to attach to, given the existing identity names and an
/// optional explicit choice. Honors the never-guess invariant: auto-attach only
/// when there is exactly one identity; otherwise require an explicit pick.
pub fn select(mut names: Vec<String>, explicit: Option<&str>) -> Selection {
    names.sort();
    if let Some(name) = explicit {
        return if names.iter().any(|n| n == name) {
            Selection::Attach(name.to_string())
        } else {
            // Named an identity that doesn't exist — make the caller choose from
            // what's actually available (or create it).
            Selection::Choose(names)
        };
    }
    match names.len() {
        0 => Selection::Empty,
        1 => Selection::Attach(names.remove(0)),
        // Multiple identities and no explicit choice → never guess.
        _ => Selection::Choose(names),
    }
}

/// On-disk registry of named identities under a base directory.
pub struct Registry {
    base: PathBuf,
}

impl Registry {
    pub fn new(base: PathBuf) -> Self {
        Self { base }
    }

    /// Names of existing identities — subdirectories that hold a `secret.key`.
    pub fn list(&self) -> Vec<String> {
        let mut out = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.base) {
            for e in entries.flatten() {
                if e.path().join("secret.key").is_file() {
                    if let Some(name) = e.file_name().to_str() {
                        out.push(name.to_string());
                    }
                }
            }
        }
        out.sort();
        out
    }

    /// Home directory for a named identity (created on demand by the caller).
    pub fn home_for(&self, name: &str) -> PathBuf {
        self.base.join(name)
    }

    /// Whether a named identity already exists (has a `secret.key`).
    pub fn exists(&self, name: &str) -> bool {
        self.home_for(name).join("secret.key").is_file()
    }
}

/// Path helper so the binary and tests agree on where the base lives.
pub fn agents_base(root: &Path) -> PathBuf {
    root.join("agents")
}

/// Persistent map from runtime session id -> identity name, so a resumed session
/// (same id) recalls the same identity with zero steps. A best-effort cache; if
/// the runtime gives no session id, callers simply skip it.
#[derive(Default)]
pub struct SessionMap {
    path: PathBuf,
    map: BTreeMap<String, String>,
}

impl SessionMap {
    pub fn load(path: PathBuf) -> Self {
        let map = std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        Self { path, map }
    }

    pub fn get(&self, session_id: &str) -> Option<&str> {
        self.map.get(session_id).map(|s| s.as_str())
    }

    pub fn set(&mut self, session_id: &str, name: &str) -> std::io::Result<()> {
        self.map.insert(session_id.to_string(), name.to_string());
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(
            &self.path,
            serde_json::to_string_pretty(&self.map).unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- select() : the never-guess combo ----

    #[test]
    fn no_identities_is_empty() {
        assert_eq!(select(vec![], None), Selection::Empty);
    }

    #[test]
    fn exactly_one_auto_attaches() {
        assert_eq!(
            select(vec!["solo".into()], None),
            Selection::Attach("solo".into())
        );
    }

    #[test]
    fn multiple_without_choice_must_choose_never_guess() {
        let sel = select(vec!["b".into(), "a".into()], None);
        assert_eq!(sel, Selection::Choose(vec!["a".into(), "b".into()]));
    }

    #[test]
    fn explicit_existing_attaches() {
        assert_eq!(
            select(vec!["a".into(), "b".into()], Some("b")),
            Selection::Attach("b".into())
        );
    }

    #[test]
    fn explicit_unknown_offers_choices() {
        assert_eq!(
            select(vec!["a".into(), "b".into()], Some("zzz")),
            Selection::Choose(vec!["a".into(), "b".into()])
        );
    }

    // ---- Registry : on-disk listing ----

    fn temp_base() -> PathBuf {
        let dir = std::env::temp_dir().join(format!("gc-regtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn make_identity(base: &Path, name: &str) {
        let home = base.join(name);
        std::fs::create_dir_all(&home).unwrap();
        std::fs::write(home.join("secret.key"), b"x").unwrap();
    }

    // ---- SessionMap : persistence ----

    #[test]
    fn session_map_persists_and_recalls() {
        let path = std::env::temp_dir().join(format!("gc-sess-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut m = SessionMap::load(path.clone());
        assert_eq!(m.get("sid-1"), None);
        m.set("sid-1", "backend").unwrap();

        // Reload from disk — the mapping survives (resume recall).
        let m2 = SessionMap::load(path.clone());
        assert_eq!(m2.get("sid-1"), Some("backend"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn registry_lists_only_identities_with_a_key() {
        let base = temp_base();
        make_identity(&base, "backend");
        make_identity(&base, "research");
        // a stray dir without a secret.key must NOT count as an identity
        std::fs::create_dir_all(base.join("not-an-identity")).unwrap();

        let reg = Registry::new(base.clone());
        assert_eq!(
            reg.list(),
            vec!["backend".to_string(), "research".to_string()]
        );
        assert!(reg.exists("backend"));
        assert!(!reg.exists("not-an-identity"));
        assert_eq!(reg.home_for("backend"), base.join("backend"));

        let _ = std::fs::remove_dir_all(&base);
    }
}
