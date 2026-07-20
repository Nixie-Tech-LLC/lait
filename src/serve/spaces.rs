//! The space supervisor — identity scoping, and lazy per-space daemon attach.
//!
//! Every Layer-B client before this one spoke to exactly **one** daemon: the
//! control channel is keyed by home ([`crate::control::control_name`]), and a CLI
//! invocation resolves exactly one store. The browser is the first client that is
//! *global to the machine* — a spaces picker means holding several daemons at
//! once — so this module is the piece with no prior art in the codebase.
//!
//! Two invariants shape it.
//!
//! **Never spawn what you were not asked for.** `SpaceDirectory::list` answers the picker by
//! probing (a short-timeout [`Request::Status`] that fails closed to `idle`),
//! never by starting anything: opening the browser must not wake every daemon a
//! user has ever registered. A space's daemon starts only when that space is
//! actually selected — see [`Supervisor::attach`].
//!
//! **Never cross an identity.** See [`scope`], which is the whole story.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use serde::Serialize;
use tokio::sync::{broadcast, Mutex};

use crate::control::{self, Doorbell, Request};
use crate::spaces::{self, SpaceEntry, StorePresence};

/// A doorbell, tagged with the space it rang for.
///
/// The tab holds one `EventSource` over N attached spaces, so the space id is the
/// demultiplexing key. Flattened so the wire shape is a [`Doorbell`] plus one
/// field — the browser re-reads the authoritative projection for each dirty
/// scope according to the shared subscription contract; this is still a dirty *flag*, not
/// state.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceDoorbell {
    pub space: String,
    #[serde(flatten)]
    pub doorbell: Doorbell,
}

/// Whose key a space's daemon signs with.
///
/// Carried on every row because it is not cosmetic: it decides which
/// `secret.key` [`Supervisor::attach`] must pin, and — once writes exist — whose
/// name a mutation lands under. The browser shows both kinds side by side, so the
/// distinction has to be in the data, not in a convention about paths.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SpaceIdentity {
    /// The identity `lait serve` itself runs as.
    Own,
    /// A named agent's self-contained home: visible for observability, but its
    /// daemon runs on the agent's key, not yours.
    Agent { name: String },
}

/// One row of the spaces picker.
#[derive(Debug, Clone, Serialize)]
pub struct SpaceRow {
    /// Stable, opaque handle for URLs — see [`store_handle`].
    pub id: String,
    /// The `ws_…` space id.
    pub space: String,
    /// Display name at last open (advisory — the catalog is authoritative).
    pub name: String,
    pub path: String,
    pub origin: String,
    pub last_opened: u64,
    /// `up` | `idle` | `missing`, exactly as `lait spaces` reports it.
    pub status: &'static str,
    pub identity: SpaceIdentity,
    pub projects: Vec<spaces::ProjectBrief>,
}

/// A registry entry, plus whose identity it runs under.
#[derive(Debug, Clone)]
pub struct Scoped<'a> {
    pub entry: &'a SpaceEntry,
    pub identity: SpaceIdentity,
}

/// A stable public id for a store path.
///
/// Derived rather than borrowed: the `ws_` id is not unique per *store* (the same
/// space can legitimately be bound at two paths), and the store path itself
/// is both unwieldy and a filesystem disclosure in a URL. blake3 is already in
/// the tree, and unlike [`crate::config::home_hash`] — whose `DefaultHasher` is
/// explicitly not stable across Rust releases, which is fine for the socket name
/// it exists for — this stays put across builds, so a bookmarked space URL keeps
/// resolving.
pub fn store_handle(path: &str) -> String {
    let hash = blake3::hash(path.as_bytes());
    hash.to_hex()[..16].to_string()
}

/// Which registered spaces this identity may see, and whose key each runs on.
///
/// **This function is the identity seam.** It depends on a fact that is easy to
/// invert: in lait, identity is *global by default*.
/// [`crate::config::identity_dir`] puts `secret.key` under the config root and
/// one key spans every repo-bound store — "like one `git` `user.email` across
/// many repos" — so N ordinary spaces are N daemons signing with the *same*
/// identity. Listing them side by side crosses nothing.
///
/// The exception is a **self-contained home**: `$LAIT_HOME` collapses identity
/// and store into one directory, giving that home its own `secret.key`. Named
/// agents are exactly that shape, living under [`crate::registry::agents_base`],
/// and [`crate::registry`] isolates them so one agent cannot read another.
///
/// `spaces.json` is a single global file that every daemon open upserts into
/// (`node.rs`), so it holds both kinds. The policy is deliberately **asymmetric**,
/// and the asymmetry is the point:
///
/// - a **global** identity (you) sees its own stores **and every agent's**, each
///   tagged [`SpaceIdentity::Agent`]. Agents are yours; watching them is the
///   reason to have a browser at all, and the registry it reads carries no
///   secrets — it is navigation state.
/// - a **self-contained** identity sees exactly its own home. An agent must not
///   enumerate your spaces or its siblings; that is what `registry`'s isolation
///   is for, and observability runs downward only.
///
/// The tag is load-bearing rather than decorative. Seeing an agent's space is
/// safe; *acting as* it is a different grant, and the tag is what lets the layers
/// above tell those apart — [`Supervisor::attach`] uses it to pin the right
/// `secret.key`, and a future write path must use it to refuse (or attribute)
/// mutations that would land under an agent's name instead of yours.
///
/// SEAM: an identity switcher changes only the caller — it picks a different
/// `(identity, self_contained)` pair and calls this again. Scoping is decided
/// here and nowhere else, so the switcher never threads through the router, the
/// supervisor, or the endpoints.
pub fn scope<'a>(
    entries: &'a [SpaceEntry],
    identity: &Path,
    agents_base: &Path,
    self_contained: bool,
) -> Vec<Scoped<'a>> {
    entries
        .iter()
        .filter_map(|entry| {
            let path = Path::new(&entry.path);
            if self_contained {
                // $LAIT_HOME: this identity is its own store and sees only itself.
                same_path(path, identity).then_some(Scoped {
                    entry,
                    identity: SpaceIdentity::Own,
                })
            } else if let Some(name) = agent_name(path, agents_base) {
                Some(Scoped {
                    entry,
                    identity: SpaceIdentity::Agent { name },
                })
            } else {
                Some(Scoped {
                    entry,
                    identity: SpaceIdentity::Own,
                })
            }
        })
        .collect()
}

/// The agent name for a home under `agents_base`, or `None` if it isn't one.
///
/// Agent homes are `agents_base/<name>` ([`crate::registry`]), so the name is the
/// first component below the base. Anything deeper still belongs to *that* agent,
/// so take the first component rather than the file name — a nested path must not
/// be able to present itself as a different agent.
///
/// The name is read off the **original** path, not the normalized one: `normalize`
/// lower-cases on Windows to make comparison case-insensitive, which is right for
/// deciding *whether* a path is under the base and wrong for the name we then
/// show a human.
fn agent_name(path: &Path, agents_base: &Path) -> Option<String> {
    if !under(path, agents_base) {
        return None;
    }
    path.components()
        .nth(agents_base.components().count())
        .map(|c| c.as_os_str().to_string_lossy().to_string())
}

/// Path equality that survives the shapes these strings actually arrive in.
///
/// Registry paths are written by several call sites and compared against a value
/// derived from the environment, so they can differ in separator and — on
/// Windows, where the filesystem is case-insensitive — in case, while naming the
/// same directory. A false negative here would hide a user's own space from the
/// picker; a false positive cannot cross an identity, because `agents_base` is a
/// distinct subtree either way.
fn same_path(a: &Path, b: &Path) -> bool {
    normalize(a) == normalize(b)
}

fn under(path: &Path, base: &Path) -> bool {
    let (path, base) = (normalize(path), normalize(base));
    Path::new(&path).starts_with(Path::new(&base))
}

fn normalize(p: &Path) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    let s = s.trim_end_matches('/').to_string();
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s
    }
}

/// Probe a store's daemon without starting one.
///
/// Mirrors `cli::space_status` — deliberately, so the browser and `lait
/// spaces` cannot disagree about what "up" means. The short timeout fails closed
/// to `idle`: a picker that hangs on a wedged daemon is worse than one that
/// under-reports it, and selecting the space will start it anyway.
async fn status(entry: &SpaceEntry) -> &'static str {
    if spaces::presence(entry) == StorePresence::Missing {
        return "missing";
    }
    let up = tokio::time::timeout(
        Duration::from_millis(300),
        control::request(Path::new(&entry.path), &Request::Status),
    )
    .await
    .map(|r| r.is_ok())
    .unwrap_or(false);
    if up {
        "up"
    } else {
        "idle"
    }
}

/// A live attachment to one space's daemon: the task pumping its doorbells into
/// the shared fan-in. Dropping it aborts the pump.
struct Attached {
    home: PathBuf,
    /// Cleared by the pump before it announces its own death.
    ///
    /// Set explicitly rather than inferred from the `JoinHandle`, because the pump
    /// has to send its farewell `reset` *before* it returns — so at the moment the
    /// client reacts to that reset, `is_finished()` is still false and we would
    /// hand back the very attachment we are trying to replace. `is_finished` is
    /// still checked as well: a panicking task never reaches the store.
    alive: Arc<AtomicBool>,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for Attached {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// Holds the N daemons the browser is currently looking at.
pub struct Supervisor {
    identity: PathBuf,
    agents_base: PathBuf,
    self_contained: bool,
    attached: Mutex<HashMap<String, Arc<Attached>>>,
    doorbells: broadcast::Sender<SpaceDoorbell>,
}

impl Supervisor {
    pub fn new(identity: PathBuf, agents_base: PathBuf, self_contained: bool) -> Self {
        // Bounded: a lagging tab must not let the daemon's dirty-set pin memory.
        // A dropped frame is recoverable by construction — the receiver sees
        // `Lagged`, and the contract for that is the same `reset` rebaseline the
        // Every subscription consumer rebaselines after an epoch change.
        let (doorbells, _) = broadcast::channel(256);
        Self {
            identity,
            agents_base,
            self_contained,
            attached: Mutex::new(HashMap::new()),
            doorbells,
        }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<SpaceDoorbell> {
        self.doorbells.subscribe()
    }

    /// The spaces this identity owns, newest-first, each with a probed status.
    ///
    /// Probes run concurrently: sequential 300ms timeouts would make the picker's
    /// latency the *sum* of every idle space, which is exactly the case a user
    /// with a dozen registered spaces hits.
    pub async fn list(&self) -> Vec<SpaceRow> {
        let entries = spaces::list();
        let scoped = scope(
            &entries,
            &self.identity,
            &self.agents_base,
            self.self_contained,
        );
        let mut set = tokio::task::JoinSet::new();
        for s in scoped {
            let e = s.entry.clone();
            let identity = s.identity.clone();
            set.spawn(async move {
                SpaceRow {
                    id: store_handle(&e.path),
                    space: e.space.clone(),
                    name: e.name.clone(),
                    path: e.path.clone(),
                    origin: e.origin.to_string(),
                    last_opened: e.last_opened,
                    status: status(&e).await,
                    identity,
                    projects: e.projects.clone(),
                }
            });
        }
        let mut rows = set.join_all().await;
        // `JoinSet` yields in completion order, so restore the registry's own
        // newest-first ordering rather than letting probe latency decide it.
        rows.sort_by_key(|r| std::cmp::Reverse(r.last_opened));
        rows
    }

    /// Resolve a public space id to its home and the identity it runs under.
    ///
    /// Resolution goes through [`scope`], so a space this identity may not see is
    /// indistinguishable from one that does not exist — an agent-scoped `serve`
    /// cannot address your spaces by guessing an id.
    pub fn resolve(&self, id: &str) -> Result<(PathBuf, SpaceIdentity)> {
        let entries = spaces::list();
        let scoped = scope(
            &entries,
            &self.identity,
            &self.agents_base,
            self.self_contained,
        );
        scoped
            .into_iter()
            .find(|s| store_handle(&s.entry.path) == id)
            .map(|s| (PathBuf::from(&s.entry.path), s.identity))
            .ok_or_else(|| anyhow!("no such space"))
    }

    /// Ensure this space's daemon is up and its doorbells are flowing.
    ///
    /// Idempotent, and the *only* place a daemon is started: attaching is what
    /// selecting a space means. Returns the home so callers can round-trip it.
    ///
    /// Two things worth knowing before calling this on an agent's space.
    ///
    /// **The identity must be pinned, not inherited.** `identity_dir` reads
    /// `$LAIT_HOME` and never `$LAIT_STORE`, so spawning a daemon at an agent's
    /// store from a globally-scoped `serve` would open it under *your* key —
    /// which cannot unwrap a space key sealed to the agent, and would put
    /// your identity on the wire in the agent's space. Hence
    /// [`crate::cli::ensure_daemon_as`] and the explicit home below.
    ///
    /// **Attaching is not free the way listing is.** [`list`](Self::list) only
    /// probes, so enumerating agents has no effect on anything. Starting a
    /// daemon brings that identity *online* — it binds an endpoint and announces
    /// presence — so watching an idle agent is what makes it visible to its
    /// space. That is usually what you want when you went looking for it, but
    /// it is a real consequence of a click, not a read.
    pub async fn attach(&self, id: &str) -> Result<PathBuf> {
        let (home, identity) = self.resolve(id)?;
        // The fast path, and only the fast path, under the lock. Spawning a daemon
        // can take seconds, and `attached` is global to every space — holding it
        // across that await would make the first attach of one slow space stall
        // RPCs to every other, which is precisely the scenario a supervisor exists
        // to avoid.
        {
            let mut attached = self.attached.lock().await;
            if let Some(a) = attached.get(id) {
                // A live attachment is reusable; a dead one is a trap. When the
                // space's daemon stops its pump ends — and if the entry outlives
                // it, every later attach short-circuits onto a corpse and the
                // doorbells for that space never come back. The failure is silent,
                // which is the worst part: the browser's own stream to `serve` is
                // still open, so the UI reports itself live while going quietly
                // stale forever.
                if a.alive.load(Ordering::Acquire) && !a.pump.is_finished() {
                    return Ok(a.home.clone());
                }
                attached.remove(id);
                // The daemon this pump was reading is gone, so `ensure_daemon`'s
                // verified-memo is now a lie — and a stale entry there does not
                // mean "already fine", it means "never respawn this". Clear it, or
                // the re-attach below short-circuits and we connect to nothing.
                crate::cli::forget_verified(&home);
            }
        }

        // A self-contained home *is* its own identity dir, so pinning it to
        // `home` is the whole fix. `Own` keeps inheriting our env, which is
        // already correct for every store the global identity signs for.
        let pin = match identity {
            SpaceIdentity::Agent { .. } => Some(home.as_path()),
            SpaceIdentity::Own => None,
        };
        // Unlocked: idempotent, so two callers racing the same space simply both
        // find it healthy.
        crate::cli::ensure_daemon_as(&home, pin).await?;

        // Re-acquire to publish. Another caller may have attached this space while
        // we were unlocked — `ensure_daemon_as` is idempotent, so they both found
        // it healthy and we simply take theirs. Checked *before* spawning a pump,
        // so the loser never creates one: a dropped `JoinHandle` detaches rather
        // than aborts, and a stray pump would quietly double every doorbell.
        let mut attached = self.attached.lock().await;
        if let Some(a) = attached.get(id) {
            if a.alive.load(Ordering::Acquire) && !a.pump.is_finished() {
                return Ok(a.home.clone());
            }
            attached.remove(id);
        }

        let tx = self.doorbells.clone();
        let space = id.to_string();
        let pump_home = home.clone();
        let alive = Arc::new(AtomicBool::new(true));
        let pump_alive = alive.clone();
        // `tokio::spawn` doesn't await, so the lock is held only long enough to
        // publish the entry.
        let pump = tokio::spawn(async move {
            // `since: 0` asks for a full rebaseline, matching a fresh attach.
            match control::subscribe(&pump_home, 0).await {
                Ok(mut sub) => loop {
                    match sub.next().await {
                        Ok(Some(doorbell)) => {
                            // Err only means "nobody listening" — the tab is
                            // closed. Keep pumping: it may come back, and the
                            // daemon is up regardless of whether anyone watches.
                            let _ = tx.send(SpaceDoorbell {
                                space: space.clone(),
                                doorbell,
                            });
                        }
                        // EOF: the daemon stopped. We do not reconnect here — the
                        // restart policy lives in `ensure_daemon`, which owns the
                        // heal path, and `attach` re-runs it once it notices this
                        // pump died.
                        Ok(None) => break,
                        Err(e) => {
                            tracing::warn!(space = %space, error = %e, "doorbell stream ended");
                            break;
                        }
                    }
                },
                Err(e) => tracing::warn!(space = %space, error = %e, "subscribe failed"),
            }

            // **One** exit, deliberately. A stream that never opened and one that
            // ended later leave the client in the same place — holding a view of a
            // space nothing is backing — so they get the same farewell. This used
            // to be two paths, and the never-opened one skipped the announcement
            // below: it still healed, but only when something happened to ask,
            // which is the exact asymmetry the announcement exists to remove.
            pump_alive.store(false, Ordering::Release);

            // Say so on the way out, or the repair deadlocks: `attach` only
            // notices a dead pump when something asks it to attach, and the thing
            // that would ask is a re-read triggered by a doorbell that is never
            // coming. A `reset` is precisely "your position is invalid, rebaseline
            // from a fresh snapshot, so the client re-reads while the
            // re-read attaches, and attaching revives the stream. The loop closes
            // itself without this task knowing anything about repair.
            let _ = tx.send(SpaceDoorbell {
                space,
                doorbell: Doorbell {
                    reset: true,
                    ..Default::default()
                },
            });
        });

        attached.insert(
            id.to_string(),
            Arc::new(Attached {
                home: home.clone(),
                alive,
                pump,
            }),
        );
        Ok(home)
    }

    /// Round-trip a request to a space's daemon, attaching it first if needed.
    pub async fn request(&self, id: &str, req: &Request) -> Result<control::Response> {
        let home = self.attach(id).await?;
        control::request(&home, req).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(path: &str) -> SpaceEntry {
        SpaceEntry {
            space: "ws_test".into(),
            name: "Test".into(),
            path: path.into(),
            origin: spaces::Origin::Founded,
            host_nick: String::new(),
            last_opened: 0,
            projects: Vec::new(),
        }
    }

    fn paths<'a>(scoped: &[Scoped<'a>]) -> Vec<&'a str> {
        scoped.iter().map(|s| s.entry.path.as_str()).collect()
    }

    #[test]
    fn global_identity_sees_its_own_stores_and_every_agent_tagged() {
        // Observability runs downward: your agents are yours, and watching them is
        // the reason to have a browser. But the tag has to survive the trip — it
        // decides which secret.key `attach` pins, so an untagged agent row would
        // open the agent's store under the human's key.
        let entries = vec![
            entry("/home/u/proj-a/.lait"),
            entry("/home/u/.config/lait/agents/scout"),
            entry("/home/u/proj-b/.lait"),
        ];
        let scoped = scope(
            &entries,
            Path::new("/home/u/.config/lait"),
            Path::new("/home/u/.config/lait/agents"),
            false,
        );
        assert_eq!(
            paths(&scoped),
            vec![
                "/home/u/proj-a/.lait",
                "/home/u/.config/lait/agents/scout",
                "/home/u/proj-b/.lait"
            ]
        );
        assert_eq!(scoped[0].identity, SpaceIdentity::Own);
        assert_eq!(
            scoped[1].identity,
            SpaceIdentity::Agent {
                name: "scout".into()
            }
        );
        assert_eq!(scoped[2].identity, SpaceIdentity::Own);
    }

    #[test]
    fn an_agent_sees_only_itself_never_the_human_or_a_sibling() {
        // The asymmetry: the human sees agents, but an agent-scoped serve must not
        // enumerate the human's spaces or another agent's — that is exactly what
        // `registry`'s per-home isolation exists to protect.
        let entries = vec![
            entry("/home/u/proj-a/.lait"),
            entry("/home/u/.config/lait/agents/scout"),
            entry("/home/u/.config/lait/agents/other"),
        ];
        let scoped = scope(
            &entries,
            Path::new("/home/u/.config/lait/agents/scout"),
            Path::new("/home/u/.config/lait/agents"),
            true,
        );
        assert_eq!(paths(&scoped), vec!["/home/u/.config/lait/agents/scout"]);
        // From its own vantage point an agent is simply itself, not "an agent".
        assert_eq!(scoped[0].identity, SpaceIdentity::Own);
    }

    #[test]
    fn agent_name_is_the_component_below_the_base_not_the_leaf() {
        // A nested path still belongs to the agent that owns the subtree; taking
        // the file name would let `agents/scout/sub` present itself as "sub".
        let entries = vec![entry("/home/u/.config/lait/agents/scout/nested/store")];
        let scoped = scope(
            &entries,
            Path::new("/home/u/.config/lait"),
            Path::new("/home/u/.config/lait/agents"),
            false,
        );
        assert_eq!(
            scoped[0].identity,
            SpaceIdentity::Agent {
                name: "scout".into()
            }
        );
    }

    #[test]
    fn agent_name_keeps_its_case_even_where_paths_compare_case_insensitively() {
        // `normalize` lower-cases on Windows so the *comparison* tolerates drift;
        // the displayed name must not inherit that.
        let entries = vec![entry("/home/u/.config/lait/agents/Scout")];
        let scoped = scope(
            &entries,
            Path::new("/home/u/.config/lait"),
            Path::new("/home/u/.config/lait/agents"),
            false,
        );
        assert_eq!(
            scoped[0].identity,
            SpaceIdentity::Agent {
                name: "Scout".into()
            }
        );
    }

    #[test]
    fn scoping_is_not_fooled_by_separator_or_case_drift() {
        // Registry paths are written by several call sites; on Windows the same
        // directory can arrive spelled differently. A false negative would hide a
        // user's own space, so normalize before comparing.
        let entries = vec![entry(r"C:\Users\U\proj\.lait")];
        let scoped = scope(
            &entries,
            Path::new("C:/users/u/proj/.lait"),
            Path::new("C:/users/u/AppData/lait/agents"),
            true,
        );
        if cfg!(windows) {
            assert_eq!(scoped.len(), 1, "same dir, different spelling");
        }
        // A path that merely *starts with the same text* as agents_base is not
        // under it, and must not be mistaken for an agent — misclassifying it
        // would pin `LAIT_HOME` at a store that has no `secret.key` of its own.
        let entries = vec![entry("/home/u/.config/lait/agents-notreally/x")];
        let scoped = scope(
            &entries,
            Path::new("/home/u/.config/lait"),
            Path::new("/home/u/.config/lait/agents"),
            false,
        );
        assert_eq!(scoped.len(), 1);
        assert_eq!(
            scoped[0].identity,
            SpaceIdentity::Own,
            "'agents-notreally' is not under 'agents'"
        );
    }

    #[test]
    fn store_handles_are_stable_and_path_distinct() {
        assert_eq!(
            store_handle("/home/u/a/.lait"),
            store_handle("/home/u/a/.lait")
        );
        assert_ne!(
            store_handle("/home/u/a/.lait"),
            store_handle("/home/u/b/.lait")
        );
        assert_eq!(store_handle("/home/u/a/.lait").len(), 16);
    }
}
