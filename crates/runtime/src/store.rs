//! The Orbit's durable on-disk footprint and its exclusive lock.
//!
//! An Orbit lives under `<root>/<space-id>/`. This module owns three of that
//! store's files: the [`replica::StoreMarkerV1`] `marker` (what Space this is,
//! and that it is a Replica store at all), an `epoch` counter durably
//! incremented before each activation, and a `lock` file carrying the OS
//! advisory exclusive lock that is the typed double-lock — only one
//! operational owner at a time. The Fabric journaled store's files (`counter`,
//! `current-manifest`, `objects/`, `journal/`) live alongside these in the
//! same directory; the two touch disjoint names.
//!
//! Technical file/lock terms are correct at this layer — it is below the domain
//! boundary.

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use mechanics::ids::SpaceId;
use replica::marker::{MarkerError, StoreMarkerV1};

use crate::error::LifecycleError;

const MARKER_FILE: &str = "marker";
const EPOCH_FILE: &str = "epoch";
const LOCK_FILE: &str = "lock";

fn io_err(e: std::io::Error) -> LifecycleError {
    LifecycleError::StoreIo(e.to_string())
}

/// A test seam mirroring the Fabric journal's: called with a named fault point
/// *before* the named operation executes; returning `true` makes the operation
/// fail there, modelling a crash or an I/O failure.
pub type StoreFaultInjector = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The named store fault points, in epoch-bump order.
pub const STORE_FAULT_POINTS: [&str; 3] = ["epoch-temp", "epoch-rename", "epoch-dir-sync"];

/// A handle to an Orbit's store directory.
#[derive(Clone)]
pub struct OrbitStore {
    dir: PathBuf,
    space: SpaceId,
    injector: Option<StoreFaultInjector>,
}

impl std::fmt::Debug for OrbitStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OrbitStore")
            .field("dir", &self.dir)
            .field("space", &self.space)
            .finish_non_exhaustive()
    }
}

impl OrbitStore {
    fn dir_for(root: &Path, space: &SpaceId) -> PathBuf {
        root.join(space.as_str())
    }

    /// Form a fresh store for `space`: create the directory, write the marker,
    /// and initialize the epoch counter to zero. Fails if a store already
    /// exists there.
    pub fn create(root: &Path, space: &SpaceId) -> Result<Self, LifecycleError> {
        let dir = Self::dir_for(root, space);
        if dir.join(MARKER_FILE).exists() {
            return Err(LifecycleError::AlreadyExists(space.clone()));
        }
        std::fs::create_dir_all(&dir).map_err(io_err)?;
        let marker = StoreMarkerV1::new(space).ok_or(LifecycleError::IntegrityFailure(
            "space id is not renderable".into(),
        ))?;
        write_sync(&dir.join(MARKER_FILE), &marker.encode())?;
        write_sync(&dir.join(EPOCH_FILE), &0u64.to_le_bytes())?;
        // Make the new directory entries themselves durable — a formation whose
        // directory entries could vanish on power loss must not report success.
        sync_dir(&dir).map_err(io_err)?;
        sync_dir(root).map_err(io_err)?;
        Ok(Self {
            dir,
            space: space.clone(),
            injector: None,
        })
    }

    /// Open an existing store, validating its marker against `space`.
    pub fn open(root: &Path, space: &SpaceId) -> Result<Self, LifecycleError> {
        let dir = Self::dir_for(root, space);
        let marker_bytes = match std::fs::read(dir.join(MARKER_FILE)) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(LifecycleError::OrbitNotFound(space.clone()))
            }
            Err(e) => return Err(io_err(e)),
        };
        let marker = StoreMarkerV1::classify(&marker_bytes).map_err(marker_err)?;
        if marker.space().as_ref() != Some(space) {
            return Err(LifecycleError::IntegrityFailure(
                "store marker names a different Space".into(),
            ));
        }
        Ok(Self {
            dir,
            space: space.clone(),
            injector: None,
        })
    }

    /// Attach a fault injector (test seam; see [`STORE_FAULT_POINTS`]).
    pub fn with_fault_injector(mut self, injector: StoreFaultInjector) -> Self {
        self.injector = Some(injector);
        self
    }

    fn point(&self, name: &str) -> Result<(), LifecycleError> {
        if let Some(injector) = &self.injector {
            if injector(name) {
                return Err(LifecycleError::StoreIo(format!("injected fault at {name}")));
            }
        }
        Ok(())
    }

    pub fn space(&self) -> &SpaceId {
        &self.space
    }

    /// The current durable epoch (zero if never activated).
    pub fn read_epoch(&self) -> Result<u64, LifecycleError> {
        // `create` writes the epoch and every later write is an atomic replace,
        // so a missing or short epoch file is corruption — never "zero". Reading
        // it as zero would reuse committed epochs, which activation must never
        // do; fail closed instead.
        let mut f = match File::open(self.dir.join(EPOCH_FILE)) {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(LifecycleError::IntegrityFailure(
                    "epoch file missing — the store is corrupt; a committed epoch \
                     cannot be safely reused"
                        .into(),
                ))
            }
            Err(e) => return Err(io_err(e)),
        };
        let mut buf = [0u8; 8];
        f.read_exact(&mut buf).map_err(|_| {
            LifecycleError::IntegrityFailure("epoch file truncated — the store is corrupt".into())
        })?;
        Ok(u64::from_le_bytes(buf))
    }

    /// Atomically increment the epoch, returning the new value. The new value is
    /// written to a temp sibling, fsynced, and atomically renamed over the epoch
    /// file — a crash at any point leaves either the complete old or the
    /// complete new value, never a partial one. Every phase **including the
    /// directory synchronization** is fallible and fault-injected: activation
    /// must not report success while durable epoch establishment is unknown,
    /// because Beacon freshness depends on never reusing an epoch a live
    /// Station acted under. A failure aborts activation; the un-acknowledged
    /// epoch was never used, so re-deriving it later is safe.
    pub fn bump_epoch(&self) -> Result<u64, LifecycleError> {
        let next = self
            .read_epoch()?
            .checked_add(1)
            .ok_or(LifecycleError::EpochOverflow)?;
        let tmp = self.dir.join(format!("{EPOCH_FILE}.tmp"));
        self.point("epoch-temp")?;
        write_sync(&tmp, &next.to_le_bytes())?;
        self.point("epoch-rename")?;
        atomic_replace(&tmp, &self.dir.join(EPOCH_FILE)).map_err(io_err)?;
        self.point("epoch-dir-sync")?;
        sync_dir(&self.dir).map_err(io_err)?;
        Ok(next)
    }

    /// Acquire the exclusive store lock (the operational-ownership / double-lock
    /// guard). Returns [`LifecycleError::ReplicaLocked`] if another owner holds
    /// it.
    pub fn acquire_lock(&self) -> Result<StoreLock, LifecycleError> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join(LOCK_FILE))
            .map_err(io_err)?;
        match file.try_lock_exclusive() {
            Ok(()) => Ok(StoreLock { file: Some(file) }),
            Err(_) => Err(LifecycleError::ReplicaLocked(self.space.clone())),
        }
    }

    /// Whether the store is currently locked by some operational owner, tested
    /// non-destructively (advisory; used by observation).
    pub fn is_locked(&self) -> bool {
        match OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(self.dir.join(LOCK_FILE))
        {
            Ok(file) => match file.try_lock_exclusive() {
                Ok(()) => {
                    let _ = FileExt::unlock(&file);
                    false
                }
                Err(_) => true,
            },
            // If we cannot even open the lock file, treat as not lockable-by-us.
            Err(_) => true,
        }
    }

    /// The store directory. The Fabric journaled store (`counter`,
    /// `current-manifest`, `objects/`, `journal/`) lives inside it, alongside
    /// the runtime-owned lifecycle files (`marker`, `epoch`, `lock`) — the two
    /// touch disjoint names.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Destroy the store directory. The caller must hold the lock (i.e. be the
    /// operational owner) so a live Station's store is never removed underneath
    /// it.
    pub fn remove(&self) -> Result<(), LifecycleError> {
        std::fs::remove_dir_all(&self.dir).map_err(io_err)
    }

    /// Every Space with a valid store marker under `root`.
    pub fn list(root: &Path) -> Vec<SpaceId> {
        let mut out = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return out;
        };
        for entry in entries.flatten() {
            if !entry.path().is_dir() {
                continue;
            }
            if let Ok(bytes) = std::fs::read(entry.path().join(MARKER_FILE)) {
                if let Ok(marker) = StoreMarkerV1::classify(&bytes) {
                    if let Some(space) = marker.space() {
                        out.push(space);
                    }
                }
            }
        }
        out.sort();
        out
    }
}

/// The held exclusive lock. Dropping it (or calling [`StoreLock::release`])
/// releases the OS lock — this is how "the lock is released last" is enforced:
/// the Station holds this, and it outlives every tracked task by construction.
#[derive(Debug)]
pub struct StoreLock {
    file: Option<File>,
}

impl StoreLock {
    /// Explicitly release the lock now.
    pub fn release(mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
        }
    }
}

impl Drop for StoreLock {
    fn drop(&mut self) {
        if let Some(file) = self.file.take() {
            let _ = FileExt::unlock(&file);
        }
    }
}

fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), LifecycleError> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(io_err)?;
    f.write_all(bytes).map_err(io_err)?;
    f.sync_all().map_err(io_err)?;
    Ok(())
}

/// Atomically move `tmp` over `dst`, replacing any existing file. `std::fs::
/// rename` replaces on both platforms lait targets (Windows uses `MoveFileExW`
/// with `MOVEFILE_REPLACE_EXISTING`), but on Windows a transient sharing
/// violation (antivirus/indexer holding the destination) can fail a single
/// attempt — retry briefly before giving up.
fn atomic_replace(tmp: &Path, dst: &Path) -> std::io::Result<()> {
    let mut last = None;
    for attempt in 0..5 {
        match std::fs::rename(tmp, dst) {
            Ok(()) => return Ok(()),
            Err(e) => {
                last = Some(e);
                if attempt < 4 {
                    std::thread::sleep(std::time::Duration::from_millis(10 << attempt));
                }
            }
        }
    }
    Err(last.expect("at least one attempt"))
}

/// Directory durability after a rename/create, so the directory entry itself
/// survives a crash. On unix this is a real fsync of the directory, and a
/// failure fails the calling phase. On Windows a directory handle needs
/// `FILE_FLAG_BACKUP_SEMANTICS` to open; if no handle can be opened at all the
/// platform does not expose directory sync and NTFS's metadata journaling is
/// the documented durability contract — but a handle that opens and then fails
/// to flush is a real error and fails the phase. (The same contract as the
/// Fabric journal's directory sync.)
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir).and_then(|d| d.sync_all())
}

#[cfg(windows)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let handle = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .or_else(|_| {
            OpenOptions::new()
                .read(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(dir)
        });
    match handle {
        // No directory handle at all: sync is unsupported here; NTFS metadata
        // journaling is the stated contract (documented, not silent).
        Err(_) => Ok(()),
        Ok(d) => d.sync_all(),
    }
}

fn marker_err(e: MarkerError) -> LifecycleError {
    match e {
        MarkerError::NotAReplicaStore => {
            LifecycleError::IntegrityFailure("not a Replica store".into())
        }
        MarkerError::UnsupportedStoreVersion { found } => {
            LifecycleError::IntegrityFailure(format!("unsupported store version {found}"))
        }
        MarkerError::CorruptStoreMarker => {
            LifecycleError::IntegrityFailure("corrupt store marker".into())
        }
        MarkerError::ReplicaIntegrityFailure => {
            LifecycleError::IntegrityFailure("replica integrity failure".into())
        }
        MarkerError::ReplicaLocked => LifecycleError::IntegrityFailure("replica locked".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_root() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("lait-store-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn an_epoch_fault_at_every_point_aborts_without_acknowledging() {
        // Durable epoch establishment must be all-or-nothing from the caller's
        // view: a fault at ANY bump phase — including the directory sync —
        // fails the bump, and the durable epoch remains readable as either the
        // complete old or the complete new value (never acknowledged-but-lost).
        for &point in STORE_FAULT_POINTS.iter() {
            let root = temp_root();
            let space = SpaceId::from_digest([7u8; 16]);
            let store = OrbitStore::create(&root, &space).unwrap();
            assert_eq!(store.read_epoch().unwrap(), 0);
            let armed = Arc::new(std::sync::atomic::AtomicBool::new(true));
            let armed2 = armed.clone();
            let faulty = store.clone().with_fault_injector(Arc::new(move |name| {
                name == point && armed2.load(Ordering::SeqCst)
            }));
            let err = faulty.bump_epoch().unwrap_err();
            assert!(
                matches!(err, LifecycleError::StoreIo(_)),
                "fault at {point} must abort the bump"
            );
            // The store is intact: the epoch reads as a complete value and the
            // next (un-faulted) bump succeeds and never reuses an acknowledged
            // epoch.
            armed.store(false, Ordering::SeqCst);
            let read = store.read_epoch().unwrap();
            assert!(read == 0 || read == 1, "complete old or complete new");
            let next = store.bump_epoch().unwrap();
            assert!(next > read, "the bump advances past whatever was durable");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn consecutive_epoch_bumps_are_monotone() {
        let root = temp_root();
        let space = SpaceId::from_digest([8u8; 16]);
        let store = OrbitStore::create(&root, &space).unwrap();
        let mut last = 0;
        for _ in 0..10 {
            let next = store.bump_epoch().unwrap();
            assert_eq!(next, last + 1);
            last = next;
        }
        assert_eq!(store.read_epoch().unwrap(), 10);
        let _ = std::fs::remove_dir_all(&root);
    }
}
