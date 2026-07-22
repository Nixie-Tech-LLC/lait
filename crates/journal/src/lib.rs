//! The journaled durable store — the semantics-free on-disk commit protocol.
//!
//! This crate knows only immutable content-addressed objects, object
//! references, an atomically swapped manifest with opaque caller metadata,
//! fsync/directory-sync discipline, fault injection, and recovery. It knows
//! nothing about Bodies, authority, Worlds, or any product — both the Fabric
//! Body store and the mechanics authority ledger commit through it.
//!
//! Layout, under one store root (which may also hold caller-owned lifecycle
//! files — this crate touches only its own names):
//!
//! ```text
//! counter            // the local transaction counter (reserved + fsynced first)
//! current-manifest   // postcard StoreManifest, atomically replaced
//! objects/<hex64>    // immutable content-addressed objects
//! journal/active     // the active journal record, atomically replaced
//! ```
//!
//! A commit executes the normative sequence:
//!
//! 1. reserve the local transaction counter and fsync it (gaps after failure
//!    are allowed; **reuse is forbidden**);
//! 2. write/fsync journal `Prepared { new objects, new manifest hash }`;
//! 3. write/fsync all temporary objects;
//! 4. write/fsync `MaterialReady`, rename the immutable objects to their final
//!    paths, and fsync their directory;
//! 5. write/fsync the new manifest temp, rename it over `current-manifest`
//!    **last**, and fsync the store directory;
//! 6. write/fsync journal `Committed`, return, then remove the journal and
//!    fsync its directory.
//!
//! Recovery on open exposes **the complete old or the complete new** state:
//! `Prepared`/`MaterialReady` found with the old manifest removes the safe
//! orphan temps/objects and exposes the old state; `MaterialReady` found with
//! the new manifest verifies it completely and finalizes it as committed. A
//! manifest naming absent or corrupt objects is an integrity failure — never
//! repaired heuristically. Unreferenced objects are garbage-collected only
//! after recovery, when no journal is active.
//!
//! Every write/fsync/rename boundary carries a named fault-injection point so
//! the crash matrix is testable; see [`JournaledStore::with_fault_injector`].

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

const COUNTER_FILE: &str = "counter";
const MANIFEST_FILE: &str = "current-manifest";
const OBJECTS_DIR: &str = "objects";
const JOURNAL_DIR: &str = "journal";
const JOURNAL_FILE: &str = "active";

/// Domain for an object's content address.
const OBJECT_DOMAIN: &[u8] = b"lait/store-object/1";
/// Domain for a manifest's identity hash (referenced by the journal).
const MANIFEST_DOMAIN: &[u8] = b"lait/store-manifest/1";

/// Why a journal operation failed. The taxonomy is deliberately small: a
/// durable-write failure (retry may help after the cause clears), an integrity
/// failure (never repaired heuristically), and the one genuinely ambiguous
/// post-switch outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JournalError {
    /// A durable write (open/write/fsync/rename) failed before the
    /// authoritative manifest switch. The old state is still exposed.
    Durability(String),
    /// The store failed integrity validation (a manifest naming absent or
    /// corrupt objects, a corrupt journal, a missing transaction counter).
    Integrity(String),
    /// The authoritative switch happened but its durability confirmation
    /// failed: the commit may or may not survive power loss. Fail stop and
    /// reopen — recovery resolves the outcome deterministically from the
    /// on-disk manifest. Never retry through this error.
    OutcomeUnknown,
}

impl std::fmt::Display for JournalError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JournalError::Durability(m) => write!(f, "durability: {m}"),
            JournalError::Integrity(m) => write!(f, "integrity: {m}"),
            JournalError::OutcomeUnknown => write!(f, "outcome unknown"),
        }
    }
}
impl std::error::Error for JournalError {}

/// One immutable object reference: content address and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    pub hash: [u8; 32],
    pub len: u64,
}

/// The store's manifest: the current object set plus opaque caller metadata
/// (the caller stores its semantic index there — the journal does not
/// interpret it). The encoded `version` field is the store-format version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreManifest {
    pub version: u8,
    pub sequence: u64,
    pub objects: Vec<ObjectRef>,
    pub meta: Vec<u8>,
}

/// The journal phases. Each replaces `journal/active` atomically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum JournalRecord {
    Prepared {
        sequence: u64,
        new_objects: Vec<ObjectRef>,
        new_manifest_hash: [u8; 32],
    },
    MaterialReady {
        sequence: u64,
        new_objects: Vec<ObjectRef>,
        new_manifest_hash: [u8; 32],
    },
    Committed {
        sequence: u64,
        new_manifest_hash: [u8; 32],
    },
}

/// A test seam: called with a named crash point *before* the named operation
/// executes; returning `true` makes the commit fail there, modelling a crash.
pub type FaultInjector = Box<dyn Fn(&str) -> bool + Send>;

/// The named fault points, in commit order (each fires before its operation).
pub const FAULT_POINTS: [&str; 9] = [
    "counter",
    "journal-prepared",
    "objects",
    "journal-material-ready",
    "rename-objects",
    "manifest-temp",
    "manifest-rename",
    "journal-committed",
    "journal-remove",
];

/// The journaled store engine.
pub struct JournaledStore {
    root: PathBuf,
    manifest: Option<StoreManifest>,
    injector: Option<FaultInjector>,
}

// The injector closure is not `Debug`; show the root + current manifest.
impl std::fmt::Debug for JournaledStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JournaledStore")
            .field("root", &self.root)
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

fn object_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(OBJECT_DOMAIN);
    h.update(bytes);
    *h.finalize().as_bytes()
}

/// The content address the store gives a byte object — public so a caller can
/// predict the [`ObjectRef`] of material it hands to [`JournaledStore::commit`]
/// (e.g. a caller's meta index referencing the objects of the same commit).
pub fn object_content_hash(bytes: &[u8]) -> [u8; 32] {
    object_hash(bytes)
}

fn manifest_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MANIFEST_DOMAIN);
    h.update(bytes);
    *h.finalize().as_bytes()
}

fn hex(hash: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(hash)
}

fn io_err(what: &str, e: std::io::Error) -> JournalError {
    JournalError::Durability(format!("{what}: {e}"))
}

fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), JournalError> {
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|e| io_err("open for write", e))?;
    f.write_all(bytes).map_err(|e| io_err("write", e))?;
    f.sync_all().map_err(|e| io_err("fsync", e))?;
    Ok(())
}

/// Atomic replace with a brief retry for Windows sharing violations.
fn atomic_replace(tmp: &Path, dst: &Path) -> Result<(), JournalError> {
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
    Err(io_err("rename", last.expect("at least one attempt")))
}

/// Directory durability after a rename/create. On unix this is a real fsync of
/// the directory, and a failure fails the calling phase. On Windows, a
/// directory handle needs `FILE_FLAG_BACKUP_SEMANTICS` to open; if no handle
/// can be opened at all the platform does not expose directory sync to us and
/// NTFS's metadata journaling is the documented durability contract — but a
/// handle that opens and then fails to flush is a real error and fails the
/// phase.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), JournalError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| io_err("fsync dir", e))
}

#[cfg(windows)]
fn sync_dir(dir: &Path) -> Result<(), JournalError> {
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
        Ok(d) => d.sync_all().map_err(|e| io_err("flush dir", e)),
    }
}

impl JournaledStore {
    /// Open a store root, running crash recovery, and return the store plus its
    /// current manifest (`None` for a fresh store). The exposed state is always
    /// the complete old or complete new one.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, JournalError> {
        let root = root.into();
        std::fs::create_dir_all(root.join(OBJECTS_DIR)).map_err(|e| io_err("objects dir", e))?;
        std::fs::create_dir_all(root.join(JOURNAL_DIR)).map_err(|e| io_err("journal dir", e))?;
        let mut store = Self {
            root,
            manifest: None,
            injector: None,
        };
        store.recover()?;
        Ok(store)
    }

    /// Attach a fault injector (test seam; see [`FAULT_POINTS`]).
    pub fn with_fault_injector(mut self, injector: FaultInjector) -> Self {
        self.injector = Some(injector);
        self
    }

    /// Attach a fault injector by reference (test seam for callers embedding
    /// the store; see [`FAULT_POINTS`]).
    pub fn set_fault_injector(&mut self, injector: FaultInjector) {
        self.injector = Some(injector);
    }

    /// The current manifest, if any commit has completed.
    pub fn manifest(&self) -> Option<&StoreManifest> {
        self.manifest.as_ref()
    }

    /// Read an immutable object, verifying its content address.
    pub fn read_object(&self, obj: &ObjectRef) -> Result<Vec<u8>, JournalError> {
        let path = self.object_path(&obj.hash);
        let bytes = std::fs::read(&path).map_err(|e| {
            JournalError::Integrity(format!("object {} unreadable: {e}", hex(&obj.hash)))
        })?;
        if bytes.len() as u64 != obj.len || object_hash(&bytes) != obj.hash {
            return Err(JournalError::Integrity(format!(
                "object {} fails its content address",
                hex(&obj.hash)
            )));
        }
        Ok(bytes)
    }

    fn object_path(&self, hash: &[u8; 32]) -> PathBuf {
        self.root.join(OBJECTS_DIR).join(hex(hash))
    }

    fn journal_path(&self) -> PathBuf {
        self.root.join(JOURNAL_DIR).join(JOURNAL_FILE)
    }

    fn point(&self, name: &str) -> Result<(), JournalError> {
        if let Some(injector) = &self.injector {
            if injector(name) {
                return Err(JournalError::Durability(format!(
                    "injected crash at {name}"
                )));
            }
        }
        Ok(())
    }

    fn write_journal(&self, record: &JournalRecord) -> Result<(), JournalError> {
        let bytes = postcard::to_stdvec(record)
            .map_err(|e| JournalError::Durability(format!("encode journal: {e}")))?;
        let dir = self.root.join(JOURNAL_DIR);
        let tmp = dir.join("active.tmp");
        write_sync(&tmp, &bytes)?;
        atomic_replace(&tmp, &self.journal_path())?;
        sync_dir(&dir)?;
        Ok(())
    }

    fn read_journal(&self) -> Result<Option<JournalRecord>, JournalError> {
        match std::fs::read(self.journal_path()) {
            Ok(bytes) => postcard::from_bytes(&bytes)
                .map(Some)
                // An unreadable journal record is corruption we do not repair
                // heuristically.
                .map_err(|e| JournalError::Integrity(format!("journal corrupt: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("read journal", e)),
        }
    }

    fn remove_journal(&self) -> Result<(), JournalError> {
        match std::fs::remove_file(self.journal_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err("remove journal", e)),
        }
        // Cleanup only: a lost removal is re-resolved by recovery.
        let _ = sync_dir(&self.root.join(JOURNAL_DIR));
        Ok(())
    }

    fn read_manifest_file(&self) -> Result<Option<(StoreManifest, [u8; 32])>, JournalError> {
        match std::fs::read(self.root.join(MANIFEST_FILE)) {
            Ok(bytes) => {
                let manifest: StoreManifest = postcard::from_bytes(&bytes)
                    .map_err(|e| JournalError::Integrity(format!("manifest corrupt: {e}")))?;
                if manifest.version != 1 {
                    return Err(JournalError::Integrity(format!(
                        "unsupported store manifest version {}",
                        manifest.version
                    )));
                }
                Ok(Some((manifest, manifest_hash(&bytes))))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("read manifest", e)),
        }
    }

    fn read_counter(&self) -> Result<u64, JournalError> {
        match File::open(self.root.join(COUNTER_FILE)) {
            Ok(mut f) => {
                let mut buf = [0u8; 8];
                f.read_exact(&mut buf)
                    .map_err(|_| JournalError::Integrity("transaction counter truncated".into()))?;
                Ok(u64::from_le_bytes(buf))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A fresh store has no counter — but a store with a manifest
                // and no counter could reuse sequences: fail closed.
                if self.root.join(MANIFEST_FILE).exists() {
                    return Err(JournalError::Integrity(
                        "transaction counter missing from a committed store".into(),
                    ));
                }
                Ok(0)
            }
            Err(e) => Err(io_err("read counter", e)),
        }
    }

    fn reserve_sequence(&self) -> Result<u64, JournalError> {
        let next = self
            .read_counter()?
            .checked_add(1)
            .ok_or_else(|| JournalError::Integrity("transaction counter overflow".into()))?;
        let tmp = self.root.join(format!("{COUNTER_FILE}.tmp"));
        write_sync(&tmp, &next.to_le_bytes())?;
        atomic_replace(&tmp, &self.root.join(COUNTER_FILE))?;
        sync_dir(&self.root)?;
        Ok(next)
    }

    /// Crash recovery, then integrity verification, then orphan GC.
    fn recover(&mut self) -> Result<(), JournalError> {
        match self.read_journal()? {
            None => {}
            Some(JournalRecord::Committed { .. }) => {
                // The commit fully landed; only the journal removal was lost.
                self.remove_journal()?;
            }
            Some(JournalRecord::Prepared { .. }) => {
                // Nothing was renamed yet: the old manifest is authoritative.
                // Orphan temps/objects are collected below.
                self.remove_journal()?;
            }
            Some(JournalRecord::MaterialReady {
                new_manifest_hash, ..
            }) => {
                let current = self.read_manifest_file()?;
                match current {
                    Some((_, hash)) if hash == new_manifest_hash => {
                        // The manifest swap completed: the new state must
                        // verify completely, then it is finalized as committed.
                        // (Verification happens below; a failure is an
                        // integrity error, not a heuristic repair.)
                        self.remove_journal()?;
                    }
                    _ => {
                        // The old manifest is still current: expose the old
                        // state; renamed-but-unreferenced objects are orphans.
                        self.remove_journal()?;
                    }
                }
            }
        }

        // Verify the exposed manifest completely, including the counter: a
        // committed store whose counter is missing or behind its manifest
        // sequence could reuse a sequence — fail closed.
        if let Some((manifest, _)) = self.read_manifest_file()? {
            for obj in &manifest.objects {
                self.read_object(obj)?;
            }
            let counter = self.read_counter()?;
            if counter < manifest.sequence {
                return Err(JournalError::Integrity(
                    "transaction counter behind the committed manifest — \
                     sequence reuse is forbidden"
                        .into(),
                ));
            }
            self.manifest = Some(manifest);
        }

        // Orphan GC: with no journal active, anything unreferenced is garbage.
        let referenced: std::collections::BTreeSet<String> = self
            .manifest
            .iter()
            .flat_map(|m| m.objects.iter().map(|o| hex(&o.hash)))
            .collect();
        if let Ok(entries) = std::fs::read_dir(self.root.join(OBJECTS_DIR)) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.ends_with(".tmp") || !referenced.contains(&name) {
                    let _ = std::fs::remove_file(entry.path());
                }
            }
        }
        let _ = std::fs::remove_file(self.root.join(format!("{COUNTER_FILE}.tmp")));
        let _ = std::fs::remove_file(self.root.join(format!("{MANIFEST_FILE}.tmp")));
        Ok(())
    }

    /// Whether the injector requests a crash at a **post-authoritative** point
    /// (where a crash may only lose cleanup, never the acknowledgment).
    fn crash_requested(&self, name: &str) -> bool {
        self.injector.as_ref().is_some_and(|i| i(name))
    }

    /// Execute one journaled commit: `new_objects` are written content-addressed,
    /// `keep` names already-stored objects to carry forward (validated to exist
    /// and match their content addresses), and `meta` is the caller's opaque
    /// metadata. Returns the reserved sequence.
    ///
    /// **Acknowledgment discipline.** The manifest rename is the authoritative
    /// switch. Every failure *before* it leaves the old state exposed and
    /// returns an error; once the rename (and the store-directory sync that
    /// makes it power-loss durable) has succeeded, the commit **is** committed
    /// and this method returns `Ok` — journal cleanup failures after that point
    /// are absorbed, because recovery finalizes a `MaterialReady` journal with
    /// the new manifest as committed. A failure raised *by the directory sync
    /// itself* after the rename is the one genuinely ambiguous case and is
    /// reported as [`JournalError::OutcomeUnknown`]: the caller must fail stop
    /// and reopen — recovery then resolves the outcome deterministically (the
    /// manifest on disk decides). A durably committed operation is therefore
    /// never reported as a plain retryable failure.
    pub fn commit(
        &mut self,
        new_objects: &[Vec<u8>],
        keep: &[ObjectRef],
        meta: Vec<u8>,
    ) -> Result<u64, JournalError> {
        // 0. Carried references must already be present and content-valid —
        //    otherwise a "successful" commit would fail integrity on next open.
        for obj in keep {
            self.read_object(obj)?;
        }

        // 1. Reserve the transaction counter (gaps allowed, reuse forbidden).
        self.point("counter")?;
        let sequence = self.reserve_sequence()?;

        let new_refs: Vec<ObjectRef> = new_objects
            .iter()
            .map(|bytes| ObjectRef {
                hash: object_hash(bytes),
                len: bytes.len() as u64,
            })
            .collect();
        let mut objects = keep.to_vec();
        objects.extend(new_refs.iter().copied());
        let manifest = StoreManifest {
            version: 1,
            sequence,
            objects,
            meta,
        };
        let manifest_bytes = postcard::to_stdvec(&manifest)
            .map_err(|e| JournalError::Durability(format!("encode manifest: {e}")))?;
        let new_manifest_hash = manifest_hash(&manifest_bytes);

        // 2. Journal Prepared.
        self.point("journal-prepared")?;
        self.write_journal(&JournalRecord::Prepared {
            sequence,
            new_objects: new_refs.clone(),
            new_manifest_hash,
        })?;

        // 3. Write all temporary objects.
        self.point("objects")?;
        for (obj, bytes) in new_refs.iter().zip(new_objects) {
            let tmp = self.object_path(&obj.hash).with_extension("tmp");
            write_sync(&tmp, bytes)?;
        }

        // 4. Journal MaterialReady, rename objects final, fsync their dir.
        self.point("journal-material-ready")?;
        self.write_journal(&JournalRecord::MaterialReady {
            sequence,
            new_objects: new_refs.clone(),
            new_manifest_hash,
        })?;
        self.point("rename-objects")?;
        for obj in &new_refs {
            let final_path = self.object_path(&obj.hash);
            if !final_path.exists() {
                atomic_replace(&final_path.with_extension("tmp"), &final_path)?;
            }
        }
        sync_dir(&self.root.join(OBJECTS_DIR))?;

        // 5. Manifest temp, then rename over current-manifest LAST.
        self.point("manifest-temp")?;
        let manifest_tmp = self.root.join(format!("{MANIFEST_FILE}.tmp"));
        write_sync(&manifest_tmp, &manifest_bytes)?;
        self.point("manifest-rename")?;
        atomic_replace(&manifest_tmp, &self.root.join(MANIFEST_FILE))?;
        if sync_dir(&self.root).is_err() {
            // The rename happened but its directory-entry durability is
            // unconfirmed: the one ambiguous outcome. Fail stop; reopening
            // resolves it (the on-disk manifest decides).
            return Err(JournalError::OutcomeUnknown);
        }

        // --- The commit is now authoritative: nothing below may fail it. ---
        self.manifest = Some(manifest);

        // 6. Journal Committed + removal are pure cleanup: recovery finalizes a
        //    MaterialReady journal with the new manifest as committed, so a
        //    crash or error here loses nothing and MUST NOT fail the call.
        if !self.crash_requested("journal-committed") {
            let wrote = self
                .write_journal(&JournalRecord::Committed {
                    sequence,
                    new_manifest_hash,
                })
                .is_ok();
            if wrote && !self.crash_requested("journal-remove") {
                let _ = self.remove_journal();
            }
        }
        Ok(sequence)
    }
}
