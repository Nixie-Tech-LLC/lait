//! The journaled durable store — Fabric's on-disk commit protocol.
//!
//! Layout, under one store root (which may also hold runtime-owned lifecycle
//! files — this module touches only its own names):
//!
//! ```text
//! counter            // the local transaction counter (reserved + fsynced first)
//! current-manifest   // postcard StoreManifestV1, atomically replaced
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

use crate::fabric::FabricError;

const COUNTER_FILE: &str = "counter";
const MANIFEST_FILE: &str = "current-manifest";
const OBJECTS_DIR: &str = "objects";
const JOURNAL_DIR: &str = "journal";
const JOURNAL_FILE: &str = "active";

/// Domain for an object's content address.
const OBJECT_DOMAIN: &[u8] = b"lait/store-object/1";
/// Domain for a manifest's identity hash (referenced by the journal).
const MANIFEST_DOMAIN: &[u8] = b"lait/store-manifest/1";

/// One immutable object reference: content address and length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObjectRef {
    pub hash: [u8; 32],
    pub len: u64,
}

/// The store's manifest: the current object set plus opaque caller metadata
/// (Replica stores its semantic frontier there — Fabric does not interpret it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoreManifestV1 {
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
    manifest: Option<StoreManifestV1>,
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

fn manifest_hash(bytes: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(MANIFEST_DOMAIN);
    h.update(bytes);
    *h.finalize().as_bytes()
}

fn hex(hash: &[u8; 32]) -> String {
    data_encoding::HEXLOWER.encode(hash)
}

fn io_err(what: &str, e: std::io::Error) -> FabricError {
    FabricError::Durability(format!("{what}: {e}"))
}

fn write_sync(path: &Path, bytes: &[u8]) -> Result<(), FabricError> {
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
fn atomic_replace(tmp: &Path, dst: &Path) -> Result<(), FabricError> {
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

/// Best-effort directory durability (real fsync on unix; backup-semantics
/// handle flush on Windows, tolerated on failure — NTFS journals metadata).
#[cfg(unix)]
fn sync_dir(dir: &Path) {
    let _ = File::open(dir).and_then(|d| d.sync_all());
}

#[cfg(windows)]
fn sync_dir(dir: &Path) {
    use std::os::windows::fs::OpenOptionsExt;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    let _ = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(dir)
        .and_then(|d| d.sync_all());
}

impl JournaledStore {
    /// Open a store root, running crash recovery, and return the store plus its
    /// current manifest (`None` for a fresh store). The exposed state is always
    /// the complete old or complete new one.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, FabricError> {
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

    /// The current manifest, if any commit has completed.
    pub fn manifest(&self) -> Option<&StoreManifestV1> {
        self.manifest.as_ref()
    }

    /// Read an immutable object, verifying its content address.
    pub fn read_object(&self, obj: &ObjectRef) -> Result<Vec<u8>, FabricError> {
        let path = self.object_path(&obj.hash);
        let bytes = std::fs::read(&path).map_err(|e| {
            FabricError::Integrity(format!("object {} unreadable: {e}", hex(&obj.hash)))
        })?;
        if bytes.len() as u64 != obj.len || object_hash(&bytes) != obj.hash {
            return Err(FabricError::Integrity(format!(
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

    fn point(&self, name: &str) -> Result<(), FabricError> {
        if let Some(injector) = &self.injector {
            if injector(name) {
                return Err(FabricError::Durability(format!("injected crash at {name}")));
            }
        }
        Ok(())
    }

    fn write_journal(&self, record: &JournalRecord) -> Result<(), FabricError> {
        let bytes = postcard::to_stdvec(record)
            .map_err(|e| FabricError::Durability(format!("encode journal: {e}")))?;
        let dir = self.root.join(JOURNAL_DIR);
        let tmp = dir.join("active.tmp");
        write_sync(&tmp, &bytes)?;
        atomic_replace(&tmp, &self.journal_path())?;
        sync_dir(&dir);
        Ok(())
    }

    fn read_journal(&self) -> Result<Option<JournalRecord>, FabricError> {
        match std::fs::read(self.journal_path()) {
            Ok(bytes) => postcard::from_bytes(&bytes)
                .map(Some)
                // An unreadable journal record is corruption we do not repair
                // heuristically.
                .map_err(|e| FabricError::Integrity(format!("journal corrupt: {e}"))),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("read journal", e)),
        }
    }

    fn remove_journal(&self) -> Result<(), FabricError> {
        match std::fs::remove_file(self.journal_path()) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_err("remove journal", e)),
        }
        sync_dir(&self.root.join(JOURNAL_DIR));
        Ok(())
    }

    fn read_manifest_file(&self) -> Result<Option<(StoreManifestV1, [u8; 32])>, FabricError> {
        match std::fs::read(self.root.join(MANIFEST_FILE)) {
            Ok(bytes) => {
                let manifest: StoreManifestV1 = postcard::from_bytes(&bytes)
                    .map_err(|e| FabricError::Integrity(format!("manifest corrupt: {e}")))?;
                if manifest.version != 1 {
                    return Err(FabricError::Integrity(format!(
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

    fn read_counter(&self) -> Result<u64, FabricError> {
        match File::open(self.root.join(COUNTER_FILE)) {
            Ok(mut f) => {
                let mut buf = [0u8; 8];
                f.read_exact(&mut buf)
                    .map_err(|_| FabricError::Integrity("transaction counter truncated".into()))?;
                Ok(u64::from_le_bytes(buf))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // A fresh store has no counter — but a store with a manifest
                // and no counter could reuse sequences: fail closed.
                if self.root.join(MANIFEST_FILE).exists() {
                    return Err(FabricError::Integrity(
                        "transaction counter missing from a committed store".into(),
                    ));
                }
                Ok(0)
            }
            Err(e) => Err(io_err("read counter", e)),
        }
    }

    fn reserve_sequence(&self) -> Result<u64, FabricError> {
        let next = self
            .read_counter()?
            .checked_add(1)
            .ok_or_else(|| FabricError::Integrity("transaction counter overflow".into()))?;
        let tmp = self.root.join(format!("{COUNTER_FILE}.tmp"));
        write_sync(&tmp, &next.to_le_bytes())?;
        atomic_replace(&tmp, &self.root.join(COUNTER_FILE))?;
        sync_dir(&self.root);
        Ok(next)
    }

    /// Crash recovery, then integrity verification, then orphan GC.
    fn recover(&mut self) -> Result<(), FabricError> {
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
                return Err(FabricError::Integrity(
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

    /// Execute one journaled commit: `new_objects` are written content-addressed,
    /// `keep` names already-stored objects to carry forward, and `meta` is the
    /// caller's opaque metadata. Returns the reserved sequence. On error the
    /// exposed state is unchanged (the next open recovers to the complete old
    /// state — or the complete new one if only the acknowledgment was lost).
    pub fn commit(
        &mut self,
        new_objects: &[Vec<u8>],
        keep: &[ObjectRef],
        meta: Vec<u8>,
    ) -> Result<u64, FabricError> {
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
        let manifest = StoreManifestV1 {
            version: 1,
            sequence,
            objects,
            meta,
        };
        let manifest_bytes = postcard::to_stdvec(&manifest)
            .map_err(|e| FabricError::Durability(format!("encode manifest: {e}")))?;
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
        sync_dir(&self.root.join(OBJECTS_DIR));

        // 5. Manifest temp, then rename over current-manifest LAST.
        self.point("manifest-temp")?;
        let manifest_tmp = self.root.join(format!("{MANIFEST_FILE}.tmp"));
        write_sync(&manifest_tmp, &manifest_bytes)?;
        self.point("manifest-rename")?;
        atomic_replace(&manifest_tmp, &self.root.join(MANIFEST_FILE))?;
        sync_dir(&self.root);

        // 6. Journal Committed, acknowledge, then remove the journal.
        self.point("journal-committed")?;
        self.write_journal(&JournalRecord::Committed {
            sequence,
            new_manifest_hash,
        })?;
        self.manifest = Some(manifest);
        self.point("journal-remove")?;
        self.remove_journal()?;
        Ok(sequence)
    }
}
