//! The Fabric operation surface and engine — the sealed contract Replica drives.
//!
//! Fabric is LAIT's canonical, sealed Loro component and the only crate that
//! names Loro. It exposes **LAIT-owned** semantic operations and results, never
//! raw documents, containers, or Loro frontier types. Replica validates and
//! constructs a semantic transaction plan, submits it to a Fabric-owned
//! [`Fabric`] engine, and advances its semantic frontier only from a durable
//! [`FabricCommitReceipt`]. Fabric never imports Replica.
//!
//! **Ownership boundary (enforced, not just documented):**
//! - Replica submits *semantic* [`FabricOp`]s — it never authors a Loro delta.
//!   The concrete translation to Loro is Fabric-private.
//! - [`FabricCommitReceipt`] and [`CausalToken`] can be constructed **only**
//!   inside this crate (their constructors are `pub(crate)`), so a receipt is
//!   proof of a real Fabric commit — an outside crate cannot forge the token
//!   Replica advances from.
//!
//! [`LoroFabric`] is the canonical engine: atomic Bodies plus the frozen
//! collaborative algebra (register/map/list/text/set/counter with stable
//! element identity) over real Loro containers, with batch atomicity and
//! cross-replica merge. [`MemFabric`] remains the atomic-only reference engine
//! for tests. The journaled store layout is still owed to S5.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// An opaque commitment to Fabric's internal causal position (Loro frontier),
/// carried as bytes. It rides inside [`FabricCommitReceipt`] and is never
/// interpreted outside Fabric — no `loro::*` type crosses the boundary.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CausalToken(Vec<u8>);

impl CausalToken {
    /// Construct a causal token. **Crate-private**: only the Fabric engine mints
    /// one, so a token always denotes a real Fabric position.
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A key into the Fabric representation — an opaque handle Replica uses to
/// address a durable object without naming a Loro container. Its concrete
/// encoding is Fabric-private and stabilizes in S5.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FabricKey(Vec<u8>);

impl FabricKey {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A single Fabric-level **semantic** operation. Replica alone translates a
/// semantic `BodyOp` into one of these; Fabric maps them canonically onto Loro.
/// Replica never authors a raw Loro delta — that is the ownership boundary.
///
/// The collaborative operations implement the frozen S1 algebra: each addresses
/// a `path` inside one collaborative Body (`key`), a path is bound to exactly
/// one collaborative type for the Body's lifetime (a second type at the same
/// path is a [`FabricError::TypeConflict`]), list elements carry **stable
/// element ids** minted by Fabric at insert time (never indices), sets are
/// add-wins (observed-remove), counters sum all increments, and text splices
/// use Unicode-scalar coordinates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FabricOp {
    /// Atomically replace the canonical bytes stored at a key.
    PutCanonical { key: FabricKey, value: Vec<u8> },
    /// Remove the object at a key (atomic value or whole collaborative Body).
    Remove { key: FabricKey },
    /// Ensure a collaborative Body root exists at a key (Body create).
    CreateBody { key: FabricKey },
    /// Last-writer-wins register set.
    RegisterSet {
        key: FabricKey,
        path: String,
        value: Vec<u8>,
    },
    /// Clear a register.
    RegisterClear { key: FabricKey, path: String },
    /// Map entry set (LWW per entry).
    MapSet {
        key: FabricKey,
        path: String,
        entry: String,
        value: Vec<u8>,
    },
    /// Map entry remove.
    MapRemove {
        key: FabricKey,
        path: String,
        entry: String,
    },
    /// Ordered-list insert at a position; Fabric mints the stable element id.
    ListInsert {
        key: FabricKey,
        path: String,
        index: u64,
        value: Vec<u8>,
    },
    /// Ordered-list remove **by stable element id**.
    ListRemove {
        key: FabricKey,
        path: String,
        element: String,
    },
    /// Ordered-list move **by stable element id** to a position.
    ListMove {
        key: FabricKey,
        path: String,
        element: String,
        index: u64,
    },
    /// Text splice with Unicode-scalar coordinates.
    TextSplice {
        key: FabricKey,
        path: String,
        index: u64,
        delete: u64,
        insert: String,
    },
    /// Add-wins set add.
    SetAdd {
        key: FabricKey,
        path: String,
        value: Vec<u8>,
    },
    /// Set remove (removes the observed adds; a concurrent add survives).
    SetRemove {
        key: FabricKey,
        path: String,
        value: Vec<u8>,
    },
    /// Commutative counter increment.
    CounterAdd {
        key: FabricKey,
        path: String,
        delta: i64,
    },
}

/// A durable transaction request: an ordered batch of Fabric operations to apply
/// atomically, carrying the request/commit metadata Fabric labels the change
/// with in the oplog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricTransactionRequest {
    /// The semantic request label (e.g. `"created"`) surfaced in the oplog.
    pub request: String,
    pub ops: Vec<FabricOp>,
}

impl FabricTransactionRequest {
    pub fn new(request: impl Into<String>, ops: Vec<FabricOp>) -> Self {
        Self {
            request: request.into(),
            ops,
        }
    }
}

/// The receipt of a durable Fabric commit. Replica advances its semantic
/// frontier **only** from this. It carries the post-commit causal token and the
/// count of changes applied. Constructed only by the Fabric engine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FabricCommitReceipt {
    causal: CausalToken,
    applied: u32,
}

impl FabricCommitReceipt {
    /// **Crate-private**: only the Fabric engine issues a receipt.
    pub(crate) fn new(causal: CausalToken, applied: u32) -> Self {
        Self { causal, applied }
    }
    pub fn causal(&self) -> &CausalToken {
        &self.causal
    }
    pub fn applied(&self) -> u32 {
        self.applied
    }
}

/// Why a Fabric commit failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FabricError {
    /// A durable write (or a rollback after a failed apply) failed. The engine
    /// state may have diverged from the store — the caller must fail stop.
    Durability(String),
    /// The engine does not support this operation ([`MemFabric`] is atomic-only).
    Unsupported,
    /// The operation's type disagrees with what its target is already bound to:
    /// a collaborative op on an atomic Body, an atomic put over a collaborative
    /// Body, or a second collaborative type at an already-bound path.
    TypeConflict,
    /// The operation was structurally invalid at apply time (out-of-bounds
    /// index, unknown element id, counter overflow). The batch is rolled back.
    InvalidOp(String),
    /// The durable store failed integrity validation (a manifest naming absent
    /// or corrupt objects, a corrupt journal, a missing transaction counter).
    /// Never repaired heuristically — recreation guidance is the caller's.
    Integrity(String),
    /// The authoritative switch happened but its durability confirmation
    /// failed: the commit may or may not survive power loss. Fail stop and
    /// reopen — recovery resolves the outcome deterministically from the
    /// on-disk manifest. Never retry through this error.
    OutcomeUnknown,
}

/// A canonical, Loro-free view of one collaborative Body, keyed by path. This
/// is what a World reads back through the bounded context: list elements expose
/// the **stable element ids** Fabric minted at insert (the handles `ListRemove`
/// / `ListMove` take), sets expose distinct member values, counters the summed
/// total.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollaborativeView {
    pub registers: BTreeMap<String, Vec<u8>>,
    pub maps: BTreeMap<String, BTreeMap<String, Vec<u8>>>,
    pub lists: BTreeMap<String, Vec<ListElement>>,
    pub texts: BTreeMap<String, String>,
    /// Distinct member values, sorted (set order is not meaningful).
    pub sets: BTreeMap<String, Vec<Vec<u8>>>,
    pub counters: BTreeMap<String, i64>,
}

/// One ordered-list element: its stable Fabric-minted id and its value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListElement {
    pub element: String,
    pub value: Vec<u8>,
}

impl std::fmt::Display for FabricError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for FabricError {}

/// The Fabric engine: the durable, canonical collaborative representation Replica
/// drives. It accepts semantic operations and returns a receipt whose
/// construction is Fabric-private; it also serves committed reads. The Loro
/// engine (S5) implements this same trait, so Replica/runtime are unchanged when
/// it lands.
pub trait Fabric {
    /// Durably apply a transaction and return a commit receipt. Atomic: either
    /// every op is applied and a receipt returned, or nothing changes.
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError>;

    /// Read the committed canonical bytes at a key, if present.
    fn read(&self, key: &FabricKey) -> Option<Vec<u8>>;

    /// Read the committed collaborative view of a Body, if the key holds one
    /// (`None` for absent keys and atomic values).
    fn read_collaborative(&self, key: &FabricKey) -> Option<CollaborativeView>;

    /// Merge another replica's exported representation into this one — the
    /// engine-level convergence primitive. Returns `Some(receipt)` when the
    /// representation changed (the receipt is engine-constructed, like every
    /// receipt) and `None` when everything was already known. The reference
    /// engine does not support merge.
    fn merge(&mut self, exported: &[u8]) -> Result<Option<FabricCommitReceipt>, FabricError>;

    /// Export the full durable representation as bytes. The engine's own
    /// constructor restores it (`LoroFabric::from_snapshot` / `MemFabric::
    /// from_snapshot`), so the caller persists the bytes and reopens with the
    /// matching engine.
    fn snapshot(&self) -> Result<Vec<u8>, FabricError>;
}

/// A minimal in-memory reference engine. It is a real engine — it applies
/// operations, serves reads, and mints receipts whose causal token advances with
/// each commit — standing in for the Loro-backed engine until S5. It owns receipt
/// construction, so a receipt from here denotes a genuine (in-memory durable)
/// commit.
#[derive(Debug, Default)]
pub struct MemFabric {
    state: BTreeMap<FabricKey, Vec<u8>>,
    counter: u64,
}

impl MemFabric {
    pub fn new() -> Self {
        Self::default()
    }

    /// Restore an in-memory engine from a [`Fabric::snapshot`].
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, FabricError> {
        let state: BTreeMap<FabricKey, Vec<u8>> =
            postcard::from_bytes(bytes).map_err(|e| FabricError::Durability(e.to_string()))?;
        Ok(Self { state, counter: 0 })
    }
}

impl Fabric for MemFabric {
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError> {
        // Apply atomically against a scratch copy, then swap in on success. The
        // reference engine is atomic-only; collaborative operations require the
        // Loro engine.
        let mut next = self.state.clone();
        for op in &request.ops {
            match op {
                FabricOp::PutCanonical { key, value } => {
                    next.insert(key.clone(), value.clone());
                }
                FabricOp::Remove { key } => {
                    next.remove(key);
                }
                _ => return Err(FabricError::Unsupported),
            }
        }
        self.state = next;
        self.counter += 1;
        Ok(FabricCommitReceipt::new(
            CausalToken::from_bytes(self.counter.to_le_bytes().to_vec()),
            request.ops.len() as u32,
        ))
    }

    fn read(&self, key: &FabricKey) -> Option<Vec<u8>> {
        self.state.get(key).cloned()
    }

    fn read_collaborative(&self, _key: &FabricKey) -> Option<CollaborativeView> {
        // The reference engine holds no collaborative Bodies.
        None
    }

    fn merge(&mut self, _exported: &[u8]) -> Result<Option<FabricCommitReceipt>, FabricError> {
        Err(FabricError::Unsupported)
    }

    fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        postcard::to_stdvec(&self.state).map_err(|e| FabricError::Durability(e.to_string()))
    }
}

/// The Loro-backed engine: the canonical collaborative representation, and the
/// reason this crate alone names Loro.
///
/// **Layout.** One root Loro map (`bodies`) keyed by the hex of each
/// [`FabricKey`]. An atomic Body is a binary value at its key; a collaborative
/// Body is a child Loro map whose keys are `"<type>:<path>"` — `reg:` LWW binary
/// registers, `map:` child maps of binary entries, `list:` child movable lists
/// whose element values are `element_id[16] || value` (the id embedded in the
/// value is the **stable element identity**, LAIT-owned and sync-stable),
/// `text:` child texts (Unicode-scalar splices), `set:` child maps implementing
/// an observed-remove set (`"<value-hash>:<unique-tag>"` per add, so a remove
/// only deletes the adds it observed — add-wins), and `cnt:` child maps
/// implementing a PN-counter (each doc session sums into its own peer key;
/// concurrent increments land in disjoint keys and always sum).
///
/// **Atomicity.** A batch is applied against the live doc but a pre-batch
/// snapshot is taken first; any apply error restores the doc from it, so a
/// failed batch changes nothing. Only a successful batch is sealed as one
/// labelled Loro change, and the receipt's causal token is the oplog frontier.
///
/// **Known limitation** (documented, not hidden): two peers *creating the same
/// fresh path concurrently* create distinct child containers, and the map's LWW
/// register keeps one — edits made in the loser before the first sync are
/// shadowed. Initialize a Body's paths in its creating transaction (before
/// concurrent editing starts), as the conformance Worlds do; deep container
/// merge is future work. The journaled store layout also remains owed to S5.
pub struct LoroFabric {
    doc: loro::LoroDoc,
}

const BODIES_MAP: &str = "bodies";

/// The collaborative type tags a path can be bound to.
const TYPE_TAGS: [&str; 6] = ["reg", "map", "list", "text", "set", "cnt"];

/// A list element id is 16 minted bytes, rendered as 32 hex chars.
const ELEMENT_ID_LEN: usize = 16;

fn typed_key(tag: &str, path: &str) -> String {
    format!("{tag}:{path}")
}

fn mint_bytes<const N: usize>() -> [u8; N] {
    let mut raw = [0u8; N];
    getrandom::fill(&mut raw).expect("getrandom");
    raw
}

/// The set-member key prefix for a value: 128 bits of BLAKE3 over the value.
fn set_member_prefix(value: &[u8]) -> String {
    data_encoding::HEXLOWER.encode(&blake3::hash(value).as_bytes()[..16])
}

impl LoroFabric {
    /// A fresh, empty Loro-backed engine with the crate's canonical Loro config.
    pub fn new() -> Self {
        let doc = loro::LoroDoc::new();
        crate::op::configure(&doc, None);
        Self { doc }
    }

    /// Restore an engine from a durable snapshot ([`LoroFabric::snapshot`]).
    pub fn from_snapshot(bytes: &[u8]) -> Result<Self, FabricError> {
        let doc = loro::LoroDoc::new();
        crate::op::configure(&doc, None);
        doc.import(bytes)
            .map_err(|e| FabricError::Durability(format!("import snapshot: {e}")))?;
        Ok(Self { doc })
    }

    /// Export the full durable representation as a Loro snapshot.
    pub fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        self.doc
            .export(loro::ExportMode::Snapshot)
            .map_err(|e| FabricError::Durability(format!("export snapshot: {e}")))
    }

    fn key_str(key: &FabricKey) -> String {
        data_encoding::HEXLOWER.encode(key.as_bytes())
    }

    fn loro_err(e: impl std::fmt::Display) -> FabricError {
        FabricError::InvalidOp(e.to_string())
    }

    /// The collaborative root of a Body: `Ok(Some)` when it exists (or was
    /// created with `create`), `Ok(None)` when absent and not created, and
    /// `TypeConflict` when the key holds an atomic value or foreign container.
    fn body_root(&self, key_str: &str, create: bool) -> Result<Option<loro::LoroMap>, FabricError> {
        let bodies = self.doc.get_map(BODIES_MAP);
        match bodies.get(key_str) {
            Some(loro::ValueOrContainer::Container(loro::Container::Map(m))) => Ok(Some(m)),
            Some(_) => Err(FabricError::TypeConflict),
            None if create => bodies
                .insert_container(key_str, loro::LoroMap::new())
                .map(Some)
                .map_err(Self::loro_err),
            None => Ok(None),
        }
    }

    /// Enforce "a path is bound to exactly one collaborative type": no other
    /// type tag may already exist at this path.
    fn check_path_type(body: &loro::LoroMap, tag: &str, path: &str) -> Result<(), FabricError> {
        for other in TYPE_TAGS {
            if other != tag && body.get(&typed_key(other, path)).is_some() {
                return Err(FabricError::TypeConflict);
            }
        }
        Ok(())
    }

    /// The Body's collaborative root for a typed-path write, with the path-type
    /// binding enforced.
    fn body_for(
        &self,
        key: &FabricKey,
        tag: &str,
        path: &str,
    ) -> Result<loro::LoroMap, FabricError> {
        let body = self
            .body_root(&Self::key_str(key), true)?
            .expect("created on demand");
        Self::check_path_type(&body, tag, path)?;
        Ok(body)
    }

    fn child_map(body: &loro::LoroMap, key: &str) -> Result<loro::LoroMap, FabricError> {
        match body.get(key) {
            Some(loro::ValueOrContainer::Container(loro::Container::Map(m))) => Ok(m),
            Some(_) => Err(FabricError::TypeConflict),
            None => body
                .insert_container(key, loro::LoroMap::new())
                .map_err(Self::loro_err),
        }
    }

    fn child_list(body: &loro::LoroMap, key: &str) -> Result<loro::LoroMovableList, FabricError> {
        match body.get(key) {
            Some(loro::ValueOrContainer::Container(loro::Container::MovableList(l))) => Ok(l),
            Some(_) => Err(FabricError::TypeConflict),
            None => body
                .insert_container(key, loro::LoroMovableList::new())
                .map_err(Self::loro_err),
        }
    }

    fn child_text(body: &loro::LoroMap, key: &str) -> Result<loro::LoroText, FabricError> {
        match body.get(key) {
            Some(loro::ValueOrContainer::Container(loro::Container::Text(t))) => Ok(t),
            Some(_) => Err(FabricError::TypeConflict),
            None => body
                .insert_container(key, loro::LoroText::new())
                .map_err(Self::loro_err),
        }
    }

    /// The `(index, decoded element blob)` pairs of a list, skipping malformed
    /// entries (which canonical writes never produce).
    fn list_entries(l: &loro::LoroMovableList) -> Vec<(usize, String, Vec<u8>)> {
        let mut out = Vec::new();
        for i in 0..l.len() {
            let Some(v) = l.get(i) else { continue };
            let Some(bytes) = v
                .into_value()
                .ok()
                .and_then(|val| val.into_binary().ok())
                .map(|b| b.to_vec())
            else {
                continue;
            };
            if bytes.len() < ELEMENT_ID_LEN {
                continue;
            }
            let id = data_encoding::HEXLOWER.encode(&bytes[..ELEMENT_ID_LEN]);
            out.push((i, id, bytes[ELEMENT_ID_LEN..].to_vec()));
        }
        out
    }

    /// Apply one operation to the live doc. Errors leave partially-applied
    /// state; [`Fabric::commit`] rolls the whole batch back from its backup.
    fn apply(&self, op: &FabricOp) -> Result<(), FabricError> {
        let bodies = self.doc.get_map(BODIES_MAP);
        match op {
            FabricOp::PutCanonical { key, value } => {
                let key_str = Self::key_str(key);
                if let Some(loro::ValueOrContainer::Container(_)) = bodies.get(&key_str) {
                    // A collaborative Body cannot be silently flattened.
                    return Err(FabricError::TypeConflict);
                }
                bodies
                    .insert(&key_str, value.as_slice())
                    .map_err(Self::loro_err)
            }
            FabricOp::Remove { key } => {
                let key_str = Self::key_str(key);
                if bodies.get(&key_str).is_some() {
                    bodies.delete(&key_str).map_err(Self::loro_err)?;
                }
                Ok(())
            }
            FabricOp::CreateBody { key } => {
                self.body_root(&Self::key_str(key), true)?;
                Ok(())
            }
            FabricOp::RegisterSet { key, path, value } => {
                let body = self.body_for(key, "reg", path)?;
                body.insert(&typed_key("reg", path), value.as_slice())
                    .map_err(Self::loro_err)
            }
            FabricOp::RegisterClear { key, path } => {
                let body = self.body_for(key, "reg", path)?;
                let k = typed_key("reg", path);
                if body.get(&k).is_some() {
                    body.delete(&k).map_err(Self::loro_err)?;
                }
                Ok(())
            }
            FabricOp::MapSet {
                key,
                path,
                entry,
                value,
            } => {
                let body = self.body_for(key, "map", path)?;
                let m = Self::child_map(&body, &typed_key("map", path))?;
                m.insert(entry, value.as_slice()).map_err(Self::loro_err)
            }
            FabricOp::MapRemove { key, path, entry } => {
                let body = self.body_for(key, "map", path)?;
                let m = Self::child_map(&body, &typed_key("map", path))?;
                if m.get(entry).is_some() {
                    m.delete(entry).map_err(Self::loro_err)?;
                }
                Ok(())
            }
            FabricOp::ListInsert {
                key,
                path,
                index,
                value,
            } => {
                let body = self.body_for(key, "list", path)?;
                let l = Self::child_list(&body, &typed_key("list", path))?;
                let index = *index as usize;
                if index > l.len() {
                    return Err(FabricError::InvalidOp("list index out of bounds".into()));
                }
                // Fabric mints the stable element id and embeds it in the value,
                // so identity survives synchronization.
                let id: [u8; ELEMENT_ID_LEN] = mint_bytes();
                let mut blob = Vec::with_capacity(ELEMENT_ID_LEN + value.len());
                blob.extend_from_slice(&id);
                blob.extend_from_slice(value);
                l.insert(index, blob.as_slice()).map_err(Self::loro_err)
            }
            FabricOp::ListRemove { key, path, element } => {
                let body = self.body_for(key, "list", path)?;
                let l = Self::child_list(&body, &typed_key("list", path))?;
                let Some((i, _, _)) = Self::list_entries(&l)
                    .into_iter()
                    .find(|(_, id, _)| id == element)
                else {
                    return Err(FabricError::InvalidOp("unknown list element".into()));
                };
                l.delete(i, 1).map_err(Self::loro_err)
            }
            FabricOp::ListMove {
                key,
                path,
                element,
                index,
            } => {
                let body = self.body_for(key, "list", path)?;
                let l = Self::child_list(&body, &typed_key("list", path))?;
                let Some((from, _, _)) = Self::list_entries(&l)
                    .into_iter()
                    .find(|(_, id, _)| id == element)
                else {
                    return Err(FabricError::InvalidOp("unknown list element".into()));
                };
                let to = *index as usize;
                if to >= l.len() {
                    return Err(FabricError::InvalidOp("list index out of bounds".into()));
                }
                l.mov(from, to).map_err(Self::loro_err)
            }
            FabricOp::TextSplice {
                key,
                path,
                index,
                delete,
                insert,
            } => {
                let body = self.body_for(key, "text", path)?;
                let t = Self::child_text(&body, &typed_key("text", path))?;
                let len = t.to_string().chars().count();
                let index = *index as usize;
                let delete = *delete as usize;
                if index + delete > len {
                    return Err(FabricError::InvalidOp("text splice out of bounds".into()));
                }
                if delete > 0 {
                    t.delete(index, delete).map_err(Self::loro_err)?;
                }
                if !insert.is_empty() {
                    t.insert(index, insert).map_err(Self::loro_err)?;
                }
                Ok(())
            }
            FabricOp::SetAdd { key, path, value } => {
                let body = self.body_for(key, "set", path)?;
                let m = Self::child_map(&body, &typed_key("set", path))?;
                // Observed-remove set: every add mints a fresh tag, so a remove
                // only deletes the adds it has seen — a concurrent add survives.
                let tag: [u8; 8] = mint_bytes();
                let member = format!(
                    "{}:{}",
                    set_member_prefix(value),
                    data_encoding::HEXLOWER.encode(&tag)
                );
                m.insert(&member, value.as_slice()).map_err(Self::loro_err)
            }
            FabricOp::SetRemove { key, path, value } => {
                let body = self.body_for(key, "set", path)?;
                let m = Self::child_map(&body, &typed_key("set", path))?;
                let prefix = format!("{}:", set_member_prefix(value));
                for k in crate::loro_ext::map_keys(&m) {
                    if k.starts_with(&prefix) {
                        m.delete(&k).map_err(Self::loro_err)?;
                    }
                }
                Ok(())
            }
            FabricOp::CounterAdd { key, path, delta } => {
                let body = self.body_for(key, "cnt", path)?;
                let m = Self::child_map(&body, &typed_key("cnt", path))?;
                // PN-counter: each doc session sums into its own peer key;
                // concurrent increments land in disjoint keys and always sum.
                let me = self.doc.peer_id().to_string();
                let current = crate::loro_ext::get_i64(&m, &me).unwrap_or(0);
                let next = current
                    .checked_add(*delta)
                    .ok_or_else(|| FabricError::InvalidOp("counter overflow".into()))?;
                m.insert(&me, next).map_err(Self::loro_err)
            }
        }
    }
}

impl Default for LoroFabric {
    fn default() -> Self {
        Self::new()
    }
}

impl Fabric for LoroFabric {
    fn commit(
        &mut self,
        request: FabricTransactionRequest,
    ) -> Result<FabricCommitReceipt, FabricError> {
        // Batch atomicity: back up the committed representation, apply, and on
        // any error restore the doc from the backup — a failed batch changes
        // nothing. (The backup is the same export the durability sink takes.)
        let backup = if request.ops.is_empty() {
            None
        } else {
            Some(self.snapshot()?)
        };
        let mut failed = None;
        for op in &request.ops {
            if let Err(e) = self.apply(op) {
                failed = Some(e);
                break;
            }
        }
        if let Some(e) = failed {
            let backup = backup.expect("ops were applied");
            match Self::from_snapshot(&backup) {
                Ok(restored) => {
                    self.doc = restored.doc;
                    return Err(e);
                }
                Err(_) => {
                    // The rollback itself failed: the in-memory state has
                    // diverged. Fail stop.
                    return Err(FabricError::Durability(
                        "rollback after failed apply did not restore".into(),
                    ));
                }
            }
        }
        // Label the change and land it as one Loro commit.
        self.doc.set_next_commit_message(&request.request);
        self.doc.commit();
        // The Loro oplog frontier is the opaque causal token.
        let causal = CausalToken::from_bytes(self.doc.oplog_frontiers().encode());
        Ok(FabricCommitReceipt::new(causal, request.ops.len() as u32))
    }

    fn read(&self, key: &FabricKey) -> Option<Vec<u8>> {
        let bodies = self.doc.get_map(BODIES_MAP);
        bodies
            .get(&Self::key_str(key))
            .and_then(|v| v.into_value().ok())
            .and_then(|v| v.into_binary().ok())
            .map(|b| b.to_vec())
    }

    fn read_collaborative(&self, key: &FabricKey) -> Option<CollaborativeView> {
        let body = self.body_root(&Self::key_str(key), false).ok()??;
        let mut view = CollaborativeView::default();
        for full_key in crate::loro_ext::map_keys(&body) {
            let Some((tag, path)) = full_key.split_once(':') else {
                continue;
            };
            let path = path.to_string();
            match tag {
                "reg" => {
                    if let Some(bytes) = crate::loro_ext::get_bytes(&body, &full_key) {
                        view.registers.insert(path, bytes);
                    }
                }
                "map" => {
                    if let Some(m) = crate::loro_ext::get_map(&body, &full_key) {
                        let mut entries = BTreeMap::new();
                        for k in crate::loro_ext::map_keys(&m) {
                            if let Some(bytes) = crate::loro_ext::get_bytes(&m, &k) {
                                entries.insert(k, bytes);
                            }
                        }
                        view.maps.insert(path, entries);
                    }
                }
                "list" => {
                    if let Some(loro::ValueOrContainer::Container(loro::Container::MovableList(
                        l,
                    ))) = body.get(&full_key)
                    {
                        view.lists.insert(
                            path,
                            Self::list_entries(&l)
                                .into_iter()
                                .map(|(_, element, value)| ListElement { element, value })
                                .collect(),
                        );
                    }
                }
                "text" => {
                    if let Some(loro::ValueOrContainer::Container(loro::Container::Text(t))) =
                        body.get(&full_key)
                    {
                        view.texts.insert(path, t.to_string());
                    }
                }
                "set" => {
                    if let Some(m) = crate::loro_ext::get_map(&body, &full_key) {
                        let mut members: Vec<Vec<u8>> = crate::loro_ext::map_keys(&m)
                            .into_iter()
                            .filter_map(|k| crate::loro_ext::get_bytes(&m, &k))
                            .collect();
                        members.sort();
                        members.dedup();
                        view.sets.insert(path, members);
                    }
                }
                "cnt" => {
                    if let Some(m) = crate::loro_ext::get_map(&body, &full_key) {
                        let total = crate::loro_ext::map_keys(&m)
                            .into_iter()
                            .filter_map(|k| crate::loro_ext::get_i64(&m, &k))
                            .fold(0i64, i64::saturating_add);
                        view.counters.insert(path, total);
                    }
                }
                _ => {}
            }
        }
        Some(view)
    }

    fn merge(&mut self, exported: &[u8]) -> Result<Option<FabricCommitReceipt>, FabricError> {
        // Concurrent collaborative edits converge under the declared algebra;
        // the oplog frontier tells whether the merge brought anything new.
        let before = self.doc.oplog_frontiers().encode();
        self.doc
            .import(exported)
            .map_err(|e| FabricError::InvalidOp(format!("merge import: {e}")))?;
        let after = self.doc.oplog_frontiers().encode();
        if after == before {
            return Ok(None);
        }
        Ok(Some(FabricCommitReceipt::new(
            CausalToken::from_bytes(after),
            0,
        )))
    }

    fn snapshot(&self) -> Result<Vec<u8>, FabricError> {
        LoroFabric::snapshot(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transaction_request_roundtrips_postcard() {
        let req = FabricTransactionRequest::new(
            "created",
            vec![
                FabricOp::PutCanonical {
                    key: FabricKey::from_bytes(vec![1, 2, 3]),
                    value: vec![9],
                },
                FabricOp::Remove {
                    key: FabricKey::from_bytes(vec![4]),
                },
            ],
        );
        let bytes = postcard::to_stdvec(&req).unwrap();
        let back: FabricTransactionRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn loro_engine_persists_reads_and_survives_a_snapshot_roundtrip() {
        let mut fabric = LoroFabric::new();
        let key = FabricKey::from_bytes(b"body/0".to_vec());
        fabric
            .commit(FabricTransactionRequest::new(
                "created",
                vec![FabricOp::PutCanonical {
                    key: key.clone(),
                    value: b"durable".to_vec(),
                }],
            ))
            .unwrap();
        assert_eq!(fabric.read(&key).as_deref(), Some(&b"durable"[..]));

        // Durable round-trip: a restored engine reads back the same state.
        let snap = fabric.snapshot().unwrap();
        let restored = LoroFabric::from_snapshot(&snap).unwrap();
        assert_eq!(restored.read(&key).as_deref(), Some(&b"durable"[..]));

        // Remove is durable too, and the causal token advances.
        let mut fabric = restored;
        let before = fabric
            .commit(FabricTransactionRequest::new("noop", vec![]))
            .unwrap();
        let after = fabric
            .commit(FabricTransactionRequest::new(
                "removed",
                vec![FabricOp::Remove { key: key.clone() }],
            ))
            .unwrap();
        assert_ne!(before.causal(), after.causal());
        assert_eq!(fabric.read(&key), None);
    }

    #[test]
    fn engine_applies_atomically_and_issues_advancing_receipts() {
        let mut fabric = MemFabric::new();
        let key = FabricKey::from_bytes(b"body/0".to_vec());
        let r1 = fabric
            .commit(FabricTransactionRequest::new(
                "created",
                vec![FabricOp::PutCanonical {
                    key: key.clone(),
                    value: b"v1".to_vec(),
                }],
            ))
            .unwrap();
        assert_eq!(r1.applied(), 1);
        assert_eq!(fabric.read(&key).as_deref(), Some(&b"v1"[..]));

        let r2 = fabric
            .commit(FabricTransactionRequest::new(
                "removed",
                vec![FabricOp::Remove { key: key.clone() }],
            ))
            .unwrap();
        // The causal token advances between commits.
        assert_ne!(r1.causal(), r2.causal());
        assert_eq!(fabric.read(&key), None);
    }
}
