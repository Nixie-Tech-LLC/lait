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
//! [`LoroFabric`] is the sole engine: atomic Bodies plus the frozen
//! collaborative algebra (register/map/list/text/set/counter with stable
//! element identity) over real Loro containers — one Loro document per Body,
//! so per-Body export/import carries exactly one Body's causal history — with
//! batch atomicity. The durable store is the journaled protocol in
//! [`crate::journal`], persisting per-Body protected objects.

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
/// encoding is Fabric-private.
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
    /// The engine does not support this operation. Reserved (the Loro engine
    /// supports the full algebra); the error surface stays stable.
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

/// The Fabric engine: the durable, canonical collaborative representation
/// Replica drives. It accepts semantic operations and returns a receipt whose
/// construction is Fabric-private, serves committed reads, and exports/imports
/// **one Body at a time** — the canonical store persists per-Body protected
/// objects, never a whole-engine snapshot. [`LoroFabric`] is the only engine.
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

    /// Export **one Body's** canonical representation, if the Body exists. A
    /// collaborative export preserves causal history and stable element
    /// identity for exactly that Body — never a whole-engine or cross-Body
    /// snapshot. This is the payload the protected Body object seals.
    fn export_body(&self, key: &FabricKey) -> Option<BodyExport>;

    /// Import one Body's canonical exported representation, addressed to
    /// exactly the given key. A collaborative import merges causally (already
    /// -known material returns `None`); an atomic import replaces the value
    /// (`None` when byte-identical). Fabric applies the change as directed —
    /// legitimacy, ordering, and conflict policy for atomic replacement are
    /// the caller's (Replica's) to decide **before** calling.
    fn import_body(
        &mut self,
        key: &FabricKey,
        export: &BodyExport,
    ) -> Result<Option<FabricCommitReceipt>, FabricError>;
}

/// One Body's canonical exported representation: an atomic Body's canonical
/// application bytes, or a collaborative Body's canonical per-Body Fabric
/// export (causality and stable element identity preserved).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BodyExport {
    Atomic(Vec<u8>),
    Collaborative(Vec<u8>),
}

/// The Loro-backed engine: the canonical collaborative representation, and the
/// reason this crate alone names Loro.
///
/// **Layout — one Loro document per Body.** Each collaborative Body is its own
/// `LoroDoc`, so its canonical export ([`Fabric::export_body`]) carries exactly
/// that Body's causal history and stable element identity — never a whole-
/// engine or cross-Body snapshot. Inside a Body's doc, one root map (`body`)
/// holds keys `"<type>:<path>"` — `reg:` LWW binary registers, `map:` child
/// maps of binary entries, `list:` child movable lists whose element values are
/// `element_id[16] || value` (the id embedded in the value is the **stable
/// element identity**, LAIT-owned and sync-stable), `text:` child texts
/// (Unicode-scalar splices), `set:` child maps implementing an observed-remove
/// set (`"<value-hash>:<unique-tag>"` per add, so a remove only deletes the
/// adds it observed — add-wins), and `cnt:` child maps implementing a
/// PN-counter (each doc session sums into its own peer key; concurrent
/// increments land in disjoint keys and always sum). An atomic Body is a plain
/// canonical byte value — its export is the application bytes themselves, and
/// replacement policy for concurrent atomic writes is decided by Replica, not
/// here.
///
/// **Atomicity.** A batch backs up every Body it touches before applying; any
/// apply error restores exactly those Bodies, so a failed batch changes
/// nothing. The receipt's causal token digests the touched Bodies' post-commit
/// positions.
///
/// **Known limitation** (documented, not hidden): two peers *creating the same
/// fresh path concurrently* create distinct child containers, and the map's LWW
/// register keeps one — edits made in the loser before the first sync are
/// shadowed. Initialize a Body's paths in its creating transaction (before
/// concurrent editing starts), as the conformance Worlds do; deep container
/// merge is future work.
pub struct LoroFabric {
    bodies: BTreeMap<FabricKey, BodyState>,
}

/// One Body's live state.
enum BodyState {
    Atomic(Vec<u8>),
    Collab(loro::LoroDoc),
}

const BODY_MAP: &str = "body";

/// Domain for the receipt's causal token digest.
const CAUSAL_DOMAIN: &[u8] = b"lait/fabric-causal/1";

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

/// A fresh per-Body doc with the crate's canonical Loro config.
fn new_body_doc() -> loro::LoroDoc {
    let doc = loro::LoroDoc::new();
    crate::op::configure(&doc, None);
    doc
}

impl BodyState {
    /// A position digest for the causal token: the atomic bytes' hash, or the
    /// collaborative doc's oplog frontier.
    fn digest(&self) -> Vec<u8> {
        match self {
            BodyState::Atomic(bytes) => blake3::hash(bytes).as_bytes().to_vec(),
            BodyState::Collab(doc) => doc.oplog_frontiers().encode().to_vec(),
        }
    }

    fn export(&self) -> Result<BodyExport, FabricError> {
        match self {
            BodyState::Atomic(bytes) => Ok(BodyExport::Atomic(bytes.clone())),
            BodyState::Collab(doc) => doc
                .export(loro::ExportMode::Snapshot)
                .map(BodyExport::Collaborative)
                .map_err(|e| FabricError::Durability(format!("export body: {e}"))),
        }
    }

    fn from_export(export: &BodyExport) -> Result<Self, FabricError> {
        match export {
            BodyExport::Atomic(bytes) => Ok(BodyState::Atomic(bytes.clone())),
            BodyExport::Collaborative(snapshot) => {
                let doc = new_body_doc();
                doc.import(snapshot)
                    .map_err(|e| FabricError::InvalidOp(format!("import body: {e}")))?;
                Ok(BodyState::Collab(doc))
            }
        }
    }
}

impl LoroFabric {
    /// A fresh, empty Loro-backed engine.
    pub fn new() -> Self {
        Self {
            bodies: BTreeMap::new(),
        }
    }

    /// The keys of every present Body.
    pub fn body_keys(&self) -> Vec<FabricKey> {
        self.bodies.keys().cloned().collect()
    }

    fn loro_err(e: impl std::fmt::Display) -> FabricError {
        FabricError::InvalidOp(e.to_string())
    }

    /// The collaborative doc for a Body, creating it when `create`. An atomic
    /// value at the key is a [`FabricError::TypeConflict`].
    fn collab_doc(
        &mut self,
        key: &FabricKey,
        create: bool,
    ) -> Result<Option<&loro::LoroDoc>, FabricError> {
        use std::collections::btree_map::Entry;
        match self.bodies.entry(key.clone()) {
            Entry::Occupied(e) => match e.into_mut() {
                BodyState::Collab(doc) => Ok(Some(doc)),
                BodyState::Atomic(_) => Err(FabricError::TypeConflict),
            },
            Entry::Vacant(v) if create => {
                let BodyState::Collab(doc) = v.insert(BodyState::Collab(new_body_doc())) else {
                    unreachable!()
                };
                Ok(Some(doc))
            }
            Entry::Vacant(_) => Ok(None),
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
    /// binding enforced. Returns the root map and the doc's peer id (for
    /// per-peer counter keys).
    fn body_for(
        &mut self,
        key: &FabricKey,
        tag: &str,
        path: &str,
    ) -> Result<(loro::LoroMap, u64), FabricError> {
        let doc = self.collab_doc(key, true)?.expect("created on demand");
        let peer = doc.peer_id();
        let body = doc.get_map(BODY_MAP);
        Self::check_path_type(&body, tag, path)?;
        Ok((body, peer))
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

    /// The causal token digesting the touched Bodies' post-commit positions.
    fn causal_for(&self, touched: &std::collections::BTreeSet<FabricKey>) -> CausalToken {
        let mut h = blake3::Hasher::new();
        h.update(CAUSAL_DOMAIN);
        for key in touched {
            h.update(&(key.as_bytes().len() as u64).to_le_bytes());
            h.update(key.as_bytes());
            match self.bodies.get(key) {
                Some(state) => {
                    let digest = state.digest();
                    h.update(&[1]);
                    h.update(&(digest.len() as u64).to_le_bytes());
                    h.update(&digest);
                }
                None => {
                    h.update(&[0]);
                }
            }
        }
        CausalToken::from_bytes(h.finalize().as_bytes().to_vec())
    }

    /// Apply one operation. Errors leave partially-applied state in the touched
    /// Body; [`Fabric::commit`] rolls the whole batch back from its backups.
    fn apply(&mut self, op: &FabricOp) -> Result<(), FabricError> {
        match op {
            FabricOp::PutCanonical { key, value } => {
                if let Some(BodyState::Collab(_)) = self.bodies.get(key) {
                    // A collaborative Body cannot be silently flattened.
                    return Err(FabricError::TypeConflict);
                }
                self.bodies
                    .insert(key.clone(), BodyState::Atomic(value.clone()));
                Ok(())
            }
            FabricOp::Remove { key } => {
                self.bodies.remove(key);
                Ok(())
            }
            FabricOp::CreateBody { key } => {
                self.collab_doc(key, true)?;
                Ok(())
            }
            FabricOp::RegisterSet { key, path, value } => {
                let (body, _) = self.body_for(key, "reg", path)?;
                body.insert(&typed_key("reg", path), value.as_slice())
                    .map_err(Self::loro_err)
            }
            FabricOp::RegisterClear { key, path } => {
                let (body, _) = self.body_for(key, "reg", path)?;
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
                let (body, _) = self.body_for(key, "map", path)?;
                let m = Self::child_map(&body, &typed_key("map", path))?;
                m.insert(entry, value.as_slice()).map_err(Self::loro_err)
            }
            FabricOp::MapRemove { key, path, entry } => {
                let (body, _) = self.body_for(key, "map", path)?;
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
                let (body, _) = self.body_for(key, "list", path)?;
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
                let (body, _) = self.body_for(key, "list", path)?;
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
                let (body, _) = self.body_for(key, "list", path)?;
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
                let (body, _) = self.body_for(key, "text", path)?;
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
                let (body, _) = self.body_for(key, "set", path)?;
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
                let (body, _) = self.body_for(key, "set", path)?;
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
                let (body, peer) = self.body_for(key, "cnt", path)?;
                let m = Self::child_map(&body, &typed_key("cnt", path))?;
                // PN-counter: each doc session sums into its own peer key;
                // concurrent increments land in disjoint keys and always sum.
                let me = peer.to_string();
                let current = crate::loro_ext::get_i64(&m, &me).unwrap_or(0);
                let next = current
                    .checked_add(*delta)
                    .ok_or_else(|| FabricError::InvalidOp("counter overflow".into()))?;
                m.insert(&me, next).map_err(Self::loro_err)
            }
        }
    }

    /// The key an operation touches.
    fn op_key(op: &FabricOp) -> &FabricKey {
        match op {
            FabricOp::PutCanonical { key, .. }
            | FabricOp::Remove { key }
            | FabricOp::CreateBody { key }
            | FabricOp::RegisterSet { key, .. }
            | FabricOp::RegisterClear { key, .. }
            | FabricOp::MapSet { key, .. }
            | FabricOp::MapRemove { key, .. }
            | FabricOp::ListInsert { key, .. }
            | FabricOp::ListRemove { key, .. }
            | FabricOp::ListMove { key, .. }
            | FabricOp::TextSplice { key, .. }
            | FabricOp::SetAdd { key, .. }
            | FabricOp::SetRemove { key, .. }
            | FabricOp::CounterAdd { key, .. } => key,
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
        // Batch atomicity: back up every Body the batch touches (by export),
        // apply, and on any error restore exactly those Bodies — a failed
        // batch changes nothing.
        let touched: std::collections::BTreeSet<FabricKey> = request
            .ops
            .iter()
            .map(|op| Self::op_key(op).clone())
            .collect();
        let mut backups: BTreeMap<FabricKey, Option<BodyExport>> = BTreeMap::new();
        for key in &touched {
            let prior = match self.bodies.get(key) {
                None => None,
                Some(state) => Some(state.export()?),
            };
            backups.insert(key.clone(), prior);
        }
        let mut failed = None;
        for op in &request.ops {
            if let Err(e) = self.apply(op) {
                failed = Some(e);
                break;
            }
        }
        if let Some(e) = failed {
            for (key, prior) in backups {
                match prior {
                    None => {
                        self.bodies.remove(&key);
                    }
                    Some(export) => match BodyState::from_export(&export) {
                        Ok(state) => {
                            self.bodies.insert(key, state);
                        }
                        Err(_) => {
                            // The rollback itself failed: the in-memory state
                            // has diverged. Fail stop.
                            return Err(FabricError::Durability(
                                "rollback after failed apply did not restore".into(),
                            ));
                        }
                    },
                }
            }
            return Err(e);
        }
        // Seal each touched collaborative doc's staged change as one labelled
        // Loro commit.
        for key in &touched {
            if let Some(BodyState::Collab(doc)) = self.bodies.get(key) {
                doc.set_next_commit_message(&request.request);
                doc.commit();
            }
        }
        Ok(FabricCommitReceipt::new(
            self.causal_for(&touched),
            request.ops.len() as u32,
        ))
    }

    fn read(&self, key: &FabricKey) -> Option<Vec<u8>> {
        match self.bodies.get(key)? {
            BodyState::Atomic(bytes) => Some(bytes.clone()),
            BodyState::Collab(_) => None,
        }
    }

    fn read_collaborative(&self, key: &FabricKey) -> Option<CollaborativeView> {
        let BodyState::Collab(doc) = self.bodies.get(key)? else {
            return None;
        };
        let body = doc.get_map(BODY_MAP);
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

    fn export_body(&self, key: &FabricKey) -> Option<BodyExport> {
        self.bodies.get(key).and_then(|s| s.export().ok())
    }

    fn import_body(
        &mut self,
        key: &FabricKey,
        export: &BodyExport,
    ) -> Result<Option<FabricCommitReceipt>, FabricError> {
        let changed = match (self.bodies.get(key), export) {
            // Atomic replacement — policy for concurrent atomic writes is
            // Replica's, decided before this call.
            (Some(BodyState::Atomic(current)), BodyExport::Atomic(bytes)) => {
                if current == bytes {
                    false
                } else {
                    self.bodies
                        .insert(key.clone(), BodyState::Atomic(bytes.clone()));
                    true
                }
            }
            (None, BodyExport::Atomic(bytes)) => {
                self.bodies
                    .insert(key.clone(), BodyState::Atomic(bytes.clone()));
                true
            }
            // Collaborative causal merge: already-known material is unchanged.
            (Some(BodyState::Collab(doc)), BodyExport::Collaborative(snapshot)) => {
                let before = doc.oplog_frontiers().encode();
                doc.import(snapshot)
                    .map_err(|e| FabricError::InvalidOp(format!("merge import: {e}")))?;
                doc.oplog_frontiers().encode() != before
            }
            (None, BodyExport::Collaborative(_)) => {
                self.bodies
                    .insert(key.clone(), BodyState::from_export(export)?);
                true
            }
            // A model mismatch at the same key is a type conflict, refused.
            (Some(BodyState::Atomic(_)), BodyExport::Collaborative(_))
            | (Some(BodyState::Collab(_)), BodyExport::Atomic(_)) => {
                return Err(FabricError::TypeConflict)
            }
        };
        if !changed {
            return Ok(None);
        }
        let mut touched = std::collections::BTreeSet::new();
        touched.insert(key.clone());
        Ok(Some(FabricCommitReceipt::new(self.causal_for(&touched), 0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_body_export_carries_exactly_one_body() {
        // Two collaborative Bodies; exporting one and importing it elsewhere
        // must bring that Body only — never a cross-Body snapshot.
        let mut a = LoroFabric::new();
        let k1 = FabricKey::from_bytes(b"body/1".to_vec());
        let k2 = FabricKey::from_bytes(b"body/2".to_vec());
        a.commit(FabricTransactionRequest::new(
            "created",
            vec![
                FabricOp::RegisterSet {
                    key: k1.clone(),
                    path: "title".into(),
                    value: b"one".to_vec(),
                },
                FabricOp::RegisterSet {
                    key: k2.clone(),
                    path: "title".into(),
                    value: b"two".to_vec(),
                },
            ],
        ))
        .unwrap();

        let export = a.export_body(&k1).unwrap();
        assert!(matches!(export, BodyExport::Collaborative(_)));
        let mut b = LoroFabric::new();
        b.import_body(&k1, &export).unwrap().unwrap();
        assert_eq!(
            b.read_collaborative(&k1).unwrap().registers["title"],
            b"one".to_vec()
        );
        assert!(
            b.read_collaborative(&k2).is_none() && b.read(&k2).is_none(),
            "the second Body did not ride along"
        );
    }

    #[test]
    fn per_body_import_preserves_stable_element_identity() {
        let mut a = LoroFabric::new();
        let k = FabricKey::from_bytes(b"body/ids".to_vec());
        a.commit(FabricTransactionRequest::new(
            "created",
            vec![FabricOp::ListInsert {
                key: k.clone(),
                path: "items".into(),
                index: 0,
                value: b"x".to_vec(),
            }],
        ))
        .unwrap();
        let element = a.read_collaborative(&k).unwrap().lists["items"][0]
            .element
            .clone();

        // B imports the Body and removes the element BY THE SAME STABLE ID.
        let mut b = LoroFabric::new();
        b.import_body(&k, &a.export_body(&k).unwrap()).unwrap();
        b.commit(FabricTransactionRequest::new(
            "removed",
            vec![FabricOp::ListRemove {
                key: k.clone(),
                path: "items".into(),
                element,
            }],
        ))
        .unwrap();
        assert!(b.read_collaborative(&k).unwrap().lists["items"].is_empty());
    }

    #[test]
    fn reimporting_known_material_is_unchanged() {
        let mut a = LoroFabric::new();
        let k = FabricKey::from_bytes(b"body/known".to_vec());
        a.commit(FabricTransactionRequest::new(
            "created",
            vec![FabricOp::CounterAdd {
                key: k.clone(),
                path: "votes".into(),
                delta: 2,
            }],
        ))
        .unwrap();
        let export = a.export_body(&k).unwrap();
        let mut b = LoroFabric::new();
        assert!(b.import_body(&k, &export).unwrap().is_some(), "new");
        assert!(
            b.import_body(&k, &export).unwrap().is_none(),
            "already known — no receipt, nothing changed"
        );
        // Atomic idempotence too.
        let ak = FabricKey::from_bytes(b"body/atomic".to_vec());
        let atomic = BodyExport::Atomic(b"v1".to_vec());
        assert!(b.import_body(&ak, &atomic).unwrap().is_some());
        assert!(b.import_body(&ak, &atomic).unwrap().is_none());
    }

    #[test]
    fn a_model_mismatch_at_the_same_key_is_a_type_conflict() {
        let mut f = LoroFabric::new();
        let k = FabricKey::from_bytes(b"body/mismatch".to_vec());
        f.commit(FabricTransactionRequest::new(
            "created",
            vec![FabricOp::PutCanonical {
                key: k.clone(),
                value: b"atomic".to_vec(),
            }],
        ))
        .unwrap();
        // A collaborative export addressed at an atomic key is refused.
        let mut other = LoroFabric::new();
        other
            .commit(FabricTransactionRequest::new(
                "created",
                vec![FabricOp::CounterAdd {
                    key: k.clone(),
                    path: "votes".into(),
                    delta: 1,
                }],
            ))
            .unwrap();
        let collab = other.export_body(&k).unwrap();
        assert_eq!(
            f.import_body(&k, &collab).unwrap_err(),
            FabricError::TypeConflict
        );
        assert_eq!(f.read(&k).as_deref(), Some(&b"atomic"[..]), "unchanged");
    }

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
    fn atomic_bodies_commit_read_remove_and_advance_the_causal_token() {
        let mut fabric = LoroFabric::new();
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
