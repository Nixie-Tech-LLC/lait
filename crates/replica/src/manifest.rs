//! Manifest v1 — the signed, paged commitment to a Replica's Body set
//! (`lait/manifest/1`).
//!
//! A manifest root binds a Space, a Replica frontier, and an ordered list of
//! page hashes under an admitted Station's signature; pages carry the
//! BodyKey-sorted entries (descriptor hash + transaction commitment per Body).
//! The ordered page hashes commit order, omission, and page count; across
//! page-index order, entries are **globally strictly increasing** by BodyKey —
//! every page's first key must exceed the previous page's last key, and no
//! BodyKey appears twice. Page-boundary overlap or regression rejects the root.
//!
//! **Binding without circularity.** A page cannot embed its root's hash (the
//! root commits to page hashes, so the reference would be circular). A page is
//! instead bound *relationally*: its canonical hash must equal the root's
//! ordered page hash at its index. Substituted, omitted, or reordered pages
//! therefore fail against the signed root.
//!
//! **Concurrency and equivocation.** Incomparable concurrent roots coexist —
//! Convergence unions their valid transactions before emitting a new local
//! root. *Equivocation* is two **different** roots by the same signer at the
//! same semantic transaction coordinate (Replica frontier); [`ManifestBook`]
//! rejects and reports it. Full dominance ordering ("a strictly dominated root
//! is stale") requires the Manifest transaction references the S5 store
//! integration adds; until then the book safely treats unordered roots as
//! concurrent (union) and dedupes exact replays.

use mechanics::ids::SpaceId;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::frontier::{AuthorityFrontier, ReplicaFrontier};
use crate::ids::BodyKey;

/// Root signature domain.
pub const MANIFEST_DOMAIN: &[u8] = b"lait/manifest/1";
/// Page hash domain.
pub const PAGE_DOMAIN: &[u8] = b"lait/manifest/1/page";
/// Pages-root domain (over the ordered page hashes).
pub const PAGES_ROOT_DOMAIN: &[u8] = b"lait/manifest/1/pages-root";
/// Ed25519 algorithm tag.
pub const SIG_ALG_ED25519: u8 = 1;
/// Maximum entries per page.
pub const MAX_ENTRIES_PER_PAGE: usize = 4096;
/// Maximum pages per manifest.
pub const MAX_PAGES: usize = 4096;
/// Maximum encoded page size (1 MiB).
pub const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// The fixed rendered-SpaceId length.
pub const SPACE_ID_LEN: usize = 29;

/// One Body's manifest entry: its key, the hash of its public descriptor, and
/// the commitment to its signed BodyTransaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestEntryV1 {
    pub key: BodyKey,
    pub descriptor_hash: [u8; 32],
    pub transaction_commitment: [u8; 32],
}

/// One manifest page: BodyKey-sorted entries for a slice of the Body set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestPageV1 {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    pub page_index: u32,
    pub entries: Vec<ManifestEntryV1>,
}

/// The signed manifest root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestRootV1 {
    pub version: u8,
    pub space: [u8; SPACE_ID_LEN],
    pub replica_frontier: ReplicaFrontier,
    pub page_count: u32,
    pub ordered_page_hashes: Vec<[u8; 32]>,
    pub pages_root: [u8; 32],
    pub signer: [u8; 32],
    pub authority_frontier: AuthorityFrontier,
    pub signature_algorithm: u8,
    #[serde(with = "serde_byte_array")]
    pub signature: [u8; 64],
}

/// Why a manifest failed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestError {
    UnsupportedVersion(u8),
    UnsupportedSignatureAlgorithm(u8),
    NonCanonical,
    BadSpaceId,
    /// Page/entry counts or sizes exceed the frozen bounds.
    Bounds,
    /// `pages_root`/`page_count` disagree with the ordered page hashes.
    PagesRootMismatch,
    /// A page's hash does not match the signed root's slot for its index.
    PageNotInRoot,
    /// Entries are unsorted or duplicated within a page, or a page boundary
    /// overlaps/regresses the previous page's keys.
    OrderViolation,
    /// A page's Space disagrees with the root's.
    SpaceMismatch,
    BadSignature,
    /// Two different roots by the same signer at the same frontier coordinate.
    Equivocation,
    /// Structurally valid and correctly signed, but the signer had no standing
    /// at the root's authority frontier.
    AuthorityUnverified,
}

impl std::fmt::Display for ManifestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for ManifestError {}

fn length_framed(domain: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + domain.len() + 4 + body.len());
    out.extend_from_slice(&(domain.len() as u16).to_be_bytes());
    out.extend_from_slice(domain);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    out
}

impl ManifestPageV1 {
    pub fn new(space: &SpaceId, page_index: u32, entries: Vec<ManifestEntryV1>) -> Option<Self> {
        Some(Self {
            version: 1,
            space: <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()?,
            page_index,
            entries,
        })
    }

    /// Canonical page bytes.
    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard manifest page")
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ManifestError> {
        if bytes.len() > MAX_PAGE_BYTES {
            return Err(ManifestError::Bounds);
        }
        let page: Self = postcard::from_bytes(bytes).map_err(|_| ManifestError::NonCanonical)?;
        if page.encode() != bytes {
            return Err(ManifestError::NonCanonical);
        }
        Ok(page)
    }

    /// The domain-separated hash the root commits to for this page.
    pub fn hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(PAGE_DOMAIN);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Structural validation: version, bounds, strict internal BodyKey order.
    pub fn validate(&self) -> Result<(), ManifestError> {
        if self.version != 1 {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }
        std::str::from_utf8(&self.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or(ManifestError::BadSpaceId)?;
        if self.entries.len() > MAX_ENTRIES_PER_PAGE || self.encode().len() > MAX_PAGE_BYTES {
            return Err(ManifestError::Bounds);
        }
        for w in self.entries.windows(2) {
            if w[0].key >= w[1].key {
                return Err(ManifestError::OrderViolation);
            }
        }
        Ok(())
    }
}

/// The commitment over the ordered page hashes.
pub fn pages_root(ordered_page_hashes: &[[u8; 32]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(PAGES_ROOT_DOMAIN);
    for ph in ordered_page_hashes {
        h.update(ph);
    }
    *h.finalize().as_bytes()
}

impl ManifestRootV1 {
    fn preimage(&self) -> Vec<u8> {
        let body = postcard::to_stdvec(&(
            self.version,
            self.space,
            self.replica_frontier,
            self.page_count,
            &self.ordered_page_hashes,
            self.pages_root,
            self.signer,
            &self.authority_frontier,
        ))
        .expect("postcard manifest root preimage");
        length_framed(MANIFEST_DOMAIN, &body)
    }

    /// Build and sign a root over already-validated pages. Any admitted Station
    /// may sign; mechanics validates its standing at the authority frontier
    /// (separately, like every signed object).
    pub fn sign(
        space: &SpaceId,
        replica_frontier: ReplicaFrontier,
        pages: &[ManifestPageV1],
        authority_frontier: AuthorityFrontier,
        signer_seed: &[u8; 32],
    ) -> Option<Self> {
        let signer = mechanics::crypto::device_from_seed(signer_seed).key_bytes()?;
        let hashes: Vec<[u8; 32]> = pages.iter().map(|p| p.hash()).collect();
        let mut root = Self {
            version: 1,
            space: <[u8; SPACE_ID_LEN]>::try_from(space.as_str().as_bytes()).ok()?,
            replica_frontier,
            page_count: hashes.len() as u32,
            pages_root: pages_root(&hashes),
            ordered_page_hashes: hashes,
            signer,
            authority_frontier,
            signature_algorithm: SIG_ALG_ED25519,
            signature: [0u8; 64],
        };
        root.signature = mechanics::crypto::sign_detached(signer_seed, &root.preimage());
        Some(root)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).expect("postcard manifest root")
    }

    pub fn decode_canonical(bytes: &[u8]) -> Result<Self, ManifestError> {
        let root: Self = postcard::from_bytes(bytes).map_err(|_| ManifestError::NonCanonical)?;
        if root.encode() != bytes {
            return Err(ManifestError::NonCanonical);
        }
        Ok(root)
    }

    /// Verify the root itself: version, algorithm, Space shape, bounds,
    /// pages-root binding, and the Station signature. (Signer standing at the
    /// authority frontier is mechanics' separate check.)
    pub fn verify(&self) -> Result<(), ManifestError> {
        if self.version != 1 {
            return Err(ManifestError::UnsupportedVersion(self.version));
        }
        if self.signature_algorithm != SIG_ALG_ED25519 {
            return Err(ManifestError::UnsupportedSignatureAlgorithm(
                self.signature_algorithm,
            ));
        }
        std::str::from_utf8(&self.space)
            .ok()
            .and_then(SpaceId::parse)
            .ok_or(ManifestError::BadSpaceId)?;
        if self.ordered_page_hashes.len() > MAX_PAGES {
            return Err(ManifestError::Bounds);
        }
        if self.page_count as usize != self.ordered_page_hashes.len()
            || self.pages_root != pages_root(&self.ordered_page_hashes)
        {
            return Err(ManifestError::PagesRootMismatch);
        }
        if !mechanics::crypto::verify_detached(&self.signer, &self.preimage(), &self.signature) {
            return Err(ManifestError::BadSignature);
        }
        Ok(())
    }

    /// Verify a complete page set against this (already-verified) root:
    /// per-page structure and hash membership at the right index, Space
    /// agreement, and **global** strict BodyKey order across page boundaries.
    pub fn verify_pages(&self, pages: &[ManifestPageV1]) -> Result<(), ManifestError> {
        if pages.len() != self.ordered_page_hashes.len() {
            return Err(ManifestError::PageNotInRoot);
        }
        let mut last_key: Option<&BodyKey> = None;
        for (i, page) in pages.iter().enumerate() {
            page.validate()?;
            if page.space != self.space {
                return Err(ManifestError::SpaceMismatch);
            }
            if page.page_index as usize != i || page.hash() != self.ordered_page_hashes[i] {
                return Err(ManifestError::PageNotInRoot);
            }
            if let (Some(prev), Some(first)) = (last_key, page.entries.first()) {
                // Every page's first key must exceed the previous page's last.
                if &first.key <= prev {
                    return Err(ManifestError::OrderViolation);
                }
            }
            if let Some(last) = page.entries.last() {
                last_key = Some(&last.key);
            }
        }
        Ok(())
    }

    /// The equivocation coordinate: one signer may publish at most one root per
    /// semantic transaction coordinate.
    pub fn coordinate(&self) -> ([u8; 32], ReplicaFrontier) {
        (self.signer, self.replica_frontier)
    }

    /// A stable identity for this exact signed root.
    pub fn root_hash(&self) -> [u8; 32] {
        let mut h = blake3::Hasher::new();
        h.update(MANIFEST_DOMAIN);
        h.update(&self.encode());
        *h.finalize().as_bytes()
    }

    /// Full verification for retention: the structural [`Self::verify`] **and**
    /// the mechanics authority check — the signer must have had standing at the
    /// root's authority frontier. This is the **only** way to mint an
    /// [`AuthorizedRoot`], and [`ManifestBook`] accepts nothing else, so an
    /// unverified or unauthorized root can never poison a signer's coordinate.
    pub fn verify_authorized(
        self,
        authority: &dyn crate::transaction::AuthoritySource,
    ) -> Result<AuthorizedRoot, ManifestError> {
        self.verify()?;
        if !authority.signer_authorized(&self.signer, &self.authority_frontier) {
            return Err(ManifestError::AuthorityUnverified);
        }
        Ok(AuthorizedRoot { root: self })
    }
}

/// A manifest root whose structure, signature, **and signer authority** have
/// been verified. Constructible only through
/// [`ManifestRootV1::verify_authorized`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRoot {
    root: ManifestRootV1,
}

impl AuthorizedRoot {
    pub fn root(&self) -> &ManifestRootV1 {
        &self.root
    }
}

/// How [`ManifestBook::observe`] classified a verified root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootObservation {
    /// A new root; it coexists with other known roots until Convergence unions.
    Accepted,
    /// An exact replay of an already-known root.
    AlreadyKnown,
}

/// The per-Space record of observed manifest roots, keyed by signer +
/// frontier coordinate. Detects equivocation (two different roots by the same
/// signer at the same coordinate) and dedupes replays. It never deletes roots —
/// incomparable concurrent roots coexist by design.
#[derive(Debug, Default)]
pub struct ManifestBook {
    /// Keyed by `(signer, frontier root, frontier count)` — raw bytes, so no
    /// ordering semantics are implied for frontiers (they are equality tokens).
    seen: BTreeMap<([u8; 32], [u8; 32], u64), [u8; 32]>,
}

impl ManifestBook {
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe an authority-verified root — the type makes verification
    /// non-optional. Equivocation is rejected and reported; the caller audits
    /// it (the book keeps the first-seen root).
    pub fn observe(&mut self, root: &AuthorizedRoot) -> Result<RootObservation, ManifestError> {
        let root = root.root();
        let (signer, frontier) = root.coordinate();
        let coordinate = (signer, frontier.root, frontier.transaction_count);
        let hash = root.root_hash();
        match self.seen.get(&coordinate) {
            Some(known) if *known == hash => Ok(RootObservation::AlreadyKnown),
            Some(_) => Err(ManifestError::Equivocation),
            None => {
                self.seen.insert(coordinate, hash);
                Ok(RootObservation::Accepted)
            }
        }
    }

    /// The number of distinct roots observed.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}
