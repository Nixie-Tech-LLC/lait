//! Manifest v1 fixtures: canonical roundtrip, signature binding, page
//! substitution/omission/reorder, ordering violations within and across pages,
//! valid concurrent roots coexisting, replay dedup, and same-coordinate
//! equivocation.

use lait_kernel::ids::SpaceId;
use replica::frontier::AuthorityFrontier as AF;
use replica::frontier::{AuthorityFrontier, ReplicaFrontier};
use replica::ids::{BodyId, BodyKey, WorldId};
use replica::manifest::{
    ManifestBook, ManifestEntryV1, ManifestError, ManifestPageV1, ManifestRootV1, RootObservation,
};
use replica::transaction::AuthoritySource;

const SIGNER_KEY_SEED: [u8; 32] = SIGNER_SEED;

/// A mechanics view that authorizes both test signer seeds.
struct BothSigners;
impl AuthoritySource for BothSigners {
    fn signer_authorized(&self, signer: &[u8; 32], _f: &AF) -> bool {
        let s1 = lait_kernel::crypto::device_from_seed(&SIGNER_KEY_SEED)
            .key_bytes()
            .unwrap();
        let s2 = lait_kernel::crypto::device_from_seed(&OTHER_SEED)
            .key_bytes()
            .unwrap();
        *signer == s1 || *signer == s2
    }
}

const SIGNER_SEED: [u8; 32] = [81u8; 32];
const OTHER_SEED: [u8; 32] = [82u8; 32];

fn space() -> SpaceId {
    SpaceId::from_digest([12u8; 16])
}

fn frontier(n: u64) -> ReplicaFrontier {
    ReplicaFrontier::new([n as u8; 32], n)
}

fn auth() -> AuthorityFrontier {
    AuthorityFrontier::from_canonical_bytes(vec![1])
}

fn entry(n: u8) -> ManifestEntryV1 {
    ManifestEntryV1 {
        key: BodyKey::new(
            WorldId::parse("com.example.notes").unwrap(),
            BodyId::from_bytes([n; 16]),
        ),
        descriptor_hash: [n; 32],
        transaction_commitment: [n; 32],
    }
}

fn page(index: u32, entries: Vec<ManifestEntryV1>) -> ManifestPageV1 {
    ManifestPageV1::new(&space(), index, entries).unwrap()
}

/// A two-page manifest with globally increasing keys: [1,2] then [3,4].
fn valid_manifest() -> (ManifestRootV1, Vec<ManifestPageV1>) {
    let pages = vec![
        page(0, vec![entry(1), entry(2)]),
        page(1, vec![entry(3), entry(4)]),
    ];
    let root = ManifestRootV1::sign(&space(), frontier(1), &pages, auth(), &SIGNER_SEED).unwrap();
    (root, pages)
}

#[test]
fn a_valid_manifest_verifies_root_and_pages() {
    let (root, pages) = valid_manifest();
    root.verify().unwrap();
    root.verify_pages(&pages).unwrap();
    // Canonical roundtrip.
    let back = ManifestRootV1::decode_canonical(&root.encode()).unwrap();
    assert_eq!(back, root);
    let pback = ManifestPageV1::decode_canonical(&pages[0].encode()).unwrap();
    assert_eq!(pback, pages[0]);
}

#[test]
fn tampering_breaks_the_signature() {
    let (mut root, _) = valid_manifest();
    root.replica_frontier = frontier(9);
    assert_eq!(root.verify(), Err(ManifestError::BadSignature));

    let (mut root, _) = valid_manifest();
    root.signature[0] ^= 0xff;
    assert_eq!(root.verify(), Err(ManifestError::BadSignature));
}

#[test]
fn pages_root_and_count_must_bind_the_hashes() {
    let (mut root, _) = valid_manifest();
    root.page_count = 1; // disagrees with ordered_page_hashes.len()
    assert_eq!(root.verify(), Err(ManifestError::PagesRootMismatch));

    let (mut root, _) = valid_manifest();
    root.pages_root = [0xEE; 32];
    assert_eq!(root.verify(), Err(ManifestError::PagesRootMismatch));
}

#[test]
fn page_substitution_omission_and_reorder_fail() {
    let (root, pages) = valid_manifest();

    // Substitution: a different page in slot 0.
    let mut substituted = pages.clone();
    substituted[0] = page(0, vec![entry(1), entry(2), entry(3)]);
    assert!(matches!(
        root.verify_pages(&substituted),
        Err(ManifestError::PageNotInRoot) | Err(ManifestError::OrderViolation)
    ));

    // Omission: fewer pages than the root commits to.
    assert_eq!(
        root.verify_pages(&pages[..1]),
        Err(ManifestError::PageNotInRoot)
    );

    // Reorder: swapped pages fail their slots.
    let mut reordered = pages.clone();
    reordered.swap(0, 1);
    assert_eq!(
        root.verify_pages(&reordered),
        Err(ManifestError::PageNotInRoot)
    );
}

#[test]
fn entry_order_is_strict_within_and_across_pages() {
    // Unsorted within a page.
    let bad = vec![page(0, vec![entry(2), entry(1)])];
    let root = ManifestRootV1::sign(&space(), frontier(1), &bad, auth(), &SIGNER_SEED).unwrap();
    root.verify().unwrap();
    assert_eq!(root.verify_pages(&bad), Err(ManifestError::OrderViolation));

    // Duplicate across the boundary: page 1 starts at the key page 0 ended on.
    let dup = vec![
        page(0, vec![entry(1), entry(2)]),
        page(1, vec![entry(2), entry(3)]),
    ];
    let root = ManifestRootV1::sign(&space(), frontier(1), &dup, auth(), &SIGNER_SEED).unwrap();
    assert_eq!(root.verify_pages(&dup), Err(ManifestError::OrderViolation));

    // Regression across the boundary.
    let regress = vec![
        page(0, vec![entry(3), entry(4)]),
        page(1, vec![entry(1), entry(2)]),
    ];
    let root = ManifestRootV1::sign(&space(), frontier(1), &regress, auth(), &SIGNER_SEED).unwrap();
    assert_eq!(
        root.verify_pages(&regress),
        Err(ManifestError::OrderViolation)
    );
}

#[test]
fn concurrent_roots_coexist_and_replays_dedupe() {
    let mut book = ManifestBook::new();
    let (root_a, _) = valid_manifest();

    // A different signer at its own coordinate coexists.
    let pages_b = vec![page(0, vec![entry(7)])];
    let root_b =
        ManifestRootV1::sign(&space(), frontier(2), &pages_b, auth(), &OTHER_SEED).unwrap();

    assert_eq!(
        book.observe(&root_a.clone().verify_authorized(&BothSigners).unwrap())
            .unwrap(),
        RootObservation::Accepted
    );
    assert_eq!(
        book.observe(&root_b.verify_authorized(&BothSigners).unwrap())
            .unwrap(),
        RootObservation::Accepted
    );
    assert_eq!(book.len(), 2, "incomparable roots coexist");

    // The same signer at a NEW coordinate is a new root, not equivocation.
    let (advanced, _) = {
        let pages = vec![page(0, vec![entry(1)])];
        (
            ManifestRootV1::sign(&space(), frontier(3), &pages, auth(), &SIGNER_SEED).unwrap(),
            pages,
        )
    };
    assert_eq!(
        book.observe(&advanced.verify_authorized(&BothSigners).unwrap())
            .unwrap(),
        RootObservation::Accepted
    );

    // An exact replay dedupes.
    assert_eq!(
        book.observe(&root_a.verify_authorized(&BothSigners).unwrap())
            .unwrap(),
        RootObservation::AlreadyKnown
    );
    assert_eq!(book.len(), 3);
}

#[test]
fn same_coordinate_equivocation_is_rejected() {
    let mut book = ManifestBook::new();
    let (root_a, _) = valid_manifest();
    book.observe(&root_a.verify_authorized(&BothSigners).unwrap())
        .unwrap();

    // The SAME signer signs a DIFFERENT Body set at the SAME frontier
    // coordinate: that is equivocation, rejected and reportable.
    let other_pages = vec![page(0, vec![entry(9)])];
    let equivocating =
        ManifestRootV1::sign(&space(), frontier(1), &other_pages, auth(), &SIGNER_SEED).unwrap();
    assert_eq!(
        book.observe(&equivocating.verify_authorized(&BothSigners).unwrap()),
        Err(ManifestError::Equivocation)
    );
    // The first-seen root is retained.
    assert_eq!(book.len(), 1);
}

#[test]
fn a_root_without_authority_cannot_enter_the_book() {
    // Structurally valid + correctly signed, but the signer has no standing:
    // verify_authorized refuses, so the coordinate can never be poisoned.
    let (root, _) = valid_manifest();
    root.verify().unwrap();
    struct Nobody;
    impl AuthoritySource for Nobody {
        fn signer_authorized(&self, _s: &[u8; 32], _f: &AF) -> bool {
            false
        }
    }
    assert_eq!(
        root.clone().verify_authorized(&Nobody),
        Err(ManifestError::AuthorityUnverified)
    );
    // With authority, it becomes an AuthorizedRoot the book accepts.
    let authorized = root.verify_authorized(&BothSigners).unwrap();
    let mut book = ManifestBook::new();
    assert_eq!(
        book.observe(&authorized).unwrap(),
        RootObservation::Accepted
    );
}

#[test]
fn version_and_space_mismatches_are_typed() {
    let (mut root, _) = valid_manifest();
    root.version = 2;
    assert_eq!(root.verify(), Err(ManifestError::UnsupportedVersion(2)));

    // A page from another Space cannot satisfy this root.
    let (root, _) = valid_manifest();
    let foreign_space = SpaceId::from_digest([99u8; 16]);
    let foreign = vec![
        ManifestPageV1::new(&foreign_space, 0, vec![entry(1), entry(2)]).unwrap(),
        ManifestPageV1::new(&foreign_space, 1, vec![entry(3), entry(4)]).unwrap(),
    ];
    assert!(matches!(
        root.verify_pages(&foreign),
        Err(ManifestError::SpaceMismatch) | Err(ManifestError::PageNotInRoot)
    ));
}
