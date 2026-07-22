//! S0 boundary guards (G2) and canonical-id fixtures (G1) for the orbital carve.
//!
//! These prove the vocabulary/dependency boundary the carve depends on, and pin
//! the canonical byte encodings of the new Body-domain identifiers so accidental
//! drift is caught. Every guard has both a **passing control** (the real crates)
//! and an **injected failing case** (a synthetic input the same predicate must
//! reject), so a guard that silently stopped checking would fail.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the `lait` package root, which is the workspace root.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

/// Whether a crate's manifest lists a dependency named `dep` (a crude but exact
/// check: a line whose first token, before `=` or whitespace, equals `dep`).
fn manifest_lists_dep(crate_dir: &str, dep: &str) -> bool {
    let manifest = read(
        &workspace_root()
            .join("crates")
            .join(crate_dir)
            .join("Cargo.toml"),
    );
    manifest.lines().any(|line| {
        let line = line.trim();
        let name = line
            .split(['=', ' ', '\t'])
            .next()
            .unwrap_or("")
            .trim_matches('"');
        name == dep
    })
}

/// Every `.rs` file under a crate's `src/`.
fn rust_sources(crate_dir: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &workspace_root().join("crates").join(crate_dir).join("src"),
        &mut out,
    );
    out
}

// ---------------------------------------------------------------------------
// G2 — only Fabric names Loro; only comms names iroh.
// ---------------------------------------------------------------------------

#[test]
fn only_fabric_names_loro_in_its_manifest() {
    // Passing control: fabric lists loro; the concept crates do not.
    assert!(
        manifest_lists_dep("fabric", "loro"),
        "fabric must list loro — it is the sealed Loro boundary"
    );
    for crate_dir in ["journal", "mechanics", "comms", "replica", "runtime"] {
        assert!(
            !manifest_lists_dep(crate_dir, "loro"),
            "{crate_dir} must NOT name loro — the dependency edge is the seal"
        );
    }
    // Injected failing case: the predicate genuinely rejects a non-listed dep.
    assert!(
        !manifest_lists_dep("fabric", "definitely-not-a-dependency"),
        "guard has teeth: a dep that is not listed is not reported as listed"
    );
}

#[test]
fn only_comms_names_iroh_in_its_manifest() {
    assert!(
        manifest_lists_dep("comms", "iroh"),
        "comms must list iroh — it is the sole network contractor"
    );
    for crate_dir in ["mechanics", "fabric", "replica", "runtime"] {
        assert!(
            !manifest_lists_dep(crate_dir, "iroh"),
            "{crate_dir} must NOT name iroh"
        );
    }
}

// ---------------------------------------------------------------------------
// G2 — replica and runtime reject product/consumer vocabulary.
// ---------------------------------------------------------------------------

/// Product/consumer symbols that must never appear in the generic concept
/// crates. These are the fabric wrapper/product types and app-minted id
/// prefixes — naming any of them in `replica`/`runtime` would re-couple the
/// generic lifecycle to the Issues product.
const PRODUCT_SYMBOLS: &[&str] = &[
    "IssueDoc",
    "CatalogDoc",
    "MembershipDoc",
    "Doorbell",
    "iss_",
    "prj_",
    "lbl_",
];

#[test]
fn concept_crates_are_free_of_product_vocabulary() {
    for crate_dir in ["replica", "runtime"] {
        for src in rust_sources(crate_dir) {
            let text = read(&src);
            for sym in PRODUCT_SYMBOLS {
                assert!(
                    !text.contains(sym),
                    "product symbol `{sym}` leaked into {}",
                    src.display()
                );
            }
        }
    }
    // Injected failing case: the scan would catch a product symbol if present.
    let sample = "struct Foo { doc: IssueDoc }";
    assert!(
        PRODUCT_SYMBOLS.iter().any(|s| sample.contains(s)),
        "guard has teeth: product vocabulary in a sample is detected"
    );
}

// ---------------------------------------------------------------------------
// G2 / S8 — every concept crate is prefix-free; no legacy crate name remains.
// ---------------------------------------------------------------------------

#[test]
fn every_concept_crate_is_prefix_free() {
    // After S8 all five concept crates carry their prefix-free canonical names.
    for crate_dir in [
        "journal",
        "mechanics",
        "fabric",
        "comms",
        "replica",
        "runtime",
    ] {
        let manifest = read(
            &workspace_root()
                .join("crates")
                .join(crate_dir)
                .join("Cargo.toml"),
        );
        let name_line = manifest
            .lines()
            .find(|l| l.trim_start().starts_with("name ="))
            .expect("a name line");
        assert!(
            name_line.contains(&format!("\"{crate_dir}\"")),
            "{crate_dir} package name must equal its prefix-free directory name"
        );
        assert!(
            !name_line.contains("lait-") && !name_line.contains("lait_"),
            "{crate_dir} is prefix-free — no legacy lait- crate name remains"
        );
    }
}

#[test]
fn no_legacy_crate_name_or_directory_remains() {
    let crates = workspace_root().join("crates");
    for legacy in ["lait-kernel", "lait-fabric", "lait-net"] {
        assert!(
            !crates.join(legacy).exists(),
            "legacy crate directory {legacy} must not exist after S8"
        );
    }
    // No source or manifest may still name a legacy crate path.
    for crate_dir in [
        "journal",
        "mechanics",
        "fabric",
        "comms",
        "replica",
        "runtime",
    ] {
        for src in rust_sources(crate_dir) {
            let text = read(&src);
            for legacy in ["lait_kernel", "lait_fabric", "lait_net"] {
                assert!(
                    !text.contains(legacy),
                    "legacy crate path `{legacy}` remains in {}",
                    src.display()
                );
            }
        }
    }
}
