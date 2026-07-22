//! Mixed-root safety as an EXECUTABLE architectural invariant, not prose.
//!
//! Today the product daemon serves every response from one docked Session
//! snapshot — the runtime holds the replica lock across a query and stamps the
//! projection with the frontier it was derived from (`independent_world` and
//! `world_policy` prove root labeling and the frontier compare-and-swap at
//! that layer). There is NO derived product cache, memoized projection, or
//! materialized view in the product layer, so a mixed-root output is not
//! constructible at this surface.
//!
//! This gate keeps that claim honest: the day someone introduces product-layer
//! caching, this scan fires and refuses the build until the cache is
//! REGISTERED here with (a) the complete root tuple it is keyed by and (b) the
//! name of a test proving a lookup keyed at one root can never serve bytes
//! derived at another (the mixed-root injection test the plans require).

use std::path::{Path, PathBuf};

/// Registered product-layer caches: `(identifier, keyed-by, mixed-root test)`.
/// An entry added here must name a `#[test]` that exists.
///
/// The ONE registered cache is the IssuesWorld derived read model
/// (`src/world/issues.rs`): its snapshot entries are keyed by the EXACT
/// Manifest root the query context is pinned to (a hit is only ever the same
/// root, so mixed-root output is unrepresentable), and its per-issue parse
/// memo is reusable across roots only under a reader-issued Body version
/// stamp whose equality guarantees byte-equivalent Bodies.
const REGISTERED_CACHES: &[(&str, &str, &str)] = &[
    (
        "RootKeyedCache",
        "snapshot: exact [u8; 32] Manifest root; per-issue memo: Body version stamp (chain frontier + sorted head transaction commitments)",
        "the_issues_world_cache_never_serves_across_roots",
    ),
    (
        "cache",
        "field of IssuesWorld holding the RootKeyedCache",
        "the_issues_world_cache_never_serves_across_roots",
    ),
    (
        "CACHED_ROOTS",
        "the bound on warm roots (current + previous)",
        "the_issues_world_cache_never_serves_across_roots",
    ),
    (
        "cached_stamp",
        "the per-issue memo's stamp comparand",
        "the_issues_world_cache_never_serves_across_roots",
    ),
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The product layer: the daemon, the World adapter, and the serve/MCP
/// surfaces — everywhere a derived cache could shortcut the Session.
fn product_sources() -> Vec<PathBuf> {
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
    walk(&workspace_root().join("src"), &mut out);
    out.sort();
    out
}

/// Strip line comments and string-literal contents, so prose about caching
/// (doc comments, CLI help strings) never fires — only CODE identifiers do.
fn code_only(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("");
        let mut in_str = false;
        let mut escaped = false;
        for c in line.chars() {
            if in_str {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '"' {
                    in_str = false;
                    out.push(' ');
                }
                continue;
            }
            if c == '"' {
                in_str = true;
                out.push(' ');
                continue;
            }
            out.push(c);
        }
        out.push('\n');
    }
    out
}

/// Identifier-level cache markers over CODE (comments and string literals
/// stripped): a doc line discussing caching does not fire, a `board_cache`
/// field or `MemoizedRows` type does.
fn cache_identifiers(text: &str) -> Vec<String> {
    let code = code_only(text);
    let mut out = Vec::new();
    let mut ident = String::new();
    for c in code.chars().chain(std::iter::once(' ')) {
        if c.is_ascii_alphanumeric() || c == '_' {
            ident.push(c);
            continue;
        }
        if !ident.is_empty() {
            let lower = ident.to_ascii_lowercase();
            if (lower.contains("cache")
                || lower.contains("memoiz")
                || lower.contains("materialized"))
                && !lower.contains("cachedir")
            {
                out.push(ident.clone());
            }
            ident.clear();
        }
    }
    out.sort();
    out.dedup();
    out
}

#[test]
fn any_product_cache_must_register_with_a_mixed_root_proof() {
    let root = workspace_root();
    let mut unregistered: Vec<String> = Vec::new();
    for file in product_sources() {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        for ident in cache_identifiers(&text) {
            let registered = REGISTERED_CACHES.iter().any(|(id, _, _)| *id == ident);
            if !registered {
                unregistered.push(format!("{rel}: `{ident}`"));
            }
        }
    }
    assert!(
        unregistered.is_empty(),
        "product-layer cache identifiers without a registered mixed-root proof:\n  {}\n\
         Register each in tests/mixed_root_guard.rs with the complete root tuple it is \
         keyed by and the name of its mixed-root rejection test — a derived cache that \
         is not keyed by its exact Manifest root can serve output mixing two roots.",
        unregistered.join("\n  ")
    );
}

#[test]
fn every_registered_cache_names_a_real_test() {
    // A registration must point at a test that exists somewhere in tests/**;
    // a dangling name would let the registry rot into prose.
    let tests_dir = workspace_root().join("tests");
    let mut all_tests = String::new();
    if let Ok(entries) = std::fs::read_dir(&tests_dir) {
        for entry in entries.flatten() {
            if entry.path().extension().and_then(|e| e.to_str()) == Some("rs") {
                all_tests.push_str(&std::fs::read_to_string(entry.path()).unwrap_or_default());
            }
        }
    }
    for (id, keyed_by, test) in REGISTERED_CACHES {
        assert!(
            !keyed_by.is_empty(),
            "cache `{id}` must document its complete root-tuple key"
        );
        assert!(
            all_tests.contains(&format!("fn {test}")),
            "cache `{id}` names mixed-root test `{test}`, which does not exist"
        );
    }
}

#[test]
fn the_detector_has_teeth() {
    assert_eq!(
        cache_identifiers("struct BoardCache { entries: Vec<u8> }"),
        vec!["BoardCache".to_string()]
    );
    assert_eq!(
        cache_identifiers("let memoized_rows = compute();"),
        vec!["memoized_rows".to_string()]
    );
    assert!(
        cache_identifiers("// discussing a cache in prose does not fire").is_empty(),
        "comments are not code"
    );
    assert!(
        cache_identifiers("let help = \"rows from the catalog cache\";").is_empty(),
        "string literals are not code"
    );
    assert!(cache_identifiers("fn compute_rows() {}").is_empty());
}
