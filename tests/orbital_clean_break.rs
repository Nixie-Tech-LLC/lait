//! M0.1 — the clean-break red gate.
//!
//! Scans every production source (the `lait` package's `src/**`, each concept
//! crate's `src/**`, every manifest, and build scripts) for legacy-architecture
//! symbols, modules, paths, and naming-policy violations. A checked-in
//! structured allowlist (`tests/clean_break_allowlist.tsv`) names every
//! violation that is *known and owned by a deletion phase*; the gate fails for
//! any violation that is not allowlisted, and for any allowlist entry that no
//! longer matches (stale entries must be pruned as the purge proceeds).
//!
//! M5 empties the allowlist; the same gate then requires zero violations.
//!
//! Every rule has a unit sample proving it fires (see `rules_have_teeth`).

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every production source file: package `src/**`, crate `src/**`, manifests,
/// and build scripts. Tests, fixtures, benches-that-don't-exist, and the web
/// viewer sources are not production Rust.
fn production_files() -> Vec<PathBuf> {
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
    let root = workspace_root();
    let mut out = Vec::new();
    walk(&root.join("src"), &mut out);
    for crate_dir in [
        "journal",
        "mechanics",
        "fabric",
        "comms",
        "replica",
        "runtime",
    ] {
        walk(&root.join("crates").join(crate_dir).join("src"), &mut out);
        let manifest = root.join("crates").join(crate_dir).join("Cargo.toml");
        if manifest.exists() {
            out.push(manifest);
        }
        let build = root.join("crates").join(crate_dir).join("build.rs");
        if build.exists() {
            out.push(build);
        }
    }
    out.push(root.join("Cargo.toml"));
    if root.join("build.rs").exists() {
        out.push(root.join("build.rs"));
    }
    out.sort();
    out
}

/// One clean-break rule: a stable id and a predicate over `(relative path,
/// file text)`. A rule may be path-scoped (only meaningful inside some crates).
struct Rule {
    id: &'static str,
    /// The deletion phase that owns clearing this rule's violations.
    #[allow(dead_code)]
    phase: &'static str,
    matcher: fn(&str, &str) -> bool,
}

/// True when `text` contains `needle` as a plain substring.
fn has(text: &str, needle: &str) -> bool {
    text.contains(needle)
}

/// Whether an identifier carries a protocol-version suffix (`FooV1`, `foo_v1`,
/// `FOO_V1`) — forbidden in project-owned Rust names; encoded version fields
/// and domain/ALPN string *contents* are exempt (they are string literals, not
/// identifiers).
fn versioned_ident(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // `..._v<digits>` (snake / screaming-snake)
    if let Some(idx) = lower.rfind("_v") {
        let tail = &lower[idx + 2..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    // `...V<digits>` (camel) — an upper-case V introducing a trailing number.
    let bytes = name.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'V' && i > 0 {
            let tail = &bytes[i + 1..];
            if !tail.is_empty() && tail.iter().all(|b| b.is_ascii_digit()) {
                // Preceded by a lowercase letter or digit → camel-case suffix.
                let prev = bytes[i - 1];
                if prev.is_ascii_lowercase() || prev.is_ascii_digit() {
                    return true;
                }
            }
        }
        i += 1;
    }
    false
}

/// Whether a source file *declares* a version-suffixed identifier (struct,
/// enum, trait, type, fn, const, static, or mod). Usages follow declarations,
/// so declarations are the violation unit.
fn declares_versioned_ident(text: &str) -> bool {
    for line in text.lines() {
        let trimmed = line.trim_start();
        for kw in [
            "pub struct ",
            "struct ",
            "pub enum ",
            "enum ",
            "pub trait ",
            "trait ",
            "pub type ",
            "type ",
            "pub fn ",
            "fn ",
            "pub const ",
            "const ",
            "pub static ",
            "static ",
            "pub mod ",
            "mod ",
        ] {
            if let Some(rest) = trimmed.strip_prefix(kw) {
                let name: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .collect();
                if !name.is_empty() && versioned_ident(&name) {
                    return true;
                }
                break;
            }
        }
    }
    false
}

/// The generic concept crates (everything but the product package).
fn in_generic_crate(path: &str) -> bool {
    path.starts_with("crates/")
}

fn in_crate(path: &str, name: &str) -> bool {
    path.starts_with(&format!("crates/{name}/"))
}

const RULES: &[Rule] = &[
    // -- legacy architecture modules (deleted whole in M5) --------------------
    Rule {
        id: "legacy-module",
        phase: "M5",
        matcher: |path, _| {
            path == "src/node.rs"
                || path == "src/sync.rs"
                || path == "src/presence.rs"
                || path == "src/proto.rs"
                || path == "src/index.rs"
                || path == "src/inbox.rs"
                || path.starts_with("src/replica/")
        },
    },
    // -- the legacy ticket ----------------------------------------------------
    Rule {
        id: "space-ticket",
        phase: "M5",
        matcher: |_, text| has(text, "SpaceTicket"),
    },
    // -- pending-member approval (replaced by acceptance-triggered admission) --
    Rule {
        id: "member-approval",
        phase: "M2",
        matcher: |_, text| {
            has(text, "MemberRequests")
                || has(text, "MemberApprove")
                || has(text, "require_approval")
        },
    },
    // -- peer cache -------------------------------------------------------------
    Rule {
        id: "peers-json",
        phase: "M5",
        matcher: |_, text| has(text, "peers.json"),
    },
    // -- legacy Loro store paths --------------------------------------------------
    Rule {
        id: "legacy-loro-path",
        phase: "M5",
        matcher: |_, text| {
            has(text, "catalog.loro") || has(text, "membership.loro") || has(text, "docs/*.loro")
        },
    },
    // -- product modules still exported by fabric ---------------------------------
    Rule {
        id: "fabric-product-module",
        phase: "M5",
        matcher: |path, _| {
            in_crate(path, "fabric")
                && (path.ends_with("issue.rs")
                    || path.ends_with("catalog.rs")
                    || path.ends_with("history.rs")
                    || path.ends_with("membership.rs")
                    || path.ends_with("store.rs"))
        },
    },
    // -- the product document wrappers, wherever they are named --------------------
    Rule {
        id: "product-doc-wrapper",
        phase: "M5",
        matcher: |_, text| has(text, "IssueDoc") || has(text, "CatalogDoc"),
    },
    // -- product ids / DTOs inside mechanics ---------------------------------------
    Rule {
        id: "mechanics-product-id",
        phase: "M5",
        matcher: |path, text| {
            in_crate(path, "mechanics")
                && (has(text, "DocId")
                    || has(text, "ProjectId")
                    || has(text, "LabelId")
                    || has(text, "BoardView")
                    || has(text, "IssueView")
                    || has(text, "\"iss_\"")
                    || has(text, "\"prj_\"")
                    || has(text, "\"lbl_\""))
        },
    },
    // -- Loro named outside fabric ---------------------------------------------------
    Rule {
        id: "loro-outside-fabric",
        phase: "M5",
        matcher: |path, text| {
            in_generic_crate(path)
                && !in_crate(path, "fabric")
                && (has(text, "Loro") || has(text, "loro::") || has(text, "loro ="))
        },
    },
    // -- World-facing flat standing / coarse grants (replaced in M0.4a) ---------------
    Rule {
        id: "world-flat-standing",
        phase: "M0",
        matcher: |path, text| {
            (in_crate(path, "runtime")
                || path.starts_with("src/world/")
                || path.starts_with("src/orbital/"))
                && (has(text, "Standing") || has(text, "Grant::Admin") || has(text, "Grant::Write"))
        },
    },
    // -- home-type selection / dual daemon routing (removed at the M4 flip) -----------
    Rule {
        id: "dual-mode-selection",
        phase: "M4",
        matcher: |path, text| {
            path.starts_with("src/")
                && (has(text, "is_orbital_home") || has(text, "detect_legacy_home"))
        },
    },
    // -- legacy sync/presence ALPNs (production registration deleted in M5) -----------
    Rule {
        id: "legacy-alpn",
        phase: "M5",
        matcher: |_, text| has(text, "lait/sync/") || has(text, "lait/presence/2"),
    },
    // -- project-owned version-suffixed identifiers (semantic renames in M6) ----------
    Rule {
        id: "version-suffixed-ident",
        phase: "M6",
        matcher: |path, text| path.ends_with(".rs") && declares_versioned_ident(text),
    },
];

/// Parse the checked-in allowlist: `path<TAB>rule<TAB>phase`, `#` comments.
fn allowlist() -> BTreeSet<(String, String)> {
    let raw = std::fs::read_to_string(workspace_root().join("tests/clean_break_allowlist.tsv"))
        .unwrap_or_default();
    raw.lines()
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .map(|l| {
            let mut cols = l.split('\t');
            let path = cols.next().unwrap_or("").trim().to_string();
            let rule = cols.next().unwrap_or("").trim().to_string();
            (path, rule)
        })
        .collect()
}

fn scan() -> BTreeSet<(String, String)> {
    let root = workspace_root();
    let mut found = BTreeSet::new();
    for file in production_files() {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        for rule in RULES {
            if (rule.matcher)(&rel, &text) {
                found.insert((rel.clone(), rule.id.to_string()));
            }
        }
    }
    found
}

#[test]
fn no_unallowlisted_legacy_violations() {
    let found = scan();
    let allowed = allowlist();
    let new: Vec<_> = found.difference(&allowed).collect();
    let stale: Vec<_> = allowed.difference(&found).collect();
    let mut msg = String::new();
    if !new.is_empty() {
        let _ = writeln!(
            msg,
            "NEW clean-break violations (not in tests/clean_break_allowlist.tsv):"
        );
        for (path, rule) in &new {
            let _ = writeln!(msg, "  {path}\t{rule}");
        }
    }
    if !stale.is_empty() {
        let _ = writeln!(
            msg,
            "STALE allowlist entries (no longer match — prune them):"
        );
        for (path, rule) in &stale {
            let _ = writeln!(msg, "  {path}\t{rule}");
        }
    }
    assert!(msg.is_empty(), "\n{msg}");
}

/// M5 flips this from a tracked count to a hard zero: once the purge lands the
/// allowlist must be empty and stay empty.
#[test]
fn allowlist_is_empty_after_m5() {
    let allowed = allowlist();
    let purge_done = !workspace_root().join("src/node.rs").exists();
    if purge_done {
        assert!(
            allowed.is_empty(),
            "the legacy purge landed (src/node.rs is gone) but {} allowlist entries remain",
            allowed.len()
        );
    }
}

/// Every rule fires on a synthetic sample — a scanner that silently stopped
/// matching would fail here, not silently pass the gate.
#[test]
fn rules_have_teeth() {
    let samples: &[(&str, &str, &str)] = &[
        ("legacy-module", "src/node.rs", ""),
        ("legacy-module", "src/replica/mod.rs", ""),
        (
            "space-ticket",
            "src/app.rs",
            "let t = SpaceTicket::parse(x);",
        ),
        (
            "member-approval",
            "src/control.rs",
            "Request::MemberApprove { .. }",
        ),
        ("member-approval", "src/cli.rs", "if require_approval {"),
        (
            "peers-json",
            "src/node.rs",
            "let p = dir.join(\"peers.json\");",
        ),
        ("legacy-loro-path", "src/x.rs", "open(\"catalog.loro\")"),
        ("legacy-loro-path", "src/x.rs", "open(\"membership.loro\")"),
        ("fabric-product-module", "crates/fabric/src/issue.rs", ""),
        ("product-doc-wrapper", "src/y.rs", "fn f(d: &IssueDoc) {}"),
        ("product-doc-wrapper", "src/y.rs", "fn f(d: &CatalogDoc) {}"),
        (
            "mechanics-product-id",
            "crates/mechanics/src/ids.rs",
            "pub struct DocId(String);",
        ),
        (
            "loro-outside-fabric",
            "crates/replica/src/replica.rs",
            "use fabric::LoroFabric;",
        ),
        (
            "world-flat-standing",
            "crates/runtime/src/session.rs",
            "pub struct Standing { grants: Vec<Grant> }",
        ),
        (
            "world-flat-standing",
            "src/world/issues.rs",
            "if standing.has(Grant::Write) {",
        ),
        (
            "dual-mode-selection",
            "src/app.rs",
            "if is_orbital_home(&home) {",
        ),
        (
            "legacy-alpn",
            "src/sync.rs",
            "pub const SYNC: &[u8] = b\"lait/sync/2\";",
        ),
        (
            "version-suffixed-ident",
            "crates/replica/src/transaction.rs",
            "pub struct BodyTransactionV1 {}",
        ),
        (
            "version-suffixed-ident",
            "crates/runtime/src/wire.rs",
            "pub const PRESENCE_ALPN_V1: &[u8] = b\"x\";",
        ),
        (
            "version-suffixed-ident",
            "src/z.rs",
            "fn decode_v1(bytes: &[u8]) {}",
        ),
    ];
    for (rule_id, path, text) in samples {
        let rule = RULES
            .iter()
            .find(|r| r.id == *rule_id)
            .unwrap_or_else(|| panic!("unknown rule {rule_id}"));
        assert!(
            (rule.matcher)(path, text),
            "rule `{rule_id}` failed to fire on its sample ({path})"
        );
    }
    // Negative controls: semantic names and encoded-version string contents
    // must NOT trip the identifier rule.
    assert!(!versioned_ident("BodyTransaction"));
    assert!(!versioned_ident("SignedCoordinates"));
    assert!(!versioned_ident("Ipv4"), "IP-family names are not versions");
    assert!(!versioned_ident("Ipv6Addr"));
    assert!(versioned_ident("BodyTransactionV1"));
    assert!(versioned_ident("PRESENCE_ALPN_V1"));
    assert!(versioned_ident("decode_v1"));
    assert!(!declares_versioned_ident(
        "const DOMAIN: &[u8] = b\"lait.invitation.accept.v1\";"
    ));
}
