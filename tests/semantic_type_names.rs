//! M6 — the semantic-naming gate, as its own named artifact.
//!
//! Project-owned Rust identifiers are semantic: no protocol-version suffix
//! (`FooV1`, `foo_v1`, `FOO_V1`) may be *declared* anywhere in production
//! sources — struct, enum, trait, type alias, fn, const, static, or mod. Wire
//! formats keep their encoded version **fields** and their versioned
//! signing-domain/ALPN/magic **string contents**; those are data, not names.
//! Byte stability across the renames is pinned by the golden fixture suites
//! (`coordinates_fixtures`, `contact_fixtures`, `beacon_presence_fixtures`,
//! `manifest_fixtures`, `transaction_marker_fixtures`), which fail if a rename
//! ever changes an encoding.
//!
//! No alias or deprecated suffixed wrapper is permitted: a `type FooV1 = Foo;`
//! shim *declares* a suffixed identifier and fails this gate like any other.

use std::path::{Path, PathBuf};

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Every production Rust source: the package `src/**` and each concept crate's
/// `src/**`. Tests and fixtures are not production names.
fn production_sources() -> Vec<PathBuf> {
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
    }
    out.sort();
    out
}

/// Whether an identifier carries a protocol-version suffix. IP-family names
/// (`Ipv4`, `Ipv6Addr`) are not versions: the `V` must introduce a *trailing*
/// number after a lowercase letter or digit, or a `_v<digits>` tail.
fn versioned_ident(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if let Some(idx) = lower.rfind("_v") {
        let tail = &lower[idx + 2..];
        if !tail.is_empty() && tail.bytes().all(|b| b.is_ascii_digit()) {
            return true;
        }
    }
    let bytes = name.as_bytes();
    for i in 1..bytes.len() {
        if bytes[i] == b'V' {
            let tail = &bytes[i + 1..];
            if !tail.is_empty()
                && tail.iter().all(|b| b.is_ascii_digit())
                && (bytes[i - 1].is_ascii_lowercase() || bytes[i - 1].is_ascii_digit())
            {
                return true;
            }
        }
    }
    false
}

/// The version-suffixed identifiers a source file *declares* (declarations are
/// the violation unit; usages follow declarations).
fn versioned_declarations(text: &str) -> Vec<String> {
    let mut out = Vec::new();
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
                    out.push(name);
                }
                break;
            }
        }
    }
    out
}

#[test]
fn no_production_identifier_carries_a_version_suffix() {
    let root = workspace_root();
    let mut violations = Vec::new();
    for file in production_sources() {
        let rel = file
            .strip_prefix(&root)
            .unwrap_or(&file)
            .to_string_lossy()
            .replace('\\', "/");
        let text = std::fs::read_to_string(&file).unwrap_or_default();
        for name in versioned_declarations(&text) {
            violations.push(format!("{rel}: `{name}`"));
        }
    }
    assert!(
        violations.is_empty(),
        "version-suffixed identifier declarations in production sources:\n  {}",
        violations.join("\n  ")
    );
}

#[test]
fn the_detector_has_teeth() {
    // Positive samples: every declaration form and suffix style fires.
    for sample in [
        "pub struct BodyTransactionV1 {",
        "struct payload_v2;",
        "pub enum FrameV10 {",
        "pub type SignedCoordinatesV1 = ();",
        "type ShimV1 = Real;",
        "fn decode_v1() {}",
        "pub const PRESENCE_ALPN_V1: &[u8] = b\"x\";",
        "static TABLE_V3: u8 = 0;",
        "mod wire_v1;",
    ] {
        assert!(
            !versioned_declarations(sample).is_empty(),
            "detector missed: {sample}"
        );
    }
    // Negative controls: semantic names, IP families, and versioned *string
    // contents* are not identifier violations.
    for sample in [
        "pub struct BodyTransaction {",
        "pub struct SignedCoordinates {",
        "pub struct Ipv4Header {",
        "use std::net::Ipv6Addr;",
        "const DOMAIN: &str = \"lait.coordinates.v1\";",
        "let alpn = b\"lait/contact/1\";",
    ] {
        assert!(
            versioned_declarations(sample).is_empty(),
            "false positive: {sample}"
        );
    }
}
