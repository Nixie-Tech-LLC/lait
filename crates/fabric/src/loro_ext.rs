//! Small read helpers over Loro containers, so [`crate::fabric`]'s export and
//! projection paths stay readable. All merge semantics live in Loro itself;
//! these helpers only read leaf values back out.

use loro::{Container, LoroMap, ValueOrContainer};

/// Read an i64 leaf from a map key.
pub fn get_i64(m: &LoroMap, key: &str) -> Option<i64> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_i64().ok())
}

/// Read a binary leaf from a map key.
pub fn get_bytes(m: &LoroMap, key: &str) -> Option<Vec<u8>> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_binary().ok())
        .map(|b| b.to_vec())
}

/// The keys of a map (order unspecified).
pub fn map_keys(m: &LoroMap) -> Vec<String> {
    let mut out = Vec::new();
    m.for_each(|k, _v| out.push(k.to_string()));
    out
}

/// A nested map container under a map key, if present.
pub fn get_map(m: &LoroMap, key: &str) -> Option<LoroMap> {
    match m.get(key) {
        Some(ValueOrContainer::Container(Container::Map(inner))) => Some(inner),
        _ => None,
    }
}
