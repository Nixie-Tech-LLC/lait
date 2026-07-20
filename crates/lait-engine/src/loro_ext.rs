//! Small read helpers over Loro containers, so the document wrappers
//! ([`crate::issue`], [`crate::catalog`]) stay readable. All merge semantics
//! live in Loro itself; these helpers only read leaf values back out.

use loro::{Container, LoroMap, LoroMovableList, ValueOrContainer};

/// Read a string leaf from a map key.
pub fn get_str(m: &LoroMap, key: &str) -> Option<String> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_string().ok())
        .map(|s| s.to_string())
}

/// Read an i64 leaf from a map key.
pub fn get_i64(m: &LoroMap, key: &str) -> Option<i64> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_i64().ok())
}

/// Read a u64 leaf (stored as i64) from a map key.
pub fn get_u64(m: &LoroMap, key: &str) -> Option<u64> {
    get_i64(m, key).map(|v| v as u64)
}

/// Read a bool leaf from a map key.
pub fn get_bool(m: &LoroMap, key: &str) -> Option<bool> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_bool().ok())
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

/// The keys whose stored value is `true`, representing a present-key set.
pub fn present_keys(m: &LoroMap) -> Vec<String> {
    let mut out = Vec::new();
    m.for_each(|k, v| {
        let present = v
            .as_value()
            .and_then(|val| val.as_bool().copied())
            .unwrap_or(true);
        if present {
            out.push(k.to_string());
        }
    });
    out
}

/// A nested map container under a map key, if present.
pub fn get_map(m: &LoroMap, key: &str) -> Option<LoroMap> {
    match m.get(key) {
        Some(ValueOrContainer::Container(Container::Map(inner))) => Some(inner),
        _ => None,
    }
}

/// The string elements of a movable list, in order.
pub fn list_strings(l: &LoroMovableList) -> Vec<String> {
    let mut out = Vec::new();
    for i in 0..l.len() {
        if let Some(v) = l.get(i) {
            if let Some(s) = v.as_value().and_then(|val| val.as_string()) {
                out.push(s.to_string());
            }
        }
    }
    out
}

/// Index of a string element in a movable list, if present.
pub fn list_index_of(l: &LoroMovableList, needle: &str) -> Option<usize> {
    for i in 0..l.len() {
        if let Some(v) = l.get(i) {
            if let Some(s) = v.as_value().and_then(|val| val.as_string()) {
                if s.as_ref() == needle {
                    return Some(i);
                }
            }
        }
    }
    None
}
