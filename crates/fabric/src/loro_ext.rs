//! Small read helpers over Loro containers, so [`crate::fabric`]'s export and
//! projection paths stay readable. All merge semantics live in Loro itself;
//! these helpers only read leaf values back out.

use loro::LoroMap;

/// Read an i64 leaf from a map key.
pub fn get_i64(m: &LoroMap, key: &str) -> Option<i64> {
    m.get(key)
        .and_then(|v| v.into_value().ok())
        .and_then(|v| v.into_i64().ok())
}

/// The keys of a map (order unspecified).
pub fn map_keys(m: &LoroMap) -> Vec<String> {
    let mut out = Vec::new();
    m.for_each(|k, _v| out.push(k.to_string()));
    out
}
