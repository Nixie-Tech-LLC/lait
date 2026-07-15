//! Small shared formatting helpers.

use std::time::{SystemTime, UNIX_EPOCH};

/// Coarse "N{s,m,h,d} ago" from a unix-seconds timestamp. Falls back to the
/// raw stamp if the clock is behind it.
pub fn ago(ts: u64) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if ts == 0 || now < ts {
        return format!("{ts} (unix)");
    }
    let d = now - ts;
    if d < 60 {
        format!("{d}s ago")
    } else if d < 3600 {
        format!("{}m ago", d / 60)
    } else if d < 86_400 {
        format!("{}h ago", d / 3600)
    } else {
        format!("{}d ago", d / 86_400)
    }
}
