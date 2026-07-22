//! Document-level commit configuration shared by every fabric constructor.
//!
//! The crate pins Loro 1.13.6, whose configuration makes these details
//! load-bearing:
//! - `record_timestamp` defaults off, producing timestamp zero.
//! - with timestamp zero, the default merge interval check is always true:
//!   consecutive same-peer changes fuse into one. `set_change_merge_interval(0)`
//!   does not fix this because same-second stamps still compare equal; only
//!   `-1` disables fusion — the interval is the granularity guarantee.
//! - a fresh doc draws a **random peer id per session**, growing every doc's
//!   version vector by one dead entry per restart, forever; callers that hold
//!   a durable peer id pass it in so restart reuses it.

use loro::LoroDoc;

/// Engine configuration applied before any op is written or imported.
pub(crate) fn configure(doc: &LoroDoc, peer: Option<u64>) {
    doc.set_record_timestamp(true);
    doc.set_change_merge_interval(-1);
    if let Some(p) = peer {
        // Only fails with uncommitted pending ops; constructors call this first.
        let _ = doc.set_peer_id(p);
    }
}
