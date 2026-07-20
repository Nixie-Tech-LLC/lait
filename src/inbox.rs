//! The durable inbox — things **addressed to you**, derived at sync-import time
//! (the only place remote changes can be honestly detected; see the tracker's
//! `import_doc`). Distinct from the `activity` firehose in three load-bearing
//! ways: it is filtered to *you* (assignments, comments on your issues,
//! `@nick` mentions, status moves on your work), it is **durable** (the
//! activity ring is per-daemon-session and dies on restart; an inbox must not
//! lose unread items), and it is attribution-honest (comments carry their real
//! CRDT author; assignment/status changes are rendered actor-unknown rather
//! than misattributed — S non-goal 6: in-doc attribution is advisory).
//!
//! Storage: `home/inbox.json`, the `seeds.json` local-state pattern — a small
//! whole-file atomic rewrite beside the store, never synced, corrupt/missing
//! degrades to empty. Bounded to the newest `INBOX_CAP` entries; the read
//! watermark is a wall-clock timestamp used only for advisory display ordering.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::dto::InboxEntry;

/// Bound on retained entries (newest kept). An inbox is a working set, not an
/// archive — history lives in `activity`/`history`.
const INBOX_CAP: usize = 200;

/// The on-disk shape: watermark + newest-last entries.
#[derive(Debug, Default, Serialize, Deserialize)]
struct InboxFile {
    #[serde(default)]
    read_up_to_ts: u64,
    #[serde(default)]
    entries: Vec<InboxEntry>,
}

fn inbox_path(home: &Path) -> PathBuf {
    home.join("inbox.json")
}

fn load(home: &Path) -> InboxFile {
    std::fs::read_to_string(inbox_path(home))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// Best-effort atomic persist (temp + rename), mirroring the registry writer.
fn save(home: &Path, file: &InboxFile) {
    let path = inbox_path(home);
    let Ok(json) = serde_json::to_string_pretty(file) else {
        return;
    };
    let tmp = path.with_extension(format!("json.tmp.{}", std::process::id()));
    if std::fs::write(&tmp, json).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// Append entries (skipping none — the deriver already filtered relevance),
/// trimming to the cap. No-op on an empty batch.
pub fn append(home: &Path, mut new: Vec<InboxEntry>) {
    if new.is_empty() {
        return;
    }
    let mut file = load(home);
    file.entries.append(&mut new);
    if file.entries.len() > INBOX_CAP {
        let drop = file.entries.len() - INBOX_CAP;
        file.entries.drain(..drop);
    }
    save(home, &file);
}

/// Read the inbox: (entries newest-first, unread count against the watermark).
pub fn list(home: &Path) -> (Vec<InboxEntry>, u64) {
    let file = load(home);
    let unread = file
        .entries
        .iter()
        .filter(|e| e.ts > file.read_up_to_ts)
        .count() as u64;
    let mut entries = file.entries;
    entries.reverse();
    (entries, unread)
}

/// Stamp the read watermark at `now` (everything currently held reads as seen).
pub fn mark_read(home: &Path, now: u64) {
    let mut file = load(home);
    file.read_up_to_ts = now;
    save(home, &file);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(ts: u64, reff: &str) -> InboxEntry {
        InboxEntry {
            ts,
            kind: "assigned".into(),
            reff: reff.into(),
            doc_id: format!("iss_{reff}"),
            title: "t".into(),
            detail: String::new(),
            actor: None,
            actor_nick: None,
        }
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("lait-inbox-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn append_list_and_watermark_roundtrip() {
        let home = scratch("basic");
        append(&home, vec![entry(10, "A-1"), entry(20, "A-2")]);
        let (entries, unread) = list(&home);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].reff, "A-2", "newest first");
        assert_eq!(unread, 2);

        mark_read(&home, 15);
        let (_, unread) = list(&home);
        assert_eq!(unread, 1, "only ts>watermark counts unread");

        // Durability: a fresh load (new daemon session) sees the same state.
        let (entries, unread) = list(&home);
        assert_eq!((entries.len(), unread), (2, 1));
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn cap_keeps_the_newest() {
        let home = scratch("cap");
        append(
            &home,
            (0..(INBOX_CAP as u64 + 50))
                .map(|i| entry(i, "A-1"))
                .collect(),
        );
        let (entries, _) = list(&home);
        assert_eq!(entries.len(), INBOX_CAP);
        assert_eq!(entries[0].ts, INBOX_CAP as u64 + 49, "newest survives");
        let _ = std::fs::remove_dir_all(&home);
    }

    #[test]
    fn corrupt_or_missing_degrades_to_empty() {
        let home = scratch("corrupt");
        assert_eq!(list(&home).1, 0);
        std::fs::write(inbox_path(&home), "{nope").unwrap();
        assert_eq!(list(&home).0.len(), 0);
        // and appends recover the file
        append(&home, vec![entry(1, "A-1")]);
        assert_eq!(list(&home).0.len(), 1);
        let _ = std::fs::remove_dir_all(&home);
    }
}
