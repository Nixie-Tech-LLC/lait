//! The operation contract (`docs/DATA-CONTRACT.md`): every commit in
//! lait carries a request kind, an (advisory) actor, and a **trust tier** — and
//! the engine is configured so those commits survive as distinct, timestamped,
//! self-labelled changes in the oplog instead of fusing into one anonymous blob.
//!
//! Kernel configuration facts this module encodes (verified empirically against
//! `loro =1.13.6` — see the contract's "gotchas"):
//! - `record_timestamp` defaults **off** → every change stamps ts 0.
//! - with ts 0, the default merge interval check (`0 ≤ 1000`) is *always* true:
//!   consecutive same-peer changes fuse into one. `set_change_merge_interval(0)`
//!   does NOT fix this (same-second stamps give `0 ≤ 0`); only **-1** disables
//!   fusion. A *constant* commit message doesn't help either (equal messages
//!   still merge) — the interval is the granularity guarantee, the message is
//!   pure semantics.
//! - a fresh doc draws a **random peer id per session**, growing every doc's
//!   version vector by one dead entry per daemon restart, forever. The store
//!   persists one random peer id per store instead ([`crate::store`]): restart
//!   reuses it (no growth), a re-created store mints fresh (no counter
//!   collision — reusing a peer id over an empty store then importing the old
//!   ops silently *drops* them, verified).

use loro::LoroDoc;
use serde::{Deserialize, Serialize};

use crate::ids::UserId;

/// Trust tier of an operation (contract §2). The tier is a property of the
/// *request kind*, never a caller choice; the I-confluence law (§2.1) bounds
/// what `Authority` may enforce (monotone grant, remove-wins revoke, append-only
/// membership, soft-delete) — anything needing consensus is unrepresentable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    /// T0 — collaborative content (title, description, comments, labels,
    /// assignees). A lost concurrent edit is a UI note, not a security event.
    Content,
    /// T1 — shared structure (ordering, hierarchy, links, row cache). Convergent
    /// and consequential, but carries no authority claim.
    Structure,
    /// T2 — authority-bearing (membership, key rotation, deletion). Signed ops
    /// in the `acl` hash-DAG where applicable; replay-validated.
    Authority,
}

impl Tier {
    fn as_u8(self) -> u8 {
        match self {
            Tier::Content => 0,
            Tier::Structure => 1,
            Tier::Authority => 2,
        }
    }
}

/// The metadata every commit must carry (contract §5). Constructed per Request
/// at the Layer-B boundary and consumed exactly once by a wrapper's `apply()`.
#[derive(Debug, Clone)]
pub struct OpCtx {
    /// Request kind (`"created"`, `"edited"`, `"member_add"`, …) — the semantic
    /// label a peer or a later session reads back out of the oplog.
    pub request: String,
    /// Advisory actor claim (non-goal 6: self-asserted, not provenance). Rides
    /// the commit message so remote changes arrive attributed.
    pub actor: UserId,
    pub tier: Tier,
}

impl OpCtx {
    pub fn content(request: impl Into<String>, actor: &UserId) -> Self {
        Self::new(request, actor, Tier::Content)
    }
    pub fn structure(request: impl Into<String>, actor: &UserId) -> Self {
        Self::new(request, actor, Tier::Structure)
    }
    pub fn authority(request: impl Into<String>, actor: &UserId) -> Self {
        Self::new(request, actor, Tier::Authority)
    }
    fn new(request: impl Into<String>, actor: &UserId, tier: Tier) -> Self {
        OpCtx {
            request: request.into(),
            actor: actor.clone(),
            tier,
        }
    }

    /// The wire form riding in the Loro commit message: compact JSON with
    /// short stable keys (it lives in every replica's oplog forever).
    pub(super) fn commit_message(&self) -> String {
        serde_json::json!({
            "r": self.request,
            "a": self.actor.as_str(),
            "t": self.tier.as_u8(),
        })
        .to_string()
    }
}

/// The parsed form of a commit message read back from the oplog. Absent or
/// unparseable (legacy pre-contract changes) fields degrade to `None`.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct OpMeta {
    #[serde(rename = "r")]
    pub request: Option<String>,
    #[serde(rename = "a")]
    pub actor: Option<String>,
    #[serde(rename = "t")]
    pub tier: Option<u8>,
}

impl OpMeta {
    pub fn parse(message: Option<&str>) -> Self {
        message
            .and_then(|m| serde_json::from_str(m).ok())
            .unwrap_or_default()
    }
    pub fn actor_id(&self) -> Option<UserId> {
        self.actor.as_deref().and_then(UserId::parse)
    }
}

/// Contract §5 engine configuration — applied by every wrapper constructor,
/// before any op is written or imported.
pub(super) fn configure(doc: &LoroDoc, peer: Option<u64>) {
    doc.set_record_timestamp(true);
    doc.set_change_merge_interval(-1);
    if let Some(p) = peer {
        // Only fails with uncommitted pending ops; constructors call this first.
        let _ = doc.set_peer_id(p);
    }
}

/// The single commit path (contract §6): stamp the op metadata, then commit.
pub(super) fn commit_with(doc: &LoroDoc, ctx: &OpCtx) {
    doc.set_next_commit_message(&ctx.commit_message());
    doc.commit();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn actor() -> UserId {
        UserId::from_key_string("a".repeat(64))
    }

    #[test]
    fn commit_message_roundtrips_through_opmeta() {
        let ctx = OpCtx::content("edited", &actor());
        let meta = OpMeta::parse(Some(&ctx.commit_message()));
        assert_eq!(meta.request.as_deref(), Some("edited"));
        assert_eq!(meta.actor_id(), Some(actor()));
        assert_eq!(meta.tier, Some(0));
    }

    #[test]
    fn legacy_messages_degrade_to_none() {
        assert!(OpMeta::parse(None).request.is_none());
        assert!(OpMeta::parse(Some("not json")).actor.is_none());
    }

    #[test]
    fn commits_stay_distinct_and_survive_reload() {
        // The load-bearing fact: N applies = N changes in the oplog, with real
        // timestamps and messages, after an export/import round trip. Under
        // engine defaults this collapses to ONE anonymous change.
        let doc = LoroDoc::new();
        configure(&doc, Some(7));
        for i in 0..5 {
            doc.get_map("m").insert("k", i).unwrap();
            commit_with(&doc, &OpCtx::content(format!("edit{i}"), &actor()));
        }
        let snap = doc.export(loro::ExportMode::Snapshot).unwrap();
        let doc2 = LoroDoc::new();
        doc2.import(&snap).unwrap();
        let mut n = 0;
        let mut with_meta = 0;
        doc2.travel_change_ancestors(
            &doc2.oplog_frontiers().iter().collect::<Vec<_>>(),
            &mut |c| {
                n += 1;
                let meta = OpMeta::parse(c.message.as_deref());
                if meta.request.is_some() && c.timestamp > 0 {
                    with_meta += 1;
                }
                std::ops::ControlFlow::Continue(())
            },
        )
        .unwrap();
        assert_eq!(n, 5, "five applies must stay five changes");
        assert_eq!(with_meta, 5, "every change carries metadata + timestamp");
    }
}
