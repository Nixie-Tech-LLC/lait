//! The plaintext **membership layer** (P3, A§11 two-protocol split): a Loro doc
//! holding the signed ACL op-graph ([`crate::acl`]) and, per key-epoch, the
//! workspace key **sealed** to each member ([`crate::crypto::seal_to`]).
//!
//! It is synced **unencrypted** (everything in it is public: signed ops + sealed
//! ciphertext key envelopes), *before* the encrypted catalog/issue docs. A member
//! replays the ACL, unseals its copy of the current-epoch key, and can then
//! decrypt the workspace. A non-member sees the signed ops + envelopes it cannot
//! open — and therefore only ciphertext for the actual issue data.
//!
//! This doc is the reference Regime-C surface (LAIT-DATA-CONTRACT §1): its
//! Loro layer only *moves* the signed ops; trust comes from `acl::replay`.
//! Commits go through [`MembershipDoc::apply`] like every other doc — note the
//! commit metadata here is **plaintext on the wire** (fine: it names ACL ops
//! whose authors are already public).

use anyhow::{anyhow, Result};
use loro::{Container, ExportMode, Frontiers, LoroDoc, LoroList, LoroMap, ValueOrContainer};

use crate::acl::SignedOp;
use crate::ids::{UserId, WorkspaceId};

use super::loro_ext as lx;
use super::op::{self, OpCtx};

const ROOT: &str = "membership";
const K_WORKSPACE: &str = "workspaceId";
const K_EPOCH: &str = "currentEpoch";
const C_ACL: &str = "acl";
const C_ACTORS: &str = "actors"; // the lait/actor/1 key-event log (flat, grow-only)
const C_KEYS: &str = "keys"; // epoch(str) -> Map<device UserId, sealed bytes>
const C_REDEEMED: &str = "redeemed"; // invite nonce(hex) -> redeemer UserId

/// A wrapper around the workspace's membership `LoroDoc`.
pub struct MembershipDoc {
    doc: LoroDoc,
}

impl MembershipDoc {
    pub fn create(workspace_id: &WorkspaceId, peer: Option<u64>, founder: &UserId) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        let root = doc.get_map(ROOT);
        root.insert(K_WORKSPACE, workspace_id.as_str())?;
        root.insert(K_EPOCH, 0i64)?;
        root.insert_container(C_ACL, LoroList::new())?;
        root.insert_container(C_ACTORS, LoroList::new())?;
        root.insert_container(C_KEYS, LoroMap::new())?;
        root.insert_container(C_REDEEMED, LoroMap::new())?;
        op::commit_with(&doc, &OpCtx::authority("init", founder));
        Ok(Self { doc })
    }

    /// Load from stored snapshot bytes, applying the contract's kernel config.
    pub fn from_snapshot(bytes: &[u8], peer: Option<u64>) -> Result<Self> {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        doc.import(bytes)
            .map_err(|e| anyhow!("import membership snapshot: {e}"))?;
        Ok(Self { doc })
    }

    /// A bare, uninitialized membership doc — for a JOINER, which imports the
    /// founder's full membership so container ids match (see `CatalogDoc::empty`).
    pub fn empty(peer: Option<u64>) -> Self {
        let doc = LoroDoc::new();
        op::configure(&doc, peer);
        Self { doc }
    }

    /// Land staged ops as one metadata-carrying change (contract §6).
    pub fn apply(&self, ctx: &OpCtx) {
        op::commit_with(&self.doc, ctx);
    }

    pub fn snapshot(&self) -> Result<Vec<u8>> {
        self.doc
            .export(ExportMode::Snapshot)
            .map_err(|e| anyhow!("export membership snapshot: {e}"))
    }
    pub fn import(&self, bytes: &[u8]) -> Result<()> {
        self.doc
            .import(bytes)
            .map(|_| ())
            .map_err(|e| anyhow!("import membership update: {e}"))
    }
    pub(in crate::engine) fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }
    /// The raw encoded frontiers (input to the combined sync head, A§8).
    pub fn head_bytes(&self) -> Vec<u8> {
        self.head().encode()
    }
    pub fn oplog_vv_bytes(&self) -> Vec<u8> {
        self.doc.oplog_vv().encode()
    }
    pub fn export_from_bytes(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        let vv = loro::VersionVector::decode(peer_vv).unwrap_or_default();
        self.doc
            .export(ExportMode::updates(&vv))
            .map_err(|e| anyhow!("export membership updates: {e}"))
    }

    fn root(&self) -> LoroMap {
        self.doc.get_map(ROOT)
    }
    fn acl_list(&self) -> Option<LoroList> {
        match self.root().get(C_ACL) {
            Some(ValueOrContainer::Container(Container::List(l))) => Some(l),
            _ => None,
        }
    }
    fn keys_map(&self) -> Option<LoroMap> {
        match self.root().get(C_KEYS) {
            Some(ValueOrContainer::Container(Container::Map(m))) => Some(m),
            _ => None,
        }
    }
    /// The actor key-event container, created on demand (like `redeemed`) so a
    /// doc founded before the actor plane still records events after upgrade.
    fn actors_list(&self, create: bool) -> Option<LoroList> {
        match self.root().get(C_ACTORS) {
            Some(ValueOrContainer::Container(Container::List(l))) => Some(l),
            _ if create => self
                .root()
                .insert_container(C_ACTORS, LoroList::new())
                .ok(),
            _ => None,
        }
    }

    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        lx::get_str(&self.root(), K_WORKSPACE).and_then(|s| WorkspaceId::parse(&s))
    }
    pub fn current_epoch(&self) -> u32 {
        lx::get_u64(&self.root(), K_EPOCH).unwrap_or(0) as u32
    }
    pub fn set_epoch(&self, epoch: u32) -> Result<()> {
        self.root().insert(K_EPOCH, epoch as i64)?;
        Ok(())
    }

    // ---- ACL ops (grow-only) ----

    /// Append a signed op (idempotent by op hash — the grow-only set, S§6).
    pub fn add_op(&self, op: &SignedOp) -> Result<()> {
        let hash = op.hash();
        if self.ops().iter().any(|o| o.hash() == hash) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(op).map_err(|e| anyhow!("encode signed op: {e}"))?;
        let list = self
            .acl_list()
            .ok_or_else(|| anyhow!("acl container missing"))?;
        list.insert(list.len(), bytes.as_slice())?;
        Ok(())
    }

    /// All signed ops currently held.
    pub fn ops(&self) -> Vec<SignedOp> {
        let Some(list) = self.acl_list() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(loro::LoroValue::Binary(b))) = list.get(i) {
                if let Ok(op) = postcard::from_bytes::<SignedOp>(&b) {
                    out.push(op);
                }
            }
        }
        out
    }

    /// The current op-graph heads (ops that are nobody's parent) — the parents
    /// for the next op (S§6 hash-chain).
    pub fn heads(&self) -> Vec<String> {
        let ops = self.ops();
        let mut is_parent = std::collections::HashSet::new();
        for o in &ops {
            for p in &o.parents {
                is_parent.insert(p.clone());
            }
        }
        ops.iter()
            .map(|o| o.hash())
            .filter(|h| !is_parent.contains(h))
            .collect()
    }

    // ---- actor key-events (the lait/actor/1 plane, grow-only like the ACL) ----

    /// Append a signed actor key-event (idempotent by event hash). Callers
    /// that author an ACL op referencing new actor events MUST add those
    /// events in the same commit as the op, so a replica never imports an op
    /// whose `actor_asof` frontier it cannot resolve.
    pub fn add_actor_event(&self, ev: &crate::actor::SignedEvent) -> Result<()> {
        let hash = ev.hash();
        if self.actor_events().iter().any(|e| e.hash() == hash) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(ev).map_err(|e| anyhow!("encode actor event: {e}"))?;
        let list = self
            .actors_list(true)
            .ok_or_else(|| anyhow!("actors container missing"))?;
        list.insert(list.len(), bytes.as_slice())?;
        Ok(())
    }

    /// All actor key-events currently held (every actor's log, flat — replay
    /// partitions by declared actor).
    pub fn actor_events(&self) -> Vec<crate::actor::SignedEvent> {
        let Some(list) = self.actors_list(false) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(loro::LoroValue::Binary(b))) = list.get(i) {
                if let Ok(ev) = postcard::from_bytes::<crate::actor::SignedEvent>(&b) {
                    out.push(ev);
                }
            }
        }
        out
    }

    /// The heads of ONE actor's log — the parents for its next event and the
    /// `actor_asof` frontier an authored op embeds. Computed over the events
    /// declaring that actor (the inception hash equals the actor id's hash).
    pub fn actor_heads(&self, actor: &crate::ids::ActorId) -> Vec<String> {
        let events = self.actor_events();
        let mine: Vec<&crate::actor::SignedEvent> = events
            .iter()
            .filter(|e| {
                if e.hash() == actor.incept_hash() {
                    return true;
                }
                postcard::from_bytes::<crate::actor::ActorOp>(&e.op)
                    .ok()
                    .and_then(|op| op.actor().cloned())
                    .is_some_and(|a| &a == actor)
            })
            .collect();
        let mut is_parent = std::collections::HashSet::new();
        for e in &mine {
            for p in &e.parents {
                is_parent.insert(p.clone());
            }
        }
        mine.iter()
            .map(|e| e.hash())
            .filter(|h| !is_parent.contains(h))
            .collect()
    }

    // ---- sealed workspace-key envelopes ----

    fn epoch_map(&self, epoch: u32, create: bool) -> Result<Option<LoroMap>> {
        let keys = self
            .keys_map()
            .ok_or_else(|| anyhow!("keys container missing"))?;
        let ek = epoch.to_string();
        match keys.get(&ek) {
            Some(ValueOrContainer::Container(Container::Map(m))) => Ok(Some(m)),
            _ if create => Ok(Some(keys.insert_container(&ek, LoroMap::new())?)),
            _ => Ok(None),
        }
    }

    /// Store the workspace key sealed to `member` for `epoch`.
    pub fn put_sealed(&self, epoch: u32, member: &UserId, sealed: &[u8]) -> Result<()> {
        let m = self.epoch_map(epoch, true)?.unwrap();
        m.insert(member.as_str(), sealed)?;
        Ok(())
    }

    /// Retrieve the sealed key envelope addressed to `member` for `epoch`.
    pub fn get_sealed(&self, epoch: u32, member: &UserId) -> Option<Vec<u8>> {
        let m = self.epoch_map(epoch, false).ok().flatten()?;
        lx::get_bytes(&m, member.as_str())
    }

    // ---- single-use invite replay guard (Pattern A) ----

    /// The redeemed-nonce map, created on demand so a workspace founded before
    /// invites existed still records redemptions (the container syncs like the
    /// rest of the membership doc, giving multi-admin replay safety).
    fn redeemed_map(&self, create: bool) -> Option<LoroMap> {
        match self.root().get(C_REDEEMED) {
            Some(ValueOrContainer::Container(Container::Map(m))) => Some(m),
            _ if create => self
                .root()
                .insert_container(C_REDEEMED, LoroMap::new())
                .ok(),
            _ => None,
        }
    }

    /// Whether a single-use invite `nonce` has already been spent.
    pub fn is_redeemed(&self, nonce: &[u8]) -> bool {
        let key = data_encoding::HEXLOWER.encode(nonce);
        self.redeemed_map(false)
            .map(|m| m.get(&key).is_some())
            .unwrap_or(false)
    }

    /// Burn a single-use invite `nonce`, recording who redeemed it. The caller is
    /// responsible for committing/persisting the doc (e.g. via `member_apply`).
    pub fn mark_redeemed(&self, nonce: &[u8], redeemer: &UserId) -> Result<()> {
        let key = data_encoding::HEXLOWER.encode(nonce);
        let m = self
            .redeemed_map(true)
            .ok_or_else(|| anyhow!("redeemed container missing"))?;
        m.insert(&key, redeemer.as_str())?;
        Ok(())
    }

    /// Members with a sealed envelope for an epoch (for re-sealing on rotation).
    pub fn sealed_members(&self, epoch: u32) -> Vec<UserId> {
        match self.epoch_map(epoch, false) {
            Ok(Some(m)) => lx::map_keys(&m)
                .into_iter()
                .map(UserId::from_key_string)
                .collect(),
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::acl::{sign_op, AclAction, AclOp, Grant};
    use crate::ids::{ActorId, SystemUlidSource};

    fn ws() -> WorkspaceId {
        WorkspaceId::mint(&SystemUlidSource)
    }
    fn user(n: u8) -> UserId {
        use ed25519_dalek::SigningKey;
        let pk = SigningKey::from_bytes(&[n; 32]).verifying_key();
        UserId::from_key_string(data_encoding::HEXLOWER.encode(pk.as_bytes()))
    }
    fn actor(n: u8) -> ActorId {
        ActorId::from_incept_hash(&format!("{:064x}", n))
    }
    fn add_op(subject: u8, grants: Vec<Grant>, parents: Vec<String>, w: &WorkspaceId) -> SignedOp {
        sign_op(
            &[1; 32],
            &AclOp {
                action: AclAction::AddMember {
                    actor: actor(subject),
                    grants,
                },
                by: actor(1),
                actor_asof: vec![],
            },
            parents,
            w,
        )
    }
    fn ctx(kind: &str) -> OpCtx {
        OpCtx::authority(kind, &user(1))
    }
    fn fresh(w: &WorkspaceId) -> MembershipDoc {
        MembershipDoc::create(w, None, &user(1)).unwrap()
    }

    #[test]
    fn ops_grow_only_and_heads_track_frontier() {
        let w = ws();
        let m = fresh(&w);
        let op1 = add_op(2, vec![Grant::Write], vec![], &w);
        m.add_op(&op1).unwrap();
        m.add_op(&op1).unwrap(); // idempotent
        m.apply(&ctx("member_add"));
        assert_eq!(m.ops().len(), 1);
        assert_eq!(m.heads(), vec![op1.hash()]);
        let op2 = sign_op(
            &[1; 32],
            &AclOp {
                action: AclAction::RemoveMember { actor: actor(2) },
                by: actor(1),
                actor_asof: vec![],
            },
            vec![op1.hash()],
            &w,
        );
        m.add_op(&op2).unwrap();
        m.apply(&ctx("member_remove"));
        assert_eq!(m.heads(), vec![op2.hash()], "head advances to the new op");
    }

    #[test]
    fn sealed_keys_per_epoch_roundtrip() {
        let m = fresh(&ws());
        m.put_sealed(0, &user(1), b"sealed-for-1").unwrap();
        m.put_sealed(0, &user(2), b"sealed-for-2").unwrap();
        m.apply(&ctx("seal"));
        assert_eq!(
            m.get_sealed(0, &user(1)).as_deref(),
            Some(&b"sealed-for-1"[..])
        );
        assert_eq!(
            m.get_sealed(1, &user(1)),
            None,
            "no envelope for a future epoch"
        );
        let mut members = m.sealed_members(0);
        members.sort();
        let mut expect = vec![user(1), user(2)];
        expect.sort();
        assert_eq!(members, expect);
    }

    #[test]
    fn redeemed_nonces_record_and_survive_a_snapshot() {
        let m = fresh(&ws());
        let nonce = [7u8; 16];
        assert!(!m.is_redeemed(&nonce), "unseen nonce is not redeemed");
        m.mark_redeemed(&nonce, &user(3)).unwrap();
        m.apply(&ctx("invite_redeem"));
        assert!(m.is_redeemed(&nonce), "burned nonce reads back as redeemed");
        assert!(
            !m.is_redeemed(&[8u8; 16]),
            "a different nonce is still fresh"
        );
        // The guard is synced state, so it must survive a snapshot round-trip
        // (this is what gives a second admin the same replay protection).
        let snap = m.snapshot().unwrap();
        let loaded = MembershipDoc::from_snapshot(&snap, None).unwrap();
        assert!(loaded.is_redeemed(&nonce), "redemption survives snapshot");
    }

    #[test]
    fn snapshot_roundtrip_preserves_membership() {
        let w = ws();
        let m = fresh(&w);
        let op = add_op(2, vec![Grant::Admin], vec![], &w);
        m.add_op(&op).unwrap();
        m.put_sealed(0, &user(2), b"k").unwrap();
        m.set_epoch(1).unwrap();
        m.apply(&ctx("member_add"));
        let snap = m.snapshot().unwrap();
        let loaded = MembershipDoc::from_snapshot(&snap, None).unwrap();
        assert_eq!(loaded.ops().len(), 1);
        assert_eq!(loaded.current_epoch(), 1);
        assert_eq!(loaded.get_sealed(0, &user(2)).as_deref(), Some(&b"k"[..]));
    }
}
