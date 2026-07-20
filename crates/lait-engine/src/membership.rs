//! The plaintext membership document transports signed authority inputs and
//! sealed key material needed before encrypted collaborative state can open.
//!
//! It carries actor and membership events, content-key epochs and envelopes,
//! and ceremony, recovery, custody, and space-authority records. It is synced
//! before encrypted catalog and issue documents so an authorized device can
//! obtain the content key needed to decrypt them.
//!
//! Plaintext means routable without the workspace content key, not trusted.
//! Loro only transports records; kernel replay validates signed inputs, and
//! malformed or unauthorized inputs remain inert. Commit metadata is likewise
//! visible to peers that receive this document.

use anyhow::{anyhow, Result};
use loro::{Container, ExportMode, Frontiers, LoroDoc, LoroList, LoroMap, ValueOrContainer};

use crate::acl::SignedOp;
use crate::ids::{UserId, WorkspaceId};

use crate::loro_ext as lx;
use crate::op::{self, OpCtx};

const ROOT: &str = "membership";
const K_WORKSPACE: &str = "workspaceId";
const C_ACL: &str = "acl";
const C_ACTORS: &str = "actors"; // the lait/actor/1 key-event log (flat, grow-only)
const C_SPACE: &str = "space"; // the lait/space/1 event log (break-glass recovery, grow-only)
const C_CEREMONY: &str = "ceremony"; // FROST DKG/signing round packages (grow-only bulletin board)
                                     // Per-device sealed key envelopes, keyed by content-addressed epoch id. The
                                     // epoch's *authorization* (gen, recipient set, key commitment) is NOT here — it
                                     // rides a signed `AclAction::MintEpoch` on the ACL DAG (C_ACL), so a replica
                                     // adopts a key only when a valid writer-signed mint authorizes its epoch. These
                                     // envelopes are unsigned ciphertext, but each is bound to its mint by
                                     // `blake3(key) == mint.key_commit`, so a forged envelope is inert.
const C_KEYS: &str = "keys"; // epoch_id(hex) -> Map<device UserId, sealed bytes>

fn epoch_hex(id: &[u8; 16]) -> String {
    data_encoding::HEXLOWER.encode(id)
}

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
        root.insert_container(C_ACL, LoroList::new())?;
        root.insert_container(C_ACTORS, LoroList::new())?;
        root.insert_container(C_SPACE, LoroList::new())?;
        root.insert_container(C_CEREMONY, LoroList::new())?;
        root.insert_container(C_KEYS, LoroMap::new())?;
        op::commit_with(&doc, &OpCtx::authority("init", founder));
        Ok(Self { doc })
    }

    /// Load stored snapshot bytes with the engine's required Loro configuration.
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

    /// Land staged operations as one metadata-bearing change.
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
    pub(crate) fn head(&self) -> Frontiers {
        self.doc.oplog_frontiers()
    }
    /// Encoded membership frontiers used in the combined synchronization head.
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
            _ if create => self.root().insert_container(C_ACTORS, LoroList::new()).ok(),
            _ => None,
        }
    }

    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        lx::get_str(&self.root(), K_WORKSPACE).and_then(|s| WorkspaceId::parse(&s))
    }

    // ---- ACL ops (grow-only) ----

    /// Append a signed operation idempotently by hash to the grow-only event set.
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
    /// for the next operation.
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

    // ---- space events (the lait/space/1 recovery plane, grow-only) ----

    fn space_list(&self) -> Option<LoroList> {
        match self.root().get(C_SPACE) {
            Some(ValueOrContainer::Container(Container::List(l))) => Some(l),
            _ => None,
        }
    }

    /// Append a signed space-plane event (idempotent by hash). These re-seed the
    /// acl root under threshold recovery authority (`lait/space/1`). The container
    /// is founded in [`create`](Self::create) and arrives by sync, so a recovering
    /// node appends to the shared container rather than minting a conflicting one
    /// (missing ⇒ the store hasn't synced yet).
    pub fn add_space_event(&self, ev: &crate::space::SignedSpaceEvent) -> Result<()> {
        let hash = ev.hash();
        if self.space_events().iter().any(|e| e.hash() == hash) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(ev).map_err(|e| anyhow!("encode space event: {e}"))?;
        let list = self
            .space_list()
            .ok_or_else(|| anyhow!("space container missing — sync the workspace first"))?;
        list.insert(list.len(), bytes.as_slice())?;
        Ok(())
    }

    // ---- FROST ceremony bulletin board (grow-only, ephemeral coordination) ----

    fn ceremony_list(&self) -> Option<LoroList> {
        match self.root().get(C_CEREMONY) {
            Some(ValueOrContainer::Container(Container::List(l))) => Some(l),
            _ => None,
        }
    }

    /// Append a signed ceremony contribution (idempotent by hash). Round packages
    /// for a FROST DKG/signing session; the container arrives by sync so a
    /// participant appends rather than minting a conflicting one.
    pub fn add_ceremony_event(&self, ev: &crate::space::SignedSpaceEvent) -> Result<()> {
        let hash = ev.hash();
        if self.ceremony_events().iter().any(|e| e.hash() == hash) {
            return Ok(());
        }
        let bytes = postcard::to_stdvec(ev).map_err(|e| anyhow!("encode ceremony event: {e}"))?;
        let list = self
            .ceremony_list()
            .ok_or_else(|| anyhow!("ceremony container missing — sync the workspace first"))?;
        list.insert(list.len(), bytes.as_slice())?;
        Ok(())
    }

    /// All ceremony contributions currently held.
    pub fn ceremony_events(&self) -> Vec<crate::space::SignedSpaceEvent> {
        let Some(list) = self.ceremony_list() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(loro::LoroValue::Binary(b))) = list.get(i) {
                if let Ok(ev) = postcard::from_bytes::<crate::space::SignedSpaceEvent>(&b) {
                    out.push(ev);
                }
            }
        }
        out
    }

    /// All space-plane events currently held.
    pub fn space_events(&self) -> Vec<crate::space::SignedSpaceEvent> {
        let Some(list) = self.space_list() else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for i in 0..list.len() {
            if let Some(ValueOrContainer::Value(loro::LoroValue::Binary(b))) = list.get(i) {
                if let Ok(ev) = postcard::from_bytes::<crate::space::SignedSpaceEvent>(&b) {
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

    // ---- per-epoch sealed key envelopes (authorization lives on the ACL DAG) ----

    fn epoch_keymap(&self, id: &[u8; 16], create: bool) -> Result<Option<LoroMap>> {
        let keys = self
            .keys_map()
            .ok_or_else(|| anyhow!("keys container missing"))?;
        let hx = epoch_hex(id);
        match keys.get(&hx) {
            Some(ValueOrContainer::Container(Container::Map(m))) => Ok(Some(m)),
            _ if create => Ok(Some(keys.insert_container(&hx, LoroMap::new())?)),
            _ => Ok(None),
        }
    }

    /// Store the workspace key sealed to `device` for `epoch`.
    pub fn put_sealed(&self, epoch: &[u8; 16], device: &UserId, sealed: &[u8]) -> Result<()> {
        let m = self.epoch_keymap(epoch, true)?.unwrap();
        m.insert(device.as_str(), sealed)?;
        Ok(())
    }

    /// Retrieve the sealed key envelope addressed to `device` for `epoch`.
    pub fn get_sealed(&self, epoch: &[u8; 16], device: &UserId) -> Option<Vec<u8>> {
        let m = self.epoch_keymap(epoch, false).ok().flatten()?;
        lx::get_bytes(&m, device.as_str())
    }

    /// The devices with a sealed envelope for `epoch` (for self-heal).
    pub fn sealed_devices(&self, epoch: &[u8; 16]) -> Vec<UserId> {
        match self.epoch_keymap(epoch, false) {
            Ok(Some(m)) => lx::map_keys(&m)
                .into_iter()
                .map(UserId::from_key_string)
                .collect(),
            _ => Vec::new(),
        }
    }

    // ---- single-use invite replay guard (Pattern A) ----
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
                nonce: None,
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
                nonce: None,
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
        // Epoch *authorization* now rides a signed MintEpoch op on the ACL DAG;
        // the doc only holds the per-device sealed envelopes, keyed by epoch id.
        let m = fresh(&ws());
        let e0 = [0u8; 16];
        let e1 = [1u8; 16];
        m.put_sealed(&e0, &user(1), b"sealed-for-1").unwrap();
        m.put_sealed(&e0, &user(2), b"sealed-for-2").unwrap();
        m.apply(&ctx("seal"));
        assert_eq!(
            m.get_sealed(&e0, &user(1)).as_deref(),
            Some(&b"sealed-for-1"[..])
        );
        assert_eq!(
            m.get_sealed(&e1, &user(1)),
            None,
            "no envelope for an unknown epoch"
        );
        let mut devs = m.sealed_devices(&e0);
        devs.sort();
        let mut expect = vec![user(1), user(2)];
        expect.sort();
        assert_eq!(devs, expect);
    }

    #[test]
    fn snapshot_roundtrip_preserves_membership() {
        let w = ws();
        let m = fresh(&w);
        let op = add_op(2, vec![Grant::Admin], vec![], &w);
        m.add_op(&op).unwrap();
        let e0 = [9u8; 16];
        m.put_sealed(&e0, &user(2), b"k").unwrap();
        m.apply(&ctx("member_add"));
        let snap = m.snapshot().unwrap();
        let loaded = MembershipDoc::from_snapshot(&snap, None).unwrap();
        assert_eq!(loaded.ops().len(), 1);
        assert_eq!(loaded.get_sealed(&e0, &user(2)).as_deref(), Some(&b"k"[..]));
    }
}
