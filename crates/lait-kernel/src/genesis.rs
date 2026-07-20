//! The workspace **genesis** — lait's root of trust, represented as pure data.
//!
//! This lives in the kernel, not the store: it is the seed that seeds every
//! trust-plane replay ([`crate::acl`], [`crate::actor`], [`crate::space`],
//! [`crate::authz`]), depends on nothing but identity types, and is durable-
//! format-agnostic. The store merely *persists* it (as `genesis.json`); it does
//! not define it.

use serde::{Deserialize, Serialize};

use crate::ids::{ActorId, WorkspaceId};

/// The workspace genesis — the root of trust. Distributed in the
/// invite ticket; persisted as public data.
///
/// Founding principals are **actors** (self-certifying identities), not raw
/// device keys: a founder's device signs
/// membership ops, but the genesis anchors trust in its *actor* so the founder
/// can rotate devices without re-founding. The founder's inception event ships
/// in the ticket and syncs in the membership doc; a replica validates it by
/// rehashing to the genesis [`ActorId`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Genesis {
    pub workspace_id: WorkspaceId,
    pub founding_actors: Vec<ActorId>,
    /// The salt that, with the founding device key, derives `workspace_id`
    /// (`lait/space/1`). Retained so this node can re-mint verifiable tickets and
    /// so a replica can confirm the id commits to its founder.
    #[serde(default)]
    pub salt: [u8; 16],
    /// The break-glass recovery commitment folded into `workspace_id`
    /// (`H(threshold ‖ sorted[H(recovery_pubkey_i)])`). Seeds the space plane's
    /// recovery authority; rotatable only by a threshold `Recover`.
    #[serde(default)]
    pub recovery_root: [u8; 32],
}
