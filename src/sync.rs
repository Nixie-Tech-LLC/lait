//! Live peer-to-peer sync over the transport seam. A **catalog-first pull** over
//! one framed [`Stream`] on a custom ALPN: exchange the one Catalog VV-diff to
//! learn the whole changed-head set, then fetch each changed issue doc by
//! per-doc VV-diff, multiplexed over the one stream as `DocId`-keyed frames.
//!
//! The protocol is a **pull** (the dialer pulls the accepter's state), which is
//! strictly turn-taking and therefore deadlock-free on one stream. Both
//! directions are covered because each node pulls from a peer whenever it hears
//! that peer's catalog head moved (gossip announce, [`crate::proto`]). All Loro
//! work happens under the replica lock in short synchronous sections; all
//! network IO happens outside the lock.
//!
//! For forward compatibility, frames are per-document `export(updates)` blobs
//! keyed by `DocId`, so encrypted space data wraps them in ciphertext chunks
//! without reshaping this protocol.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

use crate::{
    replica::{DirtySet, Replica},
    transport::Stream,
};

/// The ALPN for the pairwise Loro-sync protocol. The trailing number is the
/// protocol **epoch** — bump it for a change so breaking that peers of the old
/// epoch must not even connect (QUIC's ALPN negotiation refuses them at the
/// transport, before any frame is exchanged). Epoch 1 covered the
/// space-identity rewrite (topic-from-space-id, SpaceTicket) AND the in-band
/// `protocol_version` handshake below; epoch 0 had neither. Epoch 2 fences the
/// space-vocabulary flag day: the persisted and control shapes both changed
/// field names, so a skewed peer must fail at ALPN rather than reach a
/// confusing decode error.
pub const SYNC_ALPN: &[u8] = b"lait/sync/2";

/// The sync protocol version this build **speaks**, exchanged in the `Pull`
/// handshake. Within one ALPN epoch, bump this for a backward-compatible change
/// and raise [`MIN_SUPPORTED_PROTOCOL`] only when dropping support for an old
/// version. Peers outside `[MIN_SUPPORTED_PROTOCOL, PROTOCOL_VERSION]` are
/// refused with a clear diagnostic instead of failing to decode silently.
///
/// **v2:** the catalog gained the encrypted `authz`
/// signed-op DAG and membership gained the `AddAgent` op kind. A v1 node drops
/// op kinds it can't decode, which diverges its membership ancestor closure —
/// and thus its key-sealing recipient set — from a v2 node's, splitting E2EE.
/// So v2 refuses v1 outright (`MIN_SUPPORTED_PROTOCOL = 2`): the flag day the
/// versioning contract exists for, taken while the mesh is small. Going
/// forward, replay keeps signature-valid-but-undecodable ops as opaque DAG
/// nodes (`acl`/`authz`), so that was the last divergence-class flag day.
///
/// **v3:** the space-vocabulary rename. No divergence class — a v2 peer simply
/// spells the persisted and control shapes differently, and there is no
/// migration, so `MIN_SUPPORTED_PROTOCOL = 3` retires v2 alongside it.
pub const PROTOCOL_VERSION: u32 = 3;
/// The oldest sync protocol version we still accept from a peer. Raising this is
/// how a retired version is dropped — it defines the mixed-version support window.
pub const MIN_SUPPORTED_PROTOCOL: u32 = 3;

/// Whether we can sync with a peer advertising protocol version `peer`. Accepts
/// peers inside the supported window; outside it, returns a human-facing reason
/// (the peer is too old and must upgrade, or is newer and we must). Pure so the
/// window policy is unit-testable without a live connection.
fn check_sync_protocol(peer: u32) -> Result<()> {
    if peer < MIN_SUPPORTED_PROTOCOL {
        return Err(anyhow!(
            "peer speaks sync protocol v{peer}, older than the minimum this build \
             supports (v{MIN_SUPPORTED_PROTOCOL}); the peer must upgrade lait"
        ));
    }
    if peer > PROTOCOL_VERSION {
        return Err(anyhow!(
            "peer speaks sync protocol v{peer}, newer than this build's \
             v{PROTOCOL_VERSION}; upgrade lait to sync with it"
        ));
    }
    Ok(())
}

/// A single sync frame. Postcard-encoded, length-prefixed on the stream.
#[derive(Debug, Serialize, Deserialize)]
enum Msg {
    /// Dialer → accepter (first frame): "pull me up to date; here are my
    /// membership + catalog versions so you can send only what I lack."
    Pull {
        /// The dialer's sync protocol version (see [`PROTOCOL_VERSION`]). First
        /// field so the accepter can reject an out-of-window peer with a clear
        /// error before touching the rest of the frame.
        protocol_version: u32,
        space: String,
        membership_vv: Vec<u8>,
        catalog_vv: Vec<u8>,
    },
    /// Accepter → dialer: the plaintext membership update-diff (signed ACL +
    /// sealed key envelopes), sent *before* the encrypted catalog.
    Membership { update: Vec<u8> },
    /// Accepter → dialer: the (encrypted) catalog update-diff.
    Catalog { update: Vec<u8> },
    /// Dialer → accepter (repeated): "send me this doc's updates from my VV."
    DocRequest { doc_id: String, vv: Vec<u8> },
    /// Dialer → accepter: no more requests.
    EndRequests,
    /// Accepter → dialer (repeated): a doc's updates.
    DocUpdate { doc_id: String, bytes: Vec<u8> },
    /// Accepter → dialer: I don't hold that doc.
    DocMissing { doc_id: String },
    /// Accepter → dialer: all requested docs sent.
    EndDocs,
}

/// One `Msg` per frame. Length framing and its cap belong to the transport,
/// which owns the wire; this protocol only says what a frame *means*.
async fn send_msg(stream: &mut dyn Stream, msg: &Msg) -> Result<()> {
    let body = postcard::to_stdvec(msg).context("encode sync frame")?;
    stream.send(&body).await
}

/// `Ok(None)` is a **clean** end at a frame boundary; a truncated or lost
/// stream is an `Err`, so a partial transfer can never be mistaken for a
/// finished one.
async fn recv_msg(stream: &mut dyn Stream) -> Result<Option<Msg>> {
    match stream.recv().await? {
        Some(body) => Ok(Some(
            postcard::from_bytes(&body).context("decode sync frame")?,
        )),
        None => Ok(None),
    }
}

/// What a pull achieved.
///
/// `complete` is the distinction the caller cannot make from `dirty` alone: a
/// doc phase that ended before `EndDocs` still imported real work that must ring
/// its doorbell, but the peer's state is not yet ours. Reporting that as a
/// finished sync is how a truncated transfer disappears — re-announced and
/// persisted exactly as if everything had arrived.
pub struct PullOutcome {
    pub dirty: DirtySet,
    pub complete: bool,
}

/// **Dialer side.** Pull a peer's state up to date. The returned
/// [`PullOutcome`] carries a coalesced dirty-set of everything that changed
/// locally (the node rings one doorbell for it through daemon-side batching)
/// and whether the transfer actually reached its end.
pub async fn pull(stream: &mut dyn Stream, replica: &Mutex<Replica>) -> Result<PullOutcome> {
    // 1. send our membership + catalog VVs.
    let (space, membership_vv, catalog_vv) = {
        let t = replica.lock().unwrap();
        (t.space_str(), t.membership_vv_bytes(), t.catalog_vv_bytes())
    };
    send_msg(
        stream,
        &Msg::Pull {
            protocol_version: PROTOCOL_VERSION,
            space,
            membership_vv,
            catalog_vv,
        },
    )
    .await?;

    // Read and import the plaintext membership diff first; it may provide the
    // have just been added and can now decrypt the catalog/docs below.
    let mut dirty = DirtySet::default();
    match recv_msg(stream).await? {
        Some(Msg::Membership { update }) => {
            if !update.is_empty() {
                let mut t = replica.lock().unwrap();
                t.import_membership(&update)?;
                dirty.merge(DirtySet::catalog_structure());
            }
        }
        None => return Err(anyhow!("peer closed before sending Membership")),
        other => return Err(anyhow!("expected Membership, got {other:?}")),
    }

    // 2b. read the encrypted catalog diff, decrypt+import, compute needed docs.
    let needs = match recv_msg(stream).await? {
        Some(Msg::Catalog { update }) => {
            let changed = !update.is_empty();
            let needs = {
                let mut t = replica.lock().unwrap();
                t.import_catalog_and_compute_needs(&update)?
            };
            // A non-empty catalog diff may have changed registries/board order the
            // client should repaint; per-row dirt rides on import_doc below.
            if changed {
                dirty.merge(DirtySet::catalog_structure());
            }
            needs
        }
        None => return Err(anyhow!("peer closed before sending Catalog")),
        other => return Err(anyhow!("expected Catalog, got {other:?}")),
    };

    // 3. request each needed doc, then signal end.
    for need in &needs {
        send_msg(
            stream,
            &Msg::DocRequest {
                doc_id: need.doc_id.clone(),
                vv: need.vv.clone(),
            },
        )
        .await?;
    }
    send_msg(stream, &Msg::EndRequests).await?;

    // 4. read doc updates until EndDocs, importing each; coalesce dirty-sets.
    // A truncation here is NOT fatal: whatever imported is real and keeps its
    // doorbell, so the loop breaks with what it has instead of unwinding. What
    // it must not do is claim the pull finished — convergence then rests on the
    // caller's retry and on the next announce or heartbeat.
    let mut complete = false;
    loop {
        match recv_msg(stream).await {
            Ok(Some(Msg::DocUpdate { doc_id, bytes })) => {
                let mut t = replica.lock().unwrap();
                if let Some(d) = t.import_doc(&doc_id, &bytes)? {
                    dirty.merge(d);
                }
            }
            Ok(Some(Msg::DocMissing { .. })) => {}
            Ok(Some(Msg::EndDocs)) => {
                complete = true;
                break;
            }
            Ok(Some(other)) => return Err(anyhow!("unexpected frame during doc phase: {other:?}")),
            Ok(None) => {
                tracing::debug!("peer ended the doc phase before EndDocs");
                break;
            }
            Err(e) => {
                tracing::warn!("sync pull truncated: {e:#}");
                break;
            }
        }
    }

    stream.finish().await.ok();
    Ok(PullOutcome { dirty, complete })
}

/// **Accepter side.** Serve a pull: answer the dialer's catalog + doc requests.
/// Read-only with respect to our own state (a pull never mutates the provider),
/// so it never rings a doorbell here.
/// The stream is **borrowed**: connection lifecycle belongs to the accept loop,
/// which parks on `wait_closed` after this returns — including on the error
/// paths a `?` in here would skip.
pub async fn serve(stream: &mut dyn Stream, replica: &Mutex<Replica>) -> Result<()> {
    // 1. read the Pull; guard the space.
    let (membership_vv, catalog_vv) = match recv_msg(stream).await? {
        Some(Msg::Pull {
            protocol_version,
            space,
            membership_vv,
            catalog_vv,
        }) => {
            // Version before space: an out-of-window peer gets a clear
            // "upgrade" error rather than a confusing downstream failure.
            check_sync_protocol(protocol_version)?;
            let mine = replica.lock().unwrap().space_str();
            if space != mine {
                return Err(anyhow!("space mismatch: {space} != {mine}"));
            }
            (membership_vv, catalog_vv)
        }
        None => return Err(anyhow!("dialer closed before sending Pull")),
        other => return Err(anyhow!("expected Pull, got {other:?}")),
    };

    // 2a. send the plaintext membership diff (signed ACL + sealed keys), then
    // 2b. the encrypted catalog diff.
    let (membership, catalog) = {
        let t = replica.lock().unwrap();
        (
            t.export_membership_from(&membership_vv)?,
            t.export_catalog_from(&catalog_vv)?,
        )
    };
    send_msg(stream, &Msg::Membership { update: membership }).await?;
    send_msg(stream, &Msg::Catalog { update: catalog }).await?;

    // 3. answer doc requests until EndRequests. A vanished dialer propagates:
    // a pull never mutates the provider, so nothing of ours is at risk.
    loop {
        match recv_msg(stream).await? {
            Some(Msg::DocRequest { doc_id, vv }) => {
                let exported = replica.lock().unwrap().export_doc_from(&doc_id, &vv)?;
                match exported {
                    Some(bytes) => send_msg(stream, &Msg::DocUpdate { doc_id, bytes }).await?,
                    None => send_msg(stream, &Msg::DocMissing { doc_id }).await?,
                }
            }
            Some(Msg::EndRequests) | None => break,
            other => return Err(anyhow!("unexpected frame during request phase: {other:?}")),
        }
    }
    send_msg(stream, &Msg::EndDocs).await?;
    stream.finish().await.ok();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_window_accepts_supported_and_refuses_outside() {
        // Everything in [MIN_SUPPORTED_PROTOCOL, PROTOCOL_VERSION] is accepted.
        assert!(check_sync_protocol(PROTOCOL_VERSION).is_ok());
        assert!(check_sync_protocol(MIN_SUPPORTED_PROTOCOL).is_ok());

        // A newer peer than we understand is refused (we must upgrade).
        assert!(check_sync_protocol(PROTOCOL_VERSION + 1).is_err());

        // A peer older than the support window is refused (it must upgrade).
        assert!(check_sync_protocol(MIN_SUPPORTED_PROTOCOL - 1).is_err());
    }

    #[test]
    fn pre_v3_peers_are_refused_after_the_space_flag_day() {
        // Two closed flag days, both still enforced. v1 lost to the encrypted
        // `authz` DAG and `AddAgent`, which changed membership ancestry and so
        // the key-sealing recipient set. v2 loses to the space-vocabulary
        // rename, which moved field names across the whole persisted shape.
        // Neither is decodable here, so both are refused rather than tolerated.
        for old in [1, 2] {
            let err = check_sync_protocol(old).unwrap_err().to_string();
            assert!(
                err.contains("upgrade"),
                "the refusal must name the way out: {err}"
            );
        }
    }
}
