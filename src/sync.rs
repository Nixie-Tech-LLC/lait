//! Layer C — live P2P sync over iroh (A§8, S§8). A **catalog-first pull** over a
//! direct QUIC bi-stream on a custom ALPN: exchange the one Catalog VV-diff to
//! learn the whole changed-head set, then fetch each changed issue doc by
//! per-doc VV-diff, multiplexed over the one stream as length-prefixed,
//! `DocId`-keyed frames.
//!
//! The protocol is a **pull** (the dialer pulls the accepter's state), which is
//! strictly turn-taking and therefore deadlock-free on one bi-stream. Both
//! directions are covered because each node pulls from a peer whenever it hears
//! that peer's catalog head moved (gossip announce, [`crate::proto`]). All Loro
//! work happens under the tracker lock in short synchronous sections; all QUIC
//! IO happens outside the lock.
//!
//! Forward-compat (A§10): frames are already per-doc `export(updates)` blobs
//! keyed by `DocId`, so P2/P3 wrap the ciphertext-chunk envelope around them
//! without reshaping this protocol.

use std::sync::Mutex;

use anyhow::{anyhow, Context, Result};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::tracker::{DirtySet, Tracker};

/// The ALPN for the pairwise Loro-sync protocol.
pub const SYNC_ALPN: &[u8] = b"groupchat/sync/0";

/// A single sync frame. Postcard-encoded, length-prefixed on the stream.
#[derive(Debug, Serialize, Deserialize)]
enum Msg {
    /// Dialer → accepter (first frame): "pull me up to date; here are my
    /// membership + catalog versions so you can send only what I lack."
    Pull {
        workspace: String,
        membership_vv: Vec<u8>,
        catalog_vv: Vec<u8>,
    },
    /// Accepter → dialer: the plaintext membership update-diff (signed ACL +
    /// sealed key envelopes), sent *before* the encrypted catalog (A§11).
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

/// Max framed message size (64 MiB) — a guard against a malformed length.
const MAX_FRAME: u32 = 64 * 1024 * 1024;

async fn write_msg(send: &mut SendStream, msg: &Msg) -> Result<()> {
    let bytes = postcard::to_stdvec(msg).context("encode sync frame")?;
    let len = u32::try_from(bytes.len()).map_err(|_| anyhow!("sync frame too large"))?;
    send.write_all(&len.to_be_bytes())
        .await
        .context("write frame length")?;
    send.write_all(&bytes).await.context("write frame body")?;
    Ok(())
}

async fn read_msg(recv: &mut RecvStream) -> Result<Option<Msg>> {
    let mut len_buf = [0u8; 4];
    match recv.read_exact(&mut len_buf).await {
        Ok(()) => {}
        Err(_) => return Ok(None), // clean EOF / stream closed
    }
    let len = u32::from_be_bytes(len_buf);
    if len > MAX_FRAME {
        return Err(anyhow!("sync frame length {len} exceeds cap"));
    }
    let mut buf = vec![0u8; len as usize];
    recv.read_exact(&mut buf).await.context("read frame body")?;
    let msg: Msg = postcard::from_bytes(&buf).context("decode sync frame")?;
    Ok(Some(msg))
}

/// **Dialer side.** Pull a peer's state up to date and return a coalesced
/// dirty-set describing everything that changed locally (the node rings one
/// doorbell for it — daemon-side batching, UI.md §4.2).
pub async fn pull(conn: &Connection, tracker: &Mutex<Tracker>) -> Result<DirtySet> {
    let (mut send, mut recv) = conn.open_bi().await.context("open sync stream")?;

    // 1. send our membership + catalog VVs.
    let (workspace, membership_vv, catalog_vv) = {
        let t = tracker.lock().unwrap();
        (
            t.workspace_str(),
            t.membership_vv_bytes(),
            t.catalog_vv_bytes(),
        )
    };
    write_msg(
        &mut send,
        &Msg::Pull {
            workspace,
            membership_vv,
            catalog_vv,
        },
    )
    .await?;

    // 2a. read the plaintext membership diff first (A§11) and import it — we may
    // have just been added and can now decrypt the catalog/docs below.
    let mut dirty = DirtySet::default();
    match read_msg(&mut recv).await? {
        Some(Msg::Membership { update }) => {
            if !update.is_empty() {
                let mut t = tracker.lock().unwrap();
                t.import_membership(&update)?;
                dirty.merge(DirtySet::catalog_structure());
            }
        }
        other => return Err(anyhow!("expected Membership, got {other:?}")),
    }

    // 2b. read the encrypted catalog diff, decrypt+import, compute needed docs.
    let needs = match read_msg(&mut recv).await? {
        Some(Msg::Catalog { update }) => {
            let changed = !update.is_empty();
            let needs = {
                let mut t = tracker.lock().unwrap();
                t.import_catalog_and_compute_needs(&update)?
            };
            // A non-empty catalog diff may have changed registries/board order the
            // client should repaint; per-row dirt rides on import_doc below.
            if changed {
                dirty.merge(DirtySet::catalog_structure());
            }
            needs
        }
        other => return Err(anyhow!("expected Catalog, got {other:?}")),
    };

    // 3. request each needed doc, then signal end.
    for need in &needs {
        write_msg(
            &mut send,
            &Msg::DocRequest {
                doc_id: need.doc_id.clone(),
                vv: need.vv.clone(),
            },
        )
        .await?;
    }
    write_msg(&mut send, &Msg::EndRequests).await?;

    // 4. read doc updates until EndDocs, importing each; coalesce dirty-sets.
    loop {
        match read_msg(&mut recv).await? {
            Some(Msg::DocUpdate { doc_id, bytes }) => {
                let mut t = tracker.lock().unwrap();
                if let Some(d) = t.import_doc(&doc_id, &bytes)? {
                    dirty.merge(d);
                }
            }
            Some(Msg::DocMissing { .. }) => {}
            Some(Msg::EndDocs) | None => break,
            other => return Err(anyhow!("unexpected frame during doc phase: {other:?}")),
        }
    }

    send.finish().ok();
    Ok(dirty)
}

/// **Accepter side.** Serve a pull: answer the dialer's catalog + doc requests.
/// Read-only with respect to our own state (a pull never mutates the provider),
/// so it never rings a doorbell here.
pub async fn serve(conn: Connection, tracker: &Mutex<Tracker>) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await.context("accept sync stream")?;

    // 1. read the Pull; guard the workspace.
    let (membership_vv, catalog_vv) = match read_msg(&mut recv).await? {
        Some(Msg::Pull {
            workspace,
            membership_vv,
            catalog_vv,
        }) => {
            let mine = tracker.lock().unwrap().workspace_str();
            if workspace != mine {
                return Err(anyhow!("workspace mismatch: {workspace} != {mine}"));
            }
            (membership_vv, catalog_vv)
        }
        other => return Err(anyhow!("expected Pull, got {other:?}")),
    };

    // 2a. send the plaintext membership diff (signed ACL + sealed keys), then
    // 2b. the encrypted catalog diff.
    let (membership, catalog) = {
        let t = tracker.lock().unwrap();
        (
            t.export_membership_from(&membership_vv)?,
            t.export_catalog_from(&catalog_vv)?,
        )
    };
    write_msg(&mut send, &Msg::Membership { update: membership }).await?;
    write_msg(&mut send, &Msg::Catalog { update: catalog }).await?;

    // 3. answer doc requests until EndRequests.
    loop {
        match read_msg(&mut recv).await? {
            Some(Msg::DocRequest { doc_id, vv }) => {
                let exported = tracker.lock().unwrap().export_doc_from(&doc_id, &vv)?;
                match exported {
                    Some(bytes) => write_msg(&mut send, &Msg::DocUpdate { doc_id, bytes }).await?,
                    None => write_msg(&mut send, &Msg::DocMissing { doc_id }).await?,
                }
            }
            Some(Msg::EndRequests) | None => break,
            other => return Err(anyhow!("unexpected frame during request phase: {other:?}")),
        }
    }
    write_msg(&mut send, &Msg::EndDocs).await?;
    send.finish().ok();
    Ok(())
}
