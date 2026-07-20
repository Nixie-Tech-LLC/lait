//! Catalog-first peer sync; the network layer calls these under the replica lock.

use super::*;

impl Replica {
    // ---- catalog-first peer sync; the network layer calls these ----
    // under the replica lock; all QUIC IO happens outside the lock. ----

    /// The space id as a string (sync handshake guard).
    pub fn space_str(&self) -> String {
        self.space_id.to_string()
    }

    /// The catalog's oplog version vector, wire-encoded (sync handshake).
    pub fn catalog_vv_bytes(&self) -> Vec<u8> {
        self.catalog.oplog_vv_bytes()
    }

    /// The wire-form catalog head digest used in gossip announcements.
    pub fn catalog_head_bytes(&self) -> Vec<u8> {
        self.catalog.head_hash()
    }

    /// A combined sync head over catalog + membership (the gossip announce
    /// trigger). A membership-only change (e.g. `member add`, which doesn't touch
    /// the catalog) still moves this head so peers pull and receive it.
    pub fn sync_head_bytes(&self) -> Vec<u8> {
        let mut h = blake3::Hasher::new();
        h.update(&self.catalog.head_bytes());
        h.update(&self.membership.head_bytes());
        h.finalize().as_bytes().to_vec()
    }

    // ---- plaintext membership sync, separate from encrypted content sync ----

    /// The membership doc's oplog VV, wire-encoded.
    pub fn membership_vv_bytes(&self) -> Vec<u8> {
        self.membership.oplog_vv_bytes()
    }
    /// **Provider side.** Export the membership ops (plaintext) a puller lacks.
    pub fn export_membership_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        self.membership.export_from_bytes(peer_vv)
    }
    /// **Puller side.** Import a membership update (plaintext), then refresh our
    /// keyring — we may have just been added and can now decrypt the space.
    pub fn import_membership(&mut self, update: &[u8]) -> Result<()> {
        self.membership.import(update)?;
        self.store.save_membership(&self.membership)?;
        self.refresh_keyring();
        // Propagate newly held keys to sibling devices that the rotating author
        // may not have seen.
        self.heal_member_device_envelopes()?;
        // Two admins removing different members concurrently can leave the active
        // epoch sealed to a since-removed actor after merge; re-seal to the true
        // current set (convergent, admin-only).
        self.heal_epoch()?;
        // After a break-glass re-root syncs in, the new root's epochs are all the
        // old (de-authorized) admin's — mint a fresh one so the recovered root has
        // a readable, fenced content key.
        self.bootstrap_root_epoch_if_needed()?;
        // Advance any FROST recovery-elevation ceremony this device is part of as
        // the peers' round packages arrive. Never fatal to import: ceremony work is
        // driven off peer-controlled data, so a bad package is logged and skipped.
        if let Err(e) = self.dkg_advance() {
            tracing::warn!("ceremony advance during import failed (skipped): {e:#}");
        }
        Ok(())
    }

    /// **Provider side.** Export the catalog ops a puller at `peer_vv` lacks,
    /// **encrypted** with the current space key in a blind-relay envelope.
    pub fn export_catalog_from(&self, peer_vv: &[u8]) -> Result<Vec<u8>> {
        Ok(self.encrypt_payload(self.catalog.export_from_bytes(peer_vv)?))
    }

    /// **Provider side.** Export a single issue doc's updates from `peer_vv`
    /// (encrypted), or `None` if we don't hold that doc.
    pub fn export_doc_from(&mut self, doc_id: &str, peer_vv: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // Clone the epoch/key context before the issue borrow.
        let plain = match self.issue(&id)? {
            Some(issue) => issue.export_from_bytes(peer_vv)?,
            None => return Ok(None),
        };
        Ok(Some(self.encrypt_payload(plain)))
    }

    /// **Puller side.** Import the provider's catalog update, recompute rows for
    /// documents we hold, recompute their projections, and return the set of
    /// issue docs we must fetch: those we lack, or whose catalog `head` no longer
    /// matches our local issue-document head.
    pub fn import_catalog_and_compute_needs(&mut self, update: &[u8]) -> Result<Vec<DocNeed>> {
        // A non-member has no key and cannot decrypt the blind-relay envelope.
        // read the catalog and simply learns nothing — the E2EE outcome.
        let Some(update) = self.decrypt_payload(update) else {
            return Ok(Vec::new());
        };
        self.catalog.import(&update)?;
        let mut needs = Vec::new();
        let mut healed = false;
        for doc_id in self.catalog.doc_ids() {
            // Ensure the issue doc is loaded (if we hold it) so we can compare
            // its *real* head against the just-imported catalog row.
            let held = self.issue(&doc_id)?.is_some();
            if held {
                // Writer-direction self-heal: the imported catalog's
                // `head`/row fields LWW-merged to a peer's value, but OUR issue
                // doc is the truth for our row — recompute it from the issue doc.
                let issue = self.issues.get(&doc_id).unwrap();
                let local_head = issue.head_hash();
                let cat_head = self
                    .catalog
                    .row(&doc_id)
                    .map(|r| r.head)
                    .unwrap_or_default();
                if local_head != cat_head {
                    // heads differ: either we're behind (fetch) — record the need
                    // with our VV — or we're ahead; recomputing the row is correct
                    // either way, and a redundant fetch of an up-to-date doc is a
                    // cheap empty diff.
                    needs.push(DocNeed {
                        doc_id: doc_id.as_str().to_string(),
                        vv: issue.oplog_vv_bytes(),
                    });
                }
                self.catalog.upsert_row(issue)?;
                healed = true;
            } else {
                needs.push(DocNeed {
                    doc_id: doc_id.as_str().to_string(),
                    vv: Vec::new(), // we lack it → request a full snapshot/update
                });
            }
        }
        if healed {
            self.catalog.apply(&OpCtx::structure("row_heal", &self.me));
        }
        // A peer's imported catalog may carry new signed tombstone/restore ops
        // in the encrypted authorization DAG. Reconcile the cached
        // tombstone flags to the replay so a remote delete/restore takes effect.
        self.reconcile_tombstones()?;
        // Incremental alias upkeep after a catalog reconcile: reconcile every doc
        // the catalog now knows (O(1) per already-consistent doc, so O(N) total —
        // no O(N²) rebuild on every sync round). New peer docs and any offline
        // seq reconciliation are absorbed here.
        for id in self.catalog.doc_ids() {
            self.aliases.reconcile_doc(&self.catalog, &id);
        }
        self.store.save_catalog(&self.catalog)?;
        Ok(needs)
    }

    /// **Puller side.** Import a fetched issue-doc update (creating the doc if
    /// new), persist it, and recompute its catalog row from the issue doc
    /// using writer-direction projection. Returns a dirty set for a coalesced doorbell.
    ///
    /// The activity row and the inbox are derived from the **oplog diff** around
    /// the import: field-level changes, exactly the new comments
    /// (wherever they merged in the list — CRDT-positional, not index
    /// arithmetic), the DAG concurrency flag, and the incoming changes' advisory
    /// actor claims (their commit messages travel with the ops).
    pub fn import_doc(&mut self, doc_id: &str, bytes: &[u8]) -> Result<Option<DirtySet>> {
        let Some(id) = DocId::parse(doc_id) else {
            return Ok(None);
        };
        // A non-member has no key and cannot decrypt the blind-relay envelope.
        let Some(bytes) = self.decrypt_payload(bytes) else {
            return Ok(None);
        };
        // Viewer-relative pre-import state for the inbox's assigned/status
        // entries: "addressed to you" is a state transition, never
        // trusted attribution. `None` ⇒ the doc is new to this node.
        let prior = self.issues.get(&id).map(|i| {
            let mine = self.my_actor().is_some_and(|a| i.assignees().contains(&a));
            (mine, i.status())
        });
        let mark = self.issues.get(&id).map(|i| i.import_mark());
        // ensure a doc exists to import into (new docs arrive as a snapshot).
        if !self.issues.contains_key(&id) {
            let doc = IssueDoc::from_snapshot(&bytes, Some(self.store.peer_id()))
                .map_err(|e| anyhow!("import new issue doc: {e}"))?;
            self.issues.insert(id.clone(), doc);
        } else {
            self.issues
                .get(&id)
                .unwrap()
                .import(&bytes)
                .map_err(|e| anyhow!("import issue update: {e}"))?;
        }
        // persist + recompute the row from the issue doc (disjoint field borrows).
        let issue = self.issues.get(&id).unwrap();
        let delta = mark
            .as_ref()
            .map(|m| history::import_delta(issue, m))
            .unwrap_or_default();
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.apply(&OpCtx::structure("synced", &self.me));
        let project_id = issue.project_id();
        self.store.save_catalog(&self.catalog)?;
        // Incremental upkeep for the one fetched doc (new or updated), O(log N).
        self.aliases.reconcile_doc(&self.catalog, &id);
        // A synced document advances the activity feed by pull, never by streamed rows.
        let reff = self.aliases.canonical_for(&id);
        // Attribute the row to the incoming ops' committing **device** when it
        // is unambiguous — deliberately not resolved to an actor. This is a
        // sync/commit stamp (`committedBy`), not authorship (`createdBy`): which
        // device landed the ops is the fact worth keeping when a peer misbehaves,
        // and it survives that device later leaving its actor. Advisory either
        // way — self-asserted in the commit message (non-goal 6).
        let actor = match delta.actors.as_slice() {
            [one] => Some(one.clone()),
            _ => None,
        };
        self.push_activity_from(ActivityEvent {
            seq: 0, // stamped by push_activity_from
            doc_id: Some(id.clone()),
            reff: reff.clone(),
            kind: "synced".into(),
            changes: delta.fields.clone(),
            actor,
            actor_nick: String::new(),
            text: delta
                .new_comments
                .first()
                .map(|c| c.body.clone())
                .unwrap_or_default(),
            ts: self.now_secs(),
            collision: delta.collision,
        });
        // Inbox entries carry the friendly `KEY-n` handle when one exists —
        // they're read by a human scanning a summary line.
        let inbox_reff = self.aliases.alias_for(&id).unwrap_or(reff);
        self.derive_inbox_entries(&id, &inbox_reff, prior, &delta);
        match project_id {
            Some(p) => Ok(Some(DirtySet::issue(&p, &id))),
            None => Ok(None),
        }
    }

    /// Emit durable inbox entries for a just-imported doc: assignments to me,
    /// new comments on my work or mentioning `@mynick`, and status moves on my
    /// work. Comments come from the import's **oplog diff** (`delta`), so a
    /// concurrent comment that merged mid-list is detected exactly — the
    /// index-arithmetic `skip(prior_len)` this replaces both re-notified an old
    /// comment and dropped the new one in that case. Backfill-bounded by
    /// construction: a brand-new-to-me doc (`prior == None`) contributes at most
    /// one `assigned` entry, never a comment/status flood. Best-effort — inbox
    /// failure never affects the import.
    fn derive_inbox_entries(
        &mut self,
        id: &DocId,
        reff: &str,
        prior: Option<(bool, String)>,
        delta: &history::ImportDelta,
    ) {
        let Some(issue) = self.issues.get(id) else {
            return;
        };
        let my_actor = self.my_actor();
        let now = self.clock.now_ms() / 1000;
        let title = issue.title();
        let assignees = issue.assignees();
        let assigned_to_me = my_actor.as_ref().is_some_and(|a| assignees.contains(a));
        let my_issue = assigned_to_me || (my_actor.is_some() && issue.created_by() == my_actor);
        let entry = |kind: &str, detail: String, actor: Option<String>| crate::dto::InboxEntry {
            ts: now,
            kind: kind.into(),
            reff: reff.to_string(),
            doc_id: id.as_str().to_string(),
            title: title.clone(),
            detail,
            actor,
            actor_nick: None,
        };
        let mut entries = Vec::new();
        match prior {
            None => {
                if assigned_to_me {
                    entries.push(entry("assigned", "you were assigned".into(), None));
                }
            }
            Some((was_assigned_to_me, prior_status)) => {
                if !was_assigned_to_me && assigned_to_me {
                    entries.push(entry("assigned", "you were assigned".into(), None));
                }
                let status = issue.status();
                if status != prior_status && my_issue {
                    entries.push(entry("status", format!("{prior_status} → {status}"), None));
                }
                let mention = format!("@{}", self.my_nick).to_ascii_lowercase();
                for c in &delta.new_comments {
                    // A comment's author *is* the actor, so this is a direct
                    // comparison — no device→actor resolution, which used to
                    // silently fail once the authoring device was revoked and
                    // start notifying us about our own past comments.
                    if my_actor.as_ref() == Some(&c.author) {
                        continue;
                    }
                    let mentioned =
                        !self.my_nick.is_empty() && c.body.to_ascii_lowercase().contains(&mention);
                    if my_issue || mentioned {
                        entries.push(entry(
                            "comment",
                            c.body.clone(),
                            Some(c.author.as_str().to_string()),
                        ));
                    }
                }
            }
        }
        crate::inbox::append(self.store.home_path(), entries);
    }

    // ---- test/inspection helpers (used by integration invariant tests) ----

    /// Read a `DocMeta` row's cached head (the sync digest) for a ref, if any.
    #[doc(hidden)]
    pub fn row_head_for(&self, reff: &str) -> Option<Vec<u8>> {
        match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => self.catalog.row(&id).map(|r| r.head),
            _ => None,
        }
    }

    /// The live head of a loaded issue doc for a ref (for the load-time
    /// recompute invariant test).
    #[doc(hidden)]
    pub fn issue_head_for(&mut self, reff: &str) -> Option<Vec<u8>> {
        let id = match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => id,
            _ => return None,
        };
        self.issue(&id).ok().flatten().map(|i| i.head_hash())
    }
}
