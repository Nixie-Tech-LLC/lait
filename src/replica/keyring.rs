//! Space-key epochs: keyring refresh, payload sealing, rotation, and healing.

use super::*;

/// A 16-byte content-addressed epoch id prefixed to every AEAD ciphertext so the
/// reader selects the right key from its keyring during lazy revocation.
/// Content-addressed (not a counter) so concurrent rotations never collide.
fn epoch_prefix(id: &[u8; 16], mut blob: Vec<u8>) -> Vec<u8> {
    let mut out = id.to_vec();
    out.append(&mut blob);
    out
}
fn split_epoch(blob: &[u8]) -> Option<([u8; 16], &[u8])> {
    if blob.len() < 16 {
        return None;
    }
    let (e, rest) = blob.split_at(16);
    Some((e.try_into().ok()?, rest))
}

impl Replica {
    /// Rebuild the keyring: unseal every **authorized** epoch's envelope
    /// addressed to our device. Lazy revocation retains older keys so
    /// already-synced content stays readable). Called after any membership
    /// change/import.
    ///
    /// Two authenticity gates, both essential: we consider only epochs a valid
    /// writer-signed [`acl::AclAction::MintEpoch`] authorized (never a raw synced
    /// epoch), and we adopt the unsealed key only if `blake3(key)` matches that
    /// mint's `key_commit` — so a forged sealed envelope (an attacker overwriting
    /// our `(epoch, device)` slot with a key it chose) is rejected, not adopted.
    pub(super) fn refresh_keyring(&mut self) {
        for e in self.acl_state().epochs() {
            if self.keyring.contains_key(&e.id) {
                continue;
            }
            if let Some(sealed) = self.membership.get_sealed(&e.id, &self.me) {
                if let Some(raw) = crypto::open_sealed(&self.seed, &self.me, &sealed) {
                    if let Ok(key) = <SpaceKey>::try_from(raw.as_slice()) {
                        // Bind the envelope to the signed mint: reject a key whose
                        // hash does not match the committed value.
                        if *blake3::hash(&key).as_bytes() == e.key_commit {
                            self.keyring.insert(e.id, key);
                        }
                    }
                }
            }
        }
    }

    /// The deterministic active epoch (the encryption target): the highest
    /// `(gen, id)` among **authorized** epochs — a pure function of the signed
    /// mint set, so every replica agrees even after concurrent rotations, and an
    /// injected (unauthorized) epoch is never selected.
    pub(super) fn active_epoch(&self) -> Option<acl::EpochAuth> {
        self.acl_state()
            .epochs()
            .into_iter()
            .max_by(|a, b| a.gen.cmp(&b.gen).then_with(|| a.id.cmp(&b.id)))
    }

    /// Encrypt a sync payload with the active-epoch key (id-tagged).
    ///
    /// Two distinct "no key" cases, and only ONE may pass through in clear:
    /// - **No epochs exist at all** — a genuine keyless single-node space
    ///   that holds no protected content: pass through.
    /// - **An active epoch exists but we lack its key** — the mid-seal window
    ///   (a freshly added or recovered device awaiting self-heal). We may hold
    ///   *older* content decrypted locally, so we must **never** emit it in
    ///   clear; serve nothing until we hold the active key.
    pub(super) fn encrypt_payload(&self, plaintext: Vec<u8>) -> Vec<u8> {
        match self.active_epoch() {
            Some(e) => match self.keyring.get(&e.id) {
                Some(key) => epoch_prefix(&e.id, crypto::aead_encrypt(key, &plaintext)),
                // We can't encrypt under the active epoch — refuse to ship
                // cleartext (E2EE). An empty payload decrypts to nothing.
                None => Vec::new(),
            },
            None => plaintext,
        }
    }
    /// Decrypt a sync payload using the epoch id tag + our keyring. `None` if we
    /// lack that epoch's key — the blind-relay / non-member outcome: a non-member
    /// (empty keyring) or a removed member (missing the new epoch) learns nothing
    /// and simply imports nothing.
    pub(super) fn decrypt_payload(&self, blob: &[u8]) -> Option<Vec<u8>> {
        let (id, ct) = split_epoch(blob)?;
        let key = self.keyring.get(&id)?;
        crypto::aead_decrypt(key, ct)
    }

    /// Mint a fresh content-addressed key epoch, sealed to every device of every
    /// *current* member (computed AFTER any just-applied remove), and adopt it.
    /// A removed actor's devices are never in this set — the lazy-revocation
    /// fence. Concurrent rotations mint distinct ids, so they coexist rather than
    /// clobber; the deterministic active tip picks one for encryption and
    /// [`heal_epoch`] re-rotates if a merge leaves the tip sealed to a
    /// since-removed actor.
    ///
    /// The mint is a **signed [`acl::AclAction::MintEpoch`]** authored as our own
    /// actor, so the epoch rides the same trust boundary as membership: a replica
    /// adopts it only when this author held write standing at position. If we are
    /// not a writer the op is inert everywhere (never selected, never a key), so
    /// this degrades gracefully rather than splitting state. The op commits to
    /// `blake3(new_key)`, binding the sealed envelopes we write next.
    ///
    /// [`heal_epoch`]: Self::heal_epoch
    pub(super) fn rotate_key(&mut self) -> Result<()> {
        let gen = match self.active_epoch() {
            Some(e) => e
                .gen
                .checked_add(1)
                .ok_or_else(|| anyhow!("key-epoch generation exhausted"))?,
            None => 0,
        };
        let id = rand16();
        let new_key = crypto::random_key();
        let key_commit = *blake3::hash(&new_key).as_bytes();
        let members: Vec<(ActorId, Vec<Grant>)> = self.acl_state().members();
        let member_actors: Vec<ActorId> = members.iter().map(|(a, _)| a.clone()).collect();
        let op = self.author_acl(AclAction::MintEpoch {
            id,
            gen,
            key_commit,
            members: member_actors,
        })?;
        self.membership.add_op(&op)?;
        let plane = self.actor_plane();
        for (actor, _grants) in &members {
            for d in plane.devices_of(actor) {
                if let Some(sealed) = crypto::seal_to(&d, &new_key) {
                    self.membership.put_sealed(&id, &d, &sealed)?;
                }
            }
        }
        self.keyring.insert(id, new_key);
        Ok(())
    }

    /// Repair missing envelopes across the membership by sealing every
    /// epoch key we hold to any device of any *current member actor* that still
    /// lacks an envelope. Admin-ungated and safe — we only ever re-seal keys we
    /// already hold, and only to devices of actors who are entitled to the
    /// space key (present in the ACL). A removed actor is not in the member
    /// set, so lazy revocation is preserved.
    ///
    /// This is the backstop that lets any key-holding peer re-provision:
    /// - a *sibling* device added or reinstated after a rotation whose author
    ///   did not yet see it (reaching one device is sufficient), and
    /// - a *fresh recovery device* that reset an actor's key set and therefore
    ///   holds no key of its own; the first synced key-holder re-seals to it.
    pub(super) fn heal_member_device_envelopes(&mut self) -> Result<()> {
        let held: Vec<([u8; 16], SpaceKey)> = self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
        if held.is_empty() {
            return Ok(());
        }
        let plane = self.actor_plane();
        let member_devices: Vec<DeviceId> = self
            .acl_state()
            .members()
            .into_iter()
            .flat_map(|(actor, _)| plane.devices_of(&actor))
            .collect();
        let mut sealed_any = false;
        for (id, key) in held {
            for dev in &member_devices {
                if self.membership.get_sealed(&id, dev).is_none() {
                    if let Some(sealed) = crypto::seal_to(dev, &key) {
                        self.membership.put_sealed(&id, dev, &sealed)?;
                        sealed_any = true;
                    }
                }
            }
        }
        if sealed_any {
            self.persist_membership("device_heal")?;
        }
        Ok(())
    }

    /// Convergent re-key, covering both reasons a merge can leave the tip unfit.
    /// Admin-only (only an admin can mint); a non-admin waits — see
    /// [`rekey_pending_notice`] for what it is told meanwhile.
    ///
    /// **Staleness** — the active epoch is compromised or unusable:
    /// - its *minter* is no longer a member — a departed member controlled its
    ///   recipient list and knows its key, so it must not linger as the tip;
    /// - a *declared recipient* is no longer a member (a concurrent removal left
    ///   a stale tip); or
    /// - we hold admin standing yet cannot open it — a peer minted an epoch we
    ///   have no key for, so content is frozen under it (liveness).
    ///
    /// **Revoke fences** — replay evicted an actor whose invite was revoked
    /// concurrently with their redemption ([`acl::RekeyFence`]). They are out of
    /// the member set but still hold every epoch key sealed to them at
    /// admission, so only a mint *causally after* the revoke fences them off.
    /// Replay discharges fences it can see satisfied, so a non-empty list is
    /// exactly the outstanding work.
    ///
    /// Both are evaluated against **one** ACL snapshot and discharged by **one**
    /// rotation: a fresh mint rides the current frontier, so it descends every
    /// outstanding fence at once and is itself neither stale nor fenced. Two
    /// separately effectful heals would let the first rotate and the second
    /// mint again off a pre-rotation snapshot.
    ///
    /// Unstaggered on purpose: each observing admin may mint once, concurrent
    /// mints share a generation, `(gen, id)` selects deterministically, and the
    /// next import sees the fences discharged and stops. Bounded and convergent,
    /// the same shape the staleness heal already relied on.
    ///
    /// [`rekey_pending_notice`]: Self::rekey_pending_notice
    pub(super) fn heal_epoch(&mut self) -> Result<()> {
        // Only an admin can mint, so only an admin can heal. Note this is the
        // *only* gate: `rotate_key` draws a fresh random key and seals it with
        // public device identities, so it never needs the outgoing key —
        // gating on possession would strand the admin who cannot open the tip,
        // which is precisely the `unopenable` case below.
        if !self.am_i_admin() {
            return Ok(());
        }
        let acl = self.acl_state();
        let stale = match self.active_epoch() {
            Some(active) => {
                let members: std::collections::BTreeSet<ActorId> =
                    acl.members().into_iter().map(|(a, _)| a).collect();
                let minter_gone = !members.contains(&active.minted_by);
                let recipient_gone = active.members.iter().any(|m| !members.contains(m));
                let unopenable = !self.keyring.contains_key(&active.id);
                minter_gone || recipient_gone || unopenable
            }
            // No epoch yet ⇒ nothing to be stale. A fence is still actionable.
            None => false,
        };
        if stale || !acl.rekey_fences().is_empty() {
            self.rotate_key()?;
            self.persist_membership("epoch_heal")?;
        }
        Ok(())
    }

    /// Outstanding rekey obligations this node cannot discharge itself, for the
    /// status surface. `Some` only when we are **not** an admin (an admin heals
    /// on import instead of reporting), so a plain member learns that a revoked
    /// invite's admittee still holds live keys until an admin syncs.
    ///
    /// Callers must not describe this as the invite being undone. Rotation
    /// fences *future* content only: everything encrypted under the epochs the
    /// evicted actor was sealed stays readable by them permanently (lazy
    /// revocation — see [`acl::RekeyFence`]).
    ///
    /// The wording says *may* hold *a* key, not *the current* key: which epoch
    /// is the active tip is decided by `(gen, id)` selection, and a concurrent
    /// mint the evicted actor was never sealed can win it. What we can state is
    /// that they hold a space key able to encrypt new content until an admin
    /// rotates past the fence.
    pub fn rekey_pending_notice(&self) -> Option<String> {
        if self.am_i_admin() {
            return None;
        }
        let acl = self.acl_state();
        let fences = acl.rekey_fences();
        if fences.is_empty() {
            return None;
        }
        let who: Vec<String> = fences.iter().map(|f| f.evicted.short()).collect();
        let (subject, verb, key) = if who.len() == 1 {
            ("was", "has", "a space key")
        } else {
            ("were", "have", "space keys")
        };
        Some(format!(
            "revoked invite: {} {subject} admitted concurrently and {verb} been \
             removed, but may still hold {key} that can encrypt new content. An \
             admin must sync to rotate the key. Content already shared remains \
             readable by them.",
            who.join(", ")
        ))
    }
}
