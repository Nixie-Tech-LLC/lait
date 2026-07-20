//! Membership and authorization operations.

use super::*;

/// How an actor came to hold a seat, or why it did not need one.
///
/// The three paths produce three different sentences, and which one a caller
/// hears is a fact about what happened rather than a choice of wording — so the
/// domain reports the path and the adapter writes the sentence.
/// [`AlreadyMember`](Admission::AlreadyMember) is always paired with
/// [`Change::unchanged`]: it is the branch that seals nothing.
#[derive(Debug)]
pub enum Admission {
    /// An admin decided, directly.
    Added(ActorId),
    /// A valid invite grant decided, with no human step.
    AutoApproved(ActorId),
    /// Already seated; nothing to seal.
    AlreadyMember(ActorId),
}

/// A member lost their seat and the key rotated behind them.
#[derive(Debug)]
pub struct MemberRemoved(pub ActorId);

/// The space key rotated, to this generation.
#[derive(Debug)]
pub struct KeyRotated {
    pub generation: u64,
}

/// An invite was revoked. Whether it had *already* been redeemed decides what
/// can honestly be promised, so that fact travels with the result.
#[derive(Debug)]
pub struct InviteRevocation {
    pub already_spent: bool,
}

impl Replica {
    // ---- membership and authorization operations ----

    /// The genesis as seen *after* any break-glass recovery: `founding_actors` is
    /// the space plane's effective root (`lait/space/1`), not the immutable birth
    /// seed. With no recovery this is the birth genesis unchanged.
    pub(super) fn effective_genesis(&self) -> Genesis {
        let root = crate::space::replay(
            &self.genesis,
            &self.space_id,
            &self.membership.space_events(),
        );
        Genesis {
            founding_actors: root.root,
            ..self.genesis.clone()
        }
    }

    /// The materialized ACL state (deterministic replay from the *effective* root
    /// over the actor plane and signed ACL operations (`lait/actor/1`). Seeding
    /// from the recovery-aware root is the one integration point of the space
    /// plane: after a threshold `Recover`, replay roots on the recovered admins.
    pub fn acl_state(&self) -> AclState {
        acl::replay(
            &self.effective_genesis(),
            &self.membership.actor_events(),
            &self.membership.ops(),
        )
    }
    /// The actor plane materialized from the membership doc's key-events.
    pub fn actor_plane(&self) -> ActorPlane {
        actor::replay(&self.space_id, &self.membership.actor_events())
    }

    /// Ensure this device has an actor identity in this space, returning its
    /// inception event (for a joiner to carry in its `JoinRequest` so an admin
    /// can admit its *actor*). Idempotent: if we already have an actor, the
    /// existing inception is returned; otherwise we provision a recovery key and
    /// self-incept, persisting the event to our membership doc.
    pub fn self_inception(&mut self) -> Result<actor::SignedEvent> {
        if let Some(me) = self.my_actor() {
            let target = me.incept_hash().to_string();
            if let Some(ev) = self
                .membership
                .actor_events()
                .into_iter()
                .find(|e| e.hash() == target)
            {
                return Ok(ev);
            }
        }
        let (recovery_commit, recovery_seed) = mint_recovery();
        persist_recovery_key(&self.store, &recovery_seed)?;
        let (ev, _id) = actor::incept_single(
            &self.seed,
            &self.space_id,
            rand16(),
            rand16(),
            Some(recovery_commit),
        );
        self.membership.add_actor_event(&ev)?;
        self.persist_membership("self_incept")?;
        Ok(ev)
    }
    /// This device's own actor, if its inception has been established/synced.
    pub fn my_actor(&self) -> Option<ActorId> {
        self.actor_plane().actor_of_device(&self.me).cloned()
    }
    /// The space's founding actor — the genesis trust root every replica
    /// must share. An invite ticket MUST carry THIS (not the inviter's own
    /// actor): a joiner roots `acl::replay` on the ticket's founder, so anchoring
    /// on anyone but the true founder forks the joiner onto a genesis where the
    /// real founder — and the founding key-epoch — hold no authority.
    pub fn founding_actor(&self) -> Option<ActorId> {
        self.genesis.founding_actors.first().cloned()
    }
    /// The verifiable founding proof to put in a ticket (`lait/space/1`): the
    /// `(salt, founder_inception)` a joiner checks the space id against. Any
    /// correctly-joined node holds both — the salt in genesis, the founder's
    /// inception in the membership actor log.
    pub fn founding_proof(&self) -> Option<([u8; 16], [u8; 32], actor::SignedEvent)> {
        let founder = self.genesis.founding_actors.first()?;
        let incept = self
            .membership
            .actor_events()
            .into_iter()
            .find(|ev| ActorId::from_incept_hash(&ev.hash()) == *founder)?;
        Some((self.genesis.salt, self.genesis.recovery_root, incept))
    }
    pub fn is_member_actor(&self, actor: &ActorId) -> bool {
        self.acl_state().is_member(actor)
    }
    /// Whether this device's actor is a member / admin of the space.
    pub fn am_i_member(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().is_member(&a))
    }
    pub fn am_i_admin(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().is_admin(&a))
    }
    /// Every device key belonging to a current member actor — the resolvable
    /// identities for the local device directory.
    pub fn member_device_keys(&self) -> Vec<DeviceId> {
        let plane = self.actor_plane();
        self.acl_state()
            .members()
            .into_iter()
            .flat_map(|(a, _)| plane.devices_of(&a))
            .collect()
    }
    /// Whether a device key currently speaks for a member actor.
    pub fn is_member_device(&self, dev: &DeviceId) -> bool {
        self.actor_plane()
            .actor_of_device(dev)
            .is_some_and(|a| self.acl_state().is_member(a))
    }
    /// Members (actor, grants, and `is_me`) for the members view. `is_me`
    /// is true when this device speaks for the actor.
    pub fn members(&self) -> Vec<(ActorId, Vec<Grant>, bool)> {
        let mine = self.my_actor();
        self.acl_state()
            .members()
            .into_iter()
            .map(|(a, g)| {
                let me = mine.as_ref() == Some(&a);
                (a, g, me)
            })
            .collect()
    }

    /// Author a membership op as our own actor, embedding our current actor-log
    /// frontier so a replica resolves our device→actor binding at position.
    pub(super) fn author_acl(&self, action: AclAction) -> Result<SignedOp> {
        self.author_acl_nonce(action, None)
    }

    /// [`author_acl`] carrying an invite nonce (for `AddMember` via a single-use
    /// invite) so replay can dedup concurrent redemptions.
    ///
    /// [`author_acl`]: Self::author_acl
    fn author_acl_nonce(&self, action: AclAction, nonce: Option<[u8; 16]>) -> Result<SignedOp> {
        let by = self
            .my_actor()
            .ok_or_else(|| anyhow!("this device has no actor identity in this space yet"))?;
        let actor_asof = self.membership.actor_heads(&by);
        Ok(acl::sign_op(
            &self.seed,
            &AclOp {
                action,
                by,
                actor_asof,
                nonce,
            },
            self.membership.heads(),
            &self.space_id,
        ))
    }

    /// Seal every key epoch we hold to **every device** of `actor`. Reaching one
    /// live device is
    /// enough for that actor to propagate the key to its siblings, but we seal
    /// all devices we can see for immediacy. The actor's inception must already
    /// be present (callers import it first).
    pub(super) fn seal_epochs_to_actor(t: &mut Self, actor: &ActorId) -> Result<()> {
        let devices = t.actor_plane().devices_of(actor);
        let epochs: Vec<([u8; 16], SpaceKey)> = t.keyring.iter().map(|(e, k)| (*e, *k)).collect();
        for (epoch, key) in epochs {
            for d in &devices {
                if let Some(sealed) = crypto::seal_to(d, &key) {
                    t.membership.put_sealed(&epoch, d, &sealed)?;
                }
            }
        }
        Ok(())
    }

    /// Add (or re-grant) a member by actor and seal them the space key
    /// Administrator-only. The target actor's inception must already be
    /// known locally (the enrollment path imports it first via `redeem_invite`).
    pub fn member_add(&mut self, actor: &ActorId, grants: Vec<Grant>) -> ChangeResult<Admission> {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => {
                return Err(ReplicaError::Denied(Denied::NotAdmin(
                    AdminAction::AddMember,
                )))
            }
        }
        if !self.actor_plane().exists(actor) {
            return Err(ReplicaError::Conflict(Conflict::ActorUnknown {
                short: actor.short(),
            }));
        }
        let op = self.author_acl(AclAction::AddMember {
            actor: actor.clone(),
            grants,
        })?;
        let target = actor.clone();
        self.member_apply(op, "member_add", |t| Self::seal_epochs_to_actor(t, &target))?;
        self.push_activity(None, &actor.short(), "member_added", vec![], &actor.short());
        Ok(Change::committed(
            Admission::Added(actor.clone()),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Import a joiner's actor **inception** (from a `JoinRequest`) so a manual
    /// `member add <device>` can resolve their actor before admission. Validates
    /// the inception (a forged one is ignored) and is idempotent. Does NOT grant
    /// membership — it only makes the pending joiner's identity locally known.
    /// Returns whether the actor is now known.
    pub fn import_inception(&mut self, incept: &actor::SignedEvent) -> Result<bool> {
        let actor = ActorId::from_incept_hash(&incept.hash());
        if self.actor_plane().exists(&actor) {
            return Ok(true);
        }
        let mut candidate = self.membership.actor_events();
        candidate.push(incept.clone());
        if !actor::replay(&self.space_id, &candidate).exists(&actor) {
            return Ok(false); // invalid inception — never enters the container
        }
        self.membership.add_actor_event(incept)?;
        self.persist_membership("incept_import")?;
        Ok(true)
    }

    /// Admit a member by **importing their inception** and sealing them in —
    /// the manual-approve counterpart to [`redeem_invite`] (which additionally
    /// checks an invite grant). Admin-only. The inception is validated (a forged
    /// one is refused) before it enters the actors container.
    ///
    /// [`redeem_invite`]: Self::redeem_invite
    pub fn admit_member(
        &mut self,
        incept: &actor::SignedEvent,
        grants: Vec<Grant>,
    ) -> ChangeResult<Admission> {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => {
                return Err(ReplicaError::Denied(Denied::NotAdmin(
                    AdminAction::AddMember,
                )))
            }
        }
        let actor = ActorId::from_incept_hash(&incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(incept.clone());
        if !actor::replay(&self.space_id, &candidate).exists(&actor) {
            return Err(ReplicaError::Invalid(Invalid::ActorInception {
                in_join_request: false,
            }));
        }
        if acl.is_member(&actor) {
            return Ok(Change::unchanged(Admission::AlreadyMember(actor)));
        }
        let op = self.author_acl(AclAction::AddMember {
            actor: actor.clone(),
            grants,
        })?;
        let incept = incept.clone();
        let target = actor.clone();
        self.member_apply(op, "member_admit", |t| {
            t.membership.add_actor_event(&incept)?;
            Self::seal_epochs_to_actor(t, &target)
        })?;
        self.push_activity(None, &actor.short(), "member_added", vec![], &actor.short());
        Ok(Change::committed(
            Admission::Added(actor),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// **Pattern A auto-approval.** Admit a joiner who presented a valid,
    /// admin-signed invite grant, sealing them the key exactly like [`member_add`]
    /// but with no human `approve` step. The transport layer has already verified
    /// the issuer signature, space binding, and expiry; here we enforce the
    /// remaining, state-dependent checks: the issuer must be a *current* admin, we
    /// must be an admin able to seal, and a single-use nonce must be unspent. The
    /// nonce is burned inside the same commit as the AddMember op (atomic — no
    /// window where a member is added but the invite stays live). Idempotent: a
    /// re-presented grant or an already-member joiner is a harmless no-op.
    ///
    /// [`member_add`]: Self::member_add
    pub fn redeem_invite(
        &mut self,
        issuer_device: &DeviceId,
        joiner_incept: &actor::SignedEvent,
        nonce: &[u8; 16],
        single_use: bool,
    ) -> ChangeResult<Admission> {
        // The joiner's self-certifying actor id is its inception's hash. Validate
        // the inception cleanly incepts for THIS space before admitting it —
        // a forged inception must never enter the actors container.
        let joiner_actor = ActorId::from_incept_hash(&joiner_incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(joiner_incept.clone());
        if !actor::replay(&self.space_id, &candidate).exists(&joiner_actor) {
            return Err(ReplicaError::Invalid(Invalid::ActorInception {
                in_join_request: true,
            }));
        }

        let plane = self.actor_plane();
        let acl = self.acl_state();
        // Authority: the grant's signing device must currently speak for an admin.
        let issuer_ok = plane
            .actor_of_device(issuer_device)
            .is_some_and(|a| acl.is_admin(a));
        if !issuer_ok {
            return Err(ReplicaError::Denied(Denied::IssuerNotAdmin));
        }
        // We can only seal if we ourselves are an admin holding the key.
        match self.my_actor() {
            Some(me) if acl.is_admin(&me) => {}
            _ => return Err(ReplicaError::Denied(Denied::NodeNotAdmin)),
        }
        // Revocation kill switch: an admin-signed RevokeInvite voids this nonce
        // convergently — the only way to retire a leaked (esp. reusable) invite.
        if acl.is_invite_revoked(nonce) {
            return Err(ReplicaError::Conflict(Conflict::InviteRevoked));
        }
        // Single-use replay guard — read from the SIGNED ACL (an authorized
        // AddMember that spent this nonce), never an unsigned side container.
        // The convergent nonce dedup in replay is the real guarantee; this is the
        // fast-fail so we don't author a doomed op.
        if single_use && acl.is_nonce_spent(nonce) {
            return Err(ReplicaError::Conflict(Conflict::InviteRedeemed));
        }
        // Idempotent: already a member ⇒ nothing to seal, no ACL churn.
        if acl.is_member(&joiner_actor) {
            return Ok(Change::unchanged(Admission::AlreadyMember(joiner_actor)));
        }
        // Bind the nonce into the op for single-use invites so concurrent
        // redemptions of the same invite converge to one admitted actor.
        let op_nonce = if single_use { Some(*nonce) } else { None };
        let op = self.author_acl_nonce(
            AclAction::AddMember {
                actor: joiner_actor.clone(),
                grants: vec![Grant::Write],
            },
            op_nonce,
        )?;
        let incept = joiner_incept.clone();
        let target = joiner_actor.clone();
        self.member_apply(op, "invite_redeem", |t| {
            // Import the joiner's identity, then seal every epoch to its devices.
            // The single-use nonce is recorded by the AddMember op itself (bound
            // above), so replay is the redemption record — no side container.
            t.membership.add_actor_event(&incept)?;
            Self::seal_epochs_to_actor(t, &target)?;
            Ok(())
        })?;
        self.push_activity(
            None,
            &joiner_actor.short(),
            "member_added",
            vec![],
            &joiner_actor.short(),
        );
        Ok(Change::committed(
            Admission::AutoApproved(joiner_actor),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Remove a member (signed RemoveMember op) and **rotate the space key**
    /// using lazy revocation: a new epoch is sealed only to the remaining
    /// members' devices, so the removed actor cannot read *future* content.
    /// Admin-only.
    pub fn member_remove(&mut self, actor: &ActorId) -> ChangeResult<MemberRemoved> {
        let acl = self.acl_state();
        let me = match self.my_actor() {
            Some(me) if acl.is_admin(&me) => me,
            _ => {
                return Err(ReplicaError::Denied(Denied::NotAdmin(
                    AdminAction::RemoveMember,
                )))
            }
        };
        if actor == &me {
            return Err(ReplicaError::Denied(Denied::SelfRemoval));
        }
        let op = self.author_acl(AclAction::RemoveMember {
            actor: actor.clone(),
        })?;
        self.member_apply(op, "member_remove", |t| t.rotate_key())?;
        self.push_activity(
            None,
            &actor.short(),
            "member_removed",
            vec![],
            &actor.short(),
        );
        Ok(Change::committed(
            MemberRemoved(actor.clone()),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Rotate the space key without a membership change (key hygiene).
    pub fn key_rotate_cmd(&mut self) -> ChangeResult<KeyRotated> {
        let is_admin = self
            .my_actor()
            .is_some_and(|me| self.acl_state().is_admin(&me));
        if !is_admin {
            return Err(ReplicaError::Denied(Denied::NotAdmin(
                AdminAction::RotateKey,
            )));
        }
        self.rotate_key()?;
        self.persist_membership("key_rotate")?;
        let generation = self.active_epoch().map(|e| e.gen).unwrap_or(0);
        Ok(Change::committed(
            KeyRotated {
                generation: generation.into(),
            },
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Revoke an outstanding invite (admin-only). Accepts the invite's 32-hex
    /// nonce or a full ticket to lift it from. Authors a signed
    /// [`AclAction::RevokeInvite`]; once it syncs, no admin admits via that nonce
    /// — the kill switch for a leaked (especially reusable) invite.
    pub fn invite_revoke_cmd(&mut self, invite: String) -> ChangeResult<InviteRevocation> {
        if !self.am_i_admin() {
            return Err(ReplicaError::Denied(Denied::NotAdmin(
                AdminAction::RevokeInvite,
            )));
        }
        let Some(nonce) = Self::parse_invite_nonce(&invite) else {
            return Err(ReplicaError::Invalid(Invalid::InviteRef));
        };
        let op = self.author_acl(AclAction::RevokeInvite { nonce })?;
        // Whether it was *already* spent decides what we can honestly promise.
        let already_spent = self.acl_state().is_nonce_spent(&nonce);
        self.member_apply(op, "invite_revoke", |_| Ok(()))?;
        Ok(Change::committed(
            InviteRevocation { already_spent },
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Extract an invite nonce from either a full ticket (via its signed invite)
    /// or a raw 32-hex string.
    fn parse_invite_nonce(input: &str) -> Option<[u8; 16]> {
        let s = input.trim();
        if let Ok(ticket) = s.parse::<crate::proto::SpaceTicket>() {
            // A ticket only carries a nonce if it embeds a signed invite.
            let (_pk, grant) = ticket.invite?.verify().ok()?;
            return Some(grant.nonce);
        }
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(s.as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Resolve a `<who>` ref to a known actor: an `act_` id directly, or a
    /// device key / `@me` mapped through the actor plane to its owning actor.
    pub(super) fn resolve_actor(&self, who: &str) -> Option<ActorId> {
        if let Some(a) = ActorId::parse(who) {
            // A well-formed id resolves only if the actor is actually known to
            // this space — otherwise a typo'd/forged `act_…` would seat or
            // assign a phantom that no inception backs.
            return self.actor_plane().exists(&a).then_some(a);
        }
        let dev = index::resolve_device(who, &self.me)?;
        self.actor_plane().actor_of_device(&dev).cloned()
    }

    pub(super) fn member_add_cmd(&mut self, who: String, admin: bool) -> ChangeResult<Admission> {
        let Some(actor) = self.resolve_actor(&who) else {
            return Err(ReplicaError::NotFound(NotFound::Actor {
                named: who,
                invite_hint: true,
            }));
        };
        let grants = if admin {
            vec![Grant::Admin, Grant::Write]
        } else {
            vec![Grant::Write]
        };
        self.member_add(&actor, grants)
    }
    pub(super) fn member_remove_cmd(&mut self, who: String) -> ChangeResult<MemberRemoved> {
        let Some(actor) = self.resolve_actor(&who) else {
            return Err(ReplicaError::NotFound(NotFound::Actor {
                named: who,
                invite_hint: false,
            }));
        };
        self.member_remove(&actor)
    }
    pub(super) fn member_list(&self) -> Vec<crate::dto::MemberDto> {
        let acl = self.acl_state();
        let mine = self.my_actor();
        let members = acl
            .members()
            .into_iter()
            .map(|(actor, _grants)| {
                let standing = acl.standing(&actor).unwrap_or("member");
                crate::dto::MemberDto {
                    me: mine.as_ref() == Some(&actor),
                    // The sponsoring actor, for agents (empty otherwise).
                    sponsor: acl.sponsor_of(&actor).map(|s| s.as_str().to_string()),
                    key: actor.as_str().to_string(),
                    role: standing.into(),
                    // Local petnames live outside the replica (never synced); the
                    // node layer overlays them onto this projection after the fact.
                    alias: String::new(),
                }
            })
            .collect();
        members
    }

    /// The membership audit log: the signed ACL DAG replayed into a rendered,
    /// causally ordered list of operations and their verdicts. This provides
    /// cryptographic provenance, unlike the advisory activity feed.
    pub(super) fn member_log(&self) -> Vec<crate::dto::MemberLogEntry> {
        let (_state, audit) = acl::replay_with_audit(
            &self.effective_genesis(),
            &self.membership.actor_events(),
            &self.membership.ops(),
        );
        let entries = audit
            .into_iter()
            .map(|e| crate::dto::MemberLogEntry {
                op: e.hash,
                // The signing device key (verified — the signature covers the op).
                actor: e.author.as_str().to_string(),
                kind: e.kind.into(),
                // The subject is now an actor.
                subject: e.subject.map(|s| s.as_str().to_string()),
                role: e.grants.map(|g| {
                    if g.contains(&Grant::Admin) {
                        "admin".into()
                    } else if g.contains(&Grant::Write) {
                        "member".into()
                    } else {
                        "viewer".into()
                    }
                }),
                authorized: e.authorized,
            })
            .collect();
        entries
    }

    /// Apply a signed op + an extra key-sealing step, then commit + persist.
    pub(super) fn member_apply(
        &mut self,
        op: SignedOp,
        kind: &str,
        extra: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        self.membership.add_op(&op)?;
        extra(self)?;
        self.persist_membership(kind)
    }

    pub(super) fn persist_membership(&mut self, kind: &str) -> Result<()> {
        self.membership.apply(&OpCtx::authority(kind, &self.me));
        self.store.save_membership(&self.membership)?;
        self.store.commit("membership change");
        self.refresh_keyring();
        Ok(())
    }
}
