//! Multi-device (lait/actor/1 device management) and agent sponsorship.

use super::*;

/// An agent gained sponsored standing.
#[derive(Debug)]
pub struct AgentSponsored(pub ActorId);

/// A device joined this actor's set.
#[derive(Debug)]
pub struct DeviceAdded(pub DeviceId);

/// A device left this actor's set. De-listing is self-authored and always
/// applies; *fencing* it from existing content needs a key rotation that only
/// an admin may mint, so `rotated` says which of the two actually happened.
#[derive(Debug)]
pub struct DeviceRevoked {
    pub device: DeviceId,
    pub rotated: bool,
}

/// An actor's device set was reset to this device by its offline recovery key.
#[derive(Debug)]
pub struct ActorRecovered(pub ActorId);

/// The enrollment token another machine consumes with `device accept`.
#[derive(Debug)]
pub(super) struct DeviceInvite {
    pub actor: ActorId,
    pub space: SpaceId,
}

/// One device of this actor, and whether it is the one being asked.
#[derive(Debug)]
pub(super) struct DeviceListing {
    pub device: DeviceId,
    pub is_this_device: bool,
}

impl Replica {
    pub(super) fn agent_add_cmd(&mut self, who: String) -> ChangeResult<AgentSponsored> {
        // `who` is the agent's device key (or actor id). The agent self-incepts
        // when it joins, so by sponsor time its actor is known (synced, or
        // imported from the join request by the node layer).
        let Some(actor) = self.resolve_actor(&who) else {
            return Err(ReplicaError::NotFound(NotFound::AgentActor { named: who }));
        };
        self.agent_add_by_actor(&actor)
    }

    /// Sponsor an agent by importing its inception, then delegating to
    /// [`agent_add_by_actor`]. An agent is a **degenerate actor** (single-device,
    /// no recovery) that self-incepted in its own home.
    ///
    /// [`agent_add_by_actor`]: Self::agent_add_by_actor
    // Same situation as `admit_member`: dispatch sponsors an agent whose actor is
    // already known, so the inception-carrying entry has no production caller yet.
    #[allow(dead_code)]
    pub(crate) fn agent_add(
        &mut self,
        agent_incept: &actor::SignedEvent,
    ) -> ChangeResult<AgentSponsored> {
        let agent_actor = ActorId::from_incept_hash(&agent_incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(agent_incept.clone());
        if !actor::replay(&self.space_id, &candidate).exists(&agent_actor) {
            return Err(ReplicaError::Invalid(Invalid::AgentInception));
        }
        // Both sponsorship gates are decidable before the import, so check them
        // here: `import_inception` persists, and a refusal after it would leave
        // a durable change that reported failure and rang nothing.
        self.sponsorship_gate(&agent_actor)?;
        self.import_inception(agent_incept)?;
        self.agent_add_by_actor(&agent_actor)
    }

    /// Who may sponsor, and whether this actor still needs sponsoring. Separated
    /// out because [`agent_add`](Self::agent_add) must decide both *before* it
    /// imports an inception, and [`agent_add_by_actor`](Self::agent_add_by_actor)
    /// needs them too when reached directly.
    fn sponsorship_gate(&self, agent_actor: &ActorId) -> ReplicaResult<()> {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_human_member(&me) => {}
            _ => return Err(ReplicaError::Denied(Denied::NotHuman)),
        }
        if acl.is_member(agent_actor) {
            return Err(ReplicaError::Conflict(Conflict::AlreadyPrincipal {
                short: agent_actor.short(),
            }));
        }
        Ok(())
    }

    /// Sponsor an already-known agent actor: sign `AddAgent` and
    /// seal it the space key. Any human member may sponsor; the agent holds
    /// no membership or content authority, and its standing dies with the
    /// sponsor. The agent's inception must already be present (it self-incepts
    /// on join). Delegation, not elevation.
    pub(crate) fn agent_add_by_actor(
        &mut self,
        agent_actor: &ActorId,
    ) -> ChangeResult<AgentSponsored> {
        self.sponsorship_gate(agent_actor)?;
        if !self.actor_plane().exists(agent_actor) {
            return Err(ReplicaError::Conflict(Conflict::AgentUnknown {
                short: agent_actor.short(),
            }));
        }
        // The op is authored as the sponsor's actor (its by/asof), so the
        // AddAgent's sponsor = sponsor actor by construction.
        let op = self.author_acl(AclAction::AddAgent {
            actor: agent_actor.clone(),
        })?;
        let target = agent_actor.clone();
        self.member_apply(op, "agent_add", |t| Self::seal_epochs_to_actor(t, &target))?;
        self.push_activity(
            None,
            &agent_actor.short(),
            "agent_added",
            vec![],
            &agent_actor.short(),
        );
        Ok(Change::committed(
            AgentSponsored(agent_actor.clone()),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    // ---- multi-device (lait/actor/1 device management) ----

    /// A device-enrollment token for adding another device to *this* actor:
    /// `<actor_id> <space_id>`. The new machine consumes it with
    /// `device accept`, which produces a consent blob for `device add`.
    pub(super) fn device_invite_cmd(&self) -> ReplicaResult<DeviceInvite> {
        match self.my_actor() {
            Some(actor) => Ok(DeviceInvite {
                actor,
                space: self.space_id.clone(),
            }),
            None => Err(ReplicaError::Denied(Denied::NoActorIdentity {
                in_this_space: true,
            })),
        }
    }

    pub(super) fn device_list(&self) -> Vec<DeviceListing> {
        self.my_actor()
            .map(|a| self.actor_plane().devices_of(&a))
            .unwrap_or_default()
            .into_iter()
            .map(|device| DeviceListing {
                is_this_device: device == self.me,
                device,
            })
            .collect()
    }

    /// Add a device to our actor from its consent blob (hex-encoded
    /// [`actor::DeviceBinding`] from `device accept`), authored by this device,
    /// and seal every held epoch to it so it can decrypt immediately.
    pub(super) fn device_add_cmd(&mut self, consent_hex: String) -> ChangeResult<DeviceAdded> {
        let Some(actor) = self.my_actor() else {
            return Err(ReplicaError::Denied(Denied::NoActorIdentity {
                in_this_space: false,
            }));
        };
        let binding: actor::DeviceBinding = match data_encoding::HEXLOWER_PERMISSIVE
            .decode(consent_hex.as_bytes())
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
        {
            Some(b) => b,
            None => return Err(ReplicaError::Invalid(Invalid::DeviceConsentBlob)),
        };
        if !actor::consent_verify(
            self.space_id.as_str(),
            &binding,
            &actor::ConsentCtx::Member { actor: &actor },
        ) {
            return Err(ReplicaError::Invalid(Invalid::DeviceConsentMismatch));
        }
        let new_device = binding.device.clone();
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::AddDevice {
                actor: actor.clone(),
                binding,
            },
            self.membership.actor_heads(&actor),
            &self.space_id,
        );
        (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            let held: Vec<([u8; 16], SpaceKey)> =
                self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
            for (id, key) in held {
                if let Some(sealed) = crypto::seal_to(&new_device, &key) {
                    self.membership.put_sealed(&id, &new_device, &sealed)?;
                }
            }
            self.persist_membership("device_add")
        })()?;
        Ok(Change::committed(
            DeviceAdded(new_device),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    /// Revoke a device from our actor. De-listing is self-authored (any member
    /// may do it for their own actor). **Fencing** the device from future content
    /// needs a key rotation, which only an admin may mint: an admin rotates
    /// immediately (re-sealing the fresh epoch to the remaining devices only); a
    /// non-admin de-lists and is told the rotation is pending an admin, rather
    /// than being handed a rotation that would be inert.
    pub(super) fn device_revoke_cmd(&mut self, device: String) -> ChangeResult<DeviceRevoked> {
        let Some(actor) = self.my_actor() else {
            return Err(ReplicaError::Denied(Denied::NoActorIdentity {
                in_this_space: false,
            }));
        };
        let Some(device) = DeviceId::parse(&device) else {
            return Err(ReplicaError::Invalid(Invalid::DeviceKey));
        };
        let devices = self.actor_plane().devices_of(&actor);
        if !devices.contains(&device) {
            return Err(ReplicaError::Conflict(Conflict::NotYourDevice));
        }
        if devices.len() <= 1 {
            return Err(ReplicaError::Conflict(Conflict::OnlyDevice));
        }
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::RevokeDevice {
                actor: actor.clone(),
                device: device.clone(),
            },
            self.membership.actor_heads(&actor),
            &self.space_id,
        );
        // De-listing the device is self-authored and always applies. Fully
        // fencing it, though, requires a **key rotation**, which only an admin
        // may mint. Rotate when we can; otherwise apply the revocation and report
        // honestly that content re-keying is pending an admin — never claim a
        // rotation that would be inert (the device would keep reading under the
        // still-active epoch).
        let rotated = self.am_i_admin();
        (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            if rotated {
                self.rotate_key()?;
            }
            self.persist_membership("device_revoke")
        })()?;
        Ok(Change::committed(
            DeviceRevoked { device, rotated },
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }

    fn read_recovery_key(&self) -> Option<[u8; 32]> {
        let path = self.store.home_path().join("recovery.key");
        let bytes = crate::secretfs::read_private(&path).ok().flatten()?;
        let hex = String::from_utf8(bytes).ok()?;
        let raw = data_encoding::HEXLOWER_PERMISSIVE
            .decode(hex.trim().as_bytes())
            .ok()?;
        raw.as_slice().try_into().ok()
    }

    /// Recover our actor with the offline recovery key: authored by the recovery
    /// key (which must match the standing pre-rotation commitment), it resets the
    /// device set to *this* device. **Lazy** (design): identity/standing is
    /// restored immediately, but this fresh device holds no space key until
    /// an admin or surviving peer re-seals it (self-heal on their next sync).
    pub(crate) fn recover(&mut self) -> ChangeResult<ActorRecovered> {
        let Some(seed) = self.read_recovery_key() else {
            return Err(ReplicaError::Conflict(Conflict::RecoveryKeyMissing));
        };
        // Resolve the target actor by its pre-rotation commitment — NOT by the
        // current device set (a genuine recovery runs from a fresh device that is
        // not in the set). The actor whose standing commitment matches our
        // recovery key is the one we can recover.
        let recovery_pub = crypto::device_from_seed(&seed);
        let commit = actor::recovery_commitment(&recovery_pub);
        let plane = self.actor_plane();
        let Some(actor) = plane
            .actors()
            .find(|(_, st)| commit.is_some() && st.recovery_commit == commit)
            .map(|(id, _)| id.clone())
        else {
            return Err(ReplicaError::Conflict(Conflict::RecoveryKeyUnmatched));
        };
        let binding = actor::consent_sign(
            &self.seed,
            self.space_id.as_str(),
            rand16(),
            &actor::ConsentCtx::Member { actor: &actor },
        );
        let ev = actor::sign_event(
            &seed,
            &actor::ActorOp::Recover {
                actor: actor.clone(),
                devices: vec![binding],
                next_commit: None,
            },
            self.membership.actor_heads(&actor),
            &self.space_id,
        );
        // Validate the recovery actually took (commitment match) before persisting.
        let mut candidate = self.membership.actor_events();
        candidate.push(ev.clone());
        let recovered = actor::replay(&self.space_id, &candidate)
            .state(&actor)
            .map(|s| s.recovered)
            .unwrap_or(false);
        if !recovered {
            return Err(ReplicaError::Conflict(Conflict::RecoveryCommitmentMismatch));
        }
        (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            self.persist_membership("recover")
        })()?;
        Ok(Change::committed(
            ActorRecovered(actor),
            DirtySet::catalog(CatalogScope::Acl),
        ))
    }
}
