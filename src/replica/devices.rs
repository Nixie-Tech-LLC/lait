//! Multi-device (lait/actor/1 device management) and agent sponsorship.

use super::*;

impl Replica {
    pub(super) fn agent_add_cmd(&mut self, who: String) -> (Response, Option<DirtySet>) {
        // `who` is the agent's device key (or actor id). The agent self-incepts
        // when it joins, so by sponsor time its actor is known (synced, or
        // imported from the join request by the node layer).
        let Some(actor) = self.resolve_actor(&who) else {
            return (
                Response::not_found(format!(
                    "no known actor for '{who}' — start the agent so it joins the workspace, then sponsor it"
                )),
                None,
            );
        };
        self.agent_add_by_actor(&actor)
    }

    /// Sponsor an agent by importing its inception, then delegating to
    /// [`agent_add_by_actor`]. An agent is a **degenerate actor** (single-device,
    /// no recovery) that self-incepted in its own home.
    ///
    /// [`agent_add_by_actor`]: Self::agent_add_by_actor
    pub fn agent_add(&mut self, agent_incept: &actor::SignedEvent) -> (Response, Option<DirtySet>) {
        let agent_actor = ActorId::from_incept_hash(&agent_incept.hash());
        let mut candidate = self.membership.actor_events();
        candidate.push(agent_incept.clone());
        if !actor::replay(&self.workspace_id, &candidate).exists(&agent_actor) {
            return (Response::err("invalid agent inception"), None);
        }
        if let Err(e) = self.import_inception(agent_incept) {
            return (Response::err(format!("{e:#}")), None);
        }
        self.agent_add_by_actor(&agent_actor)
    }

    /// Sponsor an already-known agent actor: sign `AddAgent` and
    /// seal it the workspace key. Any human member may sponsor; the agent holds
    /// no membership or content authority, and its standing dies with the
    /// sponsor. The agent's inception must already be present (it self-incepts
    /// on join). Delegation, not elevation.
    pub fn agent_add_by_actor(&mut self, agent_actor: &ActorId) -> (Response, Option<DirtySet>) {
        let acl = self.acl_state();
        match self.my_actor() {
            Some(me) if acl.is_human_member(&me) => {}
            _ => {
                return (
                    Response::err("only a human member can sponsor an agent"),
                    None,
                )
            }
        }
        if !self.actor_plane().exists(agent_actor) {
            return (
                Response::err(format!(
                    "unknown agent {} — start it so its identity joins first",
                    agent_actor.short()
                )),
                None,
            );
        }
        if acl.is_member(agent_actor) {
            return (
                Response::err(format!(
                    "{} is already a workspace principal",
                    agent_actor.short()
                )),
                None,
            );
        }
        // The op is authored as the sponsor's actor (its by/asof), so the
        // AddAgent's sponsor = sponsor actor by construction.
        let op = match self.author_acl(AclAction::AddAgent {
            actor: agent_actor.clone(),
        }) {
            Ok(op) => op,
            Err(e) => return (Response::err(format!("{e:#}")), None),
        };
        let target = agent_actor.clone();
        if let Err(e) =
            self.member_apply(op, "agent_add", |t| Self::seal_epochs_to_actor(t, &target))
        {
            return (Response::err(format!("{e:#}")), None);
        }
        self.push_activity(
            None,
            &agent_actor.short(),
            "agent_added",
            vec![],
            &agent_actor.short(),
        );
        (
            Response::Ok {
                message: Some(format!("sponsored agent {}", agent_actor.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    // ---- multi-device (lait/actor/1 device management) ----

    /// A device-enrollment token for adding another device to *this* actor:
    /// `<actor_id> <workspace_id>`. The new machine consumes it with
    /// `device accept`, which produces a consent blob for `device add`.
    pub(super) fn device_invite_cmd(&self) -> (Response, Option<DirtySet>) {
        match self.my_actor() {
            Some(a) => (
                Response::Text {
                    text: format!("{} {}", a, self.workspace_id),
                },
                None,
            ),
            None => (
                Response::err("this device has no actor identity in this space yet"),
                None,
            ),
        }
    }

    pub(super) fn device_list_response(&self) -> Response {
        let devices: Vec<String> = self
            .my_actor()
            .map(|a| self.actor_plane().devices_of(&a))
            .unwrap_or_default()
            .into_iter()
            .map(|d| {
                let me = if d == self.me { " (this device)" } else { "" };
                format!("{}{}", d.as_str(), me)
            })
            .collect();
        Response::Text {
            text: if devices.is_empty() {
                "no devices".to_string()
            } else {
                devices.join("\n")
            },
        }
    }

    /// Add a device to our actor from its consent blob (hex-encoded
    /// [`actor::DeviceBinding`] from `device accept`), authored by this device,
    /// and seal every held epoch to it so it can decrypt immediately.
    pub(super) fn device_add_cmd(&mut self, consent_hex: String) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.my_actor() else {
            return (Response::err("this device has no actor identity"), None);
        };
        let binding: actor::DeviceBinding = match data_encoding::HEXLOWER_PERMISSIVE
            .decode(consent_hex.as_bytes())
            .ok()
            .and_then(|b| postcard::from_bytes(&b).ok())
        {
            Some(b) => b,
            None => return (Response::err("could not decode device consent blob"), None),
        };
        if !actor::consent_verify(
            self.workspace_id.as_str(),
            &binding,
            &actor::ConsentCtx::Member { actor: &actor },
        ) {
            return (
                Response::err("device consent is not valid for this actor"),
                None,
            );
        }
        let new_device = binding.device.clone();
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::AddDevice {
                actor: actor.clone(),
                binding,
            },
            self.membership.actor_heads(&actor),
            &self.workspace_id,
        );
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            let held: Vec<([u8; 16], WorkspaceKey)> =
                self.keyring.iter().map(|(e, k)| (*e, *k)).collect();
            for (id, key) in held {
                if let Some(sealed) = crypto::seal_to(&new_device, &key) {
                    self.membership.put_sealed(&id, &new_device, &sealed)?;
                }
            }
            self.persist_membership("device_add")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!("added device {}", new_device.short())),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }

    /// Revoke a device from our actor. De-listing is self-authored (any member
    /// may do it for their own actor). **Fencing** the device from future content
    /// needs a key rotation, which only an admin may mint: an admin rotates
    /// immediately (re-sealing the fresh epoch to the remaining devices only); a
    /// non-admin de-lists and is told the rotation is pending an admin, rather
    /// than being handed a rotation that would be inert.
    pub(super) fn device_revoke_cmd(&mut self, device: String) -> (Response, Option<DirtySet>) {
        let Some(actor) = self.my_actor() else {
            return (Response::err("this device has no actor identity"), None);
        };
        let Some(device) = UserId::parse(&device) else {
            return (Response::err("a device is a 64-hex ed25519 key"), None);
        };
        let devices = self.actor_plane().devices_of(&actor);
        if !devices.contains(&device) {
            return (Response::err("not a device of your actor"), None);
        }
        if devices.len() <= 1 {
            return (
                Response::err("cannot revoke your only device — use `recover` instead"),
                None,
            );
        }
        let ev = actor::sign_event(
            &self.seed,
            &actor::ActorOp::RevokeDevice {
                actor: actor.clone(),
                device: device.clone(),
            },
            self.membership.actor_heads(&actor),
            &self.workspace_id,
        );
        // De-listing the device is self-authored and always applies. Fully
        // fencing it, though, requires a **key rotation**, which only an admin
        // may mint. Rotate when we can; otherwise apply the revocation and report
        // honestly that content re-keying is pending an admin — never claim a
        // rotation that would be inert (the device would keep reading under the
        // still-active epoch).
        let can_rotate = self.am_i_admin();
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            if can_rotate {
                self.rotate_key()?;
            }
            self.persist_membership("device_revoke")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        let message = if can_rotate {
            format!("revoked device {} and rotated the key", device.short())
        } else {
            format!(
                "revoked device {} from your identity — ask an admin to rotate the workspace key to fence its access to existing content",
                device.short()
            )
        };
        (
            Response::Ok {
                message: Some(message),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
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
    /// restored immediately, but this fresh device holds no workspace key until
    /// an admin or surviving peer re-seals it (self-heal on their next sync).
    pub fn recover(&mut self) -> (Response, Option<DirtySet>) {
        let Some(seed) = self.read_recovery_key() else {
            return (
                Response::err(
                    "no recovery.key found beside the store — restore your offline recovery key first",
                ),
                None,
            );
        };
        // Resolve the target actor by its pre-rotation commitment — NOT by the
        // current device set (a genuine recovery runs from a fresh device that is
        // not in the set). The actor whose standing commitment matches our
        // recovery key is the one we can recover.
        let recovery_pub = crypto::user_from_seed(&seed);
        let commit = actor::recovery_commitment(&recovery_pub);
        let plane = self.actor_plane();
        let Some(actor) = plane
            .actors()
            .find(|(_, st)| commit.is_some() && st.recovery_commit == commit)
            .map(|(id, _)| id.clone())
        else {
            return (
                Response::err("no actor in this space matches this recovery key"),
                None,
            );
        };
        let binding = actor::consent_sign(
            &self.seed,
            self.workspace_id.as_str(),
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
            &self.workspace_id,
        );
        // Validate the recovery actually took (commitment match) before persisting.
        let mut candidate = self.membership.actor_events();
        candidate.push(ev.clone());
        let recovered = actor::replay(&self.workspace_id, &candidate)
            .state(&actor)
            .map(|s| s.recovered)
            .unwrap_or(false);
        if !recovered {
            return (
                Response::err("recovery key does not match this actor's commitment"),
                None,
            );
        }
        let res = (|| -> Result<()> {
            self.membership.add_actor_event(&ev)?;
            self.persist_membership("recover")
        })();
        if let Err(e) = res {
            return (Response::err(format!("{e:#}")), None);
        }
        (
            Response::Ok {
                message: Some(format!(
                    "recovered actor {} — device set reset to this device; content access re-seals once a peer syncs",
                    actor.short()
                )),
            },
            Some(DirtySet::catalog(CatalogScope::Acl)),
        )
    }
}
