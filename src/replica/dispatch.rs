//! Dispatch and resolution helpers (see `mutate` for the validate-then-commit invariant).

use super::*;

impl Replica {
    // ---- dispatch ----

    /// Whether this request mutates space **content** (and so needs write
    /// standing). Membership, device, and recovery ops are excluded — they carry
    /// their own admin/self gates. Anything unlisted defaults to un-gated here,
    /// so a missed variant fails open to today's behavior, never a false denial.
    fn requires_write(req: &Request) -> bool {
        matches!(
            req,
            Request::IssueNew { .. }
                | Request::IssueEdit { .. }
                | Request::IssueMove { .. }
                | Request::Assign { .. }
                | Request::Label { .. }
                | Request::Comment { .. }
                | Request::IssueDelete { .. }
                | Request::IssueRestore { .. }
                | Request::IssueLink { .. }
                | Request::IssueUnlink { .. }
                | Request::IssueParent { .. }
                | Request::IssueStart { .. }
                | Request::IssueDone { .. }
                | Request::IssueStop { .. }
                | Request::ProjectNew { .. }
                | Request::LabelNew { .. }
        )
    }

    /// Whether this device's actor currently holds content-write standing
    /// (`can_write` = Admin or Write grant). A viewer, agent, or non-member is
    /// false.
    pub(super) fn can_write_now(&self) -> bool {
        self.my_actor()
            .is_some_and(|a| self.acl_state().can_write(&a))
    }

    /// Handle a replica request. Returns the response plus an optional dirty-set
    /// (present only when a commit happened — never on error, so a doorbell never
    /// rings for a rejected write).
    pub fn handle(&mut self, req: Request) -> (Response, Option<DirtySet>) {
        // View-only enforcement. A member with no Write/Admin grant (a viewer)
        // is sealed the key and reads freely, but holds no content authority, so
        // it may not mutate space content. Non-members and agents are refused
        // for the same reason. Device/membership/recovery ops are self- or admin-
        // gated in their own handlers, so they are NOT gated here (a viewer must
        // still manage its own devices and recover). Signed content ops
        // (tombstones) are additionally void in the authz plane on every replica;
        // this gate refuses the unsigned-CRDT writes up front with a clear reason.
        if Self::requires_write(&req) && !self.can_write_now() {
            return (
                Response::err("view-only: your membership grants no write access"),
                None,
            );
        }
        let r = match req {
            Request::IssueNew {
                title,
                project,
                project_hint,
                assignees,
                priority,
                labels,
                body,
            } => {
                return Self::respond(
                    self.issue_new(
                        title,
                        project,
                        project_hint,
                        assignees,
                        priority,
                        labels,
                        body,
                    ),
                    Self::ref_response,
                )
            }
            Request::IssueEdit {
                reff,
                title,
                status,
                priority,
                description,
            } => {
                return Self::respond(
                    self.issue_edit(reff, title, status, priority, description),
                    Self::ref_response,
                )
            }
            Request::IssueMove { reff, project, pos } => {
                return Self::respond(self.issue_move(reff, project, pos), Self::ref_response)
            }
            Request::Assign { reff, who, add } => {
                return Self::respond(self.assign(reff, who, add), Self::ref_response)
            }
            Request::Label { reff, add, remove } => {
                return Self::respond(self.label(reff, add, remove), Self::ref_response)
            }
            Request::Comment { reff, body } => {
                return Self::respond(self.comment(reff, body), Self::ref_response)
            }
            Request::IssueDelete { reff } => {
                return Self::respond(self.issue_delete(reff), Self::deletion_response)
            }
            Request::IssueRestore { reff } => {
                return Self::respond(self.issue_restore(reff), Self::deletion_response)
            }
            Request::IssueLink { reff, kind, target } => {
                return Self::respond(
                    self.issue_link(reff, kind, target, true),
                    Self::ref_response,
                )
            }
            Request::IssueUnlink { reff, kind, target } => {
                return Self::respond(
                    self.issue_link(reff, kind, target, false),
                    Self::ref_response,
                )
            }
            Request::IssueParent { reff, parent } => {
                return Self::respond(self.issue_parent(reff, parent), Self::ref_response)
            }
            Request::IssueGraph { reff } => {
                return Self::respond_read(self.issue_graph(reff), |view| {
                    Response::Graph(Box::new(view))
                })
            }
            Request::IssueStart { reff } => {
                return Self::respond(
                    self.work_state(reff, WorkAction::Start),
                    Self::issue_response,
                )
            }
            Request::IssueDone { reff } => {
                return Self::respond(
                    self.work_state(reff, WorkAction::Done),
                    Self::issue_response,
                )
            }
            Request::IssueStop { reff } => {
                return Self::respond(
                    self.work_state(reff, WorkAction::Stop),
                    Self::issue_response,
                )
            }
            Request::IssueView { reff } => {
                return Self::respond_read(self.issue_view(reff), |view| {
                    Response::Issue(Box::new(view))
                })
            }
            Request::List { project, filter } => {
                return Self::respond_read(self.list(project, filter), |rows| Response::List {
                    rows,
                })
            }
            Request::Board {
                project,
                project_hint,
            } => {
                return Self::respond_read(self.board(project, project_hint), |view| {
                    Response::Board(Box::new(view))
                })
            }
            Request::History { reff } => {
                return Self::respond_read(self.history(reff), |page| Response::Activity {
                    events: page.events,
                    last: page.last,
                })
            }
            Request::ProjectNew { name, key } => {
                return Self::respond(self.project_new(name, key), Self::ref_response)
            }
            Request::ProjectList => Ok((
                Response::Projects {
                    projects: self.project_list(),
                },
                None,
            )),
            Request::LabelNew { name, color } => {
                return Self::respond(self.label_new(name, color), Self::ref_response)
            }
            Request::LabelList => Ok((
                Response::Labels {
                    labels: self.label_list(),
                },
                None,
            )),
            Request::Activity { since } => {
                let page = self.activity_page(since);
                Ok((
                    Response::Activity {
                        events: page.events,
                        last: page.last,
                    },
                    None,
                ))
            }
            // `as_name` is a node-layer local-petname concern; the replica only
            // seals the ACL op, so it ignores it here.
            Request::MemberAdd { who, admin, .. } => {
                return Self::respond(self.member_add_cmd(who, admin), Self::admission_response)
            }
            Request::MemberRemove { who } => {
                return Self::respond(self.member_remove_cmd(who), Self::member_removed_response)
            }
            Request::AgentAdd { key } => Ok(self.agent_add_cmd(key)),
            Request::KeyRotate => {
                return Self::respond(self.key_rotate_cmd(), Self::key_rotated_response)
            }
            Request::InviteRevoke { invite } => {
                return Self::respond(
                    self.invite_revoke_cmd(invite),
                    Self::invite_revoked_response,
                )
            }
            Request::DeviceInvite => Ok(self.device_invite_cmd()),
            Request::DeviceAdd { consent } => Ok(self.device_add_cmd(consent)),
            Request::DeviceRevoke { device } => Ok(self.device_revoke_cmd(device)),
            Request::DeviceList => Ok((self.device_list_response(), None)),
            Request::Recover => Ok(self.recover()),
            Request::SpaceRecover => Ok(self.space_recover_cmd()),
            Request::SpaceElevate { cofounders, k } => Ok(self.space_elevate_cmd(cofounders, k)),
            Request::SpaceElevateApprove { session, proposal } => {
                Ok(self.space_elevate_approve_cmd(session, proposal))
            }
            Request::SpaceCustodyExport { path, passphrase } => {
                Ok(self.space_custody_export_cmd(path, passphrase))
            }
            Request::SpaceCustodyImport {
                path,
                passphrase,
                force,
            } => Ok(self.space_custody_import_cmd(path, passphrase, force)),
            Request::SpaceRecoverApprove { session, expect } => {
                Ok(self.space_recover_approve_cmd(session, expect))
            }
            Request::Members => Ok((
                Response::Members {
                    members: self.member_list(),
                },
                None,
            )),
            Request::MemberLog => Ok((
                Response::MemberLog {
                    entries: self.member_log(),
                },
                None,
            )),
            other => Err(anyhow!("not a replica request: {other:?}")),
        };
        match r {
            Ok((resp, dirty)) => (resp, dirty),
            Err(e) => (Response::err(format!("{e:#}")), None),
        }
    }

    // ---- the control adapter ----
    //
    // The single door between the domain and the client protocol. Everything
    // below this line speaks `Response`; everything the replica exposes above it
    // speaks [`Change`] and [`ReplicaError`]. Keeping the conversion in one
    // place is what lets the domain be lifted out from under the daemon later,
    // and what keeps error prose from scattering back into the modules that
    // detect failures.

    /// Turn a command's result into a wire response and a doorbell.
    ///
    /// The `Err` arm hard-codes `None`: a refused command has nothing to
    /// announce. [`Change`] makes that unrepresentable on the way in, and this
    /// makes it unrepresentable on the way out.
    pub(super) fn respond<T>(
        result: ChangeResult<T>,
        into_response: impl FnOnce(T) -> Response,
    ) -> (Response, Option<DirtySet>) {
        match result {
            Ok(change) => {
                let (value, dirty) = change.into_parts();
                (into_response(value), dirty)
            }
            Err(e) => (Self::error_response(e), None),
        }
    }

    /// The handle a write echoes back.
    fn ref_response(r: ResolvedRef) -> Response {
        Response::Ref { reff: r.0 }
    }

    /// A work-state transition answers with the issue's fresh snapshot.
    fn issue_response(view: IssueView) -> Response {
        Response::Issue(Box::new(view))
    }

    /// Which verb a tombstone toggle used is a rendering choice, so the domain
    /// reports the direction and the sentence is written here.
    fn deletion_response(d: Deletion) -> Response {
        let verb = if d.restored { "restored" } else { "deleted" };
        Response::Ok {
            message: Some(format!("{verb} {}", d.reff)),
        }
    }

    fn admission_response(a: Admission) -> Response {
        let message = match a {
            Admission::Added(actor) => format!("added member {}", actor.short()),
            Admission::AutoApproved(actor) => {
                format!("auto-approved {} via invite", actor.short())
            }
            Admission::AlreadyMember(actor) => format!("{} is already a member", actor.short()),
        };
        Response::Ok {
            message: Some(message),
        }
    }

    fn member_removed_response(r: MemberRemoved) -> Response {
        Response::Ok {
            message: Some(format!(
                "removed member {} and rotated the key",
                r.0.short()
            )),
        }
    }

    fn key_rotated_response(k: KeyRotated) -> Response {
        Response::Ok {
            message: Some(format!(
                "rotated the space key (generation {})",
                k.generation
            )),
        }
    }

    /// Never claim the invite was undone. A redemption that causally precedes
    /// this revoke stands (it was legitimate); a concurrent one is evicted on
    /// merge and the key rotates — but in both cases content already shared
    /// stays readable by whoever was admitted. That is lazy revocation, and no
    /// amount of re-keying closes it.
    ///
    /// `spent_nonces` is grow-only, so a spent nonce says an admission
    /// *happened* — not that the actor is still a member. They may have been
    /// removed since. Point at the member list rather than asserting a seat.
    fn invite_revoked_response(r: InviteRevocation) -> Response {
        let message = if r.already_spent {
            "the invite had already been redeemed, so revoking it does not undo \
             that admission. Check the member list and remove the actor if they \
             should no longer have access."
        } else {
            "revoked the invite — it admits no one from here on. If it was \
             redeemed elsewhere before this synced, that member is removed and \
             the key rotates on merge, but content shared before then stays \
             readable by them."
        };
        Response::Ok {
            message: Some(message.into()),
        }
    }

    /// Turn a fallible read's result into a wire response. Always `None`: a read
    /// has no persistence effect, so there is nothing for it to report.
    ///
    /// A command's [`Change`] needs the sibling helper that splits it into value
    /// and doorbell. The two are kept apart so that reads never need `Change` at
    /// all: were a read to adapt through it, every domain module would need
    /// `Change::unchanged` in reach and could manufacture a commit report for
    /// something that never wrote. Separating them reserves `unchanged` for
    /// command branches that provably wrote nothing.
    pub(super) fn respond_read<T>(
        result: ReplicaResult<T>,
        into_response: impl FnOnce(T) -> Response,
    ) -> (Response, Option<DirtySet>) {
        match result {
            Ok(value) => (into_response(value), None),
            Err(e) => (Self::error_response(e), None),
        }
    }

    /// Render a domain failure. `NotFound` is the only family the control plane
    /// reports as such — scripts read the kind, people read the message.
    pub(super) fn error_response(e: ReplicaError) -> Response {
        match e {
            // A ref that named several issues, or none but with near misses, is
            // answered with the list rather than a refusal: the useful reply to
            // a typo is the handle the caller meant.
            ReplicaError::Ref(RefError::Candidates {
                candidates,
                near_miss_for,
            }) => Response::Candidates {
                candidates,
                near_miss_for,
            },
            ReplicaError::Ref(ref inner @ RefError::NoMatch { .. }) => {
                Response::not_found(inner.to_string())
            }
            ReplicaError::NotFound(ref inner) => Response::not_found(inner.to_string()),
            other => Response::err(other.to_string()),
        }
    }

    // ---- resolution helpers ----

    /// Resolve an issue ref → `DocId`, or say how it failed to name exactly one.
    pub(super) fn resolve_issue(&self, reff: &str) -> std::result::Result<DocId, ReplicaError> {
        match index::resolve_ref(&self.catalog, &self.aliases, reff) {
            RefResolution::One(id) => Ok(id),
            // Nothing matched — offer the closest handles rather than a dead end.
            // The candidate machinery already exists for the ambiguous case; a
            // typo is the more common way to get here.
            RefResolution::Zero => {
                let near = index::near_misses(&self.catalog, &self.aliases, reff, 5);
                Err(ReplicaError::Ref(if near.is_empty() {
                    RefError::NoMatch {
                        reff: reff.to_string(),
                    }
                } else {
                    RefError::Candidates {
                        candidates: near,
                        near_miss_for: Some(reff.to_string()),
                    }
                }))
            }
            RefResolution::Many(cands) => Err(ReplicaError::Ref(RefError::Candidates {
                candidates: cands,
                near_miss_for: None,
            })),
        }
    }

    pub(super) fn resolve_project(&self, input: &str) -> Option<ProjectDto> {
        index::resolve_project(&self.catalog, input)
    }

    /// Resolve the target/view project for a command. Precedence: explicit
    /// `-p`/positional (miss = hard error) → environment hint (the CLI's
    /// git-branch key — used only if it resolves, so a branch named `wip-2`
    /// never breaks `new`) → configured `project.default` (user-chosen, so a
    /// stale value errors loudly) → the sole project → a teaching error.
    pub(super) fn choose_project(
        &self,
        explicit: Option<&str>,
        hint: Option<&str>,
    ) -> std::result::Result<ProjectDto, ReplicaError> {
        if let Some(p) = explicit {
            return self.resolve_project(p).ok_or_else(|| {
                ReplicaError::NotFound(NotFound::Project {
                    named: p.to_string(),
                })
            });
        }
        if let Some(h) = hint {
            if let Some(pr) = self.resolve_project(h) {
                return Ok(pr);
            }
        }
        // Read fresh per request — no boot cache, so `lait config set` applies
        // to the very next command with no daemon notify.
        let settings = crate::config::Settings::load(Some(self.store.home_path()));
        if let Some(dflt) = settings.default_project() {
            return self.resolve_project(&dflt).ok_or_else(|| {
                ReplicaError::ProjectChoice(ProjectChoice::StaleDefault { configured: dflt })
            });
        }
        let projects = self.catalog.projects_list();
        match projects.len() {
            1 => Ok(projects.into_iter().next().unwrap()),
            0 => Err(ReplicaError::ProjectChoice(ProjectChoice::None)),
            _ => {
                let keys: Vec<String> = projects.iter().map(|p| p.key.clone()).collect();
                Err(ReplicaError::ProjectChoice(ProjectChoice::Ambiguous {
                    keys,
                }))
            }
        }
    }
}
