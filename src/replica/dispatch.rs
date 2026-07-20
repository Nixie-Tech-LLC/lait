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
            } => self.issue_new(
                title,
                project,
                project_hint,
                assignees,
                priority,
                labels,
                body,
            ),
            Request::IssueEdit {
                reff,
                title,
                status,
                priority,
                description,
            } => self.issue_edit(reff, title, status, priority, description),
            Request::IssueMove { reff, project, pos } => self.issue_move(reff, project, pos),
            Request::Assign { reff, who, add } => self.assign(reff, who, add),
            Request::Label { reff, add, remove } => self.label(reff, add, remove),
            Request::Comment { reff, body } => self.comment(reff, body),
            Request::IssueDelete { reff } => self.issue_delete(reff),
            Request::IssueRestore { reff } => self.issue_restore(reff),
            Request::IssueLink { reff, kind, target } => self.issue_link(reff, kind, target, true),
            Request::IssueUnlink { reff, kind, target } => {
                self.issue_link(reff, kind, target, false)
            }
            Request::IssueParent { reff, parent } => self.issue_parent(reff, parent),
            Request::IssueGraph { reff } => self.issue_graph(reff).map(|r| (r, None)),
            Request::IssueStart { reff } => self.work_state(reff, WorkAction::Start),
            Request::IssueDone { reff } => self.work_state(reff, WorkAction::Done),
            Request::IssueStop { reff } => self.work_state(reff, WorkAction::Stop),
            Request::IssueView { reff } => self.issue_view(reff).map(|r| (r, None)),
            Request::List { project, filter } => {
                return Self::respond(self.list(project, filter), |rows| Response::List { rows })
            }
            Request::Board {
                project,
                project_hint,
            } => self.board(project, project_hint).map(|r| (r, None)),
            Request::History { reff } => self.history(reff).map(|r| (r, None)),
            Request::ProjectNew { name, key } => self.project_new(name, key),
            Request::ProjectList => Ok((self.project_list(), None)),
            Request::LabelNew { name, color } => self.label_new(name, color),
            Request::LabelList => Ok((self.label_list(), None)),
            Request::Activity { since } => Ok((self.activity_response(since), None)),
            // `as_name` is a node-layer local-petname concern; the replica only
            // seals the ACL op, so it ignores it here.
            Request::MemberAdd { who, admin, .. } => Ok(self.member_add_cmd(who, admin)),
            Request::MemberRemove { who } => Ok(self.member_remove_cmd(who)),
            Request::AgentAdd { key } => Ok(self.agent_add_cmd(key)),
            Request::KeyRotate => Ok(self.key_rotate_cmd()),
            Request::InviteRevoke { invite } => Ok(self.invite_revoke_cmd(invite)),
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
            Request::Members => Ok((self.members_response(), None)),
            Request::MemberLog => Ok((self.member_log_response(), None)),
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
    // speaks [`Outcome`] and [`ReplicaError`]. Keeping the conversion in one
    // place is what lets the domain be lifted out from under the daemon later,
    // and what keeps error prose from scattering back into the modules that
    // detect failures.

    /// Turn a domain result into a wire response and a doorbell.
    ///
    /// The `Err` arm hard-codes `None`: a failed operation committed nothing, so
    /// it has nothing to announce. [`Outcome`] makes that unrepresentable on the
    /// way in, and this makes it unrepresentable on the way out.
    pub(super) fn respond<T>(
        result: std::result::Result<Outcome<T>, ReplicaError>,
        into_response: impl FnOnce(T) -> Response,
    ) -> (Response, Option<DirtySet>) {
        match result {
            Ok(outcome) => {
                let (value, dirty) = outcome.into_parts();
                (into_response(value), dirty)
            }
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
