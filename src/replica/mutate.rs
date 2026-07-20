//! Mutations (writes).
//!
//! **Validate then commit.** Every mutating request fully
//! resolves refs and validates *before* any Loro commit; on failure it returns
//! `Response::Error` having touched nothing and produced **no** dirty-set (so no
//! doorbell rings), which is what makes an optimistic client's rollback
//! race-free. There is no compare-and-swap token: failures occur before commit.
//!
//! **Writer-direction projection.** Every mutation ends by recomputing the issue's
//! `DocMeta` row from the issue doc via [`CatalogDoc::upsert_row`] — the issue
//! doc is always truth; the row is a one-directional cache.

use super::*;

/// The three work-state intents: `start`, `done`, and `stop`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkAction {
    Start,
    Done,
    Stop,
}

impl Replica {
    // ---- mutations ----

    #[allow(clippy::too_many_arguments)]
    pub(super) fn issue_new(
        &mut self,
        title: String,
        project: Option<String>,
        project_hint: Option<String>,
        assignees: Vec<String>,
        priority: Option<String>,
        labels: Vec<String>,
        body: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        // ---- validate (no commits yet) ----
        if title.trim().is_empty() {
            return Ok((Response::err("title must not be empty"), None));
        }
        let project = match self.choose_project(project.as_deref(), project_hint.as_deref()) {
            Ok(pr) => pr,
            Err(resp) => return Ok((resp, None)),
        };
        let priority = match priority {
            Some(p) => match Priority::parse(&p) {
                Some(pr) => pr,
                None => return Ok((Response::err(format!("bad priority '{p}'")), None)),
            },
            None => Priority::None,
        };
        // resolve assignees + labels up front (validate-then-commit)
        let mut assignee_ids = Vec::new();
        for a in &assignees {
            match self.resolve_actor(a) {
                Some(act) => assignee_ids.push(act),
                None => {
                    return Ok((
                        Response::not_found(format!("no known member matches '{a}'")),
                        None,
                    ))
                }
            }
        }
        // Labels resolve or create on first use, but the
        // whole batch is validated before anything is minted, so a bad input
        // later in the list can't leave stray labels behind.
        if let Some(l) = labels.iter().find(|l| self.invalid_label_input(l)) {
            return Ok((Response::not_found(format!("no label matches '{l}'")), None));
        }
        let mut label_ids = Vec::new();
        let mut created_label = false;
        for l in &labels {
            let (id, created) = self.resolve_or_create_label(l)?;
            created_label |= created;
            label_ids.push(id);
        }

        // ---- apply ----
        let doc_id = DocId::mint(&*self.clock);
        let issue = IssueDoc::create(NewIssue {
            doc_id: doc_id.clone(),
            workspace_id: self.workspace_id.clone(),
            project_id: project.id.clone(),
            title: title.clone(),
            priority,
            created_by: match self.my_actor() {
                Some(a) => a,
                None => return Ok((Response::err("this device has no actor identity"), None)),
            },
            committed_by: self.me.clone(),
            created_at: self.now_secs(),
            body,
            peer: Some(self.store.peer_id()),
        })?;
        for u in &assignee_ids {
            issue.add_assignee(u)?;
        }
        for l in &label_ids {
            issue.add_label(l)?;
        }
        issue.apply(&OpCtx::content("created", &self.me));

        self.catalog.upsert_row(&issue)?;
        self.catalog.assign_alias_seq(&doc_id, &project.id)?;
        self.catalog.board_insert_top(&project.id, &doc_id)?;
        self.catalog.apply(&OpCtx::structure("created", &self.me));

        self.store.save_issue(&issue)?;
        self.store.save_catalog(&self.catalog)?;
        self.issues.insert(doc_id.clone(), issue);
        // Incremental alias upkeep (O(log N)): a fresh doc + its two sorted
        // neighbours, not an O(N²) full rebuild.
        self.aliases.reconcile_doc(&self.catalog, &doc_id);
        // Durable already (fsync'd above); the git snapshot is coalesced by the
        // daemon's periodic checkpoint — no `git add -A` on the create path.
        self.store.mark_dirty();

        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "created", vec![], &title);
        let mut dirty = DirtySet::issue(&project.id, &doc_id).with_scope(CatalogScope::Boards {
            project: project.id.as_str().to_string(),
        });
        if created_label {
            dirty = dirty.with_scope(CatalogScope::Labels);
        }
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    pub(super) fn issue_edit(
        &mut self,
        reff: String,
        title: Option<String>,
        status: Option<String>,
        priority: Option<String>,
        description: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        // validate status/priority before touching anything
        if let Some(s) = &status {
            if self.catalog.workflow_state(s).is_none() {
                return Ok((Response::err(format!("no such status '{s}'")), None));
            }
        }
        let new_priority = match &priority {
            Some(p) => match Priority::parse(p) {
                Some(pr) => Some(pr),
                None => return Ok((Response::err(format!("bad priority '{p}'")), None)),
            },
            None => None,
        };
        if title.is_none() && status.is_none() && priority.is_none() && description.is_none() {
            return Ok((Response::err("nothing to edit"), None));
        }

        let ctx = OpCtx::content("edited", &self.me);
        let project_id;
        let mut changes = Vec::new();
        let mut status_transition: Option<(String, String)> = None;
        {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            project_id = issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?;
            if let Some(t) = &title {
                let from = issue.title();
                issue.set_title(t)?;
                changes.push(FieldChange {
                    field: "title".into(),
                    from: Some(from),
                    to: Some(t.clone()),
                });
            }
            if let Some(s) = &status {
                let from = issue.status();
                issue.set_status(s)?;
                changes.push(FieldChange {
                    field: "status".into(),
                    from: Some(from.clone()),
                    to: Some(s.clone()),
                });
                status_transition = Some((from, s.clone()));
            }
            if let Some(p) = new_priority {
                let from = issue.priority();
                issue.set_priority(p)?;
                changes.push(FieldChange {
                    field: "priority".into(),
                    from: Some(from.as_str().to_string()),
                    to: Some(p.as_str().to_string()),
                });
            }
            if let Some(d) = &description {
                // Spliced into the RGA text. Bodies are too big
                // for the activity row — record the transition, elide the values.
                issue.set_description(d)?;
                changes.push(FieldChange {
                    field: "description".into(),
                    from: None,
                    to: None,
                });
            }
            issue.apply(&ctx);
        }
        // Entering a done-category status removes the issue from active boards.
        // doc from the board list; reopening re-inserts it at the top.
        if let Some((from, to)) = &status_transition {
            let from_done = self.is_done_status(from);
            let to_done = self.is_done_status(to);
            if to_done && !from_done {
                self.catalog.board_remove(&project_id, &doc_id)?;
            } else if from_done && !to_done {
                self.catalog.board_insert_top(&project_id, &doc_id)?;
            }
        }

        self.persist_issue_and_row(&doc_id, "edited")?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "edited", changes, "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    /// One `start`, `done`, or `stop` work-state transition: the fields a
    /// single human intent moves — status by workflow *category* plus the
    /// viewer's assignment, in one Loro commit and one activity row.
    /// Returns a fresh `Response::Issue` snapshot (the CLI derives the git
    /// branch name from the title); a no-op (already there) returns the
    /// snapshot with no commit, no activity, no doorbell.
    pub(super) fn work_state(
        &mut self,
        reff: String,
        action: WorkAction,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let (cat, kind) = match action {
            WorkAction::Start => (StatusCategory::Active, "started"),
            WorkAction::Done => (StatusCategory::Done, "finished"),
            WorkAction::Stop => (StatusCategory::Backlog, "stopped"),
        };
        let Some(target) = self.first_state_in(cat) else {
            return Ok((
                Response::err(format!(
                    "this space's workflow has no {}-category status",
                    cat.as_str()
                )),
                None,
            ));
        };
        let me = match self.my_actor() {
            Some(a) => a,
            None => return Ok((Response::err("this device has no actor identity"), None)),
        };
        let ctx = OpCtx::content(kind, &self.me);

        let project_id;
        let mut changes = Vec::new();
        let status_transition: (String, String);
        {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            project_id = issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?;
            let from = issue.status();
            if from != target.id {
                issue.set_status(&target.id)?;
                changes.push(FieldChange {
                    field: "status".into(),
                    from: Some(from.clone()),
                    to: Some(target.id.clone()),
                });
            }
            status_transition = (from, target.id.clone());
            let assigned_to_me = issue.assignees().contains(&me);
            match action {
                WorkAction::Start if !assigned_to_me => {
                    issue.add_assignee(&me)?;
                    changes.push(FieldChange {
                        field: "assignees".into(),
                        from: None,
                        to: Some("@me".into()),
                    });
                }
                WorkAction::Stop if assigned_to_me => {
                    issue.remove_assignee(&me)?;
                    changes.push(FieldChange {
                        field: "assignees".into(),
                        from: Some("@me".into()),
                        to: None,
                    });
                }
                _ => {}
            }
            if changes.is_empty() {
                // Already exactly there — idempotent: no commit, no activity.
                return self.issue_view(reff).map(|r| (r, None));
            }
            issue.apply(&ctx);
        }
        // Entering a done-category status removes the issue from active boards.
        // doc from the board list; leaving one re-inserts it at the top.
        {
            let (from, to) = &status_transition;
            let from_done = self.is_done_status(from);
            let to_done = self.is_done_status(to);
            if to_done && !from_done {
                self.catalog.board_remove(&project_id, &doc_id)?;
            } else if from_done && !to_done {
                self.catalog.board_insert_top(&project_id, &doc_id)?;
            }
        }

        self.persist_issue_and_row(&doc_id, kind)?;
        let canonical = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &canonical, kind, changes, "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        self.issue_view(canonical).map(|r| (r, Some(dirty)))
    }

    pub(super) fn issue_move(
        &mut self,
        reff: String,
        project: Option<String>,
        pos: Option<BoardPos>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        // validate target project + anchors up front
        let new_project = match &project {
            Some(p) => match self.resolve_project(p) {
                Some(pr) => Some(pr),
                None => {
                    return Ok((
                        Response::not_found(format!("no project matches '{p}'")),
                        None,
                    ))
                }
            },
            None => None,
        };
        let anchor = match &pos {
            Some(BoardPos::Before { reff }) | Some(BoardPos::After { reff }) => {
                match self.resolve_issue(reff) {
                    Ok(id) => Some(id),
                    Err(resp) => return Ok((resp, None)),
                }
            }
            _ => None,
        };

        let old_project = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            issue
                .project_id()
                .ok_or_else(|| anyhow!("issue has no project"))?
        };

        // Project membership is authoritative: write Issue.projectId first.
        let effective_project = if let Some(np) = &new_project {
            if np.id != old_project {
                let issue = self.issues.get(&doc_id).unwrap();
                issue.set_project(&np.id)?;
                issue.apply(&OpCtx::content("moved", &self.me));
                // fix both board lists (cache maintenance)
                self.catalog.board_remove(&old_project, &doc_id)?;
                self.catalog.board_insert_top(&np.id, &doc_id)?;
            }
            np.id.clone()
        } else {
            old_project.clone()
        };

        // 2. board ordering (cache) within the effective project.
        if let Some(pos) = &pos {
            match pos {
                BoardPos::Top => self.catalog.board_insert_top(&effective_project, &doc_id)?,
                BoardPos::Bottom => {
                    self.catalog.board_remove(&effective_project, &doc_id)?;
                    self.catalog
                        .board_insert_bottom(&effective_project, &doc_id)?;
                }
                BoardPos::Before { .. } => {
                    if let Some(a) = &anchor {
                        self.catalog
                            .board_move(&effective_project, &doc_id, a, false)?;
                    }
                }
                BoardPos::After { .. } => {
                    if let Some(a) = &anchor {
                        self.catalog
                            .board_move(&effective_project, &doc_id, a, true)?;
                    }
                }
            }
        }

        self.persist_issue_and_row(&doc_id, "moved")?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "moved", vec![], "");
        let mut dirty =
            DirtySet::issue(&effective_project, &doc_id).with_scope(CatalogScope::Boards {
                project: effective_project.as_str().to_string(),
            });
        if effective_project != old_project {
            dirty = dirty.with_scope(CatalogScope::Boards {
                project: old_project.as_str().to_string(),
            });
        }
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    pub(super) fn assign(
        &mut self,
        reff: String,
        who: Vec<String>,
        add: bool,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let mut users = Vec::new();
        for w in &who {
            match self.resolve_actor(w) {
                Some(a) => users.push(a),
                None => {
                    return Ok((
                        Response::not_found(format!("no known member matches '{w}'")),
                        None,
                    ))
                }
            }
        }
        let kind = if add { "assigned" } else { "unassigned" };
        let ctx = OpCtx::content(kind, &self.me);
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            for u in &users {
                if add {
                    issue.add_assignee(u)?;
                } else {
                    issue.remove_assignee(u)?;
                }
            }
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, kind)?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(
            Some(&doc_id),
            &reff,
            if add { "assigned" } else { "unassigned" },
            vec![],
            "",
        );
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    pub(super) fn label(
        &mut self,
        reff: String,
        add: Vec<String>,
        remove: Vec<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        // Adds create the label on first use (labels are vocabulary, not
        // ceremony); removals still error on unknown (removing a
        // label that never existed is a typo, not intent). Everything that can
        // fail is validated BEFORE anything is created (validate-then-commit).
        if let Some(l) = add.iter().find(|l| self.invalid_label_input(l)) {
            return Ok((Response::not_found(format!("no label matches '{l}'")), None));
        }
        let mut remove_ids = Vec::new();
        for l in &remove {
            match self.resolve_label(l) {
                Some(id) => remove_ids.push(id),
                None => return Ok((Response::not_found(format!("no label matches '{l}'")), None)),
            }
        }
        let mut created_any = false;
        let mut add_ids = Vec::new();
        for l in &add {
            let (id, created) = self.resolve_or_create_label(l)?;
            created_any |= created;
            add_ids.push(id);
        }
        let ctx = OpCtx::content("labeled", &self.me);
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            for l in &add_ids {
                issue.add_label(l)?;
            }
            for l in &remove_ids {
                issue.remove_label(l)?;
            }
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, "labeled")?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "labeled", vec![], "");
        let mut dirty = DirtySet::issue(&project_id, &doc_id);
        if created_any {
            dirty = dirty.with_scope(CatalogScope::Labels);
        }
        Ok((Response::Ref { reff }, Some(dirty)))
    }

    pub(super) fn comment(
        &mut self,
        reff: String,
        body: String,
    ) -> Result<(Response, Option<DirtySet>)> {
        if body.trim().is_empty() {
            return Ok((Response::err("comment body must not be empty"), None));
        }
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let ts = self.now_secs();
        // The comment is attributed to the *actor* (the person); the device that
        // landed it rides the change's `OpCtx` as the advisory commit stamp.
        let me = match self.my_actor() {
            Some(a) => a,
            None => return Ok((Response::err("this device has no actor identity"), None)),
        };
        let ctx = OpCtx::content("commented", &self.me);
        let project_id = {
            let issue = self
                .issue(&doc_id)?
                .ok_or_else(|| anyhow!("issue body not present"))?;
            issue.add_comment(&me, ts, &body)?;
            issue.apply(&ctx);
            issue.project_id().ok_or_else(|| anyhow!("no project"))?
        };
        self.persist_issue_and_row(&doc_id, "commented")?;
        let reff = self.aliases.canonical_for(&doc_id);
        self.push_activity(Some(&doc_id), &reff, "commented", vec![], &body);
        Ok((
            Response::Ref { reff },
            Some(DirtySet::issue(&project_id, &doc_id)),
        ))
    }

    pub(super) fn issue_delete(&mut self, reff: String) -> Result<(Response, Option<DirtySet>)> {
        self.set_deleted(reff, true)
    }
    pub(super) fn issue_restore(&mut self, reff: String) -> Result<(Response, Option<DirtySet>)> {
        self.set_deleted(reff, false)
    }

    /// Delete or restore an issue — now a **signed content-authority op**
    /// Agents cannot delete; every deletion is attributable and
    /// reversible, and the catalog tombstone flag becomes a *cache* of the
    /// authz-plane replay. Human members only (an agent holds the key but no
    /// content authority).
    fn set_deleted(&mut self, reff: String, on: bool) -> Result<(Response, Option<DirtySet>)> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let project_id = self
            .catalog
            .row(&doc_id)
            .map(|r| r.project_id)
            .ok_or_else(|| anyhow!("no such row"))?;
        // Content authority = `can_write` (Admin or Write grant): agents and
        // grant-less viewers hold the key but no delete authority. The authz
        // plane voids their tombstone on every replica; we mirror that here so a
        // direct caller gets a clear refusal rather than a silently-void op.
        let me_actor = match self.my_actor() {
            Some(a) if self.acl_state().can_write(&a) => a,
            _ => {
                return Ok((
                    Response::err("no content authority to delete issues (view-only or agent)"),
                    None,
                ))
            }
        };
        // Sign the tombstone op, embedding both the membership frontier and the
        // actor-log frontier we observed (the at-position anchors), and append it
        // to the encrypted authz DAG.
        let op = authz::AuthzOp {
            action: authz::AuthzAction::Tombstone {
                doc: doc_id.clone(),
                on,
            },
            ts: self.now_secs(),
            asof: self.membership.heads(),
            by: me_actor.clone(),
            actor_asof: self.membership.actor_heads(&me_actor),
        };
        let signed = authz::sign_authz(
            &self.seed,
            &op,
            self.catalog.authz_heads(),
            &self.workspace_id,
        );
        self.catalog.add_authz_op(&signed)?;
        // The tombstone flag + board membership are a cache of the replay.
        let tombstoned = self.authz_state().is_tombstoned(&doc_id);
        self.catalog.set_tombstone(&doc_id, tombstoned)?;
        if tombstoned {
            self.catalog.board_remove(&project_id, &doc_id)?;
        } else {
            self.catalog.board_insert_top(&project_id, &doc_id)?;
        }
        self.catalog.apply(&OpCtx::authority(
            if on { "deleted" } else { "restored" },
            &self.me,
        ));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let reff = self.aliases.canonical_for(&doc_id);
        let verb = if on { "deleted" } else { "restored" };
        self.push_activity(Some(&doc_id), &reff, verb, vec![], "");
        let dirty = DirtySet::issue(&project_id, &doc_id).with_scope(CatalogScope::Boards {
            project: project_id.as_str().to_string(),
        });
        Ok((
            Response::Ok {
                message: Some(format!("{verb} {reff}")),
            },
            Some(dirty),
        ))
    }

    /// The materialized content-authority state (deterministic replay of the
    /// encrypted authorization DAG against membership). Roots on the
    /// **effective** genesis for the same reason [`Self::acl_state`] does: after
    /// a break-glass `Recover`, content authority must follow the recovered
    /// admins, not the superseded birth root.
    pub(super) fn authz_state(&self) -> authz::AuthzState {
        authz::replay(
            &self.effective_genesis(),
            &self.membership.actor_events(),
            &self.membership.ops(),
            &self.catalog.authz_ops(),
        )
    }

    /// Reconcile catalog tombstone flags to the authz-plane replay after a sync
    /// import (writer-direction for the T2 plane): a peer's signed delete/restore
    /// becomes visible locally. Returns the docs whose visibility changed.
    pub(super) fn reconcile_tombstones(&mut self) -> Result<Vec<DocId>> {
        let authz = self.authz_state();
        let mut changed = Vec::new();
        for doc_id in self.catalog.doc_ids() {
            if !authz.governs(&doc_id) {
                continue; // Documents outside the authorization DAG keep their legacy flag.
            }
            let want = authz.is_tombstoned(&doc_id);
            let have = self
                .catalog
                .row(&doc_id)
                .map(|r| r.tombstone)
                .unwrap_or(false);
            if want != have {
                self.catalog.set_tombstone(&doc_id, want)?;
                if let Some(pid) = self.catalog.row(&doc_id).map(|r| r.project_id) {
                    if want {
                        self.catalog.board_remove(&pid, &doc_id)?;
                    } else {
                        self.catalog.board_insert_top(&pid, &doc_id)?;
                    }
                }
                changed.push(doc_id);
            }
        }
        if !changed.is_empty() {
            self.catalog
                .apply(&OpCtx::authority("tombstone_sync", &self.me));
        }
        Ok(changed)
    }

    /// Add or remove an issue link in `edges`. `relates` is
    /// symmetric and canonicalized by sorted endpoints so one edge represents it.
    pub(super) fn issue_link(
        &mut self,
        reff: String,
        kind: String,
        target: String,
        add: bool,
    ) -> Result<(Response, Option<DirtySet>)> {
        let kind = kind.to_ascii_lowercase();
        if !LINK_KINDS.contains(&kind.as_str()) {
            return Ok((
                Response::err(format!(
                    "unknown link kind '{kind}' — one of: {}",
                    LINK_KINDS.join(", ")
                )),
                None,
            ));
        }
        let from = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let to = match self.resolve_issue(&target) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        if from == to {
            return Ok((Response::err("an issue cannot link to itself"), None));
        }
        let (a, b) = if kind == "relates" && to < from {
            (to.clone(), from.clone())
        } else {
            (from.clone(), to.clone())
        };
        if add {
            self.catalog.edge_add(&a, &kind, &b)?;
        } else if !self.catalog.edge_remove(&a, &kind, &b)? {
            return Ok((
                Response::not_found(format!("no such link: {reff} {kind} {target}")),
                None,
            ));
        }
        let verb = if add { "linked" } else { "unlinked" };
        self.catalog.apply(&OpCtx::structure(verb, &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let canonical = self.aliases.canonical_for(&from);
        let other = self.aliases.canonical_for(&to);
        self.push_activity(
            Some(&from),
            &canonical,
            verb,
            vec![],
            &format!("{kind} {other}"),
        );
        let mut dirty = DirtySet::default();
        for id in [&from, &to] {
            if let Some(r) = self.catalog.row(id) {
                dirty.merge(DirtySet::issue(&r.project_id, id));
            }
        }
        Ok((Response::Ref { reff: canonical }, Some(dirty)))
    }

    /// Set or clear an issue's parent in the sub-issue hierarchy. The `subs`
    /// tree-move CRDT prevents conflicting concurrent moves from converging to
    /// a cycle.
    pub(super) fn issue_parent(
        &mut self,
        reff: String,
        parent: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        let child = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok((resp, None)),
        };
        let parent_id = match &parent {
            Some(p) => match self.resolve_issue(p) {
                Ok(id) => Some(id),
                Err(resp) => return Ok((resp, None)),
            },
            None => None,
        };
        if parent_id.as_ref() == Some(&child) {
            return Ok((Response::err("an issue cannot be its own parent"), None));
        }
        // validate-then-commit: reject a locally visible cycle before staging
        // any op (the engine's CyclicMoveError is the backstop; concurrent
        // cross-peer cycles are resolved by the merge itself).
        let mut cur = parent_id.clone();
        while let Some(p) = cur {
            if p == child {
                return Ok((
                    Response::err("that would make an issue its own ancestor"),
                    None,
                ));
            }
            cur = self.catalog.parent_of(&p);
        }
        self.catalog.set_parent(&child, parent_id.as_ref())?;
        self.catalog.apply(&OpCtx::structure("parented", &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.mark_dirty();
        let canonical = self.aliases.canonical_for(&child);
        let text = match &parent_id {
            Some(p) => format!("under {}", self.aliases.canonical_for(p)),
            None => "unparented".to_string(),
        };
        self.push_activity(Some(&child), &canonical, "parented", vec![], &text);
        let mut dirty = DirtySet::default();
        for id in std::iter::once(&child).chain(parent_id.iter()) {
            if let Some(r) = self.catalog.row(id) {
                dirty.merge(DirtySet::issue(&r.project_id, id));
            }
        }
        Ok((Response::Ref { reff: canonical }, Some(dirty)))
    }

    /// The issue's graph neighborhood: parent, children, links, and the
    /// transitively-open blockers. The catalog IS the graph index — this is a
    /// read over the structure doc, no issue doc is opened.
    pub(super) fn issue_graph(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        let canonical = self.aliases.canonical_for(&doc_id);
        let rows: HashMap<DocId, RowMeta> = self
            .catalog
            .all_rows()
            .into_iter()
            .map(|r| (r.doc_id.clone(), r))
            .collect();
        let live = |id: &DocId| rows.get(id).filter(|r| !r.tombstone);

        let parent = self
            .catalog
            .parent_of(&doc_id)
            .and_then(|p| live(&p).map(|r| self.project_row(r)));
        let children: Vec<Row> = self
            .catalog
            .children_of(&doc_id)
            .iter()
            .filter_map(|c| live(c).map(|r| self.project_row(r)))
            .collect();

        let edges = self.catalog.edges();
        let mut links = Vec::new();
        for e in &edges {
            let (direction, other) = if e.from == doc_id {
                ("out", &e.to)
            } else if e.to == doc_id {
                ("in", &e.from)
            } else {
                continue;
            };
            if let Some(r) = live(other) {
                links.push(LinkDto {
                    kind: e.kind.clone(),
                    direction: direction.into(),
                    row: self.project_row(r),
                });
            }
        }

        // Transitive open blockers: walk `blocks` edges backwards from this
        // issue; a blocker counts while it is live and not in a done-category
        // status. BFS with a visited set — link cycles are legal in a general
        // edge set and must not hang the walk.
        let mut blocked_by = Vec::new();
        let mut seen: std::collections::HashSet<DocId> = std::collections::HashSet::new();
        let mut queue: VecDeque<DocId> = VecDeque::new();
        seen.insert(doc_id.clone());
        queue.push_back(doc_id.clone());
        while let Some(cur) = queue.pop_front() {
            for e in &edges {
                if e.kind == "blocks" && e.to == cur && seen.insert(e.from.clone()) {
                    if let Some(r) = live(&e.from) {
                        if !self.is_done_status(&r.status) {
                            blocked_by.push(self.project_row(r));
                            queue.push_back(e.from.clone());
                        }
                    }
                }
            }
        }

        Ok(Response::Graph(Box::new(GraphView {
            schema_version: SCHEMA_VERSION,
            reff: canonical,
            doc_id,
            parent,
            children,
            links,
            blocked_by,
        })))
    }

    pub(super) fn project_new(
        &mut self,
        name: String,
        key: String,
    ) -> Result<(Response, Option<DirtySet>)> {
        let key = key.trim().to_ascii_uppercase();
        if name.trim().is_empty() || key.is_empty() {
            return Ok((Response::err("project name and key are required"), None));
        }
        // 1–8 ASCII letters: anything else breaks `KEY-n` alias parsing and
        // git-branch inference (both scan for one alphabetic run).
        if key.len() > 8 || !key.chars().all(|c| c.is_ascii_alphabetic()) {
            return Ok((
                Response::err(format!(
                    "bad project key '{key}' — use 1-8 ASCII letters (it becomes the KEY in KEY-1 refs)"
                )),
                None,
            ));
        }
        if self.catalog.project_by_key(&key).is_some() {
            return Ok((
                Response::err(format!("project key '{key}' already exists")),
                None,
            ));
        }
        let id = ProjectId::mint(&*self.clock);
        self.catalog.add_project(&id, name.trim(), &key, "blue")?;
        self.catalog
            .apply(&OpCtx::structure("project_new", &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.commit(&format!("new project {key}"));
        Ok((
            Response::Ref { reff: key },
            Some(DirtySet::catalog(CatalogScope::Projects)),
        ))
    }

    pub(super) fn label_new(
        &mut self,
        name: String,
        color: Option<String>,
    ) -> Result<(Response, Option<DirtySet>)> {
        if name.trim().is_empty() {
            return Ok((Response::err("label name is required"), None));
        }
        if self.catalog.label_by_name(name.trim()).is_some() {
            return Ok((
                Response::err(format!("label '{name}' already exists")),
                None,
            ));
        }
        let id = LabelId::mint(&*self.clock);
        self.catalog
            .add_label(&id, name.trim(), color.as_deref().unwrap_or("gray"))?;
        self.catalog.apply(&OpCtx::structure("label_new", &self.me));
        self.store.save_catalog(&self.catalog)?;
        self.store.commit(&format!("new label {}", name.trim()));
        Ok((
            Response::Ref {
                reff: name.trim().to_string(),
            },
            Some(DirtySet::catalog(CatalogScope::Labels)),
        ))
    }

    /// Whether an ADD-path label input can never resolve or be created: a
    /// `lbl_`-prefixed id that doesn't exist (an id reference is a pointer, and
    /// a dangling pointer is a typo, not a new name), or an empty name. Checked
    /// for the WHOLE batch before any creation, preserving validate-then-commit.
    fn invalid_label_input(&self, input: &str) -> bool {
        let name = input.trim();
        (name.is_empty() || name.starts_with(LabelId::PREFIX))
            && self.resolve_label(input).is_none()
    }

    /// Resolve a label for an ADD path, creating it on first use (gray). The
    /// caller has already rejected [`Self::invalid_label_input`]s.
    fn resolve_or_create_label(&mut self, input: &str) -> Result<(LabelId, bool)> {
        if let Some(id) = self.resolve_label(input) {
            return Ok((id, false));
        }
        let id = LabelId::mint(&*self.clock);
        self.catalog.add_label(&id, input.trim(), "gray")?;
        Ok((id, true))
    }

    pub(super) fn resolve_label(&self, input: &str) -> Option<LabelId> {
        let input = input.trim();
        if input.starts_with(LabelId::PREFIX) {
            if let Some(id) = LabelId::parse(input) {
                if self.catalog.label(&id).is_some() {
                    return Some(id);
                }
            }
        }
        self.catalog.label_by_name(input).map(|l| l.id)
    }

    /// Persist an issue doc + recompute its row + save the catalog (the common
    /// tail of every issue mutation). `kind` labels the catalog-side change so
    /// the structure doc's oplog stays as legible as the issue docs'.
    fn persist_issue_and_row(&mut self, doc_id: &DocId, kind: &str) -> Result<()> {
        let issue = self
            .issues
            .get(doc_id)
            .ok_or_else(|| anyhow!("issue not loaded"))?;
        self.store.save_issue(issue)?;
        self.catalog.upsert_row(issue)?;
        self.catalog.apply(&OpCtx::structure(kind, &self.me));
        self.store.save_catalog(&self.catalog)?;
        // Incremental alias upkeep. The table is a pure function of {DocId set,
        // projectId, seq}: a plain field edit changes none of these, so this is a
        // cheap O(1) no-op (one row read + a group-key compare). A *project move*
        // (`issue_move`) does change projectId, and this is what re-groups its
        // `KEY-n` alias (ENG-5 → DSN-5) — so keep it on the common tail rather
        // than making each mutation remember whether it moved the issue.
        self.aliases.reconcile_doc(&self.catalog, doc_id);
        // Coalesced git snapshot (see `new_issue`): keep `git add -A` off the
        // per-edit path; the daemon's checkpoint tick commits the batch.
        self.store.mark_dirty();
        Ok(())
    }

    /// Coalesce all pending durable-store mutations into one git commit
    /// (best-effort, inspectability only). Driven by the daemon's checkpoint
    /// tick and by tests/harness; a no-op when nothing is pending.
    pub fn checkpoint(&self) -> bool {
        self.store.checkpoint()
    }
}
