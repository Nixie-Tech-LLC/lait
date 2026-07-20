//! Projections (reads) and the activity feed.

use super::*;

const ACTIVITY_RING: usize = 1000;

impl Replica {
    // ---- projections (reads) ----

    pub(super) fn is_done_status(&self, status: &str) -> bool {
        self.catalog
            .workflow_state(status)
            .map(|w| w.category == StatusCategory::Done)
            .unwrap_or(false)
    }

    /// The first workflow state in a category — where the work-state verbs land
    /// (tracks whatever column set this space's workflow has).
    pub(super) fn first_state_in(&self, cat: StatusCategory) -> Option<crate::dto::WorkflowState> {
        self.catalog
            .workflow()
            .into_iter()
            .find(|w| w.category == cat)
    }

    /// Viewer-aware assignee summary: "you", "you +2", "ab", or "".
    /// Actor-keyed: any of an actor's devices renders as "you".
    fn assignee_summary(&self, assignees: &[ActorId]) -> String {
        if assignees.is_empty() {
            return String::new();
        }
        let mine = self.my_actor().is_some_and(|a| assignees.contains(&a));
        let head = if mine {
            "you".to_string()
        } else {
            assignees[0].short()
        };
        if assignees.len() > 1 {
            format!("{head} +{}", assignees.len() - 1)
        } else {
            head
        }
    }

    pub(super) fn project_row(&self, row: &RowMeta) -> Row {
        Row {
            reff: self.aliases.canonical_for(&row.doc_id),
            doc_id: row.doc_id.clone(),
            project_id: row.project_id.clone(),
            key_alias: self.aliases.alias_for(&row.doc_id),
            title: row.title.clone(),
            status: row.status.clone(),
            priority: row.priority,
            assignee_summary: self.assignee_summary(&row.assignees),
            assignees: row.assignees.clone(),
            tombstone: row.tombstone,
            provisional: row.provisional,
        }
    }

    pub(super) fn list(&self, project: Option<String>, filter: Filter) -> Result<Response> {
        let project_filter = match &project {
            Some(p) => match self.resolve_project(p) {
                Some(pr) => Some(pr.id),
                None => return Ok(Response::not_found(format!("no project matches '{p}'"))),
            },
            None => None,
        };
        let label_filter = match &filter.label {
            Some(l) => match self.resolve_label(l) {
                Some(id) => Some(id),
                None => return Ok(Response::not_found(format!("no label matches '{l}'"))),
            },
            None => None,
        };
        let mut rows: Vec<Row> = self
            .catalog
            .all_rows()
            .into_iter()
            .filter(|r| {
                project_filter
                    .as_ref()
                    .map(|p| &r.project_id == p)
                    .unwrap_or(true)
            })
            .filter(|r| filter.all || !index::is_hidden_by_default(&self.catalog, r))
            .filter(|r| {
                filter
                    .status
                    .as_ref()
                    .map(|s| &r.status == s)
                    .unwrap_or(true)
            })
            .filter(|r| !filter.mine || self.my_actor().is_some_and(|a| r.assignees.contains(&a)))
            .map(|r| self.project_row(&r))
            .collect();
        // label filter requires the issue doc's labels (not cached in the row);
        // apply it against the locally loaded documents.
        if let Some(lid) = &label_filter {
            rows.retain(|row| {
                self.issues
                    .get(&row.doc_id)
                    .map(|i| i.labels().contains(lid))
                    .unwrap_or(false)
            });
        }
        // stable order: priority desc, then created (ULID) asc via doc_id.
        rows.sort_by(|a, b| b.priority.cmp(&a.priority).then(a.doc_id.cmp(&b.doc_id)));
        Ok(Response::List { rows })
    }

    /// Build the board, deduplicating its ordering projection:
    /// rows whose `projectId == P`, in `boards[P]` order, deduplicated,
    /// belonging-but-unlisted appended, listed-but-not-belonging ignored; the
    /// The done column uses append order sorted by descending wall-clock time.
    pub(super) fn board(
        &self,
        project: Option<String>,
        project_hint: Option<String>,
    ) -> Result<Response> {
        let project_dto = match self.choose_project(project.as_deref(), project_hint.as_deref()) {
            Ok(pr) => pr,
            Err(resp) => return Ok(resp),
        };
        let pid = &project_dto.id;
        let rows_by_doc: HashMap<String, RowMeta> = self
            .catalog
            .all_rows()
            .into_iter()
            .filter(|r| &r.project_id == pid && !r.tombstone)
            .map(|r| (r.doc_id.as_str().to_string(), r))
            .collect();
        let ordered = self.catalog.board_order(pid); // non-done, ordered
        let workflow = self.catalog.workflow();

        let mut columns = Vec::new();
        for state in &workflow {
            let mut rows: Vec<Row> = Vec::new();
            let mut seen = std::collections::HashSet::new();
            if state.category == StatusCategory::Done {
                // Append matching rows in this done state, ordered
                // by wall-clock desc (they've left the board movable list).
                let mut done: Vec<&RowMeta> = rows_by_doc
                    .values()
                    .filter(|r| r.status == state.id)
                    .collect();
                done.sort_by(|a, b| {
                    b.created_at
                        .cmp(&a.created_at)
                        .then(b.doc_id.cmp(&a.doc_id))
                });
                for r in done {
                    if seen.insert(r.doc_id.as_str().to_string()) {
                        rows.push(self.project_row(r));
                    }
                }
            } else {
                // board-ordered docs whose status maps to this column.
                for doc in &ordered {
                    if let Some(r) = rows_by_doc.get(doc.as_str()) {
                        if r.status == state.id && seen.insert(doc.as_str().to_string()) {
                            rows.push(self.project_row(r));
                        }
                    }
                }
                // belonging-but-unlisted (not in board order) appended.
                let mut unlisted: Vec<&RowMeta> = rows_by_doc
                    .values()
                    .filter(|r| r.status == state.id && !seen.contains(r.doc_id.as_str()))
                    .collect();
                unlisted.sort_by(|a, b| a.doc_id.cmp(&b.doc_id));
                for r in unlisted {
                    if seen.insert(r.doc_id.as_str().to_string()) {
                        rows.push(self.project_row(r));
                    }
                }
            }
            columns.push(BoardColumn {
                state: state.clone(),
                rows,
            });
        }
        Ok(Response::Board(Box::new(BoardView {
            schema_version: SCHEMA_VERSION,
            project: project_dto,
            columns,
        })))
    }

    pub(super) fn issue_view(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        // Clone viewer context up front so it doesn't conflict with the issue
        // borrow below.
        let ws = self.workspace_id.clone();
        let canonical = self.aliases.canonical_for(&doc_id);
        let row = self.catalog.row(&doc_id);
        let project = row
            .as_ref()
            .and_then(|r| self.catalog.project(&r.project_id));
        let key_alias = self.aliases.alias_for(&doc_id);
        let label_names: HashMap<String, String> = self
            .catalog
            .labels_list()
            .into_iter()
            .map(|l| (l.id.as_str().to_string(), l.name))
            .collect();

        let issue = match self.issue(&doc_id)? {
            Some(i) => i,
            None => {
                // Provisional: only the catalog row is known until sync completes.
                let row = row.ok_or_else(|| anyhow!("no such issue"))?;
                return Ok(Response::Issue(Box::new(IssueView {
                    schema_version: SCHEMA_VERSION,
                    reff: canonical.clone(),
                    doc_id,
                    workspace_id: ws.clone(),
                    project_id: row.project_id,
                    project_key: project.map(|p| p.key),
                    key_alias,
                    title: row.title,
                    description: String::new(),
                    status: row.status,
                    priority: row.priority,
                    assignees: row.assignees,
                    labels: vec![],
                    label_names: vec![],
                    comments: vec![],
                    // Provisional row: the body (hence the authoring actor) hasn't
                    // synced yet.
                    created_by: ActorId::from_incept_hash(&"0".repeat(64)),
                    created_at: row.created_at,
                    provisional: true,
                    corrupt_records: Vec::new(),
                })));
            }
        };
        let labels = issue.labels();
        let label_display = labels
            .iter()
            .map(|l| {
                label_names
                    .get(l.as_str())
                    .cloned()
                    .unwrap_or_else(|| l.short(4))
            })
            .collect();
        // The projection boundary: corruption leaves the typed path exactly
        // here, once, and travels to the caller in the sidecar instead of
        // hiding inside `comments`.
        let (comments, corrupt_records) = crate::dto::partition(issue.comments());
        let view = IssueView {
            schema_version: SCHEMA_VERSION,
            reff: canonical.clone(),
            doc_id: doc_id.clone(),
            workspace_id: issue.workspace_id().unwrap_or_else(|| ws.clone()),
            project_id: issue
                .project_id()
                .unwrap_or_else(|| row.as_ref().unwrap().project_id.clone()),
            project_key: project.map(|p| p.key),
            key_alias,
            title: issue.title(),
            description: issue.description(),
            status: issue.status(),
            priority: issue.priority(),
            assignees: issue.assignees(),
            labels,
            label_names: label_display,
            comments,
            created_by: issue
                .created_by()
                .unwrap_or_else(|| ActorId::from_incept_hash(&"0".repeat(64))),
            created_at: issue.created_at(),
            provisional: false,
            corrupt_records,
        };
        Ok(Response::Issue(Box::new(view)))
    }

    /// The issue's history, derived from the **oplog on disk**:
    /// durable across daemon restarts, field-level, attributed (advisory) for
    /// remote changes, with DAG-derived collision flags. The per-session
    /// activity ring stays what it is — the workspace feed's batch cursor.
    pub(super) fn history(&mut self, reff: String) -> Result<Response> {
        let doc_id = match self.resolve_issue(&reff) {
            Ok(id) => id,
            Err(resp) => return Ok(resp),
        };
        let canonical = self.aliases.canonical_for(&doc_id);
        let issue = self
            .issue(&doc_id)?
            .ok_or_else(|| anyhow!("issue body not present"))?;
        let events: Vec<ActivityEvent> = history::issue_history(issue)
            .into_iter()
            .enumerate()
            .map(|(i, ch)| ActivityEvent {
                seq: (i + 1) as u64,
                doc_id: Some(doc_id.clone()),
                reff: canonical.clone(),
                kind: ch.kind.unwrap_or_else(|| "change".into()),
                changes: ch.changes,
                actor: ch.actor,
                actor_nick: String::new(),
                text: ch
                    .comments
                    .first()
                    .map(|c| c.body.clone())
                    .unwrap_or_default(),
                ts: ch.ts,
                collision: ch.collision,
            })
            .collect();
        let last = events.last().map(|e| e.seq).unwrap_or(0);
        Ok(Response::Activity { events, last })
    }

    pub(super) fn project_list(&self) -> Response {
        Response::Projects {
            projects: self.catalog.projects_list(),
        }
    }
    pub(super) fn label_list(&self) -> Response {
        let labels: Vec<LabelDto> = self.catalog.labels_list();
        Response::Labels { labels }
    }

    // ---- activity feed ----

    pub(super) fn push_activity(
        &mut self,
        doc_id: Option<&DocId>,
        reff: &str,
        kind: &str,
        changes: Vec<FieldChange>,
        text: &str,
    ) {
        self.push_activity_from(ActivityEvent {
            seq: 0,
            doc_id: doc_id.cloned(),
            reff: reff.to_string(),
            kind: kind.to_string(),
            changes,
            actor: Some(self.me.clone()),
            actor_nick: self.my_nick.clone(),
            text: text.to_string(),
            ts: self.now_secs(),
            collision: false,
        });
    }

    /// Ring-append a fully-built event (remote imports carry their own actor
    /// and collision flag); `seq` is stamped here.
    pub(super) fn push_activity_from(&mut self, mut event: ActivityEvent) {
        self.activity_seq += 1;
        event.seq = self.activity_seq;
        self.activity.push_back(event);
        while self.activity.len() > ACTIVITY_RING {
            self.activity.pop_front();
        }
    }

    pub(super) fn activity_response(&self, since: u64) -> Response {
        let events: Vec<ActivityEvent> = self
            .activity
            .iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect();
        let last = self.activity.back().map(|e| e.seq).unwrap_or(since);
        Response::Activity { events, last }
    }

    /// The current activity high-water (for doorbell `activity_advanced` clients).
    pub fn activity_high_water(&self) -> u64 {
        self.activity_seq
    }
}
