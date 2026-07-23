//! The product control-surface router (C4.3 / C5 step 5 routing).
//!
//! `IssueRouter` maps the product's issue-family [`control::Request`] onto the
//! [`IssuesWorld`] adapter through a docked [`runtime::Session`]: it resolves
//! refs/projects/labels and chooses the project from the World's `Snapshot`
//! query, mints ids and stamps timestamps (the World is pure), submits the
//! mapped intent, and renders the mapped [`control::Response`] from the World's
//! projection. This is the seam the daemon routes every application request
//! through; membership/transport requests stay on the mechanics/Contact planes.

use runtime::{RequestId, Session, WorldError, WorldIntent, WorldQuery};
use serde::de::DeserializeOwned;

use crate::control::{BoardPos, Request, Response};
use crate::dto::{BoardView, GraphView, IssueView, LabelDto, ProjectDto, Row};
use crate::ids::{DocId, LabelId, ProjectId, SystemUlidSource, UlidSource};

use super::contract::{self, IssueIntent, IssueQuery, NewLabel, Pos, WorkAction};

/// The daemon facts the router needs per request: who is acting and the
/// project-choice inputs. (Membership/standing itself is enforced by the
/// Session's mechanics guard.)
pub struct RouterFacts {
    /// The acting device's canonical string (advisory attribution).
    pub device: String,
    /// The acting actor's canonical string (comment/create authorship).
    pub actor: String,
    /// The environment project hint (the CLI's git-branch key), if any.
    pub project_hint: Option<String>,
    /// The configured default project id, if any.
    pub default_project: Option<String>,
    /// Unix seconds now.
    pub now: u64,
}

/// The decoded catalog snapshot the router resolves against.
struct Snapshot {
    value: serde_json::Value,
}

impl Snapshot {
    fn projects(&self) -> &serde_json::Map<String, serde_json::Value> {
        self.value["catalog"]["projects"]
            .as_object()
            .expect("projects object")
    }
    fn labels(&self) -> &serde_json::Map<String, serde_json::Value> {
        self.value["catalog"]["labels"]
            .as_object()
            .expect("labels object")
    }

    /// Resolve a ref (`KEY-n` alias, `iss_` id/prefix) to a DocId string.
    fn resolve_issue(&self, reff: &str) -> RefOutcome {
        let reff = reff.trim();
        if reff.is_empty() {
            return RefOutcome::None;
        }
        let lower = reff.to_ascii_lowercase();
        if let Some(doc) = self.value["aliases"]["by_alias"][&lower].as_str() {
            return RefOutcome::One(doc.to_string());
        }
        // canonical / doc-id prefix
        if lower.starts_with(DocId::PREFIX) {
            let seqs = self.value["catalog"]["seqs"]
                .as_object()
                .expect("seqs object");
            let mut hits: Vec<String> = seqs
                .keys()
                .filter(|d| d.to_ascii_lowercase().starts_with(&lower))
                .cloned()
                .collect();
            hits.sort();
            hits.dedup();
            return match hits.len() {
                0 => RefOutcome::None,
                1 => RefOutcome::One(hits.remove(0)),
                _ => RefOutcome::Many,
            };
        }
        RefOutcome::None
    }

    /// Resolve a project ref (`prj_` id or case-insensitive KEY).
    fn resolve_project(&self, reff: &str) -> Option<String> {
        let reff = reff.trim();
        if reff.starts_with(ProjectId::PREFIX) && self.projects().contains_key(reff) {
            return Some(reff.to_string());
        }
        let upper = reff.to_ascii_uppercase();
        self.projects()
            .iter()
            .find(|(_, meta)| meta["key"].as_str() == Some(upper.as_str()))
            .map(|(id, _)| id.clone())
    }

    /// Resolve a label ref (`lbl_` id or case-insensitive name).
    fn resolve_label(&self, reff: &str) -> Option<String> {
        let reff = reff.trim();
        if reff.starts_with(LabelId::PREFIX) && self.labels().contains_key(reff) {
            return Some(reff.to_string());
        }
        let lower = reff.to_ascii_lowercase();
        self.labels()
            .iter()
            .find(|(_, meta)| {
                meta["name"]
                    .as_str()
                    .is_some_and(|n| n.eq_ignore_ascii_case(&lower))
            })
            .map(|(id, _)| id.clone())
    }
}

/// The outcome of resolving an issue ref.
enum RefOutcome {
    One(String),
    Many,
    None,
}

/// The router.
pub struct IssueRouter<'a> {
    session: &'a Session,
    identity: &'a runtime::LocalIdentity,
    clock: &'a dyn UlidSource,
}

impl<'a> IssueRouter<'a> {
    pub fn new(
        session: &'a Session,
        identity: &'a runtime::LocalIdentity,
        clock: &'a dyn UlidSource,
    ) -> Self {
        Self {
            session,
            identity,
            clock,
        }
    }

    fn snapshot(&self) -> Snapshot {
        let bytes = self
            .session
            .query(WorldQuery {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: IssueQuery::Snapshot.to_json(),
            })
            .map(|p| p.bytes)
            .unwrap_or_default();
        Snapshot {
            value: serde_json::from_slice(&bytes).unwrap_or(serde_json::json!({
                "catalog": {"projects":{},"labels":{},"seqs":{}},
                "aliases": {"by_alias":{}},
            })),
        }
    }

    fn submit(&self, intent: &IssueIntent) -> Result<super::contract::IssueEffect, WorldError> {
        let action = self.identity.sign_action(
            self.session,
            RequestId::mint(),
            WorldIntent {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: intent.to_json(),
            },
        )?;
        let committed = self.session.submit(action)?;
        Ok(
            super::contract::IssueEffect::from_json(&committed.effect).unwrap_or(
                super::contract::IssueEffect {
                    doc: None,
                    unchanged: false,
                },
            ),
        )
    }

    fn query<T: DeserializeOwned>(&self, query: &IssueQuery) -> Result<T, WorldError> {
        let bytes = self
            .session
            .query(WorldQuery {
                schema: contract::issue_schema(),
                schema_version: contract::ISSUE_SCHEMA_VERSION,
                payload: query.to_json(),
            })?
            .bytes;
        serde_json::from_slice(&bytes).map_err(|_| WorldError::InvalidRequest)
    }

    /// The canonical reff for a DocId (from the current snapshot).
    fn reff_for(&self, snapshot: &Snapshot, doc: &str) -> String {
        snapshot.value["aliases"]["by_alias"]
            .as_object()
            .and_then(|m| {
                m.iter()
                    .find(|(_, v)| v.as_str() == Some(doc))
                    .map(|(k, _)| k.to_uppercase())
            })
            .or_else(|| {
                snapshot.value["aliases"]["canonical"][doc]
                    .as_str()
                    .map(String::from)
            })
            .unwrap_or_else(|| doc.to_string())
    }

    /// Choose a project id from the legacy precedence: explicit → env hint →
    /// default → sole → error.
    fn choose_project(
        &self,
        snapshot: &Snapshot,
        explicit: Option<&str>,
        facts: &RouterFacts,
    ) -> Result<String, Response> {
        if let Some(p) = explicit {
            return snapshot
                .resolve_project(p)
                .ok_or_else(|| Response::not_found(format!("no project matches {p:?}")));
        }
        if let Some(hint) = &facts.project_hint {
            if let Some(id) = snapshot.resolve_project(hint) {
                return Ok(id);
            }
        }
        if let Some(default) = &facts.default_project {
            if let Some(id) = snapshot.resolve_project(default) {
                return Ok(id);
            }
        }
        // Auto-selection skips archived projects: a soft-hidden project must not
        // become the default board just because it is the only live-looking one
        // (CUSTOM-9). Explicit refs above still resolve it.
        let projects = snapshot.projects();
        let live: Vec<&String> = projects
            .iter()
            .filter(|(_, meta)| meta["archived"].as_bool() != Some(true))
            .map(|(id, _)| id)
            .collect();
        if live.len() == 1 {
            return Ok(live[0].clone());
        }
        Err(Response::err(
            "no project chosen and no single default — pass -p <project>",
        ))
    }

    /// Resolve a ref to a DocId or a mapped error response.
    fn resolve(&self, snapshot: &Snapshot, reff: &str) -> Result<String, Response> {
        match snapshot.resolve_issue(reff) {
            RefOutcome::One(doc) => Ok(doc),
            RefOutcome::Many => Err(Response::not_found(format!("{reff:?} is ambiguous"))),
            RefOutcome::None => Err(Response::not_found(format!("no issue matches {reff:?}"))),
        }
    }

    fn map_pos(&self, snapshot: &Snapshot, pos: BoardPos) -> Result<Pos, Response> {
        Ok(match pos {
            BoardPos::Top => Pos::Top,
            BoardPos::Bottom => Pos::Bottom,
            BoardPos::Before { reff } => Pos::Before {
                doc: self.resolve(snapshot, &reff)?,
            },
            BoardPos::After { reff } => Pos::After {
                doc: self.resolve(snapshot, &reff)?,
            },
        })
    }

    fn effect_err(e: WorldError) -> Response {
        match e {
            WorldError::Denied => {
                Response::err("view-only: your membership grants no write access")
            }
            WorldError::Conflict => Response::err("that change conflicts with the current state"),
            WorldError::RequestIdConflict => Response::err("duplicate request"),
            WorldError::InvalidRequest | WorldError::ContractViolation => {
                Response::err("invalid request")
            }
            WorldError::UnsupportedSchema | WorldError::UnsupportedSchemaVersion => {
                Response::err("unsupported request")
            }
            WorldError::LimitExceeded => Response::err("request exceeds a limit"),
            WorldError::AuthorityChanged => Response::err("membership changed — retry"),
            WorldError::StationDormant => Response::err("the space is shutting down"),
            WorldError::Persistence | WorldError::WorldPanicked => Response::err("internal error"),
            WorldError::ResetRequired => Response::err("state reset — re-query"),
            WorldError::WorldStateCorrupt => Response::err(
                "the space's issue catalog is corrupt (missing, duplicated, or mis-bound) — \
                 this store needs operator attention; nothing was changed",
            ),
        }
    }

    /// Whether the router handles this request (the issue family). Membership,
    /// transport, and daemon-local requests are dispatched elsewhere.
    pub fn handles(req: &Request) -> bool {
        matches!(
            req,
            Request::IssueNew { .. }
                | Request::IssueEdit { .. }
                | Request::IssueMove { .. }
                | Request::Assign { .. }
                | Request::Label { .. }
                | Request::Comment { .. }
                | Request::React { .. }
                | Request::IssueDelete { .. }
                | Request::IssueRestore { .. }
                | Request::IssueLink { .. }
                | Request::IssueUnlink { .. }
                | Request::IssueParent { .. }
                | Request::IssueStart { .. }
                | Request::IssueDone { .. }
                | Request::IssueStop { .. }
                | Request::IssueGraph { .. }
                | Request::IssueView { .. }
                | Request::List { .. }
                | Request::Board { .. }
                | Request::History { .. }
                | Request::ProjectNew { .. }
                | Request::ProjectList
                | Request::ProjectEdit { .. }
                | Request::LabelNew { .. }
                | Request::LabelList
                | Request::LabelEdit { .. }
                | Request::LabelDelete { .. }
                | Request::SpaceRename { .. }
                | Request::Activity { .. }
                | Request::RoleList
                | Request::RoleShow { .. }
                | Request::RoleCreate { .. }
                | Request::RoleEdit { .. }
                | Request::RoleDelete { .. }
                | Request::RoleResolve { .. }
                | Request::WorkflowShow { .. }
                | Request::WorkflowValidate { .. }
                | Request::WorkflowSet { .. }
        )
    }

    /// Route one issue-family request. Returns the mapped response and whether
    /// it committed a change (the daemon rings the doorbell / re-announces).
    pub fn route(&self, req: Request, facts: &RouterFacts) -> (Response, bool) {
        match self.route_inner(req, facts) {
            Ok((resp, changed)) => (resp, changed),
            Err(resp) => (resp, false),
        }
    }

    fn route_inner(&self, req: Request, facts: &RouterFacts) -> Result<(Response, bool), Response> {
        let snapshot = self.snapshot();
        match req {
            Request::IssueNew {
                title,
                project,
                project_hint: _,
                assignees,
                priority,
                labels,
                body,
                due,
                estimate,
            } => {
                let project = self.choose_project(&snapshot, project.as_deref(), facts)?;
                let duedate = match due.as_deref() {
                    None | Some("none") => None,
                    Some(text) => Some(parse_due(text).ok_or_else(bad_due)?),
                };
                let resolved_assignees: Vec<String> = assignees.to_vec();
                let mut label_ids = Vec::new();
                let mut new_labels = Vec::new();
                for label in &labels {
                    match snapshot.resolve_label(label) {
                        Some(id) => label_ids.push(id),
                        None => new_labels.push(NewLabel {
                            id: LabelId::mint(self.clock).as_str().to_string(),
                            name: label.clone(),
                            color: "gray".into(),
                        }),
                    }
                }
                let doc = DocId::mint(self.clock).as_str().to_string();
                let effect = self
                    .submit(&IssueIntent::IssueNew {
                        doc: doc.clone(),
                        project,
                        title,
                        priority: priority.unwrap_or_else(|| "none".into()),
                        assignees: resolved_assignees,
                        labels: label_ids,
                        new_labels,
                        body,
                        duedate,
                        estimate,
                        actor: facts.actor.clone(),
                        device: facts.device.clone(),
                        ts: facts.now,
                    })
                    .map_err(Self::effect_err)?;
                let reff = effect
                    .doc
                    .map(|d| self.reff_for(&self.snapshot(), &d))
                    .unwrap_or(doc);
                Ok((Response::Ref { reff }, true))
            }
            Request::IssueEdit {
                reff,
                title,
                status,
                priority,
                description,
                due,
                estimate,
            } => {
                let doc = self.resolve(&snapshot, &reff)?;
                // `none` clears; absent leaves the field untouched — the
                // double-option the intent carries.
                let duedate = match due.as_deref() {
                    None => None,
                    Some("none") => Some(None),
                    Some(text) => Some(Some(parse_due(text).ok_or_else(bad_due)?)),
                };
                let estimate = match estimate.as_deref() {
                    None => None,
                    Some("none") => Some(None),
                    Some(text) => Some(Some(text.parse::<u32>().map_err(|_| {
                        Response::err("estimate must be a whole number of points, or `none`")
                    })?)),
                };
                self.submit(&IssueIntent::IssueEdit {
                    doc: doc.clone(),
                    title,
                    status,
                    priority,
                    description,
                    duedate,
                    estimate,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::IssueMove { reff, project, pos } => {
                let doc = self.resolve(&snapshot, &reff)?;
                let project = match project {
                    Some(p) => Some(
                        snapshot
                            .resolve_project(&p)
                            .ok_or_else(|| Response::not_found(format!("no project {p:?}")))?,
                    ),
                    None => None,
                };
                let pos = match pos {
                    Some(p) => Some(self.map_pos(&snapshot, p)?),
                    None => None,
                };
                self.submit(&IssueIntent::IssueMove {
                    doc: doc.clone(),
                    project,
                    pos,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::Assign { reff, who, add } => {
                let doc = self.resolve(&snapshot, &reff)?;
                self.submit(&IssueIntent::Assign {
                    doc: doc.clone(),
                    who,
                    add,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::Label { reff, add, remove } => {
                let doc = self.resolve(&snapshot, &reff)?;
                let mut add_ids = Vec::new();
                let mut new_labels = Vec::new();
                for label in &add {
                    match snapshot.resolve_label(label) {
                        Some(id) => add_ids.push(id),
                        None => new_labels.push(NewLabel {
                            id: LabelId::mint(self.clock).as_str().to_string(),
                            name: label.clone(),
                            color: "gray".into(),
                        }),
                    }
                }
                let remove_ids: Vec<String> = remove
                    .iter()
                    .filter_map(|l| snapshot.resolve_label(l))
                    .collect();
                self.submit(&IssueIntent::Label {
                    doc: doc.clone(),
                    add: add_ids,
                    new_labels,
                    remove: remove_ids,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::Comment {
                reff,
                body,
                reply_to,
            } => {
                let doc = self.resolve(&snapshot, &reff)?;
                self.submit(&IssueIntent::Comment {
                    doc: doc.clone(),
                    body,
                    // The adapter mints the id (lowercase — it doubles as a
                    // Body path segment); the World re-validates it.
                    id: Some(crate::ids::mint_comment_id(self.clock)),
                    parent: reply_to,
                    actor: facts.actor.clone(),
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::React {
                reff,
                comment,
                emoji,
                on,
            } => {
                let doc = self.resolve(&snapshot, &reff)?;
                self.submit(&IssueIntent::React {
                    doc: doc.clone(),
                    comment,
                    emoji,
                    actor: facts.actor.clone(),
                    on,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::IssueDelete { reff } => {
                let doc = self.resolve(&snapshot, &reff)?;
                self.submit(&IssueIntent::SetTombstone {
                    doc: doc.clone(),
                    on: true,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!("deleted {}", self.reff_for(&snapshot, &doc))),
                    },
                    true,
                ))
            }
            Request::IssueRestore { reff } => {
                let doc = self.resolve(&snapshot, &reff)?;
                self.submit(&IssueIntent::SetTombstone {
                    doc: doc.clone(),
                    on: false,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!("restored {}", self.reff_for(&snapshot, &doc))),
                    },
                    true,
                ))
            }
            Request::IssueLink { reff, kind, target } => {
                self.link(&snapshot, reff, kind, target, true, facts)
            }
            Request::IssueUnlink { reff, kind, target } => {
                self.link(&snapshot, reff, kind, target, false, facts)
            }
            Request::IssueParent { reff, parent } => {
                let doc = self.resolve(&snapshot, &reff)?;
                let parent = match parent {
                    Some(p) => Some(self.resolve(&snapshot, &p)?),
                    None => None,
                };
                self.submit(&IssueIntent::Parent {
                    doc: doc.clone(),
                    parent,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((self.ref_response(&doc), true))
            }
            Request::IssueStart { reff } => self.work(&snapshot, reff, WorkAction::Start, facts),
            Request::IssueDone { reff } => self.work(&snapshot, reff, WorkAction::Done, facts),
            Request::IssueStop { reff } => self.work(&snapshot, reff, WorkAction::Stop, facts),
            Request::IssueView { reff } => {
                let doc = self.resolve(&snapshot, &reff)?;
                let view: IssueView = self
                    .query(&IssueQuery::View {
                        doc,
                        me: Some(facts.actor.clone()),
                    })
                    .map_err(Self::effect_err)?;
                Ok((Response::Issue(Box::new(view)), false))
            }
            Request::List { project, filter } => {
                let project = match project {
                    Some(p) => Some(
                        snapshot
                            .resolve_project(&p)
                            .ok_or_else(|| Response::not_found(format!("no project {p:?}")))?,
                    ),
                    None => None,
                };
                let rows: Vec<Row> = self
                    .query(&IssueQuery::List {
                        project,
                        label: filter.label.and_then(|l| snapshot.resolve_label(&l)),
                        status: filter.status,
                        mine: filter.mine.then(|| facts.actor.clone()),
                        all: filter.all,
                        me: Some(facts.actor.clone()),
                    })
                    .map_err(Self::effect_err)?;
                Ok((Response::List { rows }, false))
            }
            Request::Board {
                project,
                project_hint: _,
            } => {
                let project = self.choose_project(&snapshot, project.as_deref(), facts)?;
                let view: BoardView = self
                    .query(&IssueQuery::Board {
                        project,
                        me: Some(facts.actor.clone()),
                    })
                    .map_err(Self::effect_err)?;
                Ok((Response::Board(Box::new(view)), false))
            }
            Request::IssueGraph { reff } => {
                let doc = self.resolve(&snapshot, &reff)?;
                let view: GraphView = self
                    .query(&IssueQuery::Graph {
                        doc,
                        me: Some(facts.actor.clone()),
                    })
                    .map_err(Self::effect_err)?;
                Ok((Response::Graph(Box::new(view)), false))
            }
            Request::History { reff } => {
                let doc = self.resolve(&snapshot, &reff)?;
                #[derive(serde::Deserialize)]
                struct Hist {
                    events: Vec<crate::dto::ActivityEvent>,
                    last: u64,
                }
                let hist: Hist = self
                    .query(&IssueQuery::History { doc })
                    .map_err(Self::effect_err)?;
                Ok((
                    Response::Activity {
                        events: hist.events,
                        last: hist.last,
                    },
                    false,
                ))
            }
            Request::Activity { since } => {
                #[derive(serde::Deserialize)]
                struct Feed {
                    events: Vec<crate::dto::ActivityEvent>,
                    last: u64,
                }
                let feed: Feed = self
                    .query(&IssueQuery::Activity { since })
                    .map_err(Self::effect_err)?;
                Ok((
                    Response::Activity {
                        events: feed.events,
                        last: feed.last,
                    },
                    false,
                ))
            }
            Request::ProjectNew { name, key, color } => {
                let id = ProjectId::mint(self.clock).as_str().to_string();
                self.submit(&IssueIntent::ProjectNew {
                    id,
                    name,
                    key: key.clone(),
                    // Optional on the wire, resolved to the birth default here — the
                    // same shape `LabelNew` uses, so an omitted colour still lands a
                    // sensible one rather than an empty string.
                    color: color.unwrap_or_else(|| "blue".into()),
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ref {
                        reff: key.trim().to_ascii_uppercase(),
                    },
                    true,
                ))
            }
            Request::ProjectList => {
                let projects: Vec<ProjectDto> = self
                    .query(&IssueQuery::Projects)
                    .map_err(Self::effect_err)?;
                Ok((Response::Projects { projects }, false))
            }
            Request::ProjectEdit {
                project,
                name,
                color,
                description,
                lead,
                start,
                target,
                archived,
            } => {
                let id = snapshot.resolve_project(&project).ok_or_else(|| {
                    Response::not_found(format!("no project matches {project:?}"))
                })?;
                // `none`/`""` clears; absent leaves it untouched — the same
                // double-option the issue due-date carries.
                let parse_date = |v: Option<String>| -> Result<Option<Option<u64>>, Response> {
                    match v.as_deref() {
                        None => Ok(None),
                        Some("none") | Some("") => Ok(Some(None)),
                        Some(text) => Ok(Some(Some(parse_due(text).ok_or_else(bad_due)?))),
                    }
                };
                let lead = lead.map(|l| {
                    let l = l.trim();
                    if l.eq_ignore_ascii_case("none") {
                        String::new()
                    } else {
                        l.to_string()
                    }
                });
                self.submit(&IssueIntent::ProjectEdit {
                    id,
                    name,
                    color,
                    description,
                    lead,
                    start_date: parse_date(start)?,
                    target_date: parse_date(target)?,
                    archived,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((Response::Ref { reff: project }, true))
            }
            Request::LabelNew { name, color } => {
                let id = LabelId::mint(self.clock).as_str().to_string();
                self.submit(&IssueIntent::LabelNew {
                    id,
                    name: name.clone(),
                    color: color.unwrap_or_else(|| "gray".into()),
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((Response::Ref { reff: name }, true))
            }
            Request::LabelList => {
                let labels: Vec<LabelDto> =
                    self.query(&IssueQuery::Labels).map_err(Self::effect_err)?;
                Ok((Response::Labels { labels }, false))
            }
            Request::LabelEdit { label, name, color } => {
                let id = snapshot
                    .resolve_label(&label)
                    .ok_or_else(|| Response::not_found(format!("no label matches {label:?}")))?;
                self.submit(&IssueIntent::LabelEdit {
                    id,
                    name,
                    color,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((Response::Ref { reff: label }, true))
            }
            Request::LabelDelete { label } => {
                let id = snapshot
                    .resolve_label(&label)
                    .ok_or_else(|| Response::not_found(format!("no label matches {label:?}")))?;
                self.submit(&IssueIntent::LabelDelete {
                    id,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((Response::Ref { reff: label }, true))
            }
            Request::SpaceRename { name } => {
                self.submit(&IssueIntent::SpaceRename {
                    name: name.clone(),
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((Response::Ref { reff: name }, true))
            }
            Request::RoleList => {
                let roles: serde_json::Value =
                    self.query(&IssueQuery::Roles).map_err(Self::effect_err)?;
                Ok((
                    Response::Text {
                        text: serde_json::to_string_pretty(&roles).unwrap_or_default(),
                    },
                    false,
                ))
            }
            Request::RoleShow { role } => {
                let view: serde_json::Value = self
                    .query(&IssueQuery::RoleShow { role })
                    .map_err(Self::effect_err)?;
                Ok((
                    Response::Text {
                        text: serde_json::to_string_pretty(&view).unwrap_or_default(),
                    },
                    false,
                ))
            }
            Request::RoleCreate {
                name,
                description,
                project,
                capabilities,
            } => {
                // The adapter mints the id and resolves the project selector;
                // the World re-validates everything.
                let scope_project = match project {
                    None => None,
                    Some(sel) => Some(
                        snapshot
                            .resolve_project(&sel)
                            .ok_or_else(|| Response::not_found("no such project"))?,
                    ),
                };
                let role_id = format!(
                    "role_{}",
                    crate::ids::ProjectId::mint(self.clock)
                        .as_str()
                        .trim_start_matches("prj_")
                );
                self.submit(&IssueIntent::RoleCreate {
                    role_id: role_id.clone(),
                    scope_project,
                    name,
                    description: description.unwrap_or_default(),
                    capabilities,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!("created role {role_id}")),
                    },
                    true,
                ))
            }
            Request::RoleEdit {
                role,
                expect_revision,
                name,
                description,
                capabilities,
            } => {
                self.submit(&IssueIntent::RoleEdit {
                    role_id: role.clone(),
                    expected_revision: expect_revision,
                    name,
                    description,
                    capabilities,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!("edited role {role} (a new revision is the head)")),
                    },
                    true,
                ))
            }
            Request::RoleDelete {
                role,
                expect_revision,
            } => {
                self.submit(&IssueIntent::RoleDelete {
                    role_id: role.clone(),
                    expected_revision: expect_revision,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!(
                            "tombstoned role {role} — existing assignments keep their \
                             originally granted expansion until explicitly revoked"
                        )),
                    },
                    true,
                ))
            }
            Request::RoleResolve {
                role,
                expect_heads,
                body_json,
            } => {
                self.submit(&IssueIntent::RoleResolve {
                    role_id: role.clone(),
                    expected_heads: expect_heads,
                    body_json,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some(format!("resolved role {role} to one head")),
                    },
                    true,
                ))
            }
            Request::WorkflowShow { project } => {
                let project = snapshot
                    .resolve_project(&project)
                    .ok_or_else(|| Response::not_found("no such project"))?;
                let view: serde_json::Value = self
                    .query(&IssueQuery::Workflow { project })
                    .map_err(Self::effect_err)?;
                Ok((
                    Response::Text {
                        text: serde_json::to_string_pretty(&view).unwrap_or_default(),
                    },
                    false,
                ))
            }
            Request::WorkflowValidate { body_json } => {
                // Pure local validation — nothing is committed.
                match serde_json::from_str::<crate::world::workflow::WorkflowBody>(&body_json) {
                    Ok(body) => match body.validate() {
                        Ok(()) => Ok((
                            Response::Ok {
                                message: Some("the workflow body is valid".into()),
                            },
                            false,
                        )),
                        Err(why) => Err(Response::err(format!("invalid workflow: {why}"))),
                    },
                    Err(e) => Err(Response::err(format!("workflow body does not decode: {e}"))),
                }
            }
            Request::WorkflowSet {
                project,
                expect_heads,
                body_json,
            } => {
                let project = snapshot
                    .resolve_project(&project)
                    .ok_or_else(|| Response::not_found("no such project"))?;
                self.submit(&IssueIntent::WorkflowReplace {
                    project_id: project.clone(),
                    expected_heads: expect_heads,
                    body_json,
                    device: facts.device.clone(),
                    ts: facts.now,
                })
                .map_err(Self::effect_err)?;
                Ok((
                    Response::Ok {
                        message: Some("workflow replaced (a new revision is the head)".into()),
                    },
                    true,
                ))
            }
            // Ownership is fixed by the production classifier; the agreement
            // gate (control_classification) proves every Session-owned request
            // has an arm above, so a foreign request here is a caller bug,
            // never a servable state.
            other => unreachable!("misrouted issues-world request: {other:?}"),
        }
    }

    fn ref_response(&self, doc: &str) -> Response {
        Response::Ref {
            reff: self.reff_for(&self.snapshot(), doc),
        }
    }

    fn work(
        &self,
        snapshot: &Snapshot,
        reff: String,
        action: WorkAction,
        facts: &RouterFacts,
    ) -> Result<(Response, bool), Response> {
        let doc = self.resolve(snapshot, &reff)?;
        let effect = self
            .submit(&IssueIntent::WorkState {
                doc: doc.clone(),
                action,
                actor: facts.actor.clone(),
                device: facts.device.clone(),
                ts: facts.now,
            })
            .map_err(Self::effect_err)?;
        let view: IssueView = self
            .query(&IssueQuery::View {
                doc,
                me: Some(facts.actor.clone()),
            })
            .map_err(Self::effect_err)?;
        Ok((Response::Issue(Box::new(view)), !effect.unchanged))
    }

    fn link(
        &self,
        snapshot: &Snapshot,
        reff: String,
        kind: String,
        target: String,
        add: bool,
        facts: &RouterFacts,
    ) -> Result<(Response, bool), Response> {
        let doc = self.resolve(snapshot, &reff)?;
        let target = self.resolve(snapshot, &target)?;
        self.submit(&IssueIntent::Link {
            doc: doc.clone(),
            kind,
            target,
            add,
            device: facts.device.clone(),
            ts: facts.now,
        })
        .map_err(Self::effect_err)?;
        Ok((self.ref_response(&doc), true))
    }
}

/// A shared clock for the router in production.
pub fn system_clock() -> SystemUlidSource {
    SystemUlidSource
}

fn bad_due() -> Response {
    Response::err("due must be unix seconds, YYYY-MM-DD, or `none`")
}

/// Parse a due-date argument: raw unix seconds, or `YYYY-MM-DD` as UTC
/// midnight. Timezone policy is deliberately the simplest honest one — a due
/// *date* names a day, and UTC midnight is the one reading every replica
/// derives identically; clients localize for display.
fn parse_due(text: &str) -> Option<u64> {
    let text = text.trim();
    if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) {
        return text.parse().ok();
    }
    let mut parts = text.splitn(3, '-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: u32 = parts.next()?.parse().ok()?;
    let d: u32 = parts.next()?.parse().ok()?;
    if !(1970..=9999).contains(&y) || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days-from-civil: civil date -> days since 1970-01-01.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let mp = ((m + 9) % 12) as u64;
    let doy = (153 * mp + 2) / 5 + (d as u64) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    u64::try_from(days).ok().map(|d| d * 86_400)
}

#[cfg(test)]
mod tests {
    use super::parse_due;

    #[test]
    fn due_dates_parse_as_utc_midnight_and_unix_passthrough() {
        assert_eq!(parse_due("1970-01-01"), Some(0));
        // A known epoch day: 2026-07-22 = 20 656 days after the epoch.
        assert_eq!(parse_due("2026-07-22"), Some(20_656 * 86_400));
        assert_eq!(parse_due("1753142400"), Some(1_753_142_400));
        assert_eq!(parse_due("2026-13-01"), None, "month out of range");
        assert_eq!(parse_due("07-22"), None, "not a date");
        assert_eq!(parse_due(""), None);
    }
}
