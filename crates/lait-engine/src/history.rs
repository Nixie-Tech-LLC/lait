//! Derived history (LAIT-DATA-CONTRACT §5): the activity/history feed read
//! **from the oplog on disk**, not from a per-session ring. Every change in an
//! issue doc's causal DAG carries a timestamp and an [`OpMeta`] commit message
//! (post-contract writes), so `lait history` survives daemon restarts and
//! attributes remote changes — the message travels with the ops.
//!
//! Legacy changes (written before the contract) surface honestly: ts 0, no
//! kind, no actor, possibly many fields fused into one change.
//!
//! Collision detection is the DAG fact, not a heuristic: a change whose deps
//! differ from the walk's running head-set sits on a concurrent branch
//! (SCHEMA A§9's LWW collision note — the compensating control for LWW
//! `title`/`status` being allowed to drop a concurrent write).

use std::collections::{HashMap, HashSet};

use loro::{Container, Frontiers, LoroDoc, ID};

use crate::dto::{CommentDto, FieldChange};
use crate::ids::UserId;

use crate::issue::IssueDoc;
use crate::loro_ext as lx;
use crate::op::OpMeta;

/// One oplog change of an issue doc, projected for the history feed.
#[derive(Debug, Clone)]
pub struct DocChange {
    /// Request kind from the commit message (`None` for legacy changes).
    pub kind: Option<String>,
    /// Advisory actor claim from the commit message (non-goal 6).
    pub actor: Option<UserId>,
    /// Unix seconds (0 on legacy changes written before `record_timestamp`).
    pub ts: u64,
    /// True when this change was made concurrently with another branch.
    pub collision: bool,
    pub changes: Vec<FieldChange>,
    /// Comments introduced by this change (bodies for the feed's text line).
    pub comments: Vec<CommentDto>,
}

/// What an import brought in, derived from `diff(before, after)` — positional
/// and CRDT-correct, unlike index arithmetic over a merged list (the
/// `skip(prior_comments)` bug this replaces: a concurrent comment merging
/// mid-list both duplicated an old notification and dropped the new one).
#[derive(Debug, Clone, Default)]
pub struct ImportDelta {
    /// Field transitions (to-values; `from` is the pre-import state the caller
    /// captured if it needs one).
    pub fields: Vec<FieldChange>,
    /// Exactly the comments that are new to this replica, wherever they merged.
    pub new_comments: Vec<CommentDto>,
    pub assignee_added: Vec<UserId>,
    pub assignee_removed: Vec<UserId>,
    /// DAG concurrency: the import created (or extended) a concurrent branch.
    pub collision: bool,
    /// Distinct advisory actors of the incoming changes (commit messages).
    pub actors: Vec<UserId>,
    /// Distinct request kinds of the incoming changes.
    pub kinds: Vec<String>,
}

/// Opaque pre-import capture (the engine's `loro::*` types never leave the module).
pub struct ImportMark {
    frontiers: Frontiers,
    vv: loro::VersionVector,
}

impl IssueDoc {
    /// Capture the pre-import state for [`import_delta`].
    pub fn import_mark(&self) -> ImportMark {
        ImportMark {
            frontiers: self.raw().oplog_frontiers(),
            vv: self.raw().oplog_vv(),
        }
    }
}

/// The full, durable history of one issue doc, oldest first.
pub fn issue_history(issue: &IssueDoc) -> Vec<DocChange> {
    let doc = issue.raw();
    let frontiers = doc.oplog_frontiers();
    if frontiers.is_empty() {
        return Vec::new();
    }
    let mut metas = Vec::new();
    let _ = doc.travel_change_ancestors(&frontiers.iter().collect::<Vec<_>>(), &mut |c| {
        metas.push((
            c.id,
            c.lamport,
            c.timestamp,
            c.message.clone(),
            c.deps.clone(),
            c.len,
        ));
        std::ops::ControlFlow::Continue(())
    });
    // Deterministic replay order: ascending (lamport, peer) — the same total
    // order the move-op literature keys convergence on.
    metas.sort_by_key(|m| (m.1, m.0.peer));

    let mut out = Vec::new();
    let mut heads: HashSet<ID> = HashSet::new();
    let mut last_seen: HashMap<String, String> = HashMap::new();
    for (id, _lamport, ts, message, deps, len) in metas {
        let end = ID::new(id.peer, id.counter + len as i32 - 1);
        let deps_set: HashSet<ID> = deps.iter().collect();
        let collision = !heads.is_empty() && deps_set != heads;
        for d in &deps_set {
            heads.remove(d);
        }
        heads.insert(end);

        let (mut fields, comments, adds, removes) = extract(doc, &deps, &Frontiers::from(end));
        for f in &mut fields {
            f.from = last_seen.get(&f.field).cloned();
            if let Some(to) = &f.to {
                last_seen.insert(f.field.clone(), to.clone());
            }
        }
        fields.extend(set_changes(&adds, &removes));
        let meta = OpMeta::parse(message.as_deref());
        let actor = meta.actor_id();
        out.push(DocChange {
            kind: meta.request,
            actor,
            ts: ts.max(0) as u64,
            collision,
            changes: fields,
            comments,
        });
    }
    out
}

/// Derive what an import changed: run after a successful `import`, against the
/// [`ImportMark`] captured before it.
pub fn import_delta(issue: &IssueDoc, mark: &ImportMark) -> ImportDelta {
    let doc = issue.raw();
    let after = doc.oplog_frontiers();
    if after == mark.frontiers {
        return ImportDelta::default();
    }
    // Two-plus heads after import = the incoming ops were concurrent with a
    // local branch (a fast-forward import keeps a single head — verified).
    let collision = after.len() > 1;
    let (fields, new_comments, assignee_added, assignee_removed) =
        extract(doc, &mark.frontiers, &after);

    // Attribution of the incoming changes rides in their commit messages.
    let mut actors = Vec::new();
    let mut kinds = Vec::new();
    let _ = doc.travel_change_ancestors(&after.iter().collect::<Vec<_>>(), &mut |c| {
        let end = ID::new(c.id.peer, c.id.counter + c.len as i32 - 1);
        if !mark.vv.includes_id(end) {
            let meta = OpMeta::parse(c.message.as_deref());
            if let Some(a) = meta.actor_id() {
                if !actors.contains(&a) {
                    actors.push(a);
                }
            }
            if let Some(k) = meta.request {
                if !kinds.contains(&k) {
                    kinds.push(k);
                }
            }
        }
        std::ops::ControlFlow::Continue(())
    });

    let mut fields = fields;
    fields.extend(set_changes(&assignee_added, &assignee_removed));
    ImportDelta {
        fields,
        new_comments,
        assignee_added,
        assignee_removed,
        collision,
        actors,
        kinds,
    }
}

/// Render assignee set membership changes as field transitions.
fn set_changes(adds: &[UserId], removes: &[UserId]) -> Vec<FieldChange> {
    let mut out = Vec::new();
    for u in adds {
        out.push(FieldChange {
            field: "assignees".into(),
            from: None,
            to: Some(u.short()),
        });
    }
    for u in removes {
        out.push(FieldChange {
            field: "assignees".into(),
            from: Some(u.short()),
            to: None,
        });
    }
    out
}

/// Root-map keys that are identity, not activity — creation constants whose
/// presence in a diff is noise.
const IDENTITY_KEYS: [&str; 4] = ["id", "workspaceId", "createdBy", "createdAt"];

type Extracted = (Vec<FieldChange>, Vec<CommentDto>, Vec<UserId>, Vec<UserId>);

/// Map a `diff(from, to)` batch onto issue-schema semantics: root-map LWW
/// fields, the assignees/labels present-key sets, new comments, description
/// edits. Container identity is resolved via its path from the root, so the
/// extraction survives any container-id representation.
fn extract(doc: &LoroDoc, from: &Frontiers, to: &Frontiers) -> Extracted {
    let mut fields = Vec::new();
    let mut comments = Vec::new();
    let mut assignee_added = Vec::new();
    let mut assignee_removed = Vec::new();
    let Ok(batch) = doc.diff(from, to) else {
        return (fields, comments, assignee_added, assignee_removed);
    };
    for (cid, diff) in batch.iter() {
        let field = container_field(doc, cid);
        match (field.as_deref(), diff) {
            (Some("issue"), loro::event::Diff::Map(md)) => {
                for (k, v) in md.updated.iter() {
                    let key = k.to_string();
                    if IDENTITY_KEYS.contains(&key.as_str()) {
                        continue;
                    }
                    let to = v
                        .as_ref()
                        .and_then(|x| x.as_value())
                        .and_then(|val| val.as_string().map(|s| s.to_string()));
                    fields.push(FieldChange {
                        field: key,
                        from: None,
                        to,
                    });
                }
            }
            (Some("assignees"), loro::event::Diff::Map(md)) => {
                for (k, v) in md.updated.iter() {
                    let user = UserId::from_key_string(k.to_string());
                    if v.is_some() {
                        assignee_added.push(user);
                    } else {
                        assignee_removed.push(user);
                    }
                }
            }
            (Some("labels"), loro::event::Diff::Map(md)) => {
                for (k, v) in md.updated.iter() {
                    fields.push(FieldChange {
                        field: "labels".into(),
                        from: v.is_none().then(|| k.to_string()),
                        to: v.is_some().then(|| k.to_string()),
                    });
                }
            }
            (Some("comments"), loro::event::Diff::List(items)) => {
                for item in items {
                    if let loro::event::ListDiffItem::Insert { insert, .. } = item {
                        for voc in insert {
                            if let loro::ValueOrContainer::Container(Container::Map(m)) = voc {
                                comments.push(CommentDto {
                                    author: UserId::from_key_string(
                                        lx::get_str(m, "author").unwrap_or_default(),
                                    ),
                                    author_nick: None,
                                    ts: lx::get_u64(m, "ts").unwrap_or(0),
                                    body: lx::get_str(m, "body").unwrap_or_default(),
                                });
                            }
                        }
                    }
                }
            }
            (Some("description"), loro::event::Diff::Text(_)) => {
                fields.push(FieldChange {
                    field: "description".into(),
                    from: None,
                    to: None,
                });
            }
            _ => {}
        }
    }
    (fields, comments, assignee_added, assignee_removed)
}

/// Resolve which issue-schema field a container diff belongs to: the root map
/// itself is `"issue"`; a nested container's field is its key under the root.
/// Path segments are `(container, its-index-within-its-parent)`, so segment 0
/// is the root container keyed by its own name and segment 1 carries the
/// root-map key the nested container hangs from (verified empirically).
fn container_field(doc: &LoroDoc, cid: &loro::ContainerID) -> Option<String> {
    if cid.is_root() {
        return Some(cid.name().to_string());
    }
    let path = doc.get_path_to_container(cid)?;
    match path.get(1) {
        Some((_container, loro::Index::Key(k))) => Some(k.to_string()),
        _ => None,
    }
}
