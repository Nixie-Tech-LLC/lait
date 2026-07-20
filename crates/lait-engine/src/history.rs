//! Derived history read from an issue document's durable oplog rather than a
//! process-local ring. Every change in an
//! issue doc's causal DAG carries a timestamp and an [`OpMeta`] commit message
//! when metadata is present, so `lait history` survives daemon restarts and
//! attributes remote changes — the message travels with the ops.
//!
//! Older changes without commit metadata surface honestly: timestamp 0, no
//! kind, no actor, possibly many fields fused into one change.
//!
//! **Two identities, deliberately not unified.** Anything this module reads
//! *out of the document* — comment authors, assignees — is an [`ActorId`]: a
//! person, stable across their devices. Anything read *off the change itself*
//! (`DocChange::actor`, `ImportDelta::actors`) is a [`UserId`]: the device that
//! committed, self-asserted in the commit message. The feed keeps them apart on
//! purpose — "who wrote this" and "which device landed it" answer different
//! questions, and collapsing the latter into an actor loses the fact you want
//! when a single device is misbehaving.
//!
//! Collision detection is the DAG fact, not a heuristic: a change whose deps
//! differ from the walk's running head-set sits on a concurrent branch. This
//! makes otherwise-hidden concurrent LWW writes visible in history.

use std::collections::{HashMap, HashSet};

use loro::{Container, Frontiers, LoroDoc, ID};

use crate::dto::{self, CommentDto, CorruptRecord, FieldChange, Projected};
use crate::ids::{ActorId, UserId};

use crate::issue::{project_comment, IssueDoc};
use crate::op::OpMeta;

/// One oplog change of an issue doc, projected for the history feed.
#[derive(Debug, Clone)]
pub struct DocChange {
    /// Request kind from the commit message (`None` for changes without metadata).
    pub kind: Option<String>,
    /// The **device** that committed, as claimed in the commit message — a
    /// `committedBy` stamp, not authorship. Advisory and self-asserted
    /// It is never resolved to an actor. See the module note.
    pub actor: Option<UserId>,
    /// Unix seconds (0 for changes written without recorded timestamps).
    pub ts: u64,
    /// True when this change was made concurrently with another branch.
    pub collision: bool,
    pub changes: Vec<FieldChange>,
    /// Comments introduced by this change (bodies for the feed's text line).
    /// Valid records only — see [`DocChange::corrupt_records`].
    pub comments: Vec<CommentDto>,
    /// Records this change introduced that failed to project. Kept beside the
    /// typed list so the feed can note "this change landed a malformed record"
    /// without a consumer ever mistaking one for a real comment.
    pub corrupt_records: Vec<CorruptRecord>,
}

/// What an import brought in, derived from `diff(before, after)`.
///
/// The causal diff identifies comments independently of their merged list
/// positions, so concurrent insertion cannot duplicate or hide notifications.
#[derive(Debug, Clone, Default)]
pub struct ImportDelta {
    /// Field transitions (to-values; `from` is the pre-import state the caller
    /// captured if it needs one).
    pub fields: Vec<FieldChange>,
    /// Exactly the comments that are new to this replica, wherever they merged.
    /// Valid records only — see [`ImportDelta::corrupt_records`].
    pub new_comments: Vec<CommentDto>,
    /// Incoming records that failed to project. A remote peer is the *likeliest*
    /// source of malformed data, so an import is exactly where dropping it
    /// silently would be worst: this is the audit trail for a peer writing
    /// records that don't conform.
    pub corrupt_records: Vec<CorruptRecord>,
    /// Assignees are actors: assignment follows the person, not
    /// the device they happened to be on.
    pub assignee_added: Vec<ActorId>,
    pub assignee_removed: Vec<ActorId>,
    /// DAG concurrency: the import created (or extended) a concurrent branch.
    pub collision: bool,
    /// Distinct committing **devices** of the incoming changes, from their
    /// commit messages. Advisory; see [`DocChange::actor`].
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

        let Extracted {
            mut fields,
            comments,
            assignee_added,
            assignee_removed,
            corrupt_records,
        } = extract(doc, &deps, &Frontiers::from(end));
        for f in &mut fields {
            f.from = last_seen.get(&f.field).cloned();
            if let Some(to) = &f.to {
                last_seen.insert(f.field.clone(), to.clone());
            }
        }
        fields.extend(set_changes(&assignee_added, &assignee_removed));
        let meta = OpMeta::parse(message.as_deref());
        let actor = meta.actor_id();
        out.push(DocChange {
            kind: meta.request,
            actor,
            ts: ts.max(0) as u64,
            collision,
            changes: fields,
            comments,
            corrupt_records,
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
    let Extracted {
        fields,
        comments: new_comments,
        assignee_added,
        assignee_removed,
        corrupt_records,
    } = extract(doc, &mark.frontiers, &after);

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
        corrupt_records,
        assignee_added,
        assignee_removed,
        collision,
        actors,
        kinds,
    }
}

/// Render assignee set membership changes as field transitions.
fn set_changes(adds: &[ActorId], removes: &[ActorId]) -> Vec<FieldChange> {
    let mut out = Vec::new();
    for a in adds {
        out.push(FieldChange {
            field: "assignees".into(),
            from: None,
            to: Some(a.short()),
        });
    }
    for a in removes {
        out.push(FieldChange {
            field: "assignees".into(),
            from: Some(a.short()),
            to: None,
        });
    }
    out
}

/// Root-map keys that are identity, not activity — creation constants whose
/// presence in a diff is noise.
const IDENTITY_KEYS: [&str; 4] = ["id", "workspaceId", "createdBy", "createdAt"];

/// What one `diff(from, to)` batch yielded. A struct rather than a tuple: the
/// corruption sidecar makes five fields, and positional returns stop being
/// readable well before that.
#[derive(Default)]
struct Extracted {
    fields: Vec<FieldChange>,
    comments: Vec<CommentDto>,
    assignee_added: Vec<ActorId>,
    assignee_removed: Vec<ActorId>,
    corrupt_records: Vec<CorruptRecord>,
}

/// Map a `diff(from, to)` batch onto issue-schema semantics: root-map LWW
/// fields, the assignees/labels present-key sets, new comments, description
/// edits. Container identity is resolved via its path from the root, so the
/// extraction survives any container-id representation.
fn extract(doc: &LoroDoc, from: &Frontiers, to: &Frontiers) -> Extracted {
    let mut out = Extracted::default();
    let Ok(batch) = doc.diff(from, to) else {
        return out;
    };
    let Extracted {
        fields,
        comments,
        assignee_added,
        assignee_removed,
        corrupt_records,
    } = &mut out;
    let mut projected_comments: Vec<Projected<CommentDto>> = Vec::new();
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
                    // The set is keyed by `ActorId`, so a key that isn't one is
                    // corruption. Neither laundered (a wrapped-unvalidated id
                    // mis-attributes the change downstream) nor dropped (which
                    // would make an assignment silently not happen, with nothing
                    // anywhere to say why) — reported, and the caller decides.
                    let Some(actor) = ActorId::parse(k) else {
                        corrupt_records.push(
                            CorruptRecord::new(
                                format!("assignees[{k}]"),
                                "assignee key: not an ActorId",
                            )
                            .with_raw("key", k.to_string()),
                        );
                        continue;
                    };
                    if v.is_some() {
                        assignee_added.push(actor);
                    } else {
                        assignee_removed.push(actor);
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
                            // The locus is the position within *this diff*, not
                            // within the document — a diff doesn't know where
                            // its inserts landed in the merged list.
                            let locus = format!("comments+[{}]", projected_comments.len());
                            match voc {
                                loro::ValueOrContainer::Container(Container::Map(m)) => {
                                    projected_comments.push(project_comment(m, locus));
                                }
                                _ => projected_comments.push(Projected::Corrupt(
                                    CorruptRecord::new(locus, "list element is not a map"),
                                )),
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
    let (valid, corrupt) = dto::partition(projected_comments);
    comments.extend(valid);
    corrupt_records.extend(corrupt);
    out
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
