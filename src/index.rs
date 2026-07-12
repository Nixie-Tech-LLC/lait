//! Local materialized index (SCHEMA §3 "local cache"): the `KEY-n` alias table
//! and ref resolution. Never synced — rebuilt from the Catalog on load. All
//! three surfaces share this one grammar, resolved **daemon-side** (UI.md §3).
//!
//! - The **canonical** handle is a short `DocId` prefix (`iss_3f9`), collision-
//!   free by construction (S§5.4).
//! - `KEY-n` (`ENG-142`) is an advisory alias that **may collide**; colliding
//!   docs disambiguate by a deterministic suffix (`ENG-142b`) (S§5.4).
//! - Resolution can return **zero, one, or many** — ambiguity is a first-class
//!   outcome with a candidate list (UI.md §3.2), never a crash.

use std::collections::HashMap;

use crate::catalog::{CatalogDoc, RowMeta};
use crate::dto::{Candidate, ProjectDto};
use crate::ids::{DocId, ProjectId, UserId};

/// Minimum ULID chars after the `iss_` prefix in a canonical short handle.
const CANONICAL_MIN: usize = 7;

/// Canonical short handle for a doc with **no set context** — the minimum-length
/// prefix. NOTE: a ULID's leading chars are its *timestamp*, so two docs minted
/// in the same millisecond share this prefix; the collision-free handle is the
/// **shortest-unique** prefix computed over the whole doc set (git-style) by
/// [`AliasTable::canonical_for`]. Prefer that; this is a single-doc fallback.
pub fn canonical_reff(doc_id: &DocId) -> String {
    doc_id.short(CANONICAL_MIN)
}

/// The `KEY-n` alias table + canonical-handle table, built from the Catalog.
/// Handles `KEY-n` collisions with a deterministic suffix, and computes each
/// doc's **shortest-unique** canonical `iss_` prefix (S§5.4, git-style).
#[derive(Debug, Default, Clone)]
pub struct AliasTable {
    /// DocId string -> alias (`ENG-142` or `ENG-142b`).
    by_doc: HashMap<String, String>,
    /// lowercased alias -> DocId.
    by_alias: HashMap<String, DocId>,
    /// DocId string -> shortest-unique canonical handle (`iss_3f9ab2c`).
    canonical: HashMap<String, String>,
}

impl AliasTable {
    /// Build the alias table from the current catalog state. Deterministic:
    /// within one project+seq collision group, docs are ordered by DocId and the
    /// first keeps the bare `KEY-n`, the rest get suffix `b`, `c`, … (S§5.4).
    pub fn build(catalog: &CatalogDoc) -> Self {
        let mut table = AliasTable::default();
        // project id -> key
        let key_of: HashMap<String, String> = catalog
            .projects_list()
            .into_iter()
            .map(|p| (p.id.as_str().to_string(), p.key))
            .collect();
        // group rows by (projectId, seq)
        let mut groups: HashMap<(String, u32), Vec<DocId>> = HashMap::new();
        for row in catalog.all_rows() {
            if let Some(seq) = row.seq {
                groups
                    .entry((row.project_id.as_str().to_string(), seq))
                    .or_default()
                    .push(row.doc_id);
            }
        }
        for ((proj, seq), mut docs) in groups {
            let Some(key) = key_of.get(&proj) else {
                continue;
            };
            docs.sort();
            for (i, doc) in docs.into_iter().enumerate() {
                let alias = if i == 0 {
                    format!("{key}-{seq}")
                } else {
                    format!("{key}-{seq}{}", suffix(i))
                };
                table
                    .by_doc
                    .insert(doc.as_str().to_string(), alias.to_ascii_lowercase());
                table
                    .by_alias
                    .insert(alias.to_ascii_lowercase(), doc.clone());
                // store the display form (original case) on by_doc value
                table.by_doc.insert(doc.as_str().to_string(), alias);
            }
        }
        table.canonical = shortest_unique_canonicals(&catalog.doc_ids());
        table
    }

    /// The display alias for a doc, if it has one.
    pub fn alias_for(&self, doc_id: &DocId) -> Option<String> {
        self.by_doc.get(doc_id.as_str()).cloned()
    }

    /// Resolve a `KEY-n` alias to a DocId (case-insensitive).
    pub fn resolve_alias(&self, alias: &str) -> Option<DocId> {
        self.by_alias.get(&alias.to_ascii_lowercase()).cloned()
    }

    /// The collision-free canonical handle for a doc (shortest-unique `iss_`
    /// prefix over the doc set), falling back to the single-doc minimum.
    pub fn canonical_for(&self, doc_id: &DocId) -> String {
        self.canonical
            .get(doc_id.as_str())
            .cloned()
            .unwrap_or_else(|| canonical_reff(doc_id))
    }
}

/// Git-style shortest-unique prefixes: for each doc, the smallest prefix
/// (≥ [`CANONICAL_MIN`] ULID chars) that no other doc shares. Because ULIDs lead
/// with a timestamp, same-millisecond docs extend into their random tail.
fn shortest_unique_canonicals(ids: &[DocId]) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for id in ids {
        let ulid = id.ulid();
        let max = ulid.len();
        let mut k = CANONICAL_MIN.min(max);
        while k < max {
            let prefix = &ulid[..k];
            let collisions = ids.iter().filter(|o| o.ulid().starts_with(prefix)).count();
            if collisions <= 1 {
                break;
            }
            k += 1;
        }
        out.insert(
            id.as_str().to_string(),
            format!("{}{}", DocId::PREFIX, &ulid[..k]),
        );
    }
    out
}

/// `1 -> "b", 2 -> "c", …, 25 -> "z", 26 -> "aa"` (collision suffix, S§5.4).
fn suffix(i: usize) -> String {
    // i starts at 1 for the first collision (the 0th keeps the bare alias).
    let mut n = i; // 1-based: i==1 is the first collision → "b"
    let mut s = String::new();
    // Deterministic base-26 letters: 1->b, 2->c, …, 25->z, 26->aa, …
    let alphabet = b"abcdefghijklmnopqrstuvwxyz";
    loop {
        let rem = n % 26;
        s.insert(0, alphabet[rem] as char);
        if n < 26 {
            break;
        }
        n = n / 26 - 1;
    }
    s
}

/// Outcome of resolving a `<ref>` (UI.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefResolution {
    One(DocId),
    Zero,
    Many(Vec<Candidate>),
}

/// Resolve an issue `<ref>`: a short `DocId` prefix, or a `KEY-n` alias.
pub fn resolve_ref(catalog: &CatalogDoc, aliases: &AliasTable, input: &str) -> RefResolution {
    let input = input.trim();
    if input.is_empty() {
        return RefResolution::Zero;
    }

    // 1. short DocId prefix (canonical, collision-free).
    if input.starts_with(DocId::PREFIX) {
        let matches: Vec<DocId> = catalog
            .doc_ids()
            .into_iter()
            .filter(|d| {
                d.as_str()
                    .to_ascii_lowercase()
                    .starts_with(&input.to_ascii_lowercase())
            })
            .collect();
        return finalize(catalog, aliases, matches);
    }

    // 2. KEY-n alias (may collide → the alias table already disambiguated, so a
    //    bare `ENG-142` that collided resolves to the first; a suffixed
    //    `ENG-142b` resolves to the specific one).
    if let Some(doc) = aliases.resolve_alias(input) {
        return RefResolution::One(doc);
    }

    RefResolution::Zero
}

fn finalize(catalog: &CatalogDoc, aliases: &AliasTable, mut matches: Vec<DocId>) -> RefResolution {
    matches.sort();
    matches.dedup();
    match matches.len() {
        0 => RefResolution::Zero,
        1 => RefResolution::One(matches.remove(0)),
        // Many: present each candidate with its canonical handle (already 7
        // chars — astronomically unique; a genuine Many only arises from
        // too-short manual input, UI.md §3.2) plus its alias + title.
        _ => RefResolution::Many(
            matches
                .iter()
                .map(|d| Candidate {
                    reff: aliases.canonical_for(d),
                    key_alias: aliases.alias_for(d),
                    title: catalog.row(d).map(|r| r.title).unwrap_or_default(),
                })
                .collect(),
        ),
    }
}

/// Resolve a project `<ref>`: a project key (`ENG`) or a `prj_` id.
pub fn resolve_project(catalog: &CatalogDoc, input: &str) -> Option<ProjectDto> {
    let input = input.trim();
    if input.starts_with(ProjectId::PREFIX) {
        if let Some(id) = ProjectId::parse(input) {
            return catalog.project(&id);
        }
    }
    catalog.project_by_key(input)
}

/// Resolve a `<userref>`: `@me`, or a full ed25519 key. (Nick/prefix resolution
/// is presence-fed and lives in [`resolve_user_dir`], which the daemon calls with
/// a directory it assembles from members + presence + join requests. This 2-arg
/// form is the directory-free fallback used inside the tracker, where a ref has
/// already been resolved to `@me`/a full key by the node layer.)
pub fn resolve_user(input: &str, me: &UserId) -> Option<UserId> {
    let input = input.trim();
    if input == "@me" || input == "me" {
        return Some(me.clone());
    }
    UserId::parse(input)
}

/// A known identity for user-ref resolution: an ed25519 key plus its advisory
/// nick (from live presence, a join request, or our own profile). The nick may be
/// empty when only the key is known — e.g. an ACL member we've never seen online;
/// such an entry is still resolvable by key or id-prefix, just not by nick.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownUser {
    pub key: UserId,
    pub nick: String,
}

/// Outcome of resolving a `<userref>` against the presence-fed directory — the
/// user-plane twin of [`RefResolution`]. Ambiguity is first-class (UI.md §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserResolution {
    One(UserId),
    Zero,
    Many(Vec<KnownUser>),
}

/// Minimum hex chars accepted as a key id-prefix (short enough to type, long
/// enough to rarely collide across a workspace's handful of members).
const USER_PREFIX_MIN: usize = 4;

/// Resolve a `<userref>` (UI.md §3.1) against a directory: `@me`/`me`; a full
/// 64-hex ed25519 key; an advisory **nick** (case-insensitive, exact); or a
/// **key id-prefix** (≥ [`USER_PREFIX_MIN`] hex chars). Nick and prefix are
/// matched against `dir` (members + live presence + recent join requests). A
/// full key always resolves even when absent from `dir`. Multiple distinct hits
/// return `Many` so the caller can show a candidate list (UI.md §3.2). Nick is
/// tried before prefix; the first stage to hit wins.
pub fn resolve_user_dir(input: &str, me: &UserId, dir: &[KnownUser]) -> UserResolution {
    let input = input.trim();
    if input.is_empty() {
        return UserResolution::Zero;
    }
    if input == "@me" || input == "me" {
        return UserResolution::One(me.clone());
    }
    // A full key is unambiguous and resolves without the directory.
    if let Some(u) = UserId::parse(input) {
        return UserResolution::One(u);
    }

    // Exact nick match (case-insensitive), deduped by key.
    let mut nick_hits: Vec<KnownUser> = Vec::new();
    for k in dir {
        if !k.nick.is_empty()
            && k.nick.eq_ignore_ascii_case(input)
            && !nick_hits.iter().any(|h| h.key == k.key)
        {
            nick_hits.push(k.clone());
        }
    }
    match nick_hits.len() {
        1 => return UserResolution::One(nick_hits.remove(0).key),
        n if n > 1 => return UserResolution::Many(nick_hits),
        _ => {}
    }

    // Key id-prefix (hex, ≥ USER_PREFIX_MIN chars) against known keys.
    let lower = input.to_ascii_lowercase();
    let is_hex_prefix =
        lower.len() >= USER_PREFIX_MIN && lower.bytes().all(|b| b.is_ascii_hexdigit());
    if is_hex_prefix {
        let mut pfx_hits: Vec<KnownUser> = Vec::new();
        for k in dir {
            if k.key.as_str().to_ascii_lowercase().starts_with(&lower)
                && !pfx_hits.iter().any(|h| h.key == k.key)
            {
                pfx_hits.push(k.clone());
            }
        }
        match pfx_hits.len() {
            1 => return UserResolution::One(pfx_hits.remove(0).key),
            n if n > 1 => return UserResolution::Many(pfx_hits),
            _ => {}
        }
    }

    UserResolution::Zero
}

/// A `Row`-ready view: whether a row should be hidden by default (done or
/// tombstoned) — used by `ls`/`board` filtering (UI.md §2.2).
pub fn is_hidden_by_default(catalog: &CatalogDoc, row: &RowMeta) -> bool {
    if row.tombstone {
        return true;
    }
    catalog
        .workflow_state(&row.status)
        .map(|w| w.category == crate::dto::StatusCategory::Done)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dto::Priority;
    use crate::ids::{SystemUlidSource, WorkspaceId};
    use crate::issue::{IssueDoc, NewIssue};

    fn setup() -> (CatalogDoc, ProjectId, WorkspaceId) {
        let ws = WorkspaceId::mint(&SystemUlidSource);
        let c = CatalogDoc::create(&ws).unwrap();
        let p = ProjectId::mint(&SystemUlidSource);
        c.add_project(&p, "Engineering", "ENG", "blue").unwrap();
        c.doc().commit();
        (c, p, ws)
    }

    fn add_issue(
        c: &CatalogDoc,
        ws: &WorkspaceId,
        p: &ProjectId,
        title: &str,
        seq_via_assign: bool,
    ) -> DocId {
        let issue = IssueDoc::create(NewIssue {
            doc_id: DocId::mint(&SystemUlidSource),
            workspace_id: ws.clone(),
            project_id: p.clone(),
            title: title.into(),
            priority: Priority::Medium,
            created_by: UserId::from_key_string("a".repeat(64)),
            created_at: 1,
            body: None,
        })
        .unwrap();
        c.upsert_row(&issue).unwrap();
        let id = issue.doc_id().unwrap();
        if seq_via_assign {
            c.assign_alias_seq(&id, p).unwrap();
        }
        c.doc().commit();
        id
    }

    #[test]
    fn resolve_by_short_docid_prefix() {
        let (c, p, ws) = setup();
        let id = add_issue(&c, &ws, &p, "one", true);
        let aliases = AliasTable::build(&c);
        let short = canonical_reff(&id);
        assert_eq!(
            resolve_ref(&c, &aliases, &short),
            RefResolution::One(id.clone())
        );
        // full id resolves too
        assert_eq!(
            resolve_ref(&c, &aliases, id.as_str()),
            RefResolution::One(id)
        );
    }

    #[test]
    fn resolve_by_key_alias() {
        let (c, p, ws) = setup();
        let id = add_issue(&c, &ws, &p, "one", true);
        let aliases = AliasTable::build(&c);
        assert_eq!(aliases.alias_for(&id).as_deref(), Some("ENG-1"));
        assert_eq!(
            resolve_ref(&c, &aliases, "ENG-1"),
            RefResolution::One(id.clone())
        );
        assert_eq!(resolve_ref(&c, &aliases, "eng-1"), RefResolution::One(id));
    }

    #[test]
    fn unknown_ref_is_zero() {
        let (c, _p, _ws) = setup();
        let aliases = AliasTable::build(&c);
        assert_eq!(resolve_ref(&c, &aliases, "ENG-999"), RefResolution::Zero);
        assert_eq!(
            resolve_ref(&c, &aliases, "iss_zzzzzzz"),
            RefResolution::Zero
        );
    }

    #[test]
    fn key_n_collision_gets_suffix_deterministically() {
        // Two docs in the same project with the SAME seq (offline double-assign):
        // simulate by stamping seq directly on rows.
        let (c, p, ws) = setup();
        let a = add_issue(&c, &ws, &p, "a", false);
        let b = add_issue(&c, &ws, &p, "b", false);
        // force both to seq 5 (collision)
        c.set_seq(&a, 5).unwrap();
        c.set_seq(&b, 5).unwrap();
        c.doc().commit();
        let aliases = AliasTable::build(&c);
        // deterministic: sorted-first keeps ENG-5, the other gets ENG-5b
        let (first, second) = if a < b { (&a, &b) } else { (&b, &a) };
        assert_eq!(aliases.alias_for(first).as_deref(), Some("ENG-5"));
        assert_eq!(aliases.alias_for(second).as_deref(), Some("ENG-5b"));
        assert_eq!(
            resolve_ref(&c, &aliases, "ENG-5"),
            RefResolution::One(first.clone())
        );
        assert_eq!(
            resolve_ref(&c, &aliases, "ENG-5b"),
            RefResolution::One(second.clone())
        );
    }

    #[test]
    fn resolve_project_and_user() {
        let (c, p, _ws) = setup();
        assert_eq!(resolve_project(&c, "ENG").map(|x| x.id), Some(p.clone()));
        assert_eq!(resolve_project(&c, p.as_str()).map(|x| x.id), Some(p));
        let me = UserId::from_key_string("a".repeat(64));
        assert_eq!(resolve_user("@me", &me), Some(me.clone()));
        assert_eq!(
            resolve_user(&"b".repeat(64), &me),
            Some(UserId::from_key_string("b".repeat(64)))
        );
        assert_eq!(resolve_user("nick", &me), None);
    }

    fn ku(hex: char, nick: &str) -> KnownUser {
        KnownUser {
            key: UserId::from_key_string(hex.to_string().repeat(64)),
            nick: nick.into(),
        }
    }

    #[test]
    fn resolve_user_dir_by_me_and_full_key() {
        let me = UserId::from_key_string("a".repeat(64));
        let dir = vec![ku('b', "alice")];
        assert_eq!(
            resolve_user_dir("@me", &me, &dir),
            UserResolution::One(me.clone())
        );
        assert_eq!(
            resolve_user_dir("me", &me, &dir),
            UserResolution::One(me.clone())
        );
        // a full key resolves even when not in the directory
        let c = UserId::from_key_string("c".repeat(64));
        assert_eq!(
            resolve_user_dir(&"c".repeat(64), &me, &dir),
            UserResolution::One(c)
        );
    }

    #[test]
    fn resolve_user_dir_by_nick_case_insensitive() {
        let me = UserId::from_key_string("a".repeat(64));
        let dir = vec![ku('b', "Alice"), ku('c', "bob")];
        assert_eq!(
            resolve_user_dir("alice", &me, &dir),
            UserResolution::One(UserId::from_key_string("b".repeat(64)))
        );
        assert_eq!(
            resolve_user_dir("BOB", &me, &dir),
            UserResolution::One(UserId::from_key_string("c".repeat(64)))
        );
    }

    #[test]
    fn resolve_user_dir_by_id_prefix() {
        let me = UserId::from_key_string("a".repeat(64));
        // one key starts with bbbb, another with cccc
        let dir = vec![ku('b', ""), ku('c', "carol")];
        assert_eq!(
            resolve_user_dir("bbbb", &me, &dir),
            UserResolution::One(UserId::from_key_string("b".repeat(64)))
        );
        // too short (< USER_PREFIX_MIN) is not treated as a prefix
        assert_eq!(resolve_user_dir("bb", &me, &dir), UserResolution::Zero);
    }

    #[test]
    fn resolve_user_dir_ambiguous_nick_is_many() {
        let me = UserId::from_key_string("a".repeat(64));
        let dir = vec![ku('b', "sam"), ku('c', "sam")];
        match resolve_user_dir("sam", &me, &dir) {
            UserResolution::Many(c) => assert_eq!(c.len(), 2),
            other => panic!("expected Many, got {other:?}"),
        }
    }

    #[test]
    fn resolve_user_dir_unknown_is_zero() {
        let me = UserId::from_key_string("a".repeat(64));
        let dir = vec![ku('b', "alice")];
        assert_eq!(resolve_user_dir("nobody", &me, &dir), UserResolution::Zero);
        assert_eq!(resolve_user_dir("", &me, &dir), UserResolution::Zero);
    }
}
