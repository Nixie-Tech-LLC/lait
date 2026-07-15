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

use std::collections::{BTreeSet, HashMap};
use std::ops::Bound::{Excluded, Unbounded};

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
///
/// **Incremental (A§9 "Linear-grade devex").** The externally-observed outputs
/// (`by_doc`/`by_alias`/`canonical`) are a pure function of `{DocId set, each
/// doc's projectId, each doc's seq}` — nothing an *edit* changes. So the table
/// is maintained per changed doc via [`reconcile_doc`](Self::reconcile_doc) /
/// [`remove_doc`](Self::remove_doc) in **O(log N)**, instead of an O(N²) full
/// [`build`](Self::build) on every mutation. `build` is retained as the
/// authoritative full recompute (load/adopt) and is now itself O(N log N)
/// because it is just a sequence of `reconcile_doc` calls.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct AliasTable {
    /// DocId string -> alias (`ENG-142` or `ENG-142b`).
    by_doc: HashMap<String, String>,
    /// lowercased alias -> DocId.
    by_alias: HashMap<String, DocId>,
    /// DocId string -> shortest-unique canonical handle (`iss_3f9ab2c`).
    canonical: HashMap<String, String>,
    /// All known DocIds, kept sorted so each doc's shortest-unique canonical
    /// prefix is a function of its two lexicographic neighbours only:
    /// `SUP(d) = max(lcp(d, pred), lcp(d, succ)) + 1`. This is what turns
    /// canonical upkeep from the old O(N²) full scan into O(log N) per doc.
    sorted: BTreeSet<DocId>,
    /// `KEY-n` collision groups: `(projectId, seq) -> member docs`. Almost always
    /// size 1; only an offline double-assign of the same seq makes it larger.
    groups: HashMap<(String, u32), Vec<DocId>>,
    /// doc -> the `(projectId, seq)` group it currently sits in, so a seq/project
    /// change moves it between groups without a full rebuild.
    doc_group: HashMap<String, (String, u32)>,
}

impl AliasTable {
    /// Full rebuild from the current catalog — the authoritative recompute used
    /// on load/adopt. Order-independent and O(N log N): a `reconcile_doc` per
    /// doc yields exactly the same table as any incremental sequence (each doc's
    /// canonical prefix depends only on its final neighbours, and each insert
    /// re-fixes the neighbours it touches — see the module invariant).
    pub fn build(catalog: &CatalogDoc) -> Self {
        let mut table = AliasTable::default();
        for id in catalog.doc_ids() {
            table.reconcile_doc(catalog, &id);
        }
        table
    }

    /// Bring one doc's alias/canonical entries into agreement with the catalog —
    /// the incremental primitive behind create and every sync-apply. Handles a
    /// brand-new doc, a `seq` (re)assignment, and a project move; a no-op when
    /// the doc is already consistent, so calling it across every catalog doc on
    /// a sync round is O(N) total, not O(N²).
    pub fn reconcile_doc(&mut self, catalog: &CatalogDoc, doc_id: &DocId) {
        // --- canonical (shortest-unique `iss_` prefix) ---
        // The DocId itself never changes, so an already-known doc needs no
        // canonical work: any collision a *new* doc introduces is repaired when
        // that new doc is inserted (it recomputes its neighbours).
        if self.sorted.insert(doc_id.clone()) {
            let pred = self.pred(doc_id);
            let succ = self.succ(doc_id);
            self.recompute_canonical(doc_id);
            if let Some(p) = pred {
                self.recompute_canonical(&p);
            }
            if let Some(s) = succ {
                self.recompute_canonical(&s);
            }
        }

        // --- KEY-n alias group membership ---
        let want = catalog
            .row(doc_id)
            .and_then(|r| r.seq.map(|s| (r.project_id.as_str().to_string(), s)));
        let have = self.doc_group.get(doc_id.as_str()).cloned();
        if want == have {
            return;
        }
        if let Some(old) = have {
            self.detach_from_group(doc_id, &old);
            if let Some(key) = project_key(catalog, &old.0) {
                self.reassign_group(&old, &key);
            }
        }
        if let Some(new) = want {
            if let Some(key) = project_key(catalog, &new.0) {
                let members = self.groups.entry(new.clone()).or_default();
                members.push(doc_id.clone());
                // Keep the stored member list sorted so the table is truly
                // order-independent (the module invariant `build()` relies on):
                // any incremental sequence and a full rebuild — whose iteration
                // order is a HashMap walk — must produce identical tables.
                members.sort();
                self.doc_group
                    .insert(doc_id.as_str().to_string(), new.clone());
                self.reassign_group(&new, &key);
            }
        }
    }

    /// Drop a doc entirely (canonical + KEY-n). Not used by delete — which
    /// tombstones and deliberately keeps the alias resolvable — but the symmetric
    /// primitive for a genuine removal; the freed neighbours may shorten.
    pub fn remove_doc(&mut self, catalog: &CatalogDoc, doc_id: &DocId) {
        if self.sorted.remove(doc_id) {
            self.canonical.remove(doc_id.as_str());
            let pred = self.pred(doc_id);
            let succ = self.succ(doc_id);
            if let Some(p) = pred {
                self.recompute_canonical(&p);
            }
            if let Some(s) = succ {
                self.recompute_canonical(&s);
            }
        }
        if let Some(gk) = self.doc_group.remove(doc_id.as_str()) {
            self.detach_from_group(doc_id, &gk);
            if let Some(key) = project_key(catalog, &gk.0) {
                self.reassign_group(&gk, &key);
            }
        }
    }

    /// Greatest DocId strictly less than `doc` (its left sorted neighbour).
    fn pred(&self, doc: &DocId) -> Option<DocId> {
        self.sorted.range(..doc.clone()).next_back().cloned()
    }
    /// Least DocId strictly greater than `doc` (its right sorted neighbour).
    fn succ(&self, doc: &DocId) -> Option<DocId> {
        self.sorted
            .range((Excluded(doc.clone()), Unbounded))
            .next()
            .cloned()
    }

    /// Recompute one doc's canonical handle from its two sorted neighbours:
    /// the shortest prefix (≥ [`CANONICAL_MIN`]) not shared with either.
    fn recompute_canonical(&mut self, doc: &DocId) {
        let ulid = doc.ulid();
        let lp = self.pred(doc).map(|p| lcp_len(ulid, p.ulid())).unwrap_or(0);
        let ls = self.succ(doc).map(|s| lcp_len(ulid, s.ulid())).unwrap_or(0);
        let k = (lp.max(ls) + 1).clamp(CANONICAL_MIN, ulid.len());
        self.canonical.insert(
            doc.as_str().to_string(),
            format!("{}{}", DocId::PREFIX, &ulid[..k]),
        );
    }

    /// Remove a doc from its group's member list and drop its alias entries
    /// (leaving the group's remaining members to be reassigned by the caller).
    fn detach_from_group(&mut self, doc_id: &DocId, gk: &(String, u32)) {
        if let Some(v) = self.groups.get_mut(gk) {
            v.retain(|d| d.as_str() != doc_id.as_str());
            if v.is_empty() {
                self.groups.remove(gk);
            }
        }
        self.doc_group.remove(doc_id.as_str());
        if let Some(a) = self.by_doc.remove(doc_id.as_str()) {
            self.by_alias.remove(&a.to_ascii_lowercase());
        }
    }

    /// Rewrite every alias in a `(project, seq)` group: sorted-first keeps the
    /// bare `KEY-n`, the rest get deterministic suffixes `b`, `c`, … (S§5.4).
    fn reassign_group(&mut self, gk: &(String, u32), key: &str) {
        let seq = gk.1;
        let mut docs = self.groups.get(gk).cloned().unwrap_or_default();
        docs.sort();
        // clear the group's current alias entries before rewriting.
        for d in &docs {
            if let Some(a) = self.by_doc.remove(d.as_str()) {
                self.by_alias.remove(&a.to_ascii_lowercase());
            }
        }
        for (i, d) in docs.iter().enumerate() {
            let alias = if i == 0 {
                format!("{key}-{seq}")
            } else {
                format!("{key}-{seq}{}", suffix(i))
            };
            self.by_alias.insert(alias.to_ascii_lowercase(), d.clone());
            self.by_doc.insert(d.as_str().to_string(), alias);
        }
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

/// Length of the common prefix of two (ASCII, equal-alphabet) ULID strings —
/// the metric behind a doc's shortest-unique canonical prefix.
fn lcp_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count()
}

/// The display key of a project id string, if the project exists.
fn project_key(catalog: &CatalogDoc, project_id: &str) -> Option<String> {
    ProjectId::parse(project_id)
        .and_then(|p| catalog.project(&p))
        .map(|p| p.key)
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

/// Resolve a `<userref>`: `@me`, or a full ed25519 key. (Alias/prefix resolution
/// lives in [`resolve_user_dir`], which the daemon calls with a directory it
/// assembles from members + presence + join requests, named by the local alias
/// store. This 2-arg form is the directory-free fallback used inside the tracker,
/// where a ref has already been resolved to `@me`/a full key by the node layer.)
pub fn resolve_user(input: &str, me: &UserId) -> Option<UserId> {
    let input = input.trim();
    if input == "@me" || input == "me" {
        return Some(me.clone());
    }
    UserId::parse(input)
}

/// A known identity for user-ref resolution: an ed25519 key plus a locally-set
/// **alias** (petname), if any. The `nick` field carries that trusted local
/// alias — never a self-asserted wire nick, which is deliberately kept out of
/// resolution. It is empty when we know only the key (an ACL member we've never
/// aliased); such an entry is still resolvable by key or id-prefix, just not by
/// name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownUser {
    pub key: UserId,
    /// A locally-assigned alias (petname). Empty ⇒ resolvable only by key/prefix.
    pub nick: String,
}

/// Outcome of resolving a `<userref>` against the directory — the user-plane twin
/// of [`RefResolution`]. Ambiguity is first-class (UI.md §3.2).
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
/// 64-hex ed25519 key; a locally-set **alias** (case-insensitive, exact); or a
/// **key id-prefix** (≥ [`USER_PREFIX_MIN`] hex chars). Alias and prefix are
/// matched against `dir`, whose names come only from the local alias store — a
/// self-asserted wire nick is never a resolution input. A full key always
/// resolves even when absent from `dir`. Multiple distinct hits return `Many` so
/// the caller can show a candidate list (UI.md §3.2). Alias is tried before
/// prefix; the first stage to hit wins.
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
        let c = CatalogDoc::create(&ws, "test").unwrap();
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

    /// Every canonical handle must uniquely identify its doc: no *other* doc's
    /// ULID may start with it. This is the invariant the old O(N²) scan gave and
    /// the incremental neighbour recompute must preserve.
    fn assert_canonicals_unique(t: &AliasTable, c: &CatalogDoc) {
        let ids = c.doc_ids();
        for d in &ids {
            let handle = t.canonical_for(d);
            let prefix = handle.strip_prefix(DocId::PREFIX).unwrap();
            let hits = ids.iter().filter(|o| o.ulid().starts_with(prefix)).count();
            assert_eq!(
                hits, 1,
                "canonical {handle} for {d} is not unique ({hits} hits)"
            );
            assert!(
                prefix.len() >= CANONICAL_MIN,
                "canonical shorter than min: {handle}"
            );
        }
    }

    #[test]
    fn incremental_reconcile_matches_full_build_any_order() {
        let (c, p, ws) = setup();
        let q = ProjectId::mint(&SystemUlidSource);
        c.add_project(&q, "Design", "DSN", "pink").unwrap();
        c.doc().commit();
        let mut ids = Vec::new();
        for t in ["a", "b", "cc", "d", "e", "f"] {
            ids.push(add_issue(&c, &ws, &p, t, true));
        }
        for t in ["g", "h", "i"] {
            ids.push(add_issue(&c, &ws, &q, t, true));
        }

        // Reconcile in REVERSE doc order — must still equal the full build.
        let mut inc = AliasTable::default();
        let mut rev = c.doc_ids();
        rev.reverse();
        for id in &rev {
            inc.reconcile_doc(&c, id);
        }
        let full = AliasTable::build(&c);
        assert_eq!(
            inc, full,
            "incremental (reverse order) must equal full build"
        );
        assert_canonicals_unique(&inc, &c);
        // and aliases resolve
        for id in &ids {
            let a = inc.alias_for(id).unwrap();
            assert_eq!(inc.resolve_alias(&a), Some(id.clone()));
        }
    }

    #[test]
    fn reconcile_absorbs_a_seq_collision() {
        // Two docs get distinct seqs, then an offline double-assign collides them.
        let (c, p, ws) = setup();
        let a = add_issue(&c, &ws, &p, "a", true); // ENG-1
        let b = add_issue(&c, &ws, &p, "b", true); // ENG-2
        let mut t = AliasTable::build(&c);
        assert_eq!(t.alias_for(&a).as_deref(), Some("ENG-1"));
        assert_eq!(t.alias_for(&b).as_deref(), Some("ENG-2"));

        // Collide b onto seq 1, then reconcile just b.
        c.set_seq(&b, 1).unwrap();
        c.doc().commit();
        t.reconcile_doc(&c, &b);

        // Sorted-first of {a,b} at (ENG,1) keeps the bare alias; the other +suffix.
        let (first, second) = if a < b { (&a, &b) } else { (&b, &a) };
        assert_eq!(t.alias_for(first).as_deref(), Some("ENG-1"));
        assert_eq!(t.alias_for(second).as_deref(), Some("ENG-1b"));
        // and it matches a fresh full build after the change.
        assert_eq!(t, AliasTable::build(&c));
    }

    #[test]
    fn remove_doc_drops_entries_and_frees_neighbours() {
        let (c, p, ws) = setup();
        let ids: Vec<DocId> = ["a", "b", "cc", "d"]
            .iter()
            .map(|t| add_issue(&c, &ws, &p, t, true))
            .collect();
        let mut t = AliasTable::build(&c);
        let victim = &ids[1];
        assert!(t.alias_for(victim).is_some());
        t.remove_doc(&c, victim);
        // its alias no longer resolves and it has no canonical entry.
        assert_eq!(t.resolve_alias("ENG-2"), None);
        // remaining docs still have unique canonicals.
        // (build a catalog view of the survivors by filtering the assertion set)
        for d in ids.iter().filter(|d| *d != victim) {
            let handle = t.canonical_for(d);
            let prefix = handle.strip_prefix(DocId::PREFIX).unwrap();
            let hits = ids
                .iter()
                .filter(|o| *o != victim && o.ulid().starts_with(prefix))
                .count();
            assert_eq!(hits, 1, "survivor canonical {handle} not unique");
        }
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

    // ---- alias-spoofing defenses ----
    //
    // The node builds the directory's `nick` field ONLY from the local alias store;
    // a self-asserted wire nick reaches the resolver as an empty nick. These tests
    // pin the resolver contract that makes that safe: a name resolves only when a
    // *local* alias binds it to a key, so an impersonator's display name can't
    // stand in for an identity.

    #[test]
    fn spoofed_name_without_a_local_alias_resolves_to_nobody() {
        // An impersonator announced nick "alice" but we never aliased their key —
        // so it arrives with an empty nick and the claimed name resolves to Zero.
        let me = UserId::from_key_string("a".repeat(64));
        let impostor = ku('b', ""); // known key, no local alias
        let dir = vec![impostor];
        assert_eq!(resolve_user_dir("alice", &me, &dir), UserResolution::Zero);
    }

    #[test]
    fn local_alias_binds_a_name_to_the_intended_key_not_a_spoofer() {
        // We aliased the REAL alice's key -> "alice". A spoofer with a different key
        // and no alias also sits in the directory. Resolving "alice" must land on
        // the aliased key, never the spoofer.
        let me = UserId::from_key_string("a".repeat(64));
        let real = ku('b', "alice");
        let spoofer = ku('c', ""); // different key, self-asserted nick was dropped
        let dir = vec![spoofer, real.clone()];
        assert_eq!(
            resolve_user_dir("alice", &me, &dir),
            UserResolution::One(real.key)
        );
    }

    #[test]
    fn spoofer_reusing_an_existing_alias_forces_disambiguation() {
        // Defense-in-depth: even if the operator later aliases a SECOND key to the
        // same name (e.g. tricked into re-using "alice"), resolution returns Many
        // rather than silently picking one — no wrong-key-by-default.
        let me = UserId::from_key_string("a".repeat(64));
        let dir = vec![ku('b', "alice"), ku('c', "alice")];
        match resolve_user_dir("alice", &me, &dir) {
            UserResolution::Many(c) => assert_eq!(c.len(), 2),
            other => panic!("expected Many, got {other:?}"),
        }
    }
}
