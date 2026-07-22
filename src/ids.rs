//! Product identifiers: the kernel's generic identity types plus the ids the
//! Issues product owns. App-minted ids are `<prefix>_<ULID>` — see
//! [`mechanics::ids`] for the grammar and minting sources.

pub use mechanics::ids::*;

mechanics::prefixed_id!(
    /// Issue document id — app-minted, content-independent, the key in the
    /// Catalog's `docs` register and the routing key on the wire.
    ///
    /// ```
    /// use lait::ids::{DocId, SystemUlidSource};
    /// use mechanics::ids::UlidSource as _;
    /// let id = DocId::mint(&SystemUlidSource);
    /// assert!(id.as_str().starts_with("iss_"));
    /// // a short, git-style handle is a genuine prefix of the full id
    /// let short = id.short(7);
    /// assert!(id.as_str().starts_with(&short));
    /// // round-trips through parse()
    /// assert_eq!(DocId::parse(id.as_str()), Some(id));
    /// ```
    DocId, "iss_"
);
mechanics::prefixed_id!(
    /// Project id — key in the Catalog's `projects` register.
    ProjectId, "prj_"
);
mechanics::prefixed_id!(
    /// Label id — key in the Catalog's `labels` register.
    LabelId, "lbl_"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    /// A fully deterministic source: fixed clock, counter entropy.
    struct FakeSource {
        ms: Cell<u64>,
        ctr: Cell<u128>,
    }
    impl FakeSource {
        fn new(ms: u64) -> Self {
            Self {
                ms: Cell::new(ms),
                ctr: Cell::new(0),
            }
        }
    }
    impl UlidSource for FakeSource {
        fn now_ms(&self) -> u64 {
            self.ms.get()
        }
        fn rand80(&self) -> u128 {
            let v = self.ctr.get();
            self.ctr.set(v + 1);
            v
        }
    }

    #[test]
    fn docid_roundtrips_and_validates() {
        let s = FakeSource::new(1_700_000_000_000);
        let id = DocId::mint(&s);
        assert!(id.as_str().starts_with("iss_"));
        assert_eq!(DocId::parse(id.as_str()), Some(id.clone()));
        assert_eq!(DocId::parse("iss_short"), None, "bad ULID length rejected");
        assert_eq!(
            DocId::parse("prj_00000000000000000000000000"),
            None,
            "wrong prefix rejected"
        );
    }

    #[test]
    fn ulids_sort_by_time() {
        // Two ids minted at different times sort by time (ULID property), which
        // is what lets the Done view order by creation without extra state.
        let early = FakeSource::new(1_000);
        let late = FakeSource::new(2_000);
        let a = DocId::mint(&early);
        let b = DocId::mint(&late);
        assert!(a < b, "earlier ULID sorts before later: {a} !< {b}");
    }

    #[test]
    fn short_handle_is_prefix_plus_n() {
        let s = FakeSource::new(1_700_000_000_000);
        let id = DocId::mint(&s);
        let short = id.short(3);
        assert!(short.starts_with("iss_"));
        assert_eq!(short.len(), "iss_".len() + 3);
        assert!(
            id.as_str().starts_with(&short),
            "short is a genuine prefix of the full id"
        );
    }
}
