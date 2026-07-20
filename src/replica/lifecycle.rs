//! Space lifecycle: founding, joining, and opening.

use super::*;

/// Derive a project key from a human name: ≥2 words → uppercase initials (max
/// 4), one word → its first 4 letters, empty → "PRJ". Always 1–4 ASCII letters,
/// so `KEY-n` aliases and git-branch inference stay parseable.
pub fn derive_project_key(name: &str) -> String {
    let words: Vec<&str> = name
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|w| !w.is_empty())
        .collect();
    let key: String = match words.len() {
        0 => "PRJ".to_string(),
        1 => words[0].chars().take(4).collect(),
        _ => words
            .iter()
            .take(4)
            .filter_map(|w| w.chars().next())
            .collect(),
    };
    key.to_ascii_uppercase()
}

/// Found a fresh space in `store` — the `lait init` path, and the ONLY
/// place a space comes into existence on this machine besides
/// [`join_space_store`]. Mints the genesis with `me` as founding admin
/// creates the catalog carrying the display `name`, seals the epoch-0
/// space key to ourselves, and seeds the first project (named after the
/// space, key derived) so `lait new` works immediately. Errors if the store
/// already holds a space. Returns the space id and the seeded project.
pub fn found_space(
    store: &Store,
    me: &DeviceId,
    device_seed: &[u8; 32],
    name: &str,
    clock: &dyn UlidSource,
) -> Result<(SpaceId, ProjectDto)> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a space");
    }
    // Self-certifying space id (lait/space/1): derive it from the founding
    // device + a random salt so the id commits to its trust root. The salt is
    // chosen BEFORE the founding actor is incepted — an inception is scoped to a
    // space id, so the id cannot itself depend on the inception. Derive from
    // the SEED's public key (the inception's author), so the id commits to
    // exactly the key that signs the founding inception.
    let founding_device = crypto::device_from_seed(device_seed);
    let salt = rand16();
    // Mint the space's break-glass recovery key (a solo bootstrap key the
    // founder holds — later elevated to a FROST group key via Rotate) and fold its
    // commitment into the id, so root recovery is authorized offline against a
    // value bound at birth, never a compromised current admin (lait/space/1 W5).
    let (recovery_pub, recovery_secret) = crate::space::mint_recovery_key();
    let recovery_root = crate::space::recovery_commit(&recovery_pub).expect("valid recovery key");
    let ws = crate::space::derive_space_id(&founding_device, &salt, &recovery_root);
    persist_space_recovery(store, &recovery_secret)?;
    let cat = CatalogDoc::create(&ws, name, Some(store.peer_id()), me)?;
    // Seed the first project so a fresh space is usable on the very next
    // command. Plain catalog data — a joiner never hits this path.
    let project_name = if name.trim().is_empty() {
        "Main"
    } else {
        name.trim()
    };
    let project_id = ProjectId::mint(clock);
    let project_key = derive_project_key(project_name);
    cat.add_project(&project_id, project_name, &project_key, "blue")?;
    cat.apply(&OpCtx::structure("project_new", me));

    // Provision the founder's recovery key (pre-rotation commitment) and incept
    // the founding actor — the genesis anchors trust in the *actor*, so the
    // founder can rotate devices without re-founding (lait/actor/1).
    let (recovery_commit, recovery_seed) = mint_recovery();
    persist_recovery_key(store, &recovery_seed)?;
    let (incept_ev, actor_id) =
        actor::incept_single(device_seed, &ws, rand16(), rand16(), Some(recovery_commit));

    let genesis = Genesis {
        space_id: ws.clone(),
        founding_actors: vec![actor_id.clone()],
        salt,
        recovery_root,
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&cat)?;
    let membership = MembershipDoc::create(&ws, Some(store.peer_id()), me)?;
    membership.add_actor_event(&incept_ev)?;
    // Mint the founding key epoch (id-addressed, generation 0) via a SIGNED
    // MintEpoch op authored by the founder, and seal it to the founder's device.
    // The signed mint is what any replica adopts — never a raw epoch record.
    let key = crypto::random_key();
    let epoch0 = rand16();
    let key_commit = *blake3::hash(&key).as_bytes();
    let mint = acl::sign_op(
        device_seed,
        &AclOp {
            action: AclAction::MintEpoch {
                id: epoch0,
                gen: 0,
                key_commit,
                members: vec![actor_id.clone()],
            },
            by: actor_id.clone(),
            actor_asof: vec![incept_ev.hash()],
            nonce: None,
        },
        membership.heads(),
        &ws,
    );
    membership.add_op(&mint)?;
    if let Some(sealed) = crypto::seal_to(me, &key) {
        membership.put_sealed(&epoch0, me, &sealed)?;
    }
    membership.apply(&OpCtx::authority("found", me));
    store.save_membership(&membership)?;
    store.commit("init space");
    let project = cat
        .project(&project_id)
        .ok_or_else(|| anyhow!("seeded project vanished"))?;
    Ok((ws, project))
}

/// Mint a recovery keypair: returns (commitment, secret seed). The secret is
/// written to `recovery.key` and should be moved offline; the commitment is
/// public (it rides the inception).
pub(super) fn mint_recovery() -> ([u8; 32], [u8; 32]) {
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("getrandom");
    let recovery_pub = crypto::device_from_seed(&seed);
    let commit = actor::recovery_commitment(&recovery_pub).expect("valid recovery pubkey");
    (commit, seed)
}

/// Bootstrap a store from a join ticket: the `lait join` path.
/// Writes the ticket's genesis (the host is the founding admin whose signed ACL
/// the joiner validates against) and **empty** catalog/membership docs, so
/// importing the founder's ops adopts identical container ids (see
/// [`CatalogDoc::empty`] — `create()` would mint conflicting containers).
/// Errors if the store already holds a space; the CLI guarantees it doesn't.
pub fn join_space_store(
    store: &Store,
    space: &str,
    salt: &[u8; 16],
    recovery_root: &[u8; 32],
    founder_inception: &actor::SignedEvent,
) -> Result<SpaceId> {
    if store.is_initialized() {
        anyhow::bail!("store already initialized — this directory already holds a space");
    }
    let ws_id =
        SpaceId::parse(space).ok_or_else(|| anyhow!("invalid space id in ticket: {space}"))?;
    // Verify the trust root offline: the id must commit to the founder AND the
    // recovery set, and the founding inception must validly incept for THIS
    // space. A tampered anchor fails here rather than silently forking the
    // joiner (lait/space/1).
    let founder_actor =
        crate::space::verify_founding(&ws_id, salt, recovery_root, founder_inception)
            .context("verify space founding — ask for a fresh invite")?;
    let genesis = Genesis {
        space_id: ws_id.clone(),
        founding_actors: vec![founder_actor],
        salt: *salt,
        recovery_root: *recovery_root,
    };
    store.write_genesis(&genesis)?;
    store.save_catalog(&CatalogDoc::empty(Some(store.peer_id())))?;
    // Seed the verified founding inception so the actor plane roots correctly
    // from the first replay, before any sync. The seed is committed through
    // `apply` like every other write; `save_membership`
    // exports, and an export implicitly commits whatever is pending, so a bare
    // stage here would seal the joiner's trust root into an anonymous,
    // tier-less change. The actor claim is the inception's own author (the
    // founder's device): we are landing *their* signed event, not authoring one.
    let membership = MembershipDoc::empty(Some(store.peer_id()));
    membership.add_actor_event(founder_inception)?;
    membership.apply(&OpCtx::authority("join_seed", &founder_inception.author));
    store.save_membership(&membership)?;
    store.commit("join space from ticket");
    Ok(ws_id)
}

impl Replica {
    /// Open the replica over an **initialized** store — a missing catalog or
    /// genesis is an error, never a founding event (spaces are born only in
    /// [`found_space`] / [`join_space_store`]). Performs the **load-time
    /// head recompute**: heads and rows are recomputed from the real
    /// issue-doc frontiers, never trusted from disk, so a crash between an issue
    /// commit and its row mirror self-heals.
    pub fn open(
        store: Store,
        me: DeviceId,
        my_nick: String,
        seed: [u8; 32],
        clock: Box<dyn UlidSource + Send + Sync>,
    ) -> Result<Self> {
        let catalog = store.load_catalog()?.ok_or_else(|| {
            anyhow!("store not initialized — found no space here (run `lait init` or `lait join`)")
        })?;
        let genesis = store.genesis()?.ok_or_else(|| {
            anyhow!("store missing genesis.json — corrupt or pre-rewrite store; re-init or re-join")
        })?;
        // A joiner's catalog is empty (no spaceId) until the founder's ops
        // arrive over sync; the genesis is the local root of truth. A catalog
        // that DOES carry an id must agree with it.
        let space_id = match catalog.space_id() {
            Some(ws) if ws != genesis.space_id => {
                anyhow::bail!(
                    "catalog space {ws} does not match genesis {} — corrupt store",
                    genesis.space_id
                )
            }
            Some(ws) => ws,
            None => genesis.space_id.clone(),
        };
        let membership = match store.load_membership()? {
            Some(m) => m,
            None => {
                // Defensive only — both creation verbs write a membership doc.
                let m = MembershipDoc::empty(Some(store.peer_id()));
                store.save_membership(&m)?;
                m
            }
        };

        let mut replica = Replica {
            store,
            catalog,
            issues: HashMap::new(),
            aliases: AliasTable::default(),
            me,
            my_nick,
            space_id,
            activity: VecDeque::new(),
            activity_seq: 0,
            clock,
            membership,
            genesis,
            seed,
            keyring: BTreeMap::new(),
        };
        replica.refresh_keyring();
        replica.recompute_all_rows()?;
        replica.rebuild_aliases();
        Ok(replica)
    }
}
