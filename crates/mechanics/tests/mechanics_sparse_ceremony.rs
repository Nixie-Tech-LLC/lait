//! `mechanics_sparse_ceremony` — ordinary World/authority traffic invokes no
//! FROST (M3). Ten thousand ordinary signed authority operations and
//! historical authorization checks produce **zero** ceremony effects; an
//! explicit threshold command is the positive control that DOES emit ceremony
//! effects, proving the instrument distinguishes the two.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use mechanics::acl::{self, AclAction, AclOp, Grant};
use mechanics::actor;
use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};
use mechanics::genesis::Genesis;
use mechanics::ids::{ActorId, SpaceId, SystemUlidSource};
use mechanics::ledger::{AuthorityLedger, LedgerEffect};

const WORLD: &str = "com.lait.issues";
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn tempdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("lait-sparse-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn ten_thousand_ordinary_operations_invoke_no_ceremony() {
    let dir = tempdir("ordinary");
    let space = SpaceId::mint(&SystemUlidSource);
    let (incept, founder) = actor::incept_single(&seed(1), &space, [1; 16], [71; 16], None);
    let genesis = Genesis {
        space_id: space.clone(),
        founding_actors: vec![founder.clone()],
        salt: [0u8; 16],
        recovery_root: [0u8; 32],
    };
    let mut ledger = AuthorityLedger::create(&dir, genesis.clone()).unwrap();
    let (member_incept, member) = actor::incept_single(&seed(2), &space, [2; 16], [72; 16], None);
    ledger
        .commit_batch(
            &[
                LedgerEffect::Actor(incept).encode(),
                LedgerEffect::Actor(member_incept).encode(),
            ],
            &[],
        )
        .unwrap();
    // Admit the member so grants take effect.
    let add = acl::sign_op(
        &seed(1),
        &AclOp {
            action: AclAction::AddMember {
                actor: member.clone(),
                grants: vec![Grant::Write],
            },
            by: founder.clone(),
            actor_asof: ledger.actor_heads(&founder),
            nonce: None,
        },
        ledger.acl_heads(),
        &space,
    );
    ledger
        .commit_batch(&[LedgerEffect::Acl(add).encode()], &[])
        .unwrap();

    let res = PolicyResource::space(WORLD);
    let member_key = mechanics::crypto::device_from_seed(&seed(2))
        .key_bytes()
        .unwrap();
    let stranger_key = mechanics::crypto::device_from_seed(&seed(9))
        .key_bytes()
        .unwrap();

    // 500 ordinary authority mutations (capability grants) — each an ordinary
    // signed authority op, none a ceremony.
    for i in 0..500u32 {
        let cap = PolicyCapability::new(WORLD, "cap.0");
        let mut salt = [0u8; 16];
        salt[..4].copy_from_slice(&i.to_be_bytes());
        let grant_id = acl::capability_grant_id(&member, &cap, &res, &salt).unwrap();
        let op = acl::sign_op(
            &seed(1),
            &AclOp {
                action: AclAction::GrantCapability {
                    grant_id,
                    actor: member.clone(),
                    capability: cap,
                    resource: res.clone(),
                    salt,
                },
                by: founder.clone(),
                actor_asof: ledger.actor_heads(&founder),
                nonce: None,
            },
            ledger.acl_heads(),
            &space,
        );
        ledger
            .commit_batch(&[LedgerEffect::Acl(op).encode()], &[])
            .unwrap();
        assert!(
            ledger.ceremony_events().is_empty(),
            "an ordinary authority mutation must never emit a ceremony effect"
        );
    }

    // 10,000 historical authorization checks at the pinned current frontier —
    // ordinary read traffic. None touches FROST/DKG/transcript machinery.
    let frontier = ledger.frontier();
    let demand = AuthorizationDemand::require(PolicyCapability::new(WORLD, "cap.0"), res.clone())
        .encode_canonical()
        .unwrap();
    for i in 0..10_000u32 {
        let key = if i % 2 == 0 {
            &member_key
        } else {
            &stranger_key
        };
        let expect = i % 2 == 0;
        assert_eq!(ledger.signer_authorized_at(key, &frontier), expect);
        // Membership reads (also ordinary).
        let state = ledger.state_at(&frontier).unwrap();
        assert_eq!(state.signer_is_member(key), expect);
    }

    // The invariant: no ceremony effect exists after all this ordinary traffic.
    assert!(
        ledger.ceremony_events().is_empty(),
        "ordinary World/authority traffic must invoke no ceremony/FROST"
    );
    let _ = demand;
    let _ = ActorId::from_incept_hash;
    cleanup(&dir);
}

#[test]
fn an_explicit_ceremony_command_is_the_positive_control() {
    // The positive control: an explicit space/ceremony event DOES appear as a
    // ceremony effect, so the instrument above genuinely distinguishes
    // ordinary traffic from ceremonies.
    let dir = tempdir("ceremony");
    let space = SpaceId::mint(&SystemUlidSource);
    let (incept, founder) = actor::incept_single(&seed(1), &space, [1; 16], [71; 16], None);
    let genesis = Genesis {
        space_id: space.clone(),
        founding_actors: vec![founder],
        salt: [0u8; 16],
        recovery_root: [0u8; 32],
    };
    let mut ledger = AuthorityLedger::create(&dir, genesis).unwrap();
    ledger
        .commit_batch(&[LedgerEffect::Actor(incept).encode()], &[])
        .unwrap();
    assert!(ledger.ceremony_events().is_empty());

    // A signed space/ceremony event (the elevation/recovery control plane) —
    // the kind a FROST elevation produces and installs.
    let ceremony = mechanics::space::sign_op(
        &seed(1),
        &mechanics::space::SpaceOp::Rotate {
            new_recovery_key: mechanics::space::recovery_pub_of(&seed(9)),
            next_configuration: mechanics::authority::AuthorityConfigurationId::single(),
            gen: 1,
        },
        vec![],
        &space,
    );
    ledger
        .commit_batch(&[LedgerEffect::Ceremony(ceremony).encode()], &[])
        .unwrap();
    assert_eq!(
        ledger.ceremony_events().len(),
        1,
        "an explicit ceremony command emits a ceremony effect"
    );
    cleanup(&dir);
}

fn cleanup(p: &std::path::Path) {
    let _ = std::fs::remove_dir_all(p);
}
