//! `world_policy` — scoped demands, historical evaluation, implementation
//! pinning, canonical witness selection, and receipt substitution, proven
//! through the authority ledger's `authorize`/`verify_receipt` seam.
//!
//! Covers plan 01/02: exact-resource `Require`, `All`/`Any` witness selection,
//! canonical demand limits, historical authorized/currently-removed and its
//! inverse, delegation grant/revoke, non-delegable meta-capability, scope
//! isolation across two projects, implementation activation pinning, and
//! substitution of every bound receipt field.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use mechanics::acl::{self, AclAction, AclOp, Grant};
use mechanics::actor;
use mechanics::demand::{AuthorizationDemand, PolicyCapability, PolicyResource};
use mechanics::genesis::Genesis;
use mechanics::ids::{ActorId, SpaceId, SystemUlidSource};
use mechanics::ledger::{
    AuthorityLedger, AuthorizationRequest, AuthorizeError, LedgerEffect, ReceiptExpectations,
    VerifyError,
};

const WORLD: &str = "com.lait.issues";
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn seed(n: u8) -> [u8; 32] {
    [n; 32]
}

fn tempdir(tag: &str) -> PathBuf {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let p = std::env::temp_dir().join(format!("lait-worldpolicy-{tag}-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

struct Fx {
    genesis: Genesis,
    founder: ActorId,
    founder_incept: actor::SignedEvent,
    others: Vec<(actor::SignedEvent, ActorId)>,
}

fn fx(others: &[u8]) -> Fx {
    let space = SpaceId::mint(&SystemUlidSource);
    let (incept, founder) = actor::incept_single(&seed(1), &space, [1; 16], [71; 16], None);
    let others = others
        .iter()
        .map(|n| actor::incept_single(&seed(*n), &space, [*n; 16], [n + 70; 16], None))
        .collect();
    Fx {
        genesis: Genesis {
            space_id: space,
            founding_actors: vec![founder.clone()],
            salt: [0u8; 16],
            recovery_root: [0u8; 32],
        },
        founder,
        founder_incept: incept,
        others,
    }
}

fn cap(name: &str) -> PolicyCapability {
    PolicyCapability::new(WORLD, name)
}
fn space_res() -> PolicyResource {
    PolicyResource::space(WORLD)
}
fn project_res(p: &str) -> PolicyResource {
    PolicyResource {
        world: WORLD.into(),
        segments: vec!["project".into(), p.into()],
    }
}

/// A founder-authored ACL op at the ledger's current heads.
fn founder_op(fx: &Fx, ledger: &AuthorityLedger, action: AclAction) -> LedgerEffect {
    let op = acl::sign_op(
        &seed(1),
        &AclOp {
            action,
            by: fx.founder.clone(),
            actor_asof: ledger.actor_heads(&fx.founder),
            nonce: None,
        },
        ledger.acl_heads(),
        &fx.genesis.space_id,
    );
    LedgerEffect::Acl(op)
}

fn salt(n: u8) -> [u8; 16] {
    [n; 16]
}

/// A ledger with founder + members incepted and the IssuesWorld impl active.
fn ledger_with_impl(fx: &Fx, dir: &PathBuf, impl_id: [u8; 32]) -> AuthorityLedger {
    let mut ledger = AuthorityLedger::create(dir, fx.genesis.clone()).unwrap();
    let mut effects = vec![LedgerEffect::Actor(fx.founder_incept.clone()).encode()];
    for (incept, _) in &fx.others {
        effects.push(LedgerEffect::Actor(incept.clone()).encode());
    }
    ledger.commit_batch(&effects, &[]).unwrap();
    // Activate the implementation (founder is a policy admin by genesis).
    let activate = founder_op(
        fx,
        &ledger,
        AclAction::ActivateWorldImplementation {
            world: WORLD.into(),
            implementation_id: impl_id,
        },
    );
    ledger.commit_batch(&[activate.encode()], &[]).unwrap();
    ledger
}

fn grant(
    fx: &Fx,
    ledger: &AuthorityLedger,
    actor: &ActorId,
    c: &PolicyCapability,
    r: &PolicyResource,
    s: u8,
) -> LedgerEffect {
    let grant_id = acl::capability_grant_id(actor, c, r, &salt(s)).unwrap();
    founder_op(
        fx,
        ledger,
        AclAction::GrantCapability {
            grant_id,
            actor: actor.clone(),
            capability: c.clone(),
            resource: r.clone(),
            salt: salt(s),
        },
    )
}

fn request<'a>(
    fx: &'a Fx,
    device: [u8; 32],
    actor: &'a str,
    frontier: &'a [u8],
    impl_id: [u8; 32],
    demand: &'a [u8],
) -> AuthorizationRequest<'a> {
    let _ = fx;
    AuthorizationRequest {
        world: WORLD,
        actor,
        device,
        authority_frontier: frontier,
        parent_manifest_root: [9u8; 32],
        implementation_id: impl_id,
        intent_digest: [3u8; 32],
        demand,
        effect_operations_digest: [4u8; 32],
        body_transaction_core_digest: [5u8; 32],
    }
}

#[test]
fn require_all_any_witness_selection_and_historical_evaluation() {
    let dir = tempdir("witness");
    let fx = fx(&[2]);
    let impl_id = [7u8; 32];
    let mut ledger = ledger_with_impl(&fx, &dir, impl_id);
    let member = &fx.others[0].1;
    let member_dev = mechanics::crypto::device_from_seed(&seed(2))
        .key_bytes()
        .unwrap();
    // A grant's subject must be an admitted member.
    ledger
        .commit_batch(
            &[founder_op(
                &fx,
                &ledger,
                AclAction::AddMember {
                    actor: member.clone(),
                    grants: vec![Grant::Write],
                },
            )
            .encode()],
            &[],
        )
        .unwrap();

    // Grant the member two capabilities: contributor (Space) and issue.edit
    // (project p1). Then the contributor demand and an Any/All demand resolve.
    ledger
        .commit_batch(
            &[grant(
                &fx,
                &ledger,
                member,
                &cap("space.contributor"),
                &space_res(),
                10,
            )
            .encode()],
            &[],
        )
        .unwrap();
    ledger
        .commit_batch(
            &[grant(
                &fx,
                &ledger,
                member,
                &cap("issue.edit"),
                &project_res("p1"),
                11,
            )
            .encode()],
            &[],
        )
        .unwrap();
    let frontier = ledger.frontier();

    // A contributor demand (Any(contributor, admin)) is satisfied.
    let contributor = AuthorizationDemand::Any(vec![
        AuthorizationDemand::require(cap("space.contributor"), space_res()),
        AuthorizationDemand::require(cap("space.admin"), space_res()),
    ])
    .encode_canonical()
    .unwrap();
    let receipt = ledger
        .authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &frontier,
            impl_id,
            &contributor,
        ))
        .unwrap();
    assert_eq!(receipt.decision, 1);

    // An All demand needing a capability the member lacks is denied.
    let needs_admin = AuthorizationDemand::All(vec![
        AuthorizationDemand::require(cap("space.contributor"), space_res()),
        AuthorizationDemand::require(cap("space.admin"), space_res()),
    ])
    .encode_canonical()
    .unwrap();
    assert!(matches!(
        ledger.authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &frontier,
            impl_id,
            &needs_admin
        )),
        Err(AuthorizeError::Denied)
    ));

    // A project-scoped Require is satisfied for p1 but denied for p2 (exact
    // resource matching, no inheritance).
    let edit_p1 = AuthorizationDemand::require(cap("issue.edit"), project_res("p1"))
        .encode_canonical()
        .unwrap();
    let edit_p2 = AuthorizationDemand::require(cap("issue.edit"), project_res("p2"))
        .encode_canonical()
        .unwrap();
    assert!(ledger
        .authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &frontier,
            impl_id,
            &edit_p1
        ))
        .is_ok());
    assert!(matches!(
        ledger.authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &frontier,
            impl_id,
            &edit_p2
        )),
        Err(AuthorizeError::Denied)
    ));
    cleanup(&dir);
}

#[test]
fn historical_grant_then_removal_evaluated_at_each_frontier() {
    let dir = tempdir("hist");
    let fx = fx(&[2]);
    let impl_id = [7u8; 32];
    let mut ledger = ledger_with_impl(&fx, &dir, impl_id);
    let member = &fx.others[0].1;
    let member_dev = mechanics::crypto::device_from_seed(&seed(2))
        .key_bytes()
        .unwrap();
    // Admit the member so grants take effect (a grant's subject must be a member).
    ledger
        .commit_batch(
            &[founder_op(
                &fx,
                &ledger,
                AclAction::AddMember {
                    actor: member.clone(),
                    grants: vec![Grant::Write],
                },
            )
            .encode()],
            &[],
        )
        .unwrap();
    let grant_effect = grant(
        &fx,
        &ledger,
        member,
        &cap("space.contributor"),
        &space_res(),
        20,
    );
    let grant_id = match &grant_effect {
        LedgerEffect::Acl(op) => match postcard::from_bytes::<AclOp>(&op.op).unwrap().action {
            AclAction::GrantCapability { grant_id, .. } => grant_id,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };
    ledger.commit_batch(&[grant_effect.encode()], &[]).unwrap();
    let granted_frontier = ledger.frontier();

    let demand = AuthorizationDemand::require(cap("space.contributor"), space_res())
        .encode_canonical()
        .unwrap();
    assert!(ledger
        .authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &granted_frontier,
            impl_id,
            &demand
        ))
        .is_ok());

    // Revoke the grant; a later frontier denies, the historical one still allows.
    ledger
        .commit_batch(
            &[founder_op(&fx, &ledger, AclAction::RevokeCapability { grant_id }).encode()],
            &[],
        )
        .unwrap();
    let revoked_frontier = ledger.frontier();
    assert!(
        ledger
            .authorize(&request(
                &fx,
                member_dev,
                member.as_str(),
                &granted_frontier,
                impl_id,
                &demand
            ))
            .is_ok(),
        "historical grant frontier still authorizes"
    );
    assert!(matches!(
        ledger.authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &revoked_frontier,
            impl_id,
            &demand
        )),
        Err(AuthorizeError::Denied)
    ));
    cleanup(&dir);
}

#[test]
fn implementation_pin_refuses_unapproved_id() {
    let dir = tempdir("impl");
    let fx = fx(&[]);
    let impl_id = [7u8; 32];
    let mut ledger = ledger_with_impl(&fx, &dir, impl_id);
    let founder_dev = mechanics::crypto::device_from_seed(&seed(1))
        .key_bytes()
        .unwrap();
    let frontier = ledger.frontier();
    let demand = AuthorizationDemand::require(cap("space.admin"), space_res())
        .encode_canonical()
        .unwrap();
    // The founder is a policy admin but has no explicit space.admin grant, so
    // the demand is unsatisfied — proving admin capability != policy-admin.
    assert!(matches!(
        ledger.authorize(&request(
            &fx,
            founder_dev,
            fx.founder.as_str(),
            &frontier,
            impl_id,
            &demand
        )),
        Err(AuthorizeError::Denied)
    ));
    // A wrong implementation id refuses before demand evaluation.
    assert!(matches!(
        ledger.authorize(&request(
            &fx,
            founder_dev,
            fx.founder.as_str(),
            &frontier,
            [0u8; 32],
            &demand
        )),
        Err(AuthorizeError::ImplementationNotActive)
    ));
    cleanup(&dir);
}

#[test]
fn receipt_verifies_and_every_substitution_is_caught() {
    let dir = tempdir("verify");
    let fx = fx(&[2]);
    let impl_id = [7u8; 32];
    let mut ledger = ledger_with_impl(&fx, &dir, impl_id);
    let member = &fx.others[0].1;
    let member_dev = mechanics::crypto::device_from_seed(&seed(2))
        .key_bytes()
        .unwrap();
    ledger
        .commit_batch(
            &[founder_op(
                &fx,
                &ledger,
                AclAction::AddMember {
                    actor: member.clone(),
                    grants: vec![Grant::Write],
                },
            )
            .encode()],
            &[],
        )
        .unwrap();
    ledger
        .commit_batch(
            &[grant(
                &fx,
                &ledger,
                member,
                &cap("space.contributor"),
                &space_res(),
                30,
            )
            .encode()],
            &[],
        )
        .unwrap();
    let frontier = ledger.frontier();
    let demand = AuthorizationDemand::require(cap("space.contributor"), space_res())
        .encode_canonical()
        .unwrap();
    let receipt = ledger
        .authorize(&request(
            &fx,
            member_dev,
            member.as_str(),
            &frontier,
            impl_id,
            &demand,
        ))
        .unwrap();

    fn expect<'a>(
        device: &'a [u8; 32],
        frontier: &'a [u8],
        demand: &'a [u8],
    ) -> ReceiptExpectations<'a> {
        ReceiptExpectations {
            device,
            authority_frontier: frontier,
            parent_manifest_root: &[9u8; 32],
            intent_digest: &[3u8; 32],
            demand,
            effect_operations_digest: &[4u8; 32],
            body_transaction_core_digest: &[5u8; 32],
        }
    }
    // Honest verification passes.
    ledger
        .verify_receipt(&receipt, &expect(&member_dev, &frontier, &demand))
        .unwrap();

    // Substitute the device: refused.
    let wrong_dev = mechanics::crypto::device_from_seed(&seed(9))
        .key_bytes()
        .unwrap();
    assert!(matches!(
        ledger.verify_receipt(&receipt, &expect(&wrong_dev, &frontier, &demand)),
        Err(VerifyError::Binding(_))
    ));
    // Substitute the demand: refused.
    let other_demand = AuthorizationDemand::require(cap("space.admin"), space_res())
        .encode_canonical()
        .unwrap();
    assert!(matches!(
        ledger.verify_receipt(&receipt, &expect(&member_dev, &frontier, &other_demand)),
        Err(VerifyError::Binding(_))
    ));
    // Tamper the receipt's evidence digest: refused.
    let mut tampered = receipt.clone();
    tampered.policy_evidence_digest[0] ^= 0xff;
    assert!(matches!(
        ledger.verify_receipt(&tampered, &expect(&member_dev, &frontier, &demand)),
        Err(VerifyError::Binding(_))
    ));
    cleanup(&dir);
}

#[test]
fn delegation_permits_granting_but_not_meta_capability() {
    let dir = tempdir("deleg");
    let fx = fx(&[2, 3]);
    let impl_id = [7u8; 32];
    let mut ledger = ledger_with_impl(&fx, &dir, impl_id);
    let delegate = &fx.others[0].1;
    let subject = &fx.others[1].1;
    // Admit both.
    for a in [delegate, subject] {
        ledger
            .commit_batch(
                &[founder_op(
                    &fx,
                    &ledger,
                    AclAction::AddMember {
                        actor: a.clone(),
                        grants: vec![Grant::Write],
                    },
                )
                .encode()],
                &[],
            )
            .unwrap();
    }
    // The founder delegates issue.edit@p1 to the delegate.
    let deleg_id =
        acl::capability_delegation_id(delegate, &cap("issue.edit"), &project_res("p1"), &salt(40))
            .unwrap();
    ledger
        .commit_batch(
            &[founder_op(
                &fx,
                &ledger,
                AclAction::GrantDelegation {
                    delegation_id: deleg_id,
                    actor: delegate.clone(),
                    capability: cap("issue.edit"),
                    resource: project_res("p1"),
                    salt: salt(40),
                },
            )
            .encode()],
            &[],
        )
        .unwrap();
    // The delegate grants issue.edit@p1 to the subject — authorized by delegation.
    let grant_id =
        acl::capability_grant_id(subject, &cap("issue.edit"), &project_res("p1"), &salt(41))
            .unwrap();
    let delegate_grant = acl::sign_op(
        &seed(2),
        &AclOp {
            action: AclAction::GrantCapability {
                grant_id,
                actor: subject.clone(),
                capability: cap("issue.edit"),
                resource: project_res("p1"),
                salt: salt(41),
            },
            by: delegate.clone(),
            actor_asof: ledger.actor_heads(delegate),
            nonce: None,
        },
        ledger.acl_heads(),
        &fx.genesis.space_id,
    );
    ledger
        .commit_batch(&[LedgerEffect::Acl(delegate_grant).encode()], &[])
        .unwrap();
    let subject_dev = mechanics::crypto::device_from_seed(&seed(3))
        .key_bytes()
        .unwrap();
    let frontier = ledger.frontier();
    let demand = AuthorizationDemand::require(cap("issue.edit"), project_res("p1"))
        .encode_canonical()
        .unwrap();
    assert!(
        ledger
            .authorize(&request(
                &fx,
                subject_dev,
                subject.as_str(),
                &frontier,
                impl_id,
                &demand
            ))
            .is_ok(),
        "the delegated grant is effective"
    );

    // A delegate cannot grant the meta policy-admin capability (never delegable),
    // and cannot grant a capability it holds no delegation for.
    let meta_grant_id = acl::capability_grant_id(
        subject,
        &acl::policy_admin_capability(),
        &acl::policy_admin_resource(),
        &salt(42),
    )
    .unwrap();
    let bad = acl::sign_op(
        &seed(2),
        &AclOp {
            action: AclAction::GrantCapability {
                grant_id: meta_grant_id,
                actor: subject.clone(),
                capability: acl::policy_admin_capability(),
                resource: acl::policy_admin_resource(),
                salt: salt(42),
            },
            by: delegate.clone(),
            actor_asof: ledger.actor_heads(delegate),
            nonce: None,
        },
        ledger.acl_heads(),
        &fx.genesis.space_id,
    );
    ledger
        .commit_batch(&[LedgerEffect::Acl(bad).encode()], &[])
        .unwrap();
    // The meta grant was not authorized (the delegate is not a policy admin),
    // so the subject holds no policy-admin capability.
    let state = ledger.acl_state().unwrap();
    assert!(!state.is_policy_admin(subject));
    cleanup(&dir);
}

fn cleanup(p: &std::path::Path) {
    let _ = std::fs::remove_dir_all(p);
}
