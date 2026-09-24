use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar;
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tspa::{
    crypto,
    protocols::{
        login_server::LoginServer,
        messages::*,
        provider::UpSpaProvider,
        system::{account_context, unique_agreement, Requirement, System},
    },
    transport::{InMemoryTransport, Node, Packet, Target, Transport},
};

fn root() -> Root {
    Root {
        uid: b"alice".to_vec(),
        svk: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
        cid: vec![7; ROOT_LEN + 40],
        share: Scalar::from(9u64).to_bytes(),
        timestamp: 0,
    }
}

fn binding(phase: Phase, sid: u8, record: RecordId) -> Binding {
    Binding {
        sid: [sid; 16],
        phase,
        record,
    }
}
fn root_binding(phase: Phase, sid: u8) -> Binding {
    binding(phase, sid, RecordId::Root(b"alice".to_vec()))
}
fn setup(provider: &mut UpSpaProvider) {
    provider
        .handle(
            UpRequest::Setup {
                sid: [1; 16],
                root: root(),
            },
            100,
        )
        .unwrap();
}
fn finish(provider: &mut UpSpaProvider, binding: Binding, store: bool) -> Reply {
    provider
        .handle(UpRequest::Finalize { binding, store }, 100)
        .unwrap()
}
fn committed() -> UpSpaProvider {
    let mut provider = UpSpaProvider::new(1, 1000);
    setup(&mut provider);
    finish(&mut provider, root_binding(Phase::Setup, 1), true);
    provider
}
fn update() -> PasswordUpdate {
    let mut update = PasswordUpdate {
        operation: "PwdUpdate".into(),
        sid: [2; 16],
        uid: b"alice".to_vec(),
        provider_id: 1,
        timestamp_old: 0,
        timestamp_new: 100,
        cid_new: vec![8; ROOT_LEN + 40],
        share_new: Scalar::from(19u64).to_bytes(),
        signature: Vec::new(),
    };
    sign(&mut update);
    update
}
fn sign(update: &mut PasswordUpdate) {
    update.signature = SigningKey::from_bytes(&[11; 32])
        .sign(&update.signed_bytes())
        .to_bytes()
        .to_vec();
}

#[test]
fn setup_is_pending_until_store() {
    let mut provider = UpSpaProvider::new(1, 1000);
    setup(&mut provider);
    assert!(provider.roots.is_empty());
    assert!(provider
        .handle(
            UpRequest::Identify {
                uid: b"alice".to_vec(),
                blinded: crypto::hash_to_point(b"pwd").compress().to_bytes()
            },
            100
        )
        .is_err());
    finish(&mut provider, root_binding(Phase::Setup, 1), true);
    assert_eq!(provider.roots[b"alice".as_slice()], root());
}

#[test]
fn setup_discard_leaves_no_root() {
    let mut provider = UpSpaProvider::new(1, 1000);
    setup(&mut provider);
    finish(&mut provider, root_binding(Phase::Setup, 1), false);
    assert!(provider.roots.is_empty());
    assert!(provider.pending.is_empty());
    assert!(provider
        .handle(
            UpRequest::Setup {
                sid: [1; 16],
                root: root()
            },
            100
        )
        .is_err());
}

#[test]
fn finalization_is_sid_bound() {
    let mut provider = UpSpaProvider::new(1, 1000);
    setup(&mut provider);
    assert_eq!(
        finish(&mut provider, root_binding(Phase::Setup, 2), true),
        Reply::Ack(false)
    );
    assert_eq!(
        finish(&mut provider, root_binding(Phase::Setup, 2), false),
        Reply::Ack(false)
    );
    assert!(provider.roots.is_empty());
    assert_eq!(provider.pending.len(), 1);
}

#[test]
fn finalization_is_phase_bound() {
    let mut provider = UpSpaProvider::new(1, 1000);
    setup(&mut provider);
    assert_eq!(
        finish(&mut provider, root_binding(Phase::PasswordUpdate, 1), true),
        Reply::Ack(false)
    );
    assert!(provider.roots.is_empty());
    assert_eq!(provider.pending.len(), 1);
}

#[test]
fn finalization_is_record_bound_and_replay_has_no_effect() {
    let mut provider = committed();
    let old = provider.roots.clone();
    let wrong = binding(Phase::Setup, 1, RecordId::Root(b"bob".to_vec()));
    assert_eq!(finish(&mut provider, wrong, true), Reply::Ack(false));
    assert_eq!(
        finish(&mut provider, root_binding(Phase::Setup, 1), true),
        Reply::Ack(true)
    );
    finish(&mut provider, root_binding(Phase::Setup, 1), false);
    assert_eq!(provider.roots, old);
    provider
        .handle(UpRequest::PasswordUpdate(update()), 100)
        .unwrap();
    finish(&mut provider, root_binding(Phase::Setup, 1), false);
    assert_eq!(provider.pending.len(), 1);
}

#[test]
fn pending_accounts_are_not_served() {
    let mut provider = committed();
    provider
        .handle(
            UpRequest::PrepareAccount {
                binding: binding(Phase::Registration, 3, RecordId::Account([4; 32])),
                ciphertext: vec![2; ACCOUNT_LEN + 40],
                expected: None,
            },
            100,
        )
        .unwrap();
    assert!(provider
        .handle(UpRequest::ReadAccount { suid: [4; 32] }, 100)
        .is_err());
    finish(
        &mut provider,
        binding(Phase::Registration, 3, RecordId::Account([4; 32])),
        true,
    );
    assert_eq!(
        provider
            .handle(UpRequest::ReadAccount { suid: [4; 32] }, 100)
            .unwrap(),
        Reply::Account(vec![2; ACCOUNT_LEN + 40])
    );
}

#[test]
fn password_update_atomically_switches_cid_share_timestamp_and_keeps_svk() {
    let mut provider = committed();
    let old = provider.roots[b"alice".as_slice()].clone();
    let request = update();
    provider
        .handle(UpRequest::PasswordUpdate(request.clone()), 100)
        .unwrap();
    assert_eq!(provider.roots[b"alice".as_slice()], old);
    finish(&mut provider, root_binding(Phase::PasswordUpdate, 2), true);
    let new = &provider.roots[b"alice".as_slice()];
    assert_eq!(new.cid, request.cid_new);
    assert_eq!(new.share, request.share_new);
    assert_eq!(new.timestamp, 100);
    assert_eq!(new.svk, old.svk);
}

#[test]
fn password_discard_preserves_old_root() {
    let mut provider = committed();
    let old = provider.roots.clone();
    provider
        .handle(UpRequest::PasswordUpdate(update()), 100)
        .unwrap();
    finish(&mut provider, root_binding(Phase::PasswordUpdate, 2), false);
    assert_eq!(provider.roots, old);
}

#[test]
fn password_signature_binds_every_required_field() {
    let original = update();
    let mut changed = Vec::new();
    let mut item = original.clone();
    item.operation = "Other".into();
    changed.push(item);
    let mut item = original.clone();
    item.sid[0] ^= 1;
    changed.push(item);
    let mut item = original.clone();
    item.uid.push(0);
    changed.push(item);
    let mut item = original.clone();
    item.provider_id = 2;
    changed.push(item);
    let mut item = original.clone();
    item.timestamp_old = 1;
    changed.push(item);
    let mut item = original.clone();
    item.timestamp_new = 101;
    changed.push(item);
    let mut item = original.clone();
    item.cid_new[0] ^= 1;
    changed.push(item);
    let mut item = original.clone();
    item.share_new = Scalar::from(20u64).to_bytes();
    changed.push(item);
    for request in changed {
        let mut provider = committed();
        assert!(provider
            .handle(UpRequest::PasswordUpdate(request), 100)
            .is_err());
        assert!(provider.pending.is_empty());
    }
}

#[test]
fn signed_wrong_provider_index_is_rejected() {
    let mut u = update();
    u.provider_id = 2;
    sign(&mut u);
    assert!(committed()
        .handle(UpRequest::PasswordUpdate(u), 100)
        .is_err());
}
#[test]
fn signed_old_timestamp_mismatch_is_rejected() {
    let mut u = update();
    u.timestamp_old = 1;
    sign(&mut u);
    assert!(committed()
        .handle(UpRequest::PasswordUpdate(u), 100)
        .is_err());
}
#[test]
fn signed_nonincreasing_timestamp_is_rejected() {
    let mut u = update();
    u.timestamp_new = 0;
    sign(&mut u);
    assert!(committed()
        .handle(UpRequest::PasswordUpdate(u), 100)
        .is_err());
}
#[test]
fn signed_wrong_operation_is_rejected() {
    let mut u = update();
    u.operation = "Setup".into();
    sign(&mut u);
    assert!(committed()
        .handle(UpRequest::PasswordUpdate(u), 100)
        .is_err());
}
#[test]
fn clock_window_is_enforced() {
    assert!(committed()
        .handle(UpRequest::PasswordUpdate(update()), 2000)
        .is_err());
}

fn identification_reply(cid: u8, timestamp: u64) -> Reply {
    Reply::Identification {
        cid: vec![cid; ROOT_LEN + 40],
        timestamp,
        contribution: crypto::hash_to_point(b"pwd").compress().to_bytes(),
    }
}

#[test]
fn identification_uses_exact_ciphertext_and_timestamp() {
    let replies = vec![
        (1, identification_reply(1, 0)),
        (2, identification_reply(1, 1)),
        (3, identification_reply(2, 0)),
    ];
    assert!(unique_agreement(&replies, 2, 0).is_err());
}
#[test]
fn unsupported_higher_timestamp_is_not_selected() {
    let replies = vec![
        (1, identification_reply(1, 4)),
        (2, identification_reply(1, 4)),
        (3, identification_reply(2, 9000)),
    ];
    let accepted = unique_agreement(&replies, 2, 0).unwrap().unwrap();
    assert_eq!(accepted.len(), 2);
    assert_eq!(accepted[0].1, identification_reply(1, 4));
}
#[test]
fn agreement_rejects_duplicate_provider_ids() {
    assert!(unique_agreement(
        &[
            (1, identification_reply(1, 0)),
            (1, identification_reply(1, 0))
        ],
        2,
        0
    )
    .is_err());
}
#[test]
fn account_agreement_requires_exact_bytes_and_rejects_ambiguity() {
    let a = Reply::Account(vec![1; ACCOUNT_LEN + 40]);
    let b = Reply::Account(vec![2; ACCOUNT_LEN + 40]);
    assert!(unique_agreement(&[(1, a.clone()), (2, b.clone())], 2, 0).is_err());
    assert!(unique_agreement(&[(1, a.clone()), (2, a), (3, b.clone()), (4, b)], 2, 0).is_err());
}
#[test]
fn threshold_waits_until_unseen_responses_cannot_create_ambiguity() {
    let a = Reply::Account(vec![1; ACCOUNT_LEN + 40]);
    assert!(unique_agreement(&[(1, a.clone()), (2, a.clone())], 2, 2)
        .unwrap()
        .is_none());
    assert!(unique_agreement(&[(1, a.clone()), (2, a)], 2, 1)
        .unwrap()
        .is_some());
}
#[test]
fn account_ciphertext_binds_uid_and_ls_only() {
    let mut rng = ChaCha20Rng::from_seed([2; 32]);
    let ciphertext = crypto::xchacha_encrypt_detached(
        &[1; 32],
        &account_context(b"alice", b"LS1"),
        &[9; ACCOUNT_LEN],
        &mut rng,
    );
    assert!(crypto::xchacha_decrypt_detached(
        &[1; 32],
        &account_context(b"alice", b"LS1"),
        &ciphertext
    )
    .is_ok());
    assert!(crypto::xchacha_decrypt_detached(
        &[1; 32],
        &account_context(b"alice", b"LS2"),
        &ciphertext
    )
    .is_err());
    assert!(crypto::xchacha_decrypt_detached(
        &[1; 32],
        &account_context(b"bob", b"LS1"),
        &ciphertext
    )
    .is_err());
    let decoded: (String, Vec<u8>, Vec<u8>) =
        bincode::deserialize(&account_context(b"alice", b"LS1")).unwrap();
    assert_eq!(
        decoded,
        ("account".into(), b"alice".to_vec(), b"LS1".to_vec())
    );
}
#[test]
fn root_and_identification_wire_have_no_context_counter_or_svk_agreement_field() {
    let value = serde_json::to_value(root()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    assert!(value.get("ctx_id").is_none());
    assert!(value.get("ctr_id").is_none());
    let response = serde_json::to_string(&identification_reply(1, 0)).unwrap();
    assert!(!response.contains("svk"));
    assert!(response.contains("timestamp"));
}

fn system(memory: Arc<dyn Transport>, n: usize, t: usize) -> System {
    System::new(n, t, memory, [5; 32], Duration::from_secs(3)).unwrap()
}
async fn account(system: &mut System) {
    system.setup(b"alice", b"pwd").await.unwrap();
    system
        .registration(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
}

#[tokio::test]
async fn all_five_phases_and_password_change_work() {
    let memory = Arc::new(InMemoryTransport::new(3, 300000));
    let mut sys = system(memory, 3, 2);
    account(&mut sys).await;
    sys.authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.password_update(b"alice", b"pwd", b"new").await.unwrap();
    assert!(sys
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    sys.authentication(b"alice", b"new", b"LS1", b"stable")
        .await
        .unwrap();
    sys.settle().await;
}

#[tokio::test]
async fn identification_does_not_compare_provider_svk() {
    let memory = Arc::new(InMemoryTransport::new(3, 300000));
    let mut sys = system(memory.clone(), 3, 2);
    sys.setup(b"alice", b"pwd").await.unwrap();
    sys.settle().await;
    for id in 1..=3 {
        let mut node = memory.nodes[&Target::Provider(id)].lock().unwrap();
        if let Node::Provider { upspa, .. } = &mut *node {
            upspa.roots.get_mut(b"alice".as_slice()).unwrap().svk =
                SigningKey::from_bytes(&[id as u8; 32])
                    .verifying_key()
                    .to_bytes();
        }
    }
    sys.identification(b"alice", b"pwd", Requirement::AllProviders)
        .await
        .unwrap();
    sys.settle().await;
}

#[tokio::test]
async fn a_single_larger_account_counter_cannot_win() {
    let memory = Arc::new(InMemoryTransport::new(3, 300000));
    let mut sys = system(memory.clone(), 3, 2);
    account(&mut sys).await;
    let state = sys
        .identification(b"alice", b"pwd", Requirement::AllProviders)
        .await
        .unwrap();
    let mut plaintext = [99; ACCOUNT_LEN];
    plaintext[32..].copy_from_slice(&99999u64.to_le_bytes());
    let ciphertext = crypto::xchacha_encrypt_detached(
        &state.k0,
        &account_context(b"alice", b"LS1"),
        &plaintext,
        &mut ChaCha20Rng::from_seed([1; 32]),
    )
    .encode();
    {
        let mut node = memory.nodes[&Target::Provider(3)].lock().unwrap();
        if let Node::Provider { upspa, .. } = &mut *node {
            upspa
                .accounts
                .insert(crypto::hash_upspa_suid(&state.rsp, b"LS1", 3), ciphertext);
        }
    }
    sys.authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.settle().await;
}

struct FaultTransport {
    memory: InMemoryTransport,
    fail_prepare: AtomicBool,
    fail_identify: AtomicBool,
    barrier: Option<Arc<tokio::sync::Barrier>>,
}
#[async_trait]
impl Transport for FaultTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        if matches!(request, Request::Up(UpRequest::Setup { .. })) {
            if let Some(barrier) = &self.barrier {
                barrier.wait().await;
            }
        }
        if target == Target::Provider(3)
            && ((self.fail_prepare.load(Ordering::Relaxed)
                && matches!(request, Request::Up(UpRequest::PrepareAccount { .. })))
                || (self.fail_identify.load(Ordering::Relaxed)
                    && matches!(request, Request::Up(UpRequest::Identify { .. }))))
        {
            return Ok(Packet {
                response: Response {
                    result: Err("injected provider failure".into()),
                    processing_ns: 0,
                },
                bytes_sent: 0,
                bytes_received: 0,
            });
        }
        self.memory.call(target, request).await
    }
}

#[tokio::test]
async fn setup_requests_are_genuinely_concurrent() {
    let memory = Arc::new(FaultTransport {
        memory: InMemoryTransport::new(3, 300000),
        fail_prepare: AtomicBool::new(false),
        fail_identify: AtomicBool::new(false),
        barrier: Some(Arc::new(tokio::sync::Barrier::new(3))),
    });
    let mut sys = system(memory, 3, 2);
    tokio::time::timeout(Duration::from_secs(2), sys.setup(b"alice", b"pwd"))
        .await
        .unwrap()
        .unwrap();
    sys.settle().await;
}

#[tokio::test]
async fn secret_update_failure_before_ls_preserves_old_state_and_writes_need_all_providers() {
    let memory = Arc::new(FaultTransport {
        memory: InMemoryTransport::new(3, 300000),
        fail_prepare: AtomicBool::new(false),
        fail_identify: AtomicBool::new(false),
        barrier: None,
    });
    let mut sys = system(memory.clone(), 3, 2);
    account(&mut sys).await;
    memory.fail_prepare.store(true, Ordering::Relaxed);
    sys.clear_trace();
    assert!(sys
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    sys.settle().await;
    assert!(!sys
        .trace
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|c| c.operation == "ls_change_credential"));
    sys.authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.settle().await;
    for node in memory.memory.nodes.values() {
        if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
            assert!(upspa.pending.is_empty());
        }
    }
}

#[tokio::test]
async fn authentication_allows_threshold_but_write_identification_requires_all() {
    let memory = Arc::new(FaultTransport {
        memory: InMemoryTransport::new(3, 300000),
        fail_prepare: AtomicBool::new(false),
        fail_identify: AtomicBool::new(false),
        barrier: None,
    });
    let mut sys = system(memory.clone(), 3, 2);
    account(&mut sys).await;
    memory.fail_identify.store(true, Ordering::Relaxed);
    sys.authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    assert!(sys.password_update(b"alice", b"pwd", b"new").await.is_err());
    sys.settle().await;
}

#[tokio::test]
async fn registration_and_secret_update_respect_causal_stages() {
    let memory = Arc::new(InMemoryTransport::new(3, 300000));
    let mut sys = system(memory, 3, 2);
    sys.setup(b"alice", b"pwd").await.unwrap();
    sys.settle().await;
    sys.clear_trace();
    sys.registration(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.settle().await;
    assert_eq!(
        sys.trace
            .lock()
            .unwrap()
            .stages
            .iter()
            .map(|s| s.stage.as_str())
            .collect::<Vec<_>>(),
        vec![
            "identification",
            "provider_prepare",
            "ls_interaction",
            "finalization"
        ]
    );
    sys.clear_trace();
    sys.secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    sys.settle().await;
    assert_eq!(
        sys.trace
            .lock()
            .unwrap()
            .stages
            .iter()
            .map(|s| s.stage.as_str())
            .collect::<Vec<_>>(),
        vec![
            "identification",
            "account_recovery",
            "provider_prepare",
            "ls_interaction",
            "finalization"
        ]
    );
}

#[tokio::test]
async fn ls_rejection_discards_registration_accounts() {
    let memory = Arc::new(InMemoryTransport::new(3, 300000));
    let mut sys = system(memory.clone(), 3, 2);
    sys.setup(b"alice", b"pwd").await.unwrap();
    memory
        .call(
            Target::LoginServer,
            Request::Ls(LsRequest::Register {
                uid: b"stable".to_vec(),
                verifier: [0; 32],
            }),
        )
        .await
        .unwrap();
    assert!(sys
        .registration(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    sys.settle().await;
    for id in 1..=3 {
        if let Node::Provider { upspa, .. } = &*memory.nodes[&Target::Provider(id)].lock().unwrap()
        {
            assert!(upspa.accounts.is_empty());
            assert!(upspa.pending.is_empty());
        }
    }
}

#[test]
fn ordinary_login_server_interfaces() {
    let mut ls = LoginServer::default();
    ls.handle(LsRequest::Register {
        uid: b"stable".to_vec(),
        verifier: [1; 32],
    })
    .unwrap();
    assert!(ls
        .handle(LsRequest::Register {
            uid: b"stable".to_vec(),
            verifier: [2; 32]
        })
        .is_err());
    assert!(ls
        .handle(LsRequest::ChangeCredential {
            uid: b"stable".to_vec(),
            old: [2; 32],
            new: [3; 32]
        })
        .is_err());
    ls.handle(LsRequest::ChangeCredential {
        uid: b"stable".to_vec(),
        old: [1; 32],
        new: [3; 32],
    })
    .unwrap();
    assert_eq!(
        ls.handle(LsRequest::Authenticate {
            uid: b"stable".to_vec(),
            verifier: [3; 32]
        })
        .unwrap(),
        Reply::Ack(true)
    );
}
