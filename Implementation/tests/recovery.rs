use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tspa::{
    protocols::{messages::*, system::System},
    transport::{InMemoryTransport, Node, Packet, Target, Transport},
};

struct RecoveryTransport {
    memory: InMemoryTransport,
    lose_ls_reply: AtomicBool,
    block_ls_probe: AtomicBool,
    fail_store_count: AtomicUsize,
    block_provider: AtomicBool,
    release: tokio::sync::Notify,
    ls_release: tokio::sync::Notify,
    withhold_ls: AtomicBool,
}

#[async_trait]
impl Transport for RecoveryTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        if target == Target::LoginServer {
            if matches!(request, Request::Ls(LsRequest::Authenticate { .. }))
                && self.block_ls_probe.load(Ordering::SeqCst)
            {
                return Err("LS probe unavailable".into());
            }
            if matches!(request, Request::Ls(LsRequest::ChangeCredential { .. }))
                && self.withhold_ls.load(Ordering::SeqCst)
            {
                self.ls_release.notified().await;
                return Err("LS unavailable".into());
            }
        }
        if target == Target::Provider(3)
            && self.block_provider.load(Ordering::SeqCst)
            && matches!(request, Request::Up(UpRequest::Identify { .. }))
        {
            self.release.notified().await;
        }
        let lose_ls = matches!(request, Request::Ls(LsRequest::ChangeCredential { .. }))
            && self.lose_ls_reply.swap(false, Ordering::SeqCst);
        let lose_store = target == Target::Provider(3)
            && matches!(
                request,
                Request::Up(UpRequest::Finalize { store: true, .. })
            )
            && self
                .fail_store_count
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok();
        let packet = self.memory.call(target, request).await?;
        if lose_ls || lose_store {
            Err("injected lost acknowledgement after processing".into())
        } else {
            Ok(packet)
        }
    }
}

async fn fixture() -> (Arc<RecoveryTransport>, System) {
    let transport = Arc::new(RecoveryTransport {
        memory: InMemoryTransport::new(3, 300000),
        lose_ls_reply: AtomicBool::new(false),
        block_ls_probe: AtomicBool::new(false),
        fail_store_count: AtomicUsize::new(0),
        block_provider: AtomicBool::new(false),
        release: tokio::sync::Notify::new(),
        ls_release: tokio::sync::Notify::new(),
        withhold_ls: AtomicBool::new(false),
    });
    let mut system =
        System::new(3, 2, transport.clone(), [11; 32], Duration::from_secs(3)).unwrap();
    system.setup(b"alice", b"pwd").await.unwrap();
    system
        .registration(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
    system.clear_trace();
    (transport, system)
}

#[tokio::test]
async fn lost_store_ack_does_not_reverse_ls_acceptance_or_retry() {
    let (transport, mut system) = fixture().await;
    transport.fail_store_count.store(1, Ordering::SeqCst);
    system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
    assert_eq!(
        system
            .trace
            .lock()
            .unwrap()
            .stages
            .iter()
            .filter(|s| s.stage == "finalization")
            .count(),
        1
    );
    system
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
}

#[tokio::test]
async fn unknown_ls_result_is_resolved_before_provider_finalization() {
    let (transport, mut system) = fixture().await;
    system = system.with_ls_outcome_probe(true);
    transport.lose_ls_reply.store(true, Ordering::SeqCst);
    system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
    assert!(system
        .trace
        .lock()
        .unwrap()
        .stages
        .iter()
        .any(|s| s.stage == "ls_recovery"));
    assert!(!system
        .trace
        .lock()
        .unwrap()
        .calls
        .iter()
        .any(|c| c.operation == "discard_ack"));
    system
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
}

#[tokio::test]
async fn final_reply_failure_does_not_block_the_next_operation() {
    let (transport, mut system) = fixture().await;
    transport.fail_store_count.store(3, Ordering::SeqCst);
    system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system
        .password_update(b"alice", b"pwd", b"new")
        .await
        .unwrap();
    system
        .authentication(b"alice", b"new", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
    for node in transport.memory.nodes.values() {
        if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
            assert!(upspa.pending.is_empty());
        }
    }
}

#[tokio::test]
async fn authentication_returns_after_safe_threshold_before_slow_provider() {
    let (transport, mut system) = fixture().await;
    transport.block_provider.store(true, Ordering::SeqCst);
    tokio::time::timeout(
        Duration::from_secs(1),
        system.authentication(b"alice", b"pwd", b"LS1", b"stable"),
    )
    .await
    .unwrap()
    .unwrap();
    transport.release.notify_one();
    system.settle().await;
    assert_eq!(
        system
            .trace
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.operation == "identification")
            .count(),
        3
    );
}

#[tokio::test]
async fn default_lost_ls_reply_discards_every_preparation_without_probing() {
    let (transport, mut system) = fixture().await;
    let old_accounts: Vec<_> = transport
        .memory
        .nodes
        .values()
        .filter_map(|node| {
            if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
                Some((upspa.provider_id, upspa.accounts.clone()))
            } else {
                None
            }
        })
        .collect();
    transport.lose_ls_reply.store(true, Ordering::SeqCst);
    assert!(system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    system.settle().await;
    let trace = system.trace.lock().unwrap();
    assert!(!trace.stages.iter().any(|s| s.stage == "ls_recovery"));
    assert_eq!(
        trace
            .calls
            .iter()
            .filter(|c| c.operation == "discard_ack")
            .count(),
        3
    );
    drop(trace);
    for (id, accounts) in old_accounts {
        let node = transport.memory.nodes[&Target::Provider(id)]
            .lock()
            .unwrap();
        let Node::Provider { upspa, .. } = &*node else {
            unreachable!()
        };
        assert!(upspa.pending.is_empty());
        assert_eq!(upspa.accounts, accounts);
    }
    assert!(system.resume_finalization().await.is_err());
}

#[tokio::test]
async fn default_ls_deadline_discards_without_waiting_for_the_late_reply() {
    let (transport, mut previous) = fixture().await;
    previous.settle().await;
    let mut system =
        System::new(3, 2, transport.clone(), [15; 32], Duration::from_millis(40)).unwrap();
    transport.withhold_ls.store(true, Ordering::SeqCst);
    assert!(tokio::time::timeout(
        Duration::from_secs(1),
        system.secret_update(b"alice", b"pwd", b"LS1", b"stable")
    )
    .await
    .unwrap()
    .is_err());
    assert_eq!(
        system
            .trace
            .lock()
            .unwrap()
            .calls
            .iter()
            .filter(|c| c.operation == "discard_ack")
            .count(),
        3
    );
    for node in transport.memory.nodes.values() {
        if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
            assert!(upspa.pending.is_empty());
        }
    }
    transport.ls_release.notify_one();
    system.settle().await;
    system
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
}

#[tokio::test]
async fn opt_in_unresolved_probe_blocks_operations_and_can_resume() {
    let (transport, mut system) = fixture().await;
    system = system.with_ls_outcome_probe(true);
    transport.lose_ls_reply.store(true, Ordering::SeqCst);
    transport.block_ls_probe.store(true, Ordering::SeqCst);
    assert!(system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    assert!(system
        .password_update(b"alice", b"pwd", b"new")
        .await
        .is_err());
    for node in transport.memory.nodes.values() {
        if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
            assert_eq!(upspa.pending.len(), 1);
        }
    }
    transport.block_ls_probe.store(false, Ordering::SeqCst);
    system.resume_finalization().await.unwrap();
    system
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .unwrap();
    system.settle().await;
}
