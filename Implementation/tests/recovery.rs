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
    fail_store_count: AtomicUsize,
    block_provider: AtomicBool,
    release: tokio::sync::Notify,
}

#[async_trait]
impl Transport for RecoveryTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
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
        fail_store_count: AtomicUsize::new(0),
        block_provider: AtomicBool::new(false),
        release: tokio::sync::Notify::new(),
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
async fn lost_store_ack_is_retried_after_ls_change() {
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
        2
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
async fn incomplete_finalization_can_resume_without_changing_state_twice() {
    let (transport, mut system) = fixture().await;
    transport.fail_store_count.store(3, Ordering::SeqCst);
    assert!(system
        .secret_update(b"alice", b"pwd", b"LS1", b"stable")
        .await
        .is_err());
    assert!(system
        .password_update(b"alice", b"pwd", b"new")
        .await
        .is_err());
    system.resume_finalization().await.unwrap();
    system
        .authentication(b"alice", b"pwd", b"LS1", b"stable")
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
