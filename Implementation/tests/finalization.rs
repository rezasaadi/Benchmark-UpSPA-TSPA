use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tspa::{
    protocols::{messages::*, system::System},
    transport::{InMemoryTransport, Node, Packet, Target, Transport},
};

struct FinalTransport {
    memory: InMemoryTransport,
    fault: AtomicU8,
    release: tokio::sync::Notify,
}

#[async_trait]
impl Transport for FinalTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        let final_call = target == Target::Provider(3)
            && matches!(request, Request::Up(UpRequest::Finalize { .. }));
        let mut packet = self.memory.call(target, request).await?;
        if final_call {
            match self.fault.load(Ordering::SeqCst) {
                1 => self.release.notified().await,
                2 => packet.response.result = Ok(Reply::Ack(false)),
                3 => return Err("lost final reply".into()),
                _ => {}
            }
        }
        Ok(packet)
    }
}

async fn invoke(system: &mut System, phase: Phase) -> Result<()> {
    match phase {
        Phase::Setup => system.setup(b"alice", b"pwd").await,
        Phase::Registration => {
            system
                .registration(b"alice", b"pwd", b"LS1", b"alice")
                .await
        }
        Phase::SecretUpdate => {
            system
                .secret_update(b"alice", b"pwd", b"LS1", b"alice")
                .await
        }
        Phase::PasswordUpdate => system.password_update(b"alice", b"pwd", b"new").await,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn every_store_phase_keeps_its_result_when_a_final_reply_is_missing_or_fail() {
    let bound = Duration::from_millis(40);
    for phase in [
        Phase::Setup,
        Phase::Registration,
        Phase::SecretUpdate,
        Phase::PasswordUpdate,
    ] {
        for fault in [1, 2, 3] {
            let transport = Arc::new(FinalTransport {
                memory: InMemoryTransport::new(3, 300_000),
                fault: AtomicU8::new(0),
                release: tokio::sync::Notify::new(),
            });
            let mut system = System::new(3, 2, transport.clone(), [17; 32], Duration::from_secs(2))
                .unwrap()
                .with_delivery_bound(bound);
            if phase != Phase::Setup {
                system.setup(b"alice", b"pwd").await.unwrap();
            }
            if phase == Phase::SecretUpdate {
                system
                    .registration(b"alice", b"pwd", b"LS1", b"alice")
                    .await
                    .unwrap();
            }
            system.settle().await;
            system.clear_trace();
            transport.fault.store(fault, Ordering::SeqCst);
            let start = Instant::now();
            tokio::time::timeout(Duration::from_secs(1), invoke(&mut system, phase))
                .await
                .unwrap()
                .unwrap();
            if fault != 2 {
                assert!(start.elapsed() >= bound);
            }
            {
                let trace = system.trace.lock().unwrap();
                assert_eq!(
                    trace
                        .stages
                        .iter()
                        .filter(|s| s.stage == "finalization")
                        .count(),
                    1
                );
                let call = trace
                    .calls
                    .iter()
                    .find(|call| {
                        call.target == Target::Provider(3) && call.operation == "store_ack"
                    })
                    .unwrap();
                assert!(!call.success);
                assert_eq!(call.reply_missing_at_bound, fault != 2);
            }
            transport.release.notify_one();
            system.settle().await;
            let trace = system.trace.lock().unwrap();
            assert_eq!(
                trace
                    .calls
                    .iter()
                    .filter(|c| c.operation == "store_ack")
                    .count(),
                3
            );
            assert_eq!(
                trace
                    .calls
                    .iter()
                    .filter(|c| c.reply_missing_at_bound)
                    .count(),
                usize::from(fault != 2)
            );
            drop(trace);
            for node in transport.memory.nodes.values() {
                if let Node::Provider { upspa, .. } = &*node.lock().unwrap() {
                    assert!(upspa.pending.is_empty());
                }
            }
        }
    }
}
