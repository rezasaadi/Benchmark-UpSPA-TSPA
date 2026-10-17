use async_trait::async_trait;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tspa::{
    protocols::{messages::*, system::System},
    transport::{InMemoryTransport, Packet, Target, Transport},
};

#[derive(Clone, Default)]
enum Fault {
    #[default]
    None,
    AccountError,
    AccountMissing,
    AccountMalformed(Reply),
    IdentifyMalformed(Reply),
}

struct ReadTransport {
    memory: InMemoryTransport,
    fault: Mutex<Fault>,
}

#[async_trait]
impl Transport for ReadTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        let fault = self.fault.lock().unwrap().clone();
        if target == Target::Provider(3)
            && matches!(request, Request::Up(UpRequest::Identify { .. }))
        {
            if let Fault::IdentifyMalformed(reply) = &fault {
                let mut packet = self.memory.call(target, request).await?;
                packet.response.result = Ok(reply.clone());
                return Ok(packet);
            }
        }
        if target == Target::Provider(3)
            && matches!(request, Request::Up(UpRequest::ReadAccount { .. }))
        {
            match fault {
                Fault::AccountError => {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    return Err("unknown account".into());
                }
                Fault::AccountMissing => {
                    tokio::time::sleep(Duration::from_millis(350)).await;
                }
                Fault::AccountMalformed(reply) => {
                    let mut packet = self.memory.call(target, request).await?;
                    packet.response.result = Ok(reply);
                    return Ok(packet);
                }
                _ => {}
            }
        }
        self.memory.call(target, request).await
    }
}

async fn fixture() -> (Arc<ReadTransport>, System) {
    let transport = Arc::new(ReadTransport {
        memory: InMemoryTransport::new(3, 300_000),
        fault: Mutex::new(Fault::None),
    });
    let mut system = System::new(
        3,
        2,
        transport.clone(),
        [12; 32],
        Duration::from_millis(200),
    )
    .unwrap();
    system.setup(b"alice", b"pwd").await.unwrap();
    system
        .registration(b"alice", b"pwd", b"LS1", b"alice")
        .await
        .unwrap();
    system.settle().await;
    system.clear_trace();
    (transport, system)
}

fn assert_no_write_or_ls(system: &System) {
    let trace = system.trace.lock().unwrap();
    assert!(!trace
        .stages
        .iter()
        .any(|stage| matches!(stage.stage.as_str(), "provider_prepare" | "ls_interaction")));
}

#[tokio::test]
async fn secret_update_requires_every_account_read_before_preparation() {
    for fault in [Fault::AccountError, Fault::AccountMissing] {
        let (transport, mut system) = fixture().await;
        *transport.fault.lock().unwrap() = fault;
        assert!(system
            .secret_update(b"alice", b"pwd", b"LS1", b"alice")
            .await
            .is_err());
        assert_no_write_or_ls(&system);
        system.settle().await;
    }
}

#[tokio::test]
async fn authentication_tolerates_a_rejected_account_read() {
    let (transport, mut system) = fixture().await;
    *transport.fault.lock().unwrap() = Fault::AccountError;
    system
        .authentication(b"alice", b"pwd", b"LS1", b"alice")
        .await
        .unwrap();
    system.settle().await;
}

#[tokio::test]
async fn malformed_identify_stops_every_write_phase_before_preparation() {
    let malformed = [
        Reply::Ack(true),
        Reply::Account(vec![0; ACCOUNT_LEN + 40]),
        Reply::Identification {
            cid: vec![0; ROOT_LEN + 40],
            timestamp: 0,
            contribution: [255; 32],
        },
        Reply::Identification {
            cid: vec![0; 1],
            timestamp: 0,
            contribution: [0; 32],
        },
    ];
    for reply in malformed {
        for phase in [
            Phase::Registration,
            Phase::SecretUpdate,
            Phase::PasswordUpdate,
        ] {
            let (transport, mut system) = fixture().await;
            *transport.fault.lock().unwrap() = Fault::IdentifyMalformed(reply.clone());
            let result = match phase {
                Phase::Registration => {
                    system
                        .registration(b"alice", b"pwd", b"LS2", b"alice")
                        .await
                }
                Phase::SecretUpdate => {
                    system
                        .secret_update(b"alice", b"pwd", b"LS1", b"alice")
                        .await
                }
                Phase::PasswordUpdate => system.password_update(b"alice", b"pwd", b"new").await,
                _ => unreachable!(),
            };
            assert!(result.is_err(), "{phase:?}: {reply:?}");
            assert_no_write_or_ls(&system);
            system.settle().await;
        }
    }
}

#[tokio::test]
async fn malformed_account_stops_secret_update_but_authentication_is_tolerant() {
    for reply in [Reply::Ack(true), Reply::Account(vec![0; 1])] {
        let (transport, mut system) = fixture().await;
        *transport.fault.lock().unwrap() = Fault::AccountMalformed(reply);
        assert!(system
            .secret_update(b"alice", b"pwd", b"LS1", b"alice")
            .await
            .is_err());
        assert_no_write_or_ls(&system);
        system
            .authentication(b"alice", b"pwd", b"LS1", b"alice")
            .await
            .unwrap();
        system.settle().await;
    }
}
