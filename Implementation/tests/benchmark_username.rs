use std::{sync::Arc, time::Duration};
use tspa::{
    benchmark::{fixture, invoke},
    protocols::{
        messages::*,
        system::{RngMode, System},
    },
    transport::{InMemoryTransport, Node, Target},
};

#[tokio::test]
async fn benchmark_uses_the_same_public_username_at_providers_and_ls() {
    for protocol in [Protocol::UpSPA, Protocol::TSPA] {
        let transport = Arc::new(InMemoryTransport::new(3, 300_000));
        let mut system = System::new(
            3,
            2,
            transport.clone(),
            RngMode::Deterministic([31; 32]),
            Duration::from_secs(2),
        )
        .unwrap();
        fixture(&mut system, protocol, Phase::Registration)
            .await
            .unwrap();
        invoke(&mut system, protocol, Phase::Registration)
            .await
            .unwrap();
        invoke(&mut system, protocol, Phase::Authentication)
            .await
            .unwrap();
        system.settle().await;
        {
            let node = transport.nodes[&Target::LoginServer].lock().unwrap();
            let Node::LoginServer(ls) = &*node else {
                unreachable!()
            };
            assert_eq!(ls.current.len(), 1);
            assert!(ls.current.contains_key(b"user123".as_slice()));
        }
        if protocol == Protocol::UpSPA {
            let node = transport.nodes[&Target::Provider(1)].lock().unwrap();
            let Node::Provider { upspa, .. } = &*node else {
                unreachable!()
            };
            assert!(upspa.roots.contains_key(b"user123".as_slice()));
        }
    }
}
