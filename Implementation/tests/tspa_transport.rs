use curve25519_dalek::scalar::Scalar;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{sync::Arc, time::Duration};
use tspa::{
    crypto_tspa as crypto,
    protocols::{
        login_server::LoginServer, messages::*, sp::TspaProvider, system::System, tspa as legacy,
        tspa_adapter,
    },
    transport::{serve, InMemoryTransport, NetworkTransport, Node, Target, Transport},
};

#[test]
fn registration_preserves_original_stored_values_and_output() {
    for (n, t) in [(3, 2), (6, 6), (10, 4)] {
        let fixture = legacy::make_fixture(n, t);
        let mut rng = ChaCha20Rng::from_seed([1; 32]);
        let iteration = legacy::make_iter_data(&fixture, &mut rng);
        let data = tspa_adapter::registration_from_randomness(
            &fixture.uid,
            &fixture.lsj,
            &fixture.password,
            &iteration.reg_coeffs,
            &iteration.reg_oprf_keys,
            &iteration.reg_ivs,
        );
        let mut accumulator = blake3::Hasher::new();
        accumulator.update(b"tspa/registration/acc/v1");
        accumulator.update(&data.stor_uid);
        accumulator.update(&data.verifier);
        for (i, ciphertext) in data.ciphertexts.iter().enumerate() {
            accumulator.update(ciphertext);
            let mut provider = TspaProvider::new(i as u32 + 1, Scalar::ONE);
            tspa_adapter::handle(
                &mut provider,
                TspaRequest::Register {
                    stor_uid: data.stor_uid,
                    key: data.keys[i].to_bytes(),
                    ciphertext: ciphertext.to_vec(),
                },
            )
            .unwrap();
            assert_eq!(provider.get_record(&data.stor_uid), Some(*ciphertext));
            assert_eq!(provider.oprf_key, iteration.reg_oprf_keys[i]);
        }
        assert_eq!(
            *accumulator.finalize().as_bytes(),
            legacy::registration_user_side(&fixture, &iteration)
        );
    }
}

#[test]
fn authentication_preserves_original_secret_verifier_and_output() {
    let fixture = legacy::make_fixture(6, 3);
    let iteration = legacy::make_iter_data(&fixture, &mut ChaCha20Rng::from_seed([3; 32]));
    let replies: Vec<_> = iteration
        .auth_z_sel
        .iter()
        .zip(iteration.auth_ciphertexts_sel)
        .enumerate()
        .map(|(i, (z, ct))| {
            (
                i as u32 + 1,
                Reply::TspaAuthentication {
                    contribution: z.compress().to_bytes(),
                    ciphertext: ct.to_vec(),
                },
            )
        })
        .collect();
    let (secret, verifier) =
        tspa_adapter::reconstruct(&fixture.password, &fixture.lsj, iteration.auth_r, &replies)
            .unwrap();
    assert_eq!(verifier, fixture.vinfo_db);
    let mut accumulator = blake3::Hasher::new();
    accumulator.update(b"tspa/auth/acc/v1");
    accumulator.update(&crypto::hash_storuid(&fixture.uid, &fixture.lsj));
    accumulator.update(&secret);
    accumulator.update(&verifier);
    accumulator.update(&[1]);
    assert_eq!(
        *accumulator.finalize().as_bytes(),
        legacy::authentication_user_side(&fixture, &iteration)
    );
}

#[test]
fn provider_oprf_response_matches_original() {
    let mut provider = TspaProvider::new(1, Scalar::from(7u64));
    provider.put_record([2; 32], [3; 48]);
    let blinded = (crypto::hash_to_point(b"pwd") * Scalar::from(9u64))
        .compress()
        .to_bytes();
    let expected = provider.oprf_send_eval(&blinded);
    let response = tspa_adapter::handle(
        &mut provider,
        TspaRequest::Authenticate {
            stor_uid: [2; 32],
            blinded,
        },
    )
    .unwrap();
    assert_eq!(
        response,
        Reply::TspaAuthentication {
            contribution: expected,
            ciphertext: vec![3; 48]
        }
    );
}

#[tokio::test]
async fn tcp_wrapper_and_memory_agree_on_tspa_outputs_and_failures() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    let server = tokio::spawn(serve(listener, Node::provider(1, 300000), true));
    let network =
        NetworkTransport::connect(&[(Target::Provider(1), address)], Duration::from_secs(3))
            .await
            .unwrap();
    let memory = InMemoryTransport::new(1, 300000);
    let requests = vec![
        Request::Tspa(TspaRequest::Authenticate {
            stor_uid: [3; 32],
            blinded: crypto::hash_to_point(b"pwd").compress().to_bytes(),
        }),
        Request::Tspa(TspaRequest::Register {
            stor_uid: [3; 32],
            key: Scalar::from(9u64).to_bytes(),
            ciphertext: vec![4; 48],
        }),
        Request::Tspa(TspaRequest::Authenticate {
            stor_uid: [3; 32],
            blinded: crypto::hash_to_point(b"pwd").compress().to_bytes(),
        }),
        Request::Tspa(TspaRequest::Authenticate {
            stor_uid: [3; 32],
            blinded: [255; 32],
        }),
    ];
    for request in requests {
        let a = memory
            .call(Target::Provider(1), request.clone())
            .await
            .unwrap();
        let b = network.call(Target::Provider(1), request).await.unwrap();
        assert_eq!(a.response.result, b.response.result);
        assert!(b.bytes_sent > 4);
        assert!(b.bytes_received > 4);
    }
    server.abort();
}

#[tokio::test]
async fn both_protocols_complete_over_persistent_tcp_connections() {
    let mut endpoints = Vec::new();
    let mut servers = Vec::new();
    for target in [
        Target::Provider(1),
        Target::Provider(2),
        Target::Provider(3),
        Target::LoginServer,
    ] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        endpoints.push((target, listener.local_addr().unwrap().to_string()));
        let node = match target {
            Target::Provider(id) => Node::provider(id, 300000),
            Target::LoginServer => Node::LoginServer(LoginServer::default()),
        };
        servers.push(tokio::spawn(serve(listener, node, true)));
    }
    let network = Arc::new(
        NetworkTransport::connect(&endpoints, Duration::from_secs(3))
            .await
            .unwrap(),
    );
    let mut system = System::new(3, 2, network, [7; 32], Duration::from_secs(3)).unwrap();
    system.setup(b"alice", b"pwd").await.unwrap();
    system
        .registration(b"alice", b"pwd", b"LS1", b"up-user")
        .await
        .unwrap();
    system
        .secret_update(b"alice", b"pwd", b"LS1", b"up-user")
        .await
        .unwrap();
    system
        .password_update(b"alice", b"pwd", b"new")
        .await
        .unwrap();
    system
        .authentication(b"alice", b"new", b"LS1", b"up-user")
        .await
        .unwrap();
    system.reset().await.unwrap();
    system
        .tspa_registration(b"alice", b"pwd", b"LS1", b"t-user")
        .await
        .unwrap();
    system
        .tspa_authentication(b"alice", b"pwd", b"LS1", b"t-user")
        .await
        .unwrap();
    assert!(system
        .tspa_authentication(b"alice", b"wrong", b"LS1", b"t-user")
        .await
        .is_err());
    system.settle().await;
    for server in servers {
        server.abort();
    }
}
