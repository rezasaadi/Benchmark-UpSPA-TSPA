use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use std::{sync::Arc, time::Duration};
use tspa::{
    crypto,
    protocols::{
        messages::*,
        system::{Requirement, RngMode, System},
    },
    transport::{InMemoryTransport, Node, Target},
};
use zeroize::ZeroizeOnDrop;

fn wipes_on_drop<T: ZeroizeOnDrop>(_: &T) {}

#[tokio::test]
async fn recovered_secrets_and_crypto_plaintexts_have_drop_guards() {
    let transport = Arc::new(InMemoryTransport::new(3, 300_000));
    let mut system =
        System::new(3, 2, transport, RngMode::default(), Duration::from_secs(2)).unwrap();
    system.setup(b"alice", b"pwd").await.unwrap();
    let state = system
        .identification(b"alice", b"pwd", Requirement::AllProviders)
        .await
        .unwrap();
    wipes_on_drop(&state.ssk);
    wipes_on_drop(&state.rsp);
    wipes_on_drop(&state.k0);
    let mut rng = ChaCha20Rng::from_seed([22; 32]);
    let output = crypto::oprf_finalize(b"pwd", &crypto::hash_to_point(b"pwd"));
    wipes_on_drop(&output);
    let (key, shares) = crypto::toprf_gen(3, 2, &mut rng);
    wipes_on_drop(&key);
    wipes_on_drop(&shares);
    let mut ciphertext =
        crypto::xchacha_encrypt_detached(&output, &[], &[8; ACCOUNT_LEN], &mut rng);
    let plaintext = crypto::xchacha_decrypt_detached(&output, &[], &ciphertext).unwrap();
    wipes_on_drop(&plaintext);
    assert_eq!(*plaintext, [8; ACCOUNT_LEN]);
    ciphertext.tag[0] ^= 1;
    assert!(crypto::xchacha_decrypt_detached(&output, &[], &ciphertext).is_err());
    system.settle().await;
}

async fn setup_root(mode: RngMode) -> Root {
    let transport = Arc::new(InMemoryTransport::new(3, 300_000));
    let mut system = System::new(3, 2, transport.clone(), mode, Duration::from_secs(2)).unwrap();
    system.setup(b"alice", b"pwd").await.unwrap();
    system.settle().await;
    let node = transport.nodes[&Target::Provider(1)].lock().unwrap();
    let Node::Provider { upspa, .. } = &*node else {
        unreachable!()
    };
    upspa.roots[b"alice".as_slice()].clone()
}

#[tokio::test]
async fn benchmark_seeds_are_reproducible_and_library_default_uses_fresh_entropy() {
    let seed = RngMode::Deterministic([25; 32]);
    assert_eq!(setup_root(seed).await, setup_root(seed).await);
    assert!(matches!(RngMode::default(), RngMode::OsEntropy));
    assert_ne!(
        setup_root(RngMode::default()).await,
        setup_root(RngMode::default()).await
    );
}
