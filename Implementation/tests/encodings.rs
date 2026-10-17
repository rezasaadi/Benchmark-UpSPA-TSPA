use std::collections::HashSet;
use tspa::crypto::{hash_upspa_suid, hash_vinfo};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[test]
fn canonical_identifier_and_verifier_vectors() {
    let identifier = bincode::serialize(&("identifier", b"LS".as_slice(), 1u32)).unwrap();
    let verifier = bincode::serialize(&("verifier", b"LS".as_slice())).unwrap();
    assert_eq!(
        hex(&identifier),
        "0a000000000000006964656e74696669657202000000000000004c5301000000"
    );
    assert_eq!(
        hex(&verifier),
        "0800000000000000766572696669657202000000000000004c53"
    );
    let mut input = vec![0; 32];
    input.extend_from_slice(&identifier);
    assert_eq!(
        hash_upspa_suid(&[0; 32], b"LS", 1),
        *blake3::hash(&input).as_bytes()
    );
    let mut input = vec![1; 32];
    input.extend_from_slice(&verifier);
    assert_eq!(
        hash_vinfo(&[1; 32], b"LS"),
        *blake3::hash(&input).as_bytes()
    );
    assert_eq!(
        hex(&hash_upspa_suid(&[0; 32], b"LS", 1)),
        "c45a4db276a0335f86014bf500c30633f64cff98f222f81ba57b3a3cd2ab3bbb"
    );
    assert_eq!(
        hex(&hash_vinfo(&[1; 32], b"LS")),
        "a830a893721b47f2f52c51ec7b9d1ffa5e61201bc67e2a169a9f810661915a99"
    );
}

#[test]
fn prefix_sharing_domains_and_provider_indices_have_distinct_inputs() {
    let mut inputs = HashSet::new();
    let mut hashes = HashSet::new();
    for ls in [b"L".as_slice(), b"LS", b"LS\0", b"LS1", b"LS12"] {
        for id in [0u32, 1, 2, 0x3100, u32::MAX] {
            assert!(inputs.insert(bincode::serialize(&("identifier", ls, id)).unwrap()));
            assert!(hashes.insert(hash_upspa_suid(&[3; 32], ls, id)));
        }
    }
    let verifiers: HashSet<_> = [b"L".as_slice(), b"LS", b"LS\0", b"LS1", b"LS12"]
        .into_iter()
        .map(|ls| hash_vinfo(&[3; 32], ls))
        .collect();
    assert_eq!(verifiers.len(), 5);
}
