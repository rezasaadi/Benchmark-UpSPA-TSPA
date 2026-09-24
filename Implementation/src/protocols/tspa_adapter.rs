use super::{messages::*, sp::TspaProvider};
use crate::crypto_tspa as crypto;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use rand_core::RngCore;

#[derive(Clone)]
pub struct RegistrationData {
    pub stor_uid: Key,
    pub verifier: Key,
    pub keys: Vec<Scalar>,
    pub ciphertexts: Vec<super::tspa::Ciphertext>,
}

pub fn registration_from_randomness(
    uid: &[u8],
    ls: &[u8],
    password: &[u8],
    coeffs: &[Scalar],
    keys: &[Scalar],
    ivs: &[[u8; 16]],
) -> RegistrationData {
    let point = crypto::hash_to_point(password);
    let ciphertexts = keys
        .iter()
        .zip(ivs)
        .enumerate()
        .map(|(index, (key, iv))| {
            let encryption_key = crypto::oprf_finalize(password, &(point * key));
            let share = crypto::eval_poly(coeffs, Scalar::from(index as u64 + 1));
            let ct = crypto::aes256ctr_xor_32(encryption_key, *iv, share.to_bytes());
            let mut ciphertext = [0; 48];
            ciphertext[..16].copy_from_slice(iv);
            ciphertext[16..].copy_from_slice(&ct);
            ciphertext
        })
        .collect();
    RegistrationData {
        stor_uid: crypto::hash_storuid(uid, ls),
        verifier: crypto::hash_vinfo(&coeffs[0].to_bytes(), ls),
        keys: keys.to_vec(),
        ciphertexts,
    }
}

pub fn registration(
    uid: &[u8],
    ls: &[u8],
    password: &[u8],
    n: usize,
    t: usize,
    rng: &mut impl RngCore,
) -> RegistrationData {
    let coeffs: Vec<_> = (0..t).map(|_| crypto::random_scalar(rng)).collect();
    let keys: Vec<_> = (0..n).map(|_| crypto::random_scalar(rng)).collect();
    let ivs: Vec<_> = (0..n).map(|_| crypto::rand_bytes::<16>(rng)).collect();
    registration_from_randomness(uid, ls, password, &coeffs, &keys, &ivs)
}

pub fn reconstruct(
    password: &[u8],
    ls: &[u8],
    r: Scalar,
    replies: &[(u32, Reply)],
) -> Result<(Key, Key)> {
    let xs: Vec<_> = replies
        .iter()
        .map(|(id, _)| Scalar::from(*id as u64))
        .collect();
    let lambdas = crypto::lagrange_lambdas_at_zero(&xs);
    let mut secret = Scalar::ZERO;
    let inverse = r.invert();
    for ((_, response), lambda) in replies.iter().zip(lambdas) {
        let Reply::TspaAuthentication {
            contribution,
            ciphertext,
        } = response
        else {
            return Err("unexpected TSPA response".into());
        };
        let y = CompressedRistretto(*contribution)
            .decompress()
            .ok_or("invalid TSPA point")?
            * inverse;
        if ciphertext.len() != 48 {
            return Err("invalid TSPA ciphertext length".into());
        }
        let key = crypto::oprf_finalize(password, &y);
        let plaintext = crypto::aes256ctr_xor_32(
            key,
            ciphertext[..16].try_into().unwrap(),
            ciphertext[16..].try_into().unwrap(),
        );
        secret += Scalar::from_bytes_mod_order(plaintext) * lambda;
    }
    Ok((
        secret.to_bytes(),
        crypto::hash_vinfo(&secret.to_bytes(), ls),
    ))
}

pub fn handle(provider: &mut TspaProvider, request: TspaRequest) -> Result<Reply> {
    match request {
        TspaRequest::Register {
            stor_uid,
            key,
            ciphertext,
        } => {
            let ciphertext: [u8; 48] = ciphertext
                .try_into()
                .map_err(|_| "invalid TSPA ciphertext length")?;
            let key = Option::<Scalar>::from(Scalar::from_canonical_bytes(key))
                .ok_or("invalid TSPA key")?;
            provider.oprf_key = key;
            provider.put_record(stor_uid, ciphertext);
            Ok(Reply::Ack(true))
        }
        TspaRequest::Authenticate { stor_uid, blinded } => {
            CompressedRistretto(blinded)
                .decompress()
                .ok_or("invalid TSPA point")?;
            let ciphertext = provider
                .get_record(&stor_uid)
                .ok_or("unknown TSPA record")?;
            Ok(Reply::TspaAuthentication {
                contribution: provider.oprf_send_eval(&blinded),
                ciphertext: ciphertext.to_vec(),
            })
        }
    }
}
