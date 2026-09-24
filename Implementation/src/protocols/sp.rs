use crate::protocols::tspa as tspa_proto;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use std::collections::HashMap;

#[derive(Clone)]
pub struct TspaProvider {
    pub sp_id: u32,
    /// OPRF key `k_i` stored at the provider.
    pub oprf_key: Scalar,
    /// Stored record keyed by stor_uid.
    pub record_db: HashMap<[u8; 32], tspa_proto::Ciphertext>,
}

impl TspaProvider {
    pub fn new(sp_id: u32, oprf_key: Scalar) -> Self {
        Self { sp_id, oprf_key, record_db: HashMap::new() }
    }

    /// OPRF sender evaluation: given `blinded = H(pwd) * r` (compressed), return
    /// `z = blinded * k_i` (compressed).
    #[inline]
    pub fn oprf_send_eval(&self, blinded_bytes: &[u8; 32]) -> [u8; 32] {
        let blinded = CompressedRistretto(*blinded_bytes)
            .decompress()
            .expect("valid compressed Ristretto");
        let z = blinded * self.oprf_key;
        z.compress().to_bytes()
    }

    #[inline]
    pub fn put_record(&mut self, stor_uid: [u8; 32], c: tspa_proto::Ciphertext) {
        self.record_db.insert(stor_uid, c);
    }

    #[inline]
    pub fn get_record(&self, stor_uid: &[u8; 32]) -> Option<tspa_proto::Ciphertext> {
        self.record_db.get(stor_uid).copied()
    }
}

