use super::messages::*;
use curve25519_dalek::{ristretto::CompressedRistretto, scalar::Scalar};
use ed25519_dalek::{Signature, VerifyingKey};
use std::collections::HashMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Replacement {
    Root(Root),
    Account(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct Pending {
    pub binding: Binding,
    pub replacement: Replacement,
    pub timestamp_old: Option<u64>,
}

#[derive(Clone)]
struct AttemptWindow {
    started_ms: u64,
    count: u32,
}

#[derive(Clone)]
pub struct UpSpaProvider {
    pub provider_id: u32,
    pub roots: HashMap<Vec<u8>, Root>,
    pub accounts: HashMap<Key, Vec<u8>>,
    pub pending: HashMap<RecordId, Pending>,
    pub completed: HashMap<Binding, bool>,
    pub clock_window_ms: u64,
    pub attempt_limit: u32,
    pub attempt_window_ms: u64,
    attempts: HashMap<(Vec<u8>, u64), AttemptWindow>,
}

impl UpSpaProvider {
    pub fn new(provider_id: u32, clock_window_ms: u64) -> Self {
        Self {
            provider_id,
            roots: HashMap::new(),
            accounts: HashMap::new(),
            pending: HashMap::new(),
            completed: HashMap::new(),
            clock_window_ms,
            attempt_limit: 100,
            attempt_window_ms: 60_000,
            attempts: HashMap::new(),
        }
    }

    pub fn with_attempt_policy(mut self, limit: u32, window_ms: u64) -> Self {
        self.attempt_limit = limit;
        self.attempt_window_ms = window_ms;
        self
    }

    fn prepare(
        &mut self,
        binding: Binding,
        replacement: Replacement,
        timestamp_old: Option<u64>,
    ) -> Result<Reply> {
        if self.completed.contains_key(&binding) {
            return Err("session already finalized".into());
        }
        if let Some(pending) = self.pending.get(&binding.record) {
            return if pending.binding == binding
                && pending.replacement == replacement
                && pending.timestamp_old == timestamp_old
            {
                Ok(Reply::Ack(true))
            } else {
                Err("pending conflict".into())
            };
        }
        self.pending.insert(
            binding.record.clone(),
            Pending {
                binding,
                replacement,
                timestamp_old,
            },
        );
        Ok(Reply::Ack(true))
    }

    pub fn handle(&mut self, request: UpRequest, now: u64) -> Result<Reply> {
        match request {
            UpRequest::Setup { sid, root } => {
                if self.roots.contains_key(&root.uid) {
                    return Err("root already exists".into());
                }
                if root.timestamp != 0 {
                    return Err("setup timestamp must be zero".into());
                }
                decode_blob::<ROOT_LEN>(&root.cid)?;
                VerifyingKey::from_bytes(&root.svk).map_err(|_| "invalid verification key")?;
                if !bool::from(Scalar::from_canonical_bytes(root.share).is_some()) {
                    return Err("invalid share".into());
                }
                self.prepare(
                    Binding {
                        sid,
                        phase: Phase::Setup,
                        record: RecordId::Root(root.uid.clone()),
                    },
                    Replacement::Root(root),
                    None,
                )
            }
            UpRequest::Identify { uid, blinded } => {
                let root = self.roots.get(&uid).ok_or("unknown root")?;
                let point = CompressedRistretto(blinded)
                    .decompress()
                    .ok_or("invalid point")?;
                let attempts =
                    self.attempts
                        .entry((uid, root.timestamp))
                        .or_insert(AttemptWindow {
                            started_ms: now,
                            count: 0,
                        });
                if self.attempt_window_ms != 0
                    && now.saturating_sub(attempts.started_ms) >= self.attempt_window_ms
                {
                    attempts.started_ms = now;
                    attempts.count = 0;
                }
                if attempts.count >= self.attempt_limit {
                    return Err("attempt limit".into());
                }
                attempts.count += 1;
                Ok(Reply::Identification {
                    cid: root.cid.clone(),
                    timestamp: root.timestamp,
                    contribution: (point * Scalar::from_bytes_mod_order(root.share))
                        .compress()
                        .to_bytes(),
                })
            }
            UpRequest::ReadAccount { suid } => Ok(Reply::Account(
                self.accounts.get(&suid).ok_or("unknown account")?.clone(),
            )),
            UpRequest::PrepareAccount {
                binding,
                ciphertext,
                expected,
            } => {
                let RecordId::Account(suid) = binding.record else {
                    return Err("wrong record type".into());
                };
                decode_blob::<ACCOUNT_LEN>(&ciphertext)?;
                match binding.phase {
                    Phase::Registration
                        if expected.is_none() && !self.accounts.contains_key(&suid) => {}
                    Phase::SecretUpdate
                        if expected.is_some() && self.accounts.get(&suid) == expected.as_ref() => {}
                    _ => return Err("account precondition failed".into()),
                }
                self.prepare(binding, Replacement::Account(ciphertext), None)
            }
            UpRequest::PasswordUpdate(update) => {
                let old = self.roots.get(&update.uid).ok_or("unknown root")?;
                if update.operation != "PwdUpdate" {
                    return Err("wrong operation".into());
                }
                if update.provider_id != self.provider_id {
                    return Err("wrong provider index".into());
                }
                if update.timestamp_old != old.timestamp {
                    return Err("old timestamp mismatch".into());
                }
                if update.timestamp_new <= update.timestamp_old {
                    return Err("non-increasing timestamp".into());
                }
                if update.timestamp_new.abs_diff(now) > self.clock_window_ms {
                    return Err("outside clock window".into());
                }
                decode_blob::<ROOT_LEN>(&update.cid_new)?;
                if !bool::from(Scalar::from_canonical_bytes(update.share_new).is_some()) {
                    return Err("invalid share".into());
                }
                let signature =
                    Signature::from_slice(&update.signature).map_err(|_| "invalid signature")?;
                VerifyingKey::from_bytes(&old.svk)
                    .map_err(|_| "invalid key")?
                    .verify_strict(&update.signed_bytes(), &signature)
                    .map_err(|_| "invalid signature")?;
                let root = Root {
                    uid: old.uid.clone(),
                    svk: old.svk,
                    cid: update.cid_new,
                    share: update.share_new,
                    timestamp: update.timestamp_new,
                };
                self.prepare(
                    Binding {
                        sid: update.sid,
                        phase: Phase::PasswordUpdate,
                        record: RecordId::Root(update.uid),
                    },
                    Replacement::Root(root),
                    Some(update.timestamp_old),
                )
            }
            UpRequest::Finalize { binding, store } => {
                if let Some(done) = self.completed.get(&binding) {
                    return Ok(Reply::Ack(*done == store));
                }
                if !self
                    .pending
                    .get(&binding.record)
                    .is_some_and(|p| p.binding == binding)
                {
                    if !store {
                        // Remember an empty Discard so a late preparation cannot revive it.
                        self.completed.insert(binding, false);
                    }
                    return Ok(Reply::Ack(!store));
                }
                if store && binding.phase == Phase::PasswordUpdate {
                    let pending = &self.pending[&binding.record];
                    let RecordId::Root(uid) = &binding.record else {
                        return Ok(Reply::Ack(false));
                    };
                    if self.roots.get(uid).map(|root| root.timestamp) != pending.timestamp_old {
                        return Ok(Reply::Ack(false));
                    }
                }
                let pending = self.pending.remove(&binding.record).unwrap();
                if store {
                    match pending.replacement {
                        Replacement::Root(root) => {
                            self.roots.insert(root.uid.clone(), root);
                        }
                        Replacement::Account(ciphertext) => {
                            let RecordId::Account(suid) = binding.record else {
                                unreachable!()
                            };
                            self.accounts.insert(suid, ciphertext);
                        }
                    }
                }
                self.completed.insert(binding, store);
                Ok(Reply::Ack(true))
            }
        }
    }
}
