use super::{messages::*, tspa_adapter};
use crate::{
    crypto, crypto_tspa,
    transport::{Target, Transport},
};
use curve25519_dalek::ristretto::CompressedRistretto;
use ed25519_dalek::{Signer, SigningKey};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};

#[derive(Clone, Debug, Serialize)]
pub struct CallSample {
    pub stage_id: usize,
    pub target: Target,
    pub operation: String,
    pub processing_ns: Option<u64>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub success: bool,
    pub error: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct StageSample {
    pub stage_id: usize,
    pub stage: String,
    pub elapsed_ns: u64,
    pub requests: usize,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Trace {
    pub client_ns: u64,
    pub stages: Vec<StageSample>,
    pub calls: Vec<CallSample>,
}

pub struct IdentifiedState {
    pub ssk: SigningKey,
    pub rsp: Key,
    pub k0: Key,
    pub timestamp: u64,
}

#[derive(Clone)]
struct LsResolution {
    probe: Request,
    store: Vec<(Target, Request)>,
    discard: Vec<(Target, Request)>,
}

#[derive(Clone, Copy)]
pub enum Requirement {
    Threshold,
    AllProviders,
}

#[derive(Clone, Copy)]
enum Policy {
    All,
    Agreement(usize),
}

pub fn account_context(uid: &[u8], ls: &[u8]) -> Vec<u8> {
    bincode::serialize(&("account", uid, ls)).unwrap()
}

pub fn agreement_key(reply: &Reply) -> Option<Vec<u8>> {
    match reply {
        Reply::Identification {
            cid,
            timestamp,
            contribution,
        } => {
            if CompressedRistretto(*contribution).decompress().is_none()
                || decode_blob::<ROOT_LEN>(cid).is_err()
            {
                return None;
            }
            Some(bincode::serialize(&(cid, timestamp)).unwrap())
        }
        Reply::Account(ciphertext) => {
            if decode_blob::<ACCOUNT_LEN>(ciphertext).is_err() {
                return None;
            }
            Some(ciphertext.clone())
        }
        _ => None,
    }
}

struct AgreementTracker {
    threshold: usize,
    seen: HashSet<u32>,
    groups: HashMap<Vec<u8>, Vec<(u32, Reply)>>,
}

impl AgreementTracker {
    fn new(threshold: usize) -> Result<Self> {
        if threshold == 0 {
            return Err("zero threshold".into());
        }
        Ok(Self {
            threshold,
            seen: HashSet::new(),
            groups: HashMap::new(),
        })
    }

    fn push(&mut self, id: u32, reply: Reply) -> Result<()> {
        if id == 0 || !self.seen.insert(id) {
            return Err("duplicate or zero provider id".into());
        }
        if let Some(key) = agreement_key(&reply) {
            self.groups.entry(key).or_default().push((id, reply));
        }
        Ok(())
    }

    fn resolve(&self, outstanding: usize) -> Result<Option<Vec<(u32, Reply)>>> {
        let qualifying: Vec<_> = self
            .groups
            .values()
            .filter(|group| group.len() >= self.threshold)
            .collect();
        if qualifying.len() > 1 {
            return Err("ambiguous ciphertext agreement".into());
        }
        if let Some(accepted) = qualifying.first() {
            let competing = self
                .groups
                .values()
                .filter(|group| group.len() < self.threshold)
                .any(|group| group.len() + outstanding >= self.threshold);
            if outstanding < self.threshold && !competing {
                return Ok(Some((*accepted).clone()));
            }
        }
        if outstanding == 0 {
            Err("insufficient matching ciphertexts".into())
        } else {
            Ok(None)
        }
    }
}

pub fn unique_agreement(
    replies: &[(u32, Reply)],
    threshold: usize,
    outstanding: usize,
) -> Result<Option<Vec<(u32, Reply)>>> {
    let mut tracker = AgreementTracker::new(threshold)?;
    for (id, reply) in replies {
        tracker.push(*id, reply.clone())?;
    }
    tracker.resolve(outstanding)
}

pub struct System {
    pub n: usize,
    pub t: usize,
    pub transport: Arc<dyn Transport>,
    pub trace: Arc<Mutex<Trace>>,
    rng: ChaCha20Rng,
    deadline: Duration,
    running: Vec<JoinHandle<()>>,
    finalization: Option<(Vec<(Target, Request)>, bool)>,
    ls_resolution: Option<LsResolution>,
}

impl System {
    pub fn new(
        n: usize,
        t: usize,
        transport: Arc<dyn Transport>,
        seed: Key,
        deadline: Duration,
    ) -> Result<Self> {
        if n == 0 || t == 0 || t > n || n > 100 {
            return Err("require 1 <= t_sp <= n_sp <= 100".into());
        }
        Ok(Self {
            n,
            t,
            transport,
            trace: Arc::new(Mutex::new(Trace::default())),
            rng: ChaCha20Rng::from_seed(seed),
            deadline,
            running: Vec::new(),
            finalization: None,
            ls_resolution: None,
        })
    }

    fn compute<T>(&mut self, operation: impl FnOnce(&mut ChaCha20Rng) -> T) -> T {
        let start = Instant::now();
        let result = std::hint::black_box(operation(&mut self.rng));
        self.trace.lock().unwrap().client_ns += start.elapsed().as_nanos() as u64;
        result
    }

    pub async fn settle(&mut self) {
        for task in self.running.drain(..) {
            let _ = task.await;
        }
    }

    pub async fn reset(&mut self) -> Result<()> {
        self.settle().await;
        let transport = self.transport.clone();
        let targets = (1..=self.n)
            .map(|i| Target::Provider(i as u32))
            .chain([Target::LoginServer]);
        let responses = futures::future::join_all(targets.map(|target| {
            let transport = transport.clone();
            async move {
                transport
                    .call(target, Request::Reset)
                    .await?
                    .response
                    .result
            }
        }))
        .await;
        for response in responses {
            require_ack(response?)?;
        }
        self.finalization = None;
        self.ls_resolution = None;
        self.clear_trace();
        Ok(())
    }

    pub fn clear_trace(&mut self) {
        *self.trace.lock().unwrap() = Trace::default();
    }

    async fn stage(
        &mut self,
        name: &str,
        requests: Vec<(Target, Request)>,
        policy: Policy,
    ) -> Result<Vec<(u32, Reply)>> {
        let start = Instant::now();
        let count = requests.len();
        let stage_id = self.trace.lock().unwrap().stages.len();
        let (sender, mut receiver) = mpsc::unbounded_channel();
        for (target, request) in requests {
            let sender = sender.clone();
            let transport = self.transport.clone();
            let trace = self.trace.clone();
            self.running.push(tokio::spawn(async move {
                let operation = request.operation().to_owned();
                let packet = transport.call(target, request).await;
                let (result, processing_ns, bytes_sent, bytes_received) = match packet {
                    Ok(packet) => (
                        packet.response.result,
                        Some(packet.response.processing_ns),
                        Some(packet.bytes_sent),
                        Some(packet.bytes_received),
                    ),
                    Err(error) => (Err(error), None, None, None),
                };
                let success = result
                    .as_ref()
                    .is_ok_and(|reply| !matches!(reply, Reply::Ack(false)));
                let error = result.as_ref().err().cloned().unwrap_or_else(|| {
                    if success {
                        String::new()
                    } else {
                        "operation rejected".into()
                    }
                });
                trace.lock().unwrap().calls.push(CallSample {
                    stage_id,
                    target,
                    operation,
                    processing_ns,
                    bytes_sent,
                    bytes_received,
                    success,
                    error,
                });
                let _ = sender.send((target, result));
            }));
        }
        drop(sender);
        let deadline = tokio::time::Instant::now() + self.deadline;
        let mut replies = Vec::new();
        let mut first_error = None;
        let mut received = 0;
        let mut agreement = match policy {
            Policy::Agreement(threshold) => Some(AgreementTracker::new(threshold)?),
            Policy::All => None,
        };
        let result = loop {
            if received == count {
                break match policy {
                    Policy::All => first_error.map_or_else(|| Ok(replies.clone()), Err),
                    Policy::Agreement(_) => agreement
                        .as_ref()
                        .expect("agreement tracker must exist")
                        .resolve(0)
                        .and_then(|result| result.ok_or("no agreement".into())),
                };
            }
            let Some((target, response)) = tokio::time::timeout_at(deadline, receiver.recv())
                .await
                .unwrap_or(None)
            else {
                break Err("stage deadline exceeded".into());
            };
            received += 1;
            let processed = self.compute(|_| -> Result<Option<Vec<(u32, Reply)>>> {
                match response {
                    Ok(reply) => {
                        let id = match target {
                            Target::Provider(id) => id,
                            Target::LoginServer => 0,
                        };
                        if let Some(tracker) = agreement.as_mut() {
                            tracker.push(id, reply.clone())?;
                        }
                        replies.push((id, reply));
                    }
                    Err(error) => {
                        if first_error.is_none() {
                            first_error = Some(error);
                        }
                    }
                }
                match policy {
                    Policy::Agreement(_) => agreement
                        .as_ref()
                        .expect("agreement tracker must exist")
                        .resolve(count - received),
                    Policy::All => Ok(None),
                }
            });
            match processed {
                Ok(Some(accepted)) => break Ok(accepted),
                Err(error) => break Err(error),
                Ok(None) => {}
            }
        };
        self.trace.lock().unwrap().stages.push(StageSample {
            stage_id,
            stage: name.into(),
            elapsed_ns: start.elapsed().as_nanos() as u64,
            requests: count,
        });
        result
    }

    async fn all(&mut self, name: &str, requests: Vec<(Target, Request)>) -> Result<()> {
        let replies = self.stage(name, requests, Policy::All).await?;
        self.compute(|_| {
            for (_, reply) in replies {
                require_ack(reply)?;
            }
            Ok(())
        })
    }

    fn finals(
        &self,
        sid: Sid,
        phase: Phase,
        records: Vec<RecordId>,
        store: bool,
    ) -> Vec<(Target, Request)> {
        records
            .into_iter()
            .enumerate()
            .map(|(i, record)| {
                (
                    Target::Provider(i as u32 + 1),
                    Request::Up(UpRequest::Finalize {
                        binding: Binding { sid, phase, record },
                        store,
                    }),
                )
            })
            .collect()
    }

    async fn finalize(&mut self, requests: Vec<(Target, Request)>, store: bool) -> Result<()> {
        self.finalization = Some((requests.clone(), store));
        let mut last = Err("finalization incomplete".into());
        for _ in 0..3 {
            let result = self
                .stage("finalization", requests.clone(), Policy::All)
                .await;
            last = result.and_then(|replies| {
                if store {
                    for (_, reply) in replies {
                        require_ack(reply)?;
                    }
                }
                Ok(())
            });
            if last.is_ok() {
                self.finalization = None;
                return Ok(());
            }
        }
        Err(format!(
            "finalization incomplete; retained for resume: {}",
            last.unwrap_err()
        ))
    }

    pub async fn resume_finalization(&mut self) -> Result<()> {
        if self.ls_resolution.is_some() {
            return self.resolve_ls().await;
        }
        let (requests, store) = self.finalization.clone().ok_or("no finalization pending")?;
        self.finalize(requests, store).await
    }

    async fn resolve_ls(&mut self) -> Result<()> {
        let resolution = self
            .ls_resolution
            .clone()
            .ok_or("no LS resolution pending")?;
        let replies = self
            .stage(
                "ls_recovery",
                vec![(Target::LoginServer, resolution.probe)],
                Policy::All,
            )
            .await
            .map_err(|error| {
                format!("LS outcome unknown; provider preparations retained: {error}")
            })?;
        let accepted = match replies.as_slice() {
            [(_, Reply::Ack(value))] => *value,
            _ => return Err("unexpected LS resolution response; preparations retained".into()),
        };
        self.ls_resolution = None;
        self.finalize(
            if accepted {
                resolution.store
            } else {
                resolution.discard
            },
            accepted,
        )
        .await?;
        if accepted {
            Ok(())
        } else {
            Err("LS rejected operation".into())
        }
    }

    fn require_idle(&self) -> Result<()> {
        if self.finalization.is_some() || self.ls_resolution.is_some() {
            Err("finalization must complete before another phase".into())
        } else {
            Ok(())
        }
    }

    pub async fn setup(&mut self, uid: &[u8], password: &[u8]) -> Result<()> {
        self.require_idle()?;
        let n = self.n;
        let t = self.t;
        let (sid, requests) = self.compute(|rng| {
            let mut sid = [0; 16];
            rng.fill_bytes(&mut sid);
            let mut rsp = [0; 32];
            rng.fill_bytes(&mut rsp);
            let (key, shares) = crypto::toprf_gen(n, t, rng);
            let mut ssk = [0; 32];
            rng.fill_bytes(&mut ssk);
            let signing = SigningKey::from_bytes(&ssk);
            let mut k0 = [0; 32];
            rng.fill_bytes(&mut k0);
            let mut plaintext = [0; ROOT_LEN];
            plaintext[..32].copy_from_slice(&ssk);
            plaintext[32..64].copy_from_slice(&rsp);
            plaintext[64..].copy_from_slice(&k0);
            let encryption =
                crypto::oprf_finalize(password, &(crypto::hash_to_point(password) * key));
            let cid = crypto::xchacha_encrypt_detached(&encryption, &[], &plaintext, rng).encode();
            let requests = shares
                .into_iter()
                .map(|(id, share)| {
                    (
                        Target::Provider(id),
                        Request::Up(UpRequest::Setup {
                            sid,
                            root: Root {
                                uid: uid.to_vec(),
                                svk: signing.verifying_key().to_bytes(),
                                cid: cid.clone(),
                                share: share.to_bytes(),
                                timestamp: 0,
                            },
                        }),
                    )
                })
                .collect();
            (sid, requests)
        });
        let prepared = self.all("provider_prepare", requests).await;
        let records = (0..n).map(|_| RecordId::Root(uid.to_vec())).collect();
        self.finalize(
            self.finals(sid, Phase::Setup, records, prepared.is_ok()),
            prepared.is_ok(),
        )
        .await?;
        prepared
    }

    pub async fn identification(
        &mut self,
        uid: &[u8],
        password: &[u8],
        requirement: Requirement,
    ) -> Result<IdentifiedState> {
        let n = self.n;
        let (r, requests) = self.compute(|rng| {
            let r = crypto::random_scalar(rng);
            let blinded = (crypto::hash_to_point(password) * r).compress().to_bytes();
            (
                r,
                (1..=n)
                    .map(|id| {
                        (
                            Target::Provider(id as u32),
                            Request::Up(UpRequest::Identify {
                                uid: uid.to_vec(),
                                blinded,
                            }),
                        )
                    })
                    .collect(),
            )
        });
        let policy = match requirement {
            Requirement::Threshold => Policy::Agreement(self.t),
            Requirement::AllProviders => Policy::All,
        };
        let replies = self.stage("identification", requests, policy).await?;
        let threshold = self.t;
        self.compute(|_| {
            let accepted = match requirement {
                Requirement::Threshold => replies,
                Requirement::AllProviders => {
                    unique_agreement(&replies, threshold, 0)?.ok_or("no root agreement")?
                }
            };
            let Reply::Identification { cid, timestamp, .. } = &accepted[0].1 else {
                return Err("invalid root response".into());
            };
            let mut ids = Vec::new();
            let mut points = Vec::new();
            for (id, reply) in &accepted {
                let Reply::Identification { contribution, .. } = reply else {
                    return Err("invalid root response".into());
                };
                ids.push(*id);
                points.push(
                    CompressedRistretto(*contribution)
                        .decompress()
                        .ok_or("invalid point")?,
                );
                if ids.len() == threshold {
                    break;
                }
            }
            let key = crypto::toprf_client_eval_from_partials(
                password,
                r,
                &points,
                &crypto::lagrange_coeffs_at_zero(&ids),
            );
            let plaintext =
                crypto::xchacha_decrypt_detached(&key, &[], &decode_blob::<ROOT_LEN>(cid)?)
                    .map_err(|_| "root decryption failed")?;
            Ok(IdentifiedState {
                ssk: SigningKey::from_bytes(&plaintext[..32].try_into().unwrap()),
                rsp: plaintext[32..64].try_into().unwrap(),
                k0: plaintext[64..].try_into().unwrap(),
                timestamp: *timestamp,
            })
        })
    }

    async fn recover(
        &mut self,
        uid: &[u8],
        ls: &[u8],
        state: &IdentifiedState,
    ) -> Result<(Key, u64, Vec<u8>)> {
        let n = self.n;
        let requests = self.compute(|_| {
            (1..=n)
                .map(|id| {
                    (
                        Target::Provider(id as u32),
                        Request::Up(UpRequest::ReadAccount {
                            suid: crypto::hash_upspa_suid(&state.rsp, ls, id as u32),
                        }),
                    )
                })
                .collect()
        });
        let replies = self
            .stage("account_recovery", requests, Policy::Agreement(self.t))
            .await?;
        self.compute(|_| {
            let Reply::Account(ciphertext) = &replies[0].1 else {
                return Err("invalid account response".into());
            };
            let plaintext = crypto::xchacha_decrypt_detached(
                &state.k0,
                &account_context(uid, ls),
                &decode_blob::<ACCOUNT_LEN>(ciphertext)?,
            )
            .map_err(|_| "account decryption failed")?;
            Ok((
                plaintext[..32].try_into().unwrap(),
                u64::from_le_bytes(plaintext[32..].try_into().unwrap()),
                ciphertext.clone(),
            ))
        })
    }

    pub async fn registration(
        &mut self,
        uid: &[u8],
        password: &[u8],
        ls: &[u8],
        login_uid: &[u8],
    ) -> Result<()> {
        self.require_idle()?;
        let state = self
            .identification(uid, password, Requirement::AllProviders)
            .await?;
        self.account_write(uid, ls, login_uid, &state, None).await
    }

    pub async fn secret_update(
        &mut self,
        uid: &[u8],
        password: &[u8],
        ls: &[u8],
        login_uid: &[u8],
    ) -> Result<()> {
        self.require_idle()?;
        let state = self
            .identification(uid, password, Requirement::AllProviders)
            .await?;
        let old = self.recover(uid, ls, &state).await?;
        self.account_write(uid, ls, login_uid, &state, Some(old))
            .await
    }

    async fn account_write(
        &mut self,
        uid: &[u8],
        ls: &[u8],
        login_uid: &[u8],
        state: &IdentifiedState,
        old: Option<(Key, u64, Vec<u8>)>,
    ) -> Result<()> {
        let n = self.n;
        let phase = if old.is_some() {
            Phase::SecretUpdate
        } else {
            Phase::Registration
        };
        let (sid, records, requests, ls_request) = self.compute(|rng| -> Result<_> {
            let counter = match &old {
                Some((_, counter, _)) => counter.checked_add(1).ok_or("counter overflow")?,
                None => 0,
            };
            let mut sid = [0; 16];
            rng.fill_bytes(&mut sid);
            let mut secret = [0; 32];
            rng.fill_bytes(&mut secret);
            let verifier = crypto::hash_vinfo(&secret, ls);
            let mut plaintext = [0; ACCOUNT_LEN];
            plaintext[..32].copy_from_slice(&secret);
            plaintext[32..].copy_from_slice(&counter.to_le_bytes());
            let ciphertext = crypto::xchacha_encrypt_detached(
                &state.k0,
                &account_context(uid, ls),
                &plaintext,
                rng,
            )
            .encode();
            let records: Vec<_> = (1..=n)
                .map(|id| RecordId::Account(crypto::hash_upspa_suid(&state.rsp, ls, id as u32)))
                .collect();
            let requests = records
                .iter()
                .enumerate()
                .map(|(i, record)| {
                    (
                        Target::Provider(i as u32 + 1),
                        Request::Up(UpRequest::PrepareAccount {
                            binding: Binding {
                                sid,
                                phase,
                                record: record.clone(),
                            },
                            ciphertext: ciphertext.clone(),
                            expected: old.as_ref().map(|(_, _, ct)| ct.clone()),
                        }),
                    )
                })
                .collect();
            let ls_request = match old {
                Some((old_secret, _, _)) => LsRequest::ChangeCredential {
                    uid: login_uid.to_vec(),
                    old: crypto::hash_vinfo(&old_secret, ls),
                    new: verifier,
                },
                None => LsRequest::Register {
                    uid: login_uid.to_vec(),
                    verifier,
                },
            };
            Ok((sid, records, requests, ls_request))
        })?;
        let prepared = self.all("provider_prepare", requests).await;
        if let Err(error) = prepared {
            self.finalize(self.finals(sid, phase, records, false), false)
                .await?;
            return Err(error);
        }
        let probe = match &ls_request {
            LsRequest::Register { uid, verifier } => Request::Ls(LsRequest::Authenticate {
                uid: uid.clone(),
                verifier: *verifier,
            }),
            LsRequest::ChangeCredential { uid, new, .. } => Request::Ls(LsRequest::Authenticate {
                uid: uid.clone(),
                verifier: *new,
            }),
            _ => unreachable!(),
        };
        let ls_stage = self.trace.lock().unwrap().stages.len();
        let ls_result = self
            .all(
                "ls_interaction",
                vec![(Target::LoginServer, Request::Ls(ls_request))],
            )
            .await;
        let uncertain = ls_result.is_err()
            && !self.trace.lock().unwrap().calls.iter().any(|call| {
                call.stage_id == ls_stage
                    && call.target == Target::LoginServer
                    && call.processing_ns.is_some()
            });
        if uncertain {
            self.settle().await;
            self.ls_resolution = Some(LsResolution {
                probe,
                store: self.finals(sid, phase, records.clone(), true),
                discard: self.finals(sid, phase, records, false),
            });
            return self.resolve_ls().await;
        }
        let store = ls_result.is_ok();
        self.finalize(self.finals(sid, phase, records, store), store)
            .await?;
        ls_result
    }

    pub async fn authentication(
        &mut self,
        uid: &[u8],
        password: &[u8],
        ls: &[u8],
        login_uid: &[u8],
    ) -> Result<()> {
        self.require_idle()?;
        let state = self
            .identification(uid, password, Requirement::Threshold)
            .await?;
        let (secret, _, _) = self.recover(uid, ls, &state).await?;
        let request = self.compute(|_| {
            Request::Ls(LsRequest::Authenticate {
                uid: login_uid.to_vec(),
                verifier: crypto::hash_vinfo(&secret, ls),
            })
        });
        self.all("ls_interaction", vec![(Target::LoginServer, request)])
            .await
    }

    pub async fn password_update(
        &mut self,
        uid: &[u8],
        old_password: &[u8],
        new_password: &[u8],
    ) -> Result<()> {
        self.require_idle()?;
        let state = self
            .identification(uid, old_password, Requirement::AllProviders)
            .await?;
        let n = self.n;
        let t = self.t;
        let (sid, requests) = self.compute(|rng| -> Result<_> {
            let mut sid = [0; 16];
            rng.fill_bytes(&mut sid);
            let (key, shares) = crypto::toprf_gen(n, t, rng);
            let timestamp =
                now_ms().max(state.timestamp.checked_add(1).ok_or("timestamp overflow")?);
            let encryption =
                crypto::oprf_finalize(new_password, &(crypto::hash_to_point(new_password) * key));
            let mut plaintext = [0; ROOT_LEN];
            plaintext[..32].copy_from_slice(&state.ssk.to_bytes());
            plaintext[32..64].copy_from_slice(&state.rsp);
            plaintext[64..].copy_from_slice(&state.k0);
            let cid = crypto::xchacha_encrypt_detached(&encryption, &[], &plaintext, rng).encode();
            let requests = shares
                .into_iter()
                .map(|(id, share)| {
                    let mut update = PasswordUpdate {
                        operation: "PwdUpdate".into(),
                        sid,
                        uid: uid.to_vec(),
                        provider_id: id,
                        timestamp_old: state.timestamp,
                        timestamp_new: timestamp,
                        cid_new: cid.clone(),
                        share_new: share.to_bytes(),
                        signature: Vec::new(),
                    };
                    update.signature = state.ssk.sign(&update.signed_bytes()).to_bytes().to_vec();
                    (
                        Target::Provider(id),
                        Request::Up(UpRequest::PasswordUpdate(update)),
                    )
                })
                .collect();
            Ok((sid, requests))
        })?;
        let prepared = self.all("provider_prepare", requests).await;
        let records = (0..n).map(|_| RecordId::Root(uid.to_vec())).collect();
        self.finalize(
            self.finals(sid, Phase::PasswordUpdate, records, prepared.is_ok()),
            prepared.is_ok(),
        )
        .await?;
        prepared
    }

    pub async fn tspa_registration(
        &mut self,
        uid: &[u8],
        password: &[u8],
        ls: &[u8],
        login_uid: &[u8],
    ) -> Result<()> {
        let n = self.n;
        let t = self.t;
        let data = self.compute(|rng| tspa_adapter::registration(uid, ls, password, n, t, rng));
        let (requests, ls_request) = self.compute(|_| {
            let requests = data
                .keys
                .iter()
                .zip(&data.ciphertexts)
                .enumerate()
                .map(|(i, (key, ciphertext))| {
                    (
                        Target::Provider(i as u32 + 1),
                        Request::Tspa(TspaRequest::Register {
                            stor_uid: data.stor_uid,
                            key: key.to_bytes(),
                            ciphertext: ciphertext.to_vec(),
                        }),
                    )
                })
                .collect();
            (
                requests,
                Request::Ls(LsRequest::Register {
                    uid: login_uid.to_vec(),
                    verifier: data.verifier,
                }),
            )
        });
        self.all("provider_prepare", requests).await?;
        self.all("ls_interaction", vec![(Target::LoginServer, ls_request)])
            .await
    }

    pub async fn tspa_authentication(
        &mut self,
        uid: &[u8],
        password: &[u8],
        ls: &[u8],
        login_uid: &[u8],
    ) -> Result<()> {
        let t = self.t;
        let (r, requests) = self.compute(|rng| {
            let r = crypto_tspa::random_scalar(rng);
            let blinded = (crypto_tspa::hash_to_point(password) * r)
                .compress()
                .to_bytes();
            let stor_uid = crypto_tspa::hash_storuid(uid, ls);
            (
                r,
                (1..=t)
                    .map(|i| {
                        (
                            Target::Provider(i as u32),
                            Request::Tspa(TspaRequest::Authenticate { stor_uid, blinded }),
                        )
                    })
                    .collect(),
            )
        });
        let mut replies = self
            .stage("account_recovery", requests, Policy::All)
            .await?;
        let request = self.compute(|_| -> Result<_> {
            replies.sort_by_key(|(id, _)| *id);
            let (_, verifier) = tspa_adapter::reconstruct(password, ls, r, &replies)?;
            Ok(Request::Ls(LsRequest::Authenticate {
                uid: login_uid.to_vec(),
                verifier,
            }))
        })?;
        self.all("ls_interaction", vec![(Target::LoginServer, request)])
            .await
    }
}

fn require_ack(reply: Reply) -> Result<()> {
    if reply == Reply::Ack(true) {
        Ok(())
    } else {
        Err("operation rejected".into())
    }
}
