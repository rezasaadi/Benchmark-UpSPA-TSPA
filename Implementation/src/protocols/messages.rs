use serde::{Deserialize, Serialize};

pub type Sid = [u8; 16];
pub type Key = [u8; 32];
pub type Result<T> = std::result::Result<T, String>;
pub const ROOT_LEN: usize = 96;
pub const ACCOUNT_LEN: usize = 40;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Protocol {
    UpSPA,
    TSPA,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Phase {
    Setup,
    Registration,
    Authentication,
    SecretUpdate,
    PasswordUpdate,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RecordId {
    Root(Vec<u8>),
    Account(Key),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct Binding {
    pub sid: Sid,
    pub phase: Phase,
    pub record: RecordId,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Root {
    pub uid: Vec<u8>,
    pub svk: Key,
    pub cid: Vec<u8>,
    pub share: Key,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PasswordUpdate {
    pub operation: String,
    pub sid: Sid,
    pub uid: Vec<u8>,
    pub provider_id: u32,
    pub timestamp_old: u64,
    pub timestamp_new: u64,
    pub cid_new: Vec<u8>,
    pub share_new: Key,
    pub signature: Vec<u8>,
}

impl PasswordUpdate {
    pub fn signed_bytes(&self) -> Vec<u8> {
        bincode::serialize(&(
            &self.operation,
            self.sid,
            &self.uid,
            self.provider_id,
            self.timestamp_old,
            self.timestamp_new,
            &self.cid_new,
            self.share_new,
        ))
        .unwrap()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpRequest {
    Setup {
        sid: Sid,
        root: Root,
    },
    Identify {
        uid: Vec<u8>,
        blinded: Key,
    },
    ReadAccount {
        suid: Key,
    },
    PrepareAccount {
        binding: Binding,
        ciphertext: Vec<u8>,
        expected: Option<Vec<u8>>,
    },
    PasswordUpdate(PasswordUpdate),
    Finalize {
        binding: Binding,
        store: bool,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TspaRequest {
    Register {
        stor_uid: Key,
        key: Key,
        ciphertext: Vec<u8>,
    },
    Authenticate {
        stor_uid: Key,
        blinded: Key,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum LsRequest {
    Register { uid: Vec<u8>, verifier: Key },
    Authenticate { uid: Vec<u8>, verifier: Key },
    ChangeCredential { uid: Vec<u8>, old: Key, new: Key },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Request {
    Up(UpRequest),
    Tspa(TspaRequest),
    Ls(LsRequest),
    Reset,
    Ping,
}

impl Request {
    pub fn operation(&self) -> &'static str {
        match self {
            Self::Up(UpRequest::Setup { .. }) => "setup_prepare",
            Self::Up(UpRequest::Identify { .. }) => "identification",
            Self::Up(UpRequest::ReadAccount { .. }) => "account_read",
            Self::Up(UpRequest::PrepareAccount { .. }) => "account_prepare",
            Self::Up(UpRequest::PasswordUpdate(_)) => "password_prepare",
            Self::Up(UpRequest::Finalize { store: true, .. }) => "store_ack",
            Self::Up(UpRequest::Finalize { store: false, .. }) => "discard_ack",
            Self::Tspa(TspaRequest::Register { .. }) => "record_store",
            Self::Tspa(TspaRequest::Authenticate { .. }) => "oprf_and_record_read",
            Self::Ls(LsRequest::Register { .. }) => "ls_register",
            Self::Ls(LsRequest::Authenticate { .. }) => "ls_authenticate",
            Self::Ls(LsRequest::ChangeCredential { .. }) => "ls_change_credential",
            Self::Reset => "reset",
            Self::Ping => "ping",
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum Reply {
    Ack(bool),
    Identification {
        cid: Vec<u8>,
        timestamp: u64,
        contribution: Key,
    },
    Account(Vec<u8>),
    TspaAuthentication {
        contribution: Key,
        ciphertext: Vec<u8>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Response {
    pub result: Result<Reply>,
    pub processing_ns: u64,
}

pub fn decode_blob<const N: usize>(bytes: &[u8]) -> Result<crate::crypto::CtBlob<N>> {
    if bytes.len() != 24 + N + 16 {
        return Err("invalid ciphertext length".into());
    }
    Ok(crate::crypto::CtBlob {
        nonce: bytes[..24].try_into().unwrap(),
        ct: bytes[24..24 + N].try_into().unwrap(),
        tag: bytes[24 + N..].try_into().unwrap(),
    })
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
