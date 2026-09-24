use super::messages::*;
use std::collections::HashMap;

#[derive(Clone, Default)]
pub struct LoginServer {
    pub current: HashMap<Vec<u8>, Key>,
}

impl LoginServer {
    pub fn handle(&mut self, request: LsRequest) -> Result<Reply> {
        match request {
            LsRequest::Register { uid, verifier } => {
                if self.current.contains_key(&uid) {
                    return Err("already registered".into());
                }
                self.current.insert(uid, verifier);
                Ok(Reply::Ack(true))
            }
            LsRequest::Authenticate { uid, verifier } => {
                Ok(Reply::Ack(self.current.get(&uid) == Some(&verifier)))
            }
            LsRequest::ChangeCredential { uid, old, new } => {
                if self.current.get(&uid) != Some(&old) {
                    return Err("old verifier mismatch".into());
                }
                self.current.insert(uid, new);
                Ok(Reply::Ack(true))
            }
        }
    }
}
