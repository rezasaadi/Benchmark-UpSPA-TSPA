use crate::protocols::{
    login_server::LoginServer, messages::*, provider::UpSpaProvider, sp::TspaProvider, tspa_adapter,
};
use async_trait::async_trait;
use curve25519_dalek::scalar::Scalar;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex as StdMutex},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};

const MAX_FRAME: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Target {
    Provider(u32),
    LoginServer,
}

#[derive(Clone, Debug)]
pub struct Packet {
    pub response: Response,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Clone)]
pub enum Node {
    Provider {
        upspa: Box<UpSpaProvider>,
        tspa: TspaProvider,
    },
    LoginServer(LoginServer),
}

impl Node {
    pub fn provider(id: u32, clock_window_ms: u64) -> Self {
        Self::Provider {
            upspa: Box::new(UpSpaProvider::new(id, clock_window_ms)),
            tspa: TspaProvider::new(id, Scalar::ONE),
        }
    }
    pub fn handle(&mut self, request: Request) -> Response {
        let start = Instant::now();
        let result = match request {
            Request::Reset => {
                *self = match self {
                    Self::Provider { upspa, .. } => {
                        Self::provider(upspa.provider_id, upspa.clock_window_ms)
                    }
                    Self::LoginServer(_) => Self::LoginServer(LoginServer::default()),
                };
                Ok(Reply::Ack(true))
            }
            Request::Ping => Ok(Reply::Ack(true)),
            Request::Up(request) => match self {
                Self::Provider { upspa, .. } => upspa.handle(request, now_ms()),
                _ => Err("wrong node".into()),
            },
            Request::Tspa(request) => match self {
                Self::Provider { tspa, .. } => tspa_adapter::handle(tspa, request),
                _ => Err("wrong node".into()),
            },
            Request::Ls(request) => match self {
                Self::LoginServer(ls) => ls.handle(request),
                _ => Err("wrong node".into()),
            },
        };
        Response {
            result,
            processing_ns: start.elapsed().as_nanos().min(u64::MAX as u128) as u64,
        }
    }
}

#[async_trait]
pub trait Transport: Send + Sync {
    async fn call(&self, target: Target, request: Request) -> Result<Packet>;
}

#[derive(Clone)]
pub struct InMemoryTransport {
    pub nodes: HashMap<Target, Arc<StdMutex<Node>>>,
}

impl InMemoryTransport {
    pub fn new(n: usize, clock_window_ms: u64) -> Self {
        let mut nodes: HashMap<_, _> = (1..=n)
            .map(|id| {
                (
                    Target::Provider(id as u32),
                    Arc::new(StdMutex::new(Node::provider(id as u32, clock_window_ms))),
                )
            })
            .collect();
        nodes.insert(
            Target::LoginServer,
            Arc::new(StdMutex::new(Node::LoginServer(LoginServer::default()))),
        );
        Self { nodes }
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        let node = self.nodes.get(&target).ok_or("missing endpoint")?.clone();
        tokio::task::spawn_blocking(move || {
            let response = node.lock().unwrap().handle(request);
            Packet {
                response,
                bytes_sent: 0,
                bytes_received: 0,
            }
        })
        .await
        .map_err(|e| e.to_string())
    }
}

pub struct NetworkTransport {
    connections: HashMap<Target, Arc<Mutex<Option<TcpStream>>>>,
    endpoints: HashMap<Target, String>,
    pub timeout: Duration,
}

impl NetworkTransport {
    pub async fn connect(endpoints: &[(Target, String)], timeout: Duration) -> Result<Self> {
        let futures = endpoints.iter().map(|(target, address)| async move {
            let stream = tokio::time::timeout(timeout, TcpStream::connect(address))
                .await
                .map_err(|_| "connection deadline")?
                .map_err(|e| e.to_string())?;
            stream.set_nodelay(true).map_err(|e| e.to_string())?;
            Ok((*target, Arc::new(Mutex::new(Some(stream)))))
        });
        let pairs: Vec<Result<_>> = futures::future::join_all(futures).await;
        let connections = pairs.into_iter().collect::<Result<HashMap<_, _>>>()?;
        Ok(Self {
            connections,
            endpoints: endpoints.iter().cloned().collect(),
            timeout,
        })
    }
}

pub async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > MAX_FRAME {
        return Err("frame exceeds size limit".into());
    }
    stream
        .write_u32_le(bytes.len() as u32)
        .await
        .map_err(|e| e.to_string())?;
    stream.write_all(bytes).await.map_err(|e| e.to_string())
}

pub async fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let size = stream.read_u32_le().await.map_err(|e| e.to_string())? as usize;
    if size > MAX_FRAME {
        return Err("frame exceeds size limit".into());
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|e| e.to_string())?;
    Ok(bytes)
}

#[async_trait]
impl Transport for NetworkTransport {
    async fn call(&self, target: Target, request: Request) -> Result<Packet> {
        let connection = self.connections.get(&target).ok_or("missing endpoint")?;
        let mut guard = connection.lock().await;
        if guard.is_none() {
            let stream =
                tokio::time::timeout(self.timeout, TcpStream::connect(&self.endpoints[&target]))
                    .await
                    .map_err(|_| "reconnection deadline")?
                    .map_err(|e| e.to_string())?;
            stream.set_nodelay(true).map_err(|e| e.to_string())?;
            *guard = Some(stream);
        }
        let stream = guard
            .as_mut()
            .ok_or("connection closed after transport failure")?;
        let result = tokio::time::timeout(self.timeout, async {
            let bytes = bincode::serialize(&request).map_err(|e| e.to_string())?;
            write_frame(stream, &bytes).await?;
            let received = read_frame(stream).await?;
            let response = bincode::deserialize(&received).map_err(|e| e.to_string())?;
            Ok(Packet {
                response,
                bytes_sent: bytes.len() as u64 + 4,
                bytes_received: received.len() as u64 + 4,
            })
        })
        .await
        .unwrap_or_else(|_| Err("request deadline exceeded".into()));
        if result.is_err() {
            *guard = None;
        }
        result
    }
}

pub async fn serve(listener: TcpListener, node: Node, allow_reset: bool) -> Result<()> {
    let state = Arc::new(StdMutex::new(node));
    loop {
        let (mut stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let state = state.clone();
        tokio::spawn(async move {
            while let Ok(bytes) = read_frame(&mut stream).await {
                let Ok(request) = bincode::deserialize::<Request>(&bytes) else {
                    break;
                };
                let response = if matches!(request, Request::Reset) && !allow_reset {
                    Response {
                        result: Err("benchmark reset disabled".into()),
                        processing_ns: 0,
                    }
                } else {
                    let state = state.clone();
                    match tokio::task::spawn_blocking(move || state.lock().unwrap().handle(request))
                        .await
                    {
                        Ok(r) => r,
                        Err(_) => break,
                    }
                };
                let Ok(bytes) = bincode::serialize(&response) else {
                    break;
                };
                if write_frame(&mut stream, &bytes).await.is_err() {
                    break;
                }
            }
        });
    }
}
