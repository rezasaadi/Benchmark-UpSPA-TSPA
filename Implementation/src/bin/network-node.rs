use clap::Parser;
use std::net::SocketAddr;
use tspa::{
    protocols::login_server::LoginServer,
    transport::{serve, Node},
};

#[derive(Parser)]
struct Args {
    #[arg(long)]
    listen: SocketAddr,
    #[arg(long)]
    provider_id: Option<u32>,
    #[arg(long, default_value_t = 300_000)]
    clock_window_ms: u64,
    #[arg(long)]
    allow_benchmark_reset: bool,
}

#[tokio::main(worker_threads = 2)]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let node = match args.provider_id {
        Some(0) => anyhow::bail!("provider ids are one-based"),
        Some(id) => Node::provider(id, args.clock_window_ms),
        None => Node::LoginServer(LoginServer::default()),
    };
    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    println!("ready {}", listener.local_addr()?);
    serve(listener, node, args.allow_benchmark_reset)
        .await
        .map_err(anyhow::Error::msg)
}
