use clap::Parser;

#[tokio::main(worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    tspa::benchmark::run(tspa::benchmark::Args::parse()).await
}
