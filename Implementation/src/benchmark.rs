use crate::{
    protocols::{messages::*, system::System},
    transport::{InMemoryTransport, NetworkTransport, Target, Transport},
};
use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    ClientLocal,
    SpLocal,
    Network,
}

#[derive(Parser, Debug)]
#[command(about = "UpSPA/TSPA computation and real TCP benchmark")]
pub struct Args {
    #[arg(long, value_enum)]
    pub mode: Mode,
    #[arg(long, default_value = "all")]
    pub scheme: String,
    #[arg(long, default_value = "all")]
    pub phase: String,
    #[arg(long, alias = "nsp", default_value_t = 3)]
    pub n_sp: usize,
    #[arg(long, alias = "tsp", default_value_t = 2)]
    pub t_sp: usize,
    #[arg(long)]
    pub warmup: Option<usize>,
    #[arg(long)]
    pub measured: Option<usize>,
    #[arg(long, default_value = "results/run")]
    pub out: PathBuf,
    #[arg(long)]
    pub endpoints: Option<PathBuf>,
    #[arg(long)]
    pub profile_metadata: Option<PathBuf>,
    #[arg(long)]
    pub ping: Option<PathBuf>,
    #[arg(long, default_value_t = 10000)]
    pub deadline_ms: u64,
    #[arg(long, default_value_t = 300000)]
    pub clock_window_ms: u64,
    #[arg(long)]
    pub smoke: bool,
}

#[derive(Clone, Debug, Deserialize)]
pub struct Endpoints {
    pub providers: Vec<String>,
    pub login_server: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Profile {
    pub network_profile: String,
    pub requested_rtt_ms: f64,
    pub requested_jitter_ms: f64,
    pub bandwidth_mbps: f64,
    pub one_way_delay_ms: f64,
    pub one_way_jitter_ms: f64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Ping {
    pub measured_ping_rtt_ms: f64,
    pub verified: bool,
}

#[derive(Serialize)]
pub struct RunRow {
    pub protocol: Protocol,
    pub phase: Phase,
    pub n_sp: usize,
    pub t_sp: usize,
    pub mode: String,
    pub network_profile: String,
    pub requested_rtt_ms: Option<f64>,
    pub measured_ping_rtt_ms: Option<f64>,
    pub requested_jitter_ms: Option<f64>,
    pub bandwidth_mbps: Option<f64>,
    pub run_index: usize,
    pub success: bool,
    pub client_local_ms: Option<f64>,
    pub total_e2e_ms: Option<f64>,
    pub bytes_sent: Option<u64>,
    pub bytes_received: Option<u64>,
    pub application_messages: usize,
    pub causal_network_stages: usize,
    pub identification_ms: f64,
    pub account_recovery_ms: f64,
    pub provider_prepare_ms: f64,
    pub ls_interaction_ms: f64,
    pub finalization_ms: f64,
    pub error: String,
}

#[derive(Serialize)]
struct SpRow {
    protocol: Protocol,
    phase: Phase,
    n_sp: usize,
    t_sp: usize,
    mode: String,
    network_profile: String,
    run_index: usize,
    run_success: bool,
    provider_id: u32,
    stage_id: usize,
    operation: String,
    success: bool,
    processing_ns: Option<u64>,
    sp_local_ms: Option<f64>,
    error: String,
}

#[derive(Serialize)]
struct StageRow {
    protocol: Protocol,
    phase: Phase,
    n_sp: usize,
    t_sp: usize,
    mode: String,
    network_profile: String,
    run_index: usize,
    success: bool,
    stage_id: usize,
    stage: String,
    elapsed_ms: f64,
    requests: usize,
}

pub fn phases(scheme: &str, selected: &str) -> anyhow::Result<Vec<(Protocol, Phase)>> {
    let all = vec![
        (Protocol::UpSPA, Phase::Setup),
        (Protocol::TSPA, Phase::Registration),
        (Protocol::UpSPA, Phase::Registration),
        (Protocol::TSPA, Phase::Authentication),
        (Protocol::UpSPA, Phase::Authentication),
        (Protocol::UpSPA, Phase::SecretUpdate),
        (Protocol::UpSPA, Phase::PasswordUpdate),
    ];
    anyhow::ensure!(["all", "upspa", "tspa"].contains(&scheme), "invalid scheme");
    let result: Vec<_> = all
        .into_iter()
        .filter(|(protocol, phase)| {
            (scheme == "all" || scheme == format!("{protocol:?}").to_lowercase())
                && (selected == "all"
                    || selected
                        .replace(['-', '_'], "")
                        .eq_ignore_ascii_case(&format!("{phase:?}")))
        })
        .collect();
    anyhow::ensure!(!result.is_empty(), "no protocol phase matches");
    Ok(result)
}

const UID: &[u8] = b"user123";
const LS: &[u8] = b"LS1";
const LOGIN: &[u8] = b"stable-login-user";
const PASSWORD: &[u8] = b"benchmark password";
const NEW_PASSWORD: &[u8] = b"updated benchmark password";

pub async fn invoke(system: &mut System, protocol: Protocol, phase: Phase) -> Result<()> {
    match (protocol, phase) {
        (Protocol::UpSPA, Phase::Setup) => system.setup(UID, PASSWORD).await,
        (Protocol::UpSPA, Phase::Registration) => {
            system.registration(UID, PASSWORD, LS, LOGIN).await
        }
        (Protocol::UpSPA, Phase::Authentication) => {
            system.authentication(UID, PASSWORD, LS, LOGIN).await
        }
        (Protocol::UpSPA, Phase::SecretUpdate) => {
            system.secret_update(UID, PASSWORD, LS, LOGIN).await
        }
        (Protocol::UpSPA, Phase::PasswordUpdate) => {
            system.password_update(UID, PASSWORD, NEW_PASSWORD).await
        }
        (Protocol::TSPA, Phase::Registration) => {
            system.tspa_registration(UID, PASSWORD, LS, LOGIN).await
        }
        (Protocol::TSPA, Phase::Authentication) => {
            system.tspa_authentication(UID, PASSWORD, LS, LOGIN).await
        }
        _ => Err("phase not defined by TSPA".into()),
    }
}

pub async fn fixture(system: &mut System, protocol: Protocol, phase: Phase) -> Result<()> {
    system.reset().await?;
    match protocol {
        Protocol::UpSPA => {
            if phase != Phase::Setup {
                system.setup(UID, PASSWORD).await?;
            }
            if matches!(phase, Phase::Authentication | Phase::SecretUpdate) {
                system.registration(UID, PASSWORD, LS, LOGIN).await?;
            }
        }
        Protocol::TSPA => {
            if phase == Phase::Authentication {
                system.tspa_registration(UID, PASSWORD, LS, LOGIN).await?;
            }
        }
    }
    system.settle().await;
    system.clear_trace();
    Ok(())
}

pub fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn ms(value: u64) -> f64 {
    value as f64 / 1_000_000.0
}

pub async fn run(args: Args) -> anyhow::Result<()> {
    anyhow::ensure!(
        cfg!(target_os = "linux"),
        "benchmark collection requires Linux/WSL; unit tests are portable"
    );
    anyhow::ensure!(
        !cfg!(debug_assertions),
        "benchmark collection requires --release"
    );
    anyhow::ensure!(
        args.n_sp >= 1 && args.n_sp <= 100 && args.t_sp >= 1 && args.t_sp <= args.n_sp,
        "invalid deployment configuration"
    );
    anyhow::ensure!(args.deadline_ms > 0, "deadline must be positive");
    let selected = phases(&args.scheme, &args.phase)?;
    let network = args.mode == Mode::Network;
    let warmup = args.warmup.unwrap_or(50);
    let measured = args.measured.unwrap_or(200);
    anyhow::ensure!(measured > 0, "measured count must be positive");
    anyhow::ensure!(
        !args.out.exists(),
        "output directory exists; choose a new result directory"
    );
    let timeout = Duration::from_millis(args.deadline_ms);
    let (transport, profile, ping): (Arc<dyn Transport>, Profile, Ping) = if network {
        let endpoints: Endpoints = read_json(
            args.endpoints
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--endpoints required"))?,
        )?;
        anyhow::ensure!(
            endpoints.providers.len() == args.n_sp,
            "endpoint count differs from n_sp"
        );
        let mut targets = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for (i, address) in endpoints.providers.iter().enumerate() {
            let parsed: std::net::SocketAddr = address.parse()?;
            anyhow::ensure!(
                parsed.ip()
                    == std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 210, 0, i as u8 + 11)),
                "provider endpoint must use namespace address"
            );
            anyhow::ensure!(seen.insert(parsed), "duplicate endpoint");
            targets.push((Target::Provider(i as u32 + 1), address.clone()));
        }
        let ls_address: std::net::SocketAddr = endpoints.login_server.parse()?;
        anyhow::ensure!(
            ls_address.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 210, 0, 200)),
            "LS must use namespace address"
        );
        targets.push((Target::LoginServer, endpoints.login_server));
        let profile: Profile = read_json(
            args.profile_metadata
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--profile-metadata required"))?,
        )?;
        let ping: Ping = read_json(
            args.ping
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("--ping required"))?,
        )?;
        anyhow::ensure!(
            ping.verified && ping.measured_ping_rtt_ms.is_finite(),
            "ping verification required"
        );
        (
            Arc::new(
                NetworkTransport::connect(&targets, timeout)
                    .await
                    .map_err(anyhow::Error::msg)?,
            ),
            profile,
            ping,
        )
    } else {
        (
            Arc::new(InMemoryTransport::new(args.n_sp, args.clock_window_ms)),
            Profile {
                network_profile: "local".into(),
                ..Default::default()
            },
            Ping::default(),
        )
    };
    std::fs::create_dir_all(&args.out)?;
    let executable = std::env::current_exe()?;
    let target = executable
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| anyhow::anyhow!("cannot locate build target"))?;
    let environment_script = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("scripts/environment.py");
    let environment_status = std::process::Command::new("python3")
        .arg(environment_script)
        .arg("--target")
        .arg(target)
        .arg("--out")
        .arg(args.out.join("environment.json"))
        .status()?;
    anyhow::ensure!(environment_status.success(), "environment capture failed");
    if let Some(path) = &args.profile_metadata {
        std::fs::copy(path, args.out.join("profile.json"))?;
    }
    if let Some(path) = &args.ping {
        std::fs::copy(path, args.out.join("ping.json"))?;
    }
    let mode = match args.mode {
        Mode::ClientLocal => "client_local",
        Mode::SpLocal => "sp_local",
        Mode::Network => "network",
    };
    std::fs::write(
        args.out.join("run.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "mode": mode, "warmup": warmup, "measured": measured, "n_sp": args.n_sp, "t_sp": args.t_sp,
            "purpose": if args.smoke { "smoke" } else { "measurement" },
            "scheme": args.scheme, "phase": args.phase, "deadline_ms": args.deadline_ms, "clock_window_ms": args.clock_window_ms,
            "rng": "ChaCha20 deterministic per protocol/phase/run; protocol randomness included in client timing",
            "timer": "std::time::Instant", "profile": "release", "bytes_scope": "application framing; late threshold replies drained after phase timer; failed transport byte counts unknown"
        }))?,
    )?;
    let raw_path = args.out.join("raw");
    std::fs::create_dir(&raw_path)?;
    let mut run_csv = csv::Writer::from_path(raw_path.join(if network {
        "e2e.csv"
    } else if args.mode == Mode::SpLocal {
        "sp_runs.csv"
    } else {
        "client_local.csv"
    }))?;
    let mut sp_csv = csv::Writer::from_path(raw_path.join("sp_requests.csv"))?;
    let mut stage_csv = csv::Writer::from_path(raw_path.join("stage_timings.csv"))?;
    let mut trace_file = std::fs::File::create(raw_path.join("traces.jsonl"))?;
    let mut failures = 0usize;
    for (protocol, phase) in selected {
        for iteration in 0..warmup + measured {
            let seed = *blake3::hash(
                format!(
                    "{protocol:?}/{phase:?}/{}/{}/{iteration}",
                    args.n_sp, args.t_sp
                )
                .as_bytes(),
            )
            .as_bytes();
            let mut system = System::new(args.n_sp, args.t_sp, transport.clone(), seed, timeout)
                .map_err(anyhow::Error::msg)?;
            let fixture_result = fixture(&mut system, protocol, phase).await;
            let mut elapsed = None;
            let result = match fixture_result {
                Ok(()) => {
                    let start = Instant::now();
                    let result = invoke(&mut system, protocol, phase).await;
                    elapsed = Some(start.elapsed().as_nanos() as u64);
                    result
                }
                Err(error) => {
                    system.clear_trace();
                    Err(format!("fixture failed outside timer: {error}"))
                }
            };
            system.settle().await;
            let trace = system.trace.lock().unwrap().clone();
            if iteration < warmup {
                if result.is_err() {
                    failures += 1;
                }
                use std::io::Write;
                writeln!(
                    trace_file,
                    "{}",
                    serde_json::to_string(
                        &serde_json::json!({ "protocol": protocol, "phase": phase, "warmup_index": iteration, "success": result.is_ok(), "error": result.err(), "trace": trace })
                    )?
                )?;
                continue;
            }
            let index = iteration - warmup;
            let success = result.is_ok();
            if !success {
                failures += 1;
            }
            let stage_total = |name: &str| {
                trace
                    .stages
                    .iter()
                    .filter(|s| s.stage == name)
                    .fold(0.0, |total, s| total + ms(s.elapsed_ns))
            };
            let sum_bytes = |sent: bool| {
                trace.calls.iter().try_fold(0u64, |sum, call| {
                    if sent {
                        call.bytes_sent
                    } else {
                        call.bytes_received
                    }
                    .map(|v| sum + v)
                })
            };
            let row = RunRow {
                protocol,
                phase,
                n_sp: args.n_sp,
                t_sp: args.t_sp,
                mode: mode.into(),
                network_profile: profile.network_profile.clone(),
                requested_rtt_ms: network.then_some(profile.requested_rtt_ms),
                measured_ping_rtt_ms: network.then_some(ping.measured_ping_rtt_ms),
                requested_jitter_ms: network.then_some(profile.requested_jitter_ms),
                bandwidth_mbps: network.then_some(profile.bandwidth_mbps),
                run_index: index,
                success,
                client_local_ms: (args.mode == Mode::ClientLocal && elapsed.is_some())
                    .then_some(ms(trace.client_ns)),
                total_e2e_ms: if network { elapsed.map(ms) } else { None },
                bytes_sent: if network { sum_bytes(true) } else { None },
                bytes_received: if network { sum_bytes(false) } else { None },
                application_messages: trace
                    .calls
                    .iter()
                    .map(|c| {
                        usize::from(c.bytes_sent.is_some())
                            + usize::from(c.bytes_received.is_some())
                    })
                    .sum(),
                causal_network_stages: trace.stages.len(),
                identification_ms: stage_total("identification"),
                account_recovery_ms: stage_total("account_recovery"),
                provider_prepare_ms: stage_total("provider_prepare"),
                ls_interaction_ms: stage_total("ls_interaction"),
                finalization_ms: stage_total("finalization"),
                error: result.err().unwrap_or_default(),
            };
            run_csv.serialize(&row)?;
            for call in &trace.calls {
                if let Target::Provider(provider_id) = call.target {
                    sp_csv.serialize(SpRow {
                        protocol,
                        phase,
                        n_sp: args.n_sp,
                        t_sp: args.t_sp,
                        mode: mode.into(),
                        network_profile: profile.network_profile.clone(),
                        run_index: index,
                        run_success: success,
                        provider_id,
                        stage_id: call.stage_id,
                        operation: call.operation.clone(),
                        success: call.success,
                        processing_ns: call.processing_ns,
                        sp_local_ms: call.processing_ns.map(ms),
                        error: call.error.clone(),
                    })?;
                }
            }
            for stage in &trace.stages {
                stage_csv.serialize(StageRow {
                    protocol,
                    phase,
                    n_sp: args.n_sp,
                    t_sp: args.t_sp,
                    mode: mode.into(),
                    network_profile: profile.network_profile.clone(),
                    run_index: index,
                    success,
                    stage_id: stage.stage_id,
                    stage: stage.stage.clone(),
                    elapsed_ms: ms(stage.elapsed_ns),
                    requests: stage.requests,
                })?;
            }
            use std::io::Write;
            writeln!(
                trace_file,
                "{}",
                serde_json::to_string(&serde_json::json!({"run": row, "trace": trace}))?
            )?;
            run_csv.flush()?;
            sp_csv.flush()?;
            stage_csv.flush()?;
        }
        println!("{protocol:?} {phase:?}: {measured} measured runs ({warmup} warmup)");
    }
    anyhow::ensure!(
        failures == 0,
        "{failures} measured or warmup runs failed; all records retained in {}",
        args.out.display()
    );
    Ok(())
}
