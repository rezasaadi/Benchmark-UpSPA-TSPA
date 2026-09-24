# UpSPA and TSPA benchmark

A unified Rust benchmark for UpSPA and TSPA with separate client computation, storage-provider computation, and actual TCP end-to-end measurements over Linux LAN/WAN profiles.

The optimized UpSPA implementation tracks agreement incrementally and reuses accepted threshold replies. The TSPA reference construction is unchanged. UpSPA supports Setup, Registration, Authentication, Secret Update, and Password Update; TSPA supports Registration and Authentication.

## Repository structure

```text
Cargo.toml                 Workspace and release-build settings
Cargo.lock                 Locked Rust dependencies
Implementation/
  Cargo.toml               Benchmark crate
  src/                     Protocols, cryptography, transport, and measurement
    bin/bench_unified.rs   Unified benchmark executable
    bin/network-node.rs    Storage-provider and login-server executable
  tests/                   Protocol, recovery, and transport integration tests
  dockerfile               Optional container build
configs/                   Local, LAN, WAN, and deployment-grid settings
scripts/
  build.sh                 Release build and build metadata
  test.sh                  Rust and Python tests
  run.py                   Local and network experiment driver
  summarize.py             Summary CSV/JSON generation
  environment.py           Environment and build fingerprinting
  local/                   Client-local and provider-local entry points
  netns/                   Linux namespaces, traffic shaping, and verification
  tests/                   Summary tests
docs/                      Protocol mapping and measurement methodology
```

## Build and test

Use Linux or Ubuntu under WSL2, with Rust/Cargo, Python 3.11+, `iproute2`, and `iputils-ping` installed. Run commands from the repository root. Measurement collection requires Linux and a release build. Network experiments require permission to run `sudo` and a kernel supporting network namespaces, veth, and netem.

```bash
export CARGO_TARGET_DIR="$HOME/upspa-tspa-optimized-target"
bash scripts/build.sh
bash scripts/test.sh
```

Keep `CARGO_TARGET_DIR` set to the same location when running experiments. Rebuild after changing Rust sources or dependencies; collection checks the recorded source and binary hashes.

## Client and storage-provider computation

Run both local categories for three providers and threshold two, with 50 warmup and 200 measured runs per phase:

```bash
python3 scripts/run.py local --n-sp 3 --t-sp 2 --warmup 50 --measured 200 --out results/local-3-2
```

Run each category across the supplied deployment grid:

```bash
bash scripts/local/run_client.sh --warmup 50 --measured 200 --out results/client
bash scripts/local/run_sp.sh --warmup 50 --measured 200 --out results/providers
```

Client-local timing sums client computation intervals and excludes waiting for provider or login-server calls. The SP-local phase statistic sums each provider's request-processing times within a run, then summarizes the population of provider/run totals. It is not a sum across providers or a maximum-provider estimate.

## LAN and WAN end-to-end experiments

The driver creates the topology, applies and verifies the profile, starts services, collects measurements, and tears down its namespaces:

```bash
python3 scripts/run.py network --profile lan --n-sp 3 --t-sp 2 --warmup 50 --measured 200 --out results/lan-3-2
python3 scripts/run.py network --profile wan --n-sp 3 --t-sp 2 --warmup 50 --measured 200 --out results/wan-3-2
```

| Profile | Requested RTT | RTT jitter standard deviation | Egress bandwidth |
|---|---:|---:|---:|
| LAN | 0.5 ms | 0.05 ms | 1000 Mbit/s |
| WAN | 60 ms | 5 ms | 50 Mbit/s |

RTT and jitter are split across namespace egress directions. The runner records the actual qdisc configuration and ping verification. Measured end-to-end latency comes from complete live protocol execution; it is not calculated by adding local measurements to nominal network delays.

Omit `--n-sp` and `--t-sp` to use `configs/deployment_grid.csv`, or provide `--grid PATH` with `n_sp,t_sp` columns. Network configurations with more than ten providers require `--allow-large-network`.

Sample counts are explicit in the examples for reproducibility. The Python driver defaults to 50/200 warmup/measured runs locally and 5/20 for network runs; `--paper` changes the network defaults to 10/100. The low-level Rust executable defaults to 50/200. Explicit `--warmup` and `--measured` override these defaults.

## Selecting phases and configurations

```bash
python3 scripts/run.py local --scheme upspa --phase authentication --n-sp 10 --t-sp 6 --warmup 50 --measured 200 --out results/authentication-10-6
python3 scripts/run.py local --scheme upspa --phase secret-update --n-sp 10 --t-sp 6 --warmup 50 --measured 200 --out results/secret-update-10-6
python3 scripts/run.py local --sweep threshold30 --out results/threshold30
python3 scripts/run.py local --sweep scale60 --out results/scale60
```

`threshold30` enumerates every threshold from 1 to 30 at 30 providers. `scale60` enumerates every provider count from 10 to 100 with threshold `ceil(0.6*n)`. Network profiles can be adjusted with `--rtt-ms`, `--jitter-ms`, and `--bandwidth-mbps`; modified profiles are summarized separately.

## Outputs and summaries

Choose a new output directory for each experiment. Existing output directories are rejected. Each result set contains raw timing CSVs, provider-request timings, stage timings, JSONL traces, and environment/build metadata. Network result sets also contain profile and ping-verification records.

```bash
python3 scripts/summarize.py results --out results/summary
```

`summary/paper.csv` provides client-local, SP-local, LAN E2E, and WAN E2E p50 columns per deployment and environment. `summary.csv` and `summary.json` additionally contain counts, failures, p95, mean, sample standard deviation, minimum, and maximum. p99 requires at least 1000 successful timed samples. Latency statistics use successful timed runs; failed runs remain recorded. Different environment fingerprints and network profiles are kept separate.

A functional smoke run uses `--smoke --warmup 0 --measured 1`. The driver includes smoke samples in that run's immediate summary; ordinary later summary generation excludes them unless `--include-smoke` is supplied. Smoke results are not performance measurements.

## Optional container build

Build from the repository root:

```bash
docker build -f Implementation/dockerfile -t upspa-tspa-optimized .
docker run --rm upspa-tspa-optimized --help
```

The container entry point is `bench_unified`. The namespace workflow above runs on the Linux host or in WSL2.


