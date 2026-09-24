# Measurement methodology

## Independent categories

All collected results require Linux and a release build. Both protocols use the same workspace, locked dependencies, compiler flags, std::time::Instant, and transport implementation. Environment snapshots contain CPU model/topology, logical and physical core counts, RAM, uname, WSL information when available, compiler/tool versions, git revision/status, profile, build flags, lockfile hash, and binary hashes. Build metadata comes from the actual build, including when namespace services are started as root.

Client-local values are the sum of explicit `System::compute` intervals around client work using in-memory adapters. Each interval stops before awaiting a provider or LS call; the next starts when client-side processing resumes. Thus prefetched replies are used only across these untimed local provider intervals. The reference TSPA microbenchmark remains available unchanged, and its output is checked against the new wrapper. New unified local measurements include protocol randomness and password-point hashing consistently for both schemes. They should not be combined with older Windows or pre-generated-randomness results.

| Protocol and phase | Client computation inside the timer intervals |
|---|---|
| UpSPA Setup | Random generation, TOPRF key/share generation, signing-key derivation, root encryption, and request construction |
| UpSPA Registration | Identification blinding/agreement/interpolation/root decryption, account context/address derivation, Rls sampling, account encryption, verifier construction, and response validation |
| UpSPA Authentication | Identification work, exact account agreement/decryption, verifier derivation, and response validation |
| UpSPA Secret Update | Identification and account recovery work, counter increment, fresh Rls, new verifier/ciphertext, request construction, and response validation |
| UpSPA Password Update | Identification, fresh TOPRF key/shares, new timestamp, root encryption, each provider's bound signature, request construction, and response validation |
| TSPA Registration | Original polynomial/OPRF/AES-CTR construction, protocol randomness, password-point hash, verifier derivation, storage request construction, and response validation |
| TSPA Authentication | Password-point hash and blinding, address derivation, unblinding/finalization, AES-CTR share decryption, interpolation/verifier derivation, and response validation |

Provider-local values time `Node::handle` after acquiring that provider's mutex and before serializing its response. This includes the actual provider computation and map operations, not socket waiting, queue waiting, client work, or LS work. Every observed provider request records operation, provider ID, deployment, phase, and processing_ns. The paper-facing SP-local statistic sums that provider's request processing within each phase/run and takes the distribution over participating provider/run samples. Per-operation distributions are retained separately. It is neither a sum across providers nor a maximum-provider critical-path estimate.

Network E2E values are measured independently around `invoke`, immediately before entering the complete phase and immediately after it returns. They are never obtained by adding local times to simulated network values. Setup includes generation, prepare, and final delivery ACKs. Registration includes Identification where defined, provider storage/preparation, LS registration, and UpSPA finalization. Authentication includes live provider requests, reconstruction, and LS result. Secret Update includes Identification, recovery, preparation, ordinary LS change, and provider finalization. Password Update includes Identification, rekeying/encryption/signing, preparation, and provider finalization.

All successful write E2E timers end only after application delivery acknowledgements for provider finalization. This adds a measured response at every provider and a causal finalization stage. Failed retries are measured and traced too. Stage timing columns measure the actual request-stage dispatch/wait/response-processing interval; client crypto between stages remains in total E2E and the separate client-local timing, so stage columns are not intended to sum exactly to E2E.

## Fixtures, sockets, and concurrency

Every warmup and measured run performs an untimed reset followed by the phase's valid prerequisites: no root for Setup; committed root for Registration and Password Update; committed root/account for Authentication and Secret Update; installed original TSPA records/verifier for TSPA Authentication. Fixture traffic and its traces are excluded from the measured run. Fresh deterministic per-phase/run RNG seeds prevent accidental sharing of generated protocol values between measured runs while allowing reproducibility.

Network services and initial TCP connections start before warmup. Connections use TCP_NODELAY and length-prefixed bincode request/response frames. Both protocols use the same framing. The reset path is enabled only when a node starts with `--allow-benchmark-reset`; the harness sends it between completed runs through the existing endpoint connections. Fixture/reset traffic is not timed as protocol work.

Every provider request in a logical stage is a spawned Tokio task. Provider state handlers run on blocking worker threads for genuine in-memory concurrency and in distinct processes for the namespace experiment. Barrier-based tests catch sequential dispatch. True dependencies remain sequential: UpSPA prepare, then LS mutation, then finalization. TSPA provider writes are followed by LS registration because overlap is not established by the source.

Per-stage deadlines bound the client's wait. A timed-out network connection is closed and can reconnect on the next request; any recovery reconnect occurs inside the relevant phase. Threshold tasks finish reading already-issued frames after the phase returns and are drained outside its timer. Raw communication totals include these observed replies, and JSONL traces preserve every request. Transport-failure byte totals are left missing when the actual delivered count is unknown; they are never replaced by estimated payload constants. Byte totals include four-byte frame lengths and serialized application payloads, excluding TCP/IP/Ethernet headers and retransmissions.

## Isolated Linux topology

`bench-switch` contains `br-bench` and the bridge ends of all veth pairs. Keeping the switch in its own namespace prevents host bridge filtering or Docker/WSL forwarding configuration from affecting this experiment. There is no bridge address or default route to the host network.

| Namespace | Protocol address | Namespace interface | Bridge-side veth |
|---|---|---|---|
| bench-client | 10.210.0.2/24 | eth-bench | vbench-c |
| bench-sp1 ... bench-spN | 10.210.0.11 ... 10.210.0.(10+N)/24 | eth-bench | vbench-s1 ... vbench-sN |
| bench-ls | 10.210.0.200/24 | eth-bench | vbench-l |

All namespaces also have loopback enabled. Measured TCP traffic uses only the listed addresses, port 42000. Loopback TCP is used solely in untimed integration tests. Namespace commands never apply qdiscs to WSL's main eth0.

## Profiles and verification

For every client, provider, and LS namespace, the LAN rule is:

```bash
ip netns exec NAMESPACE tc qdisc replace dev eth-bench root handle 1: netem limit 10000 delay 0.250000000ms 0.035355339ms distribution normal rate 1000mbit
```

The WAN rule is:

```bash
ip netns exec NAMESPACE tc qdisc replace dev eth-bench root handle 1: netem limit 10000 delay 30.000000000ms 3.535533906ms distribution normal rate 50mbit
```

Each path crosses client egress and remote egress. Requested mean RTT R is split into R/2 on each direction. Assuming independent normal directional jitter, requested RTT standard deviation J is split into J/sqrt(2) per direction. The scripts expose both the requested profile and the qdisc-reported, potentially quantized configuration. Netem rate applies per namespace egress, so client egress bandwidth is shared by concurrent provider traffic.

Kernel timer resolution, VM scheduling, baseline processing, and netem rate granularity can make measured RTT/jitter differ from requested targets. These limitations are documented by [tc-netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html). TCP throughput-sensitive experiments have additional netem placement concerns; this harness implements the requested namespace-egress latency topology and records actual execution.

Ping verification runs from the client to every provider and LS. Per-path output, packet loss, min/mean/max/mdev, sample count, tolerance, profile hash, and topology token are saved. Default acceptance requires zero packet loss and mean within max(1 ms, 15% of requested RTT). The user can tighten `--tolerance-ms` and `--tolerance-fraction`. Acceptance is a configurable functional check, not a claim that sub-millisecond jitter targets are achieved. The network runner checks active qdiscs against the saved configuration and refuses stale or failed ping verification. Verification older than one hour must be repeated.

## Statistics

Raw samples are flushed after each measured run. A failed run is retained with its error, success=false, and any observed timing/communication. Fixture failures are recorded without a phase latency. Warmup records are retained in JSONL and excluded from reported distributions. Successful timed populations determine p50/p95/mean/stddev/min/max; count and success/failure count remain explicit. Quantiles use linear interpolation and standard deviation uses the sample estimator. p99 requires 1000 successful timed samples. Missing categories remain empty in the paper-facing table.

Summary grouping includes deployment, scheme, phase, mode, exact profile label, and environment ID. SP-local summaries never use provider timings from network runs. Different binary/toolchain/environment fingerprints are kept separate. No script edits LaTeX or replaces existing paper numbers.
