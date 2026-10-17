# Protocol conformance

Changes follow "Secure and Updatable Single Password Authentication", Sections 4.2 (threat model), 4.4 (ideal functionality), and 5 (construction).

1. Secret Update waits for every account read, then checks unique threshold agreement and decrypts before preparing anything. Rejected or missing replies prevent LS contact. Authentication retains threshold completion. Coverage: `conformance_reads.rs`. **Re-run Secret Update measurements.**

2. Reject malformed all-provider read replies. Coverage: `conformance_reads.rs` (all three write phases, malformed points, lengths and variants). Adds client validation work to Registration, Secret Update and Password Update; refresh these measurements.

3. Enforce the per-user/TOPRF-instance attempt policy in providers, preserve it on Reset, and expose/record it through both CLIs and harnesses. Coverage: `protocol.rs` attempt-policy, lifetime, reset and invalid-input tests. Adds provider work to Identify; refresh all UpSPA phases containing Identification.

4. Use the paper's injective identifier/verifier tuple encodings with BLAKE3. Coverage: `encodings.rs` fixed input/digest vectors and prefix-sharing domain/index cases. Changes stored account addresses/verifiers (fresh fixtures required) and client hash work; refresh Registration, Authentication and Secret Update.

5. Sign exactly the seven paper fields, excluding the session id. Coverage: `protocol.rs` exact tuple, sid exclusion and independent signature-tampering checks for every signed field. Changes Password Update signed bytes and cost; refresh Password Update.

6. Re-check the committed old timestamp before password-update Store. Coverage: `protocol.rs` stale/deleted-root tests, repeated Store and Discard after rejection. Adds a provider lookup to Password Update finalization; refresh that phase.

7. Empty Discard returns OK and prevents late preparation; empty Store returns FAIL; completed bindings remain immutable. Coverage: `protocol.rs` empty/rejected preparation, wrong binding, replay and conflict tests. Changes failed-write behavior; honest successful timing paths are unchanged.

8. Replace finalization retries with one concurrent dispatch and completion on all final replies or the configured delivery bound. Trace missing/failed replies without reversing the chosen Store result. Coverage: `finalization.rs` tests all four write phases with withheld, failed and lost final replies; `recovery.rs` checks no retry or blocked next phase. Changes failed/missing-reply timing; honest replies arrive before Delta, keeping E2E comparable. Refresh all UpSPA write phases for the final binary.

9. Missing LS replies/transport failures choose Discard and FAIL by default. Keep probing, unresolved-outcome blocking and resume only in opt-in `--ls-outcome-probe`, documented as outside the paper model. Coverage: `recovery.rs` lost reply, deadline, probe success, failed probe and resume tests. Changes missing-LS failure paths and opt-in recovery timing; honest successful paths retain the same stages.

10. Add zeroize guards for UpSPA transient secrets/plaintext buffers and enable signing-key erasure. System RNG mode defaults to OS-entropy-seeded ChaCha20; the benchmark preserves explicit deterministic per-run seeds and records `"rng": "deterministic-per-run"`. Coverage: `secrets.rs` guarded-type, AEAD failure, deterministic replay and independent entropy tests; all-phase regressions. Update Cargo.lock. Cleanup changes UpSPA computation; **refresh all UpSPA phase measurements**.

11. Set the benchmark LS username to the SPA uid (`user123`) while preserving the separate `login_uid` API argument. Coverage: `benchmark_username.rs` registers/authenticates both benchmark schemes and checks the stored username; existing API tests still use a distinct LS username. Shorter public username changes LS payload length and map work; refresh benchmark phases that contact the LS.

The combined update requires refreshed measurements for all UpSPA phases, with Secret Update mandatory already for item 1. The benchmark username change also changes the TSPA benchmark LS request length, while its reference construction and equivalence tests remain unchanged. No existing reported numbers or LaTeX files were edited.

Optional B1 (TLS), B2 (channel-bound finalization), and B3 (TSPA per-account adapter keys) are not enabled. If B1 is enabled in future, re-run every phase.

## Changed files by numbered item

Paths below are relative to the repository root. Every item also updates this file and `docs/protocol_mapping.md`; the numbered descriptions above identify tests and timing effects.

| Item | Implementation and tests | Other documentation/harness files |
|---|---|---|
| 1 | `Implementation/src/protocols/system.rs`; `Implementation/tests/conformance_reads.rs` | - |
| 2 | `Implementation/src/protocols/system.rs`, `mod.rs` (preserve reference formatting); `Implementation/tests/conformance_reads.rs` | - |
| 3 | `Implementation/src/protocols/provider.rs`, `src/transport.rs`, `src/benchmark.rs`, `src/bin/network-node.rs`; `Implementation/tests/protocol.rs` | `scripts/run.py`, `scripts/netns/netns.py`, `README.md`, `docs/measurement_methodology.md` |
| 4 | `Implementation/src/crypto.rs`; `Implementation/tests/encodings.rs` | - |
| 5 | `Implementation/src/protocols/messages.rs`; `Implementation/tests/protocol.rs` | - |
| 6 | `Implementation/src/protocols/provider.rs`; `Implementation/tests/protocol.rs` | - |
| 7 | `Implementation/src/protocols/provider.rs`; `Implementation/tests/protocol.rs` | - |
| 8 | `Implementation/src/protocols/system.rs`, `src/benchmark.rs`; `Implementation/tests/finalization.rs`, `recovery.rs` | `scripts/run.py`, `scripts/netns/netns.py`, `README.md`, `docs/measurement_methodology.md` |
| 9 | `Implementation/src/protocols/system.rs`, `src/benchmark.rs`; `Implementation/tests/recovery.rs` | `scripts/run.py`, `scripts/netns/netns.py`, `README.md`, `docs/measurement_methodology.md` |
| 10 | `Cargo.lock`, `Implementation/Cargo.toml`, `Implementation/src/crypto.rs`, `src/protocols/system.rs`, `src/benchmark.rs`; `Implementation/tests/secrets.rs` | `README.md`, `docs/measurement_methodology.md` |
| 11 | `Implementation/src/benchmark.rs`; `Implementation/tests/benchmark_username.rs` | `README.md`, `docs/measurement_methodology.md` |

## Validation

Validated under Ubuntu/WSL in a release build:

- `cargo fmt --check` passed.
- `cargo test --workspace --release --locked` passed: 60 tests, including all five unchanged TSPA transport/equivalence tests.
- `cargo clippy --workspace --release` passed with no warnings.
- `python3 -m unittest discover -s scripts/tests -v` passed: five tests.
- After `bash scripts/build.sh`, `python3 scripts/run.py local --smoke --warmup 0 --measured 1 --n-sp 3 --t-sp 2 --out results/smoke-conformance` passed: 14/14 phase samples across client-local and SP-local modes, with the requested policy/RNG defaults in both `run.json` files.
- The TSPA reference files `Implementation/src/protocols/tspa.rs`, `Implementation/src/crypto_tspa.rs`, and `Implementation/tests/tspa_transport.rs` are byte-for-byte unchanged from `351cb01`.

No namespace/netem benchmarks were run. Smoke samples are functional validation, not replacement paper measurements.
