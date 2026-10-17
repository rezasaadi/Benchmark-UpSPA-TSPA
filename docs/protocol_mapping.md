# Protocol mapping

## Active implementation

Transient UpSPA signing-key bytes, Rsp, K0, Rls, TOPRF outputs, blinding scalars and root/account plaintext buffers use zeroizing guards (paper Section 4.2). The ed25519 signing-key type wipes its secret on drop. Guards also run on early error returns. System RNG mode defaults to OS-entropy-seeded ChaCha20; the benchmark explicitly requests the unchanged deterministic per-run seeds for reproducibility.

`Implementation/src/crypto.rs` contains the UpSPA cryptographic primitives: BLAKE3 domain separation, Ristretto TOPRF, XChaCha20-Poly1305, and the provider-specific SUid and verifier hashes. `protocols/system.rs`, `provider.rs`, `login_server.rs`, and `messages.rs` implement the protocol state machine and ordinary login server.

`Implementation/src/protocols/tspa.rs` contains the unchanged TSPA reference client microbenchmark. `crypto_tspa.rs` and the TspaProvider implementation in `protocols/sp.rs` supply its cryptographic and provider operations. `protocols/tspa_adapter.rs` connects that construction to the unified benchmark. Output-equivalence tests in `Implementation/tests/tspa_transport.rs` check the adapter against the reference.

## Finalized UpSPA

The benchmark uses the same public username (`user123`) at storage providers and the LS, following the base construction in paper Section 5. The library keeps `login_uid` as a separate argument for callers that need another LS username.

Committed provider roots contain exactly uid, svk, cid, share, and timestamp (paper Sections 4.4 and 5). Setup generates Rsp, the TOPRF key and shares, the signing key pair, K0, and timestamp zero. Root AEAD plaintext is `ssk || Rsp || K0`, exactly 96 bytes, with empty associated data. Each provider first stages its root. Only matching Store commits it; matching Discard removes the tentative value.

Identification is one shared exchange carrying uid and the blinded TOPRF request (paper Sections 4.4 and 5). Providers return only committed cid, timestamp, and the TOPRF contribution when their attempt policy admits it. The client groups exact `(cid,timestamp)` pairs, counts distinct provider identities supplied by the endpoint mapping, and interpolates t contributions only from the uniquely accepted instance. It never selects the greatest timestamp or compares svk. The recovered state contains ssk, Rsp, K0, and timestamp.

Account addresses are `BLAKE3(Rsp || Encode("identifier", ls_j, i as u32))`; verifiers are `BLAKE3(Rls_j || Encode("verifier", ls_j))` (paper Section 5). Encode is bincode v1 default fixed-width tuple serialization throughout. Account plaintext is `Rls_j || ctr`, exactly 40 bytes. Associated data is the canonical bincode tuple `("account", uid, ls_j)`; it excludes the stable LS username and provider index. One encrypted account value is replicated at all provider-specific addresses. Recovery requires one uniquely qualifying group of exact ciphertext bytes before decryption; it does not rank counters.

Registration contacts all providers for Identification and then prepares the account at all providers concurrently (paper Sections 4.4 and 5). Only successful preparation at every provider permits ordinary LS registration. LS OK chooses Store; explicit rejection, transport failure or the LS deadline chooses Discard. Final decision delivery is included in the phase.

Authentication uses threshold agreement and successful decryption for Identification and account recovery, then invokes ordinary LS authentication with `login_uid` (paper Sections 4.4 and 5). It sends no Store/Discard.

Secret Update requires all-provider Identification and account reads before preparation (paper Sections 4.4 and 5). Rejected, malformed or missing required replies fail before preparation or LS contact. It recovers the agreed current ciphertext, increments the decrypted counter, samples a fresh Rls, and prepares the replacement at every provider. Preparation checks the expected committed ciphertext. Only all-provider preparation success permits the ordinary old/new LS credential change. Store follows LS success; Discard follows rejection, transport failure or the LS deadline.

Password Update rekeys TOPRF and encrypts the same ssk, Rsp, K0 under the new password-derived key. The signed canonical tuple contains exactly `"PwdUpdate", uid, provider_id, timestamp_old, timestamp_new, cid_new, share_new` in that order (paper Section 5). The request retains an unsigned sid for pending-write matching. The provider checks every bound field, canonical share encoding, signature, increasing timestamps, the committed old timestamp, and the configured wall-clock window. Store replaces cid, share, and timestamp together while retaining svk.

Pending writes bind sid, phase and record identifier; each record admits at most one pending value (paper Section 5). A provider mutex covers each complete state handler. Terminal decisions are retained so duplicate or conflicting finalizations cannot apply a write twice. Pending values never appear in normal reads. The optional connection-bound extension B2 is not implemented.

## Agreement and threshold safety

Discard without a matching pending write confirms OK and records the terminal Discard, including after a rejected preparation; Store without matching pending returns FAIL (paper Section 5). Neither changes another pending/committed record. Repeated final decisions return OK only for the original decision; conflicting or late decisions cannot reverse it.

Password-update pending records retain `timestamp_old`. Store re-checks it against the committed root under the same provider mutex before changing any state (paper Section 5); a changed or missing root returns FAIL and leaves the pending and committed records intact.

Providers apply a fixed attempt policy keyed by `(uid, committed timestamp)` before returning each TOPRF contribution (paper Sections 4.2, 4.4 and 5). Defaults are 100 evaluations per 60000 ms window, anchored at the first evaluation. Zero window means a lifetime cap; zero limit admits none. Only valid requests that would return contributions count. Password-update Store changes the instance; Reset clears counters and retains policy configuration.

Paper Sections 4.4 and 5 require every write-phase root/account read to be well formed. Invalid points, wrong ciphertext lengths and wrong reply variants fail before preparation. Authentication tolerates unusable replies subject to unique threshold agreement.

The optimized agreement tracker records each distinct provider response once and updates exact-value groups incrementally. Threshold Identification reuses the accepted group instead of grouping its replies again. The unique-agreement and all-provider acceptance rules remain unchanged.

Authentication dispatches all provider requests concurrently and processes responses as they arrive (paper Sections 4.4 and 5). With leading support a, largest competing support b (zero when absent), and r outstanding replies, it may stop when `a >= t` and `b + r < t`, followed by successful decryption. For small thresholds, especially `t <= n/2`, this can require more than t replies. Two qualifying ciphertexts cause failure. Duplicate provider IDs never count twice. Write-phase reads separately require all n valid replies before agreement/decryption.

Threshold transport tasks continue reading their already-dispatched responses so persistent streams are not left halfway through a frame. The benchmark drains them after stopping the complete-phase timer, before resetting state. Their actual communication and processing remain in the raw trace.

## Unchanged TSPA construction and ordering ambiguity

TSPA registration uses the reference implementation's exact construction: sample a scalar secret and Shamir polynomial, evaluate shares at provider indices, sample per-provider OPRF keys, compute the password-point OPRF output directly at the client, and encrypt each share using AES-256-CTR with the supplied 16-byte IV format. Each provider stores its key and 48-byte ciphertext. The ordinary LS stores the original secret-derived verifier. No UpSPA phase, context, transaction, identifier, or epoch is added to TSPA.

Authentication contacts the original first-t subset. The client blinds the password point, obtains fresh provider OPRF evaluations plus stored ciphertexts, unblinds, decrypts scalar shares, interpolates the secret, derives the original verifier, and performs ordinary LS login. Network responses are produced after the live requests. Output-equivalence tests compare the original client accumulators, stored ciphertexts, reconstructed secret/verifier, and original provider OPRF outputs.

The reference `Implementation/src/protocols/tspa.rs` is a client microbenchmark and does not establish whether LS registration can overlap provider storage. Its Rust construction computes the registration OPRF value directly at the client. The adapter follows that construction and uses a conservative provider-storage-then-LS order. This LS scheduling choice is not a proved dependency of a separate TSPA specification. The implementation does not introduce an extra registration OPRF protocol.

## Recovery boundary

After choosing Store or Discard, send the decision concurrently to all providers and wait until all final replies or the configured delivery bound Delta (paper Sections 4.2, 4.4 and 5). There are no automatic finalization retries. Missing/failed final replies are traced and cannot reverse the chosen result. Honest replies normally end the wait before Delta. Late replies are drained outside the benchmark phase timer.

By default a missing LS reply, including a transport failure or timeout, chooses Discard at all providers and returns FAIL (paper Section 5). No LS probe or unresolved-outcome client blocking occurs in this mode. An honest LS is assumed to respond within the paper's bound.

`--ls-outcome-probe` is an opt-in extension outside the paper's model. It probes the ordinary LS authentication interface with the proposed new verifier before choosing Store/Discard after an unknown LS result. If the probe is unavailable, preparations remain pending and further operations are blocked; `resume_finalization` can retry the probe in the same process. Explicit LS FAIL always chooses Discard.

This benchmark keeps service state and recovery records in memory. It is not a durable distributed transaction service. Permanent process failure or a crash after an LS change can leave partial provider commitment. Such executions are failed/incomplete raw samples, never successful measurements. The untimed benchmark reset restores a valid independent fixture for the next run.
