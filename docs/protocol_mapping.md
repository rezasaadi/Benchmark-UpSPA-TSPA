# Protocol mapping

## Active implementation

`Implementation/src/crypto.rs` contains the UpSPA cryptographic primitives: BLAKE3 domain separation, Ristretto TOPRF, XChaCha20-Poly1305, and the provider-specific SUid and verifier hashes. `protocols/system.rs`, `provider.rs`, `login_server.rs`, and `messages.rs` implement the protocol state machine and ordinary login server.

`Implementation/src/protocols/tspa.rs` contains the unchanged TSPA reference client microbenchmark. `crypto_tspa.rs` and the TspaProvider implementation in `protocols/sp.rs` supply its cryptographic and provider operations. `protocols/tspa_adapter.rs` connects that construction to the unified benchmark. Output-equivalence tests in `Implementation/tests/tspa_transport.rs` check the adapter against the reference.

## Finalized UpSPA

Committed provider roots contain exactly uid, svk, cid, share, and timestamp. Setup generates Rsp, the TOPRF key and shares, the signing key pair, K0, and timestamp zero. Root AEAD plaintext is `ssk || Rsp || K0`, exactly 96 bytes, with empty associated data. Each provider first stages its root. Only matching Store commits it; matching Discard removes the tentative value.

Identification is a shared subprocedure. Providers return only committed cid, timestamp, and the TOPRF contribution. The client groups exact `(cid,timestamp)` pairs, counts distinct provider identities supplied by the endpoint mapping, and interpolates only the accepted instance's contributions. It never selects the greatest timestamp or compares svk. The recovered state contains ssk, Rsp, K0, and timestamp.

Account addresses remain `H(Rsp || ls_j || i)` using the supplied domain-separated hash. Account plaintext is `Rls_j || ctr`, exactly 40 bytes. Associated data is the canonical bincode tuple `("account", uid, ls_j)`; it excludes the stable LS username and provider index. One encrypted account value is replicated at all provider-specific addresses. Recovery requires one uniquely qualifying group of exact ciphertext bytes before decryption; it does not rank counters.

Registration contacts all providers for Identification and then prepares the account at all providers concurrently. Only successful preparation at every provider permits ordinary LS registration. The LS decision is followed by provider Store or Discard; application acknowledgement completion is included in the phase.

Authentication uses threshold agreement for Identification and account recovery and then invokes ordinary LS authentication with the stable username. It sends no Store/Discard.

Secret Update requires all-provider Identification, recovers the agreed current ciphertext, increments the decrypted counter, samples a fresh Rls, and prepares the replacement at every provider. Preparation checks the expected committed ciphertext. Only all-provider preparation success permits the ordinary old/new LS credential change. Store follows LS success; Discard follows explicit rejection.

Password Update rekeys TOPRF and encrypts the same ssk, Rsp, K0 under the new password-derived key. The signed canonical tuple contains `"PwdUpdate", sid, uid, provider_id, timestamp_old, timestamp_new, cid_new, share_new` in that order. The provider checks every bound field, canonical share encoding, signature, increasing timestamps, the committed old timestamp, and the configured wall-clock window. Store replaces cid, share, and timestamp together while retaining svk.

All pending values bind sid, phase, and record identifier. A provider mutex covers each complete state handler. Wrong bindings and repeated finalizations have no state effect; terminal results are retained so a dropped Store acknowledgement can be retried without applying a write twice. Pending values never appear in normal reads.

## Agreement and threshold safety

The optimized agreement tracker records each distinct provider response once and updates exact-value groups incrementally. Threshold Identification reuses the accepted group instead of grouping its replies again. The unique-agreement and all-provider acceptance rules remain unchanged.

Authentication dispatches all selected provider requests concurrently and processes responses as they arrive. It returns after a valid unique threshold when outstanding responses cannot create a second qualifying group. For small thresholds, especially `t <= n/2`, this can require more than t replies. Two qualifying ciphertexts cause failure. Duplicate provider IDs never count twice. The all-provider requirement on write phases remains independent of threshold agreement.

Threshold transport tasks continue reading their already-dispatched responses so persistent streams are not left halfway through a frame. The benchmark drains them after stopping the complete-phase timer, before resetting state. Their actual communication and processing remain in the raw trace.

## Unchanged TSPA construction and ordering ambiguity

TSPA registration uses the reference implementation's exact construction: sample a scalar secret and Shamir polynomial, evaluate shares at provider indices, sample per-provider OPRF keys, compute the password-point OPRF output directly at the client, and encrypt each share using AES-256-CTR with the supplied 16-byte IV format. Each provider stores its key and 48-byte ciphertext. The ordinary LS stores the original secret-derived verifier. No UpSPA phase, context, transaction, identifier, or epoch is added to TSPA.

Authentication contacts the original first-t subset. The client blinds the password point, obtains fresh provider OPRF evaluations plus stored ciphertexts, unblinds, decrypts scalar shares, interpolates the secret, derives the original verifier, and performs ordinary LS login. Network responses are produced after the live requests. Output-equivalence tests compare the original client accumulators, stored ciphertexts, reconstructed secret/verifier, and original provider OPRF outputs.

The reference `Implementation/src/protocols/tspa.rs` is a client microbenchmark and does not establish whether LS registration can overlap provider storage. Its Rust construction computes the registration OPRF value directly at the client. The adapter follows that construction and uses a conservative provider-storage-then-LS order. This LS scheduling choice is not a proved dependency of a separate TSPA specification. The implementation does not introduce an extra registration OPRF protocol.

## Recovery boundary

Finalization retries use identical sid/phase/record bindings and each retry is traced. A lost LS response is resolved using the ordinary authentication interface and the proposed new verifier before choosing Store or Discard. If that resolution remains unavailable, pending state is retained and the phase reports an incomplete outcome; it does not discard a possibly accepted LS change. `resume_finalization` supports retry while the client process remains alive.

This benchmark keeps service state and recovery records in memory. It is not a durable distributed transaction service. Permanent process failure or a crash after an LS change can leave partial provider commitment. Such executions are failed/incomplete raw samples, never successful measurements. The untimed benchmark reset restores a valid independent fixture for the next run.
