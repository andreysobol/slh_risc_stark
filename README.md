# Post-Quantum Signature Verification Using STARKs

Build a proof of concept that verifies NIST-standardized post-quantum signatures inside OpenVM and generates native STARK proofs using the SWIRL backend.

Experiments start with 1 signature and increase to 2, 3, 4, 8, 16, 32, 64, and 128 signatures.

## Technology Stack

| Layer | Technology |
|---|---|
| Signature algorithm | SLH-DSA-SHA2-128s (FIPS 205) |
| Signature generation | OpenSSL 3.5+ |
| Signature verification | Custom Rust implementation |
| zkVM | OpenVM v2.1.0 |
| Proof system | SWIRL STARK backend |
| SHA-256 acceleration | OpenVM SHA-256 extension |
| Circuit framework | Plonky3 through OpenVM |

Only native STARK proofs are used. No Groth16, Halo2/KZG.

## Signature Verification Architecture

The project implements SLH-DSA-SHA2-128s according to NIST FIPS 205.

### Parameters

| Parameter | Value |
|---|---|
| Security category | 1 |
| Public key | 32 bytes |
| Private key | 64 bytes |
| Signature | 7,856 bytes |
| n | 16 |
| h | 63 |
| d | 7 |
| h' | 9 |
| a | 12 |
| k | 14 |
| w | 16 |

### Verification Pipeline

1. Parse the signature and public key.
2. Compute the message digest using SHA-256 and MGF1.
3. Reconstruct the FORS public key.
4. Reconstruct WOTS+ public keys using Winternitz hash chains.
5. Verify XMSS authentication paths.
6. Process all seven hypertree layers.
7. Reconstruct the final Merkle root.
8. Compare the reconstructed root with the public-key root.
9. Accept or reject the signature.

Location: `crates/slh-core/`

### OpenVM Guest

Location: `crates/guest/`

A single guest program supports variable batch sizes.

Execution:

1. Read N signatures, messages, and public keys.
2. Validate batch encoding.
3. Verify every signature.
4. Reject the batch if any signature is invalid.
5. Calculate SHA-256 over the canonical ordered batch.
6. Publish the batch commitment and signature count.
7. Complete successfully only if every signature is valid.

### STARK Prover and Verifier

Location: `crates/harness/`

Implements two intended proving modes.

#### Application STARK

Generates an application-level STARK without final recursive aggregation.

Used to measure the raw proving workload.

#### Aggregated STARK

Generates a recursively aggregated native STARK proof using OpenVM and SWIRL.

Used as the primary proof artifact for performance analysis.

The verifier must check:

- Proof validity.
- Expected executable configuration.
- Expected public batch commitment.
- Expected signature count.

## What the STARK Proves

For a batch of N signatures, the STARK establishes that:

1. The configured guest program executed correctly.
2. Each of the N signatures passed FIPS 205 verification.
3. The batch commitment corresponds to the messages, signatures, and public keys processed by the guest.
4. The claimed public signature count matches the batch execution.

## References

- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- OpenSSL: https://github.com/openssl/openssl
- OpenVM v2.1: https://github.com/openvm-org/openvm/tree/v2.1.0
- OpenVM SDK: https://docs.openvm.dev/book/advanced-usage/sdk/
- Accelerated SHA-2: https://docs.openvm.dev/book/guest-libraries/sha2/
- SWIRL STARK backend: https://github.com/openvm-org/stark-backend
- Plonky3: https://github.com/Plonky3/Plonky3
