# SLH-DSA × STARK: OpenVM / SWIRL research PoC

> **Execution status (2026-11-19):** Independent FIPS 205 Python verification of **all 128 OpenSSL-generated signatures succeeded**, nine negative/batch-format tests passed, and an OpenSSL 3.5 EVP baseline was measured. The **Rust/OpenVM SDK code is provided as an integration prototype but has not been compiled or run** in the environment that created this repository (Rust, Cargo and dependency/network access unavailable). **There are currently no generated OpenVM STARK proofs, no verified STARK proof benchmarks, and no VM cycle measurements.** Every missing result is marked as *not measured*. Do **not** treat this as an already proven one-signature STARK implementation until the toolchain run succeeds.

The goal is to verify **N independently signed FIPS 205 SLH-DSA-SHA2-128s messages inside one OpenVM execution** and produce both application and recursively aggregated **native SWIRL STARK** proofs. No Groth16, Halo2, KZG or EVM wrapping is used. Start with **N=1, 2, 3** and extend to **4, 8, 16, 32, 64, 128**.

## Repository contents

| Location | Purpose | Status |
|---|---|---|
| `crates/slh-core` | Rust FIPS 205 pure-verification functions; FORS, WOTS+, XMSS, HT, MGF1, SHA-256, operation counters | Source present, **not compiled here** |
| `crates/guest` | One `no_std` OpenVM binary for any positive batch N; 64 public values (36 used, rest zero); SHA-256 extension | Source present, **not compiled here** |
| `crates/harness` | Pinned OpenVM 2.1 SDK, app proving, aggregated STARK proving and verification, proof serialization, JSONL run log | Source present, **not compiled here** |
| `tools/generate_fixtures.py` | OpenSSL keypair/signature generator with stable checkpoints; fresh keypair per fixture | **Executed; 128 generated** |
| `fixtures/fixtures.json` | 128 public key, signature and message triples; no secret keys | **Generated and tested** |
| `tools/reference_check.py` | Independent FIPS205 SHA2 128s pure verifier, measures actual algorithm operations | **Executed** |
| `tools/protocol.py` | Canonical binary commitment encoding | **Executed** |
| `tools/test_protocol.py` | Positive/negative signature and canonical commitment tests | **9 tests passed** |
| `tools/measure_crypto.py` | Measure counters for all 128 signatures; batch scaling | **Executed** |
| `tools/openssl_bench.c` + `tools/measure_native.py` | In-process OpenSSL native verification baseline | **Compiled/executed** |
| `tools/benchmark.py` | End-to-end orchestrator (auto-extends fixture set, OpenVM harness, summary, plots, timeout/errors) | **Not run with OpenVM** |
| `tools/report.py` | Medians, extrema, p95, CSV/JSON and six graphs | **Executed** |
| `results/` | Cryptographic measurements, native baseline, summary, graphs | **Generated; proof metrics empty** |

## Environment / setup

> **Step-by-step guide for a clean Ubuntu machine (install, prove N=1…128, save/archive proofs, view benchmarks): [docs/RUNNING_FROM_SCRATCH.md](docs/RUNNING_FROM_SCRATCH.md).**

A Linux x86-64 machine with **Rust 1.91.1**, a working **OpenVM v2.1.0** guest compiler and SDK environment, **OpenSSL 3.5+**, C compiler, Python 3.10+, `matplotlib` and `pkg-config` is required. It is important to have adequate free RAM; begin at N=1 before considering larger proofs. For OpenVM compiler installation use [the official OpenVM v2.1.0 installation guide](https://docs.openvm.dev/book/installation/) or the [SDK guide](https://docs.openvm.dev/book/advanced-usage/sdk/).

The `rust-toolchain.toml` fixes the Rust version; Git dependency tags are fixed to `v2.1.0` in `Cargo.toml`, including the standalone STARK backend. Once dependencies resolve, **commit `Cargo.lock`** to fully pin transitive versions (it could not be generated here). For audit-grade reproducibility additionally pin upstream Git revision SHAs, record `rustc -Vv`, `cargo -V`, `openssl version -a`, OpenVM `--version` and `sha256sum fixtures/fixtures.json`.

### Step 1: verify the provided fixtures and measure cryptographic counts

```bash
python tools/test_protocol.py
python tools/measure_crypto.py
```

All 128 fixtures were checked against OpenSSL at generation and all 128 were independently checked by Python. To **extend** to 256 independently generated signatures while keeping the first 128 stable:

```bash
python tools/generate_fixtures.py --count 256
```

**Warning:** `generate_fixtures.py` outputs no private keys, and ephemeral secret keys are deleted upon closing each temporary directory. The generated fixtures contain public messages, signatures and keys only.

### Step 2: benchmark native OpenSSL (same machine)

```bash
python tools/measure_native.py
```

This compiles `tools/openssl_bench.c` and runs OpenSSL EVP verification in-process. Each run performs 1,000 verifications without process-start overhead. Five runs are collected per N, using representative keys from the fixed fixture set; **it measures native signature verification, not N independent in-process verifications per iteration**. In particular, do not confuse the N label on these baseline records with guest batch timings.

### Step 3: compile + test Rust verifier

```bash
cargo test -p slh-core --features instrument
```

**OpenVM SDK integration has to be compiled and tested on a provisioned machine.** For first incremental proof:

```bash
python tools/benchmark.py --n 1 --repeats 5 --warmup 1 --timeout 3600
python tools/benchmark.py --n 2 --repeats 5 --warmup 1 --timeout 3600
python tools/benchmark.py --n 3 --repeats 5 --warmup 1 --timeout 3600
```

For the full suite:

```bash
python tools/benchmark.py --repeats 5 --warmup 1
```

For arbitrary N (fixtures auto-generated when needed), e.g.:

```bash
python tools/benchmark.py --n 24 --mode both
```

The native harness uses the [OpenVM SDK v2.1.0 proof APIs](https://docs.openvm.dev/book/advanced-usage/sdk/). The required custom VM configuration is in `crates/guest/openvm.toml` with `rv32i`, `rv32m`, `io`, `sha2`, with `num_public_values=64` set in the harness (OpenVM requires 8·2^k; 36 is rejected). **Because OpenVM's CLI keygen restricts nondefault public value counts, use the SDK code path**, not direct `cargo openvm keygen`, for this configuration.

OpenVM exposes `sdk.app_prover(...).prove(...)` for the application proof and `sdk.prover(...).prove(stdin,&[])` followed by `Sdk::verify_proof(...)` for the recursively aggregated native STARK. SDK proving keys and guest compilation happen outside measurements. **No EVM proof APIs are called.** The harness writes each successful final native STARK proof to `results/proofs/nN-runR-stark.proof` using OpenVM's native `Encode` codec.

### Batch format and statement being proved

The guest receives a `Vec<u8>` serialized with OpenVM `StdIn::write` / `openvm::io::read`:

```
ASCII "SLHBATCH" | 0x01
u16le(length(algorithm identifier)) | ASCII "SLH-DSA-SHA2-128s/FIPS205/pure/ctx0"
u32le(number of signatures N)
for i = 0..N-1:
    u32le(message length) | message
    u32le(public key length = 32) | public key
    u32le(signature length = 7856) | signature
```

The guest checks the algorithm and lengths, verifies **all** signatures, rejects trailing bytes, computes `SHA256(entire canonical binary batch)` **inside the guest**, publishes the 32 digest bytes and then publishes N as four bytes in little-endian order. OpenVM's 64 user public values are treated as unsigned bytes; bytes 36..64 are unused and must be zero. Proof acceptance must require the externally expected 64 bytes and the expected executable/VM verifier baseline to match. Merely verifying a mathematically valid proof for a different batch is **not** sufficient.

**Security caveat:** The current Rust host implementation checks these public values and invokes `Sdk::verify_proof` against a baseline generated for the guest executable/configuration. Until this integration is compiled and the adversarial negative tests are run inside OpenVM, this statement-binding property remains a source-level design, not an experimentally verified security claim.

### Measurements and reports

`results/crypto_batch.csv` contains **actual algorithm SHA256 calls/compression blocks** for 1,2,3,4,8,16,32,64,128; *batch commitment SHA2 cost is separate*. `results/crypto_per_signature.jsonl` gives per-signature counts. `results/openssl_native.jsonl` gives a real OpenSSL EVP CPU baseline. `results/runs.jsonl` will be populated by successful/failed OpenVM attempts; `results/driver_errors.jsonl` records driver failures/timeouts. `tools/report.py` writes:

- `results/summary.csv`, with median, min, max, p95 and blank cells for unavailable measurements.
- `results/statistics.json` with complete distributions and failure records.
- `results/01_proving_time.png` through `06_amortized_proving.png`, with an honest **NOT MEASURED** label when no STARK data exist. The SHA-256 graph alone is populated from measured data now.

The Rust harness counts SHA256 operations, compression blocks, MGF1, F/H/T_l/H_msg, FORS leaves/auth paths, WOTS chains/steps, XMSS nodes and hypertree layers by executing its **instrumented native build**. This does **not** instrument the proving guest's release path. `VmHWM` is the **process cumulative high-water mark**, not a resettable per-run peak RSS. VM cycles, AIR rows, segments and SHA2 opcode counts are nullable and must only be populated by a supported OpenVM profiler, never guessed. The app proof has not been wired to a pinned byte codec for its **serialized size**, so its size is currently explicitly unavailable rather than an unreliable `Debug`-string estimate.

### Operations measured on supplied fixtures

| Batch N | SHA-256 calls | SHA-256 compression blocks | Batch commitment compression blocks |
|--:|--:|--:|--:|
| 1 | 2,100 | 4,266 | 126 |
| 2 | 4,200 | 8,532 | 250 |
| 3 | 6,315 | 12,828 | 375 |
| 4 | 8,355 | 16,974 | 499 |
| 8 | 16,860 | 34,248 | 998 |
| 16 | 33,735 | 68,526 | 1,994 |
| 32 | 67,590 | 137,292 | 3,986 |
| 64 | 135,915 | 276,054 | 7,970 |
| 128 | 270,855 | 550,158 | 15,939 |

These are **independent Python FIPS205 verifier counts**, not Rust/OpenVM trace counts and not proof-generation measurements. Actual SHA2 work depends on message length and WOTS chain digits.

## Limitations and next checks

**Before claiming success criteria 1–3**, the Rust core and OpenVM guest need an actual compile/build, OpenVM proof execution, native STARK verification and negative public-value/proof-binding checks on a provisioned machine. Add the **official NIST ACVP test vector files** (not bundled or verified here) to the Rust test suite. Check that the v2.1.0 SDK API and native proof codec signatures compile exactly as expected and adjust if the pinned SDK differs. Properly add a compatible serialized *application* proof-size measurement and stage-level profiler timings when the SDK exposes the relevant data. Do not extrapolate proof size/time stability until genuine proof data exist.

## References

- NIST FIPS 205: https://csrc.nist.gov/pubs/fips/205/final
- OpenSSL: https://github.com/openssl/openssl
- OpenVM v2.1: https://github.com/openvm-org/openvm/tree/v2.1.0
- OpenVM SDK: https://docs.openvm.dev/book/advanced-usage/sdk/
- Accelerated SHA-2: https://docs.openvm.dev/book/guest-libraries/sha2/
- SWIRL STARK backend: https://github.com/openvm-org/stark-backend
- Plonky3: https://github.com/Plonky3/Plonky3

**Scope:** Research/benchmarking only. No blockchain, consensus, EVM, smart contracts, wallet integration, formal verification or elliptic-curve proof wrappers.
