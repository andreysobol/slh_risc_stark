# Running from scratch (clean Ubuntu machine)

This guide takes a **fresh Ubuntu 24.04 LTS (x86-64)** server with a large CPU to:

1. install everything the project needs,
2. generate native OpenVM STARK proofs for batches of **N = 1, 2, 3, 4, 8, 16, 32, 64, 128** signatures,
3. save the proofs and measurements in a portable form,
4. look at the benchmark results (tables, JSON and graphs).

For background on what is being proved, see the main [README](../README.md).

> **What has been tested so far (2026-11-19):** the harness (`slh-harness`) and the guest compile with the toolchain below. A first N=1 run on a 2-core / 3.8 GB development VM was **killed by the kernel out-of-memory killer at about 3.4 GB of memory**. No STARK proof has been produced yet, so every time and memory figure below is a sizing estimate, not a measurement. Start at N=1 and use the `peak_ram_bytes` it records to plan the larger runs.

---

## 1. Hardware

| Resource | Minimum for N=1 | Recommended for the full 1…128 suite |
|---|---|---|
| CPU | 8 cores x86-64 with AVX2 | 32–96+ cores (AVX-512 helps: AMD EPYC Genoa/Turin, Intel Sapphire Rapids or later) |
| RAM | 16 GB (4 GB was **not** enough) | 128–512 GB; memory rather than CPU is the likely limit at N=64/128 |
| Disk | 30 GB free SSD | 100 GB+ NVMe (the build cache is about 10–15 GB; each proof file is roughly 1 MB or less) |
| OS | Ubuntu 22.04 / 24.04 LTS, x86-64 | Ubuntu 24.04 LTS |
| GPU | not used | not used (CPU-only build) |

Suitable cloud instances include AWS `c7a.24xlarge`/`r7a.16xlarge`, GCP `c3d-highmem-*`, and Hetzner AX162. The proving code is multithreaded (rayon), so more cores means shorter proving times.

---

## 2. Install system packages

```bash
sudo apt-get update
sudo apt-get install -y \
    build-essential pkg-config clang cmake git curl ca-certificates \
    libssl-dev python3 python3-pip python3-venv python3-matplotlib \
    jq time tmux htop unzip zip
```

| Package | Why it is needed |
|---|---|
| `build-essential`, `clang`, `cmake`, `pkg-config` | compiling native Rust dependencies and `tools/openssl_bench.c` |
| `libssl-dev` | OpenSSL headers for the native baseline |
| `python3`, `python3-matplotlib` | fixture checks, orchestration (`tools/benchmark.py`) and graphs (`tools/report.py`) |
| `jq`, `time` (`/usr/bin/time -v`) | inspecting results; measuring true per-process peak memory |
| `tmux` | keeping long proving runs alive after you disconnect from SSH |

### Optional: add swap as a safety net

Swap will not make proving fast, but it can turn an out-of-memory kill into a slow run that still finishes:

```bash
sudo fallocate -l 64G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
```

---

## 3. Install Rust (two toolchains)

The project needs **two** Rust toolchains:

* **`1.91.1`** (stable) for the host harness. `rust-toolchain.toml` selects it automatically.
* **`nightly-2026-02-28`** with the **`rust-src`** component. OpenVM v2.1.0 uses it to cross-compile the guest program for `riscv32im-risc0-zkvm-elf` (see `DEFAULT_RUSTUP_TOOLCHAIN_NAME` in `openvm-build`).

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source "$HOME/.cargo/env"

rustup toolchain install 1.91.1 --component rustfmt clippy
rustup toolchain install nightly-2026-02-28 --component rust-src

rustc +1.91.1 -V            # rustc 1.91.1 ...
rustc +nightly-2026-02-28 -V
```

You do **not** need the `cargo openvm` CLI. The harness calls the OpenVM SDK directly, because the CLI key generator rejects the custom `num_public_values = 64` setting.

---

## 4. Optional: OpenSSL ≥ 3.5

Ubuntu 24.04 ships OpenSSL 3.0, which **does not support SLH-DSA**. You only need OpenSSL 3.5 if you want to:

* generate **more than the 128 fixtures** already in `fixtures/fixtures.json`, or
* re-run the native OpenSSL baseline (`tools/measure_native.py`).

**Proving N = 1…128 needs neither.** The 128 committed fixtures are used as they are.

To build OpenSSL 3.5 into its own prefix, leaving the system OpenSSL alone:

```bash
cd /tmp
curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
tar xf openssl-3.5.4.tar.gz && cd openssl-3.5.4
./Configure --prefix=/opt/openssl-3.5 --libdir=lib
make -j"$(nproc)" && sudo make install_sw

# Use it only in the shell where you need it:
export PATH=/opt/openssl-3.5/bin:$PATH
export LD_LIBRARY_PATH=/opt/openssl-3.5/lib:$LD_LIBRARY_PATH
export PKG_CONFIG_PATH=/opt/openssl-3.5/lib/pkgconfig:$PKG_CONFIG_PATH
openssl version                                  # OpenSSL 3.5.x
openssl list -signature-algorithms | grep -i slh # should list SLH-DSA-SHA2-128s
```

---

## 5. Get the code and build it

```bash
git clone <your-repo-url> slh-stark-poc      # or: scp -r / rsync the folder onto the machine
cd slh-stark-poc

# 1) Python sanity checks (no Rust needed): 9 tests plus 128-signature cross-check
python3 tools/test_protocol.py
python3 tools/measure_crypto.py

# 2) Native Rust verifier unit tests
cargo test -p slh-core --features instrument

# 3) Build the harness in release mode (the first build downloads OpenVM and takes 10–30 min)
cargo build --release -p slh-harness
```

The first time the harness **runs**, it also compiles the guest (`crates/guest`) with the nightly toolchain into `target/riscv32im-risc0-zkvm-elf/release/slh-guest`, then generates the app and aggregation proving keys. That set-up happens **before** the timed section and is not included in the benchmark numbers.

Optional, for faster proving on the exact CPU you are using:

```bash
export RUSTFLAGS="-C target-cpu=native"
cargo build --release -p slh-harness
```

If you use this, record it next to your results, because the binary will no longer be portable to other CPUs.

---

## 6. Generate the proofs: N = 1, 2, … 128

Always run inside `tmux` so that an SSH disconnect does not kill a run that takes hours:

```bash
tmux new -s bench
cd ~/slh-stark-poc
```

### 6.1 Smoke test: N = 1, one run

```bash
/usr/bin/time -v python3 tools/benchmark.py --n 1 --repeats 1 --warmup 0 --timeout 7200 \
    2>&1 | tee logs-n1-smoke.txt
grep -E "Maximum resident|Elapsed" logs-n1-smoke.txt
```

The last line should read `N=1 run=0 status=ok prove=Some(..)s verify=Some(..)s bytes=Some(..)`. Check **Maximum resident set size** and use it to decide whether the machine has enough memory for larger N. As a rough guide, memory grows with the number of guest segments, which grows about linearly with N.

### 6.2 Recommended: one process per N

The harness records `VmHWM`, which is the **high-water mark for the whole process**. If every N runs in a single process, each later N inherits the peak from the earlier ones. Running each N in its own process gives a clean per-N `peak_ram_bytes` and isolates out-of-memory failures:

```bash
mkdir -p logs
for N in 1 2 3 4 8 16 32 64 128; do
  echo "=== N=$N  $(date -u +%FT%TZ) ==="
  /usr/bin/time -v python3 tools/benchmark.py \
      --n "$N" --repeats 5 --warmup 1 --mode both --timeout 86400 \
      > "logs/n${N}.log" 2>&1
  tail -n 3 "logs/n${N}.log"
done
```

* `--repeats 5 --warmup 1` runs 1 untimed warm-up and 5 measured runs per N. That gives a median, minimum, maximum and p95.
* `--mode both` produces the **app proof** (per segment) and the **final aggregated native STARK**. Use `--mode stark` to skip the separate app proof and save time.
* `--timeout` is in seconds and applies to each N. A timeout or crash is written to `results/driver_errors.jsonl`, and the loop moves on to the next N.
* To try a quick first pass, use `--repeats 1 --warmup 0`.

### 6.3 Alternative: everything in one command

```bash
python3 tools/benchmark.py --repeats 5 --warmup 1      # runs all of N = 1,2,3,4,8,16,32,64,128
```

This is simpler, but peak RAM is cumulative across N (see 6.2), and an out-of-memory kill at N=128 stops the whole run.

### 6.4 Other batch sizes

Any positive N works. If N is above 128, the extra fixtures are generated automatically, which needs OpenSSL 3.5 (section 4):

```bash
python3 tools/benchmark.py --n 24 --repeats 3
```

Note that the graphs plot only the standard sizes 1…128. Other sizes still appear in `runs.jsonl`.

### Controlling threads

```bash
export RAYON_NUM_THREADS=$(nproc)   # default; lower it to study scaling, e.g. 16, 32, 64
```

---

## 7. Where things are saved, and in what form

Everything is written under `results/` by default. You can change this with `--out DIR`, for example `--out results/epyc-96c`, to keep runs from different machines apart.

| File | Format | Contents |
|---|---|---|
| `results/proofs/n{N}-run{R}-stark.proof` | binary, OpenVM v2.1.0 native `Encode` codec | Final aggregated SWIRL STARK proof for N signatures, measured run R. Warm-up runs are not saved. |
| `results/runs.jsonl` | JSON Lines, one object per measured run | status, error, `batch_sha256`, hardware string, `stark_prove_seconds`, `stark_verify_seconds`, `stark_proof_bytes`, `app_prove_seconds`, `app_verify_seconds`, `guest_execute_seconds`, `peak_ram_bytes`, SHA-256/FORS/WOTS/XMSS operation counters |
| `results/driver_errors.jsonl` | JSON Lines | timeouts and harness crashes (for example out-of-memory kills) |
| `results/summary.csv` | CSV, one row per N | median / min / max / p95 of every metric, amortized seconds per signature, signatures per second, proof bytes per signature |
| `results/statistics.json` | JSON | full distributions and failure records |
| `results/01…06_*.png` | PNG graphs | proving time, proof size, verification time, SHA-256 compressions, VM cycles, amortized proving |

Every proof's **public values** (64 bytes) are `SHA-256(batch) ‖ u32le(N) ‖ 28 zero bytes`. The harness checks them against the expected batch before it accepts the proof. `batch_sha256` in `runs.jsonl` holds the matching digest, so each `.proof` file can be traced back to the exact signatures it covers.

### 7.1 Package the proofs in a portable form

`.proof` files are raw binary. To archive or share a run together with everything needed to check it:

```bash
RUN=bench-$(hostname)-$(date -u +%Y%m%dT%H%MZ)
mkdir -p "archive/$RUN"

# environment record (needed to reproduce)
{
  echo "date: $(date -u +%FT%TZ)"
  echo "cpu: $(lscpu | grep 'Model name' | sed 's/.*: *//')"
  echo "cores: $(nproc)"; free -g | sed -n 2p
  rustc +1.91.1 -Vv; cargo -V; rustc +nightly-2026-02-28 -V
  openssl version
  echo "RUSTFLAGS=${RUSTFLAGS:-}"; echo "RAYON_NUM_THREADS=${RAYON_NUM_THREADS:-default}"
  sha256sum fixtures/fixtures.json Cargo.lock
} > "archive/$RUN/environment.txt"

# integrity manifest for every proof
( cd results/proofs && sha256sum *.proof ) > "archive/$RUN/proofs.sha256"

# optional text form (base64) for proofs that must go through JSON/e-mail/tickets
mkdir -p "archive/$RUN/proofs-b64"
for f in results/proofs/*.proof; do base64 -w0 "$f" > "archive/$RUN/proofs-b64/$(basename "$f").b64"; done

# proofs + measurements + graphs + logs in one tarball
cp -r results logs "archive/$RUN/"
tar -C archive -czf "$RUN.tar.gz" "$RUN"
ls -lh "$RUN.tar.gz"
```

Copy it to your laptop:

```bash
scp user@bench-host:~/slh-stark-poc/bench-*.tar.gz .
```

To turn a base64 file back into the original proof: `base64 -d n8-run0-stark.proof.b64 > n8-run0-stark.proof`.

---

## 8. View the benchmark results

`tools/benchmark.py` runs `tools/report.py` automatically after each N. You can also regenerate the reports at any time, without proving again:

```bash
python3 tools/report.py --out results
```

### 8.1 Summary table in the terminal

```bash
# key columns only
python3 - <<'EOF'
import csv
cols = ["N","Status","Successful runs","Failed runs","Prove (s)","Verify (ms)",
        "Proof (bytes)","Peak RAM (bytes)","Amortized prove (s/sig)","Signatures/s"]
rows = list(csv.DictReader(open("results/summary.csv")))
w = [max(len(c), *(len(r[c]) for r in rows)) for c in cols]
print("  ".join(c.rjust(x) for c, x in zip(cols, w)))
for r in rows: print("  ".join(r[c].rjust(x) for c, x in zip(cols, w)))
EOF
```

All columns: `column -s, -t < results/summary.csv | less -S`

### 8.2 Ad-hoc queries on individual runs

```bash
# one line per measured run
jq -r '[.n,.run,.status,.stark_prove_seconds,.stark_verify_seconds,.stark_proof_bytes,(.peak_ram_bytes/1e9)] | @tsv' results/runs.jsonl

# failures and why
jq -r 'select(.status!="ok") | "\(.n)\t\(.error)"' results/runs.jsonl
cat results/driver_errors.jsonl | jq .

# median prove time per N
jq -s 'group_by(.n) | map({n: .[0].n, median_prove_s: (map(.stark_prove_seconds) | sort | .[length/2|floor])})' results/runs.jsonl
```

### 8.3 Graphs

The PNGs in `results/` can be opened on any machine once the tarball is copied over. To view them directly from the server:

```bash
cd results && python3 -m http.server 8000
# on your laptop:  ssh -L 8000:localhost:8000 user@bench-host   then open http://localhost:8000
```

| Graph | Shows |
|---|---|
| `01_proving_time.png` | aggregated STARK proving time against N |
| `02_proof_size.png` | final proof size against N (expected to stay roughly flat thanks to aggregation) |
| `03_verification_time.png` | STARK verification time (ms) against N |
| `04_sha256_compressions.png` | SHA-256 work in the verified signatures (measured independently) |
| `05_vm_cycles.png` | guest cycles (shows *NOT MEASURED* until a profiler is wired in) |
| `06_amortized_proving.png` | proving seconds per signature (the batching benefit) |

### 8.4 Checking a saved proof independently

Right now a proof is verified (`Sdk::verify_proof`) only inside the harness, straight after it is created. There is no separate `verify FILE` command yet. When you re-check archived proofs, compare `proofs.sha256` and the `batch_sha256` in `runs.jsonl`. Adding a standalone verifier that decodes a `.proof` file and checks it against the guest baseline is listed as follow-up work.

---

## 9. Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `died with <Signals.SIGABRT: 6>` or `SIGKILL`; `dmesg` shows `Out of memory: Killed process … (slh-harness)` | Not enough RAM. Use a larger machine, add swap, use `--mode stark`, or lower `RAYON_NUM_THREADS` (fewer parallel traces in memory). |
| `toolchain 'nightly-2026-02-28' is not installed` or `can't find crate for core` while building the guest | `rustup toolchain install nightly-2026-02-28 --component rust-src` |
| `openssl genpkey: Algorithm SLH-DSA-SHA2-128s not found` | OpenSSL is older than 3.5. Only needed for N > 128 or the native baseline (section 4). |
| `not enough fixture signatures` | Requested N > number of fixtures. Install OpenSSL 3.5 so they can be generated. |
| Build fails fetching `github.com/openvm-org/...` | The machine needs outbound HTTPS to GitHub and crates.io for the first build. |
| `public batch mismatch at byte i` | The proof's public values do not match the expected batch. Treat this as a real failure, not a flaky one. |

---

## 10. Quick reference: the whole process

```bash
# install
sudo apt-get update && sudo apt-get install -y build-essential pkg-config clang cmake git curl \
  libssl-dev python3 python3-matplotlib jq time tmux
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal
source ~/.cargo/env
rustup toolchain install 1.91.1 && rustup toolchain install nightly-2026-02-28 --component rust-src

# build + sanity
cd slh-stark-poc
python3 tools/test_protocol.py && cargo build --release -p slh-harness

# prove N = 1..128 (in tmux)
for N in 1 2 3 4 8 16 32 64 128; do
  python3 tools/benchmark.py --n $N --repeats 5 --warmup 1 --timeout 86400 > logs-n$N.log 2>&1
done

# view
column -s, -t < results/summary.csv | less -S
ls -lh results/proofs/ results/*.png
```
