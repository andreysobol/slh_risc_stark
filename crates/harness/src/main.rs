//! Native STARK benchmark harness for OpenVM v2.1.0 + SWIRL.
//! IMPORTANT: Requires the OpenVM toolchain; SDK path has not been compiled in
//! the constrained source-generation environment. No measurement is invented.

use std::{fs::{self, OpenOptions}, io::Write, path::{Path, PathBuf}, time::Instant};
use eyre::{bail, ensure, Result};
use openvm_build::GuestOptions;
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    prover::verify_app_proof_with_expected_exe_commit,
    Sdk, StdIn,
};
use openvm_sdk_config::SdkVmConfig;
use openvm_stark_backend::{codec::Encode, p3_field::PrimeField32};
use openvm_stark_sdk::config::{app_params_with_100_bits_security, MAX_APP_LOG_STACKED_HEIGHT};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAGIC: &[u8] = b"SLHBATCH\x01";
/// OpenVM requires num_public_values = 8 * 2^k (Merkle-hashed in 8-byte chunks).
/// Layout: bytes 0..32 batch SHA-256, 32..36 little-endian N, 36..64 must be zero.
const NUM_PUBLIC_VALUES: usize = 64;
const ALGORITHM: &[u8] = slh_core::ALGORITHM;

#[derive(Debug, Clone, Deserialize)]
struct Fixture {
    index: usize,
    message_hex: String,
    signature_hex: String,
    public_key_hex: String,
}
#[derive(Debug, Deserialize)]
struct FixtureSet {
    algorithm: String,
    records: Vec<Fixture>,
}
#[derive(Clone, Debug)]
struct Args {
    n: Vec<usize>,
    repeats: usize,
    warmup: usize,
    fixtures: PathBuf,
    out: PathBuf,
    mode: String,
}
fn args() -> Result<Args> {
    let mut n = vec![1,2,3,4,8,16,32,64,128];
    let mut repeats = 5;
    let mut warmup = 1;
    let mut fixtures = PathBuf::from("fixtures/fixtures.json");
    let mut out = PathBuf::from("results");
    let mut mode = String::from("both");
    let mut cli = std::env::args().skip(1);
    while let Some(arg) = cli.next() {
        match arg.as_str() {
            "--n" => { let v = cli.next().ok_or_else(|| eyre::eyre!("missing N"))?;
                let n_value: usize = v.parse()?; ensure!(n_value>0,"N must be positive"); n=vec![n_value]; }
            "--all" => n=vec![1,2,3,4,8,16,32,64,128],
            "--repeats" => repeats=cli.next().ok_or_else(||eyre::eyre!("missing repeats"))?.parse()?,
            "--warmup" => warmup=cli.next().ok_or_else(||eyre::eyre!("missing warmup"))?.parse()?,
            "--fixtures" => fixtures=PathBuf::from(cli.next().ok_or_else(||eyre::eyre!("missing fixtures"))?),
            "--out" => out=PathBuf::from(cli.next().ok_or_else(||eyre::eyre!("missing out"))?),
            "--mode" => mode=cli.next().ok_or_else(||eyre::eyre!("missing mode"))?,
            "--help"|"-h" => { println!("Usage: cargo run -p slh-harness --release -- [--n INTEGER | --all] [--repeats 5] [--warmup 1] [--mode both|app|stark] [--fixtures PATH] [--out PATH]"); std::process::exit(0); }
            _ => bail!("unknown option {arg}"),
        }
    }
    ensure!(["both","app","stark"].contains(&mode.as_str()),"bad --mode");
    ensure!(repeats>=1,"repeats must be positive");
    Ok(Args{n,repeats,warmup,fixtures,out,mode})
}

#[derive(Serialize, Default, Clone)]
struct Row {
    n: usize,
    run: usize,
    warmup: bool,
    status: String,
    error: Option<String>,
    algorithm: String,
    batch_sha256: String,
    hardware: String,
    security: String,
    guest_execute_seconds: Option<f64>,
    app_prove_seconds: Option<f64>,
    app_verify_seconds: Option<f64>,
    app_proof_bytes: Option<usize>,
    stark_prove_seconds: Option<f64>,
    stark_verify_seconds: Option<f64>,
    stark_proof_bytes: Option<usize>,
    stark_proof_public_values_bytes: usize,
    stark_proof_verification_metadata_bytes: Option<usize>,
    sha256_calls: u64,
    sha256_compressions: u64,
    mgf1_calls: u64,
    mgf1_sha256_calls: u64,
    f_calls: u64,
    h_calls: u64,
    t_l_calls: u64,
    h_msg_calls: u64,
    fors_leaves: u64,
    fors_auth_nodes: u64,
    wots_chains: u64,
    wots_steps: u64,
    xmss_auth_nodes: u64,
    hypertree_layers: u64,
    commit_sha256_calls: u64,
    commit_sha256_compressions: u64,
    vm_cycles: Option<u64>,
    sha2_accelerated_ops: Option<u64>,
    air_trace_rows: Option<u64>,
    continuation_segments: Option<u64>,
    peak_ram_bytes: Option<u64>,
}

fn push_len(dst:&mut Vec<u8>, blob:&[u8]) -> Result<()> {
    ensure!(blob.len() <= u32::MAX as usize,"field too long");
    dst.extend_from_slice(&(blob.len() as u32).to_le_bytes());
    dst.extend_from_slice(blob);
    Ok(())
}
fn pack(fixtures:&[Fixture]) -> Result<Vec<u8>> {
    ensure!(!fixtures.is_empty(),"empty batch");
    let mut result=Vec::with_capacity(64+fixtures.len()*8000);
    result.extend_from_slice(MAGIC);
    result.extend_from_slice(&(ALGORITHM.len() as u16).to_le_bytes());
    result.extend_from_slice(ALGORITHM);
    result.extend_from_slice(&(fixtures.len() as u32).to_le_bytes());
    for f in fixtures {
        let msg=hex::decode(&f.message_hex)?;
        let pk=hex::decode(&f.public_key_hex)?;
        let sig=hex::decode(&f.signature_hex)?;
        ensure!(msg.len()<=1024*1024 && pk.len()==32 && sig.len()==7856,"bad fixture {}",f.index);
        push_len(&mut result,&msg)?;
        push_len(&mut result,&pk)?;
        push_len(&mut result,&sig)?;
    }
    Ok(result)
}
fn host_hardware() -> String {
    let cpu=fs::read_to_string("/proc/cpuinfo").ok()
        .and_then(|txt|txt.lines().find(|l|l.starts_with("model name")).map(str::to_string))
        .unwrap_or_else(||"unknown CPU".into());
    let os=std::env::consts::OS;
    let gpu=std::env::var("CUDA_VISIBLE_DEVICES").unwrap_or_else(|_|"unset".into());
    format!("{os}; {cpu}; CUDA_VISIBLE_DEVICES={gpu}")
}
fn peak_ram() -> Option<u64> {
    let status=fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find(|s|s.starts_with("VmHWM:"))?
        .split_whitespace().nth(1)?.parse::<u64>().ok().map(|kb|kb*1024)
}
fn append_record(path:&Path, row:&Row) -> Result<()> {
    let mut file=OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file,row)?;
    writeln!(file)?;
    file.flush()?;
    Ok(())
}
fn main() -> Result<()> {
    let a=args()?;
    fs::create_dir_all(&a.out)?;
    let fixtures: FixtureSet = serde_json::from_slice(&fs::read(&a.fixtures)?)?;
    ensure!(fixtures.algorithm == "SLH-DSA-SHA2-128s", "unexpected algorithm");
    ensure!(a.n.iter().all(|n| *n<=fixtures.records.len()),"not enough fixture signatures");
    let hardware=host_hardware();
    let security="OpenVM v2.1.0; app_params_with_100_bits_security; SWIRL".to_string();

    // Compile guest and create proving keys BEFORE timing. Custom VM config
    // required for 64 public bytes; OpenVM CLI keygen rejects that setting.
    let mut cfg=SdkVmConfig::from_toml(include_str!("../../guest/openvm.toml"))?;
    // 32 SHA-256 batch-digest bytes + 4 bytes little-endian N.
    cfg.system.config=cfg.system.config.clone().with_public_values(NUM_PUBLIC_VALUES);
    let app_params=app_params_with_100_bits_security(MAX_APP_LOG_STACKED_HEIGHT);
    let agg_params=AggregationSystemParams::default();
    let sdk=Sdk::new(AppConfig::new(cfg,app_params),agg_params)?;
    let guest_dir=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../guest");
    let elf=sdk.build(GuestOptions::default(),guest_dir.to_str().unwrap(),&None,None)?;
    let exe=sdk.convert_to_exe(elf)?;
    let (_app_pk,app_vk)=sdk.app_keygen();
    let (_agg_pk,agg_vk)=sdk.agg_keygen();
    let mut app_prover=if a.mode=="stark" {None} else {Some(sdk.app_prover(exe.clone())?.with_program_name("slh-stark"))};
    // Commitment to this guest executable + VM config. App proofs must match it,
    // otherwise a valid proof of a *different* program would be accepted.
    let expected_exe_commit=app_prover.as_ref().map(|p|p.app_exe_commit());
    let mut stark_prover=if a.mode=="app" {None} else {Some(sdk.prover(exe.clone())?.with_program_name("slh-stark"))};
    // Build baseline once; generated from executable+VM+aggregation config.
    let baseline=stark_prover.as_ref().map(|p|p.generate_baseline());

    for n in a.n {
        let fixtures=&fixtures.records[..n];
        let input=pack(fixtures)?;
        let hash:[u8;32]=Sha256::digest(&input).into();
        let mut counts=slh_core::Counts::default();
        for f in fixtures {
            let msg=hex::decode(&f.message_hex)?;
            let pk=hex::decode(&f.public_key_hex)?;
            let sig=hex::decode(&f.signature_hex)?;
            let (valid,c)=slh_core::verify_with_counts(&msg,&sig,&pk);
            ensure!(valid,"native Rust signature verifier rejected fixture {}",f.index);
            counts.sha256_calls+=c.sha256_calls;
            counts.sha256_compressions+=c.sha256_compressions;
            counts.mgf1_calls+=c.mgf1_calls;
            counts.mgf1_sha256_calls+=c.mgf1_sha256_calls;
            counts.f+=c.f; counts.h+=c.h; counts.t_l+=c.t_l;
            counts.h_msg_inner+=c.h_msg_inner;
            counts.fors_leaves+=c.fors_leaves;counts.fors_auth_nodes+=c.fors_auth_nodes;
            counts.wots_chains+=c.wots_chains;counts.wots_steps+=c.wots_steps;
            counts.xmss_auth_nodes+=c.xmss_auth_nodes;counts.hypertree_layers+=c.hypertree_layers;
        }
        let mut stdin=StdIn::default();
        stdin.write(&input);
        for run in 0..(a.warmup+a.repeats) {
            let warmup=run<a.warmup;
            let mut row=Row {
                n, run: if warmup {run} else {run-a.warmup},warmup,
                status:"started".into(), error:None,
                algorithm:String::from_utf8_lossy(ALGORITHM).into_owned(),
                batch_sha256:hex::encode(hash),hardware:hardware.clone(),security:security.clone(),
                sha256_calls:counts.sha256_calls,sha256_compressions:counts.sha256_compressions,
                mgf1_calls:counts.mgf1_calls,mgf1_sha256_calls:counts.mgf1_sha256_calls,
                f_calls:counts.f,h_calls:counts.h,t_l_calls:counts.t_l,h_msg_calls:counts.h_msg_inner,
                fors_leaves:counts.fors_leaves,fors_auth_nodes:counts.fors_auth_nodes,
                wots_chains:counts.wots_chains,wots_steps:counts.wots_steps,
                xmss_auth_nodes:counts.xmss_auth_nodes,hypertree_layers:counts.hypertree_layers,
                commit_sha256_calls:1,
                commit_sha256_compressions:((input.len() as u64 +9+63)/64),
                stark_proof_public_values_bytes:NUM_PUBLIC_VALUES,
                ..Row::default()
            };
            let attempt=(||->Result<()> {
                let start=Instant::now();
                let _exec=sdk.execute(exe.clone(),stdin.clone())?;
                row.guest_execute_seconds=Some(start.elapsed().as_secs_f64());
                if let Some(ref mut app)=app_prover {
                    let start=Instant::now();
                    let proof=app.prove(stdin.clone())?;
                    row.app_prove_seconds=Some(start.elapsed().as_secs_f64());
                    let start=Instant::now();
                    verify_app_proof_with_expected_exe_commit::<openvm_sdk::DefaultStarkEngine>(&app_vk,&proof,expected_exe_commit)?;
                    row.app_verify_seconds=Some(start.elapsed().as_secs_f64());
                    // App proof object may span multiple STARK segment artifacts.
                    // Its serialized size is intentionally NOT guessed from Debug
                    // formatting; awaiting confirmed codec in pinned SDK.
                }
                if let Some(ref mut prover)=stark_prover {
                    let start=Instant::now();
                    let (proof,_metadata)=prover.prove(stdin.clone(),&[])?;
                    row.stark_prove_seconds=Some(start.elapsed().as_secs_f64());
                    let mut bytes=Vec::new();
                    proof.encode(&mut bytes)?;
                    row.stark_proof_bytes=Some(bytes.len());
                    // Bind to expected digest and expected N, independent of
                    // supplied proof. Do this before declaring verification OK.
                    let values=&proof.user_pvs_proof.public_values;
                    ensure!(values.len()==NUM_PUBLIC_VALUES,"incorrect public value length");
                    for (i,v) in values.iter().enumerate() {
                        let expect=match i { 0..32=>hash[i], 32..36=>(n as u32).to_le_bytes()[i-32], _=>0 };
                        ensure!(v.as_canonical_u32()==u32::from(expect),"public batch mismatch at byte {i}");
                    }
                    let start=Instant::now();
                    Sdk::verify_proof(agg_vk.clone(),baseline.clone().unwrap(),&proof)?;
                    row.stark_verify_seconds=Some(start.elapsed().as_secs_f64());
                    if !warmup {
                        let proof_dir=a.out.join("proofs");fs::create_dir_all(&proof_dir)?;
                        fs::write(proof_dir.join(format!("n{n}-run{}-stark.proof",row.run)),&bytes)?;
                    }
                }
                Ok(())
            })();
            row.peak_ram_bytes=peak_ram();
            match attempt {
                Ok(())=> row.status="ok".into(),
                Err(e)=> {row.status="failed".into();row.error=Some(format!("{e:#}"));}
            }
            if !warmup {
                append_record(&a.out.join("runs.jsonl"),&row)?;
                println!("N={n} run={} status={} prove={:?}s verify={:?}s bytes={:?}",row.run,row.status,row.stark_prove_seconds,row.stark_verify_seconds,row.stark_proof_bytes);
            }
            if row.status!="ok" { eprintln!("N={n}: {}",row.error.as_deref().unwrap_or("error")); }
        }
    }
    Ok(())
}
