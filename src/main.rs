use std::{
    io::Read,
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use plc_mint::{
    didkey, example,
    grind::{Grinder, Job, Limits, Mode, Rule},
    op,
    signer::NonceMode,
};
use rand_core::OsRng;
use serde_json::{Value, json};

#[derive(Parser)]
#[command(version, about = "Grind vanity did:plc identifiers")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Grind a job until its DID matches. Prints the hit as JSON.
    Grind {
        /// Job file, or - for stdin.
        #[arg(long)]
        job: String,
        /// Worker threads. Defaults to every logical CPU.
        #[arg(long)]
        threads: Option<usize>,
        /// Nonce strategy: rfc6979, random or incremental.
        #[arg(long, default_value = "rfc6979")]
        nonce: NonceMode,
        /// Seconds between progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_every: u64,
        /// Give up after this many attempts (exit code 2).
        #[arg(long)]
        max_attempts: Option<u64>,
        #[command(flatten)]
        gpu: GpuArgs,
    },
    /// Measure sustained attempts per second against a job that never matches.
    Bench {
        /// Seconds per run.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Thread counts to run in turn, e.g. 1,6,12. Defaults to every logical CPU.
        #[arg(long, value_delimiter = ',')]
        threads: Vec<usize>,
        /// Nonce strategies to run in turn. Defaults to all of them.
        #[arg(long, value_delimiter = ',')]
        nonce: Vec<NonceMode>,
        /// Seconds between progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_every: u64,
        #[command(flatten)]
        gpu: GpuArgs,
    },
    /// Run the GPU kernel in debug mode and check every attempt on the CPU.
    GpuSelftest {
        #[command(flatten)]
        gpu: GpuArgs,
        /// Chunks per thread per dispatch.
        #[arg(long, default_value_t = 2)]
        chunks: u32,
    },
    /// Single-threaded cost per signature for each nonce mode, and per hash check.
    Profile {
        /// Batches of 256 signatures to time per mode.
        #[arg(long, default_value_t = 40)]
        chunks: u32,
    },
    /// Recompute the DID of a signed genesis op and verify its signature.
    Verify {
        /// A signed op, or {did, operation} as in an audit log entry. - for stdin.
        file: String,
    },
    /// Generate a secp256k1 key pair.
    Keygen,
    /// Print a throwaway job with fresh keys, for testing.
    ExampleJob {
        #[arg(long, value_enum, default_value = "prefix")]
        mode: ModeArg,
        #[arg(long, default_value = "abc")]
        value: String,
    },
}

#[derive(clap::Args)]
struct GpuArgs {
    /// Grind on the GPU (Metal) instead of the CPU. Ignores --threads and --nonce.
    #[arg(long)]
    gpu: bool,
    /// GPU: nonces per thread per batched inversion.
    #[arg(long, default_value_t = 32)]
    gpu_batch: usize,
    /// GPU: threads per dispatch.
    #[arg(long, default_value_t = 65536)]
    gpu_threads: usize,
}

#[cfg(all(feature = "gpu", target_os = "macos"))]
fn gpu(args: &GpuArgs) -> Result<plc_mint::gpu::metal_backend::Gpu> {
    let gpu = plc_mint::gpu::metal_backend::Gpu::new(args.gpu_batch, args.gpu_threads)?;
    eprintln!("gpu: {} (batch {}, {} threads)", gpu.name(), gpu.batch, gpu.threads);
    Ok(gpu)
}

/// Stands in for the Metal backend in builds without it; `gpu()` always errors.
#[cfg(not(all(feature = "gpu", target_os = "macos")))]
struct NoGpu;

#[cfg(not(all(feature = "gpu", target_os = "macos")))]
impl NoGpu {
    fn run(&self, _: &Grinder, _: Limits, _: Duration, _: impl FnMut(u64, Duration)) -> Result<plc_mint::grind::Outcome> {
        unreachable!()
    }

    fn selftest(&self, _: &Grinder, _: u32) -> Result<plc_mint::gpu::DebugReport> {
        unreachable!()
    }
}

#[cfg(not(all(feature = "gpu", target_os = "macos")))]
fn gpu(_: &GpuArgs) -> Result<NoGpu> {
    anyhow::bail!("built without GPU support: rebuild on macOS with `cargo build --release --features gpu`")
}

#[derive(Clone, clap::ValueEnum)]
enum ModeArg {
    Prefix,
    Contains,
    Suffix,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Grind { job, threads, nonce, report_every, max_attempts, gpu: gpu_args } => {
            let job: Job = serde_json::from_str(&read_input(&job)?).context("invalid job JSON")?;
            let threads = threads.unwrap_or_else(logical_cpus);
            let limits = Limits { max_attempts, ..Default::default() };
            let grinder = Grinder::new(job)?;
            let every = Duration::from_secs(report_every);
            let outcome = if gpu_args.gpu {
                gpu(&gpu_args)?.run(&grinder, limits, every, progress)?
            } else {
                grinder.run(threads, nonce, limits, every, progress)?
            };
            match outcome.hit {
                Some(hit) => println!("{}", serde_json::to_string_pretty(&hit)?),
                None => {
                    eprintln!("no match within --max-attempts");
                    std::process::exit(2);
                }
            }
        }
        Command::Bench { seconds, threads, nonce, report_every, gpu: gpu_args } => {
            let threads = if threads.is_empty() { vec![logical_cpus()] } else { threads };
            let modes = if nonce.is_empty() { NonceMode::ALL.to_vec() } else { nonce };
            // A 24-character prefix: odds of a hit are 2^-120 per attempt.
            let rule = Rule { mode: Mode::Prefix, value: "a".repeat(24) };
            let grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?;

            if gpu_args.gpu {
                let gpu = gpu(&gpu_args)?;
                eprintln!("bench: gpu for {seconds}s");
                let limits = Limits { deadline: Some(Instant::now() + Duration::from_secs(seconds)), ..Default::default() };
                let outcome = gpu.run(&grinder, limits, Duration::from_secs(report_every), progress)?;
                let rate = outcome.attempts as f64 / outcome.elapsed.as_secs_f64();
                println!(
                    "{}",
                    json!({
                        "backend": "gpu",
                        "batch": gpu_args.gpu_batch,
                        "gpuThreads": gpu_args.gpu_threads,
                        "seconds": outcome.elapsed.as_secs_f64(),
                        "attempts": outcome.attempts,
                        "rate": rate.round(),
                    })
                );
                return Ok(());
            }

            for (mode, threads) in modes.iter().flat_map(|m| threads.iter().map(move |t| (*m, *t))) {
                eprintln!("bench: {mode} nonces, {threads} threads for {seconds}s");
                let limits = Limits { deadline: Some(Instant::now() + Duration::from_secs(seconds)), ..Default::default() };
                let outcome = grinder.run(threads, mode, limits, Duration::from_secs(report_every), progress)?;
                let rate = outcome.attempts as f64 / outcome.elapsed.as_secs_f64();
                println!(
                    "{}",
                    json!({
                        "nonce": mode.to_string(),
                        "threads": threads,
                        "seconds": outcome.elapsed.as_secs_f64(),
                        "attempts": outcome.attempts,
                        "rate": rate.round(),
                        "ratePerThread": (rate / threads as f64).round(),
                    })
                );
            }
        }
        Command::GpuSelftest { gpu: gpu_args, chunks } => {
            // One character anywhere: about half of all attempts match, so both
            // verdicts get exercised.
            let rule = Rule { mode: Mode::Contains, value: "a".into() };
            let grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?;
            let report = gpu(&gpu_args)?.selftest(&grinder, chunks)?;
            println!(
                "ok: {} signatures from the GPU all verify with unique nonces; {} match verdicts agree with the CPU",
                report.signatures, report.matches
            );
        }
        Command::Profile { chunks } => {
            let rule = Rule { mode: Mode::Prefix, value: "a".repeat(24) };
            let mut grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?;
            let stages = grinder.profile(chunks)?;
            let (_, check) = stages.last().cloned().unwrap();
            for (name, ns) in &stages {
                println!("{name:<28} {ns:>9.0} ns");
            }
            println!();
            for (name, sign) in &stages[..stages.len() - 1] {
                let attempt = sign + check;
                println!("{:<28} {attempt:>9.0} ns  ~{:.0}/s per thread", format!("attempt, {}", name.trim_start_matches("sign: ")), 1e9 / attempt);
            }
        }
        Command::Verify { file } => {
            let input: Value = serde_json::from_str(&read_input(&file)?).context("invalid JSON")?;
            let (expected, operation) = match input.get("operation") {
                Some(operation) => (input["did"].as_str().map(str::to_owned), operation.clone()),
                None => (None, input),
            };
            let did = op::did_for(&operation)?;
            let signed_by = op::verify_genesis(&operation)?;
            let mut out = json!({ "did": did, "signedBy": operation["rotationKeys"][signed_by] });
            if let Some(expected) = expected {
                out["matchesExpected"] = json!(expected == did);
            }
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::Keygen => {
            let key = k256::ecdsa::SigningKey::random(&mut OsRng);
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({
                    "privateKey": HEXLOWER.encode(&key.to_bytes()),
                    "didKey": didkey::encode_k256(key.verifying_key()),
                }))?
            );
        }
        Command::ExampleJob { mode, value } => {
            let mode = match mode {
                ModeArg::Prefix => Mode::Prefix,
                ModeArg::Contains => Mode::Contains,
                ModeArg::Suffix => Mode::Suffix,
            };
            println!("{}", serde_json::to_string_pretty(&example::job(&Rule { mode, value }))?);
        }
    }
    Ok(())
}

fn progress(attempts: u64, elapsed: Duration) {
    eprintln!(
        "{attempts} attempts, {:.0}s, {:.0}/s",
        elapsed.as_secs_f64(),
        attempts as f64 / elapsed.as_secs_f64()
    );
}

fn logical_cpus() -> usize {
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

fn read_input(path: &str) -> Result<String> {
    if path == "-" {
        let mut s = String::new();
        std::io::stdin().read_to_string(&mut s)?;
        Ok(s)
    } else {
        std::fs::read_to_string(path).with_context(|| format!("reading {path}"))
    }
}
