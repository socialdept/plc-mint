use std::{
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use plc_mint::{
    didkey, example,
    grind::{Grinder, Hit, Job, Limits, Mode, Rule},
    init, op,
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
    /// Create keys and a job to grind. Writes <out>/job.json and <out>/keys.json.
    Init {
        #[command(flatten)]
        init: InitArgs,
    },
    /// Grind a job until its DID matches. Prints the hit as JSON.
    Grind {
        /// Job file, or - for stdin.
        #[arg(long)]
        job: String,
        /// Save alternatives (the value in other positions) into this directory.
        #[arg(long)]
        save_alternatives: Option<PathBuf>,
        #[command(flatten)]
        grind: GrindArgs,
    },
    /// init + grind in one go. Writes <out>/keys.json, job.json and hit.json, ready for plc-claim.
    Mint {
        #[command(flatten)]
        init: InitArgs,
        #[command(flatten)]
        grind: GrindArgs,
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
struct InitArgs {
    #[arg(long, value_enum, default_value = "prefix")]
    mode: ModeArg,
    /// The string to look for (a-z, 2-7).
    #[arg(long)]
    value: String,
    /// Bring your own recovery key (did:key, k256 or P-256) instead of generating one.
    #[arg(long)]
    recovery: Option<String>,
    /// Directory to write into; created if missing. Existing files are never overwritten.
    #[arg(long)]
    out: PathBuf,
}

#[derive(clap::Args)]
struct GrindArgs {
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
    /// Alternatives to save per position (start, end, middle) when the target is a
    /// prefix or suffix. 0 turns them off.
    #[arg(long, default_value_t = 10)]
    alternatives: usize,
    #[command(flatten)]
    gpu: GpuArgs,
}

#[derive(clap::Args)]
struct GpuArgs {
    /// Grind on the GPU (Metal) instead of the CPU. Ignores --threads and --nonce.
    #[arg(long)]
    gpu: bool,
    /// GPU: nonces per thread per batched inversion.
    #[arg(long, default_value_t = 64)]
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
    fn run(
        &self,
        _: &Grinder,
        _: Limits,
        _: Duration,
        _: impl FnMut(u64, Duration),
        _: impl FnMut(Hit) -> Result<()>,
    ) -> Result<plc_mint::grind::Outcome> {
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

impl From<ModeArg> for Mode {
    fn from(mode: ModeArg) -> Self {
        match mode {
            ModeArg::Prefix => Mode::Prefix,
            ModeArg::Contains => Mode::Contains,
            ModeArg::Suffix => Mode::Suffix,
        }
    }
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Init { init } => {
            write_init(&init)?;
        }
        Command::Grind { job, save_alternatives, grind: args } => {
            let job: Job = serde_json::from_str(&read_input(&job)?).context("invalid job JSON")?;
            let hit = grind(job, &args, save_alternatives.as_deref())?;
            println!("{}", serde_json::to_string_pretty(&hit)?);
            // stdout usually goes to a file; show the result on the terminal too.
            eprintln!("{}", hit.did);
        }
        Command::Mint { init, grind: args } => {
            let job = write_init(&init)?;
            let hit = grind(serde_json::from_value(job)?, &args, Some(&init.out.join("alternatives")))?;
            let path = init.out.join("hit.json");
            write_private(&path, &serde_json::to_value(&hit)?)?;
            eprintln!("wrote {}", path.display());
            println!("{}", hit.did);
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
                let outcome = gpu.run(&grinder, limits, Duration::from_secs(report_every), progress, |_| Ok(()))?;
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
                let outcome = grinder.run(threads, mode, limits, Duration::from_secs(report_every), progress, |_| Ok(()))?;
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
            // One character as a prefix, with alternatives: about 1 in 32 attempts hits
            // the target and most of the rest land elsewhere, so every verdict gets
            // exercised.
            let rule = Rule { mode: Mode::Prefix, value: "a".into() };
            let grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?.with_alternatives(1);
            let report = gpu(&gpu_args)?.selftest(&grinder, chunks)?;
            println!(
                "ok: {} signatures from the GPU all verify with unique nonces; {} target and {} alternative verdicts agree with the CPU",
                report.signatures, report.matches, report.alternatives
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
            println!("{}", serde_json::to_string_pretty(&example::job(&Rule { mode: mode.into(), value }))?);
        }
    }
    Ok(())
}

/// Writes keys.json and job.json for `init` and returns the job.
fn write_init(args: &InitArgs) -> Result<Value> {
    let rule = Rule { mode: args.mode.clone().into(), value: args.value.to_lowercase() };
    let init = init::init(&rule, args.recovery.as_deref())?;
    let out = &args.out;
    std::fs::create_dir_all(out).with_context(|| format!("creating {}", out.display()))?;
    // Refuse up front rather than after a long grind.
    let hit = out.join("hit.json");
    anyhow::ensure!(!hit.exists(), "{} already exists", hit.display());
    write_private(&out.join("keys.json"), &init.keys)?;
    write_private(&out.join("job.json"), &init.job)?;
    eprintln!("wrote {0}/job.json and {0}/keys.json", out.display());
    eprintln!("keys.json holds private keys: keep it, back it up, never share it");
    Ok(init.job)
}

/// Grinds until a hit, saving alternatives into `alternatives` as they turn up;
/// exits with code 2 if `--max-attempts` runs out first.
fn grind(job: Job, args: &GrindArgs, alternatives: Option<&Path>) -> Result<Hit> {
    let threads = args.threads.unwrap_or_else(logical_cpus);
    let limits = Limits { max_attempts: args.max_attempts, ..Default::default() };
    let mut grinder = Grinder::new(job)?;
    if let Some(dir) = alternatives {
        grinder = grinder.with_alternatives(args.alternatives);
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let every = Duration::from_secs(args.report_every);
    let save = |hit: Hit| -> Result<()> {
        let dir = alternatives.expect("alternatives are only reported when a directory is set");
        let path = dir.join(format!("{}.json", hit.did.trim_start_matches("did:plc:")));
        let position = serde_json::to_value(hit.position)?;
        write_private(&path, &serde_json::to_value(&hit)?)?;
        eprintln!("alternative ({}): {}  -> {}", position.as_str().unwrap_or_default(), hit.did, path.display());
        Ok(())
    };
    let outcome = if args.gpu.gpu {
        gpu(&args.gpu)?.run(&grinder, limits, every, progress, save)?
    } else {
        grinder.run(threads, args.nonce, limits, every, progress, save)?
    };
    outcome.hit.ok_or_else(|| {
        eprintln!("no match within --max-attempts");
        std::process::exit(2)
    })
}

fn progress(attempts: u64, elapsed: Duration) {
    eprintln!(
        "{attempts} attempts, {:.0}s, {:.0}/s",
        elapsed.as_secs_f64(),
        attempts as f64 / elapsed.as_secs_f64()
    );
}

/// Writes JSON readable only by the owner, refusing to replace an existing file.
fn write_private(path: &std::path::Path, value: &Value) -> Result<()> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    let mut file = options.open(path).with_context(|| format!("creating {} (it must not exist yet)", path.display()))?;
    writeln!(file, "{}", serde_json::to_string_pretty(value)?)?;
    Ok(())
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
