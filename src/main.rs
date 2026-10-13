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
        /// Seconds between progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_every: u64,
        /// Give up after this many attempts (exit code 2).
        #[arg(long)]
        max_attempts: Option<u64>,
    },
    /// Measure sustained attempts per second against a job that never matches.
    Bench {
        /// Seconds per run.
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        /// Thread counts to run in turn, e.g. 1,6,12. Defaults to every logical CPU.
        #[arg(long, value_delimiter = ',')]
        threads: Vec<usize>,
        /// Seconds between progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_every: u64,
    },
    /// Time each stage of one attempt, single-threaded.
    Profile {
        #[arg(long, default_value_t = 20_000)]
        iterations: u32,
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

#[derive(Clone, clap::ValueEnum)]
enum ModeArg {
    Prefix,
    Contains,
    Suffix,
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Grind { job, threads, report_every, max_attempts } => {
            let job: Job = serde_json::from_str(&read_input(&job)?).context("invalid job JSON")?;
            let threads = threads.unwrap_or_else(logical_cpus);
            let limits = Limits { max_attempts, ..Default::default() };
            let outcome = Grinder::new(job)?.run(threads, limits, Duration::from_secs(report_every), progress)?;
            match outcome.hit {
                Some(hit) => println!("{}", serde_json::to_string_pretty(&hit)?),
                None => {
                    eprintln!("no match within --max-attempts");
                    std::process::exit(2);
                }
            }
        }
        Command::Bench { seconds, threads, report_every } => {
            let threads = if threads.is_empty() { vec![logical_cpus()] } else { threads };
            // A 24-character prefix: odds of a hit are 2^-120 per attempt.
            let rule = Rule { mode: Mode::Prefix, value: "a".repeat(24) };
            let grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?;

            for threads in threads {
                eprintln!("bench: {threads} threads for {seconds}s");
                let limits = Limits { deadline: Some(Instant::now() + Duration::from_secs(seconds)), ..Default::default() };
                let outcome = grinder.run(threads, limits, Duration::from_secs(report_every), progress)?;
                let rate = outcome.attempts as f64 / outcome.elapsed.as_secs_f64();
                println!(
                    "{}",
                    json!({
                        "threads": threads,
                        "seconds": outcome.elapsed.as_secs_f64(),
                        "attempts": outcome.attempts,
                        "rate": rate.round(),
                        "ratePerThread": (rate / threads as f64).round(),
                    })
                );
            }
        }
        Command::Profile { iterations } => {
            let rule = Rule { mode: Mode::Prefix, value: "a".repeat(24) };
            let mut grinder = Grinder::new(serde_json::from_value(example::job(&rule))?)?;
            let stages = grinder.profile(iterations)?;
            let total = stages[0].1;
            for (name, ns) in stages {
                println!("{name:<32} {:>9.0} ns  {:>5.1}%", ns, ns / total * 100.0);
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
