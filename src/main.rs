use std::{io::Read, time::Duration};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use data_encoding::HEXLOWER;
use plc_mint::{
    didkey,
    grind::{Grinder, Job, Mode, Rule},
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
        /// Seconds between progress lines on stderr.
        #[arg(long, default_value_t = 5)]
        report_every: u64,
        /// Give up after this many attempts (exit code 2).
        #[arg(long)]
        max_attempts: Option<u64>,
    },
    /// Recompute the DID of a signed genesis op and verify its signature.
    Verify {
        /// A signed op, or {did, operation} as in an audit log entry. - for stdin.
        file: String,
    },
    /// Generate a secp256k1 key pair.
    Keygen,
    /// Print a throwaway job with fresh keys, for testing and benchmarks.
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
        Command::Grind { job, report_every, max_attempts } => {
            let job: Job = serde_json::from_str(&read_input(&job)?).context("invalid job JSON")?;
            let mut grinder = Grinder::new(job)?;
            let hit = grinder.run(max_attempts, Duration::from_secs(report_every), |attempts, elapsed| {
                eprintln!(
                    "{attempts} attempts, {:.0}s, {:.0}/s",
                    elapsed.as_secs_f64(),
                    attempts as f64 / elapsed.as_secs_f64()
                );
            })?;
            match hit {
                Some(hit) => println!("{}", serde_json::to_string_pretty(&hit)?),
                None => {
                    eprintln!("no match within --max-attempts");
                    std::process::exit(2);
                }
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
            // Stand-ins for the real roles: customer recovery key (P-256), per-job
            // grind key and temp signing key (k256). Only the grind key is kept.
            let recovery = p256::ecdsa::SigningKey::random(&mut OsRng);
            let grind = k256::ecdsa::SigningKey::random(&mut OsRng);
            let temp_signing = k256::ecdsa::SigningKey::random(&mut OsRng);
            let job = json!({
                "operation": {
                    "type": "plc_operation",
                    "rotationKeys": [
                        didkey::encode_p256(recovery.verifying_key()),
                        didkey::encode_k256(grind.verifying_key()),
                    ],
                    "verificationMethods": { "atproto": didkey::encode_k256(temp_signing.verifying_key()) },
                    "alsoKnownAs": ["at://pending.example.com"],
                    "services": {
                        "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example.com" }
                    },
                    "prev": null,
                },
                "signingKey": HEXLOWER.encode(&grind.to_bytes()),
                "match": Rule { mode, value },
            });
            println!("{}", serde_json::to_string_pretty(&job)?);
        }
    }
    Ok(())
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
