//! The grinder: re-sign a fixed genesis op with fresh nonces until its DID matches.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use data_encoding::{BASE64URL_NOPAD, Encoding, HEXLOWER_PERMISSIVE};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    cbor, didkey, op,
    signer::{CHUNK, NonceMode, Signer},
};

/// Signed ops above this size are rejected by the PLC directory.
const MAX_OP_BYTES: usize = 7500;
/// base64url of a 64-byte `r || s` signature.
const SIG_LEN: usize = 86;
const ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz234567";
/// How often the coordinating thread checks limits and reports progress.
const POLL: Duration = Duration::from_millis(20);

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Job {
    /// The unsigned genesis op (no `sig` field).
    pub operation: Value,
    /// Hex secp256k1 private key; its did:key must be in `rotationKeys`.
    pub signing_key: String,
    #[serde(rename = "match")]
    pub rule: Rule,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Rule {
    pub mode: Mode,
    pub value: String,
}

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Prefix,
    Contains,
    Suffix,
}

impl Rule {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.value.is_empty(), "match value is empty");
        ensure!(self.value.len() <= 24, "match value is longer than 24 characters");
        if let Some(c) = self.value.chars().find(|c| !ALPHABET.contains(*c)) {
            bail!("'{c}' can never appear in a did:plc (allowed: a-z, 2-7)");
        }
        Ok(())
    }

    pub fn matches(&self, identifier: &[u8]) -> bool {
        let value = self.value.as_bytes();
        match self.mode {
            Mode::Prefix => identifier.starts_with(value),
            Mode::Suffix => identifier.ends_with(value),
            Mode::Contains => identifier.windows(value.len()).any(|w| w == value),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Hit {
    pub did: String,
    pub signed_op: Value,
    pub attempts: u64,
    pub elapsed_ms: u128,
    pub rate: f64,
}

/// When to give up without a hit. Both are checked with up to `threads * CHUNK`
/// attempts of overshoot.
#[derive(Default)]
pub struct Limits {
    pub max_attempts: Option<u64>,
    pub deadline: Option<Instant>,
}

pub struct Outcome {
    pub hit: Option<Hit>,
    pub attempts: u64,
    pub elapsed: Duration,
}

#[derive(Clone)]
pub struct Grinder {
    pub(crate) key: SigningKey,
    op: Value,
    pub(crate) rule: Rule,
    /// SHA-256 of the unsigned op: the prehash every attempt signs.
    pub(crate) digest: [u8; 32],
    /// The signed op's DAG-CBOR with a placeholder signature at `slot`.
    pub(crate) template: Vec<u8>,
    pub(crate) slot: usize,
    base32: Encoding,
}

impl Grinder {
    pub fn new(job: Job) -> Result<Self> {
        job.rule.validate()?;

        let op = job.operation;
        let fields = op.as_object().context("operation must be an object")?;
        ensure!(!fields.contains_key("sig"), "operation must be unsigned (no sig field)");
        ensure!(op["type"] == "plc_operation", "operation type must be plc_operation");
        ensure!(
            fields.get("prev") == Some(&Value::Null),
            "genesis must have prev: null (present, not omitted)"
        );

        let key_bytes = HEXLOWER_PERMISSIVE
            .decode(job.signing_key.trim().as_bytes())
            .context("signingKey is not hex")?;
        let key = SigningKey::from_slice(&key_bytes).context("signingKey is not a valid secp256k1 key")?;
        let did_key = didkey::encode_k256(key.verifying_key());
        let rotation = op["rotationKeys"].as_array().context("missing rotationKeys")?;
        ensure!(
            rotation.iter().any(|k| k == &did_key),
            "signingKey ({did_key}) is not in rotationKeys"
        );

        let digest = Sha256::digest(op::unsigned_bytes(&op)?).into();

        let mut placeholder = op.clone();
        placeholder["sig"] = Value::String("A".repeat(SIG_LEN));
        let template = cbor::encode(&placeholder)?;
        ensure!(template.len() <= MAX_OP_BYTES, "signed op would be {} bytes (max {MAX_OP_BYTES})", template.len());

        // `sig` sorts first (shortest key), so its text string sits near the start.
        let mut needle = vec![0x78, SIG_LEN as u8];
        needle.extend(std::iter::repeat_n(b'A', SIG_LEN));
        let slot = template
            .windows(needle.len())
            .position(|w| w == needle)
            .context("could not locate the signature slot in the template")?
            + 2;

        Ok(Self { key, op, rule: job.rule, digest, template, slot, base32: op::base32() })
    }

    /// Writes `sig` into the template, hashes it and checks the identifier.
    pub fn check(&mut self, sig: &[u8; 64]) -> bool {
        BASE64URL_NOPAD.encode_mut(sig, &mut self.template[self.slot..self.slot + SIG_LEN]);
        let hash = Sha256::digest(&self.template);

        let mut identifier = [0u8; 24];
        self.base32.encode_mut(&hash[..15], &mut identifier);
        self.rule.matches(&identifier)
    }

    /// A signer for this job's key and digest. Each worker needs its own.
    pub fn signer(&self, mode: NonceMode) -> Signer {
        Signer::new(mode, &self.key, self.digest)
    }

    /// Grinds on `threads` workers until a hit or a limit. `report` gets the running
    /// attempt total roughly every `every`.
    pub fn run(
        &self,
        threads: usize,
        nonce: NonceMode,
        limits: Limits,
        every: Duration,
        mut report: impl FnMut(u64, Duration),
    ) -> Result<Outcome> {
        let start = Instant::now();
        let stop = AtomicBool::new(false);
        let total = AtomicU64::new(0);
        let found: Mutex<Option<[u8; 64]>> = Mutex::new(None);
        let failure: Mutex<Option<anyhow::Error>> = Mutex::new(None);

        thread::scope(|scope| {
            for _ in 0..threads.max(1) {
                let mut worker = self.clone();
                let (stop, total, found, failure) = (&stop, &total, &found, &failure);
                scope.spawn(move || {
                    let mut signer = worker.signer(nonce);
                    let mut sigs = [[0u8; 64]; CHUNK];
                    while !stop.load(Ordering::Relaxed) {
                        if let Err(e) = signer.fill(&mut sigs) {
                            failure.lock().unwrap().get_or_insert(e);
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                        let mut done = 0;
                        for sig in &sigs {
                            done += 1;
                            if worker.check(sig) {
                                found.lock().unwrap().get_or_insert(*sig);
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                        total.fetch_add(done, Ordering::Relaxed);
                    }
                });
            }

            let mut last_report = start;
            while !stop.load(Ordering::Relaxed) {
                thread::sleep(POLL);
                let attempts = total.load(Ordering::Relaxed);
                if limits.max_attempts.is_some_and(|max| attempts >= max)
                    || limits.deadline.is_some_and(|deadline| Instant::now() >= deadline)
                {
                    stop.store(true, Ordering::Relaxed);
                }
                if last_report.elapsed() >= every {
                    last_report = Instant::now();
                    report(attempts, start.elapsed());
                }
            }
        });

        if let Some(e) = failure.into_inner().unwrap() {
            return Err(e);
        }
        let elapsed = start.elapsed();
        let attempts = total.into_inner();
        let hit = match found.into_inner().unwrap() {
            Some(sig) => {
                let (did, signed_op) = self.finish(&sig)?;
                Some(Hit {
                    did,
                    signed_op,
                    attempts,
                    elapsed_ms: elapsed.as_millis(),
                    rate: attempts as f64 / elapsed.as_secs_f64(),
                })
            }
            None => None,
        };
        Ok(Outcome { hit, attempts, elapsed })
    }

    /// Single-threaded nanoseconds per signature for each nonce mode, and per check
    /// (base64url + SHA-256 + base32 + match). An attempt costs one of each.
    pub fn profile(&mut self, chunks: u32) -> Result<Vec<(String, f64)>> {
        let per_sig = |start: Instant| start.elapsed().as_nanos() as f64 / (chunks as f64 * CHUNK as f64);
        let mut sigs = [[0u8; 64]; CHUNK];
        let mut stages = Vec::new();

        for mode in NonceMode::ALL {
            let mut signer = self.signer(mode);
            let start = Instant::now();
            for _ in 0..chunks {
                signer.fill(&mut sigs)?;
            }
            stages.push((format!("sign: {mode}"), per_sig(start)));
        }

        let start = Instant::now();
        for _ in 0..chunks {
            for sig in &sigs {
                std::hint::black_box(self.check(sig));
            }
        }
        stages.push((format!("check ({} B template)", self.template.len()), per_sig(start)));
        Ok(stages)
    }

    /// Builds the signed op from scratch and re-verifies it independently of the
    /// template, so a template bug can never produce a wrong result.
    pub(crate) fn finish(&self, sig: &[u8; 64]) -> Result<(String, Value)> {
        let mut signed = self.op.clone();
        signed["sig"] = Value::String(BASE64URL_NOPAD.encode(sig));

        let did = op::did_for(&signed)?;
        let identifier = did.trim_start_matches("did:plc:");
        ensure!(self.rule.matches(identifier.as_bytes()), "re-encoded DID {did} does not match the rule");
        op::verify_genesis(&signed).context("ground signature failed verification")?;

        Ok((did, signed))
    }
}
