//! The grinder: re-sign a fixed genesis op with fresh nonces until its DID matches.

use std::{
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
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
    /// `*` matches any run of characters (including none) and `_` exactly one.
    /// The pattern may sit anywhere unless it starts with `^` or ends with `$`.
    Glob,
}

/// Characters with a meaning in glob patterns.
pub const GLOB_CHARS: &str = "*_^$";

impl Rule {
    pub fn validate(&self) -> Result<()> {
        ensure!(!self.value.is_empty(), "match value is empty");
        ensure!(self.value.len() <= 24, "match value is longer than 24 characters");
        let glob = matches!(self.mode, Mode::Glob);
        if let Some(c) = self.value.chars().find(|c| !ALPHABET.contains(*c) && !(glob && GLOB_CHARS.contains(*c))) {
            if GLOB_CHARS.contains(c) {
                bail!("'{c}' is a glob character: use --mode glob");
            }
            bail!("'{c}' can never appear in a did:plc (allowed: a-z, 2-7)");
        }
        if glob {
            let body = self.value.strip_prefix('^').unwrap_or(&self.value);
            let body = body.strip_suffix('$').unwrap_or(body);
            ensure!(!body.contains(['^', '$']), "'^' may only start a glob and '$' only end it");
            ensure!(body.chars().any(|c| ALPHABET.contains(c)), "glob has no characters to match");
            let width = body.chars().filter(|c| *c != '*').count();
            if self.value.starts_with('^') && self.value.ends_with('$') && !body.contains('*') {
                ensure!(width == 24, "glob pins both ends with no '*', so it needs exactly 24 characters");
            }
        }
        Ok(())
    }

    pub fn matches(&self, identifier: &[u8]) -> bool {
        let value = self.value.as_bytes();
        match self.mode {
            Mode::Prefix => identifier.starts_with(value),
            Mode::Suffix => identifier.ends_with(value),
            Mode::Contains => identifier.windows(value.len()).any(|w| w == value),
            Mode::Glob => glob_matches(value, identifier),
        }
    }
}

/// Matches segments leftmost-first, which is exact because every segment has a
/// fixed width (`_` is one character). The GPU kernel's `glob_match` is the same
/// algorithm.
fn glob_matches(pattern: &[u8], identifier: &[u8]) -> bool {
    let (start, pattern) = pattern.strip_prefix(b"^").map_or((false, pattern), |p| (true, p));
    let (end, pattern) = pattern.strip_suffix(b"$").map_or((false, pattern), |p| (true, p));
    let segments: Vec<&[u8]> = pattern.split(|c| *c == b'*').collect();
    let last = segments.len() - 1;
    let mut pos = 0;
    for (i, segment) in segments.into_iter().enumerate() {
        if segment.is_empty() {
            continue;
        }
        let fits = |at: usize| identifier[at..].iter().zip(segment).all(|(c, p)| *p == b'_' || c == p);
        let at = if i == 0 && start {
            if segment.len() > identifier.len() || !fits(0) || (i == last && end && segment.len() != identifier.len()) {
                return false;
            }
            0
        } else if i == last && end {
            match identifier.len().checked_sub(segment.len()) {
                Some(at) if at >= pos && fits(at) => at,
                _ => return false,
            }
        } else {
            match (pos..=identifier.len().saturating_sub(segment.len())).find(|&at| at + segment.len() <= identifier.len() && fits(at)) {
                Some(at) => at,
                None => return false,
            }
        };
        pos = at + segment.len();
    }
    true
}

/// Where the match value landed in an identifier that missed the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Position {
    Start,
    End,
    Middle,
}

impl Position {
    pub const ALL: [Self; 3] = [Self::Start, Self::End, Self::Middle];
}

/// The outcome of one attempt. `code()` is the number the GPU kernel uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Miss,
    Target,
    Alternative(Position),
}

impl Verdict {
    pub fn code(self) -> u32 {
        match self {
            Self::Miss => 0,
            Self::Target => 1,
            Self::Alternative(Position::Start) => 2,
            Self::Alternative(Position::End) => 3,
            Self::Alternative(Position::Middle) => 4,
        }
    }

    pub fn from_code(code: u32) -> Self {
        match code {
            1 => Self::Target,
            2 => Self::Alternative(Position::Start),
            3 => Self::Alternative(Position::End),
            4 => Self::Alternative(Position::Middle),
            _ => Self::Miss,
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
    /// Set on alternatives: where the value sits instead of the target position.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub position: Option<Position>,
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
    /// Alternatives to keep per position; 0 means only the target counts.
    pub(crate) alternatives: usize,
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

        Ok(Self { key, op, rule: job.rule, digest, template, slot, base32: op::base32(), alternatives: 0 })
    }

    /// Also report the value in other positions than the target (prefix or suffix
    /// only), keeping up to `per_position` of each. All of them share this job's
    /// keys, so at most one may ever be published.
    pub fn with_alternatives(mut self, per_position: usize) -> Self {
        if matches!(self.rule.mode, Mode::Prefix | Mode::Suffix) {
            self.alternatives = per_position;
        }
        self
    }

    /// Writes `sig` into the template, hashes it and checks the identifier.
    pub fn check(&mut self, sig: &[u8; 64]) -> bool {
        self.verdict(sig) == Verdict::Target
    }

    /// Like `check`, but also says where the value landed when it missed the target.
    pub fn verdict(&mut self, sig: &[u8; 64]) -> Verdict {
        BASE64URL_NOPAD.encode_mut(sig, &mut self.template[self.slot..self.slot + SIG_LEN]);
        let hash = Sha256::digest(&self.template);

        let mut identifier = [0u8; 24];
        self.base32.encode_mut(&hash[..15], &mut identifier);
        self.classify(&identifier)
    }

    fn classify(&self, identifier: &[u8]) -> Verdict {
        if self.rule.matches(identifier) {
            return Verdict::Target;
        }
        if self.alternatives == 0 {
            return Verdict::Miss;
        }
        let value = self.rule.value.as_bytes();
        if identifier.starts_with(value) {
            Verdict::Alternative(Position::Start)
        } else if identifier.ends_with(value) {
            Verdict::Alternative(Position::End)
        } else if identifier.windows(value.len()).any(|w| w == value) {
            Verdict::Alternative(Position::Middle)
        } else {
            Verdict::Miss
        }
    }

    /// A signer for this job's key and digest. Each worker needs its own.
    pub fn signer(&self, mode: NonceMode) -> Signer {
        Signer::new(mode, &self.key, self.digest)
    }

    /// Grinds on `threads` workers until a hit or a limit. `report` gets the running
    /// attempt total roughly every `every`; `alternative` gets each kept alternative
    /// as it is found (see `with_alternatives`).
    pub fn run(
        &self,
        threads: usize,
        nonce: NonceMode,
        limits: Limits,
        every: Duration,
        mut report: impl FnMut(u64, Duration),
        mut alternative: impl FnMut(Hit) -> Result<()>,
    ) -> Result<Outcome> {
        let start = Instant::now();
        let stop = AtomicBool::new(false);
        let total = AtomicU64::new(0);
        let found: Mutex<Option<[u8; 64]>> = Mutex::new(None);
        let failure: Mutex<Option<anyhow::Error>> = Mutex::new(None);
        let kept = Position::ALL.map(|_| AtomicUsize::new(0));
        let alternatives: Mutex<Vec<([u8; 64], Position)>> = Mutex::new(Vec::new());

        thread::scope(|scope| {
            for _ in 0..threads.max(1) {
                let mut worker = self.clone();
                let (stop, total, found, failure, kept, alternatives) =
                    (&stop, &total, &found, &failure, &kept, &alternatives);
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
                            match worker.verdict(sig) {
                                Verdict::Miss => {}
                                Verdict::Target => {
                                    found.lock().unwrap().get_or_insert(*sig);
                                    stop.store(true, Ordering::Relaxed);
                                    break;
                                }
                                Verdict::Alternative(position) => {
                                    if kept[position as usize].fetch_add(1, Ordering::Relaxed) < worker.alternatives {
                                        alternatives.lock().unwrap().push((*sig, position));
                                    }
                                }
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
                let caught = std::mem::take(&mut *alternatives.lock().unwrap());
                for (sig, position) in caught {
                    if let Err(e) = self.hit(&sig, attempts, start.elapsed(), Some(position)).and_then(&mut alternative) {
                        failure.lock().unwrap().get_or_insert(e);
                        stop.store(true, Ordering::Relaxed);
                    }
                }
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
            Some(sig) => Some(self.hit(&sig, attempts, elapsed, None)?),
            None => None,
        };
        Ok(Outcome { hit, attempts, elapsed })
    }

    /// A verified `Hit` for `sig`, found after `attempts` in `elapsed`.
    pub(crate) fn hit(&self, sig: &[u8; 64], attempts: u64, elapsed: Duration, position: Option<Position>) -> Result<Hit> {
        let expected = position.map_or(Verdict::Target, Verdict::Alternative);
        let (did, signed_op) = self.finish(sig, expected)?;
        Ok(Hit {
            did,
            signed_op,
            attempts,
            elapsed_ms: elapsed.as_millis(),
            rate: attempts as f64 / elapsed.as_secs_f64(),
            position,
        })
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
    pub(crate) fn finish(&self, sig: &[u8; 64], expected: Verdict) -> Result<(String, Value)> {
        let mut signed = self.op.clone();
        signed["sig"] = Value::String(BASE64URL_NOPAD.encode(sig));

        let did = op::did_for(&signed)?;
        let verdict = self.classify(did.trim_start_matches("did:plc:").as_bytes());
        ensure!(verdict == expected, "re-encoded DID {did} is {verdict:?}, expected {expected:?}");
        op::verify_genesis(&signed).context("ground signature failed verification")?;

        Ok((did, signed))
    }
}
