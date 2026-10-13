//! Signature producers for the hot loop, one per nonce strategy.
//!
//! Every strategy signs the same digest with the same key and yields valid,
//! low-S ECDSA signatures; they differ only in how the nonce `k` is chosen and so
//! in cost per signature.
//!
//! **Nonce safety.** `Incremental` uses related nonces (`k0, k0+1, k0+2, …`) on one
//! message. Two published signatures from it would reveal the private key, so it is
//! only safe because exactly one signature per job ever leaves the grinder: the
//! hit. Losing signatures must never be logged, stored or returned, and a grind key
//! must never be reused across jobs. `k0` comes from a CSPRNG per worker thread.

use std::{fmt, str::FromStr};

use anyhow::{Result, bail};
use k256::{
    AffinePoint, FieldBytes, NonZeroScalar, ProjectivePoint, Scalar, U256,
    ecdsa::{Signature, SigningKey, hazmat::SignPrimitive, signature::hazmat::RandomizedPrehashSigner},
    elliptic_curve::{BatchNormalize, ops::{MulByGenerator, Reduce}, point::AffineCoordinates},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{OsRng, SeedableRng};

/// Signatures produced per `fill` call; also the batch size for shared inversions.
pub const CHUNK: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceMode {
    /// RFC 6979 deterministic nonce mixed with OS entropy, per signature. The
    /// library's standard signer; slowest.
    Rfc6979,
    /// Uniform random nonce from a per-thread ChaCha20 CSPRNG, then the library's
    /// low-level signing primitive. One generator multiplication and two inversions
    /// per signature.
    Random,
    /// `k = k0 + i`: each R is the previous plus G (one point addition), and the
    /// point normalizations and nonce inversions are batched with Montgomery's trick
    /// across `CHUNK` signatures. Needs an ECDSA review before production.
    Incremental,
}

impl NonceMode {
    pub const ALL: [NonceMode; 3] = [Self::Rfc6979, Self::Random, Self::Incremental];
}

impl FromStr for NonceMode {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "rfc6979" => Ok(Self::Rfc6979),
            "random" => Ok(Self::Random),
            "incremental" => Ok(Self::Incremental),
            other => bail!("unknown nonce mode '{other}' (rfc6979, random, incremental)"),
        }
    }
}

impl fmt::Display for NonceMode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Rfc6979 => "rfc6979",
            Self::Random => "random",
            Self::Incremental => "incremental",
        })
    }
}

pub struct Signer {
    mode: NonceMode,
    key: SigningKey,
    d: Scalar,
    digest: [u8; 32],
    z: Scalar,
    rng: ChaCha20Rng,
    /// Incremental state: the next nonce and its point `k * G`.
    k: Scalar,
    r_point: ProjectivePoint,
}

impl Signer {
    pub fn new(mode: NonceMode, key: &SigningKey, digest: [u8; 32]) -> Self {
        let mut signer = Self {
            mode,
            key: key.clone(),
            d: *key.as_nonzero_scalar().as_ref(),
            digest,
            z: <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::from(digest)),
            rng: ChaCha20Rng::from_rng(OsRng).expect("OS entropy"),
            k: Scalar::ZERO,
            r_point: ProjectivePoint::IDENTITY,
        };
        signer.reseed();
        signer
    }

    fn reseed(&mut self) {
        self.k = *NonZeroScalar::random(&mut self.rng).as_ref();
        self.r_point = ProjectivePoint::mul_by_generator(&self.k);
    }

    /// Fills `out` with `CHUNK` fresh low-S signatures as `r || s` bytes.
    pub fn fill(&mut self, out: &mut [[u8; 64]; CHUNK]) -> Result<()> {
        match self.mode {
            NonceMode::Rfc6979 => {
                for slot in out.iter_mut() {
                    let sig: Signature = self.key.sign_prehash_with_rng(&mut OsRng, &self.digest)?;
                    *slot = sig.normalize_s().unwrap_or(sig).to_bytes().into();
                }
            }
            NonceMode::Random => {
                let z = FieldBytes::from(self.digest);
                for slot in out.iter_mut() {
                    let k = NonZeroScalar::random(&mut self.rng);
                    let (sig, _) = self.d.try_sign_prehashed(*k, &z)?;
                    *slot = sig.normalize_s().unwrap_or(sig).to_bytes().into();
                }
            }
            NonceMode::Incremental => {
                // A zero nonce or zero r/s has probability ~2^-256; start over if hit.
                while !self.fill_incremental(out) {
                    self.reseed();
                }
            }
        }
        Ok(())
    }

    fn fill_incremental(&mut self, out: &mut [[u8; 64]; CHUNK]) -> bool {
        // R_i = R_0 + i*G, one mixed addition each.
        let mut points = [ProjectivePoint::IDENTITY; CHUNK];
        let mut point = self.r_point;
        for p in points.iter_mut() {
            *p = point;
            point += AffinePoint::GENERATOR;
        }
        let affine = <ProjectivePoint as BatchNormalize<[ProjectivePoint; CHUNK]>>::batch_normalize(&points);

        // k_i^-1 for all i with one inversion (Montgomery's trick).
        let mut prefix = [Scalar::ONE; CHUNK];
        let mut acc = Scalar::ONE;
        let mut k = self.k;
        for p in prefix.iter_mut() {
            acc *= k;
            *p = acc;
            k += Scalar::ONE;
        }
        let Some(mut inv) = Option::<Scalar>::from(acc.invert()) else {
            return false;
        };
        let mut k_inv = [Scalar::ZERO; CHUNK];
        for i in (0..CHUNK).rev() {
            let k_i = self.k + Scalar::from(i as u64);
            k_inv[i] = if i == 0 { inv } else { inv * prefix[i - 1] };
            inv *= k_i;
        }

        for i in 0..CHUNK {
            let r = <Scalar as Reduce<U256>>::reduce_bytes(&affine[i].x());
            let s = k_inv[i] * (self.z + r * self.d);
            let Ok(sig) = Signature::from_scalars(r, s) else {
                return false;
            };
            out[i] = sig.normalize_s().unwrap_or(sig).to_bytes().into();
        }

        self.k = k;
        self.r_point = point;
        true
    }
}
