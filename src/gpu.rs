//! GPU grinding (spike). The kernel lives in `gpu/kernel.metal`; this module
//! prepares its inputs, checks its debug output on the CPU, and drives it through
//! Metal (`--features gpu`, macOS) or as compiled C++ (`--features gpu-ref`, tests).
//!
//! The GPU is never trusted: every hit goes through `Grinder::finish`, which rebuilds
//! the op from scratch and re-verifies the signature.

use std::collections::HashSet;

use anyhow::{Result, ensure};
use k256::{
    AffinePoint, ProjectivePoint, Scalar, U256,
    ecdsa::{Signature, signature::hazmat::PrehashVerifier},
    elliptic_curve::{
        BatchNormalize, ops::{MulByGenerator, Reduce}, sec1::ToEncodedPoint,
    },
};
use rand_core::OsRng;

use crate::grind::{Grinder, Mode};

/// Words per thread in the state buffer: nonce k, then affine x and y of k*G.
pub const STATE_WORDS: usize = 24;
/// Words per attempt in the debug buffer: r, s, matched flag.
pub const DEBUG_WORDS: usize = 17;
/// Words in the hit buffer: count, thread id, r, s.
pub const HIT_WORDS: usize = 18;

/// Mirrors `struct Params` in `gpu/kernel.metal`.
#[repr(C)]
#[derive(Clone)]
pub struct Params {
    pub d: [u32; 8],
    pub z: [u32; 8],
    pub tmpl: [u32; 128],
    pub slot: u32,
    pub mode: u32,
    pub len: u32,
    pub chunks: u32,
    pub debug: u32,
    pub value: [u32; 24],
    pub sched: [u32; 384],
}

/// Big-endian 32 bytes to little-endian 32-bit limbs.
fn limbs(bytes: &[u8]) -> [u32; 8] {
    std::array::from_fn(|i| u32::from_be_bytes(bytes[28 - 4 * i..32 - 4 * i].try_into().unwrap()))
}

pub fn params(grinder: &Grinder, chunks: u32, debug: bool) -> Result<Params> {
    // SHA-256 padding of the template, as 8 blocks of big-endian words.
    let mut msg = grinder.template.clone();
    let bits = (msg.len() as u64) * 8;
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bits.to_be_bytes());
    ensure!(msg.len() == 512, "template must pad to 8 SHA-256 blocks (got {} bytes)", msg.len());
    ensure!(grinder.slot + 86 <= 128, "signature slot must sit in the first two blocks");

    let z = <Scalar as Reduce<U256>>::reduce_bytes(&grinder.digest.into());
    let rule = &grinder.rule;
    let mut value = [0u32; 24];
    for (slot, byte) in value.iter_mut().zip(rule.value.bytes()) {
        *slot = byte as u32;
    }

    Ok(Params {
        d: limbs(&grinder.key.to_bytes()),
        z: limbs(&z.to_bytes()),
        tmpl: std::array::from_fn(|i| u32::from_be_bytes(msg[4 * i..4 * i + 4].try_into().unwrap())),
        slot: grinder.slot as u32,
        mode: match rule.mode {
            Mode::Prefix => 0,
            Mode::Suffix => 1,
            Mode::Contains => 2,
        },
        len: rule.value.len() as u32,
        chunks,
        debug: debug as u32,
        value,
        sched: constant_schedules(&msg),
    })
}

/// SHA-256 message schedules (64 words each) of blocks 2..7, which never change
/// between attempts, so the kernel only runs their rounds.
fn constant_schedules(msg: &[u8]) -> [u32; 384] {
    let mut out = [0u32; 384];
    for (blk, sched) in out.chunks_exact_mut(64).enumerate() {
        let block = &msg[(blk + 2) * 64..(blk + 3) * 64];
        for t in 0..16 {
            sched[t] = u32::from_be_bytes(block[4 * t..4 * t + 4].try_into().unwrap());
        }
        for t in 16..64 {
            let s0 = sched[t - 15].rotate_right(7) ^ sched[t - 15].rotate_right(18) ^ (sched[t - 15] >> 3);
            let s1 = sched[t - 2].rotate_right(17) ^ sched[t - 2].rotate_right(19) ^ (sched[t - 2] >> 10);
            sched[t] = sched[t - 16].wrapping_add(s0).wrapping_add(sched[t - 7]).wrapping_add(s1);
        }
    }
    out
}

/// Starting nonce and point for every GPU thread. Thread t starts at
/// `k0 + t * 2^64`, so threads never overlap within 2^64 attempts each.
pub fn initial_state(threads: usize) -> Vec<u32> {
    let k0 = *k256::NonZeroScalar::random(&mut OsRng).as_ref();
    let stride = Scalar::from(u64::MAX) + Scalar::ONE;
    let step = ProjectivePoint::mul_by_generator(&stride);

    let mut ks = Vec::with_capacity(threads);
    let mut points = Vec::with_capacity(threads);
    let (mut k, mut point) = (k0, ProjectivePoint::mul_by_generator(&k0));
    for _ in 0..threads {
        ks.push(k);
        points.push(point);
        k += stride;
        point += step;
    }
    let affine: Vec<AffinePoint> = <ProjectivePoint as BatchNormalize<[ProjectivePoint]>>::batch_normalize(&points);

    let mut state = Vec::with_capacity(threads * STATE_WORDS);
    for (k, p) in ks.iter().zip(&affine) {
        let encoded = p.to_encoded_point(false);
        state.extend_from_slice(&limbs(&k.to_bytes()));
        state.extend_from_slice(&limbs(encoded.x().unwrap()));
        state.extend_from_slice(&limbs(encoded.y().unwrap()));
    }
    state
}

/// `r || s` limbs (as the kernel writes them) to signature bytes.
pub fn sig_bytes(words: &[u32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for half in 0..2 {
        for i in 0..8 {
            let limb = words[half * 8 + i];
            out[half * 32 + 28 - 4 * i..half * 32 + 32 - 4 * i].copy_from_slice(&limb.to_be_bytes());
        }
    }
    out
}

#[derive(Debug, Default)]
pub struct DebugReport {
    pub signatures: usize,
    pub matches: usize,
}

/// Checks every attempt the kernel recorded: the signature verifies (low-S) under
/// the grind key, r is unique, and the kernel's match verdict agrees with the CPU's.
pub fn verify_debug(grinder: &Grinder, dbg: &[u32], seen_r: &mut HashSet<[u8; 32]>) -> Result<DebugReport> {
    let key = grinder.key.verifying_key();
    let mut cpu = grinder.clone();
    let mut report = DebugReport::default();

    for (i, record) in dbg.chunks_exact(DEBUG_WORDS).enumerate() {
        let sig = sig_bytes(&record[..16]);
        let parsed = Signature::from_slice(&sig).map_err(|e| anyhow::anyhow!("attempt {i}: malformed signature: {e}"))?;
        key.verify_prehash(&grinder.digest, &parsed)
            .map_err(|_| anyhow::anyhow!("attempt {i}: signature does not verify"))?;
        ensure!(seen_r.insert(sig[..32].try_into().unwrap()), "attempt {i}: repeated r (nonce reuse)");

        let gpu_matched = record[16] != 0;
        ensure!(gpu_matched == cpu.check(&sig), "attempt {i}: kernel match verdict disagrees with the CPU");
        report.signatures += 1;
        report.matches += gpu_matched as usize;
    }
    Ok(report)
}

#[cfg(feature = "gpu-ref")]
pub mod reference {
    //! The kernel compiled as C++ (`gpu/cpu_ref.cpp`).

    use super::Params;

    unsafe extern "C" {
        fn plcmint_ref_batch() -> u32;
        fn plcmint_ref_run(params: *const Params, state: *mut u32, threads: u32, hit: *mut u32, dbg: *mut u32);
        fn plcmint_ref_op(op: u32, a: *const u32, b: *const u32, out: *mut u32);
    }

    /// One kernel arithmetic op on big-endian 32-byte values. See `plcmint_ref_op`.
    pub fn op(op: u32, a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
        let (a, b) = (super::limbs(a), super::limbs(b));
        let mut out = [0u32; 8];
        unsafe { plcmint_ref_op(op, a.as_ptr(), b.as_ptr(), out.as_mut_ptr()) };
        let mut bytes = [0u8; 32];
        for (i, limb) in out.iter().enumerate() {
            bytes[28 - 4 * i..32 - 4 * i].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    pub fn batch() -> usize {
        unsafe { plcmint_ref_batch() as usize }
    }

    pub fn run(params: &Params, state: &mut [u32], hit: &mut [u32], dbg: &mut [u32]) {
        let threads = state.len() / super::STATE_WORDS;
        assert!(hit.len() >= super::HIT_WORDS);
        assert!(params.debug == 0 || dbg.len() >= threads * params.chunks as usize * batch() * super::DEBUG_WORDS);
        unsafe { plcmint_ref_run(params, state.as_mut_ptr(), threads as u32, hit.as_mut_ptr(), dbg.as_mut_ptr()) }
    }
}

#[cfg(all(feature = "gpu", target_os = "macos"))]
pub mod metal_backend {
    use std::{
        collections::HashSet,
        ffi::c_void,
        time::{Duration, Instant},
    };

    use anyhow::{Context, Result, anyhow};
    use metal::{CompileOptions, ComputePipelineState, Device, MTLResourceOptions, MTLSize};

    use super::{DEBUG_WORDS, DebugReport, HIT_WORDS, Params};
    use crate::grind::{Grinder, Hit, Limits, Outcome};

    const KERNEL: &str = include_str!("../gpu/kernel.metal");
    /// Wall time to aim for per dispatch: long enough to amortize overhead, short
    /// enough to stop promptly and keep the desktop responsive.
    const TARGET: Duration = Duration::from_millis(200);

    pub struct Gpu {
        device: Device,
        pipeline: ComputePipelineState,
        pub batch: usize,
        pub threads: usize,
    }

    impl Gpu {
        pub fn new(batch: usize, threads: usize) -> Result<Self> {
            let device = Device::system_default().context("no Metal device")?;
            let source = format!("#define BATCH {batch}\n{KERNEL}");
            let library = device
                .new_library_with_source(&source, &CompileOptions::new())
                .map_err(|e| anyhow!("kernel compile failed: {e}"))?;
            let function = library.get_function("grind", None).map_err(|e| anyhow!(e))?;
            let pipeline = device.new_compute_pipeline_state_with_function(&function).map_err(|e| anyhow!(e))?;
            Ok(Self { device, pipeline, batch, threads })
        }

        pub fn name(&self) -> String {
            self.device.name().to_owned()
        }

        fn buffer(&self, words: &[u32]) -> metal::Buffer {
            self.device.new_buffer_with_data(
                words.as_ptr() as *const c_void,
                (words.len() * 4) as u64,
                MTLResourceOptions::StorageModeShared,
            )
        }

        fn dispatch(&self, params: &Params, state: &metal::Buffer, hit: &metal::Buffer, dbg: &metal::Buffer) {
            metal::objc::rc::autoreleasepool(|| {
                let queue = self.device.new_command_queue();
                let cmd = queue.new_command_buffer();
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(&self.pipeline);
                enc.set_bytes(0, size_of::<Params>() as u64, params as *const Params as *const c_void);
                enc.set_buffer(1, Some(state), 0);
                enc.set_buffer(2, Some(hit), 0);
                enc.set_buffer(3, Some(dbg), 0);
                let group = self.pipeline.max_total_threads_per_threadgroup().min(256);
                enc.dispatch_threads(MTLSize::new(self.threads as u64, 1, 1), MTLSize::new(group, 1, 1));
                enc.end_encoding();
                cmd.commit();
                cmd.wait_until_completed();
            });
        }

        fn words(buffer: &metal::Buffer, len: usize) -> &[u32] {
            unsafe { std::slice::from_raw_parts(buffer.contents() as *const u32, len) }
        }

        /// One small dispatch in debug mode, every attempt checked on the CPU, then a
        /// second dispatch to check that state carries over without nonce reuse.
        pub fn selftest(&self, grinder: &Grinder, chunks: u32) -> Result<DebugReport> {
            let state = self.buffer(&super::initial_state(self.threads));
            let hit = self.buffer(&[0u32; HIT_WORDS]);
            let records = self.threads * chunks as usize * self.batch;
            let dbg = self.buffer(&vec![0u32; records * DEBUG_WORDS]);
            let params = super::params(grinder, chunks, true)?;

            let mut seen = HashSet::new();
            let mut total = DebugReport::default();
            for _ in 0..2 {
                self.dispatch(&params, &state, &hit, &dbg);
                let report = super::verify_debug(grinder, Self::words(&dbg, records * DEBUG_WORDS), &mut seen)?;
                total.signatures += report.signatures;
                total.matches += report.matches;
            }
            let hits = Self::words(&hit, HIT_WORDS);
            if total.matches > 0 {
                anyhow::ensure!(hits[0] as usize == total.matches, "hit counter {} != matches {}", hits[0], total.matches);
                grinder.finish(&super::sig_bytes(&hits[2..18])).context("recorded hit failed CPU verification")?;
            }
            Ok(total)
        }

        pub fn run(
            &self,
            grinder: &Grinder,
            limits: Limits,
            every: Duration,
            mut report: impl FnMut(u64, Duration),
        ) -> Result<Outcome> {
            let state = self.buffer(&super::initial_state(self.threads));
            let hit = self.buffer(&[0u32; HIT_WORDS]);
            let dbg = self.buffer(&[0u32; DEBUG_WORDS]);
            let per_chunk = (self.threads * self.batch) as u64;

            let start = Instant::now();
            let mut last_report = start;
            let mut attempts = 0u64;
            let mut chunks = 1u32;
            loop {
                let params = super::params(grinder, chunks, false)?;
                let t = Instant::now();
                self.dispatch(&params, &state, &hit, &dbg);
                let took = t.elapsed();
                attempts += per_chunk * chunks as u64;

                let hits = Self::words(&hit, HIT_WORDS);
                if hits[0] != 0 {
                    let elapsed = start.elapsed();
                    let (did, signed_op) = grinder.finish(&super::sig_bytes(&hits[2..18]))?;
                    let hit = Hit {
                        did,
                        signed_op,
                        attempts,
                        elapsed_ms: elapsed.as_millis(),
                        rate: attempts as f64 / elapsed.as_secs_f64(),
                    };
                    return Ok(Outcome { hit: Some(hit), attempts, elapsed });
                }
                if limits.max_attempts.is_some_and(|max| attempts >= max)
                    || limits.deadline.is_some_and(|deadline| Instant::now() >= deadline)
                {
                    return Ok(Outcome { hit: None, attempts, elapsed: start.elapsed() });
                }
                if last_report.elapsed() >= every {
                    last_report = Instant::now();
                    report(attempts, start.elapsed());
                }

                let scale = TARGET.as_secs_f64() / took.as_secs_f64().max(1e-6);
                chunks = ((chunks as f64 * scale.clamp(0.5, 2.0)).round() as u32).clamp(1, 4096);
            }
        }
    }

}
