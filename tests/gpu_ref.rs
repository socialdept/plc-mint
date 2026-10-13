//! The GPU kernel compiled as C++ (`--features gpu-ref`), checked against the CPU:
//! every signature verifies, uses exactly the expected nonce, and gets the same
//! match verdict the CPU gives.
#![cfg(feature = "gpu-ref")]

use std::collections::HashSet;

use k256::{
    ProjectivePoint, Scalar, U256,
    elliptic_curve::{ops::{MulByGenerator, Reduce}, point::AffineCoordinates},
};
use plc_mint::{
    example,
    gpu::{self, DEBUG_WORDS, HIT_WORDS, STATE_WORDS, reference},
    grind::{Grinder, Mode, Rule},
};

const THREADS: usize = 4;
const CHUNKS: u32 = 2;

fn grinder(mode: Mode, value: &str) -> Grinder {
    Grinder::new(serde_json::from_value(example::job(&Rule { mode, value: value.into() })).unwrap()).unwrap()
}

fn nonce(state: &[u32], thread: usize) -> Scalar {
    let words = &state[thread * STATE_WORDS..thread * STATE_WORDS + 8];
    let mut bytes = [0u8; 32];
    for (i, w) in words.iter().enumerate() {
        bytes[28 - 4 * i..32 - 4 * i].copy_from_slice(&w.to_be_bytes());
    }
    <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
}

/// Runs two dispatches and checks every attempt. Returns (signatures, matches).
fn check(mode: Mode, value: &str) -> (usize, usize) {
    let grinder = grinder(mode, value);
    let params = gpu::params(&grinder, CHUNKS, true).unwrap();
    let batch = reference::batch();
    let per_dispatch = THREADS * CHUNKS as usize * batch;

    let mut state = gpu::initial_state(THREADS);
    let mut hit = vec![0u32; HIT_WORDS];
    let mut seen = HashSet::new();
    let (mut signatures, mut matches) = (0, 0);

    for _ in 0..2 {
        let before = state.clone();
        let mut dbg = vec![0u32; per_dispatch * DEBUG_WORDS];
        reference::run(&params, &mut state, &mut hit, &mut dbg);

        let report = gpu::verify_debug(&grinder, &dbg, &mut seen).unwrap();
        signatures += report.signatures;
        matches += report.matches;

        // Attempt i of thread t must use nonce k_t + i, so r = x((k_t + i) * G) mod n.
        for t in 0..THREADS {
            let k = nonce(&before, t);
            for j in 0..CHUNKS as usize * batch {
                let record = &dbg[(t * CHUNKS as usize * batch + j) * DEBUG_WORDS..][..DEBUG_WORDS];
                let expected = ProjectivePoint::mul_by_generator(&(k + Scalar::from(j as u64))).to_affine();
                let expected_r = <Scalar as Reduce<U256>>::reduce_bytes(&expected.x());
                assert_eq!(&gpu::sig_bytes(&record[..16])[..32], &expected_r.to_bytes()[..], "thread {t} attempt {j}");
            }
            // And the state advanced by exactly the attempts made.
            assert_eq!(nonce(&state, t), k + Scalar::from((CHUNKS as usize * batch) as u64));
        }
    }

    assert_eq!(hit[0] as usize, matches, "hit counter");
    if matches > 0 {
        let sig = gpu::sig_bytes(&hit[2..18]);
        assert!(grinder.clone().check(&sig), "recorded hit does not match on the CPU");
    }
    (signatures, matches)
}

#[test]
fn contains_mode_agrees_with_the_cpu() {
    let (signatures, _) = check(Mode::Contains, "a");
    assert_eq!(signatures, 2 * THREADS * CHUNKS as usize * reference::batch());
}

#[test]
fn prefix_and_suffix_modes_agree_with_the_cpu() {
    check(Mode::Prefix, "a");
    check(Mode::Suffix, "a");
}

#[test]
fn finds_and_records_a_hit() {
    // One character anywhere matches about half the time, so 128 attempts hit.
    let (_, matches) = check(Mode::Contains, "a");
    assert!(matches > 0);
}
