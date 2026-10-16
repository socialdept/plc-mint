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
    grind::{Grinder, Mode, Rule, Verdict},
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
    let (signatures, matches, _) = check_grinder(grinder(mode, value));
    (signatures, matches)
}

/// As `check`, for any grinder. Returns (signatures, matches, alternatives).
fn check_grinder(grinder: Grinder) -> (usize, usize, usize) {
    let params = gpu::params(&grinder, CHUNKS, true).unwrap();
    let batch = reference::batch();
    let per_dispatch = THREADS * CHUNKS as usize * batch;

    let mut state = gpu::initial_state(THREADS);
    let mut hit = vec![0u32; HIT_WORDS];
    let mut seen = HashSet::new();
    let (mut signatures, mut matches, mut alternatives) = (0, 0, 0);

    for _ in 0..2 {
        let before = state.clone();
        let mut dbg = vec![0u32; per_dispatch * DEBUG_WORDS];
        reference::run(&params, &mut state, &mut hit, &mut dbg);

        let report = gpu::verify_debug(&grinder, &dbg, &mut seen).unwrap();
        signatures += report.signatures;
        matches += report.matches;
        alternatives += report.alternatives;

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
    assert_eq!(hit[18] as usize, alternatives, "alternative counter");
    let recorded = gpu::alternatives(&hit);
    assert_eq!(recorded.len(), alternatives.min(gpu::ALT_SLOTS));
    for (sig, position) in recorded {
        assert_eq!(grinder.clone().verdict(&sig), Verdict::Alternative(position), "recorded alternative");
    }
    (signatures, matches, alternatives)
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
fn alternatives_agree_with_the_cpu() {
    // One character: start, end and middle all turn up within a few hundred attempts.
    for mode in [Mode::Prefix, Mode::Suffix] {
        let (_, matches, alternatives) = check_grinder(grinder(mode, "a").with_alternatives(10));
        assert!(matches > 0 && alternatives > 0);
    }
    let (_, _, alternatives) = check_grinder(grinder(Mode::Contains, "a").with_alternatives(10));
    assert_eq!(alternatives, 0, "contains has no other positions");
}

#[test]
fn glob_mode_agrees_with_the_cpu() {
    // Every attempt's verdict is compared, so misses count as much as hits.
    let mut matches = 0;
    for pattern in ["a*b", "^a*", "*a$", "^a*b$", "a*b*c*d", "^*ab*$", "aa*aa", "a_b", "^_a*b_$", "__a__"] {
        matches += check(Mode::Glob, pattern).1;
    }
    assert!(matches > 0);
}

#[test]
fn finds_and_records_a_hit() {
    // One character anywhere matches about half the time, so 128 attempts hit.
    let (_, matches) = check(Mode::Contains, "a");
    assert!(matches > 0);
}

mod arithmetic {
    use k256::{FieldElement, Scalar, elliptic_curve::{Field, PrimeField}};
    use plc_mint::gpu::reference::op;
    use rand_core::OsRng;

    const P_MINUS_1: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2e";
    const N_MINUS_1: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140";

    fn hex32(s: &str) -> [u8; 32] {
        data_encoding::HEXLOWER.decode(s.as_bytes()).unwrap().try_into().unwrap()
    }

    fn field_cases() -> Vec<FieldElement> {
        let mut cases: Vec<FieldElement> = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "00000000000000000000000000000000000000000000000000000001000003d1",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000",
            "8000000000000000000000000000000000000000000000000000000000000000",
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2d",
            P_MINUS_1,
        ]
        .iter()
        .map(|h| FieldElement::from_bytes(&hex32(h).into()).unwrap())
        .collect();
        cases.extend((0..3000).map(|_| FieldElement::random(&mut OsRng)));
        cases
    }

    fn scalar_cases() -> Vec<Scalar> {
        let mut cases: Vec<Scalar> = [
            "0000000000000000000000000000000000000000000000000000000000000001",
            "0000000000000000000000000000000000000000000000000000000000000002",
            "0000000000000000000000000000000145512319 50b75fc4402da1732fc9bebf",
            "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0",
            N_MINUS_1,
        ]
        .iter()
        .map(|h| Scalar::from_repr(hex32(&h.replace(' ', "")).into()).unwrap())
        .collect();
        cases.extend((0..3000).map(|_| Scalar::random(&mut OsRng)));
        cases
    }

    fn fb(x: &FieldElement) -> [u8; 32] {
        x.to_bytes().into()
    }

    fn sb(x: &Scalar) -> [u8; 32] {
        x.to_bytes().into()
    }

    #[test]
    fn field_ops_match_k256() {
        let cases = field_cases();
        for (i, a) in cases.iter().enumerate() {
            let b = &cases[(i * 7 + 3) % cases.len()];
            assert_eq!(op(0, &fb(a), &fb(b)), fb(&(*a * b).normalize()), "fmul {i}");
            assert_eq!(op(1, &fb(a), &fb(b)), fb(&a.square().normalize()), "fsqr {i}");
            assert_eq!(op(6, &fb(a), &fb(b)), fb(&(*a + b).normalize()), "fadd {i}");
            assert_eq!(op(7, &fb(a), &fb(b)), fb(&(*a - b).normalize()), "fsub {i}");
            if i % 10 == 0 {
                assert_eq!(op(2, &fb(a), &fb(b)), fb(&a.invert().unwrap().normalize()), "finv {i}");
            }
        }
    }

    #[test]
    fn scalar_ops_match_k256() {
        let cases = scalar_cases();
        for (i, a) in cases.iter().enumerate() {
            let b = &cases[(i * 7 + 3) % cases.len()];
            assert_eq!(op(3, &sb(a), &sb(b)), sb(&(*a * b)), "smul {i}");
            assert_eq!(op(4, &sb(a), &sb(b)), sb(&a.square()), "ssqr {i}");
            assert_eq!(op(8, &sb(a), &sb(b)), sb(&(*a + b)), "sadd {i}");
            if i % 10 == 0 {
                assert_eq!(op(5, &sb(a), &sb(b)), sb(&a.invert().unwrap()), "sinv {i}");
            }
        }
    }
}
