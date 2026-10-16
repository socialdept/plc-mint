//! Grind a match and have a second library verify the result.

use std::time::Duration;

use plc_mint::{
    example,
    grind::{Grinder, Hit, Job, Limits, Mode, Position, Rule},
    op,
    signer::NonceMode,
};
use rand_core::OsRng;
use serde_json::Value;
use sha2::{Digest, Sha256};

fn job(mode: Mode, value: &str) -> (Job, k256::ecdsa::SigningKey) {
    let job: Job = serde_json::from_value(example::job(&Rule { mode, value: value.into() })).unwrap();
    let key = data_encoding::HEXLOWER.decode(job.signing_key.as_bytes()).unwrap();
    let key = k256::ecdsa::SigningKey::from_slice(&key).unwrap();
    (job, key)
}

fn grind_with(threads: usize, nonce: NonceMode, mode: Mode, value: &str) -> (Hit, k256::ecdsa::SigningKey) {
    let (job, key) = job(mode, value);
    let limits = Limits { max_attempts: Some(5_000_000), ..Default::default() };
    let outcome = Grinder::new(job).unwrap().run(threads, nonce, limits, Duration::MAX, |_, _| {}, |_| Ok(())).unwrap();
    (outcome.hit.expect("no hit"), key)
}

fn grind(mode: Mode, value: &str) -> (Hit, k256::ecdsa::SigningKey) {
    grind_with(1, NonceMode::Rfc6979, mode, value)
}

/// Verifies with libsecp256k1, which shares no code with the RustCrypto signer and
/// rejects high-S signatures.
fn verify_with_libsecp256k1(signed_op: &Value, key: &k256::ecdsa::SigningKey) {
    let sig = data_encoding::BASE64URL_NOPAD.decode(signed_op["sig"].as_str().unwrap().as_bytes()).unwrap();
    let digest: [u8; 32] = Sha256::digest(op::unsigned_bytes(signed_op).unwrap()).into();

    let pubkey = secp256k1::PublicKey::from_slice(&key.verifying_key().to_encoded_point(true).to_bytes()).unwrap();
    let sig = secp256k1::ecdsa::Signature::from_compact(&sig).unwrap();
    secp256k1::SECP256K1
        .verify_ecdsa(&secp256k1::Message::from_digest(digest), &sig, &pubkey)
        .expect("libsecp256k1 rejected the signature");
}

#[test]
fn grinds_a_prefix() {
    let (hit, key) = grind(Mode::Prefix, "ab");
    assert!(hit.did.starts_with("did:plc:ab"), "{}", hit.did);
    assert_eq!(op::did_for(&hit.signed_op).unwrap(), hit.did);
    assert_eq!(serde_ipld_dagcbor::to_vec(&hit.signed_op).unwrap(), plc_mint::cbor::encode(&hit.signed_op).unwrap());
    verify_with_libsecp256k1(&hit.signed_op, &key);
}

#[test]
fn grinds_contains_and_suffix() {
    let (hit, key) = grind(Mode::Contains, "zz");
    assert!(hit.did["did:plc:".len()..].contains("zz"), "{}", hit.did);
    verify_with_libsecp256k1(&hit.signed_op, &key);

    let (hit, key) = grind(Mode::Suffix, "7");
    assert!(hit.did.ends_with('7'), "{}", hit.did);
    verify_with_libsecp256k1(&hit.signed_op, &key);
}

#[test]
fn grinds_on_many_threads_with_every_nonce_mode() {
    for nonce in NonceMode::ALL {
        let (hit, key) = grind_with(4, nonce, Mode::Prefix, "abc");
        assert!(hit.did.starts_with("did:plc:abc"), "{nonce}: {}", hit.did);
        assert_eq!(op::did_for(&hit.signed_op).unwrap(), hit.did);
        verify_with_libsecp256k1(&hit.signed_op, &key);
    }
}

#[test]
fn reports_alternatives_until_the_target() {
    // "ab" as a prefix: about 1 in 1024 attempts; "ab" elsewhere about 22 times as often.
    let (job, key) = job(Mode::Prefix, "ab");
    let grinder = Grinder::new(job).unwrap().with_alternatives(3);
    let mut alternatives = Vec::new();
    let outcome = grinder
        .run(2, NonceMode::Incremental, Limits::default(), Duration::MAX, |_, _| {}, |hit| {
            alternatives.push(hit);
            Ok(())
        })
        .unwrap();
    let hit = outcome.hit.unwrap();
    assert!(hit.did.starts_with("did:plc:ab") && hit.position.is_none());

    for position in Position::ALL {
        assert!(alternatives.iter().filter(|a| a.position == Some(position)).count() <= 3, "{position:?} over the cap");
    }
    for alt in &alternatives {
        let id = alt.did.trim_start_matches("did:plc:");
        let expected = if id.starts_with("ab") {
            unreachable!("a prefix match is the target, not an alternative: {id}")
        } else if id.ends_with("ab") {
            Position::End
        } else {
            assert!(id.contains("ab"), "{id}");
            Position::Middle
        };
        assert_eq!(alt.position, Some(expected), "{id}");
        assert_eq!(op::did_for(&alt.signed_op).unwrap(), alt.did);
        verify_with_libsecp256k1(&alt.signed_op, &key);
    }
}

#[test]
fn contains_has_no_alternatives() {
    let (job, _) = job(Mode::Contains, "ab");
    let mut count = 0;
    Grinder::new(job)
        .unwrap()
        .with_alternatives(3)
        .run(2, NonceMode::Incremental, Limits::default(), Duration::MAX, |_, _| {}, |_| {
            count += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(count, 0);
}

/// Backtracking reference for glob matching, independent of the leftmost-first one.
fn glob_reference(pattern: &[u8], id: &[u8]) -> bool {
    fn here(p: &[u8], s: &[u8], end: bool) -> bool {
        match p.split_first() {
            None => !end || s.is_empty(),
            Some((b'*', rest)) => (0..=s.len()).any(|i| here(rest, &s[i..], end)),
            Some((b'_', rest)) => !s.is_empty() && here(rest, &s[1..], end),
            Some((c, rest)) => s.first() == Some(c) && here(rest, &s[1..], end),
        }
    }
    let (start, p) = pattern.strip_prefix(b"^").map_or((false, pattern), |p| (true, p));
    let (end, p) = p.strip_suffix(b"$").map_or((false, p), |p| (true, p));
    if start { here(p, id, end) } else { (0..=id.len()).any(|i| here(p, &id[i..], end)) }
}

fn glob(value: &str) -> Rule {
    Rule { mode: Mode::Glob, value: value.into() }
}

#[test]
fn glob_matching() {
    let id = b"gayxxgayxxxxxxxxxxgayxxx";
    for (pattern, expected) in [
        ("gay*gay*gay", true),
        ("^gay*gay*gay", true),
        ("gay*gay*gay$", false),
        ("^gay*gay*gayxxx$", true),
        ("gay*gay*gay*gay", false),
        ("xgay*xgay", true),
        ("^xgay", false),
        ("gayx*", true),
        ("*xxx$", true),
        ("^*gay*$", true),
        ("gaygay", false),
        ("^gayxxgayxxxxxxxxxxgayxxx$", true),
        ("gay__gay", true),
        ("gay_gay", false),
        ("^___xxgay", true),
        ("gay___$", true),
        ("gay____$", false),
        ("^_______________________x$", true),
    ] {
        assert_eq!(glob(pattern).matches(id), expected, "{pattern}");
        assert_eq!(glob_reference(pattern.as_bytes(), id), expected, "reference: {pattern}");
    }
}

#[test]
fn glob_agrees_with_a_backtracking_matcher() {
    // Small alphabet so segments repeat and overlap, which is where greedy matching could slip.
    let mut seed = 0x2545f4914f6cdd1du64;
    let mut next = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for _ in 0..200_000 {
        let id: Vec<u8> = (0..24).map(|_| b"ab"[next(2) as usize]).collect();
        let mut pattern = Vec::new();
        if next(3) == 0 {
            pattern.push(b'^');
        }
        for _ in 0..1 + next(7) {
            pattern.push(b"ab*_"[next(4) as usize]);
        }
        if next(3) == 0 {
            pattern.push(b'$');
        }
        let rule = glob(std::str::from_utf8(&pattern).unwrap());
        if rule.validate().is_err() {
            continue;
        }
        assert_eq!(rule.matches(&id), glob_reference(&pattern, &id), "{} on {}", rule.value, String::from_utf8_lossy(&id));
    }
}

#[test]
fn grinds_a_glob() {
    let (hit, key) = grind(Mode::Glob, "^a*b$");
    let id = &hit.did["did:plc:".len()..];
    assert!(id.starts_with('a') && id.ends_with('b'), "{id}");
    verify_with_libsecp256k1(&hit.signed_op, &key);

    let (hit, _) = grind(Mode::Glob, "a*b*c");
    assert!(glob_reference(b"a*b*c", &hit.did.as_bytes()["did:plc:".len()..]), "{}", hit.did);
}

#[test]
fn rejects_bad_globs() {
    for value in ["a^b", "a$b", "***", "^$", "^abc$", "a*1", "a?b", "__*_", "^________________________$"] {
        assert!(glob(value).validate().is_err(), "{value} should be rejected");
    }
    assert!(Rule { mode: Mode::Prefix, value: "a*b".into() }.validate().unwrap_err().to_string().contains("--mode glob"));
}

#[test]
fn stops_at_the_deadline() {
    let (job, _) = job(Mode::Prefix, &"a".repeat(24));
    let limits = Limits { deadline: Some(std::time::Instant::now() + Duration::from_millis(200)), ..Default::default() };
    let outcome = Grinder::new(job).unwrap().run(2, NonceMode::Incremental, limits, Duration::MAX, |_, _| {}, |_| Ok(())).unwrap();
    assert!(outcome.hit.is_none());
    assert!(outcome.attempts > 0);
    assert!(outcome.elapsed < Duration::from_secs(2));
}

#[test]
fn rejects_impossible_characters() {
    for value in ["alice0", "abc1", "8", "ABC", ""] {
        assert!(Grinder::new(job(Mode::Prefix, value).0).is_err(), "{value} should be rejected");
    }
}

#[test]
fn rejects_a_key_outside_rotation_keys() {
    let (mut job, _) = job(Mode::Prefix, "a");
    job.signing_key = data_encoding::HEXLOWER.encode(&k256::ecdsa::SigningKey::random(&mut OsRng).to_bytes());
    assert!(Grinder::new(job).is_err());
}

#[test]
fn rejects_a_signed_op() {
    let (mut job, _) = job(Mode::Prefix, "a");
    job.operation["sig"] = Value::String("x".into());
    assert!(Grinder::new(job).is_err());
}
