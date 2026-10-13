//! Phase 2 gate: grind a match and have a second library verify the result.

use std::time::Duration;

use plc_mint::{
    example,
    grind::{Grinder, Hit, Job, Limits, Mode, Rule},
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
    let outcome = Grinder::new(job).unwrap().run(threads, nonce, limits, Duration::MAX, |_, _| {}).unwrap();
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
fn stops_at_the_deadline() {
    let (job, _) = job(Mode::Prefix, &"a".repeat(24));
    let limits = Limits { deadline: Some(std::time::Instant::now() + Duration::from_millis(200)), ..Default::default() };
    let outcome = Grinder::new(job).unwrap().run(2, NonceMode::Incremental, limits, Duration::MAX, |_, _| {}).unwrap();
    assert!(outcome.hit.is_none());
    assert!(outcome.attempts > 0);
    assert!(outcome.elapsed < Duration::from_secs(2));
}

#[test]
fn rejects_impossible_characters() {
    for value in ["miguel0", "abc1", "8", "ABC", ""] {
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
