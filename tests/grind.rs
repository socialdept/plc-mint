//! Phase 2 gate: grind a match and have a second library verify the result.

use std::time::Duration;

use plc_mint::{
    didkey,
    grind::{Grinder, Hit, Job},
    op,
};
use rand_core::OsRng;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn job(mode: &str, value: &str) -> (Job, k256::ecdsa::SigningKey) {
    let grind = k256::ecdsa::SigningKey::random(&mut OsRng);
    let recovery = p256::ecdsa::SigningKey::random(&mut OsRng);
    let job = json!({
        "operation": {
            "type": "plc_operation",
            "rotationKeys": [
                didkey::encode_p256(recovery.verifying_key()),
                didkey::encode_k256(grind.verifying_key()),
            ],
            "verificationMethods": { "atproto": didkey::encode_k256(k256::ecdsa::SigningKey::random(&mut OsRng).verifying_key()) },
            "alsoKnownAs": ["at://pending.example.com"],
            "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://pds.example.com" } },
            "prev": null,
        },
        "signingKey": data_encoding::HEXLOWER.encode(&grind.to_bytes()),
        "match": { "mode": mode, "value": value },
    });
    (serde_json::from_value(job).unwrap(), grind)
}

fn grind(mode: &str, value: &str) -> (Hit, k256::ecdsa::SigningKey) {
    let (job, key) = job(mode, value);
    let hit = Grinder::new(job).unwrap().run(Some(5_000_000), Duration::MAX, |_, _| {}).unwrap().expect("no hit");
    (hit, key)
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
    let (hit, key) = grind("prefix", "ab");
    assert!(hit.did.starts_with("did:plc:ab"), "{}", hit.did);
    assert_eq!(op::did_for(&hit.signed_op).unwrap(), hit.did);
    assert_eq!(serde_ipld_dagcbor::to_vec(&hit.signed_op).unwrap(), plc_mint::cbor::encode(&hit.signed_op).unwrap());
    verify_with_libsecp256k1(&hit.signed_op, &key);
}

#[test]
fn grinds_contains_and_suffix() {
    let (hit, key) = grind("contains", "zz");
    assert!(hit.did["did:plc:".len()..].contains("zz"), "{}", hit.did);
    verify_with_libsecp256k1(&hit.signed_op, &key);

    let (hit, key) = grind("suffix", "7");
    assert!(hit.did.ends_with('7'), "{}", hit.did);
    verify_with_libsecp256k1(&hit.signed_op, &key);
}

#[test]
fn rejects_impossible_characters() {
    for value in ["miguel0", "abc1", "8", "ABC", ""] {
        assert!(Grinder::new(job("prefix", value).0).is_err(), "{value} should be rejected");
    }
}

#[test]
fn rejects_a_key_outside_rotation_keys() {
    let (mut job, _) = job("prefix", "a");
    job.signing_key = data_encoding::HEXLOWER.encode(&k256::ecdsa::SigningKey::random(&mut OsRng).to_bytes());
    assert!(Grinder::new(job).is_err());
}

#[test]
fn rejects_a_signed_op() {
    let (mut job, _) = job("prefix", "a");
    job.operation["sig"] = Value::String("x".into());
    assert!(Grinder::new(job).is_err());
}
