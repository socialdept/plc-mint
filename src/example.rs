//! Throwaway jobs with fresh keys, for tests, demos and benchmarks.

use data_encoding::HEXLOWER;
use rand_core::OsRng;
use serde_json::{Value, json};

use crate::{didkey, grind::Rule};

/// A job shaped like a real one: P-256 customer recovery key first, then the k256
/// grind key, a k256 temp signing key, a neutral handle and a parking PDS. Only the
/// grind key's private half is kept (in `signingKey`).
pub fn job(rule: &Rule) -> Value {
    let recovery = p256::ecdsa::SigningKey::random(&mut OsRng);
    let grind = k256::ecdsa::SigningKey::random(&mut OsRng);
    let temp_signing = k256::ecdsa::SigningKey::random(&mut OsRng);
    json!({
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
        "match": rule,
    })
}
