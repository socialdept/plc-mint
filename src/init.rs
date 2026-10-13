//! A real job: fresh keys plus a genesis op ready to grind and later claim.

use anyhow::{Result, ensure};
use data_encoding::HEXLOWER;
use rand_core::OsRng;
use serde_json::{Value, json};

use crate::{didkey, grind::Rule};

/// Placeholders for the genesis op. The identifier is fixed at genesis, so the op
/// keeps no real handle or PDS (they would stay in the PLC log forever); `plc-claim`
/// installs the real ones in the next op.
pub const PENDING_HANDLE: &str = "at://handle.invalid";
pub const PENDING_PDS: &str = "https://pds.invalid";

pub struct Init {
    pub job: Value,
    pub keys: Value,
}

/// Generates the grind key and the temp signing key, and a k256 recovery key unless
/// `recovery` brings one (a `did:key`, k256 or P-256, whose private half stays with
/// its owner). Rotation keys: recovery first, so it outranks every other key.
pub fn init(rule: &Rule, recovery: Option<&str>) -> Result<Init> {
    rule.validate()?;
    let recovery = match recovery {
        Some(did_key) => {
            didkey::PublicKey::parse(did_key)?;
            json!({ "didKey": did_key })
        }
        None => keypair(),
    };
    let grind = keypair();
    let temp_signing = keypair();
    ensure!(recovery["didKey"] != grind["didKey"], "recovery key equals the grind key");

    let job = json!({
        "operation": {
            "type": "plc_operation",
            "rotationKeys": [recovery["didKey"], grind["didKey"]],
            "verificationMethods": { "atproto": temp_signing["didKey"] },
            "alsoKnownAs": [PENDING_HANDLE],
            "services": {
                "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": PENDING_PDS }
            },
            "prev": null,
        },
        "signingKey": grind["privateKey"],
        "match": rule,
    });
    let keys = json!({
        "note": "Keep this file secret. recovery controls the DID forever; grind and tempSigning are only needed until plc-claim finishes.",
        "recovery": recovery,
        "grind": grind,
        "tempSigning": temp_signing,
    });
    Ok(Init { job, keys })
}

fn keypair() -> Value {
    let key = k256::ecdsa::SigningKey::random(&mut OsRng);
    json!({
        "didKey": didkey::encode_k256(key.verifying_key()),
        "privateKey": HEXLOWER.encode(&key.to_bytes()),
    })
}
