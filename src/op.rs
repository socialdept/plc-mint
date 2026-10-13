//! did:plc operation hashing and verification.

use anyhow::{Context, Result, bail};
use data_encoding::{BASE64URL_NOPAD, Encoding};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{cbor, didkey::PublicKey};

/// Lowercase RFC 4648 base32, the alphabet of did:plc identifiers.
pub fn base32() -> Encoding {
    let mut spec = data_encoding::Specification::new();
    spec.symbols.push_str("abcdefghijklmnopqrstuvwxyz234567");
    spec.encoding().expect("valid base32 spec")
}

/// The 24-character identifier for a hash of a signed genesis op.
/// 24 base32 characters are exactly the first 15 bytes of the hash.
pub fn identifier(hash: &[u8]) -> String {
    base32().encode(&hash[..15])
}

pub fn did_for(signed_op: &Value) -> Result<String> {
    let hash = Sha256::digest(cbor::encode(signed_op)?);
    Ok(format!("did:plc:{}", identifier(&hash)))
}

/// DAG-CBOR of the op with its `sig` field removed: the bytes that get signed.
pub fn unsigned_bytes(op: &Value) -> Result<Vec<u8>> {
    let mut unsigned = op.as_object().context("operation must be an object")?.clone();
    unsigned.remove("sig");
    cbor::encode(&Value::Object(unsigned))
}

/// Checks a signed genesis op against its own rotation keys and returns the index
/// of the key that signed it.
pub fn verify_genesis(op: &Value) -> Result<usize> {
    if op["type"] != "plc_operation" || !op["prev"].is_null() {
        bail!("not a plc_operation genesis (type must be plc_operation, prev null)");
    }
    let sig = op["sig"].as_str().context("missing sig")?;
    let sig = BASE64URL_NOPAD.decode(sig.as_bytes()).context("sig is not base64url")?;
    let msg = unsigned_bytes(op)?;

    let keys = op["rotationKeys"].as_array().context("missing rotationKeys")?;
    for (i, key) in keys.iter().enumerate() {
        let key = PublicKey::parse(key.as_str().context("rotation key must be a string")?)?;
        if key.verify(&msg, &sig) {
            return Ok(i);
        }
    }
    bail!("signature does not verify against any rotation key")
}
