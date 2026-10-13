//! Reproduce real DIDs from their genesis ops, byte for byte.

use plc_mint::{cbor, op};
use serde_json::Value;

fn fixtures() -> Vec<(String, Value)> {
    std::fs::read_dir("tests/fixtures")
        .unwrap()
        .map(|entry| {
            let fixture: Value = serde_json::from_str(&std::fs::read_to_string(entry.unwrap().path()).unwrap()).unwrap();
            (fixture["did"].as_str().unwrap().to_owned(), fixture["operation"].clone())
        })
        .collect()
}

#[test]
fn reproduces_real_dids() {
    let fixtures = fixtures();
    assert!(!fixtures.is_empty());
    for (did, operation) in fixtures {
        assert_eq!(op::did_for(&operation).unwrap(), did);
    }
}

#[test]
fn verifies_real_signatures() {
    for (did, operation) in fixtures() {
        op::verify_genesis(&operation).unwrap_or_else(|e| panic!("{did}: {e}"));
    }
}

#[test]
fn rejects_a_tampered_op() {
    let (_, mut operation) = fixtures().remove(0);
    operation["alsoKnownAs"][0] = Value::String("at://someone-else.bsky.social".into());
    assert!(op::verify_genesis(&operation).is_err());
}

#[test]
fn encoder_agrees_with_serde_ipld_dagcbor() {
    for (did, operation) in fixtures() {
        assert_eq!(cbor::encode(&operation).unwrap(), serde_ipld_dagcbor::to_vec(&operation).unwrap(), "{did}");
    }
}
