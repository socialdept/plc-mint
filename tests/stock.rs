//! `stock` fills a JSON Lines file with DIDs that each have their own keys, and resumes.

use std::{collections::HashSet, path::Path, process::Command};

use plc_mint::{didkey, op};
use rand_core::OsRng;
use serde_json::Value;

fn stock(out: &Path, recovery: &str, count: usize) {
    let status = Command::new(env!("CARGO_BIN_EXE_plc-mint"))
        .args(["stock", "--value", "a", "--threads", "2", "--nonce", "incremental", "--recovery", recovery])
        .args(["--count", &count.to_string(), "--out"])
        .arg(out)
        .status()
        .unwrap();
    assert!(status.success());
}

fn lines(out: &Path) -> Vec<Value> {
    std::fs::read_to_string(out).unwrap().lines().map(|line| serde_json::from_str(line).unwrap()).collect()
}

#[test]
fn fills_resumes_and_never_shares_keys() {
    let dir = std::env::temp_dir().join(format!("plc-mint-stock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join("stock.jsonl");
    let _ = std::fs::remove_file(&out);
    let recovery = didkey::encode_k256(k256::ecdsa::SigningKey::random(&mut OsRng).verifying_key());

    stock(&out, &recovery, 3);
    assert_eq!(lines(&out).len(), 3);
    stock(&out, &recovery, 3);
    assert_eq!(lines(&out).len(), 3, "a full file is left alone");
    stock(&out, &recovery, 5);
    let entries = lines(&out);
    assert_eq!(entries.len(), 5, "a rerun tops the file up");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&out).unwrap().permissions().mode() & 0o777, 0o600);
    }

    let mut dids = HashSet::new();
    let mut grind_keys = HashSet::new();
    for entry in &entries {
        let signed = &entry["signedOp"];
        let did = entry["did"].as_str().unwrap();
        assert!(did.starts_with("did:plc:a"));
        assert_eq!(op::did_for(signed).unwrap(), did);
        assert_eq!(op::verify_genesis(signed).unwrap(), 1, "signed by the grind key");
        assert_eq!(signed["rotationKeys"][0], recovery.as_str());
        assert_eq!(signed["rotationKeys"][1], entry["keys"]["grind"]["didKey"]);
        assert_eq!(signed["verificationMethods"]["atproto"], entry["keys"]["tempSigning"]["didKey"]);
        assert!(entry["keys"]["recovery"].get("privateKey").is_none(), "a brought recovery key keeps no private half");
        assert!(dids.insert(did.to_owned()));
        assert!(grind_keys.insert(entry["keys"]["grind"]["privateKey"].as_str().unwrap().to_owned()));
    }

    std::fs::remove_dir_all(&dir).unwrap();
}
