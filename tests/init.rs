//! `init` produces a job that grinds into a DID controlled by the keys it wrote.

use std::time::Duration;

use plc_mint::{
    didkey,
    grind::{Grinder, Job, Limits, Mode, Rule},
    init::init,
    op,
    signer::NonceMode,
};
use rand_core::OsRng;

fn rule(value: &str) -> Rule {
    Rule { mode: Mode::Prefix, value: value.into() }
}

#[test]
fn job_grinds_with_the_written_keys() {
    let init = init(&rule("a"), None).unwrap();
    let (job, keys) = (&init.job, &init.keys);
    let operation = &job["operation"];
    assert_eq!(operation["rotationKeys"][0], keys["recovery"]["didKey"]);
    assert_eq!(operation["rotationKeys"][1], keys["grind"]["didKey"]);
    assert_eq!(operation["verificationMethods"]["atproto"], keys["tempSigning"]["didKey"]);
    assert_eq!(job["signingKey"], keys["grind"]["privateKey"]);
    for name in ["recovery", "grind", "tempSigning"] {
        assert_eq!(keys[name]["privateKey"].as_str().unwrap().len(), 64, "{name}");
    }

    let job: Job = serde_json::from_value(init.job).unwrap();
    let outcome = Grinder::new(job)
        .unwrap()
        .run(2, NonceMode::Rfc6979, Limits::default(), Duration::from_secs(60), |_, _| {})
        .unwrap();
    let hit = outcome.hit.unwrap();
    assert!(hit.did.starts_with("did:plc:a"));
    assert_eq!(op::verify_genesis(&hit.signed_op).unwrap(), 1, "signed by the grind key");
}

#[test]
fn brought_recovery_key_keeps_no_private_half() {
    let recovery = didkey::encode_p256(p256::ecdsa::SigningKey::random(&mut OsRng).verifying_key());
    let init = init(&rule("ab"), Some(&recovery)).unwrap();
    assert_eq!(init.job["operation"]["rotationKeys"][0], recovery.as_str());
    assert_eq!(init.keys["recovery"], serde_json::json!({ "didKey": recovery }));
}

#[test]
fn rejects_bad_input() {
    assert!(init(&rule("a1"), None).is_err());
    assert!(init(&rule("a"), Some("did:key:nope")).is_err());
}
