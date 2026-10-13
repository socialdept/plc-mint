//! Every signature a signer produces must be valid and low-S, not just the hits.
//! Checked with libsecp256k1, which shares no code with the RustCrypto signers.

use std::collections::HashSet;

use k256::ecdsa::SigningKey;
use plc_mint::signer::{CHUNK, NonceMode, Signer};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

fn check_mode(mode: NonceMode, chunks: usize) {
    let key = SigningKey::random(&mut OsRng);
    let digest: [u8; 32] = Sha256::digest(b"plc-mint signer test").into();
    let pubkey = secp256k1::PublicKey::from_slice(&key.verifying_key().to_encoded_point(true).to_bytes()).unwrap();
    let msg = secp256k1::Message::from_digest(digest);

    let mut signer = Signer::new(mode, &key, digest);
    let mut sigs = [[0u8; 64]; CHUNK];
    let mut seen = HashSet::new();
    for _ in 0..chunks {
        signer.fill(&mut sigs).unwrap();
        for sig in &sigs {
            let parsed = secp256k1::ecdsa::Signature::from_compact(sig).unwrap();
            secp256k1::SECP256K1
                .verify_ecdsa(&msg, &parsed, &pubkey)
                .unwrap_or_else(|e| panic!("{mode}: libsecp256k1 rejected a signature: {e}"));
            assert!(seen.insert(*sig), "{mode}: repeated signature");
        }
    }
}

#[test]
fn rfc6979_signatures_verify() {
    check_mode(NonceMode::Rfc6979, 2);
}

#[test]
fn random_signatures_verify() {
    check_mode(NonceMode::Random, 4);
}

/// Several chunks, so the carry-over of `k` and `R` between batches is covered.
#[test]
fn incremental_signatures_verify() {
    check_mode(NonceMode::Incremental, 8);
}

/// Distinct signers (one per worker thread) must start from unrelated nonces.
#[test]
fn incremental_signers_do_not_share_nonces() {
    let key = SigningKey::random(&mut OsRng);
    let digest: [u8; 32] = Sha256::digest(b"plc-mint signer test").into();
    let (mut a, mut b) = (Signer::new(NonceMode::Incremental, &key, digest), Signer::new(NonceMode::Incremental, &key, digest));
    let (mut sa, mut sb) = ([[0u8; 64]; CHUNK], [[0u8; 64]; CHUNK]);
    a.fill(&mut sa).unwrap();
    b.fill(&mut sb).unwrap();
    // Same message and key: equal r would mean equal nonces.
    let ra: HashSet<_> = sa.iter().map(|s| s[..32].to_vec()).collect();
    assert!(sb.iter().all(|s| !ra.contains(&s[..32])));
}
