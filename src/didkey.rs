//! `did:key` parsing and signature verification for the two curves PLC allows.

use anyhow::{Context, Result, bail};

const K256_CODEC: [u8; 2] = [0xe7, 0x01];
const P256_CODEC: [u8; 2] = [0x80, 0x24];

pub enum PublicKey {
    K256(k256::ecdsa::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

impl PublicKey {
    pub fn parse(did_key: &str) -> Result<Self> {
        let multibase = did_key.strip_prefix("did:key:z").context("not a base58btc did:key")?;
        let bytes = bs58::decode(multibase).into_vec().context("invalid base58")?;
        let (codec, point) = bytes.split_at_checked(2).context("did:key too short")?;

        match <[u8; 2]>::try_from(codec)? {
            K256_CODEC => Ok(Self::K256(k256::ecdsa::VerifyingKey::from_sec1_bytes(point)?)),
            P256_CODEC => Ok(Self::P256(p256::ecdsa::VerifyingKey::from_sec1_bytes(point)?)),
            other => bail!("unsupported did:key codec {other:02x?}"),
        }
    }

    /// Verifies an ECDSA-SHA256 `r || s` signature, rejecting high-S as PLC does.
    pub fn verify(&self, msg: &[u8], sig: &[u8]) -> bool {
        use k256::ecdsa::signature::Verifier;

        match self {
            Self::K256(key) => k256::ecdsa::Signature::from_slice(sig)
                .is_ok_and(|s| s.normalize_s().is_none() && key.verify(msg, &s).is_ok()),
            Self::P256(key) => p256::ecdsa::Signature::from_slice(sig)
                .is_ok_and(|s| s.normalize_s().is_none() && key.verify(msg, &s).is_ok()),
        }
    }
}

pub fn encode_k256(key: &k256::ecdsa::VerifyingKey) -> String {
    encode(K256_CODEC, &key.to_encoded_point(true).to_bytes())
}

pub fn encode_p256(key: &p256::ecdsa::VerifyingKey) -> String {
    encode(P256_CODEC, &key.to_encoded_point(true).to_bytes())
}

fn encode(codec: [u8; 2], point: &[u8]) -> String {
    let mut bytes = codec.to_vec();
    bytes.extend_from_slice(point);
    format!("did:key:z{}", bs58::encode(bytes).into_string())
}
