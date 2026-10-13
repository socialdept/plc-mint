# plc-mint

Grind vanity `did:plc` identifiers.

## What

A CLI that takes an unsigned did:plc genesis operation and a match rule, then re-signs it with fresh ECDSA nonces until the resulting DID matches (`did:plc:miguel…`). It outputs the signed operation, ready to submit to a PLC directory. Pure math: no network, no state.

## Why

A did:plc identifier is the first 24 base32 characters of the SHA-256 of the DAG-CBOR-encoded signed genesis operation. A chosen string can only be found by brute force, and each extra character costs 32x more work. Only the signature varies between attempts, so every key in the operation stays fixed and the private key of any other rotation key never touches the grinding machine.

## How

```sh
cargo build --release
B=./target/release/plc-mint

$B example-job --mode prefix --value mig > job.json   # throwaway keys, for testing
$B grind --job job.json --report-every 5              # stdout: the hit as JSON
$B verify signed-op.json                              # recompute DID + check signature
$B keygen                                             # fresh secp256k1 key pair
```

| Command | Purpose |
| --- | --- |
| `grind --job <file\|->` | Grind until the DID matches. `--max-attempts N` gives up with exit code 2. Progress goes to stderr. |
| `verify <file\|->` | Takes a signed op, or `{did, operation}` as in a `plc.directory/:did/log/audit` entry. Prints the DID, the signing rotation key and, if given, whether it matches the expected DID. |
| `keygen` | Prints `{privateKey (hex), didKey}` for secp256k1. |
| `example-job` | A job with fresh stand-in keys: P-256 recovery key, k256 grind key, k256 temp signing key. |

### Job format

```json
{
  "operation": {
    "type": "plc_operation",
    "rotationKeys": ["did:key:<recovery>", "did:key:<grind>"],
    "verificationMethods": { "atproto": "did:key:<temp signing>" },
    "alsoKnownAs": ["at://<neutral temp handle>"],
    "services": { "atproto_pds": { "type": "AtprotoPersonalDataServer", "endpoint": "https://<parking pds>" } },
    "prev": null
  },
  "signingKey": "<hex secp256k1 private key; its did:key must be in rotationKeys>",
  "match": { "mode": "prefix | contains | suffix", "value": "mig" }
}
```

Output: `{did, signedOp, attempts, elapsedMs, rate}`. The match value may only use `a-z` and `2-7`.

### Correctness

Every hit is rebuilt from scratch (not from the hot-loop template), re-hashed and re-verified before it is printed. Tests (`cargo test`):

- **Golden:** reproduce real DIDs from their `plc.directory` genesis ops byte for byte and verify their signatures (`tests/fixtures/`).
- **Encoder:** the DAG-CBOR encoder agrees with `serde_ipld_dagcbor`.
- **Grind:** ground ops verify under libsecp256k1, which shares no code with the RustCrypto signer and rejects high-S.

## Status

Single-threaded grinder works (phases 1 and 2). One thread signs with a fresh RFC 6979 + OS-entropy nonce per attempt, about **12.6k attempts/s** on the i7-9750H home server. Next: threads, then incremental nonces.
