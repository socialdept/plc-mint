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
$B grind --job job.json --threads 10                 # stdout: the hit as JSON
$B bench --seconds 300 --threads 1,6,12              # sustained attempts/s per thread count
$B profile                                           # ns per stage of one attempt
$B verify signed-op.json                              # recompute DID + check signature
$B keygen                                             # fresh secp256k1 key pair
```

| Command | Purpose |
| --- | --- |
| `grind --job <file\|->` | Grind until the DID matches. `--threads N` (default: all logical CPUs), `--max-attempts N` gives up with exit code 2. Progress goes to stderr. |
| `bench` | Grinds a never-matching job for `--seconds` at each of `--threads 1,6,12`, one JSON line per run: `{threads, seconds, attempts, rate, ratePerThread}`. |
| `profile` | Times each stage of an attempt in isolation (signing, `k*G`, inversion, RNG, base64url, SHA-256, base32 + match). |
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

Phases 1 and 2 done. Phase 3 in progress: the grinder runs one worker per thread (no shared state beyond a stop flag and an attempt counter), with `bench` and `profile` for measurement. Each attempt signs with a fresh RFC 6979 + OS-entropy nonce. Measured on the i7-9750H home server (6 cores / 12 threads), `nice -n 19`, sharing the box with Herd's queue workers (~2 cores busy), 5 minutes per run:

| Threads | Attempts/s | Per thread |
| --- | --- | --- |
| 6 | 50,197 | 8,366 |
| 10 | 57,919 | 5,792 |
| 12 | 57,767 | 4,814 |

10 threads is the sweet spot; hyperthreads past that add nothing. `profile` puts ~96% of an attempt in ECDSA signing and ~3.6% in SHA-256, so the next step is cheaper nonces, then incremental nonces.
