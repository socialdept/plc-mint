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
$B grind --job job.json --threads 10 --nonce random  # stdout: the hit as JSON
$B bench --seconds 300 --threads 10                  # sustained attempts/s, every nonce mode
$B profile                                           # ns per signature per nonce mode, and per hash check
$B verify signed-op.json                              # recompute DID + check signature
$B keygen                                             # fresh secp256k1 key pair
```

| Command | Purpose |
| --- | --- |
| `grind --job <file\|->` | Grind until the DID matches. `--threads N` (default: all logical CPUs), `--nonce MODE` (default `rfc6979`), `--max-attempts N` gives up with exit code 2. Progress goes to stderr. |
| `bench` | Grinds a never-matching job for `--seconds` at every combination of `--nonce a,b` (default: all) and `--threads 1,6,12`, one JSON line per run: `{nonce, threads, seconds, attempts, rate, ratePerThread}`. |
| `profile` | Single-threaded ns per signature for each nonce mode, ns per hash check, and the resulting attempts/s per thread. |
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

### Nonce modes

Every mode signs the same digest with the same key and yields valid, low-S signatures; they differ in how the nonce `k` is chosen.

| Mode | Nonce | Per signature |
| --- | --- | --- |
| `rfc6979` | RFC 6979 + OS entropy, via the library's standard signer | one full signing operation |
| `random` | Uniform from a per-thread ChaCha20 CSPRNG, via the library's low-level signing primitive | one `k*G` (precomputed table) + two inversions |
| `incremental` | `k = k0 + i` from a per-thread CSPRNG start | one point addition; affine conversion and `k^-1` batched over 256 signatures (Montgomery's trick) |

**`incremental` is only safe because exactly one signature per job is ever published.** Two published signatures with related nonces on the same message reveal the grind key. Losing signatures are never logged, stored or returned; a grind key must never be reused across jobs. It needs an ECDSA-literate review before production, which is why `grind` defaults to `rfc6979`.

### Correctness

Every hit is rebuilt from scratch (not from the hot-loop template), re-hashed and re-verified before it is printed. Tests (`cargo test`):

- **Golden:** reproduce real DIDs from their `plc.directory` genesis ops byte for byte and verify their signatures (`tests/fixtures/`).
- **Encoder:** the DAG-CBOR encoder agrees with `serde_ipld_dagcbor`.
- **Grind:** ground ops from every nonce mode verify under libsecp256k1, which shares no code with the RustCrypto signer and rejects high-S.
- **Signers:** every signature a signer emits, not just hits, verifies under libsecp256k1 and is unique, across batch boundaries; separate signers never share nonces.

### End to end

`e2e/` is a Bun script that takes a ground genesis through the whole account lifecycle against a local PLC directory and a stock PDS (`socialdept/atp-testnet`: PLC on `:7100`, `bluesky-social/pds:0.4` on `:7102`). Signing, DAG-CBOR and CIDs there use independent JS libraries (`@noble/curves`, `@ipld/dag-cbor`, `multiformats`), so they cross-check plc-mint too.

```sh
cargo build --release
cd e2e && bun install && bun run e2e.ts [prefix]   # PLC_URL / PDS_URL override the defaults
```

1. Generate a P-256 customer recovery key, a k256 grind key and a k256 temp signing key.
2. Grind a genesis (`rotationKeys: [recovery, grind]`, temp signing key, neutral handle) with `--nonce incremental`; re-derive the DID and verify the signature in JS.
3. Submit the genesis to PLC.
4. Import the DID into the PDS: `createAccount` with `did`, authorized by a service-auth JWT (`aud` = PDS DID, `lxm` = `createAccount`) signed by the **temp signing key**. The account starts deactivated.
5. `getRecommendedDidCredentials`, then a PLC update signed by the grind key: `rotationKeys: [recovery, grind, PDS key]`, the PDS signing key, handle and endpoint.
6. `activateAccount`, post, read the post back.
7. `updateHandle` through the PDS, which signs that PLC op with its own rotation key.
8. Drop the grind key (op signed by the grind key). A later op signed by the grind key is rejected with `Invalid signature on op`; one signed by the P-256 recovery key is accepted.
9. Five ops in the log, genesis still hashes to the DID, account active with a valid DID, can still post.

## Status

Phases 1–4 done, except the migration to a second PDS: the end-to-end test passes against a stock PDS. Phase 3 benchmarks:

Measured on the i7-9750H home server (6 cores / 12 threads), `nice -n 19`, sharing the box with Herd's queue workers (~2 cores busy), 5 minutes per run.

Thread scaling (`rfc6979`):

| Threads | Attempts/s | Per thread |
| --- | --- | --- |
| 6 | 50,197 | 8,366 |
| 10 | 57,919 | 5,792 |
| 12 | 57,767 | 4,814 |

Nonce modes at 10 threads:

| Mode | Attempts/s | vs `rfc6979` |
| --- | --- | --- |
| `rfc6979` | 62,286 | 1x |
| `random` | 71,495 | 1.15x |
| `incremental` | 1,088,388 | 17.5x |

Apple M1 Pro/Max (8 performance + 2 efficiency cores), `incremental`, 60 s runs:

| SHA-256 | Threads | Attempts/s | Per thread |
| --- | --- | --- | --- |
| software | 4 | 1,769,013 | 442,253 |
| software | 8 | 3,383,728 | 422,966 |
| ARMv8 (`asm`) | 8 | 7,513,453 | 939,182 |
| ARMv8 (`asm`) | 10 | 7,573,996 | 757,400 |

Hardware SHA-256 cut the hash check from 1,557 ns to 297 ns; an attempt is now ~1 µs, ~70% of it signing. The efficiency cores add ~1%.

On the home server, 10 threads is the sweet spot. With `incremental`, signing is ~1 µs and SHA-256 of the 465-byte template (~2.6 µs, no SHA-NI on this CPU) is now ~70% of an attempt. The signature sits in the first block, so no midstate can be reused; multi-buffer AVX2 SHA-256 is the next lever.
