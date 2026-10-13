# plc-mint

Grind vanity `did:plc` identifiers.

## What

A CLI that takes an unsigned did:plc genesis operation and a match rule, then re-signs it with fresh ECDSA nonces until the resulting DID matches (`did:plc:miguel…`). It outputs the signed operation, ready to submit to a PLC directory. Pure math: no network, no state.

## Why

A did:plc identifier is the first 24 base32 characters of the SHA-256 of the DAG-CBOR-encoded signed genesis operation. A chosen string can only be found by brute force, and each extra character costs 32x more work. Only the signature varies between attempts, so every key in the operation stays fixed and the private key of any other rotation key never touches the grinding machine.

## How

```sh
cargo run --release -- --job job.json --threads 10 --report-every 5s
cargo run --release -- --bench 300s
```

- **Input:** unsigned op fields, the signing (rotation) private key, and a match rule `{mode: prefix | contains | suffix, value}`.
- **Output:** `{did, signedOp, attempts, elapsedMs, rate}`.

Not implemented yet.

## Status

Bootstrapped. Phase 1 (spike and verify): reproduce a real DID byte for byte.
