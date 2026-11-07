# Introduction

**plc-mint** grinds vanity `did:plc` identifiers, then claims them as a new account on a PDS. It is two tools:

- **`plc-mint`** (Rust) creates keys and an unsigned `did:plc` genesis operation, then re-signs it with fresh ECDSA nonces until the resulting DID matches a pattern (`did:plc:alice…`). It runs on the CPU, or on an Apple GPU through Metal. Pure math: no network, no state.
- **`plc-claim`** (Bun) publishes the winning genesis to the PLC directory and imports the DID into a PDS as a new account, then hands the DID's signing key and endpoint over to that PDS.

## Why it works this way

A `did:plc` identifier is the first 24 base32 characters of the SHA-256 of the DAG-CBOR-encoded signed genesis operation. A chosen string can only be found by brute force, and each extra character costs 32 times more work. Only the signature varies between attempts, so every key in the operation stays fixed, and the recovery key's private half never needs to touch the grinding machine.

A DID can't be changed on an existing account. A vanity DID is always a **new** account. Move your data into it afterwards if you want. Standard account migration tools work, since you hold the recovery key.

## Status

**Viable.** Vanity DIDs ground with plc-mint have been claimed as working accounts on a real, stock self-hosted PDS (invite code, no admin access), resolve through plc.directory and show up in the Bluesky app. The [end-to-end test](internals/testing.md#end-to-end) covers the same flow locally. Open items: an independent review of the `incremental` [nonce scheme](internals/nonce-modes.md), and Bluesky's `bsky.social` entryway as a claim target.

## A first look

Create keys and grind a DID that starts with `alice`. `mint` writes `keys.json`, `job.json` and, once it finds a match, `hit.json`:

```sh
plc-mint mint --mode prefix --value alice --out ./alice --nonce incremental
```

Then claim it on the PDS that will host the account, with a dry run first:

```sh
bun claim/plc-claim.ts --hit alice/hit.json --keys alice/keys.json \
  --pds https://pds.example.com --handle alice.pds.example.com --email you@example.com \
  --dry-run
```

## Documentation

Start with [Installation](getting-started/installation.md), then [Minting](getting-started/minting.md) and [Claiming](getting-started/claiming.md) walk through the whole flow. The docs are grouped by area, and each group has an index of its own:

- **[Getting started](getting-started/README.md)**: [Installation](getting-started/installation.md), [Minting](getting-started/minting.md), [Claiming](getting-started/claiming.md)
- **[Commands](commands.md)**: Every `plc-mint` subcommand and its options, the `plc-claim` options, and the job format.
- **[Internals](internals/README.md)**: [Nonce modes](internals/nonce-modes.md), [GPU](internals/gpu.md), [Testing](internals/testing.md), [Benchmarks](internals/benchmarks.md)
