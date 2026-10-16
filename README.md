# plc-mint

Grind vanity `did:plc` identifiers, then claim them as a new account on a PDS.

## What

Two tools:

- **`plc-mint`** (Rust) creates keys and an unsigned did:plc genesis operation, then re-signs it with fresh ECDSA nonces until the resulting DID matches a pattern (`did:plc:alice…`). Pure math: no network, no state.
- **`plc-claim`** (Bun) publishes the winning genesis to the PLC directory and imports the DID into a PDS as a new account, then hands the DID's signing key and endpoint over to that PDS.

## Why

A did:plc identifier is the first 24 base32 characters of the SHA-256 of the DAG-CBOR-encoded signed genesis operation. A chosen string can only be found by brute force, and each extra character costs 32x more work. Only the signature varies between attempts, so every key in the operation stays fixed and the recovery key's private half never needs to touch the grinding machine.

A DID can't be changed on an existing account. A vanity DID is always a **new** account; move your data into it afterwards if you want (standard account migration tools work, since you hold the recovery key).

## Self-serve

### Install

Needs a Rust toolchain ([rustup](https://rustup.rs)) and, for claiming, [Bun](https://bun.sh).

```sh
cargo install --path .                    # puts plc-mint in ~/.cargo/bin
cargo install --path . --features gpu     # Apple Silicon: adds --gpu (needs Xcode command line tools)
(cd claim && bun install)                 # plc-claim's dependencies
```

### 1. Pick a pattern and check how long it takes

Patterns use `a-z` and `2-7` only (no `0`, `1`, `8`, `9`). `prefix` and `suffix` cost the same; `contains` is cheaper because the string can sit at any of the 24 positions. The time to a hit is random, so these are averages: about 1 run in 20 takes 3x longer, and restarting doesn't help.

| Length | Prefix / suffix attempts | Intel i7-9750H, 10 threads (~1M/s) | M1 Max CPU (~7.5M/s) | M1 Max GPU (~16M/s) |
| --- | --- | --- | --- | --- |
| 4 | 1.0M | 1 s | instant | instant |
| 5 | 34M | 34 s | 4.5 s | 2 s |
| 6 | 1.1B | 18 min | 2.4 min | 67 s |
| 7 | 34B | 9.5 h | 76 min | 36 min |
| 8 | 1.1T | 13 days | 41 h | 19 h |

`contains` divides these by roughly `25 - length` (about 19x for 6 characters).

**Globs** split a longer name into pieces that may land apart: `*` stands for any run of characters (including none), `_` for exactly one character, and the pattern may sit anywhere unless it starts with `^` or ends with `$`. Count only the letters for the row in the table (a `_` is free), then divide by the number of ways the pieces fit: `C(24 - width + k, k)`, where `width` is the letters plus `_`s and `k` is the number of pieces not pinned by `^` or `$`.

| Pattern | Letters | Divide by | M1 Max GPU |
| --- | --- | --- | --- |
| `gaygaygay` (prefix) | 9 | 1 | ~25 days |
| `^gay*gay*gay$` | 9 | `C(16, 1)` = 16 | ~1.6 days |
| `gay*gay*gay` | 9 | `C(18, 3)` = 816 | ~45 min |
| `gay__gay` | 6 | `C(17, 1)` = 17 | ~4 s |

Measure your own machine with `plc-mint bench --nonce incremental --seconds 20` (or `--gpu`).

### 2–3 in one go

```sh
plc-mint mint --mode prefix --value alice --out ./alice --gpu   # or --nonce incremental on a CPU
```

`mint` is `init` followed by `grind`: it writes `keys.json` and `job.json` first, then `hit.json` once it finds a match, and prints the DID. It takes the options of both. If you stop it midway, `plc-mint grind --job alice/job.json` picks up the same job (a fresh search; the odds don't depend on how long it already ran).

Any value with `*`, `_`, `^` or `$` is a glob, so `--mode glob` is optional: `plc-mint mint --value 'gay*gay*gay' --out ./gay --gpu` (quote it, or the shell expands the `*`).

**Alternatives while you wait.** For a prefix or suffix, `mint` also saves DIDs where the value lands somewhere else, as they turn up:

```
alternative (middle): did:plc:eua3ole6ialicequps5abcd2i  -> alice/alternatives/eua3ole6ialicequps5abcd2i.json
```

Positions are `start`, `end` and `middle`; the value is 15 to 20 times more likely to turn up in the middle than at a given end, so the first few arrive long before the target. Up to `--alternatives N` are kept per position (default 10, `0` turns it off). If the wait gets too long, stop the grind (Ctrl-C) and claim an alternative instead: `plc-claim --hit alice/alternatives/<id>.json …`.

**Claim only one DID per job.** The hit and all its alternatives share the job's keys and are signed by the same grind key with related nonces; two of them in public would reveal that key. `plc-claim` refuses to publish one when another from the same job (`hit.json` or `alternatives/` next to `keys.json`) is already on PLC. To get a second DID, run `mint` again.

The two steps separately:

### 2. Create keys and a job

```sh
plc-mint init --mode prefix --value alice --out ./alice
```

This writes two files, readable only by you, and never overwrites existing ones:

- `job.json`: the genesis operation to grind (rotation keys: recovery, then grind; a temporary signing key; placeholder handle `handle.invalid` and PDS `pds.invalid`, because whatever the genesis says stays in the PLC log forever).
- `keys.json`: three private keys. **The recovery key controls the DID for good**: it outranks every other key, including the PDS's. Back it up. The grind and temp signing keys are only needed until the claim finishes.

To keep the recovery key off this machine entirely, bring your own: `--recovery did:key:…` (k256 or P-256). `keys.json` then holds only its public half.

### 3. Grind

```sh
plc-mint grind --job alice/job.json --nonce incremental > alice/hit.json   # CPU
plc-mint grind --job alice/job.json --gpu > alice/hit.json                 # Apple Silicon GPU
```

Progress and, at the end, the found DID go to stderr; the hit (`{did, signedOp, attempts, elapsedMs, rate}`) goes to stdout. Every hit is rebuilt and re-verified from scratch before it is printed. `--nonce incremental` is 17x faster than the conservative default (see [Nonce modes](#nonce-modes) for why it is safe here and what is still unreviewed); `--gpu` uses the same algorithm.

### 4. Claim

Pick the PDS that will host the account and a handle on one of its domains. To use your own domain as the handle, point it at the DID first (`_atproto.<domain>` TXT record `did=<did>`, or `https://<domain>/.well-known/atproto-did`); the DID is known as soon as grinding finishes.

```sh
bun claim/plc-claim.ts --hit alice/hit.json --keys alice/keys.json \
  --pds https://pds.example.com --handle alice.pds.example.com --email you@example.com \
  --dry-run          # checks everything, changes nothing; drop it to run for real
```

1. Checks: the hit hashes to its DID and is signed by your grind key, the keys match the genesis, the PDS is reachable, invite and handle requirements are met. Nothing is published until these pass.
2. Asks for confirmation (or `--yes`), then publishes the genesis to `plc.directory`. **This is permanent**: the DID exists from now on, controlled by your keys.
3. Creates the account with the existing DID, authorized by a service-auth token signed by the temp signing key. It starts deactivated.
4. Asks the PDS for its signing key, rotation key, handle and endpoint, and installs them with a PLC update signed by the grind key. The grind key is dropped in the same update (`--keep-grind-key` keeps it). Rotation keys end up as `[your recovery key, the PDS's key]`.
5. Activates the account and confirms the PDS sees a valid DID.

The account password comes from `$PDS_PASSWORD`; without it, a random one is generated and printed once. Every step checks what is already done, so after a failure (email rejected, network error), fix the cause and run the same command again; set `$PDS_PASSWORD` if the account was already created. `--plc <url>` (or `$PLC_URL`) points at another PLC directory.

Tested against a stock self-hosted PDS (`bluesky-social/pds` 0.4). Bluesky's own `bsky.social` runs an entryway with a different import path and is untested.

### After claiming

- Keep `keys.json`, or at least the recovery key. It can rotate keys, change PDS or rescue the account even if the PDS disappears.
- The grind and temp signing keys have no power left (the e2e test checks this) and can be deleted.
- Never reuse a `job.json` or grind key for a second DID; run `init` again.

## Reference

```sh
plc-mint init --mode prefix --value mig --out DIR  # keys.json + job.json
plc-mint grind --job job.json --nonce incremental  # stdout: the hit as JSON
plc-mint mint --value mig --out DIR --gpu          # init + grind: keys.json, job.json, hit.json
plc-mint bench --seconds 300 --threads 10          # sustained attempts/s, every nonce mode
plc-mint profile                                   # ns per signature per nonce mode, and per hash check
plc-mint verify signed-op.json                     # recompute DID + check signature
plc-mint keygen                                    # fresh secp256k1 key pair
plc-mint example-job --mode prefix --value mig     # throwaway job for testing; its other keys are discarded
```

| Command | Purpose |
| --- | --- |
| `init [--mode] --value --out DIR [--recovery did:key]` | Writes `DIR/keys.json` and `DIR/job.json` (mode 0600, never overwritten). The value is lowercased and validated. `--mode` is `prefix`, `suffix`, `contains` or `glob`; without it, a value with `*`, `_`, `^` or `$` is a glob and anything else a prefix. |
| `grind --job <file\|->` | Grind until the DID matches. `--threads N` (default: all logical CPUs), `--nonce MODE` (default `rfc6979`), `--gpu`, `--max-attempts N` gives up with exit code 2, `--save-alternatives DIR` saves alternatives (up to `--alternatives N` per position). Progress goes to stderr. |
| `mint` | `init`, then `grind` on the new job; writes `DIR/hit.json` and prints the DID, saving alternatives to `DIR/alternatives/` as they turn up. Takes the options of both. |
| `bench` | Grinds a never-matching job for `--seconds` at every combination of `--nonce a,b` (default: all) and `--threads 1,6,12`, one JSON line per run: `{nonce, threads, seconds, attempts, rate, ratePerThread}`. |
| `profile` | Single-threaded ns per signature for each nonce mode, ns per hash check, and the resulting attempts/s per thread. |
| `verify <file\|->` | Takes a signed op, or `{did, operation}` as in a `plc.directory/:did/log/audit` entry. Prints the DID, the signing rotation key and, if given, whether it matches the expected DID. |
| `keygen` | Prints `{privateKey (hex), didKey}` for secp256k1. |
| `example-job` | A job with fresh stand-in keys: P-256 recovery key, k256 grind key, k256 temp signing key. Only the grind key is kept, so its DIDs can't be claimed. |

`plc-claim --help` lists its options: `--hit`, `--keys`, `--pds`, `--handle`, `--email` (required), `--invite`, `--plc`, `--keep-grind-key`, `--dry-run`, `--yes`.

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
  "match": { "mode": "prefix | contains | suffix | glob", "value": "mig" }
}
```

`init` writes this for you. Output: `{did, signedOp, attempts, elapsedMs, rate}`. The match value may only use `a-z` and `2-7`, plus `*`, `_` and a leading `^` or trailing `$` in a glob (24 characters at most in all).

### Nonce modes

Every mode signs the same digest with the same key and yields valid, low-S signatures; they differ in how the nonce `k` is chosen.

| Mode | Nonce | Per signature |
| --- | --- | --- |
| `rfc6979` | RFC 6979 + OS entropy, via the library's standard signer | one full signing operation |
| `random` | Uniform from a per-thread ChaCha20 CSPRNG, via the library's low-level signing primitive | one `k*G` (precomputed table) + two inversions |
| `incremental` | `k = k0 + i` from a per-thread CSPRNG start | one point addition; affine conversion and `k^-1` batched over 256 signatures (Montgomery's trick) |

**`incremental` is only safe because exactly one signature per job is ever published.** Two published signatures with related nonces on the same message reveal the grind key. Losing signatures are never logged, stored or returned; a grind key must never be reused across jobs (`init` makes a fresh one every time, and `plc-claim` drops it from the DID). It needs an ECDSA-literate review before production, which is why `grind` defaults to `rfc6979`.

### GPU (spike, macOS / Metal)

`gpu/kernel.metal` runs the `incremental` algorithm on the GPU: each GPU thread owns a nonce range (`k0 + t * 2^64`), walks `R_i = R_{i-1} + G`, batch-inverts point Z coordinates and nonces once per `--gpu-batch` attempts, then signs, hashes and matches on the GPU. Only the hit (and up to 16 alternatives per dispatch) comes back, and each goes through the same CPU rebuild-and-verify as every other hit. `gpu-selftest` checks every attempt's verdict (target, start, end, middle or miss) against the CPU.

```sh
cargo build --release --features gpu        # macOS only
$B gpu-selftest                             # debug dispatch: every GPU signature checked on the CPU
$B bench --gpu --seconds 60 [--gpu-batch 32] [--gpu-threads 16384]
$B grind --job job.json --gpu
```

The same kernel source compiles as C++ (`gpu/cpu_ref.cpp`), so its math is tested on any machine: `cargo test --features gpu-ref` checks that every signature verifies, uses exactly nonce `k_thread + i`, and gets the CPU's match verdict in every mode, globs included, across dispatches. It also checks every field and scalar operation (multiply, square, add, subtract, inverse) against k256 on edge values and 3,000 random inputs each.

Apple M1 Max GPU, 65,536 threads, 20 s runs (after the arithmetic optimizations below):

| `--gpu-batch` | 16 | 32 | 64 | 128 | 256 |
| --- | --- | --- | --- | --- | --- |
| Attempts/s | 7.6M | 10.4M | **15.8M** | 12.5M | 14.3M |

Batch 64 is the default: below it the per-batch inversions dominate, above it per-thread memory does.

Kernel arithmetic: 8 x 32-bit limbs; a straight-line reduction specialized for p = 2^256 - 2^32 - 977; dedicated squaring (36 partial products instead of 64); field inversion by libsecp256k1's addition chain (255 squarings, 15 multiplications); scalar inversion with a 4-bit window; SHA-256 schedules of the six constant blocks precomputed on the host.

### Correctness

Every hit is rebuilt from scratch (not from the hot-loop template), re-hashed and re-verified before it is printed. Tests (`cargo test`):

- **Golden:** reproduce real DIDs from their `plc.directory` genesis ops byte for byte and verify their signatures (`tests/fixtures/`).
- **Encoder:** the DAG-CBOR encoder agrees with `serde_ipld_dagcbor`.
- **Globs:** the leftmost-first matcher (also in the GPU kernel) agrees with a backtracking matcher on 200k random patterns and identifiers.
- **Grind:** ground ops from every nonce mode verify under libsecp256k1, which shares no code with the RustCrypto signer and rejects high-S.
- **Signers:** every signature a signer emits, not just hits, verifies under libsecp256k1 and is unique, across batch boundaries; separate signers never share nonces.

### End to end

`claim/e2e.ts` runs the self-serve flow through the real CLIs against a local PLC directory and a stock PDS (`socialdept/atp-testnet`: PLC on `:7100`, `bluesky-social/pds:0.4` on `:7102`). Signing, DAG-CBOR and CIDs in `claim/` use independent JS libraries (`@noble/curves`, `@ipld/dag-cbor`, `multiformats`), so they cross-check plc-mint too.

```sh
cargo build --release
cd claim && bun install && bun run e2e.ts [prefix]   # PLC_URL / PDS_URL override the defaults
```

1. `plc-mint init`, bringing a P-256 recovery key (as a browser-held key would be); `keys.json` keeps no private half for it.
2. `plc-mint grind --nonce incremental`; re-derive the DID and verify the signature in JS.
3. `plc-claim --dry-run` publishes nothing.
4. `plc-claim`: genesis published, account imported (service-auth JWT signed by the **temp signing key**, `aud` = PDS DID, `lxm` = `createAccount`), PDS credentials installed and the grind key dropped in one update signed by the grind key, account activated. Recovery key is the top rotation key.
5. Running `plc-claim` again is a no-op.
6. Log in with the password, post, read the post back.
7. `updateHandle` through the PDS, which signs that PLC op with its own rotation key.
8. An op signed by the grind key is rejected with `Invalid signature on op`; one signed by the P-256 recovery key is accepted.
9. Four ops in the log, genesis still hashes to the DID, account active with a valid DID.

## Status

**Viable.** Vanity DIDs ground with plc-mint have been claimed as working accounts on a real, stock self-hosted PDS (invite code, no admin access), resolve through plc.directory and show up in the Bluesky app; the end-to-end test covers the same flow locally. Open items: an independent review of the `incremental` nonce scheme, and Bluesky's `bsky.social` entryway as a claim target.

### Benchmarks

Intel i7-9750H (6 cores / 12 threads), `nice -n 19`, sharing the machine with other workloads (~2 cores busy), 5 minutes per run.

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

On the i7-9750H, 10 threads is the sweet spot. With `incremental`, signing is ~1 µs and SHA-256 of the 465-byte template (~2.6 µs, no SHA-NI on this CPU) is now ~70% of an attempt. The signature sits in the first block, so no midstate can be reused; multi-buffer AVX2 SHA-256 is the next lever.
