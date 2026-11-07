# Minting

Part of the [plc-mint docs](../introduction.md#documentation). Picking a pattern, how long it takes, creating keys and a job, grinding, and alternatives.

## Picking a pattern

Patterns use `a-z` and `2-7` only (no `0`, `1`, `8`, `9`), up to 24 characters. `prefix` and `suffix` cost the same. `contains` is cheaper because the string can sit at any of the 24 positions. The time to a hit is random, so these are averages. About 1 run in 20 takes 3 times longer, and restarting doesn't help.

| Length | Prefix / suffix attempts | Intel i7-9750H, 10 threads (~1M/s) | M1 Max CPU (~7.5M/s) | M1 Max GPU (~16M/s) |
| --- | --- | --- | --- | --- |
| 4 | 1.0M | 1 s | instant | instant |
| 5 | 34M | 34 s | 4.5 s | 2 s |
| 6 | 1.1B | 18 min | 2.4 min | 67 s |
| 7 | 34B | 9.5 h | 76 min | 36 min |
| 8 | 1.1T | 13 days | 41 h | 19 h |

`contains` divides these by roughly `25 - length` (about 19 times for 6 characters). The rates are measured, see [Benchmarks](../internals/benchmarks.md). Measure your own machine with `plc-mint bench --nonce incremental --seconds 20`, or `plc-mint bench --gpu --seconds 20`.

## Minting in one go

```sh
plc-mint mint --mode prefix --value alice --out ./alice --gpu   # or --nonce incremental on a CPU
```

`mint` is `init` followed by `grind`. It writes `keys.json` and `job.json` first, then `hit.json` once it finds a match, and prints the DID. It takes the options of both. If you stop it midway, `plc-mint grind --job alice/job.json > alice/hit.json` picks up the same job. That is a fresh search, and the odds don't depend on how long it already ran.

### Alternatives while you wait

For a prefix or suffix, `mint` also saves DIDs where the value lands somewhere else, as they turn up:

```
alternative (middle): did:plc:eua3ole6ialicequps5abcd2  -> ./alice/alternatives/eua3ole6ialicequps5abcd2.json
```

Positions are `start`, `end` and `middle`. The value is 15 to 20 times more likely to turn up in the middle than at a given end, so the first few arrive long before the target. Up to `--alternatives N` are kept per position (default 10, `0` turns it off). If the wait gets too long, stop the grind (Ctrl-C) and [claim](claiming.md) an alternative instead, passing `--hit alice/alternatives/<id>.json` to `plc-claim`.

### Claim only one DID per job

The hit and all its alternatives share the job's keys and are signed by the same grind key with related nonces. Two of them in public would reveal that key. `plc-claim` refuses to publish one when another from the same job (`hit.json` or `alternatives/` next to `keys.json`) is already on PLC. To get a second DID, run `mint` again.

## The two steps separately

### Create keys and a job

```sh
plc-mint init --mode prefix --value alice --out ./alice
```

This writes two files, readable only by you, and never overwrites existing ones:

- `job.json`: the genesis operation to grind. Its rotation keys are the recovery key, then the grind key. It has a temporary signing key, the placeholder handle `handle.invalid` and the placeholder PDS `pds.invalid`, because whatever the genesis says stays in the PLC log forever.
- `keys.json`: three private keys. **The recovery key controls the DID for good**. It outranks every other key, including the PDS's. Back it up. The grind and temp signing keys are only needed until the claim finishes.

To keep the recovery key off this machine entirely, bring your own with `--recovery did:key:…` (k256 or P-256). `keys.json` then holds only its public half.

### Grind

```sh
plc-mint grind --job alice/job.json --nonce incremental > alice/hit.json   # CPU
plc-mint grind --job alice/job.json --gpu > alice/hit.json                 # Apple Silicon GPU
```

Progress and, at the end, the found DID go to stderr. The hit (`{did, signedOp, attempts, elapsedMs, rate}`) goes to stdout. Every hit is rebuilt and re-verified from scratch before it is printed. `--nonce incremental` is about 17 times faster than the conservative default, `rfc6979`. See [Nonce modes](../internals/nonce-modes.md) for why it is safe here and what is still unreviewed. `--gpu` uses the same algorithm.

`grind` saves alternatives only when you pass `--save-alternatives DIR`.
