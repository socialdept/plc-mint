# Commands

Part of the [plc-mint docs](introduction.md#documentation). Every `plc-mint` subcommand and its options, the `plc-claim` options, and the job format.

## plc-mint

```sh
plc-mint init --mode prefix --value mig --out DIR  # keys.json + job.json
plc-mint grind --job job.json --nonce incremental  # stdout: the hit as JSON
plc-mint mint --value mig --out DIR --gpu          # init + grind: keys.json, job.json, hit.json
plc-mint bench --seconds 300 --threads 10          # sustained attempts/s, every nonce mode
plc-mint profile                                   # ns per signature per nonce mode, and per hash check
plc-mint verify signed-op.json                     # recompute DID + check signature
plc-mint keygen                                    # fresh secp256k1 key pair
plc-mint example-job --mode prefix --value mig     # throwaway job for testing, its other keys are discarded
plc-mint gpu-selftest                              # GPU builds: every GPU signature checked on the CPU
```

| Command | Purpose |
| --- | --- |
| `init --mode --value --out DIR [--recovery did:key]` | Writes `DIR/keys.json` and `DIR/job.json` (mode 0600, never overwritten). `--mode` is `prefix` (default), `contains` or `suffix`. The value is lowercased and validated. |
| `grind --job <file\|->` | Grind until the DID matches. `--threads N` (default: all logical CPUs), `--nonce MODE` (default `rfc6979`), `--gpu`, `--max-attempts N` gives up with exit code 2, `--save-alternatives DIR` saves alternatives (up to `--alternatives N` per position, default 10). Progress goes to stderr every `--report-every` seconds (default 5). |
| `mint` | `init`, then `grind` on the new job. Writes `DIR/hit.json` and prints the DID, saving alternatives to `DIR/alternatives/` as they turn up. Takes the options of both. Refuses to start if `DIR/hit.json` already exists. |
| `bench` | Grinds a never-matching job for `--seconds` (default 60) at every combination of `--nonce a,b` (default: all) and `--threads a,b` (such as `1,6,12`, default: all logical CPUs), one JSON line per run: `{nonce, threads, seconds, attempts, rate, ratePerThread}`. With `--gpu` it makes one GPU run instead: `{backend, batch, gpuThreads, seconds, attempts, rate}`. |
| `profile` | Single-threaded ns per signature for each nonce mode, ns per hash check, and the resulting attempts/s per thread. `--chunks N` sets the batches of 256 signatures timed per mode (default 40). |
| `verify <file\|->` | Takes a signed op, or `{did, operation}` as in a `plc.directory/:did/log/audit` entry. Prints the DID, the signing rotation key and, if given, whether it matches the expected DID. |
| `keygen` | Prints `{privateKey (hex), didKey}` for secp256k1. |
| `example-job` | A job with fresh stand-in keys: P-256 recovery key, k256 grind key, k256 temp signing key. Only the grind key is kept, so its DIDs can't be claimed. Defaults to `--mode prefix --value abc`. |
| `gpu-selftest` | Runs the GPU kernel in debug mode and checks every attempt on the CPU. `--chunks N` sets the chunks per thread per dispatch (default 1). See [GPU](internals/gpu.md). |

The GPU options, on `grind`, `mint`, `bench` and `gpu-selftest`: `--gpu` grinds on the GPU and ignores `--threads` and `--nonce`, `--gpu-batch N` sets the nonces per thread per batched inversion (default 64), and `--gpu-threads N` the threads per dispatch (default 65,536).

## plc-claim

`bun claim/plc-claim.ts --help` lists its options:

| Option | Purpose |
| --- | --- |
| `--hit <file>` | Output of `plc-mint grind`, or `hit.json` from `mint`. Required. |
| `--keys <file>` | `keys.json` from `plc-mint init`. Required. |
| `--pds <url>` | The PDS that will host the account. Required. |
| `--handle <handle>` | On one of the PDS's domains, or your own domain already pointing at the DID. Required. |
| `--email <email>` | Account email. Required. |
| `--invite <code>` | Invite code, if the PDS needs one. |
| `--plc <url>` | PLC directory (default: `https://plc.directory`, or `$PLC_URL`). |
| `--keep-grind-key` | Leave the grind key in `rotationKeys` (default: drop it). |
| `--dry-run` | Run the checks, change nothing. |
| `--yes` | Don't ask before publishing the DID. |

## Job format

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
  "signingKey": "<hex secp256k1 private key, whose did:key must be in rotationKeys>",
  "match": { "mode": "prefix | contains | suffix", "value": "mig" }
}
```

`init` writes this for you. The operation must be unsigned, with `prev: null` present, and the signed op may not exceed 7,500 bytes, the PLC directory's limit. The match value may only use `a-z` and `2-7`. Output: `{did, signedOp, attempts, elapsedMs, rate}`.
