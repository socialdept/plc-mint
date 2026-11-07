# Nonce modes

Part of the [plc-mint docs](../introduction.md#documentation). How each mode picks the ECDSA nonce, what it costs, and why `incremental` is safe only here.

Every mode signs the same digest with the same key and yields valid, low-S signatures. They differ in how the nonce `k` is chosen. Pick one with `--nonce` on `grind` and `mint`.

| Mode | Nonce | Per signature |
| --- | --- | --- |
| `rfc6979` | RFC 6979 + OS entropy, via the library's standard signer | one full signing operation |
| `random` | Uniform from a per-thread ChaCha20 CSPRNG, via the library's low-level signing primitive | one `k*G` (precomputed table) + two inversions |
| `incremental` | `k = k0 + i` from a per-thread CSPRNG start | one point addition, with affine conversion and `k^-1` batched over 256 signatures (Montgomery's trick) |

`rfc6979` is the default.

> [!WARNING]
> **`incremental` is only safe because exactly one signature per job is ever published.** Two published signatures with related nonces on the same message reveal the grind key. Losing signatures are never logged, stored or returned. A grind key must never be reused across jobs: `init` makes a fresh one every time, and `plc-claim` drops it from the DID. It needs an ECDSA-literate review before production, which is why `grind` defaults to `rfc6979`.

The same reasoning is why `plc-claim` publishes only [one DID per job](../getting-started/minting.md#claim-only-one-did-per-job).
