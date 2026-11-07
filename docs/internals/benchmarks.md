# Benchmarks

Part of the [plc-mint docs](../introduction.md#documentation). Measured attempts per second by thread count, nonce mode and SHA-256 implementation.

These are measurements from the machines named, not guarantees. Run `plc-mint bench` and `plc-mint profile` for your own, see [Commands](../commands.md).

## Intel i7-9750H

6 cores and 12 threads, `nice -n 19`, sharing the machine with other workloads (about 2 cores busy), 5 minutes per run.

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

On the i7-9750H, 10 threads is the sweet spot. With `incremental`, signing is about 1 µs and SHA-256 of the 465-byte template (about 2.6 µs, no SHA-NI on this CPU) is now about 70% of an attempt. The signature sits in the first block, so no midstate can be reused. Multi-buffer AVX2 SHA-256 is the next lever.

## Apple M1 Pro/Max

8 performance and 2 efficiency cores, `incremental`, 60 s runs:

| SHA-256 | Threads | Attempts/s | Per thread |
| --- | --- | --- | --- |
| software | 4 | 1,769,013 | 442,253 |
| software | 8 | 3,383,728 | 422,966 |
| ARMv8 (`asm`) | 8 | 7,513,453 | 939,182 |
| ARMv8 (`asm`) | 10 | 7,573,996 | 757,400 |

Hardware SHA-256 cut the hash check from 1,557 ns to 297 ns. An attempt is now about 1 µs, about 70% of it signing. The efficiency cores add about 1%. The `asm` feature of `sha2` is turned on for every `aarch64` build.

For the GPU, see [batch size](gpu.md#batch-size).
