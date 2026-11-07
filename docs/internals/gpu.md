# GPU

Part of the [plc-mint docs](../introduction.md#documentation). The Metal kernel, its self-test, the C++ reference build, batch sizes and the kernel arithmetic.

The GPU backend is a spike, for macOS through Metal.

## How it grinds

`gpu/kernel.metal` runs the [`incremental`](nonce-modes.md) algorithm on the GPU. Each GPU thread owns a nonce range (`k0 + t * 2^64`), walks `R_i = R_{i-1} + G`, batch-inverts point Z coordinates and nonces once per `--gpu-batch` attempts, then signs, hashes and matches on the GPU. Only the hit (and up to 16 alternatives per dispatch) comes back, and each goes through the same CPU rebuild-and-verify as every other hit. `gpu-selftest` checks every attempt's verdict (target, start, end, middle or miss) against the CPU.

```sh
cargo build --release --features gpu        # macOS only
B=target/release/plc-mint
$B gpu-selftest                             # debug dispatch: every GPU signature checked on the CPU
$B bench --gpu --seconds 60 [--gpu-batch 32] [--gpu-threads 16384]
$B grind --job job.json --gpu
```

## Testing the kernel anywhere

The same kernel source compiles as C++ (`gpu/cpu_ref.cpp`), so its math is tested on any machine. `cargo test --features gpu-ref` checks that every signature verifies, uses exactly nonce `k_thread + i`, and gets the CPU's match verdict, across dispatches. It also checks every field and scalar operation (multiply, square, add, subtract, inverse) against k256 on edge values and 3,000 random inputs each.

## Batch size

Apple M1 Max GPU, 65,536 threads, 20 s runs (after the arithmetic optimizations below):

| `--gpu-batch` | 16 | 32 | 64 | 128 | 256 |
| --- | --- | --- | --- | --- | --- |
| Attempts/s | 7.6M | 10.4M | **15.8M** | 12.5M | 14.3M |

Batch 64 is the default. Below it the per-batch inversions dominate, and above it per-thread memory does. The default for `--gpu-threads` is 65,536.

## Kernel arithmetic

- 8 x 32-bit limbs.
- A straight-line reduction specialized for p = 2^256 - 2^32 - 977.
- Dedicated squaring (36 partial products instead of 64).
- Field inversion by libsecp256k1's addition chain (255 squarings, 15 multiplications).
- Scalar inversion with a 4-bit window.
- SHA-256 schedules of the six constant blocks precomputed on the host.
