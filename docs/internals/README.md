# Internals

Part of the [plc-mint docs](../introduction.md#documentation).

- **[Nonce modes](nonce-modes.md)**: How each mode picks the ECDSA nonce, what it costs, and why `incremental` is safe only here.
- **[GPU](gpu.md)**: The Metal kernel, its self-test, the C++ reference build, batch sizes and the kernel arithmetic.
- **[Testing](testing.md)**: How hits are checked, the Rust test suites, and the end-to-end test against a local PLC and PDS.
- **[Benchmarks](benchmarks.md)**: Measured attempts per second by thread count, nonce mode and SHA-256 implementation.
