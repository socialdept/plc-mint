# Testing

Part of the [plc-mint docs](../introduction.md#documentation). How hits are checked, the Rust test suites, and the end-to-end test against a local PLC and PDS.

## Correctness

Every hit is rebuilt from scratch (not from the hot-loop template), re-hashed and re-verified before it is printed. The Rust tests run with `cargo test`:

- **Golden:** reproduce real DIDs from their `plc.directory` genesis ops byte for byte and verify their signatures (`tests/fixtures/`).
- **Encoder:** the DAG-CBOR encoder agrees with `serde_ipld_dagcbor`.
- **Grind:** ground ops from every nonce mode verify under libsecp256k1, which shares no code with the RustCrypto signer and rejects high-S.
- **Signers:** every signature a signer emits, not just hits, verifies under libsecp256k1 and is unique, across batch boundaries. Separate signers never share nonces.
- **Init:** a job from `init` grinds with the keys it wrote, a brought recovery key keeps no private half, and bad input is rejected.

`cargo test --features gpu-ref` adds the [GPU kernel tests](gpu.md#testing-the-kernel-anywhere).

## End to end

`claim/e2e.ts` runs the self-serve flow through the real CLIs against a local PLC directory and a stock PDS from [atp-testnet](https://github.com/socialdept/atp-testnet): PLC on `:7100`, `bluesky-social/pds:0.4` on `:7102`. Signing, DAG-CBOR and CIDs in `claim/` use independent JS libraries (`@noble/curves`, `@ipld/dag-cbor`, `multiformats`), so they cross-check plc-mint too.

```sh
cargo build --release
cd claim && bun install && bun run e2e.ts [prefix]   # PLC_URL / PDS_URL override the defaults
```

The prefix defaults to `e2e`. The test:

1. Runs `plc-mint init`, bringing a P-256 recovery key (as a browser-held key would be). `keys.json` keeps no private half for it.
2. Runs `plc-mint grind --nonce incremental --save-alternatives`, then re-derives the DID and verifies the signature in JS, for the hit and every alternative.
3. Runs `plc-claim --dry-run`, which publishes nothing.
4. Runs `plc-claim`: genesis published, account imported (service-auth JWT signed by the **temp signing key**, `aud` = PDS DID, `lxm` = `createAccount`), PDS credentials installed and the grind key dropped in one update signed by the grind key, account activated. The recovery key is the top rotation key.
5. Checks that `plc-claim` refuses an alternative from the same job, which never reaches PLC.
6. Runs `plc-claim` again, which is a no-op.
7. Logs in with the password, posts, and reads the post back.
8. Calls `updateHandle` through the PDS, which signs that PLC op with its own rotation key.
9. Checks that an op signed by the grind key is rejected by PLC as an invalid signature, and one signed by the P-256 recovery key is accepted.
10. Checks four ops in the log, that the genesis still hashes to the DID, and that the account is active with a valid DID.
