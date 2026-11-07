# Installation

Part of the [plc-mint docs](../introduction.md#documentation). What you need, and installing `plc-mint` and `plc-claim`.

## Requirements

`plc-mint` needs a Rust toolchain ([rustup](https://rustup.rs)). Claiming needs [Bun](https://bun.sh). The GPU backend is for Apple Silicon and needs the Xcode command line tools.

## Installing

From a checkout of the repo:

```sh
cargo install --path .                    # puts plc-mint in ~/.cargo/bin
cargo install --path . --features gpu     # Apple Silicon: adds --gpu (needs Xcode command line tools)
(cd claim && bun install)                 # plc-claim's dependencies
```

A build without the `gpu` feature still accepts `--gpu`, but stops with an error asking you to rebuild on macOS with `--features gpu`.

`plc-claim` is a script, so run it with Bun from the checkout: `bun claim/plc-claim.ts`.

## Configuration

Neither tool has a config file. `plc-mint` takes everything as options, and its jobs and keys live in the directory you give `--out`. `plc-claim` reads two environment variables:

- **`PDS_PASSWORD`**: the account password. Without it, a random one is generated and printed.
- **`PLC_URL`**: the PLC directory, when `--plc` is not given. The default is `https://plc.directory`.

See [Commands](../commands.md) for every option.
