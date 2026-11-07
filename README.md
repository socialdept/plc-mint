# plc-mint

Grind vanity `did:plc` identifiers, then claim them as a new account on a PDS.

plc-mint is two tools. `plc-mint`, in Rust, creates keys and a genesis operation, then re-signs it on your CPU or Apple GPU until the resulting DID matches a pattern, such as `did:plc:alice…`. `plc-claim`, in Bun, publishes the winning genesis to the PLC directory and imports the DID into a PDS as a new account. To learn all about it, head over to [the documentation](https://socialde.pt/docs/plc-mint).

Here are a few short examples of what you can do. Create keys and grind a DID that starts with `alice`, in one go:

```sh
plc-mint mint --mode prefix --value alice --out ./alice --gpu   # or --nonce incremental on a CPU
```

Measure how fast your machine grinds:

```sh
plc-mint bench --nonce incremental --seconds 20
```

Check that the claim would work, without changing anything:

```sh
bun claim/plc-claim.ts --hit alice/hit.json --keys alice/keys.json \
  --pds https://pds.example.com --handle alice.pds.example.com --email you@example.com \
  --dry-run
```

Recompute the DID of a signed genesis operation and check its signature:

```sh
plc-mint verify signed-op.json
```

## Documentation

You'll find the documentation on [https://socialde.pt/docs/plc-mint](https://socialde.pt/docs/plc-mint).

Find yourself stuck using it? Found a bug? Do you have general questions or suggestions for improving it? Feel free to [create an issue on GitHub](https://github.com/socialdept/plc-mint/issues).

## License

The MIT License (MIT). Please see [LICENSE](LICENSE) for more information.
