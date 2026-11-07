# Claiming

Part of the [plc-mint docs](../introduction.md#documentation). Publishing the DID and importing it into a PDS, and what to keep afterwards.

## Claiming a DID

Pick the PDS that will host the account and a handle on one of its domains. To use your own domain as the handle, point it at the DID first, with a `_atproto.<domain>` TXT record `did=<did>` or with `https://<domain>/.well-known/atproto-did`. The DID is known as soon as grinding finishes.

```sh
bun claim/plc-claim.ts --hit alice/hit.json --keys alice/keys.json \
  --pds https://pds.example.com --handle alice.pds.example.com --email you@example.com \
  --dry-run          # checks everything, changes nothing, drop it to run for real
```

1. Checks that the hit hashes to its DID and is signed by your grind key, that the keys match the genesis, that the PDS is reachable, and that invite and handle requirements are met. Nothing is published until these pass.
2. Asks for confirmation, then publishes the genesis to `plc.directory`. **This is permanent**: the DID exists from now on, controlled by your keys. Pass `--yes` to skip the question, which is required when stdin is not a terminal.
3. Creates the account with the existing DID, authorized by a service-auth token signed by the temp signing key. It starts deactivated.
4. Asks the PDS for its signing key, rotation key, handle and endpoint, and installs them with a PLC update signed by the grind key. The grind key is dropped in the same update (`--keep-grind-key` keeps it). Rotation keys end up as `[your recovery key, the PDS's key]`.
5. Activates the account and confirms the PDS sees a valid DID.

At the end it prints `{did, handle, pds, rotationKeys}` as JSON on stdout.

The account password comes from `$PDS_PASSWORD`. Without it, a random one is generated and printed. Every step checks what is already done, so after a failure (email rejected, network error), fix the cause and run the same command again. Set `$PDS_PASSWORD` if the account was already created. `--plc <url>` (or `$PLC_URL`) points at another PLC directory.

Tested against a stock self-hosted PDS (`bluesky-social/pds` 0.4). Bluesky's own `bsky.social` runs an entryway with a different import path and is untested.

## After claiming

- Keep `keys.json`, or at least the recovery key. It can rotate keys, change PDS or rescue the account even if the PDS disappears.
- The grind and temp signing keys have no power left and can be deleted. Neither is a rotation key after the claim, and the [end-to-end test](../internals/testing.md#end-to-end) checks that PLC rejects an operation signed by the grind key.
- Never reuse a `job.json` or grind key for a second DID. Run `init` again.
