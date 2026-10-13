#!/usr/bin/env bun
// plc-claim: publish a ground did:plc and import it into a PDS as a new account.
//
//   plc-claim --hit hit.json --keys keys.json --pds https://pds.example.com \
//             --handle alice.example.com --email alice@example.com [--invite CODE]
//
// Every step checks what is already done, so re-running after a failure resumes.

import { existsSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { parseArgs } from 'node:util'
import { randomBytes, bytesToHex } from '@noble/hashes/utils'
import { HttpError, cidOf, didOf, hex, opSignedBy, pdsClient, plcClient, secp256k1, serviceAuth, signOp, type Op } from './lib'

const USAGE = `usage: plc-claim --hit <file> --keys <file> --pds <url> --handle <handle> --email <email> [options]

  --hit <file>       output of \`plc-mint grind\`
  --keys <file>      keys.json from \`plc-mint init\`
  --pds <url>        the PDS that will host the account
  --handle <handle>  on one of the PDS's domains, or your own domain already pointing at the DID
  --email <email>    account email
  --invite <code>    invite code, if the PDS needs one
  --plc <url>        PLC directory (default: https://plc.directory, or $PLC_URL)
  --keep-grind-key   leave the grind key in rotationKeys (default: drop it)
  --dry-run          run the checks, change nothing
  --yes              don't ask before publishing the DID

The account password comes from $PDS_PASSWORD; without it a random one is generated and printed.`

const { values: args } = parseArgs({
  options: {
    hit: { type: 'string' },
    keys: { type: 'string' },
    pds: { type: 'string' },
    handle: { type: 'string' },
    email: { type: 'string' },
    invite: { type: 'string' },
    plc: { type: 'string' },
    'keep-grind-key': { type: 'boolean', default: false },
    'dry-run': { type: 'boolean', default: false },
    yes: { type: 'boolean', default: false },
    help: { type: 'boolean', short: 'h', default: false },
  },
})

if (args.help) {
  console.log(USAGE)
  process.exit(0)
}

const say = (msg: string) => console.error(msg)
function fail(msg: string): never {
  say(`error: ${msg}`)
  process.exit(1)
}

for (const name of ['hit', 'keys', 'pds', 'handle', 'email'] as const) {
  if (!args[name]) fail(`--${name} is required\n\n${USAGE}`)
}

const PLC = args.plc ?? process.env.PLC_URL ?? 'https://plc.directory'
const PDS = args.pds!
const handle = args.handle!.replace(/^@/, '').toLowerCase()
const plc = plcClient(PLC)
const xrpc = pdsClient(PDS)

type KeyPair = { didKey: string; privateKey?: string }
const hit: { did: string; signedOp: Op } = await Bun.file(args.hit!).json()
const keys: { recovery: KeyPair; grind: KeyPair; tempSigning: KeyPair } = await Bun.file(args.keys!).json()
const did = hit.did
const genesis = hit.signedOp

// --- checks: nothing below changes anything until the plan is printed --------

say(`checking ${did}`)
if (didOf(genesis) !== did) fail('the genesis op in --hit does not hash to its DID')
if (genesis.prev !== null) fail('--hit is not a genesis op')
const genesisKeys = genesis.rotationKeys as string[]
if (!opSignedBy(genesis, keys.grind.didKey)) fail('the genesis op is not signed by the grind key in --keys (wrong keys.json?)')
if (!genesisKeys.includes(keys.recovery.didKey)) fail('the recovery key in --keys is not a rotation key of this DID')
if ((genesis.verificationMethods as Record<string, string>).atproto !== keys.tempSigning.didKey) {
  fail('the temp signing key in --keys is not the signing key of this DID')
}
if (!keys.grind.privateKey || !keys.tempSigning.privateKey) fail('--keys is missing the grind or temp signing private key')
const grindKey = hex(keys.grind.privateKey)
const tempKey = hex(keys.tempSigning.privateKey)

// Every DID from one job (the hit and its alternatives) carries a signature from the
// same grind key with related nonces. Two of them in public would reveal the key, so
// only one may ever be published.
const jobDir = dirname(args.keys!)
const siblingFiles = [
  join(jobDir, 'hit.json'),
  ...(existsSync(join(jobDir, 'alternatives')) ? readdirSync(join(jobDir, 'alternatives')).map((f) => join(jobDir, 'alternatives', f)) : []),
].filter((f) => f.endsWith('.json') && existsSync(f))
const siblings: string[] = []
for (const file of siblingFiles) {
  const other = (await Bun.file(file).json()).did as string
  if (other && other !== did && !siblings.includes(other)) siblings.push(other)
}
for (const other of siblings) {
  if ((await plc.audit(other)) !== null) {
    fail(
      `${other}, from the same job, is already published. Publishing a second DID from one job ` +
        `would reveal the grind key. Grind a new job (plc-mint init) instead.`,
    )
  }
}

const server = await xrpc('com.atproto.server.describeServer').catch((e) => fail(`${PDS} is not reachable as a PDS: ${e.message}`))
const audit = await plc.audit(did)
const published = audit !== null
const accountExists = await xrpc('com.atproto.repo.describeRepo', { query: { repo: did } }).then(
  () => true,
  (e) => !(e instanceof HttpError && e.body.error === 'RepoNotFound'),
)

if (!accountExists) {
  if (server.inviteCodeRequired && !args.invite) fail(`${PDS} requires an invite code (--invite)`)
  const domains: string[] = server.availableUserDomains ?? []
  if (!domains.some((d) => handle.endsWith(d))) {
    // Outside the PDS's own domains the handle has to resolve to the DID first.
    const resolved = await xrpc('com.atproto.identity.resolveHandle', { query: { handle } }).then(
      (r) => r.did as string,
      () => null,
    )
    if (resolved !== did) {
      fail(
        `${handle} is not on ${PDS}'s domains (${domains.join(', ') || 'none'}) and does not resolve to ${did}.\n` +
          `Either pick a handle ending in one of those domains, or point your domain at the DID first:\n` +
          `  DNS TXT  _atproto.${handle}  "did=${did}"\n` +
          `  or serve https://${handle}/.well-known/atproto-did containing ${did}`,
      )
    }
  }
}

say(`  PDS        ${PDS} (${server.did})`)
say(`  PLC        ${PLC}`)
say(`  handle     ${handle}`)
say(`  genesis    ${published ? 'already published' : 'not published yet'}`)
say(`  account    ${accountExists ? 'already exists' : 'will be created'}`)
say(`  grind key  ${args['keep-grind-key'] ? 'kept' : 'dropped'} once the PDS keys are installed`)
if (siblings.length) say(`  others     ${siblings.length} other DID(s) from this job become unusable once this one is published`)

if (args['dry-run']) {
  say('dry run: checks passed, nothing changed')
  process.exit(0)
}

try {
  // --- 1. publish the genesis --------------------------------------------------

  if (!published) {
    if (!args.yes) {
      if (!process.stdin.isTTY) fail('publishing is permanent; pass --yes to confirm non-interactively')
      const answer = prompt(`\nPublishing ${did} to ${PLC} is permanent. Continue? [y/N]`)
      if (answer?.trim().toLowerCase() !== 'y') fail('aborted, nothing changed')
    }
    say('publishing the genesis op')
    await plc.submit(did, genesis)
  }

  // --- 2. import the DID into the PDS ------------------------------------------

  let password = process.env.PDS_PASSWORD
  let generatedPassword: string | undefined
  let token: string

  if (!accountExists) {
    if (!password) password = generatedPassword = bytesToHex(randomBytes(16))
    say('creating the account (deactivated until the DID points at the PDS)')
    const auth = serviceAuth({ iss: did, aud: server.did, lxm: 'com.atproto.server.createAccount', key: tempKey })
    const account = await xrpc('com.atproto.server.createAccount', {
      token: auth,
      body: { did, handle, email: args.email, password, ...(args.invite ? { inviteCode: args.invite } : {}) },
    })
    if (generatedPassword) say(`  password: ${generatedPassword}  (save it now)`)
    token = account.accessJwt
  } else {
    if (!password) fail('the account already exists: set $PDS_PASSWORD to its password to resume')
    token = (await xrpc('com.atproto.server.createSession', { body: { identifier: did, password } })).accessJwt
  }

  // --- 3. point the DID at the PDS ---------------------------------------------

  const creds = await xrpc('com.atproto.identity.getRecommendedDidCredentials', { token })
  const current = await plc.data(did)
  const installed =
    current.verificationMethods?.atproto === creds.verificationMethods.atproto &&
    current.services?.atproto_pds?.endpoint === creds.services.atproto_pds.endpoint

  if (!installed) {
    if (!current.rotationKeys.includes(keys.grind.didKey)) {
      fail('the grind key is no longer a rotation key, so plc-claim cannot update the DID; use the recovery key')
    }
    say('installing the PDS signing key, handle and endpoint (PLC update signed by the grind key)')
    // Recovery key first, so it outranks the PDS's key; then the PDS's own rotation
    // key, which it needs to sign handle changes.
    const rotationKeys = [
      ...new Set([keys.recovery.didKey, ...(args['keep-grind-key'] ? [keys.grind.didKey] : []), ...creds.rotationKeys]),
    ]
    const head = (await plc.audit(did))!.at(-1)!
    await plc.submit(
      did,
      signOp(secp256k1, grindKey, {
        type: 'plc_operation',
        rotationKeys,
        verificationMethods: creds.verificationMethods,
        alsoKnownAs: creds.alsoKnownAs,
        services: creds.services,
        prev: head.cid ?? (await cidOf(head.operation)),
      }),
    )
  }

  // --- 4. activate ---------------------------------------------------------------

  let status = await xrpc('com.atproto.server.checkAccountStatus', { token })
  if (!status.activated) {
    say('activating the account')
    await xrpc('com.atproto.server.activateAccount', { token, body: null })
    status = await xrpc('com.atproto.server.checkAccountStatus', { token })
  }
  if (!status.activated || !status.validDid) fail(`account not ready: ${JSON.stringify(status)}`)

  const final = await plc.data(did)
  say(`done: ${did} is live on ${PDS} as @${handle}`)
  say('keep keys.json: its recovery key can move or rescue the account even without this PDS')
  if (siblings.length) say(`the ${siblings.length} other DID(s) from this job can never be published now; delete them`)
  console.log(
    JSON.stringify(
      { did, handle, pds: PDS, rotationKeys: final.rotationKeys, ...(generatedPassword ? { password: generatedPassword } : {}) },
      null,
      2,
    ),
  )
} catch (e) {
  const message = e instanceof HttpError ? (e.body.message ?? e.message) : (e as Error).message
  fail(`${message}\nfix the cause and run the same command again to resume`)
}
