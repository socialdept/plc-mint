// End-to-end: the self-serve flow (plc-mint init, grind, plc-claim) against a local
// PLC + PDS (socialdept/atp-testnet), then checks that the account is fully usable
// and that the keys end up with the right powers.
//
//   bun run e2e.ts [prefix]     (default prefix: "e2e")

import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { bytesToHex, randomBytes } from '@noble/hashes/utils'
import { didKey, didOf, hex, opSignedBy, p256, pdsClient, plcClient, secp256k1, signOp, type Op } from './lib'

const PLC = process.env.PLC_URL ?? 'http://localhost:7100'
const PDS = process.env.PDS_URL ?? 'http://localhost:7102'
const BIN = new URL('../target/release/plc-mint', import.meta.url).pathname
const CLAIM = new URL('./plc-claim.ts', import.meta.url).pathname
const PREFIX = process.argv[2] ?? 'e2e'

const plc = plcClient(PLC)
const xrpc = pdsClient(PDS)

let step = 0
const log = (msg: string) => console.log(`\n[${++step}] ${msg}`)
const ok = (msg: string) => console.log(`    ok  ${msg}`)
function check(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`FAILED: ${msg}`)
  ok(msg)
}

async function run(cmd: string[], env: Record<string, string> = {}) {
  const proc = Bun.spawn(cmd, { env: { ...process.env, ...env }, stdout: 'pipe', stderr: 'pipe' })
  const [stdout, stderr, code] = await Promise.all([new Response(proc.stdout).text(), new Response(proc.stderr).text(), proc.exited])
  if (code !== 0) throw new Error(`${cmd.join(' ')} exited ${code}\n${stderr}`)
  return stdout
}

const head = async (did: string) => (await plc.audit(did))!.at(-1)!.cid
const dir = mkdtempSync(join(tmpdir(), 'plc-mint-e2e-'))
const tag = bytesToHex(randomBytes(3))
const handle = `mint-${tag}.test`
const password = bytesToHex(randomBytes(16))

try {
  log('plc-mint init, bringing a P-256 recovery key (as a browser passkey-style key would be)')
  const recovery = p256.utils.randomPrivateKey()
  await run([BIN, 'init', '--mode', 'prefix', '--value', PREFIX, '--recovery', didKey(p256, recovery), '--out', dir])
  const keys = await Bun.file(join(dir, 'keys.json')).json()
  check(keys.recovery.privateKey === undefined, 'keys.json holds no private half for a brought recovery key')
  const grind = hex(keys.grind.privateKey)

  log(`plc-mint grind for prefix "${PREFIX}" (incremental nonces)`)
  const hit = JSON.parse(await run([BIN, 'grind', '--job', join(dir, 'job.json'), '--threads', '2', '--nonce', 'incremental']))
  await Bun.write(join(dir, 'hit.json'), JSON.stringify(hit))
  const did: string = hit.did
  check(did.startsWith(`did:plc:${PREFIX}`), `found ${did} in ${hit.attempts} attempts`)
  check(didOf(hit.signedOp) === did, '@ipld/dag-cbor + sha256 reproduce the DID')
  check(opSignedBy(hit.signedOp, keys.grind.didKey), '@noble/curves verifies the genesis signature (low-S)')

  const claimArgs = ['bun', CLAIM, '--hit', join(dir, 'hit.json'), '--keys', join(dir, 'keys.json'), '--pds', PDS, '--plc', PLC, '--handle', handle, '--email', `${tag}@example.com`]

  log('plc-claim --dry-run changes nothing')
  await run([...claimArgs, '--dry-run'])
  check((await plc.audit(did)) === null, 'genesis not published')

  log('plc-claim: publish, import into the PDS, install PDS keys, drop the grind key, activate')
  const claimed = JSON.parse(await run([...claimArgs, '--yes'], { PDS_PASSWORD: password }))
  check(claimed.did === did && claimed.handle === handle, `claimed @${handle}`)
  const doc = await plc.data(did)
  check(doc.rotationKeys[0] === keys.recovery.didKey, 'recovery key is the top rotation key')
  check(!doc.rotationKeys.includes(keys.grind.didKey), 'grind key dropped')
  check(doc.alsoKnownAs[0] === `at://${handle}`, `PLC shows at://${handle}`)
  check((await plc.audit(did))!.length === 2, 'two ops in the log: genesis, credentials')

  log('plc-claim again resumes as a no-op')
  await run([...claimArgs, '--yes'], { PDS_PASSWORD: password })
  check((await plc.audit(did))!.length === 2, 'still two ops')

  log('Use the account')
  const { accessJwt: token } = await xrpc('com.atproto.server.createSession', { body: { identifier: handle, password } })
  const status = await xrpc('com.atproto.server.checkAccountStatus', { token })
  check(status.activated && status.validDid, 'activated, valid DID')
  const post = await xrpc('com.atproto.repo.createRecord', {
    token,
    body: { repo: did, collection: 'app.bsky.feed.post', record: { $type: 'app.bsky.feed.post', text: `hello from ${did}`, createdAt: new Date().toISOString() } },
  })
  check(post.uri.startsWith(`at://${did}/`), `posted ${post.uri}`)
  const fetched = await xrpc('com.atproto.repo.getRecord', { query: { repo: did, collection: 'app.bsky.feed.post', rkey: post.uri.split('/').at(-1) } })
  check(fetched.value.text === `hello from ${did}`, 'record reads back')

  log('Change the handle through the PDS (it signs that PLC op with its own rotation key)')
  const newHandle = `renamed-${tag}.test`
  await xrpc('com.atproto.identity.updateHandle', { token, body: { handle: newHandle } })
  check((await plc.data(did)).alsoKnownAs[0] === `at://${newHandle}`, `PLC shows at://${newHandle}`)

  log('The grind key is powerless; the recovery key still works')
  const current = await plc.data(did)
  const next = async (rotationKeys: string[]): Promise<Op> => ({
    type: 'plc_operation',
    rotationKeys,
    verificationMethods: current.verificationMethods,
    alsoKnownAs: current.alsoKnownAs,
    services: current.services,
    prev: await head(did),
  })
  const rejection = await plc.submit(did, signOp(secp256k1, grind, await next([keys.grind.didKey]))).then(
    () => '',
    (e) => (e.body?.message ?? e.message).split(':')[0] as string,
  )
  check(/invalid signature/i.test(rejection), `PLC rejects an op signed by the grind key ("${rejection}")`)
  await plc.submit(did, signOp(p256, recovery, await next(current.rotationKeys)))
  check(true, 'PLC accepts an op signed by the P-256 recovery key')

  log('Final state')
  const audit = (await plc.audit(did))!
  check(audit.length === 4, `${audit.length} ops: genesis, credentials, handle, recovery`)
  check(didOf(audit[0].operation) === did, 'genesis in the log still hashes to the DID')
  const final = await xrpc('com.atproto.server.checkAccountStatus', { token })
  check(final.activated && final.validDid, 'account still active with a valid DID')

  console.log(`\nPASS  ${did}  (@${newHandle})`)
} finally {
  rmSync(dir, { recursive: true, force: true })
}
