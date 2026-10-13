// End-to-end: grind a vanity genesis with plc-mint, then do everything the web layer
// will do (PLC submit, import the DID into a stock PDS, install real credentials,
// activate, post, drop the grind key) and check the account is fully usable.
//
// Runs against a local PLC + PDS (socialdept/atp-testnet). Signing, DAG-CBOR and
// CIDs here use independent JS libraries, so they also cross-check plc-mint.
//
//   bun run e2e.ts [prefix]     (default prefix: "e2e")

import * as dagCbor from '@ipld/dag-cbor'
import { p256 } from '@noble/curves/p256'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { bytesToHex, randomBytes } from '@noble/hashes/utils'
import { base32 } from 'multiformats/bases/base32'
import { base58btc } from 'multiformats/bases/base58'
import { CID } from 'multiformats/cid'
import { sha256 as cidSha256 } from 'multiformats/hashes/sha2'

const PLC = process.env.PLC_URL ?? 'http://localhost:7100'
const PDS = process.env.PDS_URL ?? 'http://localhost:7102'
const BIN = new URL('../target/release/plc-mint', import.meta.url).pathname
const PREFIX = process.argv[2] ?? 'e2e'

type Op = Record<string, unknown>
type Curve = typeof secp256k1 | typeof p256

// --- helpers ---------------------------------------------------------------

let step = 0
const log = (msg: string) => console.log(`\n[${++step}] ${msg}`)
const ok = (msg: string) => console.log(`    ok  ${msg}`)
function check(cond: unknown, msg: string): asserts cond {
  if (!cond) throw new Error(`FAILED: ${msg}`)
  ok(msg)
}

const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
const utf8 = (s: string) => new TextEncoder().encode(s)

function didKey(curve: Curve, priv: Uint8Array): string {
  const codec = curve === secp256k1 ? [0xe7, 0x01] : [0x80, 0x24]
  return `did:key:${base58btc.encode(new Uint8Array([...codec, ...curve.getPublicKey(priv, true)]))}`
}

function sign(curve: Curve, priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return curve.sign(sha256(msg), priv, { lowS: true }).toCompactRawBytes()
}

function signOp(curve: Curve, priv: Uint8Array, unsigned: Op): Op {
  return { ...unsigned, sig: b64url(sign(curve, priv, dagCbor.encode(unsigned))) }
}

async function cidOf(op: Op): Promise<string> {
  return CID.create(1, dagCbor.code, await cidSha256.digest(dagCbor.encode(op))).toString()
}

/** did:plc identifier, computed independently of plc-mint. */
function didOf(signedOp: Op): string {
  return `did:plc:${base32.baseEncode(sha256(dagCbor.encode(signedOp))).slice(0, 24)}`
}

async function http(url: string, init: RequestInit = {}) {
  const res = await fetch(url, init)
  const text = await res.text()
  if (!res.ok) throw new Error(`${init.method ?? 'GET'} ${url} -> ${res.status}: ${text}`)
  // PLC answers submissions with a bare `OK`.
  return res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text
}

// `body: null` sends a POST with no body (procedures with no input, like activateAccount).
const xrpc = (nsid: string, opts: { token?: string; body?: unknown; query?: Record<string, string> } = {}) =>
  http(`${PDS}/xrpc/${nsid}${opts.query ? `?${new URLSearchParams(opts.query)}` : ''}`, {
    method: opts.body === undefined ? 'GET' : 'POST',
    headers: {
      ...(opts.body == null ? {} : { 'content-type': 'application/json' }),
      ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
    },
    body: opts.body == null ? undefined : JSON.stringify(opts.body),
  })

const submit = (did: string, op: Op) =>
  http(`${PLC}/${did}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(op) })

async function headCid(did: string): Promise<string> {
  const log = await http(`${PLC}/${did}/log/audit`)
  return log.at(-1).cid
}

// --- the flow --------------------------------------------------------------

const pdsDid: string = (await xrpc('com.atproto.server.describeServer')).did
const tag = bytesToHex(randomBytes(3))
const handle = `mint-${tag}.test`

log('Keys: customer recovery (P-256, never leaves "the browser"), grind + temp signing (k256)')
const recovery = p256.utils.randomPrivateKey()
const grind = secp256k1.utils.randomPrivateKey()
const tempSigning = secp256k1.utils.randomPrivateKey()
const keys = { recovery: didKey(p256, recovery), grind: didKey(secp256k1, grind), temp: didKey(secp256k1, tempSigning) }
ok(`recovery ${keys.recovery}`)
ok(`grind    ${keys.grind}`)

log(`Grind a genesis with prefix "${PREFIX}" (plc-mint, incremental nonces)`)
const job = {
  operation: {
    type: 'plc_operation',
    rotationKeys: [keys.recovery, keys.grind],
    verificationMethods: { atproto: keys.temp },
    alsoKnownAs: [`at://pending-${tag}.test`],
    services: { atproto_pds: { type: 'AtprotoPersonalDataServer', endpoint: 'https://pds.test' } },
    prev: null,
  },
  signingKey: bytesToHex(grind),
  match: { mode: 'prefix', value: PREFIX },
}
const proc = Bun.spawn([BIN, 'grind', '--job', '-', '--threads', '2', '--nonce', 'incremental'], { stdin: 'pipe' })
proc.stdin.write(JSON.stringify(job))
proc.stdin.end()
const hit = JSON.parse(await new Response(proc.stdout).text())
check((await proc.exited) === 0, `plc-mint found ${hit.did} in ${hit.attempts} attempts, ${hit.elapsedMs} ms`)
const genesis: Op = hit.signedOp
const did: string = hit.did

log('Verify the ground genesis with independent JS libraries')
check(didOf(genesis) === did, `@ipld/dag-cbor + sha256 reproduce ${did}`)
const { sig, ...unsignedGenesis } = genesis
check(
  secp256k1.verify(Buffer.from(sig as string, 'base64url'), sha256(dagCbor.encode(unsignedGenesis)), secp256k1.getPublicKey(grind, true), { lowS: true }),
  '@noble/curves verifies the signature (low-S)',
)

log('Submit genesis to the PLC directory')
await submit(did, genesis)
const genesisCid = await cidOf(genesis)
check((await headCid(did)) === genesisCid, `PLC accepted it; head CID ${genesisCid}`)

log('Import the DID into the PDS: createAccount with a service-auth JWT signed by the temp signing key')
const now = Math.floor(Date.now() / 1000)
const jwtHeader = b64url(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256K' })))
const jwtPayload = b64url(
  utf8(JSON.stringify({ iss: did, aud: pdsDid, lxm: 'com.atproto.server.createAccount', iat: now, exp: now + 60, jti: tag })),
)
const serviceAuth = `${jwtHeader}.${jwtPayload}.${b64url(sign(secp256k1, tempSigning, utf8(`${jwtHeader}.${jwtPayload}`)))}`
const account = await http(`${PDS}/xrpc/com.atproto.server.createAccount`, {
  method: 'POST',
  headers: { 'content-type': 'application/json', authorization: `Bearer ${serviceAuth}` },
  body: JSON.stringify({ did, handle, email: `${tag}@example.com`, password: bytesToHex(randomBytes(16)) }),
})
check(account.did === did, `account created for ${account.handle}`)
const token: string = account.accessJwt
const before = await xrpc('com.atproto.server.checkAccountStatus', { token })
check(before.activated === false, 'account starts deactivated')

log('Install the PDS credentials with a PLC update signed by the grind key')
const creds = await xrpc('com.atproto.identity.getRecommendedDidCredentials', { token })
const update = signOp(secp256k1, grind, {
  type: 'plc_operation',
  // Customer key on top, our grind key, then the PDS's own key so it can sign
  // handle changes for the account.
  rotationKeys: [keys.recovery, keys.grind, ...creds.rotationKeys],
  verificationMethods: creds.verificationMethods,
  alsoKnownAs: creds.alsoKnownAs,
  services: creds.services,
  prev: genesisCid,
})
await submit(did, update)
const doc = await http(`${PLC}/${did}/data`)
check(doc.verificationMethods.atproto === creds.verificationMethods.atproto, 'PLC now points at the PDS signing key')
check(doc.services.atproto_pds.endpoint === creds.services.atproto_pds.endpoint, `PDS endpoint ${doc.services.atproto_pds.endpoint}`)

log('Activate and use the account')
await xrpc('com.atproto.server.activateAccount', { token, body: null })
const status = await xrpc('com.atproto.server.checkAccountStatus', { token })
check(status.activated && status.validDid, `activated, validDid: ${status.validDid}`)
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
check((await http(`${PLC}/${did}/data`)).alsoKnownAs[0] === `at://${newHandle}`, `PLC shows at://${newHandle}`)

log('Drop the grind key from rotationKeys (signed by the grind key, as in the hand-off)')
const current = await http(`${PLC}/${did}/data`)
await submit(
  did,
  signOp(secp256k1, grind, {
    type: 'plc_operation',
    rotationKeys: current.rotationKeys.filter((k: string) => k !== keys.grind),
    verificationMethods: current.verificationMethods,
    alsoKnownAs: current.alsoKnownAs,
    services: current.services,
    prev: await headCid(did),
  }),
)
const afterDrop = await http(`${PLC}/${did}/data`)
check(!afterDrop.rotationKeys.includes(keys.grind), `rotationKeys now ${afterDrop.rotationKeys.length}: customer + PDS`)

log('The grind key is now powerless; the customer recovery key still works')
const grindAttempt = signOp(secp256k1, grind, {
  type: 'plc_operation',
  rotationKeys: [keys.grind],
  verificationMethods: afterDrop.verificationMethods,
  alsoKnownAs: afterDrop.alsoKnownAs,
  services: afterDrop.services,
  prev: await headCid(did),
})
const rejection = await submit(did, grindAttempt).then(
  () => '',
  (e: Error) => JSON.parse(e.message.slice(e.message.indexOf('{'))).message.split(':')[0] as string,
)
check(/invalid signature/i.test(rejection), `PLC rejects an op signed by the dropped grind key ("${rejection}")`)
await submit(
  did,
  signOp(p256, recovery, {
    type: 'plc_operation',
    rotationKeys: afterDrop.rotationKeys,
    verificationMethods: afterDrop.verificationMethods,
    alsoKnownAs: afterDrop.alsoKnownAs,
    services: afterDrop.services,
    prev: await headCid(did),
  }),
)
check(true, 'PLC accepts an op signed by the P-256 recovery key')

log('Final state')
const audit = await http(`${PLC}/${did}/log/audit`)
check(audit.length === 5, `${audit.length} ops in the PLC log: genesis, credentials, handle, drop grind key, recovery`)
check(didOf(audit[0].operation) === did, 'genesis in the log still hashes to the DID')
const final = await xrpc('com.atproto.server.checkAccountStatus', { token })
check(final.activated && final.validDid, 'account still active with a valid DID')
const post2 = await xrpc('com.atproto.repo.createRecord', {
  token,
  body: { repo: did, collection: 'app.bsky.feed.post', record: { $type: 'app.bsky.feed.post', text: 'still here', createdAt: new Date().toISOString() } },
})
check(post2.uri.startsWith(`at://${did}/`), 'can still post')

console.log(`\nPASS  ${did}  (@${newHandle})`)
