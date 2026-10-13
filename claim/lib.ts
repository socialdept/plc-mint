// Shared by plc-claim and the end-to-end test. Signing, DAG-CBOR and CIDs use
// independent JS libraries, so everything here also cross-checks plc-mint.

import * as dagCbor from '@ipld/dag-cbor'
import { p256 } from '@noble/curves/p256'
import { secp256k1 } from '@noble/curves/secp256k1'
import { sha256 } from '@noble/hashes/sha256'
import { hexToBytes } from '@noble/hashes/utils'
import { base32 } from 'multiformats/bases/base32'
import { base58btc } from 'multiformats/bases/base58'
import { CID } from 'multiformats/cid'
import { sha256 as cidSha256 } from 'multiformats/hashes/sha2'

export type Op = Record<string, unknown>
export type Curve = typeof secp256k1 | typeof p256
export { p256, secp256k1, sha256, dagCbor }

const K256 = [0xe7, 0x01]
const P256 = [0x80, 0x24]

export const b64url = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url')
export const utf8 = (s: string) => new TextEncoder().encode(s)

export function didKey(curve: Curve, priv: Uint8Array): string {
  const codec = curve === secp256k1 ? K256 : P256
  return `did:key:${base58btc.encode(new Uint8Array([...codec, ...curve.getPublicKey(priv, true)]))}`
}

/** The curve and compressed public key behind a did:key. */
export function parseDidKey(key: string): { curve: Curve; pub: Uint8Array } {
  const bytes = base58btc.decode(key.replace(/^did:key:/, ''))
  const codec = [bytes[0], bytes[1]].join()
  if (codec === K256.join()) return { curve: secp256k1, pub: bytes.slice(2) }
  if (codec === P256.join()) return { curve: p256, pub: bytes.slice(2) }
  throw new Error(`unsupported did:key ${key}`)
}

export function sign(curve: Curve, priv: Uint8Array, msg: Uint8Array): Uint8Array {
  return curve.sign(sha256(msg), priv, { lowS: true }).toCompactRawBytes()
}

export function signOp(curve: Curve, priv: Uint8Array, unsigned: Op): Op {
  return { ...unsigned, sig: b64url(sign(curve, priv, dagCbor.encode(unsigned))) }
}

/** Whether `signedOp` carries a valid low-S signature by `key` (a did:key). */
export function opSignedBy(signedOp: Op, key: string): boolean {
  const { sig, ...unsigned } = signedOp
  const { curve, pub } = parseDidKey(key)
  return curve.verify(Buffer.from(sig as string, 'base64url'), sha256(dagCbor.encode(unsigned)), pub, { lowS: true })
}

export async function cidOf(op: Op): Promise<string> {
  return CID.create(1, dagCbor.code, await cidSha256.digest(dagCbor.encode(op))).toString()
}

/** did:plc identifier, computed independently of plc-mint. */
export function didOf(signedOp: Op): string {
  return `did:plc:${base32.baseEncode(sha256(dagCbor.encode(signedOp))).slice(0, 24)}`
}

export const hex = hexToBytes

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: { error?: string; message?: string },
  ) {
    super(message)
  }
}

export async function http(url: string, init: RequestInit = {}) {
  const res = await fetch(url, init)
  const text = await res.text()
  if (!res.ok) {
    let body = {}
    try {
      body = JSON.parse(text)
    } catch {}
    throw new HttpError(`${init.method ?? 'GET'} ${url} -> ${res.status}: ${text}`, res.status, body)
  }
  // PLC answers submissions with a bare `OK`.
  return res.headers.get('content-type')?.includes('json') ? JSON.parse(text) : text
}

export function plcClient(plc: string) {
  const base = plc.replace(/\/$/, '')
  return {
    submit: (did: string, op: Op) =>
      http(`${base}/${did}`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(op) }),
    data: (did: string) => http(`${base}/${did}/data`),
    /** The audit log, or null if PLC has never seen the DID. */
    audit: (did: string): Promise<{ cid: string; operation: Op }[] | null> =>
      http(`${base}/${did}/log/audit`).catch((e) => {
        if (e instanceof HttpError && e.status === 404) return null
        throw e
      }),
  }
}

type XrpcOpts = { token?: string; body?: unknown; query?: Record<string, string> }

/** `body: null` sends a POST with no body (procedures with no input, like activateAccount). */
export function pdsClient(pds: string) {
  const base = pds.replace(/\/$/, '')
  return (nsid: string, opts: XrpcOpts = {}) =>
    http(`${base}/xrpc/${nsid}${opts.query ? `?${new URLSearchParams(opts.query)}` : ''}`, {
      method: opts.body === undefined ? 'GET' : 'POST',
      headers: {
        ...(opts.body == null ? {} : { 'content-type': 'application/json' }),
        ...(opts.token ? { authorization: `Bearer ${opts.token}` } : {}),
      },
      body: opts.body == null ? undefined : JSON.stringify(opts.body),
    })
}

/** A short-lived inter-service JWT, signed by the DID's atproto signing key. */
export function serviceAuth(opts: { iss: string; aud: string; lxm: string; key: Uint8Array }): string {
  const now = Math.floor(Date.now() / 1000)
  const header = b64url(utf8(JSON.stringify({ typ: 'JWT', alg: 'ES256K' })))
  const jti = b64url(crypto.getRandomValues(new Uint8Array(12)))
  const payload = b64url(utf8(JSON.stringify({ iss: opts.iss, aud: opts.aud, lxm: opts.lxm, iat: now, exp: now + 60, jti })))
  return `${header}.${payload}.${b64url(sign(secp256k1, opts.key, utf8(`${header}.${payload}`)))}`
}
