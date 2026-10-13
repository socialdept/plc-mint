// plc-mint GPU kernel: incremental-nonce ECDSA over secp256k1 + SHA-256 + match.
//
// The same source also compiles as C++ (gpu/cpu_ref.cpp) so the math can be
// tested against libsecp256k1 on any machine; Metal-only parts sit behind
// __METAL_VERSION__.
//
// Each thread owns a nonce range: state holds its next nonce k and the affine
// point k*G. Per chunk it walks BATCH consecutive nonces (R_i = R_{i-1} + G),
// batch-inverts the point Z coordinates and the nonces (Montgomery's trick), then
// signs, hashes and matches each. Same nonce-safety rules as the CPU incremental
// signer: only the hit ever leaves the GPU.
//
// 256-bit numbers are 8 x 32-bit limbs, least significant first.

#ifdef __METAL_VERSION__
#include <metal_stdlib>
using namespace metal;
#define LOCAL thread
#define CONST constant
#define DEVICE device
#else
#define LOCAL
#define CONST const
#define DEVICE
#endif

#ifndef BATCH
#define BATCH 32
#endif

// Mirrors gpu::Params on the host.
struct Params {
    uint d[8];        // grind private key
    uint z[8];        // SHA-256 of the unsigned op, mod n
    uint tmpl[128];   // padded SHA-256 message (8 blocks), big-endian words
    uint slot;        // byte offset of the 86-char signature in the message
    uint mode;        // 0 prefix, 1 suffix, 2 contains
    uint len;         // match length
    uint chunks;      // chunks of BATCH attempts per thread per dispatch
    uint debug;       // nonzero: write every attempt to dbg
    uint value[24];   // match characters
    uint sched[384];  // SHA-256 message schedules (64 words) of the constant blocks 2..7
};

struct U256 { uint v[8]; };

// secp256k1 field prime p = 2^256 - (2^32 + 977) and group order n = 2^256 - c_n.
// The field has its own reduction (reduce_p); scalars use the generic reduce512.
CONST uint P_MOD[8] = {0xFFFFFC2F, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
CONST uint N_MOD[8] = {0xD0364141, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
CONST uint N_C[5] = {0x2FC9BEBF, 0x402DA173, 0x50B75FC4, 0x45512319, 0x00000001};
CONST uint N_EXP[8] = {0xD036413F, 0xBFD25E8C, 0xAF48A03B, 0xBAAEDCE6, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF};
CONST uint N_HALF[8] = {0x681B20A0, 0xDFE92F46, 0x57A4501D, 0x5D576E73, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x7FFFFFFF};
CONST uint G_X[8] = {0x16F81798, 0x59F2815B, 0x2DCE28D9, 0x029BFCDB, 0xCE870B07, 0x55A06295, 0xF9DCBBAC, 0x79BE667E};
CONST uint G_Y[8] = {0xFB10D4B8, 0x9C47D08F, 0xA6855419, 0xFD17B448, 0x0E1108A8, 0x5DA4FBFC, 0x26A3C465, 0x483ADA77};

CONST uint SHA_K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
CONST uint SHA_H0[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

// --- 256-bit integers -------------------------------------------------------

inline U256 u_load(CONST uint* m) {
    U256 r;
    for (int i = 0; i < 8; i++) r.v[i] = m[i];
    return r;
}

inline U256 u_small(uint x) {
    U256 r;
    for (int i = 0; i < 8; i++) r.v[i] = 0;
    r.v[0] = x;
    return r;
}

inline bool u_is_zero(U256 a) {
    uint acc = 0;
    for (int i = 0; i < 8; i++) acc |= a.v[i];
    return acc == 0;
}

// a >= m
inline bool u_gte(U256 a, CONST uint* m) {
    for (int i = 7; i >= 0; i--) {
        if (a.v[i] != m[i]) return a.v[i] > m[i];
    }
    return true;
}

// a > m
inline bool u_gt(U256 a, CONST uint* m) {
    for (int i = 7; i >= 0; i--) {
        if (a.v[i] != m[i]) return a.v[i] > m[i];
    }
    return false;
}

inline U256 u_add(U256 a, U256 b, LOCAL uint& carry) {
    U256 r;
    ulong c = 0;
    for (int i = 0; i < 8; i++) {
        c += (ulong)a.v[i] + (ulong)b.v[i];
        r.v[i] = (uint)c;
        c >>= 32;
    }
    carry = (uint)c;
    return r;
}

inline U256 u_sub(U256 a, U256 b, LOCAL uint& borrow) {
    U256 r;
    uint br = 0;
    for (int i = 0; i < 8; i++) {
        ulong t = (ulong)a.v[i] - (ulong)b.v[i] - (ulong)br;
        r.v[i] = (uint)t;
        br = (uint)(t >> 63);
    }
    borrow = br;
    return r;
}

// --- modular arithmetic for m = 2^256 - c -----------------------------------

// Reduces a 512-bit product w[16] by folding the high half: hi * 2^256 = hi * c.
inline U256 reduce512(LOCAL uint* w, CONST uint* c, int cl, CONST uint* m) {
    for (int iter = 0; iter < 8; iter++) {
        uint any = 0;
        for (int i = 8; i < 16; i++) any |= w[i];
        if (any == 0) break;

        uint hi[8];
        for (int i = 0; i < 8; i++) {
            hi[i] = w[8 + i];
            w[8 + i] = 0;
        }
        for (int i = 0; i < 8; i++) {
            if (hi[i] == 0) continue;
            ulong carry = 0;
            for (int j = 0; j < cl; j++) {
                ulong t = (ulong)hi[i] * (ulong)c[j] + (ulong)w[i + j] + carry;
                w[i + j] = (uint)t;
                carry = t >> 32;
            }
            for (int k = i + cl; carry != 0 && k < 16; k++) {
                ulong t = (ulong)w[k] + carry;
                w[k] = (uint)t;
                carry = t >> 32;
            }
        }
    }
    U256 r;
    for (int i = 0; i < 8; i++) r.v[i] = w[i];
    if (u_gte(r, m)) {
        uint b;
        r = u_sub(r, u_load(m), b);
    }
    return r;
}


// Inputs must already be < m.
inline U256 add_mod(U256 a, U256 b, CONST uint* m) {
    uint carry, b2;
    U256 r = u_add(a, b, carry);
    if (carry != 0 || u_gte(r, m)) r = u_sub(r, u_load(m), b2);
    return r;
}

inline U256 sub_mod(U256 a, U256 b, CONST uint* m) {
    uint borrow, c2;
    U256 r = u_sub(a, b, borrow);
    if (borrow != 0) r = u_add(r, u_load(m), c2);
    return r;
}

// Reduces w[16] mod p = 2^256 - 0x1000003D1 in straight-line code:
// hi * 2^256 = hi * 977 + hi * 2^32.
inline U256 reduce_p(LOCAL uint* w) {
    uint r[8];
    ulong c = 0;
    for (int i = 0; i < 8; i++) {
        c += (ulong)w[i] + (ulong)w[8 + i] * 977u;
        if (i > 0) c += (ulong)w[7 + i];
        r[i] = (uint)c;
        c >>= 32;
    }
    c += (ulong)w[15];
    // Fold the remaining carry (< 2^34) the same way.
    ulong t = (ulong)r[0] + c * 977u;
    r[0] = (uint)t;
    t >>= 32;
    t += (ulong)r[1] + c;
    r[1] = (uint)t;
    t >>= 32;
    for (int i = 2; i < 8; i++) {
        t += (ulong)r[i];
        r[i] = (uint)t;
        t >>= 32;
    }
    if (t != 0) {
        // Wrapped past 2^256 once more; r is now tiny, so this cannot carry far.
        ulong u = (ulong)r[0] + 977u;
        r[0] = (uint)u;
        u = (ulong)r[1] + 1u + (u >> 32);
        r[1] = (uint)u;
        for (int i = 2; i < 8 && (u >> 32) != 0; i++) {
            u = (ulong)r[i] + (u >> 32);
            r[i] = (uint)u;
        }
    }
    U256 out;
    for (int i = 0; i < 8; i++) out.v[i] = r[i];
    if (u_gte(out, P_MOD)) {
        uint b;
        out = u_sub(out, u_load(P_MOD), b);
    }
    return out;
}

inline void mul_wide(U256 a, U256 b, LOCAL uint* w) {
    for (int i = 0; i < 16; i++) w[i] = 0;
    for (int i = 0; i < 8; i++) {
        ulong carry = 0;
        for (int j = 0; j < 8; j++) {
            ulong t = (ulong)a.v[i] * (ulong)b.v[j] + (ulong)w[i + j] + carry;
            w[i + j] = (uint)t;
            carry = t >> 32;
        }
        w[i + 8] = (uint)carry;
    }
}

// a^2 with 36 partial products: off-diagonal terms once, doubled, plus squares.
inline void sqr_wide(U256 a, LOCAL uint* w) {
    for (int i = 0; i < 16; i++) w[i] = 0;
    for (int i = 0; i < 7; i++) {
        ulong carry = 0;
        for (int j = i + 1; j < 8; j++) {
            ulong t = (ulong)a.v[i] * (ulong)a.v[j] + (ulong)w[i + j] + carry;
            w[i + j] = (uint)t;
            carry = t >> 32;
        }
        w[i + 8] = (uint)carry;
    }
    uint top = 0;
    for (int i = 0; i < 16; i++) {
        uint next = w[i] >> 31;
        w[i] = (w[i] << 1) | top;
        top = next;
    }
    ulong carry = 0;
    for (int i = 0; i < 8; i++) {
        ulong sq = (ulong)a.v[i] * (ulong)a.v[i];
        ulong lo = (ulong)w[2 * i] + (sq & 0xFFFFFFFFul) + carry;
        w[2 * i] = (uint)lo;
        ulong hi = (ulong)w[2 * i + 1] + (sq >> 32) + (lo >> 32);
        w[2 * i + 1] = (uint)hi;
        carry = hi >> 32;
    }
}

inline U256 fmul(U256 a, U256 b) {
    uint w[16];
    mul_wide(a, b, w);
    return reduce_p(w);
}

inline U256 fsqr(U256 a) {
    uint w[16];
    sqr_wide(a, w);
    return reduce_p(w);
}

inline U256 smul(U256 a, U256 b) {
    uint w[16];
    mul_wide(a, b, w);
    return reduce512(w, N_C, 5, N_MOD);
}

inline U256 ssqr(U256 a) {
    uint w[16];
    sqr_wide(a, w);
    return reduce512(w, N_C, 5, N_MOD);
}
inline U256 fadd(U256 a, U256 b) { return add_mod(a, b, P_MOD); }
inline U256 fsub(U256 a, U256 b) { return sub_mod(a, b, P_MOD); }
inline U256 sadd(U256 a, U256 b) { return add_mod(a, b, N_MOD); }

inline U256 fsqr_n(U256 a, int n) {
    for (int i = 0; i < n; i++) a = fsqr(a);
    return a;
}

// a^(p-2) = a^-1 via libsecp256k1's addition chain: 255 squarings, 15 multiplications.
// p-2 is 223 ones, a zero, 22 ones, then 0000101101.
inline U256 finv(U256 a) {
    U256 x2 = fmul(fsqr(a), a);
    U256 x3 = fmul(fsqr(x2), a);
    U256 x6 = fmul(fsqr_n(x3, 3), x3);
    U256 x9 = fmul(fsqr_n(x6, 3), x3);
    U256 x11 = fmul(fsqr_n(x9, 2), x2);
    U256 x22 = fmul(fsqr_n(x11, 11), x11);
    U256 x44 = fmul(fsqr_n(x22, 22), x22);
    U256 x88 = fmul(fsqr_n(x44, 44), x44);
    U256 x176 = fmul(fsqr_n(x88, 88), x88);
    U256 x220 = fmul(fsqr_n(x176, 44), x44);
    U256 x223 = fmul(fsqr_n(x220, 3), x3);
    U256 t = fmul(fsqr_n(x223, 23), x22);
    t = fmul(fsqr_n(t, 5), a);
    t = fmul(fsqr_n(t, 3), x2);
    return fmul(fsqr_n(t, 2), a);
}

// a^(n-2) = a^-1 with a fixed 4-bit window: 252 squarings, ~78 multiplications.
inline U256 sinv(U256 a) {
    U256 table[16];
    table[0] = u_small(1);
    table[1] = a;
    for (int i = 2; i < 16; i++) table[i] = smul(table[i - 1], a);
    U256 r = table[N_EXP[7] >> 28];
    for (int nib = 62; nib >= 0; nib--) {
        for (int i = 0; i < 4; i++) r = ssqr(r);
        uint d = (N_EXP[nib >> 3] >> ((nib & 7) * 4)) & 15;
        if (d != 0) r = smul(r, table[d]);
    }
    return r;
}

// --- points -------------------------------------------------------------------

struct Jac { U256 x, y, z; };

// Jacobian P + affine G. Valid while P != +-G, i.e. for any nonce other than +-1.
inline Jac add_g(Jac p) {
    U256 gx = u_load(G_X), gy = u_load(G_Y);
    U256 z1z1 = fsqr(p.z);
    U256 u2 = fmul(gx, z1z1);
    U256 s2 = fmul(gy, fmul(p.z, z1z1));
    U256 h = fsub(u2, p.x);
    U256 r = fsub(s2, p.y);
    U256 hh = fsqr(h);
    U256 hhh = fmul(h, hh);
    U256 v = fmul(p.x, hh);
    Jac o;
    o.x = fsub(fsub(fsub(fsqr(r), hhh), v), v);
    o.y = fsub(fmul(r, fsub(v, o.x)), fmul(p.y, hhh));
    o.z = fmul(p.z, h);
    return o;
}

// --- SHA-256, encodings, match ------------------------------------------------

inline uint ror32(uint x, uint n) { return (x >> n) | (x << (32 - n)); }

// w[0..16] holds the block; w is used as the 64-word schedule.
inline void sha_block(LOCAL uint* h, LOCAL uint* w) {
    for (int t = 16; t < 64; t++) {
        uint s0 = ror32(w[t - 15], 7) ^ ror32(w[t - 15], 18) ^ (w[t - 15] >> 3);
        uint s1 = ror32(w[t - 2], 17) ^ ror32(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] + s0 + w[t - 7] + s1;
    }
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint t1 = hh + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[t] + w[t];
        uint t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

// Rounds only, for a block whose 64-word schedule was precomputed on the host.
inline void sha_rounds_const(LOCAL uint* h, CONST uint* w) {
    uint a = h[0], b = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
    for (int t = 0; t < 64; t++) {
        uint t1 = hh + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[t] + w[t];
        uint t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
        hh = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e; h[5] += f; h[6] += g; h[7] += hh;
}

inline uint b64url(uint v) {
    return v < 26 ? 'A' + v : v < 52 ? 'a' + (v - 26) : v < 62 ? '0' + (v - 52) : v == 62 ? '-' : '_';
}

inline uint b32(uint v) { return v < 26 ? 'a' + v : '2' + (v - 26); }

inline void put_byte(LOCAL uint* msg, uint pos, uint ch) {
    uint sh = (3 - (pos & 3)) * 8;
    msg[pos >> 2] = (msg[pos >> 2] & ~(0xFFu << sh)) | (ch << sh);
}

// Byte j (big-endian) of r || s.
inline uint sig_byte(U256 r, U256 s, uint j) {
    U256 x = j < 32 ? r : s;
    uint k = j & 31;
    return (x.v[7 - (k >> 2)] >> (24 - 8 * (k & 3))) & 0xFF;
}

// Writes the signature into the message, hashes it and matches the identifier.
inline bool check(CONST Params& P, U256 r, U256 s) {
    uint msg[32];
    for (int i = 0; i < 32; i++) msg[i] = P.tmpl[i];

    uint pos = P.slot;
    for (uint g = 0; g < 21; g++) {
        uint b0 = sig_byte(r, s, 3 * g), b1 = sig_byte(r, s, 3 * g + 1), b2 = sig_byte(r, s, 3 * g + 2);
        put_byte(msg, pos++, b64url(b0 >> 2));
        put_byte(msg, pos++, b64url(((b0 & 3) << 4) | (b1 >> 4)));
        put_byte(msg, pos++, b64url(((b1 & 15) << 2) | (b2 >> 6)));
        put_byte(msg, pos++, b64url(b2 & 63));
    }
    uint last = sig_byte(r, s, 63);
    put_byte(msg, pos++, b64url(last >> 2));
    put_byte(msg, pos, b64url((last & 3) << 4));

    uint h[8];
    for (int i = 0; i < 8; i++) h[i] = SHA_H0[i];
    uint w[64];
    for (int blk = 0; blk < 2; blk++) {
        for (int i = 0; i < 16; i++) w[i] = msg[blk * 16 + i];
        sha_block(h, w);
    }
    for (int blk = 2; blk < 8; blk++) sha_rounds_const(h, P.sched + (blk - 2) * 64);

    // First 15 bytes of the hash as 24 base32 characters.
    uint id[24];
    for (uint i = 0; i < 24; i++) {
        uint bit = 5 * i, word = bit >> 5, off = bit & 31;
        ulong pair = ((ulong)h[word] << 32) | (ulong)h[word + 1];
        id[i] = b32((uint)(pair >> (59 - off)) & 31);
    }

    uint len = P.len;
    if (P.mode == 0) {
        for (uint i = 0; i < len; i++) if (id[i] != P.value[i]) return false;
        return true;
    }
    if (P.mode == 1) {
        for (uint i = 0; i < len; i++) if (id[24 - len + i] != P.value[i]) return false;
        return true;
    }
    for (uint start = 0; start + len <= 24; start++) {
        bool ok = true;
        for (uint i = 0; i < len && ok; i++) ok = id[start + i] == P.value[i];
        if (ok) return true;
    }
    return false;
}

// --- the per-thread loop ------------------------------------------------------

inline void record_hit(DEVICE uint* hit, uint tid, U256 r, U256 s) {
#ifdef __METAL_VERSION__
    if (atomic_fetch_add_explicit((device atomic_uint*)hit, 1u, memory_order_relaxed) != 0) return;
#else
    if (hit[0]++ != 0) return;
#endif
    hit[1] = tid;
    for (int i = 0; i < 8; i++) {
        hit[2 + i] = r.v[i];
        hit[10 + i] = s.v[i];
    }
}

inline void run_thread(CONST Params& P, LOCAL U256& k, LOCAL U256& x, LOCAL U256& y, uint tid,
                       DEVICE uint* hit, DEVICE uint* dbg) {
    U256 d, z;
    for (int i = 0; i < 8; i++) {
        d.v[i] = P.d[i];
        z.v[i] = P.z[i];
    }

    for (uint chunk = 0; chunk < P.chunks; chunk++) {
        // R_i = R_0 + i*G in Jacobian coordinates.
        U256 X[BATCH], Z[BATCH], fpre[BATCH], kinv[BATCH];
        Jac cur;
        cur.x = x;
        cur.y = y;
        cur.z = u_small(1);
        for (int i = 0; i < BATCH; i++) {
            X[i] = cur.x;
            Z[i] = cur.z;
            cur = add_g(cur);
        }

        // Invert every Z, plus the next start point's, with one field inversion.
        U256 acc = u_small(1);
        for (int i = 0; i < BATCH; i++) {
            acc = fmul(acc, Z[i]);
            fpre[i] = acc;
        }
        U256 inv = finv(fmul(acc, cur.z));
        U256 zl = fmul(inv, fpre[BATCH - 1]);
        inv = fmul(inv, cur.z);
        for (int i = BATCH - 1; i > 0; i--) {
            U256 zi = Z[i];
            Z[i] = fmul(inv, fpre[i - 1]);
            inv = fmul(inv, zi);
        }
        Z[0] = inv;

        // Invert every nonce k_i = k + i with one scalar inversion.
        U256 ki = k;
        acc = u_small(1);
        for (int i = 0; i < BATCH; i++) {
            acc = smul(acc, ki);
            kinv[i] = acc;
            ki = sadd(ki, u_small(1));
        }
        inv = sinv(acc);
        for (int i = BATCH - 1; i > 0; i--) {
            U256 k_i = sadd(k, u_small((uint)i));
            kinv[i] = smul(inv, kinv[i - 1]);
            inv = smul(inv, k_i);
        }
        kinv[0] = inv;

        for (int i = 0; i < BATCH; i++) {
            U256 zinv = Z[i];
            U256 r = fmul(X[i], fsqr(zinv));
            if (u_gte(r, N_MOD)) {
                uint b;
                r = u_sub(r, u_load(N_MOD), b);
            }
            U256 s = smul(kinv[i], sadd(z, smul(r, d)));
            if (u_gt(s, N_HALF)) {
                uint b;
                s = u_sub(u_load(N_MOD), s, b);
            }
            if (u_is_zero(r) || u_is_zero(s)) continue;

            bool matched = check(P, r, s);
            if (P.debug != 0) {
                DEVICE uint* out = dbg + ((tid * P.chunks + chunk) * BATCH + (uint)i) * 17;
                for (int j = 0; j < 8; j++) {
                    out[j] = r.v[j];
                    out[8 + j] = s.v[j];
                }
                out[16] = matched ? 1 : 0;
            }
            if (matched) record_hit(hit, tid, r, s);
        }

        // Advance to the next chunk: affine R_BATCH and k + BATCH.
        U256 zl2 = fsqr(zl);
        x = fmul(cur.x, zl2);
        y = fmul(cur.y, fmul(zl2, zl));
        k = sadd(k, u_small(BATCH));
    }
}

#ifdef __METAL_VERSION__
kernel void grind(constant Params& P [[buffer(0)]],
                  device uint* state [[buffer(1)]],
                  device uint* hit [[buffer(2)]],
                  device uint* dbg [[buffer(3)]],
                  uint tid [[thread_position_in_grid]]) {
    device uint* st = state + tid * 24;
    U256 k, x, y;
    for (int i = 0; i < 8; i++) {
        k.v[i] = st[i];
        x.v[i] = st[8 + i];
        y.v[i] = st[16 + i];
    }
    run_thread(P, k, x, y, tid, hit, dbg);
    for (int i = 0; i < 8; i++) {
        st[i] = k.v[i];
        st[8 + i] = x.v[i];
        st[16 + i] = y.v[i];
    }
}
#endif
