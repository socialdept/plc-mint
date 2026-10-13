// Compiles gpu/kernel.metal for the CPU, so its math can be tested with
// `cargo test --features gpu-ref` on any machine.

#include <cstdint>

typedef uint32_t uint;
typedef uint64_t ulong;

#define BATCH 8
#include "kernel.metal"

extern "C" uint plcmint_ref_batch() { return BATCH; }

// Runs `threads` kernel threads in sequence over the same state layout as the GPU.
extern "C" void plcmint_ref_run(const Params* params, uint* state, uint threads, uint* hit, uint* dbg) {
    for (uint tid = 0; tid < threads; tid++) {
        uint* st = state + tid * 24;
        U256 k, x, y;
        for (int i = 0; i < 8; i++) {
            k.v[i] = st[i];
            x.v[i] = st[8 + i];
            y.v[i] = st[16 + i];
        }
        run_thread(*params, k, x, y, tid, hit, dbg);
        for (int i = 0; i < 8; i++) {
            st[i] = k.v[i];
            st[8 + i] = x.v[i];
            st[16 + i] = y.v[i];
        }
    }
}

// One kernel arithmetic op on little-endian limbs, for tests:
// 0 fmul, 1 fsqr, 2 finv, 3 smul, 4 ssqr, 5 sinv, 6 fadd, 7 fsub, 8 sadd.
extern "C" void plcmint_ref_op(uint op, const uint* a, const uint* b, uint* out) {
    U256 x, y, r;
    for (int i = 0; i < 8; i++) {
        x.v[i] = a[i];
        y.v[i] = b[i];
    }
    switch (op) {
        case 0: r = fmul(x, y); break;
        case 1: r = fsqr(x); break;
        case 2: r = finv(x); break;
        case 3: r = smul(x, y); break;
        case 4: r = ssqr(x); break;
        case 5: r = sinv(x); break;
        case 6: r = fadd(x, y); break;
        case 7: r = fsub(x, y); break;
        default: r = sadd(x, y); break;
    }
    for (int i = 0; i < 8; i++) out[i] = r.v[i];
}
