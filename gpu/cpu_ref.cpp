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
