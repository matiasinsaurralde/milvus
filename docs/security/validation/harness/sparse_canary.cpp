#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <stdexcept>

static constexpr size_t kElementSize = 8;

static bool detect_overflow_with_canary(size_t size) {
    size_t num_elements = size / kElementSize;
    size_t alloc = num_elements * kElementSize;
    auto* buf = new uint8_t[alloc + 16];
    for (int i = 0; i < 16; i++) buf[alloc + i] = 0xC5;

    auto* data = new uint8_t[size];
    std::memset(data, 0x11, size);
    for (size_t i = alloc; i < size; i++) data[i] = 0xEE;

    // BUG pattern from CopyAndWrapSparseRow: memcpy(size) into floor(size/8)*8 buffer
    std::memcpy(buf, data, size);

    bool corrupted = false;
    for (int i = 0; i < 16; i++) {
        if (buf[alloc + i] != 0xC5) { corrupted = true; break; }
    }
    std::fprintf(stderr, "size=%zu alloc=%zu overflow_bytes=%zu canary_corrupted=%s\n",
                 size, alloc, size - alloc, corrupted ? "YES" : "NO");
    delete[] data;
    delete[] buf;
    return corrupted;
}

static void buggy_copy_and_wrap(const void* data, size_t size, bool validate) {
    size_t num_elements = size / kElementSize;
    auto* row = new uint8_t[num_elements * kElementSize];
    std::memcpy(row, data, size); // overflow happens here when size%8!=0
    if (validate) {
        if (size % kElementSize != 0) {
            std::fprintf(stderr, "validate failed AFTER memcpy\n");
            delete[] row;
            throw std::runtime_error("invalid size");
        }
    }
    delete[] row;
}

int main() {
    const size_t size = 71; // 8*8+7
    if (!detect_overflow_with_canary(size)) {
        std::fprintf(stderr, "UNEXPECTED: canary not corrupted\n");
        return 2;
    }
    uint8_t payload[71];
    std::memset(payload, 0x42, sizeof(payload));
    try {
        buggy_copy_and_wrap(payload, sizeof(payload), true);
        std::fprintf(stderr, "UNEXPECTED: no exception\n");
        return 3;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "caught after overflow: %s\n", e.what());
    }
    std::fprintf(stderr, "VALIDATION_OK: overflow-before-validate reproduced\n");
    return 0;
}
