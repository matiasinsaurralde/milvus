# Runbook: Sparse search heap overflow (`CopyAndWrapSparseRow`)

## Status

**Partially validated in this environment (2026-07-21).**

| Layer | Result |
|-------|--------|
| Bug pattern (alloc `floor(size/8)*8`, memcpy `size`, then validate) | **Confirmed** via standalone canary + AddressSanitizer |
| Proxy search path skips `ValidateSparseFloatRows` when types match | **Confirmed** via unit test |
| Full segcore / querynode ASAN with real `Search` RPC | **Not run here** (C++ core not built in this agent image) — steps below |

Overflow magnitude is `size % 8` (1–7) attacker-controlled bytes. Realistic impact: heap corruption / probabilistic crash DoS. Not a demonstrated native RCE.

## Root cause

```272:280:internal/core/src/common/Utils.h
CopyAndWrapSparseRow(...) {
    size_t num_elements = size / element_size();  // floor
    SparseRow row(num_elements);                  // alloc floor*8
    FastMemcpy(row.data(), data, size);           // copy full size  ← overflow
    if (validate) {
        AssertInfo(size % element_size() == 0, ...);  // too late
```

Search path calls this with `validate=true` from `query/Plan.cpp` after `ParsePlaceholderGroup`. The proxy's `ConvertPlaceholderGroup` returns sparse placeholders **unchanged** when types already match (`vector_type_convert.go`) — it never calls `ValidateSparseFloatRows` (that helper is insert/upsert-only).

## 1. Canary + ASAN (no Milvus build)

```bash
g++ -O0 -g -std=c++17 \
  -o /tmp/sparse_canary \
  docs/security/validation/harness/sparse_canary.cpp
/tmp/sparse_canary
# Expect:
#   size=71 alloc=64 overflow_bytes=7 canary_corrupted=YES
#   validate failed AFTER memcpy
#   VALIDATION_OK: overflow-before-validate reproduced

g++ -O0 -g -std=c++17 -fsanitize=address -fno-omit-frame-pointer \
  -o /tmp/sparse_canary_asan \
  docs/security/validation/harness/sparse_canary.cpp
/tmp/sparse_canary_asan
# Expect: AddressSanitizer: heap-buffer-overflow
#   WRITE of size 71 ... located 0 bytes after 64-byte region
```

Evidence from this agent run:

- `docs/security/validation/evidence/sparse_canary_canary.txt`
- `docs/security/validation/evidence/sparse_canary_asan.txt`

## 2. Proxy unit test (documents the missing check)

```bash
go test -tags dynamic,test -gcflags="all=-N -l" -count=1 \
  ./internal/proxy/ -run TestConvertPlaceholderGroupSparseInvalidLengthPassThrough -v
```

**Pass criteria today (bug present):** test **PASSES** — invalid 71-byte sparse row is passed through with `err == nil`.

**After a proxy-side fix** that rejects `len%8!=0` on search placeholders, this test should be updated to expect an error (or replaced with a positive validation test).

## 3. End-to-end on ASAN-instrumented querynode / standalone

**Prefer the curl + Python gRPC checklist:** [end_user_http_triggers.md](./end_user_http_triggers.md) §1.

Requires a Milvus build with segcore linked with AddressSanitizer (or running under a heap debugger) only if you want ASAN proof; a stock docker image still exercises the overflow (usually as a returned error after the bad memcpy).

1. Setup collection/insert/load with curl (valid sparse JSON maps).
2. Run `harness/sparse_search_trigger.py` (gRPC Search with 71-byte sparse placeholder).
3. **Pass criteria (bug present):** ASAN reports `heap-buffer-overflow` in `CopyAndWrapSparseRow` / `memcpy` / `FastMemcpy`, **or** RPC returns a plan/parameter error after the overflow already occurred. Note: `AssertInfo` throws `SegcoreError` after the copy; cgo catches it — so the client may see a clean error while the heap was already corrupted.

Without ASAN, single-request crashes may be rare (≤7 bytes); repeated malformed searches increase chance of delayed crash.

**REST-only curl cannot trigger this** — JSON sparse maps are re-encoded to `len%8==0` before placeholders are built.

## Fix verification

Move the `size % element_size() == 0` check **before** allocation/`FastMemcpy` in `CopyAndWrapSparseRow`, and/or call `ValidateSparseFloatRows` in the proxy search path. After the fix:

- Canary with validate-before-copy should leave the canary intact / ASAN clean.
- E2E Search with length 71 should return a parameter error with **no** ASAN overflow.
