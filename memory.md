# Memory-safety review — Milvus core

Scope: full-codebase audit of the memory-unsafe surfaces reachable from
untrusted input (C++ segcore/deserialize, import/storage parsing, Go `unsafe`/cgo,
Rust FFI). Reachability chains were traced by code; the two write-overflows were
validated with AddressSanitizer PoCs that reproduce the exact vulnerable
arithmetic at unit level (a full cluster+gRPC E2E build of the C++ core is not
practical in a sandbox).

Findings are grouped by exploit class. **Two are RCE-grade heap-overflow writes**
(both ASan-confirmed); the rest are out-of-bounds reads (info-leak/crash) and DoS.

---

## Summary table

| ID | Class | Location | Verdict |
|----|-------|----------|---------|
| C1 | Heap overflow (write) | `common/VectorArray.h:57-70` | Crash + strong RCE potential |
| C2 | Heap overflow (write) | `common/Utils.h:276-299` | Crash/DoS + limited RCE |
| H1 | OOB read | `common/FieldData.cpp:362-374,740-748` | Info-leak / crash |
| H2 | OOB read | `common/FieldData.cpp:445-469` | Info-leak / crash |
| D1 | SIGFPE (DoS) | `common/VectorArray.h:62,88,108` | Node crash |
| D2 | Panic (DoS) | `util/segcore/plan.go:210` | Querynode crash |
| D3 | Panic (DoS) | `importutilv2/numpy/field_reader.go:93-124` | Import-worker crash |
| D4 | Integer underflow (DoS) | `storage/BinlogReader.cpp:27-50` | Robustness gap |
| R1 | Rust UB / OOB read | `tantivy-binding/src/string_c.rs:8` | Crash |
| L1 | Latent cgo size mismatch | `util/segcore/segment.go:261-307` | Guarded today |

Root pattern behind C1, D1, H1, H2: **C++ deserialization trusts an
attacker-controlled dimension (per-row proto `dim` or Arrow `DIM_KEY`) that Go
validated only against the schema dim — the two are independent and must be
cross-checked at the C++ construction site.**

---

## 🔴 Critical — RCE candidates (attacker-controlled heap-overflow WRITE)

### C1. `VectorArray` float-branch heap overflow — controlled size and content

**`internal/core/src/common/VectorArray.h:57-70`** (the `kFloatVector` case)

```cpp
dim_ = vector_field.dim();                                 // :57  per-row proto dim — attacker-controlled
length_ = vector_field.float_vector().data().size()/dim_;  // :62  truncating divide
auto data = new float[length_ * dim_];                     // :63  buffer sized (N/dim)*dim floats
size_ = vector_field.float_vector().data().size()*sizeof(float);
FastMemcpy(data, ...data().data(), ...data().size()*sizeof(float)); // :66-69  copies ALL N floats
```

The buffer holds `length_*dim_ = (N/dim_)*dim_` floats but the memcpy copies all
`N`. When `N % dim_ != 0` it overruns; with `dim_ > N` (e.g. `dim_=2^20`, `N=8`)
`length_=0`, the allocation is `new float[0]`, and it writes `N*4` attacker-
controlled bytes into a zero-length block. `N` is bounded only by request size,
so this is a large, content-controlled heap overflow. The sibling branches
(binary/fp16/bf16/int8) size the buffer from the real byte length and are safe —
**only the float branch is broken.**

- **Reachability:** Insert/upsert of an `ArrayOfVector` field with float element
  type. The proxy gate `checkArrayOfVectorFieldData` validates each row's float
  length against the **schema** dim only —
  `validateVectorCount(len(floatVector.GetData()), int(dim))` where
  `dim = typeutil.GetDim(fieldSchema)` (`internal/proxy/validate_util.go:1185,1226`).
  It **never validates the per-row proto field `VectorField.dim`**. The attacker
  makes `len(data) % schema_dim == 0` (passes Go) while setting the per-row `dim`
  to anything. That proto passes through the WAL/pipeline unchanged (`CheckAligned`
  only checks row counts) to the growing segment:
  `ConcurrentVector.cpp:~90` → `VectorArray(vector_array[i])` → the constructor above.
- **Corrupted object:** the freshly `new[]`-ed float buffer and adjacent heap
  (contents = attacker's float bytes).
- **Verdict:** heap overflow, attacker-controlled length + content → **crashes
  reliably; strong RCE potential.** ASan PoC: `WRITE of size 32, 0 bytes after
  1-byte region`.
- **Fix:** validate `dim_ > 0` and `dim_ == schema_dim`, reject
  `data().size() % dim_ != 0`, and copy `length_*dim_*sizeof(float)` (not
  `N*sizeof(float)`). The same missing check causes the `dim_==0` SIGFPE (D1).

### C2. `CopyAndWrapSparseRow` copies before it validates

**`internal/core/src/common/Utils.h:276-299`**

```cpp
size_t num_elements = size / element_size();   // element_size()==8
SparseRow row(num_elements);                   // allocates num_elements*8 bytes
FastMemcpy(row.data(), data, size);            // copies `size` bytes  ← OVERFLOW
if (validate) { AssertInfo(size % element_size()==0, ...); ... }  // too late
```

When `size` isn't a multiple of 8, the buffer is `(size/8)*8` bytes but `size`
bytes are copied — up to a 7-byte overflow. The `size%8` assert meant to catch
this runs **after** the memcpy, so even `validate=true` does not prevent it.

- **Reachability:** Search with a `SparseFloatVector` placeholder.
  `query/Plan.cpp:174` → `SparseBytesToRows(ph.values(), /*validate=*/true)` →
  `CopyAndWrapSparseRow(row.data(), row.size(), true)`. The placeholder bytes are
  parsed straight from the request proto and are **not** length-validated in Go on
  the search path — `ValidateSparseFloatRows`
  (`pkg/util/typeutil/schema.go:3772`, which checks `len%8`) runs only on
  insert/import; `ConvertPlaceholderGroup`
  (`internal/proxy/vector_type_convert.go:84-98`) passes sparse placeholders
  through untouched. Attacker sends a sparse query row of length e.g. 13.
- **Corrupted object:** the `SparseRow` heap buffer / adjacent heap (≤7 attacker
  bytes).
- **Verdict:** smaller overflow → **crash/DoS; limited RCE.** The intended defense
  (`validate=true`) is defeated by ordering. ASan PoC: `WRITE of size 13, 0 bytes
  after 8-byte region`.
- **Fix:** move the `size % element_size() == 0` check **before** the
  allocation/memcpy and throw on failure. This also hardens the insert path
  (`ConcurrentVector.cpp:48`, `validate=false`).

---

## 🟠 High — attacker-controlled OOB reads (info-leak / crash)

### H1. Nullable-vector binlog deserialize trusts `dim` metadata, never checks row length

**`internal/core/src/common/FieldData.cpp:362-374`** + `FillFieldData` memcpy
(`:740-748`), reached via `storage/PayloadReader.cpp:85-115`. Nullable vectors are
stored as variable-length `arrow::binary()` with the width carried only in Arrow
metadata `DIM_KEY` (`stoi`, checked `>0` only). The read copies
`valid_count*dim_*sizeof(T)` bytes from the concatenated value buffer with no check
that rows are actually `dim_*sizeof(T)` wide → OOB read of adjacent heap (over-read
surfaces as vector data → info disclosure, or segfaults). The Go import reader
*does* enforce this (`importutilv2/parquet/field_reader.go:945`); the C++ path
does not. **Fix:** assert `total_values_length == valid_count*dim_*sizeof(T)`
before the copy.

### H2. `VECTOR_ARRAY` binlog deserialize: metadata dim vs FixedSizeBinary width mismatch

**`internal/core/src/common/FieldData.cpp:445-469`**. `bytes_per_vec` derives from
attacker-controlled metadata `DIM_KEY`/`ELEMENT_TYPE_KEY`; the per-element copy
trusts it and never compares to `binary_array->byte_width()` → per-element OOB
read. **Fix:** `AssertInfo(bytes_per_vec == binary_array->byte_width())`.

> H1/H2 require the attacker to influence stored binlog/import payloads rather than
> a direct RPC field, so they are one trust-hop further out than C1/C2, but they
> are real missing-validation OOB reads on the load path.

---

## 🟡 Medium — DoS (remotely triggerable crash, memory-safe)

- **D1. `VectorArray` per-row `dim==0` → SIGFPE** (`VectorArray.h:62,88,108`) —
  same unchecked per-row dim as C1; a single crafted insert crashes the node.
  Fixed by the same `dim_>0`/`==schema_dim` guard.
- **D2. Empty retrieve-plan panic** (`internal/util/segcore/plan.go:210`) —
  `NewRetrievePlan` indexes `&expr[0]` with no `len==0` guard;
  `proto.Unmarshal(nil,...)` succeeds upstream, so an empty `SerializedExprPlan`
  on a Query RPC panics the querynode. The sibling search path (`plan.go:48`) has
  the guard; retrieve is missing it.
- **D3. numpy shape-product overflow**
  (`internal/util/importutilv2/numpy/field_reader.go:93-124`) — `total *= shape[i]`
  over an unbounded header shape wraps negative → `make([]T, negativeN)` panic. A
  header-only `.npy` crashes the import worker. **Fix:** bound each `shape[i]>=0`
  and detect overflow before allocating.
- **D4. `BinlogReader::Read` negative-length**
  (`storage/BinlogReader.cpp:27-50`, `storage/Event.cpp:260`) —
  `payload_length = event_length - 16` can underflow negative; the
  `nbytes > remain` check passes a negative `nbytes` and moves the cursor
  backward. Add `nbytes < 0` rejection.

---

## 🟡 Medium — Rust FFI (OOB read, DoS)

- **R1. `from_utf8_unchecked` on attacker analyzer text**
  (`internal/core/thirdparty/tantivy/tantivy-binding/src/string_c.rs:8`) —
  `c_str_to_str` builds a `&str` over unchecked bytes; reached from
  `RunAnalyzer`/BM25 `analyze()` (`internal/querynodev2/services.go:1652`,
  `internal/util/function/bm25_function.go:265`) with no UTF-8 guard (the insert
  path *has* `checkInputUtf8Compatiable`; the analyzer twin dropped it). Non-UTF-8
  input is immediate UB → tantivy's `char_indices` reads past the buffer → OOB
  read/crash. **Fix:** validate UTF-8 centrally in `c_str_to_str` (return
  `Result`), mirroring the safe `cstr_to_str!` macro used by the search-query
  entry points.

---

## Latent / defense-in-depth (currently guarded — worth hardening, not exploitable today)

- **L1. Insert/Delete cgo boundary** (`internal/util/segcore/segment.go:261-307`)
  passes one count for two Go arrays (`RowIDs`/`Timestamps`); safe only because
  `CheckAligned` runs in the pipeline filter first. No local assertion — any
  alternate caller (import/recovery/replication replay) reaching
  `LocalSegment.Insert/Delete` without `CheckAligned` gets a C++ OOB read. Add a
  `len(RowIDs)==len(Timestamps)` assert at the boundary.

The Go `unsafe`/cgo audit otherwise came back clean: `minhash_function.go`,
`fastpb/unsafeopt.go`, `cgoconverter`, and the varchar-PK parser all bounds-check
or derive lengths from the same C struct. Rust ownership (`into_raw`/`from_raw`
pairs, token free paths) is balanced — no double-free/leak.

---

## Fix priority

1. **C1** — fix first: the only RCE-grade primitive with controllable size and
   content; the fix also closes D1.
2. **C2** — reorder the sparse validation (one-line move) to restore the intended
   guard.
3. **H1/H2** — add width assertions on the C++ load path.
4. **R1 + D2/D3/D4** — cheap guards closing remote DoS.

---

## PoC validation (AddressSanitizer)

Both PoCs reproduce the exact source arithmetic (`std::memcpy` stands in for
`FastMemcpy`; `SparseRow`/`VectorField` are faithful layout stand-ins) and were
compiled with `g++ -fsanitize=address`.

**C1 — VectorArray float branch** (`dim_=2^20`, `N=8` floats → `new float[0]`,
copy 32 bytes):

```
==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 32 at 0x... thread T0
    #0 memcpy
    #1 main poc_vectorarray.cpp:40
0x...11 is located 0 bytes after 1-byte region [0x...10,0x...11)
allocated by: operator new[]  (poc_vectorarray.cpp:38  ->  new float[length_*dim_])
```

**C2 — CopyAndWrapSparseRow** (`size=13` → 8-byte `SparseRow`, copy 13 bytes):

```
==ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 13 at 0x... thread T0
    #0 memcpy
    #1 main poc_sparse.cpp:36
0x...18 is located 0 bytes after 8-byte region [0x...10,0x...18)
allocated by: SparseRow::SparseRow(unsigned long)  (poc_sparse.cpp:22)
```
