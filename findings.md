# Milvus Security Variant Hunt — Findings

**Repo:** milvus-io/milvus (fork: matiasinsaurralde/milvus)
**HEAD:** `b7cbb91a161c1830bd0a54e024c48cb8dc8f468d`
**Branch:** `claude/milvus-security-variants-hgddyk`
**Focus:** RCE and DoS paths (memory-corruption prioritized), with reachability gated on attacker → input → sink and adversarial falsification of each candidate.

> **Verification caveat.** This environment could **not** build or run the C++ segcore, **nor** the
> cgo-dependent Go packages (`internal/proxy` and friends fail with missing `milvus_core` / `rdkafka` /
> `rocksdb` / `milvus-storage` pkg-config — confirmed empirically). Every finding below is verified by
> direct source inspection and control-/data-flow reasoning, and each fix mirrors an existing in-tree
> pattern. **No fix, and no repro, has been compiled or run here** — including the Go authz test (A1),
> which needs the compiled core on `PKG_CONFIG_PATH`. The [How to test](#how-to-test-in-your-environment)
> section and each finding give concrete, runnable build + repro steps (AddressSanitizer / ThreadSanitizer
> unit tests + end-to-end) for a full build.

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
| C1 | Growing-segment reopen data race on non-atomic `schema_` → conditional UAF | Data race / UAF (RCE-relevant) | **External** — `AddCollectionField` + concurrent Search on a growing segment | ⚠️ Documented, not fixed |
| C2 | StorageV1 index mmap-target path missing generation suffix → SIGBUS / corrupt-index OOB | Data race (crash / memory corruption) | **External-triggered** — index rebuild / load-release cycling | ⚠️ Documented, not fixed |
| A1 | `RestoreSnapshot` cross-database privilege bypass | Authz bypass (cross-db privilege escalation) | **External** — user with `RestoreSnapshot` on any one db | ⚠️ Documented, not fixed |

Killed / cleared candidates are listed at the [end](#killed--cleared). The three
[concurrency/authz threads](#concurrency--authz-findings-threads-1-3) resumed from the prior hunt are
written up in their own section.

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

## Concurrency & authz findings (threads #1–#3)

These resume the three residual threads from the prior hunt: #2 segcore reopen staging (prioritized,
RCE scope), #1 local index-cache TOCTOU, #3 RBAC `DBNameGetter`. Verification note: memory-safety
concurrency bugs need a running build with sanitizers, which this environment lacks — each item below
gives a ThreadSanitizer/AddressSanitizer repro plan. **No TSan build option exists today** (only
`USE_ASAN`, `CMakeLists.txt:230-233`); the plans include the one-block CMake change to add
`-fsanitize=thread`. ASan catches the *outcome* (heap-use-after-free / SIGBUS) when the interleaving
hits; TSan catches the *race* regardless of timing.

### C1 — Growing-segment reopen: data race on non-atomic `schema_` → conditional UAF (thread #2, EXTERNAL)

**This is the live result of the reopen audit.** The **sealed** reopen path is sound (see "cleared"
below); the **growing** path is not.

`SegmentGrowingImpl::Reopen` (`internal/core/src/segcore/SegmentGrowingImpl.cpp:2554-2624`) publishes a
new schema by overwriting the plain member `SchemaPtr schema_` in place — `schema_ = sch;` at **`:2613`**
— while holding `std::unique_lock(sch_mutex_)` (`:2556`). But:
- **`sch_mutex_` is held by exactly two functions in the whole tree** (verified by grep): `Insert`
  (`:644`, shared) and `Reopen` (`:2556`, unique). **No query reader takes it.**
- **Growing segments have no read gate:** `AcquireSegmentReadLease` returns `nullptr` for
  `SegmentType::Growing` (`internal/core/src/segcore/segment_c.cpp:415-417`). The sealed drain gate that
  serializes reopen-vs-read does not exist here.
- Reader paths dereference `schema_` lock-free: `SegmentGrowingImpl::get_schema()` returns `*schema_`
  (`SegmentGrowingImpl.h:217-218`, a bare `const Schema&`), consumed by `query::SearchOnGrowing`
  (`SearchOnGrowing.cpp:65` `auto& schema = segment.get_schema();`, `:69` `auto& field =
  schema[vecfield_id];` — a `const FieldMeta&` held **for the whole search**), and by
  `bulk_subscript` (`:1616,1643`), plus ~40 other `schema_->` sites, none under `sch_mutex_`.

**Reachability (external):** a loaded growing segment (recently-inserted, not-yet-flushed data) serving
concurrent `Search`/`Query` while `AddCollectionField` raises the collection schema version → the next
query's `LazyCheckSchema` (`segment_c.cpp:487`, called *before* any lease) invokes `Reopen`, swapping
`schema_` under a reader.

**Failure modes:**
- **Data race (confirmed, UB):** concurrent non-atomic read (`schema_->…` in one thread) and write
  (`schema_ = sch` in another) of a `shared_ptr` is a data race by the C++ memory model — TSan will flag
  it deterministically. (On x86-64 a single-word `operator->` deref reads a coherent old-or-new pointer,
  so it does not *itself* tear into a wild pointer; the escalation below is the memory-safety impact.)
- **Use-after-free (conditional):** `schema_ = sch` drops the segment's strong ref to the old `Schema`.
  If that was the **last** strong ref, `~Schema()` frees the `FieldMeta` storage while an in-flight
  `SearchOnGrowing` still holds `const FieldMeta& field` into it → heap-use-after-free read (dim /
  data-type / analyzer-params consumed downstream). Whether it is the last ref depends on other holders
  (the triggering query's own plan schema, any querynode collection-schema cache). **This lifetime
  condition is the open question the repro settles** — I did not prove the old `Schema` is uniquely
  owned by the segment at swap time, so C1 is reported as a *confirmed data race with a
  lifetime-conditional UAF escalation*, not a proven unconditional UAF.

**Why the existing test misses it:** `internal/core/unittest/test_growing_concurrent_reopen.cpp` reads
only an existing field and **retains strong refs to every schema version for the whole round**, so no
old `Schema` is ever freed (masks the UAF), and it runs without TSan (misses the race).

**Repro plan.** Build ASan: `scripts/core_build.sh -a`. Extend `test_growing_concurrent_reopen.cpp`:
(1) a writer thread looping `impl->Reopen(make_schema(k))` where each `make_schema` **adds a field**
(changes field count) and the temporary is **not retained** (so the swap drops the old schema's last
external ref); (2) reader threads looping `vector_search` / `Retrieve` (they hold `const FieldMeta&`
across the call, unlike single-offset scalar `bulk_subscript`). Expected ASan: `heap-use-after-free
READ`, free stack in `~Schema` / `shared_ptr<Schema>::operator=` from `Reopen …:2613`, use stack in
`SearchOnGrowing.cpp:69`. For the race independent of the free, add a TSan build (CMake block below) —
it reports `data race … Write … SegmentGrowingImpl.cpp:2613` vs `Read … SearchOnGrowing.cpp:65` on the
`schema_` member on the first overlap, even with all schemas retained.

```cmake
# add to internal/core/CMakeLists.txt next to the USE_ASAN block (~:230), + a -t flag in core_build.sh
if (USE_TSAN STREQUAL "ON")
    add_compile_options(-fno-omit-frame-pointer -fsanitize=thread)
    add_link_options(-fsanitize=thread)
endif()
```

**Fix direction (not applied):** bring the growing path to the sealed discipline — either make readers
capture an **owning** `SchemaPtr` snapshot for the query lifetime (return `SchemaPtr` from
`get_schema()` / atomically publish `schema_` via `std::atomic_load`/`atomic_store` COW), or hold
`sch_mutex_` (shared) across every `schema_` deref. Per G1 the fix must cover *all* ~40 `schema_`/
`get_schema()` read sites, not just `bulk_subscript`.

**Cleared (sealed reopen):** the sealed path (`ChunkedSegmentSealedImpl`) is sound. `published_state_`
is accessed only via `std::atomic_load`/`atomic_store` (`:960,1963,4776` — no plain member read exists);
writes clone-on-write (`BuildNextPublishedState`→`ClonePublishedState`, bitsets `.clone()`d) then
`atomic_store`; destructive `DropFieldData`/`DropIndex` and all `Reopen` overloads stage into a fresh
clone and publish under the `SegmentReadGate` **Drain** (`SegmentReadLease.h:198-244`), which blocks
until `active_readers==0`; the query-time `LazyCheckSchema` uses **FailFast** (refuses to publish while
readers are active). The read lease is held for the entire search+result lifetime (`segment_c.cpp:488`
→ `SearchResult::read_lease_`), protecting borrowed spans. **Latent hazards** (defensive, not live):
`ChunkedSegmentSealedImpl::get_schema()` returns a bare `const Schema&` into the now-swappable schema
(`:3575`) — safe for leased query callers but a hazard for auxiliary non-leased callers
(`SegmentInterface.cpp:728,751`); recommend returning `SchemaPtr`. Two invariants could not be verified
in-tree (the `cachinglayer::CacheSlot`/`CacheAccessor` pin-ownership contract, and
`ChunkedColumnInterface::CancelWarmup()` semantics — both external modules absent from this checkout);
they underpin the pin-safety of every span-returning accessor and `DropFieldData`'s pre-drain
`CancelWarmup` (`:4002`).

### C2 — StorageV1 index mmap-target path missing generation suffix → SIGBUS / corrupt-index OOB (thread #1, EXTERNAL-triggered)

The DiskFileManager download-cache fix (#50608) is **complete** — every local prefix routes through
`AppendLocalPathGeneration` (per-instance `g_file_path_generation` suffix) + write-lease
(`DiskFileManagerImpl.cpp`), verified across all getters and their consumers (DiskANN, tantivy, text,
ngram, scalar-sort, json-stats). **But it stops at the mmap-target boundary.** The StorageV1 index
translator builds the mmap file path with **no** generation suffix and **no** lease:

`SealedIndexTranslator::get_cells` (`internal/core/src/segcore/storagev1translator/SealedIndexTranslator.cpp:168-173`):
```cpp
auto base_path = mmap_dir_path / "index_files" / index_id / segment_id / field_id;
config_[MMAP_FILE_PATH] = (base_path / "index").string();   // stable key, no per-instance suffix
```
This feeds `VectorMemIndex::LoadFromFile` / scalar mmap indexes, which `FileWriter`-open the path
`O_CREAT|O_RDWR|O_TRUNC` (`FileWriter.cpp:141`), `mmap(MAP_SHARED)` it, and register
`MmapFileRAII` whose destructor `unlink()`s that exact path (`common/File.h:151`). Two live instances of
the same index cell (same `index_id/segment_id/field_id`) therefore resolve to **one file**:
- **delete/overwrite-while-mmapped:** an evicted-but-still-pinned instance holds the `MAP_SHARED`
  mapping while a replacing load `O_TRUNC`s the same inode → the old mapping reads zero/half-written
  pages → **SIGBUS in a query thread**, or a corrupt-index OOB read.

**In-tree corroboration (decisive):** the repo already fixes this exact race for StorageV2 column
groups — `GroupChunkTranslator.cpp:509-514` appends `g_mmap_path_generation` with the comment *"the new
FileWriter would O_TRUNC the same file that the old translator's MAP_SHARED mmap still references,
causing SIGBUS on concurrent reads."* That guard exists only in the two V2 translators
(`GroupChunkTranslator.cpp:514`, `ManifestGroupTranslator.cpp:489`); the V1 **index**
(`SealedIndexTranslator`) and V1 field-data (`ChunkTranslator.cpp:196`,
`DefaultValueChunkTranslator.cpp:281`) paths were left out. Index cells go through the same
`cachinglayer` CacheSlot machinery, so cell replacement (which the V2 comment names as the trigger) hits
the same window.

**Reachability (external-triggered):** index rebuild / version bump on a loaded collection
(`CreateIndex`/alter — new index version loads while queries run on the old), load/release collection
cycling, or cache eviction + immediate re-query of the same sealed index. The DiskFileManager
generation isolates the *download* cache per load, but the *mmap target* path is shared across those
loads.

**Repro plan.** `scripts/core_build.sh -a -u`. The existing `DiskFileManagerTest.cpp` generation tests
pass and give false confidence (they cover the download cache, not the mmap target). Add a translator-
layer stress test driving two threads at the **same** `MMAP_FILE_PATH`: thread A writes a known byte
pattern, `mmap(MAP_SHARED)`, and loops reads (simulating a pinned in-flight query), then `unlink`s
(simulating `~MmapFileRAII`); thread B loops `FileWriter`(O_TRUNC)+rewrite (simulating a replacing
load). Confirmation: torn reads (pattern B/zero where A's pattern was) and/or SIGBUS when B truncates a
file A still maps beyond new EOF — under ASan a corrupted-read/`heap-use-after-free` report. A self-
contained skeleton using `storage::FileWriter` + raw `mmap`/`unlink` reproduces it without a full
segment. **Fix direction (not applied):** mirror `g_mmap_path_generation` into
`SealedIndexTranslator.cpp:168` (and the two V1 field-data translators) so a replacing load writes a
distinct inode and the old `MmapFileRAII::unlink` only removes its own generation.



### A1 — `RestoreSnapshot` cross-database privilege bypass (thread #3, EXTERNAL, authz)

The db-scope fix #50690 special-cases exactly one cross-db request — `RenameCollection` — forcing the
authorization db to `AnyWord` (cluster scope) when source ≠ target
(`internal/proxy/privilege_interceptor.go:102-104`). `RestoreSnapshotRequest` has the **same
source-db→target-db shape but was not covered**, and it is a **Collection-level** privilege
(`PrivilegeRestoreSnapshot`, `pkg/util/constant.go:370`, in `CollectionAdminPrivileges`), so it is
**not** forced to `AnyWord` at `privilege_interceptor.go:96-98`.

- **Authorization db = source.** `privilege_interceptor.go:95` → `GetCurDBNameFromRequestOrContext` →
  `RestoreSnapshotRequest.GetDbName()` (field #3, source). The authz resource is
  `{source_db, source_collection, RestoreSnapshot}`.
- **Execution db = target.** `internal/proxy/task_snapshot.go:563` uses source `GetDbName()` only to
  resolve the *source* collection; `Execute` (`:587`) sends `TargetDbName: rst.req.GetTargetDbName()`
  (field #6) to datacoord, which creates the restored collection in the **target** db
  (`internal/datacoord/services.go:2501-2506`). No authz is performed against the target db anywhere.

**Bypass:** a user granted `RestoreSnapshot` on `db_a` only issues
`RestoreSnapshotRequest{DbName:"db_a", CollectionName:"c_src", TargetDbName:"db_b",
TargetCollectionName:"c_new"}`. Authz passes (scoped to `db_a`), but the restore **materializes
collection `c_new` inside `db_b`** — a database the user holds no privilege on. Cross-database
privilege escalation, exactly the class #50690 closed for RenameCollection.

**Audit scope:** all 107 privilege-bearing message types (reflected over `commonpb.E_PrivilegeExtObj`)
were classified. Every non-Cluster type implements `DBNameGetter` (so the context-fallback class is
clean), and of the 4 multi-db-field non-Cluster types, `HybridSearch` / `AlterDatabase` /
`RenameCollection` do not diverge. **`RestoreSnapshot` is the sole divergence.**

**Verification status:** by inspection only. This environment **cannot build the Go `proxy` package** —
it depends via cgo/pkg-config on compiled native libs (`milvus_core`, `rdkafka`, `rocksdb`,
`milvus-storage`), which are absent — so the unit-test repro below was **not** run here.

**Repro (unit test — run in a full build).** Add to `internal/proxy/privilege_interceptor_test.go`
(mirrors `TestPrivilegeInterceptorRenameCollection`):

```go
func TestPrivilegeInterceptorRestoreSnapshotCrossDB(t *testing.T) {
    paramtable.Init()
    Params.Save(Params.CommonCfg.AuthorizationEnabled.Key, "true")
    defer Params.Reset(Params.CommonCfg.AuthorizationEnabled.Key)

    client := &MockMixCoordClientInterface{}
    client.listPolicy = func(ctx context.Context, in *internalpb.ListPolicyRequest) (*internalpb.ListPolicyResponse, error) {
        return &internalpb.ListPolicyResponse{
            Status: merr.Success(),
            PolicyInfos: []string{ // RestoreSnapshot granted on db_a only
                funcutil.PolicyForPrivilege("role_snap", commonpb.ObjectType_Collection.String(), "*",
                    commonpb.ObjectPrivilege_PrivilegeRestoreSnapshot.String(), "db_a"),
            },
            UserRoles: []string{funcutil.EncodeUserRoleCache("snapuser", "role_snap")},
        }, nil
    }
    assert.NoError(t, InitMetaCache(context.Background(), client))

    // same-db (db_a->db_a): allowed — validates the grant matches.
    _, err := PrivilegeInterceptor(GetContext(context.Background(), "snapuser:pwd"),
        &milvuspb.RestoreSnapshotRequest{DbName: "db_a", CollectionName: "c_src",
            TargetDbName: "db_a", TargetCollectionName: "c_new"})
    assert.NoError(t, err)

    // cross-db (db_a->db_b): MUST be denied. On current HEAD this assertion FAILS
    // (interceptor returns nil = allowed) -> that failure is the proof of bypass.
    _, err = PrivilegeInterceptor(GetContext(context.Background(), "snapuser:pwd"),
        &milvuspb.RestoreSnapshotRequest{DbName: "db_a", CollectionName: "c_src",
            TargetDbName: "db_b", TargetCollectionName: "c_new"})
    assert.Error(t, err)
}
```
Run: `go test -tags dynamic,test -gcflags="all=-N -l" -count=1 ./internal/proxy/ -run TestPrivilegeInterceptorRestoreSnapshotCrossDB`
(requires the compiled core on `PKG_CONFIG_PATH`). Pre-fix: the cross-db assertion **fails** (err nil =
allowed) — the proof. **End-to-end (pymilvus):** create `db_a`+`db_b`; grant a user `RestoreSnapshot`
on `db_a` only; as admin snapshot a collection in `db_a`; as the user restore with `db_name=db_a`,
`target_db_name=db_b`. Secure = PermissionDenied; bug = collection created in `db_b`.

**Fix direction (not applied):** extend the cross-db guard at `privilege_interceptor.go:102-104` to
`RestoreSnapshotRequest` (`GetDbName() != GetTargetDbName()` → `AnyWord`), pre-filling an empty
`TargetDbName` from the context db (as `DatabaseInterceptor` does for `RenameCollection.NewDBName`)
before comparing.

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

## Additional surfaces investigated — cleared / defense-in-depth

These three surfaces were swept for externally-reachable RCE. None yielded a new externally-reachable
memory-corruption bug; each surfaced concrete latent / defense-in-depth gaps worth hardening.

### S1 — StorageV3 / milvus-storage packed reader + external collections

**Important reachability fact:** the external-collection load path is **genuinely attacker-byte
controlled**. A tenant supplies a fully user-chosen URI (`ValidateExternalSource`,
`pkg/util/externalspec/external_spec.go:170` checks only scheme/host/no-userinfo) with their **own**
credentials (`extfs` must be self-sufficient, "no inheritance from Milvus fs.\* config",
`external_spec.go:216`), and the files are **referenced, not copied** into the manifest
(`internal/datanode/external/task_update.go:1003`; `milvus_table_deltalog.go:59` "keep their source
paths … instead of copying"). So a querynode later reads packed/parquet/manifest bytes from storage the
tenant controls — unlike the classic import path (N1), which re-derives dim and re-serializes.

**Why the classic OOB class does NOT reproduce here:** the load path
(`ChunkedSegmentSealedImpl::ApplyLoadDiff` → `LoadColumnGroups` → `ManifestGroupTranslator`) runs
`NormalizeArrowForChunkWriter` / `NormalizeExternalArrowByType` on every field **before** any
`ChunkWriter` touches it (`ManifestGroupTranslator.cpp:475-478`), which validates file-native arrow
widths against the schema dim/type: `ValidateFixedSizeBinaryVectorWidth` (`storage/Util.cpp:1941`),
`ValidateBinaryVectorWidth` (`:1958`), and the LIST→FSB per-row `actual==expected` check *before* the
`FastMemcpy` (`:2157-2168`). A crafted parquet whose vector width ≠ schema dim is rejected with
`SegcoreError`, not an OOB. Manifest `num_rows`/`row_count` is trusted only for accounting (OOM/assert,
not memory access; cross-checked at `GroupChunkTranslator.cpp:202`). loon FFI errors throw
(`loon_ffi/util.cpp:146-151`); no trusted size crosses the boundary as a raw count.

**Latent gap (LOW now, HIGH if it regresses):** `GroupChunkTranslator::load_group_chunk`
(`internal/core/src/segcore/GroupChunkTranslator.cpp:446-550`) feeds file-native arrow **directly** into
`create_group_chunk` with **no** `NormalizeArrowForChunkWriter`, and `ChunkWriter<FixedSizeBinaryArray,T>`
reads `array->length() * dim_ * sizeof(T)` using the **schema** `dim_`, ignoring the arrow `byte_width`
(`ChunkWriter.h:108,138`) — an OOB heap over-read if a narrower FSB reached it. Today this translator is
gated to `storage_version==2` (internal Milvus-written packed segments,
`ChunkedSegmentSealedImpl.cpp:2009-2016`); external collections are pinned to `StorageV3`
(`task_update.go:989`, `milvus_table_refresh.go:216`), so attacker bytes cannot reach it. It becomes
attacker-reachable the moment any external/referenced-file path sets `storage_version==2` or reuses
`GroupChunkTranslator`. **Hardening:** validate arrow `byte_width` unconditionally inside `ChunkWriter` /
`create_group_chunk` (don't rely on the caller normalizing), or add a guarding comment + assert.

### S2 — Scalar ARRAY element access (query-index path: SAFE)

The attacker-controlled query index `arr[i]` (from `nested_path`, `std::stoi` at eval) is
**soundly bounds-checked** at every site: `Array::get_data<T>`/`ArrayView::get_data<T>` assert
`0 <= index < length_` (`Array.h:260-263,530-533`, an always-on throwing `AssertInfo`), and every
evaluator pre-guards `index >= data[offset].length()` (`UnaryExpr.h:485,546,559,588,608`;
`BinaryArithOpEvalRangeExpr.cpp:715`; `TermExpr.cpp:464`; `JsonContainsExpr.cpp:377,416`). String
sub-offsets are Milvus-recomputed at serialization, not raw attacker bytes. Residual **write-side,
size-gated** hardening gaps only:
- **`ArrayChunkWriter` missing uint32 overflow guard** — `internal/core/src/common/ChunkWriter.cpp:287,295`
  push `static_cast<uint32_t>(cursor)` with no check, while sibling `StringChunkWriter` (`:69-71`) and
  `JSONChunkWriter` (`:142-144`) assert `cursor <= UINT32_MAX`. A chunk with >4 GB of array payload wraps
  the header offset → query-time OOB read via `ArrayChunk::View` (`Chunk.h:415-418`). Gated by chunk-size
  limits. **Fix:** add the same assert.
- **`ArrayChunk::View(int idx)`** (`Chunk.h:412-431`) lacks the `idx < row_nums_` assert its
  `VectorArrayChunk::View` sibling has (`Chunk.h:538-542`). Callers pass bounded offsets; defense-in-depth.
- **`Array.h:124` `int size_` accumulator** (`//type risk`) — signed 32-bit total-string-bytes overflow
  → under-alloc + OOB write on the *serialization* path; needs ~2 GB in one array row, blocked by the
  default-on proxy `checkMaxLen`/`checkMaxCap`. Harden to `int64_t`.
- **`std::stoi(nested_path_[0])`** (`UnaryExpr.cpp:462`, `BinaryArithOpEvalRangeExpr.cpp:687`,
  `TermExpr.cpp:415`) throws on a non-numeric/oversize index — controlled exception (query error), not
  corruption.

### S3 — Delete/PK path + search-result reduce (internal-only / self-consistent by construction)

The C++ reduce was refactored (slicing/group-merge moved to Go; `reduce_c.cpp` no longer exists). No
externally-reachable bug; all residuals rely on internal Go construction discipline rather than a C++
invariant:
- **`ParsePksFromIDs` count trust** (`internal/core/src/segcore/Utils.cpp:169-189`) — `pks` is sized from
  the caller `size`, never asserted equal to the proto element count `GetSizeOfIdArray(*ids)`. VARCHAR
  with proto > size → `std::copy` heap OOB **write**; INT64 with proto < size → OOB read. Callers
  (`SegmentGrowingImpl.cpp:1235`, `ChunkedSegmentSealedImpl.cpp:6424`, the `LoadDeletedRecord` pair)
  currently derive both from the same Go source (`internal/util/segcore/segment.go:290`), so the online
  path is self-consistent — luck of construction, not defense. **Fix:** `AssertInfo(size == GetSizeOfIdArray(*ids))`.
- **Delete timestamps length parity** — `internal/querynodev2/services.go:1622,1689` pass
  `req.GetTimestamps()` to `segment.Delete` without checking `len(pks) == len(tss)`; C++ then reads `size`
  timestamps (`SegmentGrowingImpl.cpp:1239-1242`). The sibling `UseLoad` branch **does** validate
  (`internal/storage/delta_data.go:126`). Internal worker→worker gRPC; the proxy/streaming layer sets the
  counts equal. **Fix:** restore parity (length check or C++ assert).
- **`bulk_subscript_impl` offset bound** (`ChunkedSegmentSealedImpl.cpp:4986`) — no `0 <= offset < num_rows`
  check; `FillOutputFieldsOrdered` (`search_result_export_c.cpp:942-968`) re-enters it with Go-reduce
  offsets that aren't re-validated (the search path validates them at `reduce/Reduce.cpp:147-153`).
- **`group_size_` int overflow** (`SearchGroupByOperator.cpp:282-283`) — `topk_ * group_size_ * niter`
  int multiply; only the proxy cap (`search_util.go:937`, `MaxGroupSize`) prevents it. Add a C++ clamp.

### Residual follow-ups from the prior hunt

The three residual threads flagged by the prior hunt were **resumed and are now written up above**:
- local index-cache TOCTOU (`5eb509aa`/#50608) → **C2** (found the StorageV1 mmap-target gap).
- segcore reopen publication staging (`e6d549ef`/#50580) → **C1** (sealed cleared; growing race found).
- RBAC request types lacking a `DBNameGetter` → **A1** (found the `RestoreSnapshot` cross-db bypass).

Still open (not yet run):
- **Assertion-as-DoS sweep:** `exec/expression` + `exec/operator` asserts that depend on attacker batch
  *shape* rather than internal invariants (D3 is one instance).
- **`get_schema()` reference-return hardening** on both sealed and growing (return `SchemaPtr`) — noted
  under C1; independent of whether the growing UAF (C1) is proven unconditional.
- **cachinglayer pin-ownership contract** (`CacheSlot`/`CacheAccessor`) and
  `ChunkedColumnInterface::CancelWarmup()` semantics — external modules absent from this checkout;
  they underpin the sealed reopen "cleared" verdict (C1) and should be confirmed against the full tree.
