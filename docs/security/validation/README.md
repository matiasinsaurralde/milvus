# Security validation runbooks

Lab validation for findings from the security research engagement.

| Finding | Runbook | Validated here? |
|---------|---------|-----------------|
| Filter-expression stack-overflow DoS | [filter_expr_stack_overflow_dos.md](./filter_expr_stack_overflow_dos.md) | **Yes** — process abort at DEPTH=50000 |
| Sparse search heap overflow | [sparse_search_heap_overflow.md](./sparse_search_heap_overflow.md) | **Yes** (canary + ASAN); proxy unit test needs full build deps; e2e segcore ASAN not run |

Harnesses live under `harness/`. Raw logs under `evidence/`.
