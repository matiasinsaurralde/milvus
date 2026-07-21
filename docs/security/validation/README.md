# Security validation runbooks

Lab validation for findings from the security research engagement.

| Finding | Runbook | Validated here? |
|---------|---------|-----------------|
| **End-user curl / HTTP triggers (start here)** | [end_user_http_triggers.md](./end_user_http_triggers.md) | Checklist for live deploys |
| Filter-expression stack-overflow DoS | [filter_expr_stack_overflow_dos.md](./filter_expr_stack_overflow_dos.md) | **Yes** — process abort at DEPTH=50000 |
| Sparse search heap overflow | [sparse_search_heap_overflow.md](./sparse_search_heap_overflow.md) | **Yes** (canary + ASAN); proxy unit test needs full build deps; e2e segcore ASAN not run |

Harnesses live under `harness/` (includes `sparse_search_trigger.py` for gRPC sparse overflow). Raw logs under `evidence/`.

**Note on sparse + curl:** plain JSON REST cannot send `len%8!=0` sparse rows (server re-encodes maps). Use curl for setup, then the Python gRPC trigger — still no Milvus compile.
