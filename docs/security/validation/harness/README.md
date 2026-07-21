# Security validation harnesses

Lab-only scripts and canaries used to validate findings documented under `docs/security/validation/`.

| Artifact | Purpose |
|----------|---------|
| `sparse_canary.cpp` | Reproduces `CopyAndWrapSparseRow` validate-after-copy overflow without linking Milvus/knowhere |
| `sparse_search_trigger.py` | End-user gRPC Search with `len%8!=0` sparse placeholder (REST/JSON cannot do this) |

These are **not** exploit packages. They demonstrate bug conditions for maintainers (canary corruption / ASAN reports / process abort under a gated Go test).

See also: [end_user_http_triggers.md](../end_user_http_triggers.md).
