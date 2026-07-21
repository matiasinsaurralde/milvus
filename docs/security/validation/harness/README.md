# Security validation harnesses

Lab-only scripts and canaries used to validate findings documented under `docs/security/validation/`.

| Artifact | Purpose |
|----------|---------|
| `sparse_canary.cpp` | Reproduces `CopyAndWrapSparseRow` validate-after-copy overflow without linking Milvus/knowhere |

These are **not** exploit packages. They demonstrate bug conditions for maintainers (canary corruption / ASAN reports / process abort under a gated Go test).
