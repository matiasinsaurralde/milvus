# Runbook: Filter-expression stack-overflow DoS (pre-auth at defaults)

## Status

**Validated in this environment (2026-07-21).**

`ParseExpr` with deeply nested parentheses (or prefix `not`) causes a Go **fatal stack overflow** inside the ANTLR-generated recursive `(*PlanParser).expr`. The process aborts. `recover()` in `handleExprInternal` cannot catch it.

| Depth | Expr length | Result (with `-gcflags="all=-N -l"`) |
|------:|------------:|--------------------------------------|
| 5,000 | ~10 KB | Survives (`ParseExpr` returns `nil`) |
| 40,000+ | ~80 KB+ | **`fatal error: stack overflow`** |
| 50,000 | ~100 KB | **Crash confirmed** (saved evidence) |

Default `common.security.authorizationEnabled=false` makes this reachable without credentials on Search/Query/Delete once a collection exists (attacker can create one when auth is off).

## Root cause

- Grammar: `internal/parser/planparserv2/Plan.g4` — recursive `'(' expr ')'`, unary `NOT expr`, etc.
- Generated parser: `generated/plan_parser.go` — `expr()` recurses per nesting level.
- Guard: `handleExprInternal` only `recover()`s panics (`plan_parser_v2.go`); stack overflow is a runtime fatal error.
- No expression-length / nesting-depth cap; gRPC recv default allows up to 256 MB.

## Unit-level validation (no live cluster)

From repo root:

```bash
# Control: should SKIP under normal CI / without the env gate
go test -tags dynamic,test -gcflags="all=-N -l" -count=1 \
  ./internal/parser/planparserv2/ -run TestSecurityProbeDeepParensExt -v

# Survive at modest depth
MILVUS_SEC_VALIDATE_DOS=1 DEPTH=5000 go test -tags dynamic,test \
  -gcflags="all=-N -l" -count=1 -timeout 90s \
  ./internal/parser/planparserv2/ -run TestSecurityProbeDeepParensExt -v
# Expect: EXT returned err=<nil> and PASS

# Crash the test process (destructive)
MILVUS_SEC_VALIDATE_DOS=1 DEPTH=50000 go test -tags dynamic,test \
  -gcflags="all=-N -l" -count=1 -timeout 60s \
  ./internal/parser/planparserv2/ -run TestSecurityProbeDeepParensExt -v
# Expect: exit != 0, stderr contains:
#   fatal error: stack overflow
#   ... (*PlanParser).expr ...
```

Prefix-unary variant:

```bash
MILVUS_SEC_VALIDATE_DOS=1 DEPTH=50000 go test -tags dynamic,test \
  -gcflags="all=-N -l" -count=1 -timeout 60s \
  ./internal/parser/planparserv2/ -run TestSecurityProbeDeepNotExt -v
```

Evidence captured from this agent run:

- `docs/security/validation/evidence/dos_stack_overflow_depth50000.txt`
- `docs/security/validation/evidence/dos_survive_depth5000.txt`

## End-to-end validation (live Milvus, defaults)

**Warning:** this kills the proxy/standalone process. Use an isolated lab deploy only.

1. Start standalone with published `19530` (e.g. `deployments/docker/standalone/docker-compose.yml`). Confirm `authorizationEnabled` is unset/false.
2. Create any collection with an `Int64` scalar field (e.g. `a`) via pymilvus / Go SDK / REST — no auth required at defaults.
3. Issue a Query/Search/Delete whose filter is nested parentheses around a valid predicate, with nesting depth ≥ ~50k (total filter string ≪ 256 MB gRPC limit). Example shape (do not paste 50k parens into a terminal by hand — generate in a script):

   ```text
   ((((((((( ... (a > 1) ... )))))))))
   ```

4. **Pass criteria:** milvus-standalone / proxy process exits; logs show `fatal error: stack overflow` with frames in `planparserv2/generated.(*PlanParser).expr`.

## Fix verification (after patch)

A correct fix should make `DEPTH=50000` (and larger) return a structured error from `ParseExpr` **without** aborting the process. Re-run the crash command above and expect `EXT returned err=<non-nil>` and process exit 0 from `go test`.

Suggested fix directions: max nesting / max expr length before parse; or parse on a bounded-stack worker and treat overflow as rejection.
