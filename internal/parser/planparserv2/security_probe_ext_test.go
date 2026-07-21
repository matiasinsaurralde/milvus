package planparserv2_test

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/milvus-io/milvus-proto/go-api/v3/schemapb"
	"github.com/milvus-io/milvus/internal/parser/planparserv2"
	"github.com/milvus-io/milvus/pkg/v3/util/typeutil"
)

// TestSecurityProbeDeepParensExt is a destructive validation harness for the
// filter-expression stack-overflow DoS.
//
// Gated behind MILVUS_SEC_VALIDATE_DOS=1 so normal CI is unaffected.
// A nesting DEPTH of ~50000 (expr length ~100k) reliably triggers:
//
//	fatal error: stack overflow
//
// inside generated.(*PlanParser).expr. Go's recover() cannot catch this; the
// process aborts. See docs/security/validation/filter_expr_stack_overflow_dos.md.
//
//	MILVUS_SEC_VALIDATE_DOS=1 DEPTH=50000 go test -tags dynamic,test \
//	  -gcflags="all=-N -l" -count=1 \
//	  ./internal/parser/planparserv2/ -run TestSecurityProbeDeepParensExt
func TestSecurityProbeDeepParensExt(t *testing.T) {
	if os.Getenv("MILVUS_SEC_VALIDATE_DOS") != "1" {
		t.Skip("gated")
	}
	depth, _ := strconv.Atoi(os.Getenv("DEPTH"))
	if depth <= 0 {
		depth = 50000
	}
	schema := &schemapb.CollectionSchema{
		Name: "t",
		Fields: []*schemapb.FieldSchema{
			{FieldID: 100, Name: "pk", IsPrimaryKey: true, DataType: schemapb.DataType_Int64},
			{FieldID: 101, Name: "a", DataType: schemapb.DataType_Int64},
		},
	}
	helper, err := typeutil.CreateSchemaHelper(schema)
	if err != nil {
		t.Fatal(err)
	}
	expr := strings.Repeat("(", depth) + "a > 1" + strings.Repeat(")", depth)
	fmt.Fprintf(os.Stderr, "EXT Probe depth=%d len=%d\n", depth, len(expr))
	_, err = planparserv2.ParseExpr(helper, expr, nil)
	fmt.Fprintf(os.Stderr, "EXT returned err=%v\n", err)
}

// TestSecurityProbeDeepNotExt validates the same fatal stack overflow via
// prefix-unary recursion (`not not not … a > 1`).
func TestSecurityProbeDeepNotExt(t *testing.T) {
	if os.Getenv("MILVUS_SEC_VALIDATE_DOS") != "1" {
		t.Skip("gated")
	}
	depth, _ := strconv.Atoi(os.Getenv("DEPTH"))
	if depth <= 0 {
		depth = 50000
	}
	schema := &schemapb.CollectionSchema{
		Name: "t",
		Fields: []*schemapb.FieldSchema{
			{FieldID: 100, Name: "pk", IsPrimaryKey: true, DataType: schemapb.DataType_Int64},
			{FieldID: 101, Name: "a", DataType: schemapb.DataType_Int64},
		},
	}
	helper, err := typeutil.CreateSchemaHelper(schema)
	if err != nil {
		t.Fatal(err)
	}
	expr := strings.Repeat("not ", depth) + "a > 1"
	fmt.Fprintf(os.Stderr, "NOT Probe depth=%d len=%d\n", depth, len(expr))
	_, err = planparserv2.ParseExpr(helper, expr, nil)
	fmt.Fprintf(os.Stderr, "NOT returned err=%v\n", err)
}
