package privatelist_test

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/rangecheck"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/privatelist"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

type poolCostCircuit struct {
	Root     frontend.Variable
	Subjects []privatelist.Subject
	Rows     []privatelist.Row
	Query    []privatelist.Query
}

func (c *poolCostCircuit) Define(api frontend.API) error {
	pool := privatelist.OpenPool(api, rangecheck.New(api), 1, c.Root, c.Rows, c.Subjects)
	for _, query := range c.Query {
		pool.Read(api, query)
	}
	return nil
}

func poolCost(t *testing.T, rows, queries int) int {
	t.Helper()
	return ringkey.Compile(t, &poolCostCircuit{Subjects: make([]privatelist.Subject, rows), Rows: make([]privatelist.Row, rows), Query: make([]privatelist.Query, queries)}).GetNbConstraints()
}

// Differences of whole compiles carry the lookup and range tables each row and query add.
func TestMeasuredConstraints(t *testing.T) {
	one, two, four := poolCost(t, 1, 1), poolCost(t, 2, 1), poolCost(t, 4, 1)
	t.Logf("pool of 1 row and 1 query, %d", one)
	t.Logf("row marginal from 1 to 2, %d", two-one)
	t.Logf("row marginal from 2 to 4, %d each", (four-two)/2)
	t.Logf("query marginal, %d", poolCost(t, 1, 2)-one)
	for _, width := range privatelist.ApplyWidths {
		cs := ringkey.Compile(t, applyCircuit(t, width))
		t.Logf("apply width %d, %d, %d per write", width, cs.GetNbConstraints(), cs.GetNbConstraints()/width)
	}
}
