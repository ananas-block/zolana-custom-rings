package audit_test

import (
	"fmt"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/audit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

var compiledSections = map[string]*ringkey.Bound{}

// compileSection compiles the section once per shape and locates the public input binding with the honest assignment.
func compileSection(t *testing.T, shape audit.StreamShape) *ringkey.Bound {
	t.Helper()
	name := fmt.Sprintf("%+v", shape)
	if c, ok := compiledSections[name]; ok {
		return c
	}
	honest := ringaudit.NewSection(t, shape)
	c := ringkey.Bind(t, ringaudit.NewSectionCircuit(shape), honest.Circuit(t))
	compiledSections[name] = c
	return c
}
