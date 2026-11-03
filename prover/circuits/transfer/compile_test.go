package transfer_test

import (
	"testing"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
)

// Every key of the catalog compiles with one public input and one BSB22 commitment over private wires, the shape groth16-solana verifies, at its pinned count.
func TestCatalogCompilesToTheVerifiedShape(t *testing.T) {
	if testing.Short() {
		t.Skip("compiles every transfer key")
	}
	keys := map[string]func() (frontend.Circuit, error){}
	for _, shape := range transfer.ConfidentialShapes {
		keys[shape.String()] = func() (frontend.Circuit, error) { return transfer.NewConfidentialTransferCircuit(shape) }
	}
	for _, shape := range append(transfer.AnonymousShapes[:], transfer.EntryShapes[:]...) {
		keys[shape.String()] = func() (frontend.Circuit, error) { return transfer.NewAnonymousTransferCircuit(shape) }
	}
	for name, build := range keys {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			circuit, err := build()
			if err != nil {
				t.Fatal(err)
			}
			cs := ringkey.Compile(t, circuit)
			t.Logf("%s: %d constraints", name, cs.GetNbConstraints())
			if _, pinned := ringkey.Pinned[name]; pinned {
				ringkey.RequirePinned(t, name, cs)
				return
			}
			if public := cs.GetNbPublicVariables() - 1; public != 1 {
				t.Errorf("%d public inputs, the program verifies one", public)
			}
			commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
			if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
				t.Errorf("commitments %v, want one over private wires", cs.GetCommitments())
			}
		})
	}
}
