// Package ringkey compiles a ring circuit as the ring prover does and holds it to its pinned constraint count.
package ringkey

import (
	_ "embed"
	"encoding/json"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

//go:embed constraints.json
var constraintCounts []byte

// Pinned holds measured constraint counts by key file stem.
var Pinned = func() map[string]int {
	var counts map[string]int
	if err := json.Unmarshal(constraintCounts, &counts); err != nil {
		panic(err)
	}
	return counts
}()

// Compile takes the compress threshold of the zolana ring prover.
func Compile(t testing.TB, circuit frontend.Circuit) constraint.ConstraintSystem {
	t.Helper()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(300))
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func RequirePinned(t testing.TB, name string, cs constraint.ConstraintSystem) {
	t.Helper()
	pinned, ok := Pinned[name]
	if !ok {
		t.Fatalf("%s has no pin", name)
	}
	if got := cs.GetNbConstraints(); got != pinned {
		t.Errorf("%s: %d constraints, pinned %d", name, got, pinned)
	}
	if public := cs.GetNbPublicVariables() - 1; public != 1 {
		t.Errorf("%s: %d public inputs, the program verifies one", name, public)
	}
	commitments, ok := cs.GetCommitments().(constraint.Groth16Commitments)
	if !ok || len(commitments) != 1 || commitments[0].NbPublicCommitted != 0 {
		t.Errorf("%s: commitments %v, want one over private wires", name, cs.GetCommitments())
	}
}
