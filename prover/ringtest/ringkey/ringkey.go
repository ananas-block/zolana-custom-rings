// Package ringkey compiles a ring circuit as the ring prover does and holds it to its pinned constraint count.
package ringkey

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// Pinned holds constraint counts by key file name.
var Pinned = map[string]int{
	"custom_ring_audit_packed_2":            52874,
	"custom_ring_audit_packed_4":            63019,
	"custom_ring_audit_delivered_8":         281902,
	"custom_ring_audit_delivered_16":        518961,
	"custom_ring_audit_anonymous_4_2":       123506,
	"custom_ring_audit_anonymous_32_2":      171225,
	"custom_ring_audit_anonymous_1_16":      552649,
	"custom_ring_audit_anonymous_entry_8_2": 138040,
	"custom_ring_policy_member_2":           48455,
	"custom_ring_policy_member_16":          286047,
	"custom_ring_policy_delegate_2x2":       50089,
	"custom_ring_apply_records_1":           15492,
	"custom_ring_apply_records_16":          232892,
	"custom_ring_register_key":              36991,
	"custom_ring_deposit":                   148936,
	"custom_ring_merge_anonymous_8":         56192,
	"custom_ring_merge_anonymous_24":        81698,
}

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
