package registry

import (
	"testing"

	"github.com/consensys/gnark/frontend"
)

func TestSharedQuadProofMaximumCanopyWidth(t *testing.T) {
	proof := SharedQuadProof{
		Canopy: make([]frontend.Variable, Capacity),
		Paths:  []SharedQuadPath{{Index: Capacity - 1}},
	}
	if err := proof.validate(1); err != nil {
		t.Fatal(err)
	}
	proof.Canopy = append(proof.Canopy, 0)
	if err := proof.validate(1); err == nil {
		t.Fatal("oversize canopy accepted")
	}
}
