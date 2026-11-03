package audit_test

import (
	"math/big"
	"testing"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
)

// Every commitment case of the Rust auditor vector ends in the tail the Go host publishes.
func TestCommitmentTailIsTheRustDisclosure(t *testing.T) {
	var vectors struct {
		Cases []struct {
			Name   string `json:"name"`
			Key    string `json:"key"`
			Inputs []struct {
				Commitment string `json:"commitment"`
			} `json:"inputs"`
			Plaintext []string `json:"plaintext"`
		} `json:"cases"`
	}
	ringtest.ReadVector(t, "audit/audit-disclosure-anonymous.json", &vectors)
	covered := 0
	for _, c := range vectors.Cases {
		if c.Key != "commitment" {
			continue
		}
		hashes := make([]*big.Int, len(c.Inputs))
		for i, input := range c.Inputs {
			hashes[i] = ringtest.VectorField(t, input.Commitment)
		}
		tail := ringaudit.CommitmentRecords(hashes)
		written := c.Plaintext[len(c.Plaintext)-len(tail):]
		for i, field := range tail {
			if field.Cmp(ringtest.VectorField(t, written[i])) != 0 {
				t.Errorf("%s tail field %d is %x, the vector holds %s", c.Name, i, field, written[i])
			}
		}
		covered++
	}
	if covered == 0 {
		t.Fatal("the vector holds no commitment case")
	}
}
