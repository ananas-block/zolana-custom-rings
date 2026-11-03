package ring

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringprotocol"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover/common"
)

func TestInstalledAnonymousTagPredicates(t *testing.T) {
	key := keyOf(t, wideAnonymousKey)
	system := loadRingSystem(t, key.Circuit)
	fresh := func(t testing.TB) ringtransfer.BuiltAnonymous {
		t.Helper()
		built := ringtransfer.Hidden(key.anonymousShape()).Build(t)
		built.Audit.Outputs[6].TagPreimage = big.NewInt(0x777)
		built.Audit.Outputs[6].Tag = ringprotocol.RecipientTag(t, built.Audit.Outputs[6].TagPreimage)
		built.Circuit.Outputs[6] = built.Audit.Outputs[6].Wires()
		built.Rebind(t)
		return built
	}
	t.Run("proof_with_matching_dummy_preimage", func(t *testing.T) {
		built := fresh(t)
		params := requestOf[AnonymousTransferParams](t, key.Circuit, built.Circuit)
		request := extensionOf(t, key.Circuit).Request()
		if err := json.Unmarshal(mustMarshal(t, params), request); err != nil {
			t.Fatal(err)
		}
		proof, err := (common.ExtensionProof{System: system, Request: request}).Prove()
		if err != nil {
			t.Fatal(err)
		}
		if err := verifyProof(system, proof, built.Circuit); err != nil {
			t.Fatal(err)
		}
	})
	for _, testCase := range []struct {
		name string
		slot int
	}{
		{"live_tag_mismatch", 1},
		{"dummy_tag_preimage_mismatch", 6},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			built := fresh(t)
			built.Audit.Outputs[testCase.slot].Tag = big.NewInt(7)
			built.Circuit.Outputs[testCase.slot] = built.Audit.Outputs[testCase.slot].Wires()
			built.Rebind(t)
			ringtest.RequireRefused(t, test.IsSolved(built.Circuit, built.Circuit, ecc.BN254.ScalarField()), "audit.assertSlotTag")
			witness, err := frontend.NewWitness(built.Circuit, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := system.ConstraintSystem.Solve(witness); err == nil {
				t.Fatal("mutated tag satisfied the installed constraint system")
			}
		})
	}
}
