package transfer_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// A dummy between live inputs keeps SPP's private_tx_hash, the readers would pair each later note with another nullifier.
func TestDummyBetweenSpentInputsIsRefused(t *testing.T) {
	for _, rail := range []ringtransfer.Rail{ringtransfer.InProof, ringtransfer.Delegate} {
		b := onRail(rail).Build(t)
		nk := spptest.MustNullifierPk(t, ringtest.AsBigInt(7))
		first := ringaudit.SpentUtxo(t, b.Sender, nk, b.Audit.RingProgramID, 100, 51)
		second := ringaudit.SpentUtxo(t, b.Sender, nk, b.Audit.RingProgramID, 60, 52)
		for i := range b.Inputs {
			b.Inputs[i] = ringaudit.SpareInput(i)
		}
		b.Inputs[0], b.Inputs[2] = first, second
		for i, input := range b.Inputs {
			b.Circuit.Inputs[i] = input.Wires()
		}
		b.Audit.InputCount, b.Circuit.InputCount = 3, 3
		b.Rehash(t)
		ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), "assertFollowsUtxo")
	}
}
