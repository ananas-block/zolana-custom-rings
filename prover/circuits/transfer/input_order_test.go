package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	transaction "github.com/helius-labs/zolana/prover/server/circuits/spp_transaction/shared"
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
		ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), "transfer.OpenInputs")
	}
}

// A slot is a note or a canonical dummy on every rail, an address slot or a dummy with content carries a value the evidence never shows.
func TestInputSlotsHoldTheirDomain(t *testing.T) {
	for name, mutate := range map[string]func(*ringaudit.Utxo){
		"an address input":         func(u *ringaudit.Utxo) { u.Domain = transaction.AddressDomain },
		"a dummy with an amount":   func(u *ringaudit.Utxo) { u.Amount = 1 },
		"a dummy with an asset":    func(u *ringaudit.Utxo) { u.Asset = big.NewInt(1) },
		"a dummy with a data hash": func(u *ringaudit.Utxo) { u.DataHash = big.NewInt(1) },
		"a dummy with a ring":      func(u *ringaudit.Utxo) { u.RingProgramID = big.NewInt(1) },
	} {
		t.Run(name, func(t *testing.T) {
			for _, rail := range []ringtransfer.Rail{ringtransfer.Signer, ringtransfer.InProof, ringtransfer.Delegate} {
				b := onRail(rail).Build(t)
				mutate(&b.Inputs[2])
				b.Circuit.Inputs[2] = b.Inputs[2].Wires()
				b.Rehash(t)
				refused(t, b, "shared.UtxoWires.OpenInput")
			}
			a := ringtransfer.Hidden(anonymous2).Build(t)
			mutate(&a.Audit.Inputs[2])
			a.Circuit.Inputs[2] = a.Audit.Inputs[2].Wires()
			a.Circuit.PrivateTxHash = a.Audit.PrivateTxHash(t)
			a.Rebind(t)
			refusedAnonymous(t, a, "shared.UtxoWires.OpenInput")
		})
	}
}

// Only the in-proof rail publishes a sender and only the signer rail binds a run, a rail reading another's cell would screen a sender no authorization names.
func TestRailCellsStayOnTheirRail(t *testing.T) {
	t.Run("a signer rail statement sender", func(t *testing.T) {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Circuit.Sender = b.Sender
		b.Rebind(t)
		refused(t, b, "transfer.(*ConfidentialTransferCircuit).assertRail")
	})
	for _, rail := range []ringtransfer.Rail{ringtransfer.InProof, ringtransfer.Delegate} {
		t.Run("a run on an owner rail", func(t *testing.T) {
			b := onRail(rail).Build(t)
			b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = []*big.Int{b.Sender}, 1, b.Sender
			b.Rebind(t)
			refused(t, b, "transfer.(*ConfidentialTransferCircuit).spendInputs")
		})
	}
}
