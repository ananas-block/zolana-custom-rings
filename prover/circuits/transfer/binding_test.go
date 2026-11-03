package transfer_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

// Every statement element binds, an unchanged witness fails the public input binding alone when one element moves.
func TestStatementBindsEveryElement(t *testing.T) {
	if testing.Short() {
		t.Skip("solves the compiled key once per statement element")
	}
	t.Run("confidential", func(t *testing.T) {
		circuit, err := transfer.NewConfidentialTransferCircuit(confidential2)
		if err != nil {
			t.Fatal(err)
		}
		b := cosigned(t, true).Build(t)
		requireEveryElementBound(t, ringkey.Bind(t, circuit, b.Circuit), b.Circuit, b.Statement(t))
	})
	t.Run("anonymous", func(t *testing.T) {
		circuit, err := transfer.NewAnonymousTransferCircuit(anonymous2)
		if err != nil {
			t.Fatal(err)
		}
		b := hiddenExempt(t, 100).Build(t)
		requireEveryElementBound(t, ringkey.Bind(t, circuit, b.Circuit), b.Circuit, b.Statement(t))
	})
}

func requireEveryElementBound(t *testing.T, bound *ringkey.Bound, assignment frontend.Circuit, statement []*big.Int) {
	t.Helper()
	for i := range statement {
		moved := slices.Clone(statement)
		moved[i] = new(big.Int).Add(moved[i], big.NewInt(1))
		bound.RefuseStatement(t, assignment, moved)
	}
	ringkey.SetPublicInput(assignment, spptest.MustHashChain4(t, statement))
	bound.RequireSolved(t, assignment)
}

// A dummy slot's opening enters the output chain and stays out of SPP's private transaction hash.
func TestDummySlotEntersTheOutputChainOnly(t *testing.T) {
	b := ringtransfer.Signed(confidential2).Build(t)
	before := ringtest.AsBigInt(b.Circuit.PrivateTxHash)
	dummy := &b.Audit.Outputs[1]
	if dummy.Utxo.IsUtxo() {
		t.Fatal("slot 1 is no dummy")
	}
	dummy.Utxo.TreeID++
	b.Circuit.Outputs[1] = dummy.Wires()
	b.Rehash(t)
	if ringtest.AsBigInt(b.Circuit.PrivateTxHash).Cmp(before) != 0 {
		t.Fatal("a dummy slot changed the private transaction hash")
	}
	requireSolved(t, b.Circuit)
}

// An exit enters both projections, a transfer keeping the old private transaction hash over a changed exit is refused.
func TestExitEntersBothProjections(t *testing.T) {
	shape := transfer.ConfidentialShape{Inputs: 24, Outputs: 4, Withdrawals: 4}
	// The test engine rewrites the assignment it solves, every mutation starts from a fresh build.
	build := func(t *testing.T, raise bool) (ringtransfer.Built, *big.Int) {
		t.Helper()
		b := ringtransfer.Signed(shape).Build(t)
		before := ringtest.AsBigInt(b.Circuit.PrivateTxHash)
		exit := &b.Audit.Outputs[2]
		if !exit.Utxo.IsUtxo() || exit.Utxo.RingProgramID.Sign() != 0 {
			t.Fatal("slot 2 is no exit")
		}
		if raise {
			exit.Utxo.Amount++
			b.Circuit.Outputs[2] = exit.Wires()
			b.Rehash(t)
		}
		return b, before
	}
	raised, before := build(t, true)
	if ringtest.AsBigInt(raised.Circuit.PrivateTxHash).Cmp(before) == 0 {
		t.Fatal("an exit left the private transaction hash unchanged")
	}
	requireSolved(t, raised.Circuit)
	stale, before := build(t, true)
	stale.Circuit.PrivateTxHash = before
	stale.Rebind(t)
	ringtest.RequireRefused(t, test.IsSolved(stale.Circuit, stale.Circuit, ecc.BN254.ScalarField()), "transfer.(*ConfidentialTransferCircuit).Define")
}
