package transfer_test

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var (
	confidential2 = transfer.ConfidentialShape{Inputs: 32, Outputs: 2, Withdrawals: 4}
	anonymous2    = transfer.AnonymousShape{InputClass: 24, Outputs: 2, Withdrawals: 4}
	entry2        = transfer.AnonymousShape{InputClass: 8, Outputs: 2, Withdrawals: 4, FullOpenings: true}
)

// Every honest witness solves and binds its public input.
func TestConfidentialRailsSolve(t *testing.T) {
	for _, tc := range []struct {
		name  string
		world ringtransfer.Confidential
	}{
		{"signer", ringtransfer.Signed(confidential2)},
		{"signer with key escrow", escrowed()},
		{"in-proof", onRail(ringtransfer.InProof)},
		{"in-proof on an audit-only ring", unscreenedInProof()},
		{"delegate", onRail(ringtransfer.Delegate)},
		{"audit-only ring", unscreened()},
		{"exempt withdrawal", exempt(t, 100)},
		{"exempt withdrawal on an audit-only ring", unscreenedExempt(t)},
		{"co-signed withdrawal", cosigned(t, true)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.world.Build(t)
			ringtest.RequirePublicInputBound(t, b.Circuit, b.Circuit)
		})
	}
}

func TestAnonymousRailsSolve(t *testing.T) {
	for _, tc := range []struct {
		name  string
		world ringtransfer.Anonymous
	}{
		{"commitment", ringtransfer.Hidden(anonymous2)},
		{"entry", ringtransfer.Hidden(entry2)},
		{"audit-only ring", hiddenUnscreened()},
		{"exempt withdrawal", hiddenExempt(t, 100)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.world.Build(t)
			ringtest.RequirePublicInputBound(t, b.Circuit, b.Circuit)
		})
	}
}

// The signer rail's envelope holds tx_viewing_sk alone at any published count.
func TestSignerRailEnvelopeIgnoresTheInputCount(t *testing.T) {
	for _, count := range []int{1, 2, confidential2.Inputs} {
		b := ringtransfer.Signed(confidential2).Build(t)
		b.Audit.InputCount, b.Circuit.InputCount = count, count
		b.Rebind(t)
		requireSolved(t, b.Circuit)
	}
}

// Every shape of the catalog solves its plain honest witness.
func TestEveryShapeSolves(t *testing.T) {
	for _, shape := range transfer.ConfidentialShapes {
		t.Run(shape.String(), func(t *testing.T) {
			b := ringtransfer.Signed(shape).Build(t)
			requireSolved(t, b.Circuit)
		})
	}
	for _, shape := range append(transfer.AnonymousShapes[:], transfer.EntryShapes[:]...) {
		t.Run(shape.String(), func(t *testing.T) {
			b := ringtransfer.Hidden(shape).Build(t)
			requireSolved(t, b.Circuit)
		})
	}
}

// A wide key screens as many distinct withdrawal owners as it has legs.
func TestWideWithdrawalKeyScreensEveryLeg(t *testing.T) {
	shape := transfer.ConfidentialShape{Inputs: 32, Outputs: 2, Withdrawals: 32}
	w := ringtransfer.Signed(shape)
	gross := uint64(0)
	for i := range shape.Withdrawals {
		leg := ringtransfer.Withdrawal{Owner: big.NewInt(int64(5000 + i)), Asset: ringtransfer.Asset(t), Amount: 10}
		w.Withdrawals = append(w.Withdrawals, leg)
		gross += leg.Amount
	}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -int64(gross), Gross: gross}}
	requireSolved(t, w.Build(t).Circuit)
}

type confidentialRefusal struct {
	name    string
	honest  func(t testing.TB) ringtransfer.Confidential
	world   func(w *ringtransfer.Confidential)
	witness func(t testing.TB, b ringtransfer.Built)
	in      string
}

var confidentialRefusals = []confidentialRefusal{
	{name: "exempt gross above the threshold", honest: func(t testing.TB) ringtransfer.Confidential { return exempt(t, 100) }, world: func(w *ringtransfer.Confidential) {
		w.Withdrawals[0].Amount, w.Public[0].Net, w.Public[0].Gross = 101, -101, 101
	}, in: "policy.(*PolicyInputs).assertExemption"},
	{name: "exempt withdrawal of an asset without a record", honest: func(t testing.TB) ringtransfer.Confidential { return exempt(t, 100) }, world: func(w *ringtransfer.Confidential) {
		other := big.NewInt(0x0b0b)
		w.Withdrawals[0].Asset, w.Public[0].Asset = other, other
	}, in: "policy.(*PolicyInputs).assertExemption"},
	{name: "exempt gross past u64", honest: func(t testing.TB) ringtransfer.Confidential { return exempt(t, 100) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Circuit.PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		b.Rebind(t)
	}, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "sender on the frozen list", honest: func(testing.TB) ringtransfer.Confidential { return ringtransfer.Signed(confidential2) }, world: func(w *ringtransfer.Confidential) { w.Policy.Frozen = true }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "screened under another own root", honest: func(testing.TB) ringtransfer.Confidential { return ringtransfer.Signed(confidential2) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Circuit.OwnRoot = 5
		b.Rebind(t)
	}, in: "registry.SharedQuadProof.AssertLeavesWhen"},
	{name: "recipient other than the slot owner", honest: func(testing.TB) ringtransfer.Confidential { return ringtransfer.Signed(confidential2) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Circuit.Recipients[0] = 7
		b.Rebind(t)
	}, in: "policy.(*PolicyInputs).assertRecipients"},
	{name: "approval bit set within every co-sign bound", honest: func(testing.TB) ringtransfer.Confidential { return ringtransfer.Signed(confidential2) }, world: func(w *ringtransfer.Confidential) { w.ApprovalRequired = true }, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "approval bit clear past the co-sign bound", honest: func(t testing.TB) ringtransfer.Confidential { return cosigned(t, true) }, world: func(w *ringtransfer.Confidential) { w.ApprovalRequired = false }, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "in-proof input of another owner", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.InProof) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Inputs[1].OwnerPkHash = big.NewInt(0x0ddd)
		b.Circuit.Inputs[1] = b.Inputs[1].Wires()
		b.Rehash(t)
	}, in: "audit.spentBySender"},
	{name: "signer rail opening an input", honest: func(testing.TB) ringtransfer.Confidential { return ringtransfer.Signed(confidential2) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Inputs[0] = ringaudit.SpentUtxo(t, b.Sender, spptest.MustNullifierPk(t, big.NewInt(7)), b.Audit.RingProgramID, 100, 51)
		b.Circuit.Inputs[0] = b.Inputs[0].Wires()
		b.Rehash(t)
	}, in: "audit.spentBySender"},
	// A spent note past the published count stays out of the auditor's evidence.
	{name: "in-proof UTXO at the input count", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.InProof) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Audit.InputCount, b.Circuit.InputCount = 1, 1
		b.Rebind(t)
	}, in: "audit.spentBySender"},
	{name: "delegate move with a second member's input", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Inputs[1].OwnerPkHash = big.NewInt(0x0ddd)
		b.Circuit.Inputs[1] = b.Inputs[1].Wires()
		b.Rehash(t)
	}, in: "audit.spentBySender"},
	{name: "delegate move without a spent input", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Inputs[0] = ringaudit.SpareInput(0)
		b.Circuit.Inputs[0] = b.Inputs[0].Wires()
		b.Rehash(t)
	}, in: "audit.spentBySender"},
	{name: "delegate with the approval bit", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, world: func(w *ringtransfer.Confidential) { w.ApprovalRequired = true }, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "delegate with a statement sender", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Circuit.Sender = b.Sender
		b.Rebind(t)
	}, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "delegate with in_proof", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Circuit.InProof = 1
		b.Rebind(t)
	}, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "delegate without key escrow", honest: func(testing.TB) ringtransfer.Confidential { return onRail(ringtransfer.Delegate) }, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Audit.Layout.Escrow = false
		b.Circuit.Layout = b.Audit.Layout.Value()
		b.Rebind(t)
	}, in: "transfer.(*ConfidentialTransferCircuit).Define"},
	{name: "every output a dummy under an unrelated envelope key", honest: fullWithdrawal, witness: func(t testing.TB, b ringtransfer.Built) {
		b.Audit.Transfer = b.Audit.WithUnrelatedKey(t)
		sk := b.Audit.Keys.TxViewingSk()
		ringtest.SetBytes(b.Circuit.TxViewingSk[:], sk[:])
		b.Rebind(t)
	}, in: "audit.AuditWires.AssertBlinding"},
	{name: "escrow of another key ciphertext", honest: func(testing.TB) ringtransfer.Confidential { return escrowed() }, witness: func(_ testing.TB, b ringtransfer.Built) { b.Circuit.CtHashes[0] = 7 }, in: "policy.(*PolicyInputs).assertEscrow"},
}

func TestConfidentialRefusals(t *testing.T) {
	for _, r := range confidentialRefusals {
		t.Run(r.name, func(t *testing.T) {
			requireSolved(t, r.honest(t).Build(t).Circuit)
			w := r.honest(t)
			if r.world != nil {
				r.world(&w)
			}
			b := w.Build(t)
			if r.witness != nil {
				r.witness(t, b)
			}
			ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), r.in)
		})
	}
}

// A gate off binds none of the wires only its predicates read.
func TestGateOffDropsItsPredicates(t *testing.T) {
	t.Run("an unscreened ring ignores the table and the sender's lists", func(t *testing.T) {
		w := unscreened()
		w.Policy.Frozen = true
		b := w.Build(t)
		b.Circuit.Rules[1] = 0x1234
		requireSolved(t, b.Circuit)
	})
	t.Run("an unexempt transfer ignores the gross", func(t *testing.T) {
		w := exempt(t, 100)
		w.Exempt = false
		b := w.Build(t)
		b.Circuit.PublicGross[0] = new(big.Int).Lsh(big.NewInt(1), 64)
		b.Rebind(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("the delegate rail bounds no outflow", func(t *testing.T) {
		w := onRail(ringtransfer.Delegate)
		w.Policy.Cap, w.Policy.CosignAbove = 1000, 500
		w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: 5000}}
		w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -5000, Gross: 5000}}
		requireSolved(t, w.Build(t).Circuit)
	})
}

type anonymousRefusal struct {
	name    string
	honest  func(t testing.TB) ringtransfer.Anonymous
	world   func(w *ringtransfer.Anonymous)
	witness func(t testing.TB, b ringtransfer.BuiltAnonymous)
	in      string
}

var anonymousRefusals = []anonymousRefusal{
	{name: "party identity equal to the hidden sender", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, witness: func(t testing.TB, b ringtransfer.BuiltAnonymous) {
		b.Circuit.PartyIdentities[2] = b.Audit.SenderPkHash(t)
		b.Rebind(t)
	}, in: "shared.AssertAnonymousParties"},
	{name: "recipient published on the anonymous rail", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, witness: func(t testing.TB, b ringtransfer.BuiltAnonymous) {
		b.Circuit.Recipients[0] = b.Circuit.Outputs[0].Output.OwnerPkHash
	}, in: "policy.(*PolicyInputs).assertRecipients"},
	{name: "commitment key spending a default-ring note", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, witness: func(t testing.TB, b ringtransfer.BuiltAnonymous) {
		b.Audit.Inputs[1].RingProgramID = big.NewInt(0)
		b.Circuit.Inputs[1] = b.Audit.Inputs[1].Wires()
		b.Circuit.PrivateTxHash = b.Audit.PrivateTxHash(t)
		b.Rebind(t)
	}, in: "audit.Spend"},
	// A spent note past the published count stays out of the auditor's evidence.
	{name: "hidden UTXO at the input count", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, witness: func(t testing.TB, b ringtransfer.BuiltAnonymous) {
		b.Audit.InputCount, b.Circuit.InputCount = 1, 1
		b.Rebind(t)
	}, in: "audit.spentBySender"},
	{name: "every output a dummy under an unrelated envelope key", honest: hiddenFullWithdrawal, witness: func(t testing.TB, b ringtransfer.BuiltAnonymous) {
		b.Audit.Transfer = b.Audit.WithUnrelatedKey(t)
		sk := b.Audit.Keys.TxViewingSk()
		ringtest.SetBytes(b.Circuit.TxViewingSk[:], sk[:])
		b.Rebind(t)
	}, in: "audit.AuditWires.AssertBlinding"},
	{name: "exempt gross above the threshold", honest: func(t testing.TB) ringtransfer.Anonymous { return hiddenExempt(t, 100) }, world: func(w *ringtransfer.Anonymous) {
		w.Withdrawals[0].Amount, w.Public[0].Net, w.Public[0].Gross = 101, -101, 101
	}, in: "policy.(*PolicyInputs).assertExemption"},
	{name: "hidden sender on the frozen list", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, world: func(w *ringtransfer.Anonymous) { w.Policy.Frozen = true }, in: "policy.(*PolicyInputs).assertRules"},
	{name: "approval bit set within every co-sign bound", honest: func(testing.TB) ringtransfer.Anonymous { return ringtransfer.Hidden(anonymous2) }, world: func(w *ringtransfer.Anonymous) { w.ApprovalRequired = true }, in: "transfer.(*AnonymousTransferCircuit).Define"},
}

func TestAnonymousRefusals(t *testing.T) {
	for _, r := range anonymousRefusals {
		t.Run(r.name, func(t *testing.T) {
			requireSolved(t, r.honest(t).Build(t).Circuit)
			w := r.honest(t)
			if r.world != nil {
				r.world(&w)
			}
			b := w.Build(t)
			if r.witness != nil {
				r.witness(t, b)
			}
			ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), r.in)
		})
	}
}

func onRail(rail ringtransfer.Rail) ringtransfer.Confidential {
	w := ringtransfer.Signed(confidential2)
	w.Rail = rail
	return w
}

func escrowed() ringtransfer.Confidential {
	w := ringtransfer.Signed(confidential2)
	w.Escrow = true
	return w
}

func unscreened() ringtransfer.Confidential {
	w := ringtransfer.Signed(confidential2)
	w.Policy.Screened = false
	return w
}

func unscreenedInProof() ringtransfer.Confidential {
	w := onRail(ringtransfer.InProof)
	w.Policy.Screened = false
	return w
}

// exempt withdraws gross of the fixture asset to one owner under the threshold 100.
func exempt(t testing.TB, gross uint64) ringtransfer.Confidential {
	t.Helper()
	w := ringtransfer.Signed(confidential2)
	w.Exempt = true
	w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: gross}}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -int64(gross), Gross: gross}}
	return w
}

func fullWithdrawal(t testing.TB) ringtransfer.Confidential {
	t.Helper()
	w := ringtransfer.Signed(confidential2)
	w.AllDummies = true
	w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: 160}}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -160, Gross: 160}}
	return w
}

func unscreenedExempt(t testing.TB) ringtransfer.Confidential {
	t.Helper()
	w := exempt(t, 100)
	w.Policy.Screened = false
	return w
}

// cosigned withdraws past the co-sign bound 500 and below the cap 1000.
func cosigned(t testing.TB, approval bool) ringtransfer.Confidential {
	t.Helper()
	w := ringtransfer.Signed(confidential2)
	w.Policy.Cap, w.Policy.CosignAbove = 1000, 500
	w.ApprovalRequired = approval
	w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: 600}}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -600, Gross: 600}}
	return w
}

func hiddenUnscreened() ringtransfer.Anonymous {
	w := ringtransfer.Hidden(anonymous2)
	w.Policy.Screened = false
	return w
}

func hiddenExempt(t testing.TB, gross uint64) ringtransfer.Anonymous {
	t.Helper()
	w := ringtransfer.Hidden(anonymous2)
	w.Exempt = true
	w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: gross}}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -int64(gross), Gross: gross}}
	return w
}

func hiddenFullWithdrawal(t testing.TB) ringtransfer.Anonymous {
	t.Helper()
	w := ringtransfer.Hidden(anonymous2)
	w.AllDummies = true
	w.Withdrawals = []ringtransfer.Withdrawal{{Owner: big.NewInt(0x0bb0), Asset: ringtransfer.Asset(t), Amount: 160}}
	w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: -160, Gross: 160}}
	return w
}

func requireSolved(t *testing.T, circuit frontend.Circuit) {
	t.Helper()
	if err := test.IsSolved(circuit, circuit, ecc.BN254.ScalarField()); err != nil {
		t.Fatal(err)
	}
}
