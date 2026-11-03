package transfer_test

import (
	"math/big"
	"slices"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/circuits/transfer"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringaudit"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringkey"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringtransfer"
	"github.com/helius-labs/zolana/prover/server/prover-test/spp/spptest"
)

var (
	coOwner      = big.NewInt(0x0c0c)
	otherCoOwner = big.NewInt(0x0d0d)
)

func refused(t *testing.T, b ringtransfer.Built, frame string) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), frame)
}

func refusedAnonymous(t *testing.T, b ringtransfer.BuiltAnonymous, frame string) {
	t.Helper()
	ringtest.RequireRefused(t, test.IsSolved(b.Circuit, b.Circuit, ecc.BN254.ScalarField()), frame)
}

// A public-funded signer transfer keeps a dummy at slot 0, distinct owners spend beside each other.
func TestSignerRailSpends(t *testing.T) {
	t.Run("a dummy at slot 0", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.PublicFunded = true
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("distinct owners", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an audit-only ring takes an empty set", func(t *testing.T) {
		w := unscreened()
		w.PublicFunded = true
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = nil, 0, 0
		b.Rebind(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("a policy refuses an empty set", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.PublicFunded = true
		b := w.Build(t)
		b.Run, b.Circuit.SignerCount, b.Circuit.Signers[0] = nil, 0, 0
		b.Rebind(t)
		refused(t, b, "transfer.(*ConfidentialTransferCircuit).spendInputs")
	})
	t.Run("a policy refuses more owners than its sender rows", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{big.NewInt(0x1001), big.NewInt(0x1002), big.NewInt(0x1003)}
		requireSolved(t, w.Build(t).Circuit)
		w.CoOwners = append(w.CoOwners, big.NewInt(0x1004))
		b := w.Build(t)
		refused(t, b, "transfer.SignerSet.AssertAtMost")
	})
	t.Run("a co-owner off the policy is refused though it receives nothing", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners, w.FrozenCoOwner = []*big.Int{coOwner}, true
		refused(t, w.Build(t), "policy.(*PolicyInputs).assertRules")
	})
}

// The statement binds SPP's run with its count and order, another run names another transaction.
func TestSignerSetStatementBindsTheRun(t *testing.T) {
	honest := func(t *testing.T) ringtransfer.Built {
		t.Helper()
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner}
		return w.Build(t)
	}
	circuit, err := transfer.NewConfidentialTransferCircuit(confidential2)
	if err != nil {
		t.Fatal(err)
	}
	b := honest(t)
	bound := ringkey.Bind(t, circuit, b.Circuit)
	for name, run := range map[string][]*big.Int{
		"a reordered run":  {coOwner, b.Sender},
		"an extra signer":  {b.Sender, coOwner, otherCoOwner},
		"a missing signer": {b.Sender},
	} {
		t.Run(name, func(t *testing.T) {
			moved := honest(t)
			assignment := moved.Circuit
			moved.Run = run
			bound.RefuseStatement(t, assignment, moved.Statement(t))
		})
	}
	// A member past the count would extend a chain the program never hashed.
	t.Run("a count of zero holds every slot at zero", func(t *testing.T) {
		w := unscreened()
		w.PublicFunded = true
		empty := w.Build(t)
		empty.Run, empty.Circuit.SignerCount, empty.Circuit.Signers[0] = nil, 0, 0
		empty.Rebind(t)
		requireSolved(t, empty.Circuit)
		for _, slot := range []int{0, 1, confidential2.Inputs - 1} {
			forged := w.Build(t)
			forged.Run, forged.Circuit.SignerCount, forged.Circuit.Signers[0] = nil, 0, 0
			forged.Circuit.Signers[slot] = 0x0e0e
			forged.Rebind(t)
			refused(t, forged, "transfer.OpenSigners")
		}
	})
	// A chain over zeros would let one empty set carry two encodings.
	t.Run("an empty run has one encoding", func(t *testing.T) {
		w := unscreened()
		w.PublicFunded = true
		empty := w.Build(t)
		empty.Run, empty.Circuit.SignerCount, empty.Circuit.Signers[0] = nil, 0, 0
		empty.Rebind(t)
		statement := empty.Statement(t)
		zeros := make([]*big.Int, confidential2.Inputs)
		for i := range zeros {
			zeros[i] = big.NewInt(0)
		}
		statement[25] = spptest.MustHashChain4(t, zeros)
		bound.RefuseStatement(t, empty.Circuit, statement)
	})
}

// Every entry of the private list is an opened commitment, a chain node over two notes opens to none.
func TestChainNodeCannotHideAnInput(t *testing.T) {
	w := ringtransfer.Signed(confidential2)
	b := w.Build(t)
	real := slices.Clone(b.Inputs)
	b.Inputs[1] = ringaudit.SpareInput(1)
	b.Circuit.Inputs[1] = b.Inputs[1].Wires()
	// SPP spends both notes, the witness opens one.
	outputs := spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, b.Audit.Utxos()))
	b.Circuit.PrivateTxHash = spptest.MustPoseidon(t, 5, []*big.Int{spptest.MustNonZeroHashChain(t, ringaudit.SpentHashes(t, real)), outputs, big.NewInt(0), ringtest.AsBigInt(b.Circuit.PrivateTxBlinding)})
	b.Rebind(t)
	refused(t, b, "transfer.transactionBinding.bindTransaction")
}

// Omission removes a suffix on the confidential family, an omitted slot publishes no cell and holds no note.
func TestConfidentialCompactSlots(t *testing.T) {
	shape := transfer.ConfidentialShape{Inputs: 24, Outputs: 4, Withdrawals: 4}
	w := ringtransfer.Signed(shape)
	w.Exits = []int{}
	w.Omitted = 1
	requireSolved(t, w.Build(t).Circuit)
	t.Run("a live note past the count", func(t *testing.T) {
		w := ringtransfer.Signed(shape)
		w.Exits = []int{}
		b := w.Build(t)
		b.Audit.Omitted = 2
		b.Circuit.OutputCount = 2
		b.Rebind(t)
		refused(t, b, "audit.OpenSlots")
	})
}

// Every anonymous sender binds an address and hides, a frame of public owners belongs to the confidential family.
func TestAnonymousRailSpends(t *testing.T) {
	t.Run("a public co-owner beside the hidden sender", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner}
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("a frame of public owners", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{coOwner}
		b := w.Build(t)
		b.Audit.Signers = []*big.Int{b.Audit.SenderPkHash(t), coOwner}
		copy(b.Circuit.Signers, b.Audit.SignerWires())
		b.Circuit.SignerCount = 2
		b.Rebind(t)
		refusedAnonymous(t, b, "transfer.AnonymousInputs.Spend")
	})
	t.Run("a co-owner off the policy is refused though it receives nothing", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners, w.FrozenCoOwner = []*big.Int{coOwner}, true
		refusedAnonymous(t, w.Build(t), "policy.(*PolicyInputs).assertRules")
	})
	t.Run("a policy leaves three rows beside the hidden sender", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.CoOwners = []*big.Int{big.NewInt(0x1001), big.NewInt(0x1002), big.NewInt(0x1003)}
		requireSolved(t, w.Build(t).Circuit)
		w.CoOwners = append(w.CoOwners, big.NewInt(0x1004))
		refusedAnonymous(t, w.Build(t), "transfer.SignerSet.AssertAtMost")
	})
	t.Run("an audit-only ring takes the whole run", func(t *testing.T) {
		w := hiddenUnscreened()
		w.CoOwners = []*big.Int{big.NewInt(0x1001), big.NewInt(0x1002), big.NewInt(0x1003), big.NewInt(0x1004)}
		w.CoOwners = w.CoOwners[:3]
		requireSolved(t, w.Build(t).Circuit)
	})
	t.Run("an entry key spends one owner's notes", func(t *testing.T) {
		b := ringtransfer.Hidden(entry2).Build(t)
		b.Audit.Inputs[1].OwnerPkHash = coOwner
		b.Circuit.Inputs[1] = b.Audit.Inputs[1].Wires()
		b.Circuit.PrivateTxHash = b.Audit.PrivateTxHash(t)
		b.Rebind(t)
		refusedAnonymous(t, b, "transfer.InputSection.AssertOwnedBy")
	})
	t.Run("a recipient under a wrong nullifier key opens no record", func(t *testing.T) {
		b := ringtransfer.Hidden(anonymous2).Build(t)
		b.Audit.Outputs[1].Utxo.NullifierPk = spptest.MustNullifierPk(t, big.NewInt(99))
		b.Circuit.Outputs[1] = b.Audit.Outputs[1].Wires()
		b.Circuit.PrivateTxHash = b.Audit.PrivateTxHash(t)
		b.Rebind(t)
		refusedAnonymous(t, b, "audit.AuditWires.DeliverRecipients")
	})
	t.Run("a sender with no enrollment", func(t *testing.T) {
		w := ringtransfer.Hidden(anonymous2)
		w.Unenrolled = true
		refusedAnonymous(t, w.Build(t), "audit.AuditWires.DeliverRecipients")
	})
	t.Run("an audit-only ring binds every address", func(t *testing.T) {
		w := hiddenUnscreened()
		w.Unenrolled = true
		refusedAnonymous(t, w.Build(t), "audit.AuditWires.DeliverRecipients")
	})
	t.Run("a wrong tag on a live slot", func(t *testing.T) {
		b := ringtransfer.Hidden(anonymous2).Build(t)
		b.Audit.Outputs[1].Tag = big.NewInt(7)
		b.Circuit.Outputs[1] = b.Audit.Outputs[1].Wires()
		b.Rebind(t)
		refusedAnonymous(t, b, "audit.assertSlotTag")
	})
	t.Run("a nonzero tag on change", func(t *testing.T) {
		b := ringtransfer.Hidden(anonymous2).Build(t)
		b.Audit.Outputs[0].Tag = big.NewInt(7)
		b.Circuit.Outputs[0] = b.Audit.Outputs[0].Wires()
		b.Rebind(t)
		refusedAnonymous(t, b, "audit.assertSlotTag")
	})
	t.Run("a wrong bundle tag", func(t *testing.T) {
		b := ringtransfer.Hidden(entry2).Build(t)
		b.Circuit.SenderBundleTag = 7
		refusedAnonymous(t, b, "audit.AuditWires.DeliverRecipients")
	})
	t.Run("the reply digest binds alone", func(t *testing.T) {
		b := ringtransfer.Hidden(anonymous2).Build(t)
		b.Circuit.ReplyDigest = 0x7e
		b.Rebind(t)
		requireSolved(t, b.Circuit)
	})
	t.Run("an omitted slot", func(t *testing.T) {
		w := ringtransfer.Hidden(transfer.AnonymousShape{InputClass: 16, Outputs: 4, Withdrawals: 4})
		w.Omitted = 1
		requireSolved(t, w.Build(t).Circuit)
	})
}

// A debit reads every input the rail opened, an owner's exit leaves the ring on the full key.
func TestOutflowReadsTheOpenedInputs(t *testing.T) {
	t.Run("an exit to the sender counts against the cap", func(t *testing.T) {
		shape := transfer.ConfidentialShape{Inputs: 24, Outputs: 4, Withdrawals: 4}
		w := ringtransfer.Signed(shape)
		w.Policy.Cap, w.Policy.CosignAbove = 150, 0
		b := w.Build(t)
		refused(t, b, "policy.(*PolicyInputs).constrainOutflow")
	})
	t.Run("a mixed owner deposit of a spent asset", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner}
		w.Public = []ringtransfer.PublicSlot{{Asset: ringtransfer.Asset(t), Net: 50}}
		refused(t, w.Build(t), "policy.(*PolicyInputs).assertNoMixedDeposit")
	})
	t.Run("a mixed owner deposit of an unrelated asset", func(t *testing.T) {
		w := ringtransfer.Signed(confidential2)
		w.CoOwners = []*big.Int{coOwner}
		w.Public = []ringtransfer.PublicSlot{{Asset: big.NewInt(0x0b0b), Net: 50}}
		requireSolved(t, w.Build(t).Circuit)
	})
}
