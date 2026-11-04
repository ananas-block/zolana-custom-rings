package policy_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/test"

	"github.com/helius-labs/zolana-custom-rings/prover/ringtest"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringpolicy"
	"github.com/helius-labs/zolana-custom-rings/prover/ringtest/ringregistry"
)

const outflow = "policy.(*PolicyInputs).constrainOutflow"

func requireRefusedIn(t *testing.T, w ringpolicy.World, frame string) {
	t.Helper()
	b := w.Build(t)
	ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), frame)
}

// capped is a ring whose AssetA cap is 100 with no co-sign bound, each owner holds its own budget.
func capped() ringpolicy.World {
	w := ringpolicy.Confidential()
	w.Table.Limits = []ringpolicy.OutflowLimit{{Asset: ringpolicy.AssetA, Cap: 100}}
	w.Slots = nil
	return w
}

// A deposit lowers a single owner's debit, clamped at zero.
func TestDepositOffsetsASingleOwnersDebit(t *testing.T) {
	w := capped()
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 300}}
	t.Run("a deposit of the whole payment", func(t *testing.T) {
		deposit := w
		deposit.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 300}}
		requireSolved(t, deposit.Build(t))
	})
	t.Run("a deposit past the payment clamps at zero", func(t *testing.T) {
		deposit := w
		deposit.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 400}}
		requireSolved(t, deposit.Build(t))
	})
	t.Run("a deposit of part still holds the rest to the cap", func(t *testing.T) {
		deposit := w
		deposit.Public = []ringpolicy.PublicSlot{{Asset: ringpolicy.AssetA, Amount: 150}}
		requireRefusedIn(t, deposit, outflow)
	})
}

// A debit reads the opened inputs, a dummy's amount on either side counts for nothing.
func TestDebitReadsOnlyLiveSlots(t *testing.T) {
	w := capped()
	w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200}}
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 200}, {Asset: ringpolicy.AssetA, Amount: 200}}
	requireRefusedIn(t, w, outflow)
}

// Change returns to the owner while an exit leaves the ring, whoever receives it.
func TestSameOwnerExitCountsAsLeaving(t *testing.T) {
	w := capped()
	w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200}}
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200}}
	requireSolved(t, w.Build(t))
	w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 200, Exit: true}}
	requireRefusedIn(t, w, outflow)
}

// Each owner meets the cap alone, a credit to one owner never pays another's debit.
func TestDebitKeepsOwnersApart(t *testing.T) {
	twoOwners := func() ringpolicy.World {
		w := capped()
		w.CoOwners = []int64{ringpolicy.Bob}
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 80}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 80}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 160}}
		return w
	}
	t.Run("two owners each under the cap", func(t *testing.T) {
		requireSolved(t, twoOwners().Build(t))
	})
	t.Run("one owner past the cap beside one under it", func(t *testing.T) {
		w := twoOwners()
		w.Inputs[0].Amount, w.Inputs[1].Amount = 150, 10
		requireRefusedIn(t, w, outflow)
	})
	t.Run("change to the co-owner credits only the co-owner", func(t *testing.T) {
		w := twoOwners()
		w.Inputs[0].Amount, w.Inputs[1].Amount = 200, 0
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 200}}
		requireRefusedIn(t, w, outflow)
	})
	t.Run("an owner's notes aggregate across nullifier keys", func(t *testing.T) {
		w := capped()
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 80}, {Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 80}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 160}}
		b := w.Build(t)
		b.Circuit.Inputs[1].NullifierPk = 0x6e6c
		ringtest.RequireRefused(t, test.IsSolved(b.Assignment(), b.Assignment(), ecc.BN254.ScalarField()), outflow)
	})
}

// Every sender row meets the sender rules, a co-owner who receives nothing included.
func TestEveryCoOwnerIsScreened(t *testing.T) {
	w := ringpolicy.Confidential()
	w.CoOwners = []int64{ringpolicy.Bob}
	w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 400}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
	requireSolved(t, w.Build(t))
	w.Own[ringpolicy.Bob] = ringpolicy.Escrowed(ringregistry.AllowBit | ringregistry.FrozenBit)
	requireRefusedIn(t, w, "policy.assertSenderRules")
}

// Input assets stay hidden from the program, only the proof can see a deposit no owner could be credited alone.
func TestMixedOwnerDepositOfASpentAssetIsRefused(t *testing.T) {
	mixed := func(depositAsset int64) ringpolicy.World {
		w := ringpolicy.Confidential()
		w.Table.Limits = nil
		w.CoOwners = []int64{ringpolicy.Bob}
		w.Inputs = []ringpolicy.Slot{{Owner: ringpolicy.Sender, Asset: ringpolicy.AssetA, Amount: 100}, {Owner: ringpolicy.Bob, Asset: ringpolicy.AssetA, Amount: 100}}
		w.Slots = []ringpolicy.Slot{{Owner: ringpolicy.Alice, Asset: ringpolicy.AssetA, Amount: 200}}
		w.Public = []ringpolicy.PublicSlot{{Asset: depositAsset, Amount: 50}}
		return w
	}
	t.Run("the same asset", func(t *testing.T) {
		requireRefusedIn(t, mixed(ringpolicy.AssetA), "policy.(*PolicyInputs).assertNoMixedDeposit")
	})
	t.Run("an unrelated asset", func(t *testing.T) {
		requireSolved(t, mixed(ringpolicy.AssetB).Build(t))
	})
	t.Run("a single owner of the same asset", func(t *testing.T) {
		w := mixed(ringpolicy.AssetA)
		w.Inputs[1].Owner = ringpolicy.Sender
		requireSolved(t, w.Build(t))
	})
	t.Run("a withdrawal of the same asset", func(t *testing.T) {
		w := mixed(ringpolicy.AssetA)
		w.Public[0].Amount = -50
		requireSolved(t, w.Build(t))
	})
}

// A zero secret key owes no escrow record, any other key under the same owner does.
func TestZeroNullifierKeyWaivesOnlyTheEscrow(t *testing.T) {
	zeroKey := func() ringpolicy.World {
		w := ringpolicy.Confidential()
		w.Own[ringpolicy.Alice] = ringpolicy.Record{Lists: ringregistry.AllowBit}
		return w
	}
	t.Run("a record without a key refuses another nullifier key", func(t *testing.T) {
		requireRefusedIn(t, zeroKey(), "policy.(*PolicyInputs).assertEscrow")
	})
	t.Run("a zero secret owner with a record settles", func(t *testing.T) {
		w := zeroKey()
		w.Slots[0].ZeroKey = true
		requireSolved(t, w.Build(t))
	})
	t.Run("a zero secret owner with no record settles off a policy", func(t *testing.T) {
		w := zeroKey()
		w.Slots[0].ZeroKey = true
		w.Unscreened = true
		delete(w.Own, ringpolicy.Alice)
		requireSolved(t, w.Build(t))
	})
	t.Run("a zero secret owner still answers the owner rules", func(t *testing.T) {
		w := zeroKey()
		w.Slots[0].ZeroKey = true
		w.Own[ringpolicy.Alice] = ringpolicy.Record{}
		requireRefusedIn(t, w, "policy.assertPaymentRules")
	})
}
